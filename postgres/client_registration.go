package oauthpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/jackc/pgx/v5"
)

const dynamicRegistrationOperation = "identity.oauth-server.dynamic-register"

// The existing coordinator encrypts this nonsecret immutable preparation.
// Neither it nor the token table is a second command/outcome journal.
type registrationMutation struct {
	Digest, Policy       [32]byte
	CreatedAt, ExpiresAt time.Time
	ClientName           string
}

func registrationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "oauth-server", OperationID: dynamicRegistrationOperation, SchemaID: dynamicRegistrationOperation + ".native-public-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func (s *Store) registrationSelected() bool {
	return s.config.Protocol.ManagedClients != nil && s.config.Protocol.ManagedClients.DynamicRegistration != nil && s.config.PublicClients
}

func (p *phase) registering() bool {
	return p.input.ClientChange != nil && p.input.ClientChange.DynamicRegistration != nil
}

func (s *Store) registrationPolicy() [32]byte {
	if !s.registrationSelected() {
		return [32]byte{}
	}
	p := s.config.Protocol.ManagedClients
	wire, _ := json.Marshal(struct {
		Configuration, Management [32]byte
		Profile                   *oauth.DynamicRegistrationPolicy
	}{s.identity, s.managementPolicy(), p.DynamicRegistration})
	defer clear(wire)
	return sha256.Sum256(wire)
}

// BootstrapRegistrationToken provisions trusted startup custody under the exact
// configured immutable owner, issuer, environment, audience, version and ceilings.
// Only a digest is persisted. Repeating the identical provisioning is harmless;
// expiry/policy changes conflict, and consumed tokens are never replenished.
// This is not a protocol endpoint or RFC7592 registration access token issuer.
func (s *Store) BootstrapRegistrationToken(ctx context.Context, wire string, expires time.Time) error {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return err
	}
	defer stop()
	if !s.registrationSelected() {
		return oauth.ErrAccessDenied
	}
	if _, err := oauth.ParseToken(wire); err != nil || expires.IsZero() || expires.Year() > 9999 || expires.Nanosecond()%1000 != 0 || !expires.After(s.now()) {
		return oauth.ErrInvalidRequest
	}
	digest := sha256.Sum256([]byte(wire))
	policy := s.registrationPolicy()
	p := s.config.Protocol.ManagedClients
	d := p.DynamicRegistration
	_, err = s.pool.Raw().Exec(ctx, `INSERT INTO `+s.schema+`.initial_registration_tokens(digest,issuer,environment,platform_owner,tenant_id,audience,policy_version,policy_digest,created_at,expires_at)
 SELECT $1,$2,$3,$4,$5,$6,$7::numeric,$8,clock_timestamp(),$9 WHERE $9>clock_timestamp() ON CONFLICT(digest) DO NOTHING`, digest[:], s.config.Protocol.Issuer.String(), s.config.Protocol.Environment, p.Owner.PlatformID(), string(p.TenantID), d.Audience, strconv.FormatUint(d.Version, 10), policy[:], expires)
	if err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	retained, _, err := s.registrationToken(ctx, wire)
	if err != nil {
		return err
	}
	if !retained.ExpiresAt.Equal(expires) {
		return oauth.ErrAccessDenied
	}
	return nil
}

func (s *Store) registrationToken(ctx context.Context, wire string) (registrationMutation, string, error) {
	var row registrationMutation
	if !s.registrationSelected() {
		return row, "", oauth.ErrAccessDenied
	}
	if _, err := oauth.ParseToken(wire); err != nil {
		return row, "", oauth.ErrAccessDenied
	}
	row.Digest, row.Policy = sha256.Sum256([]byte(wire)), s.registrationPolicy()
	p := s.config.Protocol.ManagedClients
	d := p.DynamicRegistration
	var consumed string
	var now time.Time
	err := s.pool.Raw().QueryRow(ctx, `SELECT created_at,expires_at,COALESCE(consumed_command,''),clock_timestamp() FROM `+s.schema+`.initial_registration_tokens
 WHERE digest=$1 AND issuer=$2 AND environment=$3 AND platform_owner=$4 AND tenant_id=$5 AND audience=$6 AND policy_version=$7::numeric AND policy_digest=$8`, row.Digest[:], s.config.Protocol.Issuer.String(), s.config.Protocol.Environment, p.Owner.PlatformID(), string(p.TenantID), d.Audience, strconv.FormatUint(d.Version, 10), row.Policy[:]).Scan(&row.CreatedAt, &row.ExpiresAt, &consumed, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return registrationMutation{}, "", oauth.ErrAccessDenied
	}
	if err != nil {
		return registrationMutation{}, "", publicError(ctx, err, oauth.ErrAccessDenied)
	}
	// pgx TimestamptzCodec.ScanLocation may project the same instant in different
	// local zones. Canonical UTC must precede both the protocol-command HMAC and
	// retained preparation, as for the native device timestamp reader.
	row.CreatedAt, row.ExpiresAt = row.CreatedAt.UTC(), row.ExpiresAt.UTC()
	if now.Before(row.CreatedAt) || !now.Before(row.ExpiresAt) || !s.now().Before(row.ExpiresAt) {
		return registrationMutation{}, "", oauth.ErrAccessDenied
	}
	return row, consumed, nil
}

// registrationPhase derives one server-owned protocol-command from authenticated
// token custody and immutable policy/metadata. Request headers and network do not
// select the identity. The existing keyed intent domain keeps raw tokens out of
// command IDs, journal fields, audit records and encrypted command preparation.
func (s *Store) registrationPhase(r oauth.DynamicRegisterRequest, token registrationMutation) (*phase, error) {
	metadata, err := json.Marshal(struct {
		Redirects, Scopes []string
		Name              string
	}{r.RedirectURIs, r.Scopes, r.ClientName})
	if err != nil {
		return nil, oauth.ErrInvalidRequest
	}
	defer clear(metadata)
	intent := s.intent("oauth-public-rfc7591-v1", string(token.Digest[:]), string(token.Policy[:]), string(metadata), token.CreatedAt.Format(time.RFC3339Nano), token.ExpiresAt.Format(time.RFC3339Nano))
	id, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(intent[:16]))
	if err != nil {
		return nil, oauth.ErrInvalidRequest
	}
	p := s.config.Protocol.ManagedClients
	client := oauth.Client{ID: oauth.ManagedClientPrefix + string(id), Owner: p.Owner, Version: 1, Public: true, Resource: s.config.Protocol.Resource, AuthenticationMethod: "none", Redirects: slices.Clone(r.RedirectURIs), Scopes: slices.Clone(r.Scopes)}
	token.ClientName = r.ClientName
	change := &clientMutation{Client: client, Policy: s.managementPolicy(), DynamicRegistration: &token}
	if s.config.ClientMetadataUpdates {
		change.SecretVersion = 1
	}
	phase := &phase{store: s, client: client, input: phaseInput{Schema: 1, Configuration: s.identity, Transition: createManagedClient, ClientChange: change, Grant: grantRecord{Tenant: p.TenantID, ClientID: client.ID, ClientVersion: 1, ClientFingerprint: clientFingerprint(client), Resource: client.Resource, Scopes: slices.Clone(client.Scopes)}, Scopes: slices.Clone(client.Scopes), Intent: intent, CreatedAt: s.now(), ObservationUntil: token.ExpiresAt, Network: r.Network}}
	phase.bind(id, dynamicRegistrationOperation, string(id))
	return phase, nil
}

// DynamicRegister authenticates real initial-token custody before consulting
// admission policy, and consumes it with client creation in the sole Work.
// A consumed token cannot register again, even with identical metadata.
func (s *Store) DynamicRegister(ctx context.Context, r oauth.DynamicRegisterRequest) (out oauth.DynamicRegisterResult, err error) {
	defer func() {
		if recover() != nil {
			out = oauth.DynamicRegisterResult{Completion: out.Completion}
			err = oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if !s.registrationSelected() {
		return out, oauth.ErrAccessDenied
	}
	r, err = oauth.ValidateDynamicRegisterRequest(r, *s.config.Protocol.ManagedClients, s.config.Protocol.Issuer)
	if err != nil {
		return out, err
	}
	token, consumed, err := s.registrationToken(ctx, r.InitialAccessToken)
	if err != nil {
		return out, err
	}
	if consumed != "" {
		return out, oauth.ErrAccessDenied
	}
	p, err := s.registrationPhase(r, token)
	if err != nil {
		return out, err
	}
	out.Completion = oauth.Completion{CommandID: p.input.Binding.CommandID, Outcome: identity.CommitOutcomeUnknown}
	result, err := p.execute(ctx)
	out.Completion.Outcome, out.Completion.Replayed = result.Outcome, p.observedHistory && !p.applied
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if result.Outcome == identity.CommitOutcomeCommitted && p.applied {
		out.Client, out.ClientName = p.client, r.ClientName
	}
	return out, nil
}

// RecoverDynamicRegistration authenticates the original token, exact configured
// policy and registration intent, then reconciles only the existing coordinator
// command. It never executes absent work, recreates clients or returns secrets.
// Custody must remain unexpired, including after terminal client deletion.
// A live original lease returns InProgress without error. The matching kernel
// also recognizes this exact declaration before retained preparation attaches;
// recovery preserves the original claim, generation and rollback fences.
// Proven rollback retains NotCommitted + ErrUnavailable as a dependency-failure pair;
// ErrUnavailable alone is not rollback proof. Lost commit acknowledgement must
// reconcile to the original outcome rather than allocate another command.
func (s *Store) RecoverDynamicRegistration(ctx context.Context, r oauth.DynamicRegisterRequest) (out oauth.DynamicRegisterResult, err error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if !s.registrationSelected() {
		return out, oauth.ErrAccessDenied
	}
	r, err = oauth.ValidateDynamicRegisterRequest(r, *s.config.Protocol.ManagedClients, s.config.Protocol.Issuer)
	if err != nil {
		return out, err
	}
	token, consumed, err := s.registrationToken(ctx, r.InitialAccessToken)
	if err != nil {
		return out, err
	}
	p, err := s.registrationPhase(r, token)
	if err != nil {
		return out, err
	}
	if consumed != "" && consumed != string(p.input.Binding.CommandID) {
		return out, oauth.ErrAccessDenied
	}
	if err := s.coordinator(p); err != nil {
		return out, err
	}
	admission, err := p.coordinator.ObserveCommandAdmission(ctx, p.query(), p.caller())
	if admission.Validate() != nil || admission.Absent {
		if err != nil {
			return out, publicError(ctx, err, oauth.ErrAccessDenied)
		}
		return out, oauth.ErrAccessDenied
	}
	if err != nil && admission.Record.Outcome == identity.CommitOutcomeInvalid {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	// Authenticated initial custody and immutable metadata already derive the
	// exact server-owned command identity. Metadata-only recovery must not demand
	// generated output: interruption may leave only the coordinator's committed
	// start/declaration. Its original lease and recovery participants alone decide
	// durability, including started-without-output; never reconstruct execution.
	result, err := p.coordinator.RecoverFeatureCommand(ctx, p.query(), p.caller())
	out.Completion = oauth.Completion{CommandID: p.input.Binding.CommandID, Outcome: result.Outcome, Replayed: true}
	return out, publicError(ctx, err, oauth.ErrAccessDenied)
}

func (p *phase) checkRegistrationToken(ctx context.Context, w kernel.Work, final bool) error {
	if !p.registering() || !p.store.registrationSelected() || p.input.Transition != createManagedClient || !p.client.Public || p.input.Binding.OperationID != dynamicRegistrationOperation {
		return identity.ForbiddenError{}
	}
	r := p.input.ClientChange.DynamicRegistration
	if r.Policy != p.store.registrationPolicy() || r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) || p.input.ObservationUntil != r.ExpiresAt {
		return identity.ForbiddenError{}
	}
	policy := p.store.config.Protocol.ManagedClients
	profile := policy.DynamicRegistration
	rows, err := w.Query(ctx, `SELECT created_at,expires_at,COALESCE(consumed_command,''),COALESCE(client_id,'') FROM `+p.store.schema+`.initial_registration_tokens WHERE digest=$1 AND policy_digest=$2 AND issuer=$3 AND environment=$4 AND platform_owner=$5 AND tenant_id=$6 AND audience=$7 AND policy_version=$8::numeric FOR UPDATE`, r.Digest[:], r.Policy[:], p.store.config.Protocol.Issuer.String(), p.store.config.Protocol.Environment, policy.Owner.PlatformID(), string(policy.TenantID), profile.Audience, strconv.FormatUint(profile.Version, 10))
	if err != nil {
		return err
	}
	var created, expires time.Time
	var consumed, client string
	if !rows.Next() {
		rows.Close()
		return identity.ForbiddenError{}
	}
	err = rows.Scan(&created, &expires, &consumed, &client)
	more := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	if err != nil || more || rowErr != nil {
		return identity.UnavailableError{}
	}
	if !created.Equal(r.CreatedAt) || !expires.Equal(r.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	if final && p.applied {
		if consumed != string(p.input.Binding.CommandID) || client != p.client.ID {
			return identity.ForbiddenError{}
		}
	} else if consumed != "" || client != "" {
		return identity.ForbiddenError{}
	}
	return p.checkRegistrationExpiry(ctx, w)
}

func (p *phase) checkRegistrationExpiry(ctx context.Context, w kernel.Work) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	r := p.input.ClientChange.DynamicRegistration
	if now.Before(r.CreatedAt) || !now.Before(r.ExpiresAt) || !p.store.now().Before(r.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *phase) consumeRegistrationToken(ctx context.Context, w kernel.Work) error {
	r := p.input.ClientChange.DynamicRegistration
	n, err := w.Exec(ctx, `UPDATE `+p.store.schema+`.initial_registration_tokens SET consumed_command=$3,client_id=$4,consumed_at=clock_timestamp() WHERE digest=$1 AND policy_digest=$2 AND consumed_command IS NULL AND expires_at>clock_timestamp()`, r.Digest[:], r.Policy[:], string(p.input.Binding.CommandID), p.client.ID)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

var _ oauth.DynamicRegistrar = (*Store)(nil)
