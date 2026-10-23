package oauthpostgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/jackc/pgx/v5"
)

type issuedHint struct {
	Issuer, Environment string
	Digest              [32]byte
	Grant               grantRecord
	Command             identity.CommandID
	Subject, KeyID      string
	IssuedAt, ExpiresAt time.Time
}

type logoutIntent struct {
	Hint               issuedHint
	RedirectURI, State string
}

func endSessionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "oauth-server/oidc", OperationID: "identity.oauth-server.end-session", SchemaID: "identity.oauth-server.end-session.native-rp-logout-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// EndSessionSelected reports immutable explicit composition only; no IO,
// migration, signing publication or endpoint activation occurs here.
func (s *Store) EndSessionSelected() bool {
	return s != nil && s.config.RPInitiatedLogout && s.endSession != nil
}

func (s *Store) loadIssuedHint(ctx context.Context, tenant identity.TenantID, client string, digest [32]byte) (issuedHint, error) {
	var raw []byte
	err := s.pool.Raw().QueryRow(ctx, `SELECT projection FROM `+s.schema+`.issued_id_token_hints WHERE digest=$1 AND tenant_id=$2 AND client_id=$3`, digest[:], string(tenant), client).Scan(&raw)
	if err != nil {
		return issuedHint{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	var h issuedHint
	if len(raw) > 65536 || decodeJSON(raw, &h) != nil || h.Issuer != s.config.Protocol.Issuer.String() || h.Environment != s.config.Protocol.Environment || h.Digest != digest || h.Grant.Tenant != tenant || h.Grant.ClientID != client || h.Grant.Workload != nil || h.Subject == "" || h.KeyID == "" || !h.ExpiresAt.After(h.IssuedAt) {
		return issuedHint{}, oauth.ErrAccessDenied
	}
	if _, err := identity.ParseCommandID(string(h.Command)); err != nil {
		return issuedHint{}, oauth.ErrAccessDenied
	}
	return h, nil
}

func (s *Store) logoutPhase(client oauth.Client, h issuedHint, uri, state, network string) (*phase, error) {
	source, err := sessionpg.OriginalSessionFromFields(h.Grant.Tenant, h.Grant.User, h.Grant.Source)
	if err != nil {
		return nil, oauth.ErrAccessDenied
	}
	b, err := source.Bindings()
	if err != nil {
		return nil, oauth.ErrAccessDenied
	}
	p := &phase{store: s, client: client, input: phaseInput{Schema: 1, Configuration: s.identity, Transition: endSession, Grant: h.Grant, Scopes: h.Grant.Scopes, CreatedAt: s.now(), Network: network, Logout: &logoutIntent{Hint: h, RedirectURI: uri, State: state}, Intent: s.intent("end-session", base64.RawURLEncoding.EncodeToString(h.Digest[:]), uri, state)}}
	p.bind(h.Command, endSessionOperation().OperationID, b.SessionID)
	return p, nil
}

func (s *Store) logoutCookie(source session.Session, raw string) bool {
	b, err := source.Bindings()
	if err != nil {
		return false
	}
	token, err := session.ParseToken(raw)
	if err != nil {
		return false
	}
	for _, key := range s.config.Session.Validation.LookupKeys {
		digest, err := token.Digest(key, string(b.TenantID))
		if err == nil && digest.KeyVersion == b.Lookup.KeyVersion && subtle.ConstantTimeCompare(digest.Sum[:], b.Lookup.Sum[:]) == 1 {
			return true
		}
	}
	return false
}

// EndSession binds a verified, durably issued hint to its exact initiating
// browser. Fresh invalidation uses the existing sole coordinator and session
// effect. Repeats reconcile the original encrypted command without authenticating
// a self-revoked cookie as a current session or renewing its delivery deadline.
func (s *Store) EndSession(ctx context.Context, e oauth.EndSessionExecution) (out oauth.EndSessionResult, err error) {
	defer func() {
		if recover() != nil {
			out = oauth.EndSessionResult{}
			err = oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	now := s.config.Protocol.Clock.Now()
	proofStart := e.Input.Hint.ReadStartedAt()
	if !s.EndSessionSelected() || e.StartedAt.IsZero() || e.StartedAt.After(now) || proofStart.IsZero() || proofStart.After(now) || e.Input.TenantID == "" || e.Input.Hint.Digest() == ([32]byte{}) || e.Input.State != "" && !boundedText(e.Input.State, 1024) {
		return out, oauth.ErrAccessDenied
	}
	// Public Store callers can narrow the sealed verification observation, never
	// replace it with a fresh timestamp. Current key/session reads do not renew
	// the original <=20s budget required by the selected native logout profile.
	started := minTime(e.StartedAt, proofStart)
	if !now.Before(started.Add(20 * time.Second)) {
		return out, oauth.ErrAccessDenied
	}
	client, err := s.checkedClient(ctx, e.Client)
	if err != nil || client.Workload != nil || client.ID != e.Input.ClientID {
		return out, oauth.ErrAccessDenied
	}
	if e.Input.Origin != s.config.Protocol.Issuer.String() || !boundedText(e.Input.Network, 128) || e.Input.PostLogoutRedirectURI != "" && !oauth.PostLogoutRedirectAllowed(client, e.Input.PostLogoutRedirectURI) {
		return out, oauth.ErrAccessDenied
	}
	h, err := s.loadIssuedHint(ctx, e.Input.TenantID, client.ID, e.Input.Hint.Digest())
	if err != nil {
		return out, err
	}
	if h.Subject != e.Input.Subject || h.KeyID != e.Input.Hint.KeyID() || !h.IssuedAt.Equal(e.Input.IssuedAt) || !h.ExpiresAt.Equal(e.Input.ExpiresAt) || h.Grant.ClientVersion != client.Version || h.Grant.ClientFingerprint != clientFingerprint(client) {
		return out, oauth.ErrAccessDenied
	}
	source, err := sessionpg.OriginalSessionFromFields(h.Grant.Tenant, h.Grant.User, h.Grant.Source)
	if err != nil || !s.logoutCookie(source, e.Input.Session.Token()) {
		return out, oauth.ErrAccessDenied
	}
	p, err := s.logoutPhase(client, h, e.Input.PostLogoutRedirectURI, e.Input.State, e.Input.Network)
	if err != nil {
		return out, err
	}
	if err = s.coordinator(p); err != nil {
		return out, err
	}
	admission, err := p.coordinator.ObserveCommandAdmission(ctx, p.query(), p.caller())
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if !admission.Absent {
		result, err := s.recoverLogoutPhase(ctx, p, false)
		return logoutMetadata(result, true), err
	}
	// The source may already have been ended using another genuinely issued
	// hint. Locate that original transition in existing effects, never execute
	// the unused candidate command or invent another session journal.
	var original string
	err = s.pool.Raw().QueryRow(ctx, `SELECT command_id FROM `+s.schema+`.effects WHERE tenant_id=$1 AND record_id=$2 AND operation_id='identity.oauth-server.end-session'`, string(h.Grant.Tenant), p.input.Binding.RecordID).Scan(&original)
	if err == nil {
		var raw []byte
		if err = s.pool.Raw().QueryRow(ctx, `SELECT projection FROM `+s.schema+`.issued_id_token_hints WHERE command_id=$1 AND tenant_id=$2 AND client_id=$3`, original, string(h.Grant.Tenant), client.ID).Scan(&raw); err != nil {
			return out, publicError(ctx, err, oauth.ErrAccessDenied)
		}
		var previous issuedHint
		if decodeJSON(raw, &previous) != nil || !sameJSON(previous.Grant.Source, h.Grant.Source) {
			return out, oauth.ErrAccessDenied
		}
		p, err = s.logoutPhase(client, previous, e.Input.PostLogoutRedirectURI, e.Input.State, e.Input.Network)
		if err != nil {
			return out, err
		}
		if err = s.coordinator(p); err != nil {
			return out, err
		}
		result, err := s.recoverLogoutPhase(ctx, p, false)
		return logoutMetadata(result, true), err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return out, oauth.ErrUnavailable
	}
	observed, err := s.recoverySession(ctx, RecoveryRequest{TenantID: h.Grant.Tenant, Session: e.Input.Session})
	if err != nil {
		return out, err
	}
	fields, err := sessionpg.OriginalSessionFields(observed.Session)
	if err != nil || !sameJSON(fields, h.Grant.Source) {
		return out, oauth.ErrAccessDenied
	}
	p.observation, p.browser, p.csrf = observed, e.Input.Session, e.Input.CSRF
	p.input.ObservationUntil = minTime(observed.ValidUntil(), started.Add(20*time.Second)).UTC().Truncate(time.Microsecond)
	if !s.now().Before(p.input.ObservationUntil) {
		return out, oauth.ErrAccessDenied
	}
	result, err := p.execute(ctx)
	completion := oauth.Completion{Outcome: result.Outcome, CommandID: p.input.Binding.CommandID, Replayed: !p.applied}
	if result.Outcome != identity.CommitOutcomeCommitted || !p.applied {
		out = logoutMetadata(RecoveryResult{Outcome: result.Outcome, CommandID: p.input.Binding.CommandID}, !p.applied)
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if err != nil {
		return oauth.EndSessionResult{Completion: completion}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	out = oauth.EndSessionResult{Outcome: oauth.EndSessionLocalOnly, Completion: completion, ValidUntil: p.input.ObservationUntil}
	if e.Input.PostLogoutRedirectURI != "" {
		out.Outcome = oauth.EndSessionRedirect
		out.RedirectURI = e.Input.PostLogoutRedirectURI
		out.State = e.Input.State
	}
	return out, nil
}

func logoutMetadata(r RecoveryResult, replayed bool) oauth.EndSessionResult {
	out := oauth.EndSessionResult{Completion: oauth.Completion{Outcome: r.Outcome, CommandID: r.CommandID, Replayed: replayed}}
	if r.Outcome == identity.CommitOutcomeCommitted {
		out.Outcome = oauth.EndSessionLocalOnly
	} else if r.Outcome == identity.CommitOutcomeUnknown || r.Outcome == identity.CommitOutcomeInProgress {
		out.Outcome = oauth.EndSessionUnknownReconciliation
	}
	return out
}

func (s *Store) recoverLogoutPhase(ctx context.Context, p *phase, metadataOnly bool) (RecoveryResult, error) {
	if _, err := s.originalGrantAuthority(ctx, p.input.Grant, s.now()); err != nil {
		return RecoveryResult{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if _, err := s.VerificationSigningKey(ctx, p.input.Logout.Hint.KeyID); err != nil {
		return RecoveryResult{}, err
	}
	wire, generation, err := p.coordinator.QueryFeaturePreparation(ctx, p.query(), p.caller(), p.registration(), p)
	if err != nil {
		return RecoveryResult{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	defer clear(wire)
	p.metadataRecovery = metadataOnly
	if err = p.restore(ctx, generation, wire, true); err != nil {
		return RecoveryResult{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	p.output = preparedOutput{}
	result, err := p.coordinator.RecoverFeatureCommand(ctx, p.query(), p.caller())
	return RecoveryResult{Outcome: result.Outcome, CommandID: p.input.Binding.CommandID, RetryAfter: result.RetryAfter}, publicError(ctx, err, oauth.ErrAccessDenied)
}

func (s *Store) grantEndSessionFence(ctx context.Context, g grantRecord) error {
	if !s.config.RPInitiatedLogout || g.Workload != nil {
		return nil
	}
	original, err := sessionpg.OriginalSessionFromFields(g.Tenant, g.User, g.Source)
	if err != nil {
		return oauth.ErrInvalidGrant
	}
	b, err := original.Bindings()
	if err != nil {
		return oauth.ErrInvalidGrant
	}
	revoked, err := s.sessionRecords.OIDCEndSessionRevoked(ctx, g.Tenant, g.User, b.SessionID)
	if err != nil {
		return err
	}
	if revoked {
		return oauth.ErrInvalidGrant
	}
	return nil
}

func (s *Store) recoverEndSession(ctx context.Context, r RecoveryRequest) (RecoveryResult, error) {
	if !s.EndSessionSelected() || r.ClientAuthentication.Method() != "none" || r.ConsentID != "" || r.Token == "" || len(r.Token) > 16384 {
		return RecoveryResult{}, oauth.ErrAccessDenied
	}
	client, err := s.CurrentClient(ctx, r.ClientID)
	if err != nil {
		return RecoveryResult{}, err
	}
	h, err := s.loadIssuedHint(ctx, r.TenantID, r.ClientID, sha256.Sum256([]byte(r.Token)))
	if err != nil || h.Command != r.CommandID || h.Grant.ClientFingerprint != clientFingerprint(client) {
		return RecoveryResult{}, oauth.ErrAccessDenied
	}
	source, err := sessionpg.OriginalSessionFromFields(h.Grant.Tenant, h.Grant.User, h.Grant.Source)
	if err != nil || !s.logoutCookie(source, r.Session.Token()) {
		return RecoveryResult{}, oauth.ErrAccessDenied
	}
	p, err := s.logoutPhase(client, h, "", "", "")
	if err != nil {
		return RecoveryResult{}, err
	}
	if err = s.coordinator(p); err != nil {
		return RecoveryResult{}, err
	}
	return s.recoverLogoutPhase(ctx, p, true)
}

func (p *phase) persistIssuedHint(ctx context.Context, w kernel.Work) error {
	// Legacy authenticated preparation resumes unchanged after activation;
	// it cannot acquire a new association that its original output never held.
	if !p.store.config.RPInitiatedLogout || p.output.IDToken == "" || p.output.EndSessionCommand == "" {
		return nil
	}
	h := issuedHint{Issuer: p.store.config.Protocol.Issuer.String(), Environment: p.store.config.Protocol.Environment, Digest: sha256.Sum256([]byte(p.output.IDToken)), Grant: p.input.Grant, Command: p.output.EndSessionCommand, Subject: p.output.Subject, KeyID: p.output.SigningKeyID, IssuedAt: p.input.CreatedAt.Truncate(time.Second), ExpiresAt: p.output.Artifacts[0].ExpiresAt}
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	defer clear(raw)
	n, err := w.Exec(ctx, `INSERT INTO `+p.store.schema+`.issued_id_token_hints(digest,grant_id,tenant_id,client_id,command_id,projection) VALUES($1,$2,$3,$4,$5,$6::jsonb)`, h.Digest[:], h.Grant.ID, string(h.Grant.Tenant), h.Grant.ClientID, string(h.Command), string(raw))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *phase) checkEndSession(ctx context.Context, w kernel.Work, final bool) error {
	i := p.input
	if !p.store.EndSessionSelected() || i.Logout == nil || i.Logout.Hint.Grant.ClientFingerprint != clientFingerprint(p.client) || i.Grant.ClientFingerprint != clientFingerprint(p.client) {
		return identity.ForbiddenError{}
	}
	if err := p.requireManagedClient(ctx, w); err != nil {
		return err
	}
	var public []byte
	rows, err := w.Query(ctx, `SELECT public_key FROM `+p.store.schema+`.signing_keys WHERE kid=$1 AND published_at IS NOT NULL AND state IN('published','retired') FOR SHARE`, i.Logout.Hint.KeyID)
	if err != nil {
		return err
	}
	if !rows.Next() || rows.Scan(&public) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return identity.ForbiddenError{}
	}
	rows.Close()
	var key oauth.PublicSigningKey
	if decodeJSON(public, &key) != nil || !validPublicSigningKey(key) || key.Kid != i.Logout.Hint.KeyID {
		return identity.ForbiddenError{}
	}
	source, err := sessionpg.OriginalSessionFromFields(i.Grant.Tenant, i.Grant.User, i.Grant.Source)
	if err != nil {
		return err
	}
	if final && p.applied {
		return p.store.endSession.Check(ctx, w, p, p.command)
	}
	if err = p.checkBrowser(source); err != nil {
		return err
	}
	if err = sessionpg.RequireSession(ctx, w, p.store.config.Session.Repository, source); err != nil {
		return err
	}
	for _, key := range p.store.config.CSRFKeys {
		if source.CSRFState().Check(session.CSRFBinding{TenantID: i.Grant.Tenant, SessionID: p.sessionID(source), SessionVersion: p.sessionVersion(source)}, p.csrf, key) == nil {
			return sessionpg.RequireCSRF(ctx, w, p.store.config.Session.Repository, source, p.csrf, key)
		}
	}
	return identity.ForbiddenError{}
}

func (p *phase) mutateEndSession(ctx context.Context, w kernel.Work) error {
	if _, err := p.store.endSession.Apply(ctx, w, p, p.command); err != nil {
		return err
	}
	life := p.lifecycle()
	digest := effectDigest(p.input.Binding, p.registration(), life)
	n, err := w.Exec(ctx, `INSERT INTO `+p.store.schema+`.effects(tenant_id,command_id,operation_id,record_id,grant_id,before_version,after_version,binding_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8)`, string(p.input.Binding.TenantID), string(p.input.Binding.CommandID), p.input.Binding.OperationID, p.input.Binding.RecordID, p.input.Grant.ID, strconv.FormatUint(life.BeforeVersion, 10), strconv.FormatUint(life.AfterVersion, 10), digest[:])
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
