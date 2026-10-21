package oauthpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type clientMutation struct {
	Client  oauth.Client
	Version uint64
	Policy  [32]byte
	Overlap time.Duration
}

func (m clientMutation) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Registration managedRegistration
		Version      uint64
		Policy       [32]byte
		Overlap      time.Duration `json:",omitempty"`
	}{registrationWire(m.Client), m.Version, m.Policy, m.Overlap})
}
func (m *clientMutation) UnmarshalJSON(wire []byte) error {
	var v struct {
		Registration managedRegistration
		Version      uint64
		Policy       [32]byte
		Overlap      time.Duration `json:",omitempty"`
	}
	if err := decodeJSON(wire, &v); err != nil {
		return err
	}
	c, err := registrationClient(v.Registration)
	if err != nil {
		return err
	}
	*m = clientMutation{c, v.Version, v.Policy, v.Overlap}
	return nil
}

var _ oauth.ClientManager = (*Store)(nil)

func (s *Store) managementPolicy() [32]byte {
	p := s.config.Protocol.ManagedClients
	if p == nil {
		return [32]byte{}
	}
	wire, _ := json.Marshal(struct {
		Configuration     [32]byte
		Platform          string
		Tenant            identity.TenantID
		Redirects, Scopes []string
	}{s.identity, p.Owner.PlatformID(), p.TenantID, p.Redirects, p.Scopes.Scopes()})
	defer clear(wire)
	return sha256.Sum256(wire)
}
func (s *Store) managementDecision(ctx context.Context, user identity.UserID, action string) error {
	p := s.config.Protocol.ManagedClients
	if p == nil {
		return oauth.ErrAccessDenied
	}
	return s.consentDecision(ctx, authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Coordinator.AdmissionPolicy.PolicyVersion), Request: authorization.Request{Tenant: authorization.TenantID(p.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: authorization.Action(action), Resource: authorization.Resource{Type: "oauth.platform", ID: authorization.ResourceID(p.Owner.PlatformID())}}})
}
func (s *Store) managementObservation(ctx context.Context, c oauth.ClientManagementExecution, action string) (oauth.ClientManagementExecution, error) {
	p := s.config.Protocol.ManagedClients
	if p == nil {
		return c, oauth.ErrAccessDenied
	}
	r, err := oauth.ValidateClientManagementRequest(c.Request, c.Delete, *p, s.config.Protocol.Issuer)
	if err != nil {
		return c, err
	}
	c.Request = r
	if c.ValidateAt(s.now()) != nil {
		return c, oauth.ErrAccessDenied
	}
	current, err := s.recoverySession(ctx, RecoveryRequest{TenantID: r.TenantID, Session: r.Session})
	if err != nil {
		return c, err
	}
	a, err := sessionpg.OriginalSessionFields(c.Session.Session)
	if err != nil {
		return c, oauth.ErrAccessDenied
	}
	b, err := sessionpg.OriginalSessionFields(current.Session)
	if err != nil || !sameJSON(a, b) {
		return c, oauth.ErrAccessDenied
	}
	bindings, _ := current.Session.Bindings()
	matched := false
	for _, key := range s.config.CSRFKeys {
		if current.Session.CSRFState().Check(session.CSRFBinding{TenantID: bindings.TenantID, SessionID: bindings.SessionID, SessionVersion: bindings.Version}, r.CSRF, key) == nil {
			matched = true
			break
		}
	}
	if !matched {
		return c, oauth.ErrAccessDenied
	}
	if err := s.managementDecision(ctx, bindings.UserID, action); err != nil {
		return c, err
	}
	return c, nil
}

// ManageClient authenticates the original manager and exact platform policy,
// then uses the existing immutable prepared request-key owner and sole Work.
// Generated secret custody exists only in encrypted native preparation and the
// fresh known-committed invocation; durable client authentication is digest-only.
func (s *Store) ManageClient(ctx context.Context, c oauth.ClientManagementExecution) (out oauth.ClientManagementResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.ClientManagementResult{Completion: oauth.Completion{Outcome: identity.CommitOutcomeUnknown}}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	action := "identity.oauth-server.client-create"
	if c.Delete {
		action = "identity.oauth-server.client-delete"
	}
	c, err = s.managementObservation(ctx, c, action)
	if err != nil {
		return out, err
	}
	p, err := s.clientManagementPhase(ctx, c, action)
	if err != nil {
		return out, err
	}
	if err = s.coordinator(p); err != nil {
		return out, err
	}
	intent, err := p.clientIntent(c.Request)
	if err != nil {
		return out, err
	}
	b, _ := c.Session.Session.Bindings()
	scope := kernel.RequestKeyScope{TenantID: b.TenantID, ActorID: identity.ActorID(b.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: action}
	caller := p.caller()
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(action)}
	k, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, c.Request.RequestKey, intent, caller, p.registration(), p)
	if err != nil {
		var conflict identity.ConflictError
		var unknown identity.UnknownCommitError
		if errors.As(err, &conflict) {
			out.Completion.Outcome = identity.CommitOutcomeConflict
		}
		if errors.As(err, &unknown) {
			out.Completion.Outcome = identity.CommitOutcomeUnknown
			out.Completion.CommandID = unknown.CommandID
		}
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	defer clear(wire)
	out.Completion = oauth.Completion{CommandID: k.Admission.CommandID, Outcome: identity.CommitOutcomeUnknown}
	if err = p.restoreClientKey(ctx, k, wire); err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	out.Client = p.client
	result, err := p.execute(ctx)
	out.Completion.Outcome, out.Completion.Replayed = result.Outcome, !p.applied
	if err != nil || ctx.Err() != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if c.ValidateAt(s.now()) != nil || !s.now().Before(p.input.ObservationUntil) {
		return oauth.ClientManagementResult{Completion: out.Completion}, oauth.ErrAccessDenied
	}
	if p.applied && result.Outcome == identity.CommitOutcomeCommitted && !c.Delete {
		out.Secret, err = oauth.ParseToken(p.output.ClientSecret)
	}
	return out, err
}
func (s *Store) clientManagementPhase(ctx context.Context, c oauth.ClientManagementExecution, action string) (*phase, error) {
	r := c.Request
	client := oauth.Client{ID: oauth.ManagedClientPrefix + "pending", Owner: s.config.Protocol.ManagedClients.Owner, Version: 1, Resource: s.config.Protocol.Resource, AuthenticationMethod: "client_secret_basic", Redirects: r.Redirects, Scopes: r.Scopes}
	version := uint64(0)
	transition := createManagedClient
	record := ""
	if c.Delete {
		existing, err := s.readManagedClient(ctx, r.ClientID)
		if err != nil {
			return nil, err
		}
		client = existing.Client
		version = r.Version
		transition = deleteManagedClient
		record = strings.TrimPrefix(client.ID, oauth.ManagedClientPrefix)
	}
	source, err := sessionpg.OriginalSessionFields(c.Session.Session)
	if err != nil {
		return nil, oauth.ErrAccessDenied
	}
	b, _ := c.Session.Session.Bindings()
	p := &phase{store: s, client: client, observation: c.Session, browser: r.Session, csrf: r.CSRF, clientManagement: &c, input: phaseInput{Schema: 1, Configuration: s.identity, Transition: transition, Grant: grantRecord{Tenant: b.TenantID, User: b.UserID, ClientID: client.ID, ClientVersion: client.Version, ClientFingerprint: clientFingerprint(client), Resource: client.Resource, Source: source, Scopes: slices.Clone(client.Scopes)}, Scopes: slices.Clone(client.Scopes), ClientChange: &clientMutation{Client: client, Version: version, Policy: s.managementPolicy()}, Intent: s.intent(action, r.ClientID)}}
	p.bind("", action, record)
	return p, nil
}

func (p *phase) clientIntent(r oauth.ClientManagementRequest) (identity.RequestIntent, error) {
	wire, err := json.Marshal(struct {
		Policy            [32]byte
		Delete            bool
		ID                string
		Version           uint64
		Redirects, Scopes []string
		Origin, Network   string
		Source            []identity.FeatureField
		RotationOverlap   *time.Duration `json:",omitempty"`
	}{p.store.managementPolicy(), p.input.Transition == deleteManagedClient, r.ClientID, r.Version, r.Redirects, r.Scopes, r.Origin, r.Network, p.input.Grant.Source, p.rotationOverlap()})
	if err != nil {
		return identity.RequestIntent{}, err
	}
	defer clear(wire)
	d := sha256.Sum256(wire)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "management-input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: d[:]}}})
}
func (p *phase) clientAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if p.input.ClientChange == nil || p.store.config.Protocol.ManagedClients == nil || k.Scope.TenantID != p.input.Grant.Tenant || k.Scope.ActorID != identity.ActorID(p.input.Grant.User) || k.Scope.ActorKind != authorization.SubjectUser || k.Scope.Method != "POST" || k.Scope.RouteID != p.input.Binding.OperationID || k.Feature != p.registration() || k.Namespace != p.store.config.RequestKeys.Namespace || k.PolicyVersion != p.store.config.RequestKeys.Policy.PolicyVersion || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	// The public custody type deliberately refuses generic serialization; bind
	// its explicit authenticated fields exactly as the native request owner does.
	wire, err := json.Marshal(struct {
		Namespace      string
		Scope          kernel.RequestKeyScope
		Admission      kernel.RequestKeyAdmission
		Feature        kernel.FeatureRegistration
		PolicyVersion  uint64
		Intent, Policy [32]byte
	}{k.Namespace, k.Scope, k.Admission, k.Feature, k.PolicyVersion, k.IntentDigest, p.store.managementPolicy()})
	if err != nil {
		return envelope.Context{}, err
	}
	defer clear(wire)
	d := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "oauth-managed-client-input-v1", "binding": base64.RawURLEncoding.EncodeToString(d[:])})
}
func (p *phase) prepareClientKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	aad, err := p.clientAAD(k)
	if err != nil || p.clientManagement == nil {
		return nil, identity.ForbiddenError{}
	}
	c := p.clientManagement
	if c.ValidateAt(p.store.now()) != nil {
		return nil, identity.ForbiddenError{}
	}
	expected, err := p.clientIntent(c.Request)
	a, ok := intent.Fields()
	b, valid := expected.Fields()
	if err != nil || !ok || !valid || !sameJSON(a, b) {
		return nil, identity.ForbiddenError{}
	}
	i := p.input
	client := i.ClientChange.Client
	if i.Transition == createManagedClient {
		client.ID = oauth.ManagedClientPrefix + string(k.Admission.CommandID)
		i.Binding.RecordID = string(k.Admission.CommandID)
	} else {
		r, err := p.store.readManagedClient(ctx, client.ID)
		if err != nil || r.State != "active" || r.Version != c.Request.Version || !p.store.config.ClientSecretRotation && r.Version != 1 {
			return nil, identity.ForbiddenError{}
		}
		client = r.Client
	}
	i.Binding.CommandID, i.Binding.CorrelationID = k.Admission.CommandID, string(k.Admission.CommandID)
	i.ClientChange = &clientMutation{Client: client, Version: i.ClientChange.Version, Policy: p.store.managementPolicy(), Overlap: i.ClientChange.Overlap}
	i.Grant.ClientID, i.Grant.ClientFingerprint = client.ID, clientFingerprint(client)
	i.CreatedAt, i.ObservationUntil, i.Network = p.store.now(), c.Session.ValidUntil(), c.Request.Network
	wire, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	sealed, err := p.store.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: wire, Context: aad, KeyReference: p.store.config.ActiveEnvelopeKeyID})
	if err != nil {
		return nil, err
	}
	return sealed.MarshalBinary()
}
func (p *phase) restoreClientKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
	aad, err := p.clientAAD(k)
	if err != nil {
		return err
	}
	if len(wire) == 0 || len(wire) > 262144 {
		return identity.ForbiddenError{}
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return identity.ForbiddenError{}
	}
	plain, err := p.store.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil {
		return identity.ForbiddenError{}
	}
	defer clear(plain)
	var original phaseInput
	if decodeJSON(plain, &original) != nil || original.ClientChange == nil || original.ClientChange.Policy != p.store.managementPolicy() || original.Transition != p.input.Transition || original.Configuration != p.store.identity || original.Binding.CommandID != k.Admission.CommandID || original.Binding.TenantID != p.input.Grant.Tenant || original.Binding.UserID != p.input.Grant.User || original.Binding.ActorID != identity.ActorID(p.input.Grant.User) || original.Binding.ActorKind != authorization.SubjectUser || original.Binding.OperationID != p.input.Binding.OperationID || original.ClientChange.Client.ID != oauth.ManagedClientPrefix+original.Binding.RecordID || !p.store.managedMetadata(original.ClientChange.Client) || !sameJSON(original.Grant.Source, p.input.Grant.Source) || original.Intent != p.input.Intent {
		return identity.ForbiddenError{}
	}
	if p.input.Transition != createManagedClient && original.ClientChange.Client.ID != p.client.ID {
		return identity.ForbiddenError{}
	}
	p.input, p.client = original, original.ClientChange.Client
	return nil
}

func (p *phase) checkClientChange(ctx context.Context, w kernel.Work, final bool) error {
	i := p.input
	if i.ClientChange.Policy != p.store.managementPolicy() {
		return identity.ForbiddenError{}
	}
	// The exact platform decision is made before protected Work. This digest
	// binds its immutable configured policy revision; the common phase admission
	// above fences the original actor's actual authorization epoch under lock.
	// Permission withdrawal must advance that existing owning epoch, not mutate
	// an unversioned callback and expect a new in-transaction policy authority.
	rows, err := w.Query(ctx, `SELECT version::text,state,registration FROM `+p.store.schema+`.managed_clients WHERE client_id=$1 FOR UPDATE`, p.client.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := rows.Next()
	if !found {
		if rows.Err() != nil {
			return rows.Err()
		}
		if i.Transition == createManagedClient && !p.applied {
			return nil
		}
		return identity.ForbiddenError{}
	}
	var version, state string
	var wire []byte
	if rows.Scan(&version, &state, &wire) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	wantVersion, wantState := uint64(1), "active"
	if i.Transition != createManagedClient {
		wantVersion = i.ClientChange.Version
	}
	if i.Transition == createManagedClient && !p.applied {
		return identity.ConflictError{}
	}
	if final && p.applied && i.Transition == deleteManagedClient {
		wantVersion, wantState = i.ClientChange.Version+1, "deleted"
	}
	wantClient := p.client
	if final && p.applied && i.Transition == rotateManagedSecret {
		wantVersion++
		wantClient.Version++
	}
	c, decodeErr := decodeRegistration(wire)
	if version != strconv.FormatUint(wantVersion, 10) || state != wantState || decodeErr != nil || clientFingerprint(c) != clientFingerprint(wantClient) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *phase) mutateClientChange(ctx context.Context, w kernel.Work) error {
	i := p.input
	var n int64
	var err error
	if i.Transition == createManagedClient {
		wire, e := json.Marshal(registrationWire(p.client))
		if e != nil {
			return e
		}
		defer clear(wire)
		n, err = w.Exec(ctx, `INSERT INTO `+p.store.schema+`.managed_clients(client_id,issuer,environment,platform_owner,tenant_id,version,registration,secret_digest,state,created_command,created_at) VALUES($1,$2,$3,$4,$5,1,$6::jsonb,$7,'active',$8,$9)`, p.client.ID, p.store.config.Protocol.Issuer.String(), p.store.config.Protocol.Environment, p.client.Owner.PlatformID(), string(i.Binding.TenantID), string(wire), p.output.ClientDigest, string(i.Binding.CommandID), i.CreatedAt)
	} else if i.Transition == rotateManagedSecret {
		client := p.client
		client.Version++
		wire, e := json.Marshal(registrationWire(client))
		if e != nil {
			return e
		}
		defer clear(wire)
		var expiry any
		if i.ClientChange.Overlap > 0 {
			expiry = i.CreatedAt.Add(i.ClientChange.Overlap)
		}
		n, err = w.Exec(ctx, `UPDATE `+p.store.schema+`.managed_clients SET version=version+1,registration=$4::jsonb,previous_secret_digest=CASE WHEN $5::timestamptz IS NULL THEN NULL ELSE secret_digest END,previous_secret_version=CASE WHEN $5::timestamptz IS NULL THEN NULL ELSE secret_version END,previous_secret_expires_at=$5,secret_digest=$6,secret_version=secret_version+1,rotated_command=$2,rotated_at=$3 WHERE client_id=$1 AND version=$7::numeric AND state='active'`, p.client.ID, string(i.Binding.CommandID), i.CreatedAt, string(wire), expiry, p.output.ClientDigest, strconv.FormatUint(i.ClientChange.Version, 10))
	} else if p.store.config.ClientSecretRotation {
		n, err = w.Exec(ctx, `UPDATE `+p.store.schema+`.managed_clients SET version=version+1,state='deleted',deleted_command=$2,deleted_at=$3,previous_secret_digest=NULL,previous_secret_version=NULL,previous_secret_expires_at=NULL WHERE client_id=$1 AND version=$4::numeric AND state='active'`, p.client.ID, string(i.Binding.CommandID), i.CreatedAt, strconv.FormatUint(i.ClientChange.Version, 10))
	} else {
		n, err = w.Exec(ctx, `UPDATE `+p.store.schema+`.managed_clients SET version=2,state='deleted',deleted_command=$2,deleted_at=$3 WHERE client_id=$1 AND version=1 AND state='active'`, p.client.ID, string(i.Binding.CommandID), i.CreatedAt)
	}
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	life := p.lifecycle()
	digest := effectDigest(i.Binding, p.registration(), life)
	n, err = w.Exec(ctx, `INSERT INTO `+p.store.schema+`.effects(tenant_id,command_id,operation_id,record_id,client_id,before_version,after_version,binding_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8)`, string(i.Binding.TenantID), string(i.Binding.CommandID), i.Binding.OperationID, i.Binding.RecordID, p.client.ID, strconv.FormatUint(life.BeforeVersion, 10), strconv.FormatUint(life.AfterVersion, 10), digest[:])
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// Recovery authenticates original encrypted preparation and current manager
// authority, including after terminal deletion. It never recreates execution
// custody, changes a client, or delivers retained secret material.
func (s *Store) recoverClientManagement(ctx context.Context, r RecoveryRequest) (out RecoveryResult, err error) {
	policy := s.config.Protocol.ManagedClients
	if policy == nil || r.TenantID != policy.TenantID || r.Token != "" || r.ConsentID != "" || r.ClientAuthentication.Method() != "none" || !strings.HasPrefix(r.ClientID, oauth.ManagedClientPrefix) {
		return out, oauth.ErrAccessDenied
	}
	record := strings.TrimPrefix(r.ClientID, oauth.ManagedClientPrefix)
	if _, err := identity.ParseSubjectID(record); err != nil {
		return out, oauth.ErrInvalidRequest
	}
	if r.OperationID == "identity.oauth-server.client-create" && record != string(r.CommandID) {
		return out, oauth.ErrAccessDenied
	}
	observed, err := s.recoverySession(ctx, r)
	if err != nil {
		return out, err
	}
	execution := oauth.ClientManagementExecution{Request: oauth.ClientManagementRequest{TenantID: r.TenantID, Session: r.Session}, Session: observed, Delete: r.OperationID == "identity.oauth-server.client-delete"}
	if execution.ValidateAt(s.now()) != nil {
		return out, oauth.ErrAccessDenied
	}
	b, _ := observed.Session.Bindings()
	if err := s.managementDecision(ctx, b.UserID, r.OperationID); err != nil {
		return out, err
	}
	source, err := sessionpg.OriginalSessionFields(observed.Session)
	if err != nil {
		return out, oauth.ErrAccessDenied
	}
	transition, version := createManagedClient, uint64(0)
	intentID := ""
	if execution.Delete {
		transition, version, intentID = deleteManagedClient, 1, r.ClientID
	}
	if r.OperationID == "identity.oauth-server.client-rotate-secret" {
		if !s.config.ClientSecretRotation {
			return out, oauth.ErrAccessDenied
		}
		transition, version, intentID = rotateManagedSecret, 1, r.ClientID
	}
	client := oauth.Client{ID: r.ClientID, Owner: policy.Owner, Version: 1, Resource: s.config.Protocol.Resource, AuthenticationMethod: "client_secret_basic", Redirects: policy.Redirects, Scopes: policy.Scopes.Scopes()}
	p := &phase{store: s, client: client, observation: observed, input: phaseInput{Schema: 1, Configuration: s.identity, Transition: transition, Grant: grantRecord{Tenant: b.TenantID, User: b.UserID, Source: source}, ClientChange: &clientMutation{Client: client, Version: version, Policy: s.managementPolicy()}, Intent: s.intent(r.OperationID, intentID)}}
	p.bind(r.CommandID, r.OperationID, record)
	if err := s.coordinator(p); err != nil {
		return out, err
	}
	binding, wire, err := p.coordinator.QueryRequestPreparation(ctx, p.query(), p.caller(), p.registration(), p)
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	defer clear(wire)
	if err := p.restoreClientKey(ctx, binding, wire); err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	admission, err := p.coordinator.ObserveCommandAdmission(ctx, p.query(), p.caller())
	if err != nil && (admission.Validate() != nil || admission.Absent) {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if admission.Absent {
		return out, oauth.ErrAccessDenied
	}
	if admission.Record.Outcome == identity.CommitOutcomeInProgress {
		prepared, generation, err := p.coordinator.QueryFeaturePreparation(ctx, p.query(), p.caller(), p.registration(), p)
		if err != nil {
			return out, publicError(ctx, err, oauth.ErrAccessDenied)
		}
		defer clear(prepared)
		if err := p.restore(ctx, generation, prepared, true); err != nil {
			return out, publicError(ctx, err, oauth.ErrAccessDenied)
		}
	}
	// Terminal reconciliation can retire generated output. The immutable native
	// request preparation above still authenticates original manager/client/input;
	// only the coordinator's retained journal decides terminal durability.
	p.output = preparedOutput{}
	if execution.ValidateAt(s.now()) != nil || s.managementDecision(ctx, b.UserID, r.OperationID) != nil {
		return out, oauth.ErrAccessDenied
	}
	result, err := p.coordinator.RecoverFeatureCommand(ctx, p.query(), p.caller())
	out = RecoveryResult{Outcome: result.Outcome, CommandID: r.CommandID, RetryAfter: result.RetryAfter}
	return out, publicError(ctx, err, oauth.ErrAccessDenied)
}
