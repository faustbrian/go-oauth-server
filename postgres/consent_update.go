package oauthpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

var _ oauth.ConsentUpdater = (*Store)(nil)
var _ kernel.RequestKeyPreparationContributor = (*phase)(nil)

// ConsentUpdate retains original input in the kernel's existing immutable
// request-key mapping, then uses the sole coordinator's normal prepared Work.
// The mapping is correlation only: original session custody is authenticated
// before resolving it and again before mutation/recovery. No credentials return.
func (s *Store) ConsentUpdate(ctx context.Context, c oauth.ConsentUpdateExecution) (out oauth.ConsentUpdateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.ConsentUpdateResult{Completion: oauth.Completion{Outcome: identity.CommitOutcomeUnknown}}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if !s.config.ConsentNarrowing {
		return out, oauth.ErrAccessDenied
	}
	r, err := c.Request.Validated()
	if err != nil {
		return out, err
	}
	c.Request = r
	client, err := s.checkedClient(ctx, c.Client)
	if err != nil || client.Workload != nil || client.ID != r.ClientID || client.Version != r.ClientVersion || client.Resource != r.Resource || !scopeSubset(r.Scopes, client.Scopes) {
		return out, oauth.ErrAccessDenied
	}
	_, caller, err := s.consentObservation(ctx, oauth.ConsentExecution{Command: r.Consent, Session: c.Session}, oauth.ConsentNarrow)
	if err != nil {
		return out, err
	}
	source, err := sessionpg.OriginalSessionFields(c.Session.Session)
	if err != nil {
		return out, oauth.ErrAccessDenied
	}
	p := s.consentNarrowPhase(client, c.Session, r.Consent.Input().ID, "", source)
	p.browser, p.csrf, p.consentCommand, p.consentUpdate = r.Consent.Input().Session, r.Consent.Input().CSRF, r.Consent, &c
	if err := s.coordinator(p); err != nil {
		return out, err
	}
	intent, err := p.narrowingIntent(r, source)
	if err != nil {
		return out, err
	}
	b, _ := c.Session.Session.Bindings()
	scope := kernel.RequestKeyScope{TenantID: b.TenantID, ActorID: identity.ActorID(b.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: "identity.oauth-server.consent-update"}
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	k, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.RequestKey, intent, caller, p.registration(), p)
	if err != nil {
		var conflict identity.ConflictError
		var unknown identity.UnknownCommitError
		if errors.As(err, &conflict) {
			out.Completion.Outcome = identity.CommitOutcomeConflict
			return out, err
		}
		if errors.As(err, &unknown) {
			out.Completion.Outcome = identity.CommitOutcomeUnknown
			out.Completion.CommandID = unknown.CommandID
		}
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	defer clear(wire)
	out.Completion = oauth.Completion{CommandID: k.Admission.CommandID, Outcome: identity.CommitOutcomeUnknown}
	if err := p.restoreNarrowingRequest(ctx, k, wire); err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	result, err := p.execute(ctx)
	out.Completion.Outcome, out.Completion.Replayed = result.Outcome, !p.applied
	out.Updated = err == nil && result.Outcome == identity.CommitOutcomeCommitted
	return out, publicError(ctx, err, oauth.ErrAccessDenied)
}

func (s *Store) consentNarrowPhase(client oauth.Client, observed session.GetResult, id string, command identity.CommandID, source []identity.FeatureField) *phase {
	b, _ := observed.Session.Bindings()
	p := &phase{store: s, client: client, observation: observed, input: phaseInput{Schema: 1, Configuration: s.identity, Transition: narrowConsent, Grant: grantRecord{Tenant: b.TenantID, User: b.UserID, ClientID: client.ID, ClientVersion: client.Version, ClientFingerprint: clientFingerprint(client), Source: source, Resource: client.Resource}, Intent: s.intent("consent-update", id), Narrowing: &consentDeletion{ID: id}}}
	p.bind(command, "identity.oauth-server.consent-update", id)
	return p
}

func (p *phase) narrowingIntent(r oauth.ConsentUpdateRequest, source []identity.FeatureField) (identity.RequestIntent, error) {
	i := r.Consent.Input()
	frame, err := json.Marshal(struct {
		Profile         string
		Configuration   [32]byte
		ID              string
		Version         uint64
		Client          string
		ClientVersion   uint64
		Resource        string
		Scopes          []string
		Origin, Network string
		Source          []identity.FeatureField
	}{"oauth-consent-narrow-input-v1", p.store.identity, i.ID, i.Version, r.ClientID, r.ClientVersion, r.Resource, r.Scopes, i.Origin, i.Network, source})
	if err != nil {
		return identity.RequestIntent{}, oauth.ErrInvalidRequest
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.store.identity[:]}}, {Name: "input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}})
}

func (p *phase) narrowingAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if !p.store.config.ConsentNarrowing || p.input.Transition != narrowConsent || k.Namespace != p.store.config.RequestKeys.Namespace || k.Scope.Method != "POST" || k.Scope.RouteID != "identity.oauth-server.consent-update" || k.Scope.TenantID != p.input.Grant.Tenant || k.Scope.ActorID != identity.ActorID(p.input.Grant.User) || k.Scope.ActorKind != authorization.SubjectUser || k.Feature != p.registration() || k.PolicyVersion != p.store.config.RequestKeys.Policy.PolicyVersion || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	frame, err := json.Marshal(struct {
		Namespace             string
		Scope                 kernel.RequestKeyScope
		Admission             kernel.RequestKeyAdmission
		Feature               kernel.FeatureRegistration
		Policy                uint64
		Intent, Configuration [32]byte
	}{k.Namespace, k.Scope, k.Admission, k.Feature, k.PolicyVersion, k.IntentDigest, p.store.identity})
	if err != nil {
		return envelope.Context{}, oauth.ErrUnavailable
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "oauth-consent-narrow-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *phase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	if p.input.ClientChange != nil {
		return p.prepareClientKey(ctx, k, intent)
	}
	aad, err := p.narrowingAAD(k)
	if err != nil || p.consentUpdate == nil {
		return nil, identity.ForbiddenError{}
	}
	r := p.consentUpdate.Request
	expected, err := p.narrowingIntent(r, p.input.Grant.Source)
	if err != nil {
		return nil, err
	}
	a, ok := intent.Fields()
	b, valid := expected.Fields()
	if !ok || !valid || !sameJSON(a, b) {
		return nil, identity.ForbiddenError{}
	}
	if (oauth.ConsentExecution{Command: r.Consent, Session: p.observation}).ValidateAt(p.store.now()) != nil {
		return nil, identity.ForbiddenError{}
	}
	record, err := p.store.readConsent(ctx, p.input.Grant.Tenant, p.input.Grant.User, r.Consent.Input().ID)
	if err != nil {
		return nil, err
	}
	client, err := p.store.consentClient(ctx, record)
	if err != nil || client.ID != p.client.ID || record.State != "active" || record.Version != r.Consent.Input().Version || record.Version == math.MaxUint64 || record.Generation == math.MaxUint64 || len(r.Scopes) >= len(record.Scopes) || !scopeSubset(r.Scopes, record.Scopes) {
		return nil, identity.ForbiddenError{}
	}
	i := p.input
	i.Binding.CommandID, i.Binding.CorrelationID = k.Admission.CommandID, string(k.Admission.CommandID)
	i.Narrowing = &consentDeletion{ID: record.ID, Version: record.Version, Generation: record.Generation}
	i.Grant.Scopes, i.Scopes = slices.Clone(record.Scopes), slices.Clone(r.Scopes)
	i.CreatedAt, i.ObservationUntil, i.Network = p.store.now(), p.observation.ValidUntil(), r.Consent.Input().Network
	plain, err := json.Marshal(i)
	if err != nil {
		return nil, oauth.ErrUnavailable
	}
	defer clear(plain)
	sealed, err := p.store.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, Context: aad, KeyReference: p.store.config.ActiveEnvelopeKeyID})
	if err != nil {
		return nil, err
	}
	return sealed.MarshalBinary()
}

func (p *phase) restoreNarrowingRequest(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
	aad, err := p.narrowingAAD(k)
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
	if decodeJSON(plain, &original) != nil || original.Schema != 1 || original.Transition != narrowConsent || original.Configuration != p.store.identity || original.Narrowing == nil || original.Narrowing.ID != p.input.Binding.RecordID || original.Binding.CommandID != k.Admission.CommandID || original.Binding.TenantID != p.input.Grant.Tenant || original.Binding.UserID != p.input.Grant.User || original.Binding.ActorID != identity.ActorID(p.input.Grant.User) || original.Binding.ActorKind != authorization.SubjectUser || original.Grant.ClientID != p.client.ID || original.Grant.ClientVersion != p.client.Version || original.Grant.ClientFingerprint != clientFingerprint(p.client) || original.Grant.Resource != p.client.Resource || !sameJSON(original.Grant.Source, p.input.Grant.Source) || original.Intent != p.input.Intent {
		return identity.ForbiddenError{}
	}
	if p.consentUpdate != nil && (original.Narrowing.Version != p.consentUpdate.Request.Consent.Input().Version || !slices.Equal(original.Scopes, p.consentUpdate.Request.Scopes) || original.Network != p.consentUpdate.Request.Consent.Input().Network) {
		return identity.ForbiddenError{}
	}
	p.input = original
	return nil
}

func (p *phase) checkConsentNarrowing(ctx context.Context, w kernel.Work, final bool) error {
	d := p.input.Narrowing
	if !p.store.config.ConsentNarrowing || d == nil || d.ID != p.input.Binding.RecordID {
		return identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT version::text,generation::text,state,client_version::text,client_fingerprint,scopes FROM `+p.store.schema+`.consents WHERE consent_id=$1 AND tenant_id=$2 AND user_id=$3 AND client_id=$4 FOR UPDATE`, d.ID, string(p.input.Grant.Tenant), string(p.input.Grant.User), p.client.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return rows.Err()
		}
		return identity.ForbiddenError{}
	}
	var version, generation, state, clientVersion string
	var fp, scopes []byte
	if rows.Scan(&version, &generation, &state, &clientVersion, &fp, &scopes) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	v, g, expectedScopes := d.Version, d.Generation, p.input.Grant.Scopes
	if final && p.applied {
		v++
		g++
		expectedScopes = p.input.Scopes
	}
	var actual []string
	fingerprint := clientFingerprint(p.client)
	if version != strconv.FormatUint(v, 10) || generation != strconv.FormatUint(g, 10) || state != "active" || clientVersion != strconv.FormatUint(p.client.Version, 10) || !slices.Equal(fp, fingerprint[:]) || decodeJSON(scopes, &actual) != nil || !slices.Equal(actual, expectedScopes) || len(p.input.Scopes) >= len(p.input.Grant.Scopes) || !scopeSubset(p.input.Scopes, p.input.Grant.Scopes) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *phase) mutateConsentNarrowing(ctx context.Context, w kernel.Work) error {
	i, d := p.input, p.input.Narrowing
	scopes, err := json.Marshal(i.Scopes)
	if err != nil {
		return err
	}
	defer clear(scopes)
	n, err := w.Exec(ctx, `UPDATE `+p.store.schema+`.consents SET scopes=$4::jsonb,version=version+1,generation=generation+1 WHERE consent_id=$1 AND version=$2::numeric AND generation=$3::numeric AND state='active'`, d.ID, strconv.FormatUint(d.Version, 10), strconv.FormatUint(d.Generation, 10), string(scopes))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	life := p.lifecycle()
	digest := effectDigest(i.Binding, p.registration(), life)
	n, err = w.Exec(ctx, `INSERT INTO `+p.store.schema+`.effects(tenant_id,command_id,operation_id,record_id,consent_id,before_version,after_version,binding_digest) VALUES($1,$2,$3,$4,$4,$5::numeric,$6::numeric,$7)`, string(i.Binding.TenantID), string(i.Binding.CommandID), i.Binding.OperationID, d.ID, strconv.FormatUint(life.BeforeVersion, 10), strconv.FormatUint(life.AfterVersion, 10), digest[:])
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
