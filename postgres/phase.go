package oauthpostgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type generatedArtifact struct {
	ID                 string
	Kind               oauth.TokenKind
	Wire               string
	Digest             oauth.TokenDigest
	ExpiresAt          time.Time
	Transition, Replay identity.CommandID
}
type preparedOutput struct {
	Schema     uint32
	Generation uint64
	Input      phaseInput
	Artifacts  []generatedArtifact
}

// Generated credentials exist only in invocation memory or the existing
// coordinator's authenticated encrypted preparation, never scalar commands.
func (preparedOutput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth prepared output(redacted)"))
}
func (generatedArtifact) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth generated artifact(redacted)"))
}

type phase struct {
	store             *Store
	client            oauth.Client
	input             phaseInput
	browser           auth.BearerCredential
	csrf              session.CSRFToken
	observation       session.GetResult
	command           identity.Command
	declaration, plan kernel.CommandPlan
	counters          kernel.CommandCounterPlan
	registry          *kernel.ContributorRegistry
	coordinator       *kernel.Coordinator
	output            preparedOutput
	applied           bool
}

var _ kernel.FeaturePreparationContributor = (*phase)(nil)
var _ kernel.FeatureCommitContributor = (*phase)(nil)
var _ kernel.OAuthConsentContributor = (*phase)(nil)

func (*phase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "oauth-server/postgres", ContractID: "identity.oauth-server", Version: 1}
}
func operation(name string) identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "oauth-server", OperationID: name, SchemaID: name + ".public-password-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func workloadOperation(name string) identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "oauth-server", OperationID: name, SchemaID: name + ".configured-workload-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}
func (p *phase) operation(name string) identity.FeatureOperation {
	if p.input.Grant.Workload != nil {
		return workloadOperation(name)
	}
	return operation(name)
}
func (*phase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{operation("identity.oauth-server.authorize"), operation("identity.oauth-server.continue"), operation("identity.oauth-server.token"), operation("identity.oauth-server.revoke"), workloadOperation("identity.oauth-server.token"), workloadOperation("identity.oauth-server.revoke")}
}
func (p *phase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation(p.input.Binding.OperationID)}
}

// Protocol operation IDs and security action names intentionally differ. The
// closed taxonomy is SECURITY_EVENTS.md's OAuth server row; consent approval
// and replay revocation each declare their distinct composed actions once.
func (p *phase) auditActions() []string {
	switch p.input.Transition {
	case createInteraction, createWorkload:
		return []string{"identity.oauth_server.authorize"}
	case approveInteraction:
		return []string{"identity.oauth_server.grant_consent", "identity.oauth_server.authorize"}
	case exchangeCode:
		return []string{"identity.oauth_server.exchange_code"}
	case rotateRefresh:
		return []string{"identity.oauth_server.rotate_refresh"}
	case rejectReplay:
		if p.input.TargetKind == oauth.TokenRefresh {
			return []string{"identity.oauth_server.detect_refresh_reuse", "identity.oauth_server.revoke_token"}
		}
	}
	// Denial consumes/revokes the pending interaction grant; it does not revoke
	// an unrelated previously granted consent or report an authorization allow.
	return []string{"identity.oauth_server.revoke_token"}
}
func (p *phase) auditPlans(digest [32]byte) []kernel.AuditPlan {
	actions := p.auditActions()
	plans := make([]kernel.AuditPlan, len(actions))
	for i, action := range actions {
		plans[i] = kernel.AuditPlan{EventType: action, EventIndex: uint16(i), SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}
	}
	return plans
}
func (p *phase) lifecycle() kernel.LifecyclePlan {
	before := p.input.Grant.Version
	event := "grant.revoked.v1"
	switch p.input.Transition {
	case createInteraction, createWorkload:
		event = "grant.created.v1"
	case approveInteraction:
		event = "grant.authorized.v1"
		if !slices.Equal(p.input.Scopes, p.input.Grant.Scopes) {
			event = "grant.scope_changed.v1"
		}
	case exchangeCode:
		event = "grant.code_exchanged.v1"
	case rotateRefresh:
		event = "grant.refresh_rotated.v1"
	case revokeAccess:
		before = 0
		event = "oauth_access.revoked.v1"
	}
	return kernel.LifecyclePlan{EventType: event, BeforeVersion: before, AfterVersion: before + 1}
}

func (p *phase) subjectType() string {
	if p.input.Transition == revokeAccess {
		return "oauth_token"
	}
	return "oauth_grant"
}

func (p *phase) execute(ctx context.Context) (result identity.CommandResult, executeErr error) {
	defer func() {
		if recover() != nil {
			result = identity.CommandResult{Binding: p.input.Binding, Outcome: identity.CommitOutcomeUnknown}
			executeErr = identity.UnknownCommitError{CommandID: p.input.Binding.CommandID}
		}
	}()
	if err := p.store.coordinator(p); err != nil {
		return identity.CommandResult{}, err
	}
	policy := p.store.config.Coordinator.AdmissionPolicy
	caller := p.caller()
	caller.Request.Environment.Time = policy.Clock.Now().UTC()
	decision, err := policy.Authorization.Decide(ctx, caller)
	if err != nil {
		return identity.CommandResult{}, oauth.ErrUnavailable
	}
	if ctx.Err() != nil {
		return identity.CommandResult{}, ctx.Err()
	}
	if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(policy.PolicyVersion) {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	admission, err := p.coordinator.ObserveCommandAdmission(ctx, p.query(), p.caller())
	if err != nil {
		return identity.CommandResult{}, err
	}
	if !admission.Absent {
		// A terminal result is historical metadata, never an instruction to
		// decrypt/redeliver output or reconstruct today's aggregate as success.
		if admission.Record.Outcome != identity.CommitOutcomeInProgress {
			return p.coordinator.RecoverFeatureCommand(ctx, p.query(), p.caller())
		}
		wire, generation, err := p.coordinator.QueryFeaturePreparation(ctx, p.query(), p.caller(), p.registration(), p)
		if err != nil {
			return identity.CommandResult{Binding: p.input.Binding, Outcome: identity.CommitOutcomeUnknown}, identity.UnknownCommitError{CommandID: p.input.Binding.CommandID}
		}
		defer clear(wire)
		if err := p.restore(ctx, generation, wire, true); err != nil {
			return identity.CommandResult{}, err
		}
	}
	if err := p.buildCommand(); err != nil {
		return identity.CommandResult{}, err
	}
	return p.coordinator.ExecutePreparedFeature(ctx, p.command, p.plan)
}

func (p *phase) buildCommand() error {
	i := p.input
	b := i.Binding
	if i.Schema != 1 || i.Configuration != p.store.identity || b.ValidateFor(p.operation(b.OperationID)) != nil || i.Grant.Version == math.MaxUint64 || i.Grant.ClientFingerprint != clientFingerprint(p.client) || i.Grant.ClientID != p.client.ID || i.Intent == ([32]byte{}) || i.CreatedAt.IsZero() || i.CreatedAt.Nanosecond()%1000 != 0 || !scopeSubset(i.Scopes, i.Grant.Scopes) {
		return oauth.ErrInvalidRequest
	}
	if i.Transition == approveInteraction {
		if _, err := identity.ParseSubjectID(i.Consent.ID); err != nil || i.Consent.BeforeVersion == math.MaxUint64 || i.Consent.AfterVersion != i.Consent.BeforeVersion+1 || i.Consent.Created != (i.Consent.BeforeVersion == 0) {
			return oauth.ErrInvalidRequest
		}
	} else if i.Consent != (consentMutation{}) {
		return oauth.ErrInvalidRequest
	}
	// This fixed native codec commits every nonsecret typed input, including
	// original owner fields, with a scalar commitment. It never places JSON or
	// credential wire bytes in FeatureFields. The original encrypted preparation
	// authenticates the same complete typed projection during restoration.
	frame, err := json.Marshal(i)
	if err != nil {
		return oauth.ErrInvalidRequest
	}
	commitment := sha256.Sum256(frame)
	clear(frame)
	fields := slices.Clone(i.Grant.Source)
	fields = append(fields,
		identity.FeatureField{Name: "oauth.input-commitment", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: commitment[:]}},
		identity.FeatureField{Name: "oauth.caller-intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: i.Intent[:]}},
		identity.FeatureField{Name: "oauth.configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: i.Configuration[:]}},
		identity.FeatureField{Name: "oauth.created-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: i.CreatedAt}},
		identity.FeatureField{Name: "oauth.transition", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(i.Transition)}},
		identity.FeatureField{Name: "oauth.grant", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: i.Grant.ID}},
		identity.FeatureField{Name: "oauth.client", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: i.Grant.ClientID}},
		identity.FeatureField{Name: "oauth.grant-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.Grant.Version}},
	)
	if i.Transition == approveInteraction {
		fields = append(fields,
			identity.FeatureField{Name: "oauth.consent-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: i.Consent.ID}},
			identity.FeatureField{Name: "oauth.consent-before-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.Consent.BeforeVersion}},
			identity.FeatureField{Name: "oauth.consent-after-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.Consent.AfterVersion}},
			identity.FeatureField{Name: "oauth.consent-created", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: i.Consent.Created}},
		)
	}
	spec := identity.FeatureCommandSpec{Binding: b, Operation: p.operation(b.OperationID), Fields: fields}
	var command identity.Command
	if p.browserRequired() {
		command, err = identity.NewFeatureSessionCommand(spec, p.browser)
	} else {
		command, err = identity.NewFeatureCommand(spec)
	}
	if err != nil {
		return err
	}
	// Privileged risk's exact dimensions are actor/resource/network; its
	// public Subject contract rejects extra User/session dimensions rather
	// than silently ignoring a different authority scope.
	command, counters, err := p.store.counters.PrepareCommandCounters(command, risk.Subject{Actor: string(b.ActorID), Resource: b.RecordID, Network: i.Network}, i.CreatedAt)
	if err != nil {
		return err
	}
	p.command, p.counters = command, counters
	life := p.lifecycle()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return err
	}
	actorKind := audit.ActorHuman
	if i.Grant.Workload != nil {
		actorKind = audit.ActorService
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: i.CreatedAt, Action: p.auditActions()[0], Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: actorKind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: p.subjectType(), ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": p.subjectType(), "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(life.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(life.AfterVersion, 10), "retention.class": "protected"}})
	if err != nil {
		return err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, p.operation(b.OperationID), p.subjectType(), seed)
	if err != nil {
		return err
	}
	p.declaration = kernel.CommandPlan{Contributors: p.registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation(b.OperationID)}, SubjectType: p.subjectType(), CommandCounters: &counters, Lifecycle: &life, Audits: p.auditPlans(digest)}
	p.plan, err = p.coordinator.PrepareFeaturePreparationPlan(command, p.declaration)
	return err
}

func (p *phase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || c != p.command {
		return identity.ForbiddenError{}
	}
	copy := plan
	copy.Digest = [32]byte{}
	if !reflect.DeepEqual(copy, p.declaration) {
		return identity.ForbiddenError{}
	}
	return nil
}

// ValidateOAuthConsent is the closed public native owner's pure custody check.
// No declaration alone records consent: mutate must report its actual successful
// SQL receipt to the same Work before the kernel may stage the secondary event.
func (p *phase) ValidateOAuthConsent(c identity.Command) error {
	if p == nil || c != p.command || p.input.Transition != approveInteraction || p.input.Binding.OperationID != "identity.oauth-server.continue" || p.input.Consent.ID == p.input.Grant.ID || p.input.Grant.ClientID != p.client.ID {
		return identity.ForbiddenError{}
	}
	s, ok := c.Feature()
	if !ok || s.Binding != p.input.Binding || s.Operation != operation("identity.oauth-server.continue") {
		return identity.ForbiddenError{}
	}
	consent := p.input.Consent
	if _, err := identity.ParseSubjectID(consent.ID); err != nil || consent.BeforeVersion == math.MaxUint64 || consent.AfterVersion != consent.BeforeVersion+1 || consent.Created != (consent.BeforeVersion == 0) {
		return identity.ForbiddenError{}
	}
	matched := 0
	for _, field := range s.Fields {
		switch field.Name {
		case "oauth.client":
			if field.Value.Kind != identity.FeatureText || field.Value.Text != p.client.ID {
				return identity.ForbiddenError{}
			}
			matched++
		case "oauth.consent-id":
			if field.Value.Kind != identity.FeatureText || field.Value.Text != consent.ID {
				return identity.ForbiddenError{}
			}
			matched++
		case "oauth.consent-before-version":
			if field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != consent.BeforeVersion {
				return identity.ForbiddenError{}
			}
			matched++
		case "oauth.consent-after-version":
			if field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != consent.AfterVersion {
				return identity.ForbiddenError{}
			}
			matched++
		case "oauth.consent-created":
			if field.Value.Kind != identity.FeatureBool || field.Value.Bool != consent.Created {
				return identity.ForbiddenError{}
			}
			matched++
		}
	}
	if matched != 5 {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *phase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (p *phase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	return p.check(ctx, w, false)
}
func (p *phase) browserRequired() bool {
	return p.input.Transition == createInteraction || p.input.Transition == approveInteraction || p.input.Transition == denyInteraction
}
func (p *phase) issuing() bool {
	return p.input.Transition == createInteraction || p.input.Transition == approveInteraction || p.input.Transition == exchangeCode || p.input.Transition == rotateRefresh || p.input.Transition == createWorkload
}

func (p *phase) check(ctx context.Context, w kernel.Work, final bool) error {
	b, feature, life, err := w.FeatureScope(p)
	if err != nil || b != p.input.Binding || feature != p.registration() || life != p.lifecycle() {
		return identity.ForbiddenError{}
	}
	i := p.input
	g := i.Grant
	if g.ClientFingerprint != clientFingerprint(p.client) || g.ClientVersion != p.client.Version || g.ClientID != p.client.ID || i.Configuration != p.store.identity {
		return identity.ForbiddenError{}
	}
	if g.Workload != nil {
		if !p.store.validWorkload(g, p.client) || b.UserID != "" || b.AnonymousFlowID != g.ID || b.ActorKind != authorization.SubjectServiceAccount || string(b.ActorID) != g.Workload.ID {
			return identity.ForbiddenError{}
		}
		if p.issuing() {
			if err := p.checkWorkload(ctx, w); err != nil {
				return err
			}
		}
	} else if p.client.Workload != nil {
		return identity.ForbiddenError{}
	}
	// Public-client revocation is authorized by exact client-bound token
	// possession, not by an active end-user browser. Disabling an account must
	// not prevent revoking its old grant. Issuance always checks current epochs.
	if p.browserRequired() || i.Transition == exchangeCode || i.Transition == rotateRefresh {
		original, err := sessionpg.OriginalSessionFromFields(g.Tenant, g.User, g.Source)
		if err != nil {
			return identity.ForbiddenError{}
		}
		directory, credential, authorization, err := sessionpg.OriginalSessionAdmission(p.store.config.Session.Profile, original, b)
		if err != nil {
			return err
		}
		if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
			return err
		}
		if _, err := w.RequireActiveActorCredential(ctx, p, credential); err != nil {
			return err
		}
		if err := w.RequireActiveActorAuthorization(ctx, p, authorization); err != nil {
			return err
		}
		if p.browserRequired() {
			if err := p.checkBrowser(original); err != nil {
				return err
			}
			if err := sessionpg.RequireSession(ctx, w, p.store.config.Session.Repository, original); err != nil {
				return err
			}
			if i.Transition != createInteraction {
				var checked bool
				for _, key := range p.store.config.CSRFKeys {
					if original.CSRFState().Check(session.CSRFBinding{TenantID: g.Tenant, SessionID: p.sessionID(original), SessionVersion: p.sessionVersion(original)}, p.csrf, key) == nil {
						if err := sessionpg.RequireCSRF(ctx, w, p.store.config.Session.Repository, original, p.csrf, key); err != nil {
							return err
						}
						checked = true
						break
					}
				}
				if !checked {
					return identity.ForbiddenError{}
				}
			}
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if p.browserRequired() && (p.observation.ValidateAt(now) != nil || !now.Before(i.ObservationUntil)) {
		return identity.ForbiddenError{}
	}
	if p.issuing() && (!now.Before(g.ExpiresAt) || !i.TargetExpires.IsZero() && !now.Before(i.TargetExpires)) {
		return identity.ForbiddenError{}
	}
	if final && p.issuing() {
		for _, artifact := range p.output.Artifacts {
			if !now.Before(artifact.ExpiresAt) {
				return identity.ForbiddenError{}
			}
		}
	}
	if i.Transition == createInteraction || i.Transition == createWorkload {
		return nil
	}
	workloadColumn := "NULL::jsonb"
	if workloadSelected(p.store.config.Protocol.Clients) {
		workloadColumn = "workload_source"
	}
	rows, err := w.Query(ctx, `SELECT state,version::text,client_version::text,client_fingerprint,source_session,scopes,resource,expires_at,`+workloadColumn+` FROM `+p.store.schema+`.grants WHERE grant_id=$1 AND tenant_id=$2 AND COALESCE(user_id,'')=$3 AND client_id=$4 FOR UPDATE`, g.ID, string(g.Tenant), string(g.User), g.ClientID)
	if err != nil {
		return err
	}
	var state, version, clientVersion, resource string
	var fingerprint, source, scopes, workload []byte
	var expires time.Time
	if !rows.Next() {
		rows.Close()
		return identity.ForbiddenError{}
	}
	err = rows.Scan(&state, &version, &clientVersion, &fingerprint, &source, &scopes, &resource, &expires, &workload)
	extra := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	if err != nil || extra || rowErr != nil {
		return identity.UnavailableError{}
	}
	expectedVersion := g.Version
	if final && p.applied && i.Transition != revokeAccess {
		expectedVersion++
	}
	if version != strconv.FormatUint(expectedVersion, 10) || clientVersion != strconv.FormatUint(g.ClientVersion, 10) || subtle.ConstantTimeCompare(fingerprint, g.ClientFingerprint[:]) != 1 || resource != g.Resource || !expires.Equal(g.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	var originalFields []identity.FeatureField
	if decodeJSON(source, &originalFields) != nil || !sameJSON(originalFields, g.Source) {
		return identity.ForbiddenError{}
	}
	if g.Workload != nil {
		var actual workloadSource
		if decodeJSON(workload, &actual) != nil || !sameJSON(actual, *g.Workload) {
			return identity.ForbiddenError{}
		}
	} else if len(workload) > 0 {
		return identity.ForbiddenError{}
	}
	expectedScopes := g.Scopes
	if final && p.applied && i.Transition == approveInteraction {
		expectedScopes = i.Scopes
	}
	var actualScopes []string
	if decodeJSON(scopes, &actualScopes) != nil || !slices.Equal(actualScopes, expectedScopes) {
		return identity.ForbiddenError{}
	}
	expectedState := "active"
	if final && p.applied && (i.Transition == denyInteraction || i.Transition == rejectReplay || i.Transition == revokeFamily) {
		expectedState = "revoked"
	}
	if state != expectedState {
		return identity.ForbiddenError{}
	}
	if err := p.checkTarget(ctx, w, now, final); err != nil {
		return err
	}
	return p.checkConsent(ctx, w, final)
}

func (p *phase) checkConsent(ctx context.Context, w kernel.Work, final bool) error {
	if p.input.Transition != approveInteraction {
		return nil
	}
	i := p.input
	g, c := i.Grant, i.Consent
	rows, err := w.Query(ctx, `SELECT consent_id,version::text,client_version::text,scopes,granted_at FROM `+p.store.schema+`.consents WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3 FOR UPDATE`, string(g.Tenant), string(g.User), g.ClientID)
	if err != nil {
		return err
	}
	if !rows.Next() {
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			return rowErr
		}
		if c.Created && !(final && p.applied) {
			return nil
		}
		return identity.ForbiddenError{}
	}
	var id, version, clientVersion string
	var scopes []byte
	var grantedAt time.Time
	err = rows.Scan(&id, &version, &clientVersion, &scopes, &grantedAt)
	extra := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	if err != nil || extra || rowErr != nil {
		return identity.UnavailableError{}
	}
	want := c.BeforeVersion
	if final && p.applied {
		want = c.AfterVersion
	} else if c.Created {
		return identity.ForbiddenError{}
	}
	if id != c.ID || version != strconv.FormatUint(want, 10) {
		return identity.ForbiddenError{}
	}
	if final && p.applied {
		var actual []string
		if decodeJSON(scopes, &actual) != nil || !slices.Equal(actual, i.Scopes) || clientVersion != strconv.FormatUint(g.ClientVersion, 10) || !grantedAt.Equal(i.CreatedAt) {
			return identity.ForbiddenError{}
		}
	}
	return nil
}

func (p *phase) sessionID(s session.Session) string      { b, _ := s.Bindings(); return b.SessionID }
func (p *phase) sessionVersion(s session.Session) uint64 { b, _ := s.Bindings(); return b.Version }
func (p *phase) checkBrowser(original session.Session) error {
	if p.observation.ValidateAt(p.store.now()) != nil {
		return identity.ForbiddenError{}
	}
	fields, err := sessionpg.OriginalSessionFields(p.observation.Session)
	if err != nil || !sameJSON(fields, p.input.Grant.Source) {
		return identity.ForbiddenError{}
	}
	bindings, err := original.Bindings()
	borrowed, ok := p.command.SessionToken()
	if err != nil || !ok {
		return identity.ForbiddenError{}
	}
	token, err := session.ParseToken(borrowed.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	for _, key := range p.store.config.Session.Validation.LookupKeys {
		digest, err := token.Digest(key, string(bindings.TenantID))
		if err == nil && digest.KeyVersion == bindings.Lookup.KeyVersion && subtle.ConstantTimeCompare(digest.Sum[:], bindings.Lookup.Sum[:]) == 1 {
			return nil
		}
	}
	return identity.ForbiddenError{}
}

func (p *phase) checkTarget(ctx context.Context, w kernel.Work, now time.Time, final bool) error {
	i := p.input
	rows, err := w.Query(ctx, `SELECT artifact_id,kind,state,payload,expires_at FROM `+p.store.schema+`.artifacts WHERE digest_version=$1 AND digest=$2 AND grant_id=$3 AND client_id=$4 FOR UPDATE`, i.Target.KeyVersion, i.Target.Sum[:], i.Grant.ID, i.Grant.ClientID)
	if err != nil {
		return err
	}
	if !rows.Next() {
		rows.Close()
		return identity.ForbiddenError{}
	}
	var kind int16
	var targetID string
	var state string
	var payload []byte
	var expires time.Time
	err = rows.Scan(&targetID, &kind, &state, &payload, &expires)
	extra := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	if err != nil || extra || rowErr != nil {
		return identity.UnavailableError{}
	}
	var stored artifactPayload
	if decodeJSON(payload, &stored) != nil || targetID != i.TargetID || kind != int16(i.TargetKind) || !sameJSON(stored, i.TargetPayload) || !expires.Equal(i.TargetExpires) {
		return identity.ForbiddenError{}
	}
	want := "active"
	if i.Transition == rejectReplay || i.Transition == revokeFamily && i.TargetKind == oauth.TokenRefresh && state == "consumed" {
		// RFC7009 permits revoking an original consumed refresh's still-live
		// family. Consumption removes issuance authority, not this exact client's
		// ability to withdraw its descendants; the same Work fences the root.
		want = "consumed"
	}
	if final && p.applied {
		switch i.Transition {
		case approveInteraction, denyInteraction, exchangeCode, rotateRefresh:
			want = "consumed"
		case revokeAccess:
			want = "revoked"
		case revokeFamily:
			if state != "consumed" {
				want = "revoked"
			} else {
				want = "consumed"
			}
		}
	}
	if state != want {
		return identity.ForbiddenError{}
	}
	if p.issuing() && !now.Before(expires) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *phase) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	if ctx == nil || c != p.command || generation == 0 {
		return nil, identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	i := p.input
	if p.browserRequired() && !p.store.now().Before(i.ObservationUntil) {
		return nil, identity.ForbiddenError{}
	}
	out := preparedOutput{Schema: 1, Generation: generation, Input: i}
	var kinds []oauth.TokenKind
	switch i.Transition {
	case createInteraction:
		kinds = []oauth.TokenKind{oauth.TokenContinuation}
	case approveInteraction:
		kinds = []oauth.TokenKind{oauth.TokenCode}
	case exchangeCode, rotateRefresh:
		kinds = []oauth.TokenKind{oauth.TokenAccess, oauth.TokenRefresh}
	case createWorkload:
		kinds = []oauth.TokenKind{oauth.TokenAccess}
	}
	for _, kind := range kinds {
		id, err := identity.NewSubjectID()
		if err != nil {
			return nil, oauth.ErrUnavailable
		}
		token, err := oauth.NewToken()
		if err != nil {
			return nil, oauth.ErrUnavailable
		}
		digest, err := token.Digest(p.store.active, oauth.TokenScope{Issuer: p.store.config.Protocol.Issuer, Environment: p.store.config.Protocol.Environment, ClientID: p.client.ID, Kind: kind})
		if err != nil {
			return nil, err
		}
		wire, err := token.Reveal()
		if err != nil {
			return nil, err
		}
		next, err := identity.NewCommandID()
		if err != nil {
			return nil, oauth.ErrUnavailable
		}
		replay, err := identity.NewCommandID()
		if err != nil {
			return nil, oauth.ErrUnavailable
		}
		expires := i.Grant.ExpiresAt
		switch kind {
		case oauth.TokenContinuation:
			expires = minTime(expires, i.CreatedAt.Add(p.store.config.Protocol.ContinuationTTL))
		case oauth.TokenCode:
			expires = minTime(expires, i.CreatedAt.Add(p.store.config.Protocol.CodeTTL))
		case oauth.TokenAccess:
			expires = minTime(expires, i.CreatedAt.Add(p.store.config.Protocol.AccessTTL))
		}
		out.Artifacts = append(out.Artifacts, generatedArtifact{ID: string(id), Kind: kind, Wire: wire, Digest: digest, ExpiresAt: expires, Transition: next, Replay: replay})
	}
	plain, err := json.Marshal(out)
	if err != nil {
		return nil, oauth.ErrUnavailable
	}
	defer clear(plain)
	aad, err := p.aad(generation)
	if err != nil {
		return nil, err
	}
	sealed, err := p.store.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, Context: aad, KeyReference: p.store.config.ActiveEnvelopeKeyID})
	if err != nil {
		return nil, oauth.ErrUnavailable
	}
	return sealed.MarshalBinary()
}

func (p *phase) aad(generation uint64) (envelope.Context, error) {
	frame, err := json.Marshal(struct {
		Profile       string
		Configuration [32]byte
		Binding       identity.CommandBinding
		Generation    uint64
	}{"oauth-code-output-v1", p.store.identity, p.input.Binding, generation})
	if err != nil {
		return envelope.Context{}, oauth.ErrUnavailable
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "oauth-code-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (p *phase) restore(ctx context.Context, generation uint64, wire []byte, initial bool) error {
	if len(wire) < 1 || len(wire) > 262144 {
		return oauth.ErrUnavailable
	}
	aad, err := p.aad(generation)
	if err != nil {
		return err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return oauth.ErrUnavailable
	}
	plain, err := p.store.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil {
		return oauth.ErrUnavailable
	}
	defer clear(plain)
	var out preparedOutput
	if decodeJSON(plain, &out) != nil || out.Schema != 1 || out.Generation != generation || out.Input.Configuration != p.store.identity || out.Input.Binding != p.input.Binding || out.Input.Intent != p.input.Intent || out.Input.Transition != p.input.Transition || out.Input.Grant.ID != p.input.Grant.ID || out.Input.Grant.ClientFingerprint != clientFingerprint(p.client) || !sameJSON(out.Input.Grant.Source, p.input.Grant.Source) {
		return identity.ForbiddenError{}
	}
	if !initial && !sameJSON(out.Input, p.input) {
		return identity.ForbiddenError{}
	}
	if out.Input.Grant.Workload != nil {
		if !p.store.validWorkload(out.Input.Grant, p.client) || p.input.Grant.Workload == nil {
			return identity.ForbiddenError{}
		}
		original, retained := p.input.Grant.Workload, out.Input.Grant.Workload
		if original.ID != retained.ID || original.Platform != retained.Platform || original.GlobalAuthorityID != retained.GlobalAuthorityID || original.PolicyNamespace != retained.PolicyNamespace {
			return identity.ForbiddenError{}
		}
	} else if p.client.Workload != nil {
		return identity.ForbiddenError{}
	}
	want := 0
	switch out.Input.Transition {
	case createInteraction, approveInteraction, createWorkload:
		want = 1
	case exchangeCode, rotateRefresh:
		want = 2
	}
	if len(out.Artifacts) != want {
		return oauth.ErrUnavailable
	}
	for index, a := range out.Artifacts {
		if _, err := identity.ParseSubjectID(a.ID); err != nil {
			return oauth.ErrUnavailable
		}
		expected := oauth.TokenContinuation
		switch out.Input.Transition {
		case approveInteraction:
			expected = oauth.TokenCode
		case createWorkload:
			expected = oauth.TokenAccess
		case exchangeCode, rotateRefresh:
			expected = oauth.TokenAccess
			if index == 1 {
				expected = oauth.TokenRefresh
			}
		}
		token, err := oauth.ParseToken(a.Wire)
		if err != nil || a.Kind != expected || !a.ExpiresAt.After(out.Input.CreatedAt) || a.ExpiresAt.After(out.Input.Grant.ExpiresAt) {
			return oauth.ErrUnavailable
		}
		var matched bool
		for _, key := range p.store.config.TokenKeys {
			digest, err := token.Digest(key, oauth.TokenScope{Issuer: p.store.config.Protocol.Issuer, Environment: p.store.config.Protocol.Environment, ClientID: p.client.ID, Kind: a.Kind})
			if err == nil && digest == a.Digest {
				matched = true
			}
		}
		if !matched {
			return oauth.ErrUnavailable
		}
		if _, err := identity.ParseCommandID(string(a.Transition)); err != nil {
			return oauth.ErrUnavailable
		}
		if _, err := identity.ParseCommandID(string(a.Replay)); err != nil {
			return oauth.ErrUnavailable
		}
	}
	p.input, p.output = out.Input, out
	return nil
}
func (p *phase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.command {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	if err := p.restore(ctx, generation, wire, false); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	return p.command, p.plan, nil
}

func (p *phase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.check(ctx, w, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(wire)
	if err := p.restore(ctx, generation, wire, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	for _, artifact := range p.output.Artifacts {
		if !now.Before(artifact.ExpiresAt) {
			return identity.FeatureReceipt{}, identity.ForbiddenError{}
		}
	}
	if err := p.mutate(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	if err := p.CheckFeatureCommit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	life := p.lifecycle()
	return identity.FeatureReceipt{Operation: p.operation(p.input.Binding.OperationID), BeforeVersion: life.BeforeVersion, AfterVersion: life.AfterVersion}, nil
}
func (p *phase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	return p.check(ctx, w, true)
}

func (p *phase) generatedToken(kind oauth.TokenKind) oauth.Token {
	for _, a := range p.output.Artifacts {
		if a.Kind == kind {
			token, _ := oauth.ParseToken(a.Wire)
			return token
		}
	}
	return oauth.Token{}
}
func (p *phase) generatedExpiry(kind oauth.TokenKind) time.Time {
	for _, a := range p.output.Artifacts {
		if a.Kind == kind {
			return a.ExpiresAt
		}
	}
	return time.Time{}
}
func (p *phase) authorizationResult(r identity.CommandResult) oauth.AuthorizeResult {
	out := oauth.AuthorizeResult{CommandID: p.input.Binding.CommandID, Outcome: authorizeOutcome(r)}
	if r.Outcome != identity.CommitOutcomeCommitted || !p.applied {
		return out
	}
	out.Request = p.input.Request
	switch p.input.Transition {
	case createInteraction:
		out.Outcome = oauth.ConsentRequired
		out.Continuation = p.generatedToken(oauth.TokenContinuation)
		out.ExpiresAt = p.generatedExpiry(oauth.TokenContinuation)
	case approveInteraction:
		out.Outcome = oauth.AuthorizationRedirect
		out.Code = p.generatedToken(oauth.TokenCode)
		out.ExpiresAt = p.generatedExpiry(oauth.TokenCode)
	case denyInteraction:
		out.Outcome = oauth.AuthorizationDenied
	}
	return out
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
