package oauthpostgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	Schema       uint32
	Generation   uint64
	Input        phaseInput
	Artifacts    []generatedArtifact
	IDToken      string `json:",omitempty"`
	Subject      string `json:",omitempty"`
	SigningKeyID string `json:",omitempty"`
	ClientSecret string `json:",omitempty"`
	ClientDigest []byte `json:",omitempty"`
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
	consentCommand    oauth.ConsentCommand
	consentUpdate     *oauth.ConsentUpdateExecution
	clientManagement  *oauth.ClientManagementExecution
	command           identity.Command
	declaration, plan kernel.CommandPlan
	counters          kernel.CommandCounterPlan
	registry          *kernel.ContributorRegistry
	coordinator       *kernel.Coordinator
	output            preparedOutput
	applied           bool
	metadataRecovery  bool
	oidc              func(context.Context, oauth.OIDCClaimsInput) (oauth.OIDCClaimsProjection, error)
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
func (p *phase) FeatureOperations() []identity.FeatureOperation {
	operations := []identity.FeatureOperation{operation("identity.oauth-server.authorize"), operation("identity.oauth-server.continue"), operation("identity.oauth-server.token"), operation("identity.oauth-server.revoke"), workloadOperation("identity.oauth-server.token"), workloadOperation("identity.oauth-server.revoke")}
	if p.store != nil && p.store.config.ConsentManagement {
		operations = append(operations, operation("identity.oauth-server.consent-delete"))
	}
	if p.store != nil && p.store.config.ConsentNarrowing {
		operations = append(operations, operation("identity.oauth-server.consent-update"))
	}
	if p.store != nil && p.store.config.Protocol.ManagedClients != nil {
		operations = append(operations, operation("identity.oauth-server.client-create"), operation("identity.oauth-server.client-delete"))
	}
	if p.store != nil && p.store.config.ClientSecretRotation {
		operations = append(operations, operation("identity.oauth-server.client-rotate-secret"))
	}
	if p.store != nil && p.store.config.ClientMetadataUpdates {
		operations = append(operations, operation("identity.oauth-server.client-update"))
	}
	return operations
}
func (p *phase) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation(p.input.Binding.OperationID)}
}

// Protocol operation IDs and security action names intentionally differ. The
// closed taxonomy is SECURITY_EVENTS.md's OAuth server row; consent approval
// and replay revocation each declare their distinct composed actions once.
func (p *phase) auditActions() []string {
	switch p.input.Transition {
	case createManagedClient:
		return []string{"identity.oauth_server.create_client"}
	case deleteManagedClient:
		return []string{"identity.oauth_server.delete_client"}
	case rotateManagedSecret:
		return []string{"identity.oauth_server.rotate_client_secret"}
	case updateManagedClient:
		return []string{"identity.oauth_server.update_client"}
	case deleteConsent, narrowConsent:
		return []string{"identity.oauth_server.revoke_consent"}
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
	case createManagedClient:
		before = 0
		// LIFECYCLE_CASCADES.md lifecycle.events.oauth_server fixes these
		// names; terminal deletion is client revocation, not a new event family.
		event = "oauth_client.created.v1"
	case deleteManagedClient:
		before = p.input.ClientChange.Version
		event = "oauth_client.revoked.v1"
	case rotateManagedSecret:
		before = p.input.ClientChange.Version
		event = "oauth_client.secret_rotated.v1"
	case updateManagedClient:
		before = p.input.ClientChange.Version
		event = "oauth_client.configuration_changed.v1"
	case deleteConsent:
		before = p.input.Deletion.Version
		event = "consent.revoked.v1"
	case narrowConsent:
		before = p.input.Narrowing.Version
		event = "consent.scope_changed.v1"
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
	if p.input.ClientChange != nil {
		return "oauth_client"
	}
	if p.input.Transition == deleteConsent || p.input.Transition == narrowConsent {
		return "oauth_consent"
	}
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
	handoff := false
	if err != nil {
		var reauthentication kernel.OAuthReauthenticationRequiredError
		if !errors.As(err, &reauthentication) || admission.Record.Outcome != identity.CommitOutcomeNotCommitted || p.input.Transition != approveInteraction || p.input.PreviousSource == nil || p.input.Authentication == nil || p.input.Authentication.Requirement != oauth.OIDCAuthenticationCurrent {
			return identity.CommandResult{Binding: p.input.Binding, Outcome: admission.Record.Outcome}, err
		}
		// Only an actual classified terminal predecessor selects a candidate.
		// The sole coordinator re-proves it under journal locks and advances the
		// native pointer atomically with acknowledged start; this read cannot.
		next, err := identity.NewCommandID()
		if err != nil {
			return identity.CommandResult{}, err
		}
		p.input.ContinuationPrevious = p.input.Binding.CommandID
		p.bind(next, p.input.Binding.OperationID, p.input.Binding.RecordID)
		handoff = true
	}
	if !handoff && !admission.Absent {
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
	if i.Authentication != nil {
		if !authenticationRequested(i.Request) || i.Transition != createInteraction && i.Transition != approveInteraction || i.Authentication.Requirement != oauth.OIDCAuthenticationCurrent && ((i.Authentication.Requirement != oauth.OIDCAuthenticationFresh && i.Authentication.Requirement != oauth.OIDCAuthenticationSilent) || i.Transition != createInteraction) {
			return oauth.ErrInvalidRequest
		}
	}
	if i.SilentConsent != nil {
		if !p.store.validSilentInput(i, p.client) {
			return oauth.ErrInvalidRequest
		}
	} else if i.Request.Prompt == "none" && (i.Transition == createInteraction || i.Transition == approveInteraction) {
		return oauth.ErrInvalidRequest
	}
	if i.PreviousSource != nil && (i.Transition != approveInteraction || i.Authentication == nil || i.Authentication.Requirement != oauth.OIDCAuthenticationCurrent) {
		return oauth.ErrInvalidRequest
	}
	if i.Transition == approveInteraction {
		if i.Consent.ExpiresAt != nil && (!i.Consent.ExpiresAt.After(i.CreatedAt) || i.Consent.ExpiresAt.After(i.CreatedAt.Add(24*time.Hour))) {
			return oauth.ErrInvalidRequest
		}
		if _, err := identity.ParseSubjectID(i.Consent.ID); err != nil || i.Consent.BeforeVersion == math.MaxUint64 || i.Consent.AfterVersion != i.Consent.BeforeVersion+1 || i.Consent.Created != (i.Consent.BeforeVersion == 0) {
			return oauth.ErrInvalidRequest
		}
	} else if i.Consent != (consentMutation{}) {
		return oauth.ErrInvalidRequest
	}
	if i.Transition == deleteConsent {
		if !p.store.config.ConsentManagement || i.Deletion == nil || i.Deletion.ID != b.RecordID || i.Deletion.Version == 0 || i.Deletion.Version == math.MaxUint64 || i.Deletion.Generation == 0 || i.Deletion.Generation == math.MaxUint64 || i.Grant.ID != "" {
			return oauth.ErrInvalidRequest
		}
	} else if i.Deletion != nil {
		return oauth.ErrInvalidRequest
	}
	if i.Transition == narrowConsent {
		if !p.store.config.ConsentNarrowing || i.Narrowing == nil || i.Narrowing.ID != b.RecordID || i.Narrowing.Version == 0 || i.Narrowing.Version == math.MaxUint64 || i.Narrowing.Generation == 0 || i.Narrowing.Generation == math.MaxUint64 || i.Grant.ID != "" || len(i.Scopes) >= len(i.Grant.Scopes) {
			return oauth.ErrInvalidRequest
		}
	} else if i.Narrowing != nil {
		return oauth.ErrInvalidRequest
	}
	if i.ClientChange != nil {
		if (i.Transition != createManagedClient && i.Transition != deleteManagedClient && i.Transition != rotateManagedSecret && i.Transition != updateManagedClient) || !p.store.managedMetadata(i.ClientChange.Client) || i.ClientChange.Client.ID != oauth.ManagedClientPrefix+b.RecordID || clientFingerprint(i.ClientChange.Client) != clientFingerprint(p.client) || i.Transition == createManagedClient && i.ClientChange.Version != 0 || i.Transition != createManagedClient && (i.ClientChange.Version == 0 || i.ClientChange.Version == math.MaxUint64 || i.ClientChange.Version != p.client.Version) {
			return oauth.ErrInvalidRequest
		}
		if i.Transition == rotateManagedSecret {
			if !p.store.config.ClientSecretRotation || i.ClientChange.Overlap < 0 || i.ClientChange.Overlap > 24*time.Hour || i.ClientChange.Overlap%time.Microsecond != 0 {
				return oauth.ErrInvalidRequest
			}
		} else if i.ClientChange.Overlap != 0 {
			return oauth.ErrInvalidRequest
		}
		if i.ClientChange.SecretVersion != 0 && (!p.store.config.ClientMetadataUpdates || i.ClientChange.SecretVersion > p.client.Version) {
			return oauth.ErrInvalidRequest
		}
		if i.Transition == updateManagedClient {
			if !p.store.config.ClientMetadataUpdates || i.ClientChange.SecretVersion == 0 {
				return oauth.ErrInvalidRequest
			}
			if _, err := p.store.updatedClient(p.client, i.ClientChange.Replacement); err != nil {
				return err
			}
		} else if i.ClientChange.Replacement != nil {
			return oauth.ErrInvalidRequest
		}
	} else if i.Transition == createManagedClient || i.Transition == deleteManagedClient || i.Transition == rotateManagedSecret || i.Transition == updateManagedClient {
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
	recordField := identity.FeatureField{Name: "oauth.grant", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: i.Grant.ID}}
	versionField := identity.FeatureField{Name: "oauth.grant-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.Grant.Version}}
	if i.Transition == deleteConsent {
		recordField = identity.FeatureField{Name: "oauth.consent-root", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: i.Deletion.ID}}
		versionField = identity.FeatureField{Name: "oauth.consent-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.Deletion.Version}}
	}
	if i.Transition == narrowConsent {
		recordField = identity.FeatureField{Name: "oauth.consent-root", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: i.Narrowing.ID}}
		versionField = identity.FeatureField{Name: "oauth.consent-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.Narrowing.Version}}
	}
	if i.ClientChange != nil {
		recordField = identity.FeatureField{Name: "oauth.client-root", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: i.ClientChange.Client.ID}}
		versionField = identity.FeatureField{Name: "oauth.client-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: i.ClientChange.Version}}
	}
	fields = append(fields,
		identity.FeatureField{Name: "oauth.input-commitment", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: commitment[:]}},
		identity.FeatureField{Name: "oauth.caller-intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: i.Intent[:]}},
		identity.FeatureField{Name: "oauth.configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: i.Configuration[:]}},
		identity.FeatureField{Name: "oauth.created-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: i.CreatedAt}},
		identity.FeatureField{Name: "oauth.transition", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(i.Transition)}},
		recordField,
		identity.FeatureField{Name: "oauth.client", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: i.Grant.ClientID}},
		versionField,
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
	if err := p.check(ctx, w, false); err != nil {
		return err
	}
	// Current-source/grant/consent checks can wait. Do not acknowledge a start
	// using the authentication age sampled before those protected locks.
	return p.checkArtifactExpiry(ctx, w)
}
func (p *phase) browserRequired() bool {
	return p.input.ClientChange != nil || p.input.Transition == createInteraction || p.input.Transition == approveInteraction || p.input.Transition == denyInteraction || p.input.Transition == deleteConsent || p.input.Transition == narrowConsent
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
	if p.input.ClientChange == nil {
		if err := p.requireManagedClient(ctx, w); err != nil {
			return err
		}
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
	if err := p.checkSubjectBinding(ctx, w, final); err != nil {
		return err
	}
	if err := p.checkPreviousSource(ctx, w); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if i.Authentication != nil && !i.Authentication.Until.IsZero() && !now.Before(i.Authentication.Until) {
		return kernel.OAuthReauthenticationRequiredError{}
	}
	if p.browserRequired() && (p.observation.ValidateAt(now) != nil || !now.Before(i.ObservationUntil)) {
		return identity.ForbiddenError{}
	}
	if i.ClientChange != nil {
		if p.clientManagement == nil || p.clientManagement.ValidateAt(now) != nil {
			return identity.ForbiddenError{}
		}
		return p.checkClientChange(ctx, w, final)
	}
	if i.Transition == deleteConsent {
		if (oauth.ConsentExecution{Command: p.consentCommand, Session: p.observation}).ValidateAt(now) != nil {
			return identity.ForbiddenError{}
		}
		return p.checkConsentDeletion(ctx, w, final)
	}
	if i.Transition == narrowConsent {
		if (oauth.ConsentExecution{Command: p.consentCommand, Session: p.observation}).ValidateAt(now) != nil {
			return identity.ForbiddenError{}
		}
		return p.checkConsentNarrowing(ctx, w, final)
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
		if i.SilentConsent != nil {
			return p.checkSilentConsent(ctx, w)
		}
		return nil
	}
	if err := p.checkGrantConsent(ctx, w, final); err != nil {
		return err
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
	expectedSource := g.Source
	if i.PreviousSource != nil && !(final && p.applied) {
		expectedSource = i.PreviousSource
	}
	if decodeJSON(source, &originalFields) != nil || !sameJSON(originalFields, expectedSource) {
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
	if p.store.config.ConsentManagement {
		return p.checkManagedConsent(ctx, w, final)
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
	if i.ClientChange != nil {
		// Generation is outside the coordinator's protected SQL transaction.
		// Keep application policy callbacks here; Work only fences the original
		// real actor epoch and immutable configured revision, without renewing time.
		if p.clientManagement == nil || p.clientManagement.ValidateAt(p.store.now()) != nil {
			return nil, identity.ForbiddenError{}
		}
		if err := p.store.managementDecision(ctx, i.Grant.User, i.Binding.OperationID); err != nil {
			return nil, err
		}
	}
	out := preparedOutput{Schema: 1, Generation: generation, Input: i}
	if i.Transition == createManagedClient || i.Transition == rotateManagedSecret {
		token, err := oauth.NewToken()
		if err != nil {
			return nil, err
		}
		out.ClientSecret, err = token.Reveal()
		if err != nil {
			return nil, err
		}
		version := p.managementSecretVersion()
		if i.Transition == rotateManagedSecret {
			version++
		}
		digest, err := oauth.DigestClientSecret(p.client.ID, version, out.ClientSecret)
		if err != nil {
			return nil, err
		}
		out.ClientDigest = slices.Clone(digest[:])
	}
	out.Subject = i.TargetPayload.Subject
	out.SigningKeyID = i.TargetPayload.SigningKeyID
	var kinds []oauth.TokenKind
	switch i.Transition {
	case createInteraction:
		if i.SilentConsent == nil {
			kinds = []oauth.TokenKind{oauth.TokenContinuation}
		} else {
			kinds = []oauth.TokenKind{oauth.TokenCode}
		}
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
			if authenticationRequested(i.Request) && i.Transition == approveInteraction {
				expires = minTime(expires, i.TargetExpires)
			}
		case oauth.TokenAccess:
			expires = minTime(expires, i.CreatedAt.Add(p.store.config.Protocol.AccessTTL))
		}
		out.Artifacts = append(out.Artifacts, generatedArtifact{ID: string(id), Kind: kind, Wire: wire, Digest: digest, ExpiresAt: expires, Transition: next, Replay: replay})
	}
	if i.Transition == exchangeCode {
		selected := false
		for _, scope := range i.Scopes {
			if p.store.config.Protocol.OIDCScopes.Contains(scope) {
				selected = true
			}
		}
		if selected {
			if p.oidc == nil {
				return nil, oauth.ErrAccessDenied
			}
			// The selected child emits whole-second NumericDates. Conserve that
			// exact deadline as the native access deadline too, so preparation,
			// restored Work fences, persistence and core delivery cannot outlive
			// the signed exp. Never round above the original grant/TTL ceiling.
			out.Artifacts[0].ExpiresAt = out.Artifacts[0].ExpiresAt.Truncate(time.Second)
			if !i.CreatedAt.Before(out.Artifacts[0].ExpiresAt) {
				return nil, oauth.ErrAccessDenied
			}
			original, err := sessionpg.OriginalSessionFromFields(i.Grant.Tenant, i.Grant.User, i.Grant.Source)
			if err != nil {
				return nil, oauth.ErrAccessDenied
			}
			bindings, err := original.Bindings()
			if err != nil {
				return nil, oauth.ErrAccessDenied
			}
			registration, boundSubject, err := subjectClaims(p.client, i.Grant)
			if err != nil {
				return nil, err
			}
			claims, err := p.oidc(ctx, oauth.OIDCClaimsInput{Issuer: p.store.config.Protocol.Issuer, Environment: p.store.config.Protocol.Environment, TenantID: i.Grant.Tenant, UserID: i.Grant.User, ClientID: p.client.ID, Nonce: i.Request.Nonce, Scopes: slices.Clone(i.Scopes), IssuedAt: i.CreatedAt, ExpiresAt: out.Artifacts[0].ExpiresAt, AuthenticatedAt: bindings.Authentication.Proof.IssuedAt, SubjectRegistration: registration, BoundSubject: boundSubject})
			if err != nil {
				return nil, err
			}
			if !boundedText(claims.Subject, 128) || !boundedText(claims.SigningKeyID, 128) || boundSubject != "" && claims.Subject != boundSubject {
				return nil, oauth.ErrUnavailable
			}
			out.IDToken, err = claims.IDToken.Reveal()
			if err != nil {
				return nil, oauth.ErrUnavailable
			}
			out.Subject = claims.Subject
			out.SigningKeyID = claims.SigningKeyID
		}
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
	if decodeJSON(plain, &out) != nil {
		return identity.ForbiddenError{}
	}
	transitionMatches := out.Input.Transition == p.input.Transition
	if p.metadataRecovery {
		// Recovery has no proposed consent/network intent. The owning
		// preparation authenticates that original intent, but never authorizes
		// execution or redelivery. Keep exact continuation/client/source scope.
		transitionMatches = p.input.Transition == approveInteraction && (out.Input.Transition == approveInteraction || out.Input.Transition == denyInteraction)
		if out.Input.Target != p.input.Target || out.Input.TargetID != p.input.TargetID || out.Input.TargetKind != oauth.TokenContinuation || !out.Input.TargetExpires.Equal(p.input.TargetExpires) || !sameJSON(out.Input.TargetPayload, p.input.TargetPayload) {
			return identity.ForbiddenError{}
		}
	}
	if out.Schema != 1 || out.Generation != generation || out.Input.Configuration != p.store.identity || out.Input.Binding != p.input.Binding || !p.metadataRecovery && out.Input.Intent != p.input.Intent || !transitionMatches || out.Input.Grant.ID != p.input.Grant.ID || out.Input.Grant.ClientFingerprint != clientFingerprint(p.client) || !sameJSON(out.Input.Grant.Source, p.input.Grant.Source) {
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
	if out.Input.Transition == createManagedClient || out.Input.Transition == rotateManagedSecret {
		// Authenticate the originally captured generation, not a registration
		// version advanced by metadata replacement. Legacy absent fields retain
		// their original coupled interpretation in managementSecretVersion.
		version := p.managementSecretVersion()
		if out.Input.Transition == rotateManagedSecret {
			version++
		}
		digest, err := oauth.DigestClientSecret(p.client.ID, version, out.ClientSecret)
		if err != nil || !slices.Equal(digest[:], out.ClientDigest) {
			return oauth.ErrUnavailable
		}
	} else if out.ClientSecret != "" || len(out.ClientDigest) != 0 {
		return oauth.ErrUnavailable
	}
	for index, a := range out.Artifacts {
		if _, err := identity.ParseSubjectID(a.ID); err != nil {
			return oauth.ErrUnavailable
		}
		expected := oauth.TokenContinuation
		if out.Input.Transition == createInteraction && out.Input.SilentConsent != nil {
			expected = oauth.TokenCode
		}
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
		if out.IDToken != "" && (out.Input.Transition != exchangeCode || index == 0 && a.ExpiresAt.Nanosecond() != 0) {
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
	if err := p.checkContinuationAttempt(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.checkArtifactExpiry(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
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
	if err := p.check(ctx, w, true); err != nil {
		return err
	}
	if p.output.IDToken != "" {
		if err := p.checkSigning(ctx, w); err != nil {
			return err
		}
	}
	// Source/grant/consent and signing fences can wait. Sample authoritative
	// expiry after all of them, including continuations without an ID token.
	return p.checkArtifactExpiry(ctx, w)
}

func (p *phase) checkArtifactExpiry(ctx context.Context, w kernel.Work) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	// The consent-root lock may wait after the original source check. Neither
	// that wait nor a second primary read can renew sensitive proof or admission.
	if p.input.Transition == narrowConsent && ((oauth.ConsentExecution{Command: p.consentCommand, Session: p.observation}).ValidateAt(now) != nil || !now.Before(p.input.ObservationUntil)) {
		return identity.ForbiddenError{}
	}
	if p.input.ClientChange != nil && (p.clientManagement == nil || p.clientManagement.ValidateAt(now) != nil || !now.Before(p.input.ObservationUntil)) {
		return identity.ForbiddenError{}
	}
	if p.input.ClientAuthentication != nil && !p.input.ClientAuthentication.validAt(p.store.now(), now) {
		return identity.ForbiddenError{}
	}
	if p.input.Authentication != nil && !p.input.Authentication.Until.IsZero() && !now.Before(p.input.Authentication.Until) {
		return kernel.OAuthReauthenticationRequiredError{}
	}
	if p.input.SilentConsent != nil && (p.observation.ValidateAt(now) != nil || p.observation.ValidateAt(p.store.now()) != nil || !now.Before(p.input.ObservationUntil) || !now.Before(p.input.SilentConsent.ExpiresAt)) {
		return identity.ForbiddenError{}
	}
	for _, artifact := range p.output.Artifacts {
		if !now.Before(artifact.ExpiresAt) {
			return identity.ForbiddenError{}
		}
	}
	return nil
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
		if p.input.SilentConsent != nil {
			out.Outcome = oauth.AuthorizationRedirect
			out.Code = p.generatedToken(oauth.TokenCode)
			out.ExpiresAt = p.generatedExpiry(oauth.TokenCode)
			break
		}
		out.Outcome = oauth.ConsentRequired
		if p.input.Authentication != nil && p.input.Authentication.Requirement == oauth.OIDCAuthenticationFresh {
			out.Outcome = oauth.FreshAuthenticationRequired
		}
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
