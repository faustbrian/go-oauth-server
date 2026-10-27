package oauthpostgres

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5"
)

// Config selects platform-owned public/configured-Basic password single-factor
// web clients and/or explicitly configured machine workloads. Every authority,
// schema, policy and key is trusted startup input.
// Protocol clients are immutable registrations; changing policy invalidates
// earlier grants instead of silently widening them. IntentKey must be a dedicated
// nonzero key, independent of token, session, fingerprint and envelope keys.
// Retain all key versions/configuration needed by outstanding commands.
// Install kernel preparation/protected-counter, applicable session/workload,
// authorization, risk lockout, audit/outbox and OAuth histories before enabling calls. Construction
// never installs migrations or adopts existing objects. The pool/keyring and
// policy dependencies remain borrowed and must outlive concurrent operations.
type Config struct {
	Schema                string
	Protocol              oauth.Config
	Session               sessionpg.SessionServiceConfig
	CSRFKeys              []session.CSRFKey
	TokenKeys             []oauth.TokenDigestKey
	ActiveTokenKeyVersion uint32
	IntentKey             [32]byte
	ActiveEnvelopeKeyID   string
	Coordinator           kernel.CoordinatorConfig
	RequestKeys           kernel.RequestKeyConfig
	PolicyID              string
	Counters              riskpg.Config
	// WorkloadAuthority binds configured machine clients to existing primary
	// directory and service-account authorization owners, never user substitutes.
	WorkloadAuthority WorkloadAuthorityConfig
	// WorkloadExchangeClientNamespace selects a distinct real authorization
	// namespace keyed by tenant and client ID. Initialize its epoch to the
	// immutable registration Version before selecting WorkloadExchange. Advance
	// withdraws lineage AND new issuance from that unchanged registration.
	// It must differ from WorkloadAuthority.PolicyNamespace. No request creates
	// or adopts an authority row; absent/stale/unavailable authority denies.
	WorkloadExchangeClientNamespace string
	// HumanCodeExchangeClientNamespace is an independent public authorization
	// namespace for deterministic per-registration subjects. Explicit native
	// bootstrap initializes epoch1; exchange never creates or repairs authority.
	// It must differ from session, workload principal and workload client policy
	// namespaces: the public authority owner has no separate subject-kind key.
	HumanCodeExchangeClientNamespace string
	// ConsentManagement enables own-consent reads/withdrawal and mandatory
	// consent-generation fences for every human token. Install the forward
	// ConsentMigrationSource and retire all old/unselected serving instances
	// before enabling. Workload-only composition must leave this false.
	ConsentManagement bool
	// ConsentNarrowing selects keyed strict-subset updates. ConsentManagement
	// and the kernel's request-key preparation history must already be installed.
	// Existing read/delete-only compositions leave this false.
	ConsentNarrowing bool
	// ClientSecretRotation enables bounded managed confidential-secret overlap.
	// Install ClientRotationMigrationSource and retire non-rotation instances
	// before enabling; every secret change advances actual client authority.
	ClientSecretRotation bool
	// ClientMetadataUpdates separates registration authority from digest generation.
	// Install ClientUpdateMigrationSource and retire all non-update-aware serving
	// instances before enabling. Rotation-aware consent/client history is required.
	ClientMetadataUpdates bool
	// PublicClients selects no-secret managed human-web registrations. It must
	// match Protocol.ManagedClients.PublicClients. Install ClientPublicMigrationSource
	// and retire unaware serving instances before enabling; confidential-only
	// deployments leave both false and need no additional schema.
	PublicClients bool
	// ConsentReuseTTL explicitly selects silent OIDC approval reuse for 1s..24h.
	// Zero selects only a preactivation legacy writer. After installing expiry
	// history, EVERY accepting writer must retain a positive TTL; mixed/zero
	// writer rollback is unsupported. Revoke consent to withdraw reuse. Install
	// forward history and retire old writers first; legacy NULL is never reusable.
	ConsentReuseTTL time.Duration
	// RPInitiatedLogout selects exact issued-hint/source-session termination.
	// Install both owners' forward logout histories and retire unaware serving
	// instances before enabling. Only this explicit purpose withdraws existing
	// OAuth grants; ordinary browser signout retains its existing grant policy.
	RPInitiatedLogout bool
	// ProfileUserInfo explicitly selects the existing primary profile owner for
	// consented OIDC display-name reads. It must match the profile scope catalog;
	// stored immutable schemas are never guessed or migrated by this adapter.
	ProfileUserInfo *ProfileUserInfoConfig
}

// Format redacts keys, correlated deployment scopes and policy dependencies.
func (Config) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("oauthpostgres.Config(redacted)")) }

// MarshalJSON denies implicit secret-bearing configuration export.
func (Config) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

// MarshalText denies implicit secret-bearing configuration export.
func (Config) MarshalText() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

// Store implements the public OAuth execution seam through the existing sole
// identity coordinator. It owns no pool, transaction, journal, goroutine or
// private authentication engine. Each invocation owns one comparable native
// participant and encrypted preparation. Immutable configuration is safe for
// concurrent callers; requests remain borrowed until their bounded call returns.
type Store struct {
	pool           *database.Pool
	config         Config
	schema         string
	identity       [32]byte
	domain         *kernel.Repository
	profiles       *kernel.Repository
	counters       *riskpg.Repository
	crypto         *envelope.Service
	active         oauth.TokenDigestKey
	policy         *authority.AuthorityStore
	endSession     *sessionpg.OIDCEndSessionEffect
	sessionRecords *sessionpg.Repository
}

var _ oauth.Store = (*Store)(nil)

// NewStore validates and freezes native composition without IO or generation.
// Unsupported session profiles and missing current counter/lockout owners deny;
// no caller-written domain store, Work, coordinator or phase hook is accepted.
func NewStore(pool *database.Pool, c Config, keys *keyring.Provider) (*Store, error) {
	protocol, err := c.Protocol.Validated()
	if err != nil || pool == nil || pool.Raw() == nil || keys == nil || !validSchema(c.Schema) || c.IntentKey == ([32]byte{}) || c.ActiveEnvelopeKeyID == "" || len(c.ActiveEnvelopeKeyID) > 256 || c.PolicyID == "" || len(c.PolicyID) > 128 || c.Coordinator.MaximumDuration <= 0 || c.Coordinator.MaximumDuration > protocol.MaximumDuration || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.QueryPolicy.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion || c.Counters.CommandCounters == nil || !c.Counters.EnforceLockouts || len(c.TokenKeys) < 1 || len(c.TokenKeys) > 4 || len(c.CSRFKeys) > 4 {
		return nil, oauth.ErrInvalidRequest
	}
	web := protocol.ManagedClients != nil || webSelected(protocol.Clients)
	if web && (c.Session.Profile.Validate() != nil || c.Session.Profile.AuthenticationMethod != "password" || c.Session.Profile.CredentialKind != identity.CredentialPassword || c.Session.Profile.CredentialOwner != "identity/password" || c.Session.Repository.MaximumDuration <= 0 || c.Session.Repository.MaximumDuration > protocol.MaximumDuration || len(c.CSRFKeys) < 1) {
		return nil, oauth.ErrInvalidRequest
	}
	if workloadSelected(protocol.Clients) {
		for _, client := range protocol.Clients {
			if client.Workload != nil && ((kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.WorkloadAuthority.GlobalAuthorityID, TenantID: client.Workload.TenantID()}).Validate() != nil || (authority.AuthorityScope{TenantID: authorization.TenantID(client.Workload.TenantID()), PolicyNamespace: c.WorkloadAuthority.PolicyNamespace, SubjectID: authorization.SubjectID(client.Workload.ID())}).Validate() != nil) {
				return nil, oauth.ErrInvalidRequest
			}
		}
	} else if c.WorkloadAuthority != (WorkloadAuthorityConfig{}) {
		return nil, oauth.ErrInvalidRequest
	}
	if protocol.WorkloadExchange != nil {
		if c.WorkloadExchangeClientNamespace == c.WorkloadAuthority.PolicyNamespace {
			return nil, oauth.ErrInvalidRequest
		}
		for _, client := range protocol.Clients {
			if client.Workload != nil && (authority.AuthorityScope{TenantID: authorization.TenantID(client.Workload.TenantID()), PolicyNamespace: c.WorkloadExchangeClientNamespace, SubjectID: authorization.SubjectID(client.ID)}).Validate() != nil {
				return nil, oauth.ErrInvalidRequest
			}
		}
	} else if c.WorkloadExchangeClientNamespace != "" {
		return nil, oauth.ErrInvalidRequest
	}
	if c.ConsentManagement && !web {
		return nil, oauth.ErrInvalidRequest
	}
	if protocol.HumanCodeExchange != nil {
		if !c.ConsentManagement || c.HumanCodeExchangeClientNamespace == c.WorkloadAuthority.PolicyNamespace || c.HumanCodeExchangeClientNamespace == c.WorkloadExchangeClientNamespace || c.HumanCodeExchangeClientNamespace == c.Session.Profile.PolicyNamespace || (authority.AuthorityScope{TenantID: "scope-validation", PolicyNamespace: c.HumanCodeExchangeClientNamespace, SubjectID: "scope-validation"}).Validate() != nil {
			return nil, oauth.ErrInvalidRequest
		}
	} else if c.HumanCodeExchangeClientNamespace != "" {
		return nil, oauth.ErrInvalidRequest
	}
	if c.ConsentNarrowing && !c.ConsentManagement {
		return nil, oauth.ErrInvalidRequest
	}
	if protocol.ManagedClients != nil && !c.ConsentManagement {
		return nil, oauth.ErrInvalidRequest
	}
	if c.ClientSecretRotation && protocol.ManagedClients == nil {
		return nil, oauth.ErrInvalidRequest
	}
	if c.ClientMetadataUpdates && !c.ClientSecretRotation {
		return nil, oauth.ErrInvalidRequest
	}
	if c.PublicClients != (protocol.ManagedClients != nil && protocol.ManagedClients.PublicClients) {
		return nil, oauth.ErrInvalidRequest
	}
	if c.ConsentReuseTTL != 0 && (!c.ConsentManagement || len(protocol.OIDCScopes.Scopes()) == 0 || c.ConsentReuseTTL < time.Second || c.ConsentReuseTTL > 24*time.Hour || c.ConsentReuseTTL%time.Microsecond != 0) {
		return nil, oauth.ErrInvalidRequest
	}
	if c.RPInitiatedLogout && (!web || !protocol.OIDCScopes.Contains("openid")) {
		return nil, oauth.ErrInvalidRequest
	}
	// Privileged's native counters supply exactly velocity. The upstream
	// protected-provider admission API is CredentialMutation-only; accepting
	// another mandatory signal here would silently omit its owning provider.
	operations := (&phase{}).FeatureOperations()
	if c.ConsentManagement {
		operations = append(operations, operation("identity.oauth-server.consent-delete"))
	}
	if c.ConsentNarrowing {
		operations = append(operations, operation("identity.oauth-server.consent-update"))
	}
	if protocol.ManagedClients != nil {
		operations = append(operations, operation("identity.oauth-server.client-create"), operation("identity.oauth-server.client-delete"))
	}
	if c.ClientSecretRotation {
		operations = append(operations, operation("identity.oauth-server.client-rotate-secret"))
	}
	if c.ClientMetadataUpdates {
		operations = append(operations, operation("identity.oauth-server.client-update"))
	}
	if c.RPInitiatedLogout {
		operations = append(operations, endSessionOperation())
	}
	for _, operation := range operations {
		admitted, err := c.Counters.CommandCounters.Policy.Admit(risk.Action(operation.OperationID))
		if err != nil || admitted.PolicyVersion != c.Counters.PolicyVersion || admitted.PolicyVersion != c.Coordinator.AdmissionPolicy.PolicyVersion || admitted.Preflight != "" || admitted.Profile.Class != risk.Privileged || !slices.Equal(admitted.Profile.RequiredSignals, []string{"velocity"}) {
			return nil, oauth.ErrInvalidRequest
		}
	}
	c.Protocol = protocol
	c.TokenKeys = slices.Clone(c.TokenKeys)
	c.CSRFKeys = slices.Clone(c.CSRFKeys)
	c.Session.Validation.LookupKeys = slices.Clone(c.Session.Validation.LookupKeys)
	c.Coordinator.RetainedFingerprintKeys = maps.Clone(c.Coordinator.RetainedFingerprintKeys)
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy = &query
	c.Coordinator.AdmissionPolicy = &admission
	profiles, err := newUserInfoProfileRepository(pool, c)
	if err != nil {
		return nil, oauth.ErrInvalidRequest
	}
	if c.ProfileUserInfo != nil {
		// The primary repository owns the frozen schema copy. Retain only its
		// selected identity here, not an alias to caller-owned personal defaults.
		c.ProfileUserInfo = &ProfileUserInfoConfig{ProfileSchema: c.ProfileUserInfo.ProfileSchema}
	}
	s := &Store{pool: pool, config: c, schema: pgx.Identifier{c.Schema}.Sanitize(), profiles: profiles}
	if c.RPInitiatedLogout {
		if s.endSession, err = sessionpg.NewOIDCEndSessionEffect(c.Session.Repository, c.Session.Profile); err != nil {
			return nil, oauth.ErrInvalidRequest
		}
		if s.sessionRecords, err = sessionpg.NewRepository(pool, c.Session.Repository); err != nil {
			return nil, oauth.ErrInvalidRequest
		}
	}
	for i, key := range c.TokenKeys {
		if key.Version() == 0 {
			return nil, oauth.ErrInvalidRequest
		}
		for _, prior := range c.TokenKeys[:i] {
			if prior.Version() == key.Version() {
				return nil, oauth.ErrInvalidRequest
			}
		}
		if key.Version() == c.ActiveTokenKeyVersion {
			s.active = key
		}
	}
	if s.active.Version() == 0 {
		return nil, oauth.ErrInvalidRequest
	}
	for i, key := range c.CSRFKeys {
		if key.Version() == 0 {
			return nil, oauth.ErrInvalidRequest
		}
		for _, prior := range c.CSRFKeys[:i] {
			if prior.Version() == key.Version() {
				return nil, oauth.ErrInvalidRequest
			}
		}
	}
	if s.domain, err = kernel.NewRepository(pool, kernel.Config{MaximumDuration: protocol.MaximumDuration}); err != nil {
		return nil, oauth.ErrInvalidRequest
	}
	if protocol.OwningClientIntrospection || protocol.HumanCodeExchange != nil || workloadSelected(protocol.Clients) || len(protocol.OIDCScopes.Scopes()) > 0 || protocol.ManagedClients != nil {
		if s.policy, err = authority.NewAuthorityStore(pool.Raw(), protocol.MaximumDuration); err != nil {
			return nil, oauth.ErrInvalidRequest
		}
	}
	if s.counters, err = riskpg.NewRepository(c.Counters); err != nil {
		return nil, oauth.ErrInvalidRequest
	}
	if s.crypto, err = envelope.NewService(keys); err != nil {
		return nil, oauth.ErrInvalidRequest
	}
	// Key versions are immutable deployment obligations, not public keys. This
	// commitment binds all public policy that can change a retained grant.
	// Active envelope/digest writer selection is not authority policy: retained
	// ciphertext authenticates its own key reference, so rotating a writer while
	// retaining original keys must not strand native recovery or live grants.
	type profile sessionpg.IdentifierAdmissionConfig
	var workloadAuthority *WorkloadAuthorityConfig
	if workloadSelected(protocol.Clients) {
		value := c.WorkloadAuthority
		workloadAuthority = &value
	}
	var consentManagement *bool
	if c.ConsentManagement {
		enabled := true
		consentManagement = &enabled
	}
	frame, err := json.Marshal(struct {
		Profile                                       string
		Schema, Issuer, Environment, Resource, Policy string
		Clients                                       []clientPolicy
		Session                                       profile
		SessionSchema                                 string
		PolicyVersion                                 uint64
		Durations                                     []time.Duration
		WorkloadAuthority                             *WorkloadAuthorityConfig `json:",omitempty"`
		ConsentManagement                             *bool                    `json:",omitempty"`
	}{"oauth-code-public-password-v1", c.Schema, protocol.Issuer.String(), protocol.Environment, protocol.Resource, c.PolicyID, clientPolicies(protocol.Clients), profile(c.Session.Profile), c.Session.Repository.Schema, admission.PolicyVersion, []time.Duration{protocol.CodeTTL, protocol.ContinuationTTL, protocol.AccessTTL, protocol.RefreshTTL}, workloadAuthority, consentManagement})
	if err != nil {
		return nil, oauth.ErrInvalidRequest
	}
	s.identity = sha256.Sum256(frame)
	clear(frame)
	// ConsentReuseTTL is deliberately outside this legacy identity: changing a
	// reuse ceiling must not strand existing grants or encrypted preparation.
	// Explicit approval freezes its actual expiry; silent reuse never renews it
	// and checks both that original expiry and today's selected ceiling.
	// Narrowing enables a new operation, not a new policy for existing grants.
	// Preserve their prepared configuration identity; its separate input profile
	// and operation gate bind selection without stranding older recovery.
	if c.ConsentNarrowing || protocol.ManagedClients != nil {
		if err := s.coordinator(&phase{store: s}); err != nil {
			return nil, oauth.ErrInvalidRequest
		}
	}
	return s, nil
}

// NewService composes the native primary session owner and Store with the core
// protocol in one public entry point. No custom SessionReader/domain store is
// needed. It has NewStore's ownership, migration and concurrency obligations.
func NewService(pool *database.Pool, c Config, keys *keyring.Provider) (*oauth.Service, error) {
	store, err := NewStore(pool, c, keys)
	if err != nil {
		return nil, err
	}
	if store.config.Protocol.ManagedClients == nil && !webSelected(store.config.Protocol.Clients) {
		return oauth.NewService(store.config.Protocol, oauth.Dependencies{Store: store})
	}
	sessions, err := sessionpg.NewSessionService(pool, store.config.Session)
	if err != nil {
		return nil, oauth.ErrInvalidRequest
	}
	deps := oauth.Dependencies{Sessions: sessions, Store: store}
	if store.config.Protocol.ManagedClients != nil {
		deps.Clients = store
	}
	return oauth.NewService(store.config.Protocol, deps)
}

type clientPolicy struct {
	ID, Method, Resource, Platform string
	Version                        uint64
	Public                         bool
	Redirects, Scopes              []string
	Workload                       *workloadPolicy                `json:",omitempty"`
	SubjectRegistration            *oauth.OIDCSubjectRegistration `json:",omitempty"`
	PostLogoutRedirects            []string                       `json:",omitempty"`
	DeviceAuthorization            bool                           `json:",omitempty"`
}
type workloadPolicy struct {
	Tenant, ID string
	AccessTTL  time.Duration
}

func clientPolicies(clients []oauth.Client) []clientPolicy {
	out := make([]clientPolicy, len(clients))
	for i, c := range clients {
		out[i] = clientPolicy{ID: c.ID, Method: c.AuthenticationMethod, Resource: c.Resource, Platform: c.Owner.PlatformID(), Version: c.Version, Public: c.Public, Redirects: c.Redirects, Scopes: c.Scopes, PostLogoutRedirects: c.PostLogoutRedirects, DeviceAuthorization: c.DeviceAuthorization}
		if c.Workload != nil {
			out[i].Workload = &workloadPolicy{Tenant: string(c.Workload.TenantID()), ID: c.Workload.ID(), AccessTTL: c.Workload.AccessTTL()}
		}
		if c.SubjectRegistration != nil {
			owned := *c.SubjectRegistration
			out[i].SubjectRegistration = &owned
		}
	}
	return out
}
func clientFingerprint(c oauth.Client) [32]byte {
	wire, _ := json.Marshal(clientPolicies([]oauth.Client{c}))
	defer clear(wire)
	return sha256.Sum256(wire)
}

func (s *Store) coordinator(p *phase) error {
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return oauth.ErrInvalidRequest
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return oauth.ErrInvalidRequest
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.domain, s.counters, audits, lifecycle, p})
	if err != nil {
		return oauth.ErrInvalidRequest
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(s.pool, registry, s.config.Coordinator, s.config.RequestKeys)
	if err != nil {
		return oauth.ErrInvalidRequest
	}
	p.registry, p.coordinator = registry, coordinator
	return nil
}

// Format redacts runtime composition and stable correlation commitments.
func (*Store) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("oauthpostgres.Store(redacted)")) }

// MarshalJSON denies runtime custody export.
func (*Store) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

// MarshalText denies runtime custody export.
func (*Store) MarshalText() ([]byte, error) { return nil, oauth.ErrInvalidRequest }
