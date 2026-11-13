package oauthpostgres

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// OrganizationAPIKeyExchangeConfig separately selects one exact organization,
// tenant and modern native source. Source.Source must be NewOrganizationService
// on this primary; all borrowed owners must outlive the Store. Neither request
// text nor Basic authentication can choose another owner. Install the complete
// OrganizationAPIKeyExchangeMigrationSource before client bootstrap/enablement.
// This adds no human, workload, legacy-organization or cache authority. Released
// APIKeyExchangeConfig and Config shapes/default identities remain unchanged.
type OrganizationAPIKeyExchangeConfig struct {
	Source         APIKeyExchangeConfig
	OrganizationID apikey.OrganizationID
}

func (OrganizationAPIKeyExchangeConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oauthpostgres.OrganizationAPIKeyExchangeConfig(redacted)"))
}
func (OrganizationAPIKeyExchangeConfig) MarshalJSON() ([]byte, error) {
	return nil, oauth.ErrInvalidRequest
}

// NewOrganizationAPIKeyExchangeStore freezes the explicitly selected modern org
// source through the existing native coordinator. c.APIKeyExchange must be nil;
// its source comes only from selected, never two competing selectors. Existing
// NewStore remains USER-only. No schema, authority, transaction or worker is
// installed; original journal/preparation/recovery owners remain unchanged.
func NewOrganizationAPIKeyExchangeStore(pool *database.Pool, c Config, keys *keyring.Provider, selected OrganizationAPIKeyExchangeConfig) (*Store, error) {
	query := organization.CredentialAuthorityQuery{TenantID: selected.Source.TenantID, OrganizationID: organization.ID(selected.OrganizationID)}
	if c.APIKeyExchange != nil || c.Protocol.APIKeyExchange == nil || c.Protocol.APIKeyExchange.LegacySHA256 || query.Validate() != nil || selected.Source.Configuration.Spec().Algorithm != apikey.AlgorithmModernHMACSHA256 {
		return nil, oauth.ErrInvalidRequest
	}
	source := selected.Source
	c.APIKeyExchange = &source
	return newStore(pool, c, keys, apikey.OrganizationID(strings.Clone(string(selected.OrganizationID))))
}

// NewOrganizationAPIKeyExchangeService composes that exact Store with the core
// protocol and existing native owners. It requires no caller-written domain
// store, authority callback, verifier or orchestration. Construction/ownership
// and schema-before-profile obligations match the selected Store constructor.
func NewOrganizationAPIKeyExchangeService(pool *database.Pool, c Config, keys *keyring.Provider, selected OrganizationAPIKeyExchangeConfig) (*oauth.Service, error) {
	store, err := NewOrganizationAPIKeyExchangeStore(pool, c, keys, selected)
	if err != nil {
		return nil, err
	}
	return serviceFromStore(pool, store)
}

// A private closed holder retains either real owner observation without putting
// organization epochs into USER fields. It owns no authority or state machine.
type apiKeyCurrentAuthority struct {
	user         *apikey.SourceAuthorityObservation
	organization *apikey.OrganizationSourceAuthorityObservation
}

func (o apiKeyCurrentAuthority) grant() []string {
	if o.organization != nil && o.user == nil {
		return o.organization.Grant
	}
	if o.user != nil && o.organization == nil {
		return o.user.Grant
	}
	return nil
}
func (o apiKeyCurrentAuthority) started() time.Time {
	if o.organization != nil && o.user == nil {
		started := o.organization.ReadStartedAt
		if o.organization.OrganizationReadStartedAt.Before(started) {
			started = o.organization.OrganizationReadStartedAt
		}
		return started
	}
	if o.user != nil && o.organization == nil {
		return o.user.ReadStartedAt
	}
	return time.Time{}
}
func (o apiKeyCurrentAuthority) until() time.Time {
	if o.organization != nil && o.user == nil {
		return o.organization.ValidUntil
	}
	if o.user != nil && o.organization == nil {
		return o.user.ValidUntil
	}
	return time.Time{}
}

func (o apiKeyCurrentAuthority) validate(s *Store, g grantRecord, now time.Time) error {
	c := s.config.APIKeyExchange.Configuration
	if s.organizationAPIKeyID != "" {
		binding, err := g.APIKeySource.organizationBinding(c)
		if err != nil || o.organization == nil || o.user != nil {
			return oauth.ErrInvalidGrant
		}
		// The real source already validated this primary-DB snapshot. Do not
		// reinterpret its original VerifiedAt against the OAuth wall clock;
		// the source fence checks current DB time after all Work waits below.
		if !now.Before(o.organization.ValidUntil) {
			return oauth.ErrInvalidGrant
		}
		return o.organization.Validate(binding, c, o.organization.VerifiedAt)
	}
	binding, err := g.APIKeySource.binding(c)
	if err != nil || o.user == nil || o.organization != nil {
		return oauth.ErrInvalidGrant
	}
	return o.user.Validate(binding, c, now)
}

func (o apiKeyCurrentAuthority) require(ctx context.Context, s *Store, w kernel.Work, p kernel.FeatureExecutionContributor) error {
	if s.organizationAPIKeyID != "" && o.organization != nil && o.user == nil {
		return s.config.APIKeyExchange.Source.RequireOrganizationSourceAuthority(ctx, w, p, *o.organization)
	}
	if s.organizationAPIKeyID == "" && o.user != nil && o.organization == nil {
		return s.config.APIKeyExchange.Source.RequireSourceAuthority(ctx, w, p, *o.user)
	}
	return identity.ForbiddenError{}
}

func (s apiKeyGrantSource) organizationBinding(c apikey.Configuration) (apikey.OrganizationSourceAuthorityBinding, error) {
	binding, err := s.sourceBinding()
	if err != nil || !s.sourceWindow(c) {
		return apikey.OrganizationSourceAuthorityBinding{}, oauth.ErrInvalidGrant
	}
	org := apikey.OrganizationSourceAuthorityBinding(binding)
	if org.Validate(c) != nil {
		return apikey.OrganizationSourceAuthorityBinding{}, oauth.ErrInvalidGrant
	}
	return org, nil
}

func (s *Store) sourceFromVerification(r apikey.VerificationResult, now time.Time) (*apiKeyGrantSource, error) {
	c := s.config.APIKeyExchange.Configuration
	if s.organizationAPIKeyID == "" {
		return apiKeySourceFromVerification(r, c, now)
	}
	binding, err := apikey.NewOrganizationSourceAuthorityBinding(r, c, now)
	if err != nil || binding.Owner.Spec().OrganizationID != s.organizationAPIKeyID {
		return nil, oauth.ErrInvalidGrant
	}
	return apiKeySourceProjection(apikey.SourceAuthorityBinding(binding), r), nil
}

func (s *Store) sourceOwnerMatches(g grantRecord) bool {
	owner := g.APIKeySource.Owner
	if owner.TenantID != s.config.APIKeyExchange.TenantID || g.Tenant != owner.TenantID {
		return false
	}
	if s.organizationAPIKeyID != "" {
		_, err := g.APIKeySource.organizationBinding(s.config.APIKeyExchange.Configuration)
		return err == nil && owner.Kind == apikey.OwnerOrganization && owner.OrganizationID == s.organizationAPIKeyID && owner.UserID == "" && g.User == ""
	}
	_, err := g.APIKeySource.binding(s.config.APIKeyExchange.Configuration)
	return err == nil && owner.Kind == apikey.OwnerUser && g.User == owner.UserID
}

func (s *Store) currentAPIKey(ctx context.Context, g grantRecord) (apiKeyCurrentAuthority, error) {
	c := s.config.APIKeyExchange.Configuration
	if s.organizationAPIKeyID != "" {
		binding, err := g.APIKeySource.organizationBinding(c)
		if err != nil {
			return apiKeyCurrentAuthority{}, err
		}
		current, err := s.config.APIKeyExchange.Source.ObserveOrganizationSourceAuthority(ctx, binding)
		if err != nil {
			return apiKeyCurrentAuthority{}, apiKeyError(ctx, err)
		}
		return apiKeyCurrentAuthority{organization: &current}, nil
	}
	binding, err := g.APIKeySource.binding(c)
	if err != nil {
		return apiKeyCurrentAuthority{}, err
	}
	current, err := s.config.APIKeyExchange.Source.ObserveSourceAuthority(ctx, binding)
	if err != nil {
		return apiKeyCurrentAuthority{}, apiKeyError(ctx, err)
	}
	return apiKeyCurrentAuthority{user: &current}, nil
}

func (s *Store) organizationAPIKeySchemaReady(ctx context.Context) error {
	if s.organizationAPIKeyID == "" {
		return nil
	}
	var ready bool
	err := s.pool.Raw().QueryRow(ctx, `SELECT count(*)=2 AND bool_and(convalidated) AND NOT (SELECT attnotnull FROM pg_attribute WHERE attrelid=($1||'.grants')::regclass AND attname='user_id') FROM pg_constraint WHERE conrelid=($1||'.grants')::regclass AND conname IN('grants_api_key_organization_owner','grants_api_key_organization_source')`, s.config.Schema).Scan(&ready)
	if err != nil || !ready {
		return oauth.ErrUnavailable
	}
	return nil
}

func apiKeySourceProjection(b apikey.SourceAuthorityBinding, r apikey.VerificationResult) *apiKeyGrantSource {
	return &apiKeyGrantSource{ConfigurationID: b.ConfigurationAuthority.ConfigurationID, ConfigurationRevision: b.ConfigurationRevision, ConfigurationAuthority: b.ConfigurationAuthority.Version, KeyID: b.KeyID, RootID: b.RootID, Owner: b.Owner.Spec(), AuthorityVersion: b.AuthorityVersion, RootVersion: b.RootVersion, Issuer: b.Issuer, Environment: b.Environment, Audience: b.Audience, Grant: slices.Clone(b.Grant), ExpiresAt: b.ExpiresAt, ReadStartedAt: r.ReadStartedAt, VerifiedAt: r.VerifiedAt, ValidUntil: r.ValidUntil}
}
