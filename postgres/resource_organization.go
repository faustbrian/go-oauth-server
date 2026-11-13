package oauthpostgres

import (
	"context"
	"slices"
	"time"

	"github.com/faustbrian/go-identity/apikey"
	oauth "github.com/faustbrian/go-oauth-server"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// NewOrganizationResourceVerifier composes actual opaque access, current
// organization/key/client owners and bounded parent lineage for one fixed
// organization policy. Install and select the separate modern organization key
// profile first; no consent/session USER substitute or introspection Active
// value is accepted. Pool, keys, source and clocks remain caller-owned and must
// outlive concurrent calls. No worker, cache, journal or migration is installed.
func NewOrganizationResourceVerifier(pool *database.Pool, c Config, keys *keyring.Provider, selected OrganizationAPIKeyExchangeConfig, policy oauth.OrganizationResourceVerificationConfig) (*oauth.OrganizationResourceVerifier, error) {
	policy, err := policy.Validated()
	if err != nil || policy.OrganizationID != selected.OrganizationID || policy.Verification.TenantID != selected.Source.TenantID {
		return nil, oauth.ErrInvalidRequest
	}
	s, err := NewOrganizationAPIKeyExchangeStore(pool, c, keys, selected)
	if err != nil {
		return nil, err
	}
	var client oauth.Client
	for _, candidate := range s.config.Protocol.Clients {
		if candidate.ID == policy.Verification.ClientID {
			client = candidate
			break
		}
	}
	p := policy.Verification
	if !s.apiKeyExchangeSelected(client) || client.Version != p.ClientVersion || p.Issuer != s.config.Protocol.Issuer || p.Environment != s.config.Protocol.Environment || p.Resource != client.Resource || !scopeSubset(p.Scopes.Scopes(), client.Scopes) {
		return nil, oauth.ErrInvalidRequest
	}
	return oauth.NewOrganizationResourceVerifier(policy, &organizationResourceReader{store: s, policy: policy, client: client})
}

type organizationResourceReader struct {
	store  *Store
	policy oauth.OrganizationResourceVerificationConfig
	client oauth.Client
}

func (r *organizationResourceReader) active(a artifactRecord, now time.Time) bool {
	p := r.policy.Verification
	return a.Kind == oauth.TokenAccess && a.Grant.Workload == nil && a.Grant.APIKeySource != nil && a.Grant.User == "" && a.APIKeyOnly && a.Grant.Tenant == p.TenantID && a.Grant.ClientID == p.ClientID && a.Grant.ClientVersion == p.ClientVersion && a.Grant.Resource == p.Resource && activeIntrospectionArtifact(a, now) && r.store.validAPIKeyLineage(a.Payload.APIKeyExchange, a.Grant, r.client)
}

func (r *organizationResourceReader) ReadOrganizationResourceAccess(ctx context.Context, wire string) (out oauth.OrganizationResourceAccessProjection, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.OrganizationResourceAccessProjection{}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := r.store.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	s := r.store
	started := s.now()
	// lookup authenticates the actual issuer/environment/client/access digest
	// namespace. No source key or current validity struct can replace custody.
	a, err := s.lookup(ctx, wire, r.client, []oauth.TokenKind{oauth.TokenAccess})
	if err != nil {
		return out, resourceAccessError(ctx, err)
	}
	now, err := s.introspectionTime(ctx)
	if err != nil {
		return out, err
	}
	if !r.active(a, now) {
		return out, oauth.ErrInvalidResourceToken
	}
	scopes, err := selectedScopes(a.Payload.Scopes)
	if err != nil || !slices.Equal(scopes, a.Payload.Scopes) || !scopeSubset(scopes, r.client.Scopes) {
		return out, oauth.ErrInvalidResourceToken
	}
	first, err := s.observeAPIKey(ctx, a.Grant, r.client)
	if err != nil {
		return out, resourceAccessError(ctx, err)
	}
	if first.organization == nil || !scopeSubset(scopes, first.grant()) || !now.Before(first.until()) {
		return out, oauth.ErrInvalidResourceToken
	}
	if err := s.readAPIKeyLineage(ctx, a, r.client, now); err != nil {
		return out, resourceAccessError(ctx, err)
	}
	current, err := s.lookup(ctx, wire, r.client, []oauth.TokenKind{oauth.TokenAccess})
	if err != nil {
		return out, resourceAccessError(ctx, err)
	}
	now, err = s.introspectionTime(ctx)
	if err != nil {
		return out, err
	}
	if !r.active(current, now) || !sameJSON(current, a) {
		return out, oauth.ErrInvalidResourceToken
	}
	// Repeat current primary owners after late token/lineage work, retaining
	// both original windows instead of promoting the later positive read.
	last, err := s.observeAPIKey(ctx, a.Grant, r.client)
	if err != nil {
		return out, resourceAccessError(ctx, err)
	}
	if last.organization == nil || !scopeSubset(scopes, last.grant()) {
		return out, oauth.ErrInvalidResourceToken
	}
	if err := s.readAPIKeyLineage(ctx, a, r.client, now); err != nil {
		return out, resourceAccessError(ctx, err)
	}
	current, err = s.lookup(ctx, wire, r.client, []oauth.TokenKind{oauth.TokenAccess})
	if err != nil {
		return out, resourceAccessError(ctx, err)
	}
	now, err = s.introspectionTime(ctx)
	if err != nil {
		return out, err
	}
	finished := s.now()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if finished.Before(started) || !finished.Before(started.Add(20*time.Second)) {
		return out, oauth.ErrUnavailable
	}
	if !r.active(current, now) || !sameJSON(current, a) {
		return out, oauth.ErrInvalidResourceToken
	}
	until := resourceExpiry(started.Add(20*time.Second), a.ExpiresAt, a.Grant.ExpiresAt, a.Grant.APIKeySource.ExpiresAt, first.until(), last.until())
	if !now.Before(until) || !finished.Before(until) {
		return out, oauth.ErrInvalidResourceToken
	}
	for _, originalStart := range []time.Time{first.started(), last.started()} {
		if originalStart.Before(started) {
			started = originalStart
		}
	}
	lineage := a.Payload.APIKeyExchange
	owner := last.organization.Owner
	if owner.Spec().Kind != apikey.OwnerOrganization || owner.Spec().OrganizationID != r.policy.OrganizationID {
		return out, oauth.ErrInvalidResourceToken
	}
	return oauth.OrganizationResourceAccessProjection{Issuer: s.config.Protocol.Issuer, Environment: s.config.Protocol.Environment, Owner: owner, APIKeyActor: a.Grant.APIKeySource.KeyID, TenantID: a.Grant.Tenant, ClientID: a.Grant.ClientID, ClientVersion: a.Grant.ClientVersion, Resource: a.Grant.Resource, Scopes: slices.Clone(scopes), Kind: a.Kind, Lineage: oauth.OrganizationResourceLineage{RootID: a.Grant.APIKeySource.RootID, RootVersion: lineage.RootVersion, ParentID: lineage.ParentID, ParentTokenType: lineage.ParentTokenType, ParentVersion: lineage.ParentVersion, TokenID: a.ID, Depth: lineage.Depth}, ReadStartedAt: started, ValidUntil: until, TokenExpiresAt: resourceExpiry(a.ExpiresAt, a.Grant.ExpiresAt), CredentialExpiresAt: a.Grant.APIKeySource.ExpiresAt}, nil
}
