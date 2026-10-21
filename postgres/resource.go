package oauthpostgres

import (
	"context"
	"errors"
	"slices"
	"time"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// NewResourceVerifier composes the direct opaque-access profile over actual
// primary OAuth/identity owners. Policy is trusted startup input, not request
// selection. Install and select ConsentManagement before construction; exact
// client/version/issuer/environment/resource mismatches deny, never retarget.
// No introspection endpoint, client credential, cache, worker or migration is
// installed. Borrowed pool, keys and clocks must outlive concurrent calls.
func NewResourceVerifier(pool *database.Pool, c Config, keys *keyring.Provider, policy oauth.ResourceVerificationConfig) (*oauth.ResourceVerifier, error) {
	policy, err := policy.Validated()
	if err != nil || !c.ConsentManagement {
		return nil, oauth.ErrInvalidRequest
	}
	s, err := NewStore(pool, c, keys)
	if err != nil {
		return nil, err
	}
	var client oauth.Client
	for _, candidate := range s.config.Protocol.Clients {
		if candidate.ID == policy.ClientID {
			client = candidate
			break
		}
	}
	if client.ID == "" || client.Workload != nil || client.Version != policy.ClientVersion || policy.Issuer != s.config.Protocol.Issuer || policy.Environment != s.config.Protocol.Environment || policy.Resource != client.Resource || !scopeSubset(policy.Scopes.Scopes(), client.Scopes) {
		return nil, oauth.ErrInvalidRequest
	}
	if s.policy == nil {
		s.policy, err = authority.NewAuthorityStore(pool.Raw(), s.config.Protocol.MaximumDuration)
		if err != nil {
			return nil, oauth.ErrInvalidRequest
		}
	}
	return oauth.NewResourceVerifier(policy, &resourceAccessReader{store: s, policy: policy, client: client})
}

// The private reader captures all trust context; the only per-call input is
// borrowed access custody. An introspection Active value never enters this path.
type resourceAccessReader struct {
	store  *Store
	policy oauth.ResourceVerificationConfig
	client oauth.Client
}

func (r *resourceAccessReader) ReadResourceAccess(ctx context.Context, token string) (out oauth.ResourceAccessProjection, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.ResourceAccessProjection{}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := r.store.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	s := r.store
	start := s.now()
	// Token.Digest authenticates issuer/environment/client/kind with independent
	// length framing. lookup's persisted digest/version/kind/client predicate
	// proves this exact namespace; no absent issuer column is treated as proof.
	a, err := s.lookup(ctx, token, r.client, []oauth.TokenKind{oauth.TokenAccess})
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
	credentialExpiry, err := s.introspectionAuthority(ctx, a.Grant, now)
	if err != nil {
		return out, resourceAccessError(ctx, err)
	}
	current, err := s.lookup(ctx, token, r.client, []oauth.TokenKind{oauth.TokenAccess})
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
	// The first primary owner pass is not renewable evidence. Repeat it after
	// late OAuth work, retaining the earliest original credential expiry, then
	// fence actual token/consent generation again before returning any identity.
	currentCredentialExpiry, err := s.introspectionAuthority(ctx, a.Grant, now)
	if err != nil {
		return out, resourceAccessError(ctx, err)
	}
	current, err = s.lookup(ctx, token, r.client, []oauth.TokenKind{oauth.TokenAccess})
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
	if finished.Before(start) || !finished.Before(start.Add(20*time.Second)) {
		return out, oauth.ErrUnavailable
	}
	if !r.active(current, now) || !sameJSON(current, a) {
		return out, oauth.ErrInvalidResourceToken
	}
	until := resourceExpiry(start.Add(20*time.Second), a.ExpiresAt, a.Grant.ExpiresAt, credentialExpiry, currentCredentialExpiry)
	if !now.Before(until) || !finished.Before(until) {
		return out, oauth.ErrInvalidResourceToken
	}
	return oauth.ResourceAccessProjection{Issuer: s.config.Protocol.Issuer, Environment: s.config.Protocol.Environment, TenantID: a.Grant.Tenant, UserID: a.Grant.User, ClientID: a.Grant.ClientID, ClientVersion: a.Grant.ClientVersion, Resource: a.Grant.Resource, Kind: a.Kind, Scopes: slices.Clone(scopes), ReadStartedAt: start, ValidUntil: until, TokenExpiresAt: resourceExpiry(a.ExpiresAt, a.Grant.ExpiresAt), CredentialExpiresAt: resourceExpiry(credentialExpiry, currentCredentialExpiry)}, nil
}

func (r *resourceAccessReader) active(a artifactRecord, now time.Time) bool {
	return a.Kind == oauth.TokenAccess && a.Grant.Workload == nil && a.Grant.User != "" && a.Grant.Tenant == r.policy.TenantID && a.Grant.ClientID == r.policy.ClientID && a.Grant.ClientVersion == r.policy.ClientVersion && a.Grant.Resource == r.policy.Resource && activeIntrospectionArtifact(a, now)
}

func resourceExpiry(values ...time.Time) time.Time {
	var until time.Time
	for _, value := range values {
		if !value.IsZero() && (until.IsZero() || value.Before(until)) {
			until = value
		}
	}
	return until
}

func resourceAccessError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, oauth.ErrAccessDenied) || introspectionError(ctx, err) == nil {
		return oauth.ErrInvalidResourceToken
	}
	return oauth.ErrUnavailable
}
