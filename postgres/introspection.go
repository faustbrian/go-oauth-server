package oauthpostgres

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

var _ oauth.Introspector = (*Store)(nil)

// Introspect reads an actual opaque token for its separately authenticated,
// owning confidential client. It is opt-in, bounded, uncached and read-only.
// Current original directory/user/identifier/credential/authorization expectations
// match code/refresh admission; ordinary browser logout does not revoke an
// approved OAuth grant. No source session is authenticated or issued here.
// Unknown/foreign/inactive/withdrawn tokens return only false; dependency failures
// and cancellation deny with zero metadata. Explicit machine grants instead
// check their frozen directory/workload authorization epochs, not a fabricated
// user/session. Token hints never constrain lookup.
func (s *Store) Introspect(ctx context.Context, c oauth.IntrospectionCommand) (out oauth.IntrospectResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.IntrospectResult{}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if !s.config.Protocol.OwningClientIntrospection {
		return out, oauth.ErrAccessDenied
	}
	client, err := s.checkedClient(ctx, c.Client)
	if err != nil || client.Public || c.Request.ClientAuthentication.Method() != "client_secret_basic" || c.Request.ClientID != client.ID {
		return out, oauth.ErrInvalidClient
	}
	proof, err := s.authenticateClientSnapshot(ctx, client, c.Request.ClientAuthentication)
	if err != nil {
		return out, err
	}
	defer func() {
		if err == nil {
			if fence := s.finishClientAuthentication(ctx, client, proof); fence != nil {
				out = oauth.IntrospectResult{}
				err = fence
			}
		}
	}()
	if !boundedText(c.Request.Token, 2048) || c.Request.Hint != 0 && c.Request.Hint != oauth.TokenAccess && c.Request.Hint != oauth.TokenRefresh {
		return out, oauth.ErrInvalidRequest
	}
	// All contributing primary reads share this original bounded start. Neither
	// the final fence nor a later caller may renew it (shared-issuer-v1 SI-05/06).
	start := s.now()
	target, err := s.lookup(ctx, c.Request.Token, client, []oauth.TokenKind{oauth.TokenAccess, oauth.TokenRefresh})
	if err != nil {
		return out, introspectionError(ctx, err)
	}
	now, err := s.introspectionTime(ctx)
	if err != nil {
		return out, err
	}
	if !activeIntrospectionArtifact(target, now) {
		return out, nil
	}
	scopes, err := selectedScopes(target.Payload.Scopes)
	if err != nil || !slices.Equal(scopes, target.Payload.Scopes) || !scopeSubset(scopes, client.Scopes) {
		return out, nil
	}
	var credentialExpiry time.Time
	if target.Grant.Workload != nil {
		credentialExpiry, err = s.workloadIntrospectionAuthority(ctx, target.Grant, client)
	} else {
		credentialExpiry, err = s.introspectionAuthority(ctx, target.Grant, now)
	}
	if err != nil {
		return out, introspectionError(ctx, err)
	}
	// Re-read the actual OAuth rows after authority reads, so a concurrent
	// rotation, access revocation or family withdrawal cannot reuse the initial
	// positive token state. This is not an independent transaction or lease.
	current, err := s.lookup(ctx, c.Request.Token, client, []oauth.TokenKind{oauth.TokenAccess, oauth.TokenRefresh})
	if err != nil {
		return out, introspectionError(ctx, err)
	}
	now, err = s.introspectionTime(ctx)
	if err != nil {
		return out, err
	}
	if err := s.grantEndSessionFence(ctx, target.Grant); err != nil {
		return out, introspectionError(ctx, err)
	}
	finished := s.now()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if finished.Before(start) || !finished.Before(start.Add(20*time.Second)) {
		return out, oauth.ErrUnavailable
	}
	if !activeIntrospectionArtifact(current, now) || !sameJSON(current, target) || !credentialExpiry.IsZero() && !now.Before(credentialExpiry) {
		return out, nil
	}
	subject := string(target.Grant.User)
	if target.Grant.Workload != nil {
		subject = target.Grant.Workload.ID
	}
	return oauth.IntrospectResult{Active: true, ClientID: client.ID, Subject: subject, Resource: target.Grant.Resource, Issuer: s.config.Protocol.Issuer, Scopes: scopes, ExpiresAt: target.ExpiresAt}, nil
}

func activeIntrospectionArtifact(a artifactRecord, now time.Time) bool {
	return a.State == "active" && a.GrantState == "active" && !now.Before(a.CreatedAt) && !now.Before(a.Grant.CreatedAt) && now.Before(a.ExpiresAt) && now.Before(a.Grant.ExpiresAt) && !a.ExpiresAt.After(a.Grant.ExpiresAt)
}

func (s *Store) introspectionTime(ctx context.Context) (time.Time, error) {
	var now time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	return now, nil
}

// OriginalSessionAdmission is the public owner of the exact supported source
// vocabulary and method/authority scope mapping. Only its frozen expectations
// are compared below; OAuth neither reconstructs identity SQL nor infers epochs.
func (s *Store) introspectionAuthority(ctx context.Context, g grantRecord, now time.Time) (time.Time, error) {
	if err := s.grantEndSessionFence(ctx, g); err != nil {
		return time.Time{}, err
	}
	return s.originalGrantAuthority(ctx, g, now)
}

// Historical logout result access checks the original account/credential and
// current result-access policy, but must not treat its own tombstone as denial.
// This projection authenticates no browser session and grants no token lease.
func (s *Store) originalGrantAuthority(ctx context.Context, g grantRecord, now time.Time) (time.Time, error) {
	original, err := sessionpg.OriginalSessionFromFields(g.Tenant, g.User, g.Source)
	if err != nil {
		return time.Time{}, oauth.ErrInvalidGrant
	}
	binding := identity.CommandBinding{TenantID: g.Tenant, UserID: g.User, ActorID: identity.ActorID(g.User), ActorKind: authorization.SubjectUser}
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(s.config.Session.Profile, original, binding)
	if err != nil {
		return time.Time{}, oauth.ErrInvalidGrant
	}
	currentDirectory, err := s.domain.GetDirectoryAuthority(ctx, directory.Query)
	if err != nil {
		return time.Time{}, err
	}
	status, err := s.domain.GetStatus(ctx, identity.UserStatusQuery{TenantID: g.Tenant, UserID: g.User})
	if err != nil {
		return time.Time{}, err
	}
	identifiers, err := s.domain.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: g.Tenant, UserID: g.User, MaximumIdentifiers: 128})
	if err != nil {
		return time.Time{}, err
	}
	currentCredential, err := s.domain.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: g.Tenant, UserID: g.User, CredentialID: credential.Credential.ID})
	if err != nil {
		return time.Time{}, err
	}
	currentPolicy, err := s.policy.Get(ctx, policy.Scope)
	if err != nil {
		return time.Time{}, err
	}
	if !currentDirectory.Enabled || currentDirectory.GlobalVersion != directory.GlobalVersion || currentDirectory.TenantVersion != directory.TenantVersion || !status.User.Status.AllowsAuthentication() || status.AuthorityVersion != credential.UserAuthorityVersion || !identifiers.User.Status.AllowsAuthentication() || identifiers.AuthorityVersion != credential.IdentifierAuthorityVersion || identity.CheckCredentialAuthority(currentCredential, credential.Credential, credential.CredentialAuthorityVersion, now) != nil || currentPolicy.Version != policy.Version {
		return time.Time{}, oauth.ErrInvalidGrant
	}
	return currentCredential.ExpiresAt, nil
}

func introspectionError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var denied identity.ForbiddenError
	if errors.Is(err, oauth.ErrInvalidGrant) || errors.Is(err, identity.ErrUserAbsent) || errors.Is(err, authority.ErrAuthorityDenied) || errors.As(err, &denied) {
		return nil
	}
	return oauth.ErrUnavailable
}
