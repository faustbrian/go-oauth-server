package oauthpostgres

import (
	"context"
	"slices"
	"time"

	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

var _ oauth.UserInfoReader = (*Store)(nil)

// UserInfo admits only a genuine current access artifact for its registered
// human client. Both primary OAuth reads fence the same original authority read;
// neither this projection nor the child may turn it into a positive cache.
func (s *Store) UserInfo(ctx context.Context, c oauth.UserInfoCommand) (out oauth.OIDCClaimsInput, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.OIDCClaimsInput{}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	client, err := s.checkedClient(ctx, c.Client)
	if err != nil || client.Workload != nil || client.ID != c.Request.ClientID {
		return out, oauth.ErrAccessDenied
	}
	start := s.now()
	a, err := s.lookup(ctx, c.Request.AccessToken, client, []oauth.TokenKind{oauth.TokenAccess})
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	now, err := s.introspectionTime(ctx)
	if err != nil {
		return out, err
	}
	if !activeIntrospectionArtifact(a, now) || a.Payload.Subject == "" {
		return out, oauth.ErrAccessDenied
	}
	credentialExpiry, err := s.introspectionAuthority(ctx, a.Grant, now)
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	current, err := s.lookup(ctx, c.Request.AccessToken, client, []oauth.TokenKind{oauth.TokenAccess})
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	now, err = s.introspectionTime(ctx)
	if err != nil {
		return out, err
	}
	if err := s.grantEndSessionFence(ctx, a.Grant); err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	finished := s.now()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if finished.Before(start) || !finished.Before(start.Add(20*time.Second)) {
		return out, oauth.ErrUnavailable
	}
	if !activeIntrospectionArtifact(current, now) || !sameJSON(a, current) || !credentialExpiry.IsZero() && !now.Before(credentialExpiry) {
		return out, oauth.ErrAccessDenied
	}
	var state string
	if a.Payload.SigningKeyID == "" || s.pool.Raw().QueryRow(ctx, `SELECT state FROM `+s.schema+`.signing_keys WHERE kid=$1`, a.Payload.SigningKeyID).Scan(&state) != nil || state == "compromised" {
		return out, oauth.ErrAccessDenied
	}
	original, err := sessionpg.OriginalSessionFromFields(a.Grant.Tenant, a.Grant.User, a.Grant.Source)
	if err != nil {
		return out, oauth.ErrAccessDenied
	}
	bindings, err := original.Bindings()
	if err != nil {
		return out, oauth.ErrAccessDenied
	}
	registration, boundSubject, err := subjectClaims(client, a.Grant)
	if err != nil || boundSubject != "" && boundSubject != a.Payload.Subject {
		return out, oauth.ErrAccessDenied
	}
	out = oauth.OIDCClaimsInput{Issuer: s.config.Protocol.Issuer, Environment: s.config.Protocol.Environment, TenantID: a.Grant.Tenant, UserID: a.Grant.User, ClientID: client.ID, Nonce: a.Payload.Request.Nonce, ExpectedSubject: a.Payload.Subject, Scopes: slices.Clone(a.Payload.Scopes), IssuedAt: a.CreatedAt, ExpiresAt: a.ExpiresAt, AuthenticatedAt: bindings.Authentication.Proof.IssuedAt, UserInfo: true, SubjectRegistration: registration, BoundSubject: boundSubject,
		AuthorityExpiresAt: earliestUserInfoExpiry(start.Add(20*time.Second), a.ExpiresAt, a.Grant.ExpiresAt, credentialExpiry)}
	if slices.Contains(a.Payload.Scopes, "email") || slices.Contains(a.Payload.Scopes, "phone") {
		lifetime, err := original.Lifetime(now)
		if err != nil {
			return oauth.OIDCClaimsInput{}, oauth.ErrAccessDenied
		}
		out.AuthorityExpiresAt = earliestUserInfoExpiry(out.AuthorityExpiresAt, lifetime.ExpiresAt)
		return s.userInfoIdentifiers(ctx, c.Request.AccessToken, client, a, out, start)
	}
	return out, nil
}
