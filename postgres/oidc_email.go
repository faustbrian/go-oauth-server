package oauthpostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
)

func earliestUserInfoExpiry(values ...time.Time) time.Time {
	var earliest time.Time
	for _, value := range values {
		if !value.IsZero() && (earliest.IsZero() || value.Before(earliest)) {
			earliest = value
		}
	}
	return earliest
}

// This adapter transports the selected extension's native primary custody; it
// does not choose a contact or interpret verification as an OIDC claim. The
// child owns that policy. No callback, cache or substitute directory is used.
func (s *Store) userInfoIdentifiers(ctx context.Context, token string, client oauth.Client, original artifactRecord, out oauth.OIDCClaimsInput, start time.Time) (oauth.OIDCClaimsInput, error) {
	query := identity.IdentifierQuery{TenantID: original.Grant.Tenant, UserID: original.Grant.User, MaximumIdentifiers: 128}
	before, err := s.domain.GetIdentifierState(ctx, query)
	if err != nil {
		return oauth.OIDCClaimsInput{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	now, err := s.introspectionTime(ctx)
	if err != nil {
		return oauth.OIDCClaimsInput{}, err
	}
	credentialExpiry, err := s.introspectionAuthority(ctx, original.Grant, now)
	if err != nil {
		return oauth.OIDCClaimsInput{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	out.AuthorityExpiresAt = earliestUserInfoExpiry(out.AuthorityExpiresAt, credentialExpiry)
	after, err := s.domain.GetIdentifierState(ctx, query)
	if err != nil {
		return oauth.OIDCClaimsInput{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if !sameJSON(before, after) {
		return oauth.OIDCClaimsInput{}, oauth.ErrAccessDenied
	}
	// Repeat the native token/client/grant/consent/subject fences after the
	// directory work. A second read cannot renew the original 20-second window.
	current, err := s.lookup(ctx, token, client, []oauth.TokenKind{oauth.TokenAccess})
	if err != nil {
		return oauth.OIDCClaimsInput{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	var keyState string
	if current.Payload.SigningKeyID == "" || s.pool.Raw().QueryRow(ctx, `SELECT state FROM `+s.schema+`.signing_keys WHERE kid=$1`, current.Payload.SigningKeyID).Scan(&keyState) != nil || keyState == "compromised" {
		return oauth.OIDCClaimsInput{}, oauth.ErrAccessDenied
	}
	now, err = s.introspectionTime(ctx)
	if err != nil {
		return oauth.OIDCClaimsInput{}, err
	}
	if err := ctx.Err(); err != nil {
		return oauth.OIDCClaimsInput{}, err
	}
	if err := s.grantEndSessionFence(ctx, original.Grant); err != nil {
		return oauth.OIDCClaimsInput{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	finished := s.now()
	if finished.Before(start) || !finished.Before(out.AuthorityExpiresAt) || !now.Before(out.AuthorityExpiresAt) || !activeIntrospectionArtifact(current, now) || !sameJSON(original, current) {
		return oauth.OIDCClaimsInput{}, oauth.ErrAccessDenied
	}
	out.Identifiers = &after
	return out, nil
}
