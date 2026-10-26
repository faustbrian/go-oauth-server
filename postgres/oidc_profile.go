package oauthpostgres

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	database "github.com/faustbrian/go-postgres"
)

// ProfileUserInfoConfig selects an exact existing identity profile schema from
// the same borrowed primary pool. NewStore freezes AttributeSchemas through the
// public identity repository and inherits the protocol/caller read budget. This
// configuration is neither consent nor permission to rewrite stored schemas.
// No callback, raw identity-table reader, migration or background work is added.
type ProfileUserInfoConfig struct {
	AttributeSchemas []identity.AttributeSchema
	ProfileSchema    kernel.ProfileSchemaRef
}

// Format prevents private schema defaults from entering diagnostics.
func (ProfileUserInfoConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oauthpostgres.ProfileUserInfoConfig(redacted)"))
}

// MarshalJSON rejects implicit disclosure of caller-owned schema defaults.
func (ProfileUserInfoConfig) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

// MarshalText rejects implicit disclosure of caller-owned schema defaults.
func (ProfileUserInfoConfig) MarshalText() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

func newUserInfoProfileRepository(pool *database.Pool, c Config) (*kernel.Repository, error) {
	if c.Protocol.OIDCScopes.Contains("profile") != (c.ProfileUserInfo != nil) {
		return nil, oauth.ErrInvalidRequest
	}
	if c.ProfileUserInfo == nil {
		return nil, nil
	}
	if !webSelected(c.Protocol.Clients) || c.ProfileUserInfo.ProfileSchema.ID == "" || c.ProfileUserInfo.ProfileSchema.Version == 0 {
		return nil, oauth.ErrInvalidRequest
	}
	return kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Protocol.MaximumDuration, AttributeSchemas: c.ProfileUserInfo.AttributeSchemas, ProfileSchema: c.ProfileUserInfo.ProfileSchema})
}

// The existing profile owner reads one aggregate snapshot, with all stored
// values/schema validated before its name-only projection. Bracket authority
// work with two snapshots; an intervening profile/version change denies this
// call instead of combining before/after data. A new authorized call may read
// the committed current name, without changing its original grant authority.
func (s *Store) userInfoProfile(ctx context.Context, token string, client oauth.Client, original artifactRecord, out oauth.OIDCClaimsInput, start time.Time) (oauth.OIDCClaimsInput, error) {
	if s.profiles == nil {
		return oauth.OIDCClaimsInput{}, oauth.ErrAccessDenied
	}
	query := identity.ProfileQuery{TenantID: original.Grant.Tenant, UserID: original.Grant.User, Fields: []identity.FieldName{{Value: "name"}}}
	before, err := s.profiles.GetProfile(ctx, query)
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
	after, err := s.profiles.GetProfile(ctx, query)
	if err != nil {
		return oauth.OIDCClaimsInput{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if !sameJSON(before, after) {
		return oauth.OIDCClaimsInput{}, oauth.ErrAccessDenied
	}
	// Recheck the original owners after projection work, including changes that
	// commit as the second profile read finishes. These reads cannot renew the
	// original session/credential/grant/read-start validity ceiling.
	now, err = s.introspectionTime(ctx)
	if err != nil {
		return oauth.OIDCClaimsInput{}, err
	}
	credentialExpiry, err = s.introspectionAuthority(ctx, original.Grant, now)
	if err != nil {
		return oauth.OIDCClaimsInput{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	out.AuthorityExpiresAt = earliestUserInfoExpiry(out.AuthorityExpiresAt, credentialExpiry)
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
	out.Profile = &after
	return out, nil
}
