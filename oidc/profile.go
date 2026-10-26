package oidc

import (
	"context"
	"slices"
	"unicode/utf8"

	oauth "github.com/faustbrian/go-oauth-server"
)

func (s *Service) profileClaims(ctx context.Context, in oauth.OIDCClaimsInput) (UserInfo, error) {
	if err := ctx.Err(); err != nil {
		return UserInfo{}, err
	}
	if !s.config.ProfileUserInfo || !in.UserInfo || !slices.Contains(in.Scopes, "profile") || in.AuthorityExpiresAt.IsZero() || !s.config.Clock.Now().Before(in.AuthorityExpiresAt) || in.Profile == nil {
		return UserInfo{}, oauth.ErrAccessDenied
	}
	record := in.Profile
	p := record.Profile
	if record.User.Validate(in.TenantID) != nil || !record.User.Status.AllowsAuthentication() || record.User.ID != in.UserID || p.ID != in.UserID || p.TenantID != in.TenantID || p.Version != record.User.Version || len(p.Name) > 256 || !utf8.ValidString(p.Name) || p.Image != "" || len(p.AdditionalFields) != 0 {
		return UserInfo{}, oauth.ErrAccessDenied
	}
	if err := ctx.Err(); err != nil {
		return UserInfo{}, err
	}
	if !s.config.Clock.Now().Before(in.AuthorityExpiresAt) {
		return UserInfo{}, oauth.ErrAccessDenied
	}
	// OIDC Core1.0 errata2 §§5.1/5.4: name is a voluntary display claim.
	// No name omits the claim; the profile scope does not imply every field.
	return UserInfo{Name: p.Name}, nil
}
