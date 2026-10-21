package oidc

import (
	"context"
	"slices"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
)

func (s *Service) phoneClaims(ctx context.Context, in oauth.OIDCClaimsInput) (UserInfo, error) {
	if err := ctx.Err(); err != nil {
		return UserInfo{}, err
	}
	now := s.config.Clock.Now()
	if !s.config.PhoneUserInfo || !in.UserInfo || !slices.Contains(in.Scopes, "phone") || in.AuthorityExpiresAt.IsZero() || !now.Before(in.AuthorityExpiresAt) || in.Identifiers == nil {
		return UserInfo{}, oauth.ErrAccessDenied
	}
	state := in.Identifiers
	if state.User.Validate(in.TenantID) != nil || state.User.ID != in.UserID || !state.User.Status.AllowsAuthentication() || state.AuthorityVersion == 0 || len(state.Identifiers) > 128 || len(state.Identifiers) != len(state.Verifications) {
		return UserInfo{}, oauth.ErrAccessDenied
	}
	chosen := -1
	for j, identifier := range state.Identifiers {
		verification := state.Verifications[j]
		if identifier.Validate(in.UserID) != nil || verification.Validate(identifier, now) != nil || j > 0 && identifier.ID <= state.Identifiers[j-1].ID {
			return UserInfo{}, oauth.ErrAccessDenied
		}
		for _, previous := range state.Identifiers[:j] {
			if previous.Kind == identifier.Kind && (previous.CanonicalValue == identifier.CanonicalValue || previous.Primary && identifier.Primary) {
				return UserInfo{}, oauth.ErrAccessDenied
			}
		}
		if identifier.Kind != identity.IdentifierPhone || verification.State != identity.VerificationVerified {
			continue
		}
		// Core 1.0 errata2 §5.1 requires E.164 for verified numbers. Native
		// phone owns metadata/possession; this boundary only checks canonical wire
		// shape, retaining its bytes rather than reparsing or normalizing them.
		if !canonicalPhone(identifier.CanonicalValue) {
			return UserInfo{}, oauth.ErrAccessDenied
		}
		// This conservative selected profile omits unverified phones (Core §5.4
		// permits omission). Prefer the owner's per-kind primary among verified
		// contacts; absent one, the first stable IdentifierID wins.
		if chosen < 0 || identifier.Primary {
			chosen = j
		}
	}
	if err := ctx.Err(); err != nil {
		return UserInfo{}, err
	}
	if !s.config.Clock.Now().Before(in.AuthorityExpiresAt) {
		return UserInfo{}, oauth.ErrAccessDenied
	}
	if chosen < 0 {
		return UserInfo{}, nil
	}
	verified := true
	return UserInfo{PhoneNumber: state.Identifiers[chosen].CanonicalValue, PhoneNumberVerified: &verified}, nil
}

func canonicalPhone(value string) bool {
	if len(value) < 3 || len(value) > 16 || value[0] != '+' || value[1] < '1' || value[1] > '9' {
		return false
	}
	for _, digit := range []byte(value[2:]) {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
