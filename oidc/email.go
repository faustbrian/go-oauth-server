package oidc

import (
	"context"
	"net/mail"
	"slices"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
)

func (s *Service) emailClaims(ctx context.Context, in oauth.OIDCClaimsInput) (UserInfo, error) {
	if err := ctx.Err(); err != nil {
		return UserInfo{}, err
	}
	now := s.config.Clock.Now()
	if !s.config.EmailUserInfo || !in.UserInfo || !slices.Contains(in.Scopes, "email") || in.AuthorityExpiresAt.IsZero() || !now.Before(in.AuthorityExpiresAt) || in.Identifiers == nil {
		return UserInfo{}, oauth.ErrAccessDenied
	}
	state := in.Identifiers
	if state.User.Validate(in.TenantID) != nil || state.User.ID != in.UserID || !state.User.Status.AllowsAuthentication() || state.AuthorityVersion == 0 || len(state.Identifiers) > 128 || len(state.Identifiers) != len(state.Verifications) {
		return UserInfo{}, oauth.ErrAccessDenied
	}
	chosen, rank := -1, 0
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
		if identifier.Kind != identity.IdentifierEmail || verification.State == identity.VerificationRevoked {
			continue
		}
		// OIDC Core 1.0 errata2 §5.1 requires addr-spec, not a display-name
		// mailbox. Preserve owner canonical bytes rather than reinterpret casing.
		parsed, err := mail.ParseAddress(identifier.CanonicalValue)
		if err != nil || parsed.Name != "" || parsed.Address != identifier.CanonicalValue {
			return UserInfo{}, oauth.ErrAccessDenied
		}
		candidateRank := 1
		if verification.State == identity.VerificationVerified {
			candidateRank = 2
			if identifier.Primary {
				candidateRank = 3
			}
		}
		// Primary is the identity owner's preferred contact marker. When absent,
		// verified before pending and stable ID order give deterministic selection
		// without pretending that an unverified contact proves possession.
		if candidateRank > rank {
			chosen, rank = j, candidateRank
		}
	}
	if err := ctx.Err(); err != nil {
		return UserInfo{}, err
	}
	if !s.config.Clock.Now().Before(in.AuthorityExpiresAt) {
		return UserInfo{}, oauth.ErrAccessDenied
	}
	if chosen < 0 {
		return UserInfo{}, nil // Voluntary claims may be omitted: Core §5.4.
	}
	verified := state.Verifications[chosen].State == identity.VerificationVerified
	return UserInfo{Email: state.Identifiers[chosen].CanonicalValue, EmailVerified: &verified}, nil
}
