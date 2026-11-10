package oauthserver

import (
	"context"
	"fmt"
	"slices"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// DynamicRegistrationPolicy selects RFC7591 browser registration under
// the containing ManagedClientPolicy's exact immutable platform owner/tenant.
// Audience is the exact issuer + /oauth2/register; Version identifies this
// immutable admission policy. Changing either requires new native initial-token
// provisioning. AllowedScopes is a nonempty unique subset of the managed OAuth
// scope ceiling. Confidential Basic registration requires ConfidentialClients.
// No OIDC, device or RFC7592 profile is selected.
type DynamicRegistrationPolicy struct {
	Audience      string
	Version       uint64
	AllowedScopes []string
	// ConfidentialClients additionally selects Basic-authenticated browser
	// registration. Zero preserves the original no-secret public-only profile.
	ConfidentialClients bool `json:",omitempty"`
}

func (p DynamicRegistrationPolicy) validated(managed ManagedClientPolicy, issuer Issuer) (DynamicRegistrationPolicy, error) {
	if !managed.PublicClients || p.Version == 0 || p.Audience != issuer.String()+"/oauth2/register" {
		return DynamicRegistrationPolicy{}, ErrInvalidRequest
	}
	scopes, err := validatedScopes(p.AllowedScopes)
	if err != nil || !scopeSubset(scopes, managed.Scopes.values) || hasExtensionScope(scopes) {
		return DynamicRegistrationPolicy{}, ErrInvalidScope
	}
	p.AllowedScopes = scopes
	return p, nil
}

// DynamicRegisterRequest is the typed native RFC7591 metadata and initial
// bearer custody. It needs no browser session, CSRF, client-selected command ID
// or Idempotency-Key. The native owner derives protocol-command identity from
// authenticated custody and immutable input. Public=false means confidential,
// a valid separately selected class, not an absent Boolean. This finite profile
// selects authorization_code + refresh_token, response code, and either public
// method none or explicitly enabled confidential client_secret_basic.
// InitialAccessToken must be canonical opaque 32-byte custody. Network is trusted
// bounded transport attribution. Secret-bearing input cannot be serialized.
type DynamicRegisterRequest struct {
	InitialAccessToken                      string
	Public                                  bool
	RedirectURIs, GrantTypes, ResponseTypes []string
	AuthenticationMethod                    string
	Scopes                                  []string
	ClientName                              string
	Network                                 string
}

func (DynamicRegisterRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("DynamicRegisterRequest(redacted)"))
}
func (DynamicRegisterRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (DynamicRegisterRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// DynamicRegisterResult exposes a managed client and original command completion.
// Only a newly committed confidential registration delivers ClientSecret once;
// public, replayed, unknown and recovered outcomes never deliver a secret.
// No RFC7592 management URI/token is selected.
// ClientName is the accepted bounded display metadata. Recovery is historical
// metadata only and cannot establish that the client is still active.
type DynamicRegisterResult struct {
	Client       Client
	ClientName   string
	ClientSecret Token
	Completion   Completion
}

func (DynamicRegisterResult) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("DynamicRegisterResult(redacted)"))
}
func (DynamicRegisterResult) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (DynamicRegisterResult) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// DynamicRegistrar is additive to Store. Implementations must authenticate the
// real native initial-token owner/audience/version, use database time, and
// atomically consume it with managed client creation in the existing protected
// transaction. A policy decision, session, request key or absence read is not
// initial-token authority. Unknown outcomes return original recovery identity.
type DynamicRegistrar interface {
	DynamicRegister(context.Context, DynamicRegisterRequest) (DynamicRegisterResult, error)
}

// ValidateDynamicRegisterRequest bounds and copies exact registration metadata.
// It grants no initial-token validity, current authority or consumption rights.
func ValidateDynamicRegisterRequest(r DynamicRegisterRequest, p ManagedClientPolicy, issuer Issuer) (DynamicRegisterRequest, error) {
	if p.DynamicRegistration == nil {
		return DynamicRegisterRequest{}, ErrAccessDenied
	}
	profile, err := p.DynamicRegistration.validated(p, issuer)
	if err != nil {
		return DynamicRegisterRequest{}, err
	}
	if _, err := ParseToken(r.InitialAccessToken); err != nil {
		return DynamicRegisterRequest{}, ErrAccessDenied
	}
	if !r.Public && !profile.ConfidentialClients {
		return DynamicRegisterRequest{}, ErrAccessDenied
	}
	wantMethod := "client_secret_basic"
	if r.Public {
		wantMethod = "none"
	}
	if r.AuthenticationMethod != wantMethod || len(r.GrantTypes) != 2 || !slices.Contains(r.GrantTypes, "authorization_code") || !slices.Contains(r.GrantTypes, "refresh_token") || len(r.ResponseTypes) != 1 || r.ResponseTypes[0] != "code" || !visible(r.Network, 128) || !visible(r.ClientName, 256) || !utf8.ValidString(r.ClientName) {
		return DynamicRegisterRequest{}, ErrInvalidRequest
	}
	redirects, err := NewRedirectPolicy(r.RedirectURIs)
	if err != nil {
		return DynamicRegisterRequest{}, ErrInvalidRequest
	}
	for _, target := range redirects.targets {
		if !slices.Contains(p.Redirects, target) {
			return DynamicRegisterRequest{}, ErrAccessDenied
		}
	}
	scopes, err := validatedScopes(r.Scopes)
	if err != nil || !scopeSubset(scopes, profile.AllowedScopes) {
		return DynamicRegisterRequest{}, ErrInvalidScope
	}
	r.RedirectURIs, r.Scopes = slices.Clone(redirects.targets), scopes
	r.GrantTypes, r.ResponseTypes = []string{"authorization_code", "refresh_token"}, []string{"code"}
	return r, nil
}

// DynamicRegister performs the selected native RFC7591 profile. Full HTTP
// composition remains a separate consumer; no management endpoints are implied.
func (s *Service) DynamicRegister(ctx context.Context, r DynamicRegisterRequest) (out DynamicRegisterResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = DynamicRegisterResult{Completion: out.Completion}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if s.config.ManagedClients == nil {
		return out, ErrAccessDenied
	}
	r, err = ValidateDynamicRegisterRequest(r, *s.config.ManagedClients, s.config.Issuer)
	if err != nil {
		return out, err
	}
	registrar, ok := s.deps.Store.(DynamicRegistrar)
	if !ok || nilDependency(registrar) {
		return out, ErrAccessDenied
	}
	out, err = registrar.DynamicRegister(ctx, r)
	if r.Public || out.Completion.Replayed || out.Completion.Outcome != identity.CommitOutcomeCommitted {
		out.ClientSecret = Token{}
	}
	if ctx.Err() != nil {
		return DynamicRegisterResult{Completion: out.Completion}, ctx.Err()
	}
	if err != nil {
		return DynamicRegisterResult{Completion: out.Completion}, operationError(ctx, err)
	}
	return out, nil
}
