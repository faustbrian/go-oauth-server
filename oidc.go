package oauthserver

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// OIDCExtension is the one consumer-owned optional extension. Core preserves
// native session/grant authority and does not interpret identity claim meanings.
// Implementations are immutable, borrowed, concurrent-safe and bounded by ctx.
type OIDCExtension interface {
	Scopes() ScopeCatalog
	ValidateAuthorization(context.Context, OIDCAuthorizationInput) (OIDCAuthorizationProjection, error)
	Claims(context.Context, OIDCClaimsInput) (OIDCClaimsProjection, error)
	OIDCDiscovery(context.Context) (OIDCDiscoveryProjection, error)
}

// NewOIDCScopeCatalog reserves 1..6 unique extension-owned names without giving
// them OAuth resource semantics. Config.Scopes remains OAuth-only.
func NewOIDCScopeCatalog(names []string) (ScopeCatalog, error) {
	values, err := validatedScopes(names)
	if err != nil || len(values) > 6 {
		return ScopeCatalog{}, ErrInvalidRequest
	}
	for _, value := range values {
		if !isOIDCScope(value) {
			return ScopeCatalog{}, ErrInvalidRequest
		}
	}
	return ScopeCatalog{values: values}, nil
}

func hasExtensionScope(scopes []string) bool {
	for _, scope := range scopes {
		if isOIDCScope(scope) {
			return true
		}
	}
	return false
}

type OIDCAuthorizationInput struct {
	Issuer      Issuer
	Environment string
	Client      Client
	Request     AuthorizationRequest
	Session     session.GetResult
	// Reauthentication is original native continuation context, never protocol
	// input. The adapter must authenticate/fence this stored original session
	// and request time as well as the newly submitted current session.
	Reauthentication *OIDCReauthenticationInput
}

// OIDCReauthenticationInput conserves the original pending authorization's
// native context. Reconstructed metadata alone cannot authorize a transition.
type OIDCReauthenticationInput struct {
	OriginalSession session.Session
	RequestedAt     time.Time
}

// OIDCAuthenticationRequirement is the extension's typed policy projection;
// it never authenticates a session or permits bypassing native current owners.
type OIDCAuthenticationRequirement uint8

const (
	OIDCAuthenticationCurrent OIDCAuthenticationRequirement = iota + 1
	OIDCAuthenticationFresh
	// OIDCAuthenticationSilent requires current authentication without any user
	// interaction. It is extension policy, never proof of reusable consent; the
	// durable owner must independently admit exact unexpired approval.
	OIDCAuthenticationSilent
)

func (OIDCAuthorizationInput) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oauthserver.OIDCAuthorizationInput(redacted)"))
}

// OIDCSubjectCandidate is a trusted extension's first-binding proposal, not an
// established subject or bearer authority. Native authenticated Authorize Work
// resolves the durable binding atomically; an existing binding always wins.
// KeyVersion identifies writer custody and is not part of subject namespace.
type OIDCSubjectCandidate struct {
	Registration  OIDCSubjectRegistration
	Subject       string
	KeyVersion    uint32
	KeyCommitment [32]byte
}

func (OIDCSubjectCandidate) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oauthserver.OIDCSubjectCandidate(redacted)"))
}

type OIDCAuthorizationProjection struct {
	Accepted         bool
	SubjectCandidate *OIDCSubjectCandidate
	// Authentication is zero only for requests without selected prompt/max_age.
	// AuthenticationUntil is an exclusive positive max_age policy deadline, not
	// renewable session admission; native Work must check it after waits.
	Authentication      OIDCAuthenticationRequirement
	AuthenticationUntil time.Time
}

func validSubjectCandidate(c Client, candidate *OIDCSubjectCandidate) bool {
	if c.SubjectRegistration == nil || c.SubjectRegistration.SubjectType() != "pairwise" {
		return candidate == nil
	}
	return candidate != nil && candidate.Registration == *c.SubjectRegistration && opaque32(candidate.Subject) && candidate.KeyVersion != 0 && candidate.KeyCommitment != ([32]byte{})
}

// OIDCClaimsInput is supplied only after native grant/primary-authority admission
// by the adapter. It is not a caller-selected subject or a renewable proof.
// ExpectedSubject is an immutable previous artifact projection for UserInfo.
type OIDCClaimsInput struct {
	Issuer                               Issuer
	Environment                          string
	TenantID                             identity.TenantID
	UserID                               identity.UserID
	ClientID, Nonce, ExpectedSubject     string
	Scopes                               []string
	IssuedAt, ExpiresAt, AuthenticatedAt time.Time
	UserInfo                             bool
	// SubjectRegistration and BoundSubject are the current registered policy
	// and the original grant's durable native binding, never caller selectors.
	SubjectRegistration *OIDCSubjectRegistration
	BoundSubject        string
	// Identifiers is optional trusted-only primary directory custody for the
	// selected UserInfo extension, never caller input or an authentication proof.
	// AuthorityExpiresAt retains the earliest original contributing deadline;
	// copying or projecting this input cannot renew primary-read freshness.
	Identifiers        *identity.IdentifierState
	AuthorityExpiresAt time.Time
}

func (OIDCClaimsInput) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oauthserver.OIDCClaimsInput(redacted)"))
}
func (OIDCClaimsInput) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (OIDCClaimsInput) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

type OIDCClaimsProjection struct {
	Subject, SigningKeyID string
	IDToken               IDToken
}

func (OIDCClaimsProjection) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oauthserver.OIDCClaimsProjection(redacted)"))
}

type OIDCDiscoveryProjection struct {
	JWKSURI                          string   `json:"jwks_uri"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
	EndSessionEndpoint               string   `json:"end_session_endpoint,omitempty"`
}

// IDToken is explicit reveal-once signed authentication custody, not an access
// token or current authorization proof. Parsing gives no verification authority.
// Copies share delivery permission; implicit diagnostics/serialization redact.
type IDToken struct{ state *tokenState }

func ParseIDToken(wire string) (IDToken, error) {
	if len(wire) < 1 || len(wire) > 16384 || len(strings.Split(wire, ".")) != 3 || !visible(wire, 16384) {
		return IDToken{}, ErrInvalidRequest
	}
	return IDToken{state: &tokenState{wire: strings.Clone(wire)}}, nil
}
func (t IDToken) Reveal() (string, error)    { return (Token{state: t.state}).Reveal() }
func (IDToken) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte("oauthserver.IDToken(redacted)")) }
func (IDToken) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (IDToken) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// WithOIDC returns a new immutable service with exactly one configured child.
// The original service remains OAuth-only and rejects extension scopes. This
// two-step construction lets the child consume the existing public Service
// struct without changing it into the stale goal document's breaking interface.
func (s *Service) WithOIDC(extension OIDCExtension) (*Service, error) {
	if s == nil || nilDependency(extension) || !nilDependency(s.deps.OIDC) || !slices.Equal(extension.Scopes().Scopes(), s.config.OIDCScopes.Scopes()) {
		return nil, ErrInvalidRequest
	}
	d := s.deps
	d.OIDC = extension
	return NewService(s.config, d)
}

// UserInfoRequest carries an owning-client selector and possessed access token.
// Neither value overrides the token's native subject, audience or scope.
type UserInfoRequest struct{ ClientID, AccessToken string }

func (UserInfoRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oauthserver.UserInfoRequest(redacted)"))
}
func (UserInfoRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (UserInfoRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

type UserInfoCommand struct {
	Request UserInfoRequest
	Client  Client
}
type UserInfoReader interface {
	UserInfo(context.Context, UserInfoCommand) (OIDCClaimsInput, error)
}

// UserInfoSource obtains uncached native authority for the optional child. It
// returns no identity fields beyond the selected grant projection; it never
// accepts an ID token as an access credential or renews evidence on replay.
func (s *Service) UserInfoSource(ctx context.Context, r UserInfoRequest) (out OIDCClaimsInput, err error) {
	defer func() {
		if recover() != nil {
			out, err = OIDCClaimsInput{}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return OIDCClaimsInput{}, err
	}
	defer stop()
	c, err := s.currentClient(ctx, r.ClientID)
	if err != nil || c.Workload != nil || !opaque32(r.AccessToken) {
		return OIDCClaimsInput{}, ErrAccessDenied
	}
	reader, ok := s.deps.Store.(UserInfoReader)
	if !ok || nilDependency(reader) {
		return OIDCClaimsInput{}, ErrAccessDenied
	}
	out, err = reader.UserInfo(ctx, UserInfoCommand{Request: r, Client: c})
	if err != nil || ctx.Err() != nil {
		return OIDCClaimsInput{}, operationError(ctx, err)
	}
	if out.Issuer != s.config.Issuer || out.ClientID != c.ID || out.TenantID == "" || out.UserID == "" || out.ExpectedSubject == "" || !scopeSubset(out.Scopes, c.Scopes) || !out.UserInfo || !s.config.Clock.Now().Before(out.ExpiresAt) || !out.AuthorityExpiresAt.IsZero() && !s.config.Clock.Now().Before(out.AuthorityExpiresAt) {
		return OIDCClaimsInput{}, ErrAccessDenied
	}
	if c.SubjectRegistration != nil && (out.SubjectRegistration == nil || *out.SubjectRegistration != *c.SubjectRegistration || out.Environment != s.config.Environment) || c.SubjectRegistration == nil && out.SubjectRegistration != nil {
		return OIDCClaimsInput{}, ErrAccessDenied
	}
	return out, nil
}
