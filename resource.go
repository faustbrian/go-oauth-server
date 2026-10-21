package oauthserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// ErrInvalidResourceToken denies unknown, wrong-kind, expired, withdrawn or
// foreign access custody without disclosing which property failed.
var ErrInvalidResourceToken = errors.New("oauthserver: invalid resource token")

// ResourceVerificationConfig is trusted startup policy, never request input.
// It selects exactly one native human client/tenant/resource and OAuth scope
// catalog. Clock is trusted, fast and concurrency-safe; MaximumDuration is
// 1ms..5s. A verifier borrows its reader/clock for its concurrent lifetime.
type ResourceVerificationConfig struct {
	Issuer          Issuer
	Environment     string
	TenantID        identity.TenantID
	ClientID        string
	ClientVersion   uint64
	Resource        string
	Scopes          ScopeCatalog
	Clock           Clock
	MaximumDuration time.Duration
}

// Validated checks the finite trusted policy without IO or authority claims.
func (c ResourceVerificationConfig) Validated() (ResourceVerificationConfig, error) {
	if !validOrigin(c.Issuer.String()) || !identifier(c.Environment) || !identifier(string(c.TenantID)) || !identifier(c.ClientID) || c.ClientVersion == 0 || c.ClientVersion == ^uint64(0) || !validOrigin(c.Resource) || len(c.Scopes.values) == 0 || hasExtensionScope(c.Scopes.values) || nilDependency(c.Clock) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second {
		return ResourceVerificationConfig{}, ErrInvalidRequest
	}
	return c, nil
}

// ResourceVerifyRequest borrows an opaque access token until Verify returns.
// Scope may demand one supported scope; it cannot choose any trust context.
// RFC6749 section1.5 reserves refresh tokens for authorization servers only.
type ResourceVerifyRequest struct{ AccessToken, Scope string }

func (ResourceVerifyRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ResourceVerifyRequest(redacted)"))
}
func (ResourceVerifyRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ResourceVerifyRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ResourceAccessProjection is trusted native-reader output, not a credential
// or public authentication assertion. ReadStartedAt is the earliest contributing
// read start; ValidUntil cannot exceed it+20s or token/credential expiry. Native
// readers recheck current token/consent/subject/credential/policy before return.
type ResourceAccessProjection struct {
	Issuer                                                         Issuer
	Environment                                                    string
	TenantID                                                       identity.TenantID
	UserID                                                         identity.UserID
	ClientID                                                       string
	ClientVersion                                                  uint64
	Resource                                                       string
	Scopes                                                         []string
	Kind                                                           TokenKind
	ReadStartedAt, ValidUntil, TokenExpiresAt, CredentialExpiresAt time.Time
}

func (ResourceAccessProjection) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ResourceAccessProjection(redacted)"))
}
func (ResourceAccessProjection) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ResourceAccessProjection) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ResourceAccessReader is a trusted, already policy-bound native access reader.
// It accepts no caller-selected tenant/client/issuer/resource. Implementations
// authenticate actual access kind and repeat primary current-authority fences;
// no positive cache, refresh fallback, writes or renewed evidence is permitted.
type ResourceAccessReader interface {
	ReadResourceAccess(context.Context, string) (ResourceAccessProjection, error)
}

// ResourceVerifier freezes policy and composition independently of protocol
// Service and RFC7662 metadata disclosure. It owns no pool or background work.
type ResourceVerifier struct {
	config ResourceVerificationConfig
	reader ResourceAccessReader
}

func (*ResourceVerifier) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ResourceVerifier(redacted)"))
}

// NewResourceVerifier freezes trusted reader policy. Applications normally use
// the native constructor rather than implementing missing authority themselves.
func NewResourceVerifier(c ResourceVerificationConfig, r ResourceAccessReader) (*ResourceVerifier, error) {
	owned, err := c.Validated()
	if err != nil || nilDependency(r) {
		return nil, ErrInvalidRequest
	}
	return &ResourceVerifier{config: owned, reader: r}, nil
}

// ResourcePrincipal is an opaque, scope-bound result of one completed access
// verification. Zero is invalid. Metadata getters confer no authority; consumers
// must call RequireScope immediately before their selected resource read. Copies
// retain the original clock/deadline and cannot renew evidence or act as tokens.
type ResourcePrincipal struct {
	subject         identity.UserID
	tenant          identity.TenantID
	resource, scope string
	start, until    time.Time
	clock           Clock
}

func (ResourcePrincipal) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ResourcePrincipal(redacted)"))
}
func (ResourcePrincipal) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ResourcePrincipal) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// Subject returns nonsecret identity metadata, not an authorization decision.
func (p ResourcePrincipal) Subject() identity.UserID { return p.subject }

// TenantID returns the immutable configured tenant, never a request override.
func (p ResourcePrincipal) TenantID() identity.TenantID { return p.tenant }

// Resource returns the exact configured audience/resource origin.
func (p ResourcePrincipal) Resource() string { return p.resource }

// ValidUntil returns original evidence expiry; reading it never renews custody.
func (p ResourcePrincipal) ValidUntil() time.Time { return p.until }

// RequireScope checks the exact verified scope using the original trusted clock.
// It performs no refresh and grants no general resource/business authorization.
func (p ResourcePrincipal) RequireScope(scope string) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	if nilDependency(p.clock) || p.subject == "" || scope != p.scope {
		return ErrInvalidResourceToken
	}
	now := p.clock.Now()
	if now.Before(p.start) || !now.Before(p.until) {
		return ErrInvalidResourceToken
	}
	return nil
}

// Verify returns only a scope-bound access principal or a zero result/error.
// Invalid tokens and insufficient scopes fail closed; dependency failures and
// cancellation return no metadata. Every call performs a new native read.
func (v *ResourceVerifier) Verify(ctx context.Context, r ResourceVerifyRequest) (out ResourcePrincipal, err error) {
	defer func() {
		if recover() != nil {
			out, err = ResourcePrincipal{}, ErrUnavailable
		}
	}()
	if v == nil || ctx == nil {
		return out, ErrInvalidRequest
	}
	ctx, stop := context.WithTimeout(ctx, v.config.MaximumDuration)
	defer stop()
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if !visible(r.AccessToken, 2048) {
		return out, ErrInvalidResourceToken
	}
	if len(r.Scope) > 128 || !v.config.Scopes.Contains(r.Scope) {
		return out, ErrInvalidScope
	}
	start := v.config.Clock.Now()
	p, err := v.reader.ReadResourceAccess(ctx, r.AccessToken)
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if err != nil {
		if errors.Is(err, ErrInvalidResourceToken) {
			return out, ErrInvalidResourceToken
		}
		return out, ErrUnavailable
	}
	now := v.config.Clock.Now()
	scopes, err := validatedScopes(p.Scopes)
	if err != nil || !slices.Equal(scopes, p.Scopes) || p.Kind != TokenAccess || p.Issuer != v.config.Issuer || p.Environment != v.config.Environment || p.TenantID != v.config.TenantID || p.ClientID != v.config.ClientID || p.ClientVersion != v.config.ClientVersion || p.Resource != v.config.Resource || !identifier(string(p.UserID)) || p.ReadStartedAt.IsZero() || p.ReadStartedAt.After(now) || now.Before(start) || !p.ValidUntil.After(p.ReadStartedAt) || p.ValidUntil.After(p.ReadStartedAt.Add(20*time.Second)) || p.TokenExpiresAt.IsZero() || p.TokenExpiresAt.Year() > 9999 {
		return out, ErrUnavailable
	}
	until := p.ValidUntil
	for _, deadline := range []time.Time{start.Add(20 * time.Second), p.TokenExpiresAt, p.CredentialExpiresAt} {
		if !deadline.IsZero() && deadline.Before(until) {
			until = deadline
		}
	}
	if !now.Before(until) {
		return out, ErrInvalidResourceToken
	}
	if !slices.Contains(scopes, r.Scope) {
		return out, ErrInvalidScope
	}
	return ResourcePrincipal{subject: p.UserID, tenant: p.TenantID, resource: p.Resource, scope: r.Scope, start: p.ReadStartedAt, until: until, clock: v.config.Clock}, nil
}
