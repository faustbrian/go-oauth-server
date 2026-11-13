package oauthserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

// OrganizationResourceVerificationConfig selects one trusted organization in
// addition to the exact tenant/client/resource policy. It is startup input,
// never a request override. Clock and reader lifetimes/concurrency follow
// ResourceVerificationConfig. It selects opaque modern-key delegation only;
// existing USER verification configuration and principals remain unchanged.
type OrganizationResourceVerificationConfig struct {
	Verification   ResourceVerificationConfig
	OrganizationID apikey.OrganizationID
}

// Validated checks finite configuration shape without reading or granting any
// organization, key or client authority. Canonical ownership is native state.
func (c OrganizationResourceVerificationConfig) Validated() (OrganizationResourceVerificationConfig, error) {
	owned, err := c.Verification.Validated()
	if err != nil || !identifier(string(c.OrganizationID)) {
		return OrganizationResourceVerificationConfig{}, ErrInvalidRequest
	}
	c.Verification = owned
	return c, nil
}

func (OrganizationResourceVerificationConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("OrganizationResourceVerificationConfig(redacted)"))
}
func (OrganizationResourceVerificationConfig) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidRequest
}

// OrganizationResourceLineage is read-only provenance, not a replay grant or
// independently authenticated assertion. RootID belongs to the API-key domain;
// TokenID and access ParentID belong to OAuth artifacts. Equal bytes across
// those domains do not turn an API key into an OAuth parent. The native reader
// must validate the entire bounded chain, current roots and parent withdrawal.
type OrganizationResourceLineage struct {
	RootID          apikey.KeyID
	RootVersion     uint64
	ParentID        string
	ParentTokenType string
	ParentVersion   uint64
	TokenID         string
	Depth           uint8
}

func (l OrganizationResourceLineage) valid(actor apikey.KeyID) bool {
	if _, err := apikey.ParseKeyID(string(actor)); err != nil {
		return false
	}
	if l.RootID != actor || l.RootVersion == 0 || !identifier(l.TokenID) || !identifier(l.ParentID) || l.Depth == 0 || l.Depth > 4 {
		return false
	}
	if l.Depth == 1 {
		return l.ParentTokenType == APIKeyTokenType && l.ParentID == string(l.RootID) && l.ParentVersion == l.RootVersion
	}
	return l.ParentTokenType == AccessTokenType && l.ParentID != l.TokenID && l.ParentVersion == 1
}

// OrganizationResourceAccessProjection is trusted native-reader output for one
// actual opaque access token. It is neither a credential nor an authentication
// factory. Owner must be tagged ORG, with APIKeyActor separate from the owning
// organization and calling Basic client. There is deliberately no USER arm.
// ReadStartedAt precedes all contributing native reads; ValidUntil preserves
// their earliest original deadline and cannot exceed read-start+20s or token/key
// expiry. A reader must repeat actual current root/parent/owner/client checks.
type OrganizationResourceAccessProjection struct {
	Issuer                                                         Issuer
	Environment                                                    string
	Owner                                                          apikey.Owner
	APIKeyActor                                                    apikey.KeyID
	TenantID                                                       identity.TenantID
	ClientID                                                       string
	ClientVersion                                                  uint64
	Resource                                                       string
	Scopes                                                         []string
	Kind                                                           TokenKind
	Lineage                                                        OrganizationResourceLineage
	ReadStartedAt, ValidUntil, TokenExpiresAt, CredentialExpiresAt time.Time
}

func (OrganizationResourceAccessProjection) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("OrganizationResourceAccessProjection(redacted)"))
}
func (OrganizationResourceAccessProjection) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidRequest
}
func (OrganizationResourceAccessProjection) MarshalText() ([]byte, error) {
	return nil, ErrInvalidRequest
}

// OrganizationResourceAccessReader is an already policy-bound trusted native
// owner. Only borrowed access custody is request input; it cannot select another
// tenant, organization, client or resource. No introspection Active value,
// current-policy callback, cached positive or fabricated USER is a substitute.
type OrganizationResourceAccessReader interface {
	ReadOrganizationResourceAccess(context.Context, string) (OrganizationResourceAccessProjection, error)
}

// OrganizationResourceVerifier freezes exact policy independently of protocol
// Service and RFC7662 metadata. It owns no pool, worker, cache or refresh loop.
// Its immutable policy/reader are borrowed for concurrent bounded calls.
type OrganizationResourceVerifier struct {
	config OrganizationResourceVerificationConfig
	reader OrganizationResourceAccessReader
}

func (*OrganizationResourceVerifier) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("OrganizationResourceVerifier(redacted)"))
}

// NewOrganizationResourceVerifier freezes a trusted reader and validated policy.
// Applications normally use the native constructor, not missing domain stores
// supplied as callbacks. Invalid composition returns ErrInvalidRequest.
func NewOrganizationResourceVerifier(c OrganizationResourceVerificationConfig, r OrganizationResourceAccessReader) (*OrganizationResourceVerifier, error) {
	owned, err := c.Validated()
	if err != nil || nilDependency(r) {
		return nil, ErrInvalidRequest
	}
	return &OrganizationResourceVerifier{config: owned, reader: r}, nil
}

// OrganizationResourcePrincipal is an opaque result of one completed resource
// verification. Zero is invalid. Metadata accessors grant no authority or replay
// custody. Immediately RequireScope before the selected resource operation and
// independently apply application-specific business/row-owner policy. Copies
// retain the original strict scope, trusted clock and absolute deadline.
type OrganizationResourcePrincipal struct {
	owner           apikey.Owner
	actor           apikey.KeyID
	tenant          identity.TenantID
	client          string
	clientVersion   uint64
	resource, scope string
	lineage         OrganizationResourceLineage
	start, until    time.Time
	clock           Clock
}

func (OrganizationResourcePrincipal) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("OrganizationResourcePrincipal(redacted)"))
}
func (OrganizationResourcePrincipal) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (OrganizationResourcePrincipal) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// Owner returns immutable tagged organization metadata, never a human identity.
func (p OrganizationResourcePrincipal) Owner() apikey.Owner { return p.owner }

// APIKeyActor returns the authenticated integration key, not its creator/client.
func (p OrganizationResourcePrincipal) APIKeyActor() apikey.KeyID { return p.actor }

// TenantID returns the fixed verified tenant, not caller-selected request input.
func (p OrganizationResourcePrincipal) TenantID() identity.TenantID { return p.tenant }

// ClientID returns the separately authenticated original Basic registration.
func (p OrganizationResourcePrincipal) ClientID() string { return p.client }

// ClientVersion returns the exact original immutable calling registration epoch.
func (p OrganizationResourcePrincipal) ClientVersion() uint64 { return p.clientVersion }

// Resource returns the exact configured resource origin.
func (p OrganizationResourcePrincipal) Resource() string { return p.resource }

// Lineage returns copied nonsecret root/parent provenance, not replay authority.
func (p OrganizationResourcePrincipal) Lineage() OrganizationResourceLineage { return p.lineage }

// ReadStartedAt returns the original start, without promoting a new window.
func (p OrganizationResourcePrincipal) ReadStartedAt() time.Time { return p.start }

// ValidUntil returns the earliest original expiry, without refreshing authority.
func (p OrganizationResourcePrincipal) ValidUntil() time.Time { return p.until }

// RequireScope checks only the exact verified scope and original clock window.
// It neither refreshes evidence nor decides application-specific business policy.
func (p OrganizationResourcePrincipal) RequireScope(scope string) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	if nilDependency(p.clock) || p.owner.Spec().Kind != apikey.OwnerOrganization || p.actor == "" || scope != p.scope {
		return ErrInvalidResourceToken
	}
	now := p.clock.Now()
	if now.Before(p.start) || !now.Before(p.until) {
		return ErrInvalidResourceToken
	}
	return nil
}

// Verify returns one scope-bound organization principal or a zero result/error.
// Every call performs a genuine new reader invocation. Failure/cancellation can
// never fall back to earlier authority or disclose a partial principal.
func (v *OrganizationResourceVerifier) Verify(ctx context.Context, r ResourceVerifyRequest) (out OrganizationResourcePrincipal, err error) {
	defer func() {
		if recover() != nil {
			out, err = OrganizationResourcePrincipal{}, ErrUnavailable
		}
	}()
	if v == nil || ctx == nil {
		return out, ErrInvalidRequest
	}
	c := v.config.Verification
	ctx, stop := context.WithTimeout(ctx, c.MaximumDuration)
	defer stop()
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if !visible(r.AccessToken, 2048) {
		return out, ErrInvalidResourceToken
	}
	if len(r.Scope) > 128 || !c.Scopes.Contains(r.Scope) {
		return out, ErrInvalidScope
	}
	start := c.Clock.Now()
	p, err := v.reader.ReadOrganizationResourceAccess(ctx, r.AccessToken)
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if err != nil {
		if errors.Is(err, ErrInvalidResourceToken) {
			return out, ErrInvalidResourceToken
		}
		return out, ErrUnavailable
	}
	now := c.Clock.Now()
	owner := p.Owner.Spec()
	scopes, err := validatedScopes(p.Scopes)
	ownerMatches := p.Owner.Validate() == nil && owner.Kind == apikey.OwnerOrganization && owner.OrganizationID == v.config.OrganizationID && owner.TenantID == c.TenantID
	contextMatches := p.Issuer == c.Issuer && p.Environment == c.Environment && p.TenantID == c.TenantID && p.ClientID == c.ClientID && p.ClientVersion == c.ClientVersion && p.Resource == c.Resource
	windowValid := !p.ReadStartedAt.IsZero() && !p.ReadStartedAt.After(now) && !now.Before(start) && p.ValidUntil.After(p.ReadStartedAt) && !p.ValidUntil.After(p.ReadStartedAt.Add(20*time.Second))
	if err != nil || !slices.Equal(scopes, p.Scopes) || p.Kind != TokenAccess || !ownerMatches || !contextMatches || !p.Lineage.valid(p.APIKeyActor) || !windowValid || p.TokenExpiresAt.IsZero() || p.TokenExpiresAt.Year() > 9999 || p.CredentialExpiresAt.IsZero() || p.CredentialExpiresAt.Year() > 9999 {
		return out, ErrUnavailable
	}
	until := p.ValidUntil
	for _, deadline := range []time.Time{start.Add(20 * time.Second), p.TokenExpiresAt, p.CredentialExpiresAt} {
		if deadline.Before(until) {
			until = deadline
		}
	}
	if !now.Before(until) {
		return out, ErrInvalidResourceToken
	}
	if !slices.Contains(scopes, r.Scope) {
		return out, ErrInvalidScope
	}
	return OrganizationResourcePrincipal{owner: p.Owner, actor: p.APIKeyActor, tenant: p.TenantID, client: p.ClientID, clientVersion: p.ClientVersion, resource: p.Resource, scope: r.Scope, lineage: p.Lineage, start: p.ReadStartedAt, until: until, clock: c.Clock}, nil
}
