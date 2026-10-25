package oauthserver

import (
	"slices"
	"strings"
)

// Issuer is one exact configured HTTPS origin. Zero is invalid. Its value is
// public metadata, never derived from an inbound Host or forwarded header.
type Issuer struct{ value string }

// NewIssuer validates the selected origin-only issuer profile without IO.
// Trailing slash and path-bearing issuers are unselected rather than normalized.
func NewIssuer(value string) (Issuer, error) {
	if !validOrigin(value) {
		return Issuer{}, ErrInvalidRequest
	}
	return Issuer{value: strings.Clone(value)}, nil
}

// String returns configured public issuer metadata; zero returns empty.
func (i Issuer) String() string { return i.value }

// ScopeCatalog is the immutable OAuth-resource scope set. Core never assigns
// OIDC identity/claim/offline semantics. Zero denies all scopes. Copies can be
// shared concurrently; Scopes returns independently owned projection data.
type ScopeCatalog struct{ values []string }

// NewScopeCatalog validates/copies 1..16 unique OAuth scopes. OIDC reserved
// scopes belong to the optional OIDC extension and are rejected by this core
// constructor even if supplied by configuration. No IO or defaults occur.
func NewScopeCatalog(values []string) (ScopeCatalog, error) {
	return newScopeCatalog(values, false)
}

func newScopeCatalog(values []string, oidc bool) (ScopeCatalog, error) {
	if len(values) < 1 || len(values) > 16 {
		return ScopeCatalog{}, ErrInvalidRequest
	}
	owned := slices.Clone(values)
	slices.Sort(owned)
	for i, value := range owned {
		parsed, err := parseScopes(value)
		if err != nil || len(parsed) != 1 || !oidc && isOIDCScope(value) || i > 0 && value == owned[i-1] {
			return ScopeCatalog{}, ErrInvalidRequest
		}
	}
	return ScopeCatalog{values: owned}, nil
}

// Scopes returns the sorted public catalog. Mutations cannot change policy.
func (c ScopeCatalog) Scopes() []string { return slices.Clone(c.values) }

// Contains matches exact case-sensitive scope text. Zero catalogs deny all.
func (c ScopeCatalog) Contains(scope string) bool {
	_, found := slices.BinarySearch(c.values, scope)
	return found
}

func isOIDCScope(value string) bool {
	switch value {
	case "openid", "profile", "email", "address", "phone", "offline_access":
		return true
	default:
		return false
	}
}

// Owner is an explicit immutable client-management owner, distinct from the
// authenticated end user and calling client. The selected profile admits only
// a deployment-configured platform owner; absent/user/org approximations deny.
type Owner struct{ platform string }

// NewPlatformOwner validates a configured platform owner, not request-selected
// tenant authority. It grants no management permission or end-user identity.
func NewPlatformOwner(id string) (Owner, error) {
	if !identifier(id) {
		return Owner{}, ErrInvalidRequest
	}
	return Owner{platform: strings.Clone(id)}, nil
}

// PlatformID returns public owner identity or empty for an invalid zero value.
func (o Owner) PlatformID() string { return o.platform }

// Client is a non-secret projection. Public=false is the valid confidential
// class and requires client_secret_basic; Public=true selects none and never a
// secret. ValidateClient establishes syntax only, not durable existence, current
// owner authorization or selected issuance capability. Never mutate a supplied
// projection concurrently with validation or service construction.
type Client struct {
	ID, AuthenticationMethod, Resource string
	Owner                              Owner
	Version                            uint64
	Public                             bool
	// DeviceAuthorization explicitly permits RFC8628 for this registered human
	// client. Zero preserves browser-only permission. The optional device child
	// and native composition must still be selected; this is not authentication.
	DeviceAuthorization bool `json:",omitempty"`
	// HumanCodeExchange selects the separate configured human-access delegation
	// operation for this confidential web client. It does not replace Basic
	// authentication or alter existing registration/grant identity. False retains
	// the existing profile; the global/native selection is also required.
	HumanCodeExchange bool `json:",omitempty"`
	Redirects, Scopes []string
	// PostLogoutRedirects independently registers exact RP logout targets.
	// Empty selects local-only logout, never an authorization-redirect fallback.
	PostLogoutRedirects []string `json:",omitempty"`
	// Workload explicitly selects access-only client credentials instead of
	// browser code/consent/refresh. Nil retains the existing web profile.
	Workload *Workload `json:",omitempty"`
	// SubjectRegistration selects immutable OIDC subject policy independently
	// of client authentication. Nil retains legacy public-subject behavior.
	SubjectRegistration *OIDCSubjectRegistration `json:",omitempty"`
}

// ValidateClient checks/copies complete immutable registration policy. It
// accepts exactly the reference authentication matrix's two metadata classes;
// the supported runtime profile must additionally supply the selected class's
// actual authentication implementation before advertising or issuing for it.
func ValidateClient(input Client) (Client, error) {
	if input.HumanCodeExchange && (input.Public || input.Workload != nil) {
		return Client{}, ErrInvalidRequest
	}
	if !identifier(input.ID) || !identifier(input.Owner.platform) || input.Version == 0 || !validOrigin(input.Resource) || input.Public && input.AuthenticationMethod != "none" || !input.Public && input.AuthenticationMethod != "client_secret_basic" {
		return Client{}, ErrInvalidRequest
	}
	var redirects RedirectPolicy
	var err error
	if input.Workload != nil {
		if input.Public || !input.Workload.valid() || len(input.Redirects) != 0 || input.DeviceAuthorization {
			return Client{}, ErrInvalidRequest
		}
	} else {
		redirects, err = NewRedirectPolicy(input.Redirects)
		if err != nil {
			return Client{}, err
		}
	}
	if !validSubjectRegistration(input) {
		return Client{}, ErrInvalidRequest
	}
	if len(input.PostLogoutRedirects) != 0 {
		if input.Workload != nil {
			return Client{}, ErrInvalidRequest
		}
		logout, err := NewRedirectPolicy(input.PostLogoutRedirects)
		if err != nil {
			return Client{}, err
		}
		input.PostLogoutRedirects = slices.Clone(logout.targets)
	}
	scopes, err := newScopeCatalog(input.Scopes, true)
	if err != nil {
		return Client{}, err
	}
	input.ID, input.Resource, input.AuthenticationMethod = strings.Clone(input.ID), strings.Clone(input.Resource), strings.Clone(input.AuthenticationMethod)
	input.Redirects, input.Scopes = slices.Clone(redirects.targets), scopes.Scopes()
	return input.snapshot(), nil
}

// Own every mutable projection, including the Workload pointee: unexported
// fields do not prevent a consumer from replacing an entire exported value.
// Use a fresh snapshot at constructor and adapter boundaries so neither caller
// nor adapter mutation can alter retained policy or in-flight result checks.
func (c Client) snapshot() Client {
	c.Redirects, c.Scopes = slices.Clone(c.Redirects), slices.Clone(c.Scopes)
	c.PostLogoutRedirects = slices.Clone(c.PostLogoutRedirects)
	if c.Workload != nil {
		owned := *c.Workload
		c.Workload = &owned
	}
	if c.SubjectRegistration != nil {
		owned := *c.SubjectRegistration
		c.SubjectRegistration = &owned
	}
	return c
}

// PostLogoutRedirectAllowed tests only exact explicitly registered logout
// metadata. It authenticates no client or session; callers must separately
// obtain current registration and prove the hint/session association. An absent
// target is local-only, not a registered redirect, under RP-Initiated Logout §3.
func PostLogoutRedirectAllowed(c Client, target string) bool {
	return target != "" && c.Workload == nil && slices.Contains(c.PostLogoutRedirects, target)
}

func identifier(value string) bool {
	if !visible(value, 128) {
		return false
	}
	for i := range len(value) {
		b := value[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.') {
			return false
		}
	}
	return true
}
