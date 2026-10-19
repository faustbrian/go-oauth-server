package oauthserver

import (
	"context"
	"net/url"
	"path"
	"slices"
	"strings"
)

// DiscoveryConfig selects the unsigned RFC8414 authorization-server projection.
// Zero disables discovery. Enabled configuration requires token/revocation
// endpoints, authorization only when web clients exist, and introspection iff
// OwningClientIntrospection is selected with an eligible confidential client.
// Every URL is trusted startup configuration, not inferred from a request Host.
// The selected deployment policy restricts endpoints to distinct canonical
// HTTPS paths on the exact issuer origin; RFC8414 itself permits other origins.
// No listener, HTTP route or endpoint implementation is created by this value.
type DiscoveryConfig struct {
	Enabled                                                                         bool
	AuthorizationEndpoint, TokenEndpoint, RevocationEndpoint, IntrospectionEndpoint string
}

// DiscoveryOauthRequest is the empty public, read-only discovery operation.
// It accepts no effective issuer, host, client, tenant or scope override.
type DiscoveryOauthRequest struct{}

// DiscoveryOauthMetadata is a caller-owned nonsecret RFC8414 JSON projection,
// extended only by RFC9207 issuer-response support and RFC9728 protected_resources.
// Each call returns independently owned slices; mutation conveys no authority
// and cannot change a service or another caller's metadata. Zero is not valid
// metadata. It contains no OIDC, registration, device, signing or verifier claim.
type DiscoveryOauthMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported  []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported,omitempty"`
	AuthorizationResponseISSParameterSupported bool     `json:"authorization_response_iss_parameter_supported,omitempty"`
	ProtectedResources                         []string `json:"protected_resources"`
}

// DiscoveryOauthResult carries exact configured metadata on success only.
// It owns no resource and does not authenticate a client or protected request.
type DiscoveryOauthResult struct{ Metadata DiscoveryOauthMetadata }

func validateDiscovery(c Config) error {
	d := c.Discovery
	if !d.Enabled {
		if d != (DiscoveryConfig{}) {
			return ErrInvalidRequest
		}
		return nil
	}
	web, _, basic, _ := discoveryProfiles(c.Clients)
	if d.TokenEndpoint == "" || d.RevocationEndpoint == "" || web != (d.AuthorizationEndpoint != "") || c.OwningClientIntrospection != (d.IntrospectionEndpoint != "") || c.OwningClientIntrospection && !basic {
		return ErrInvalidRequest
	}
	seen := map[string]bool{c.Issuer.String() + "/.well-known/oauth-authorization-server": true}
	for _, endpoint := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.RevocationEndpoint, d.IntrospectionEndpoint} {
		if endpoint == "" {
			continue
		}
		if !validDiscoveryEndpoint(c.Issuer, endpoint) || seen[endpoint] {
			return ErrInvalidRequest
		}
		seen[endpoint] = true
	}
	return nil
}

func validDiscoveryEndpoint(issuer Issuer, endpoint string) bool {
	if !visible(endpoint, 2048) || strings.ContainsAny(endpoint, "\\#?%*") {
		return false
	}
	u, err := url.Parse(endpoint)
	// This origin/path restriction is the explicit selected deployment policy,
	// not a claim that RFC8414 requires same-origin endpoint URLs. Canonical
	// paths prevent metadata and the selected transport from disagreeing after
	// percent/dot/slash normalization (RFC8414 sections3.3/6.2).
	return err == nil && u.Scheme == "https" && u.User == nil && u.Opaque == "" && u.Scheme+"://"+u.Host == issuer.String() && u.Path != "" && u.Path != "/" && strings.HasPrefix(u.Path, "/") && path.Clean(u.Path) == u.Path && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.String() == endpoint
}

func discoveryProfiles(clients []Client) (web, workload, basic, public bool) {
	for _, client := range clients {
		web = web || client.Workload == nil
		workload = workload || client.Workload != nil
		basic = basic || !client.Public
		public = public || client.Public
	}
	return
}

// DiscoveryOauth projects the immutable current selected runtime without IO,
// callbacks, credential work or storage access. Disabled discovery returns
// ErrAccessDenied and zero metadata; invalid/nil input returns ErrInvalidRequest,
// and cancellation preserves the context error. Concurrent calls are safe.
// The application may serve Metadata as application/json at the RFC8414
// well-known URL; transport registration and TLS remain application-owned.
func (s *Service) DiscoveryOauth(ctx context.Context, _ DiscoveryOauthRequest) (DiscoveryOauthResult, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return DiscoveryOauthResult{}, err
	}
	defer stop()
	if !s.config.Discovery.Enabled {
		return DiscoveryOauthResult{}, ErrAccessDenied
	}
	c := s.config
	d := c.Discovery
	web, workload, basic, public := discoveryProfiles(c.Clients)
	m := DiscoveryOauthMetadata{Issuer: c.Issuer.String(), AuthorizationEndpoint: d.AuthorizationEndpoint, TokenEndpoint: d.TokenEndpoint, RevocationEndpoint: d.RevocationEndpoint, IntrospectionEndpoint: d.IntrospectionEndpoint, ScopesSupported: c.Scopes.Scopes(), ResponseTypesSupported: []string{}, ProtectedResources: []string{c.Resource}}
	if !nilDependency(s.deps.OIDC) {
		m.ScopesSupported = append(m.ScopesSupported, s.deps.OIDC.Scopes().Scopes()...)
		slices.Sort(m.ScopesSupported)
	}
	if web {
		m.ResponseTypesSupported = []string{"code"}
		m.ResponseModesSupported = []string{"query"}
		m.CodeChallengeMethodsSupported = []string{"S256"}
		m.GrantTypesSupported = []string{"authorization_code", "refresh_token"}
		m.AuthorizationResponseISSParameterSupported = true
	}
	if workload {
		m.GrantTypesSupported = append(m.GrantTypesSupported, "client_credentials")
	}
	slices.Sort(m.GrantTypesSupported)
	if basic {
		m.TokenEndpointAuthMethodsSupported = append(m.TokenEndpointAuthMethodsSupported, "client_secret_basic")
	}
	if public {
		m.TokenEndpointAuthMethodsSupported = append(m.TokenEndpointAuthMethodsSupported, "none")
	}
	m.RevocationEndpointAuthMethodsSupported = slices.Clone(m.TokenEndpointAuthMethodsSupported)
	if c.OwningClientIntrospection {
		m.IntrospectionEndpointAuthMethodsSupported = []string{"client_secret_basic"}
	}
	if err := ctx.Err(); err != nil {
		return DiscoveryOauthResult{}, err
	}
	return DiscoveryOauthResult{Metadata: m}, nil
}
