package oauthserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

func discoveryEndpoints() oauth.DiscoveryConfig {
	return oauth.DiscoveryConfig{Enabled: true, AuthorizationEndpoint: "https://issuer.example/oauth2/authorize", TokenEndpoint: "https://issuer.example/oauth2/token", RevocationEndpoint: "https://issuer.example/oauth2/revoke"}
}

type managedDiscoveryStore struct{ managedStore }

func (managedDiscoveryStore) Introspect(context.Context, oauth.IntrospectionCommand) (oauth.IntrospectResult, error) {
	return oauth.IntrospectResult{}, oauth.ErrAccessDenied
}

func TestDiscoveryIncludesManagedHumanBasicCapability(t *testing.T) {
	for _, introspection := range []bool{false, true} {
		t.Run(map[bool]string{false: "managed-basic", true: "managed-introspection"}[introspection], func(t *testing.T) {
			sessions, _, now, _ := coreSessionFixture(t)
			config := coreConfig(t, now)
			owner, _ := oauth.NewPlatformOwner("platform")
			config.ManagedClients = &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: config.Scopes}
			config.Discovery = discoveryEndpoints()
			config.OwningClientIntrospection = introspection
			if introspection {
				config.Discovery.IntrospectionEndpoint = "https://issuer.example/oauth2/introspect"
			}
			store := managedDiscoveryStore{}
			service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
			if err != nil {
				t.Fatal("selected managed Basic composition rejected", err)
			}
			out, err := service.DiscoveryOauth(context.Background(), oauth.DiscoveryOauthRequest{})
			if err != nil || !slices.Equal(out.Metadata.TokenEndpointAuthMethodsSupported, []string{"client_secret_basic", "none"}) || !slices.Equal(out.Metadata.RevocationEndpointAuthMethodsSupported, []string{"client_secret_basic", "none"}) || !slices.Equal(out.Metadata.GrantTypesSupported, []string{"authorization_code", "refresh_token"}) {
				t.Fatal("metadata omitted actual managed Basic/web capability", err)
			}
			if introspection && !slices.Equal(out.Metadata.IntrospectionEndpointAuthMethodsSupported, []string{"client_secret_basic"}) {
				t.Fatal("managed owning-client introspection omitted")
			}
			if !introspection && out.Metadata.IntrospectionEndpoint != "" {
				t.Fatal("unselected introspection advertised")
			}
		})
	}
}

func TestDiscoveryManagedHumanWebComposesWithExistingStaticWorkload(t *testing.T) {
	sessions, _, _, _ := coreSessionFixture(t)
	config, _ := workloadCoreConfig(t)
	owner, _ := oauth.NewPlatformOwner("platform")
	config.ManagedClients = &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: config.Scopes}
	config.Discovery = discoveryEndpoints()
	store := managedDiscoveryStore{}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
	if err != nil {
		t.Fatal("selected human web rejected because static registrations are machine-only", err)
	}
	out, err := service.DiscoveryOauth(context.Background(), oauth.DiscoveryOauthRequest{})
	if err != nil || !slices.Equal(out.Metadata.GrantTypesSupported, []string{"authorization_code", "client_credentials", "refresh_token"}) || !slices.Equal(out.Metadata.TokenEndpointAuthMethodsSupported, []string{"client_secret_basic"}) || !slices.Equal(out.Metadata.ResponseTypesSupported, []string{"code"}) || !slices.Equal(out.Metadata.CodeChallengeMethodsSupported, []string{"S256"}) {
		t.Fatal("metadata does not describe coherent selected managed human/static machine composition", err)
	}
}

func TestDiscoveryWorkloadAndIntrospectionAdvertiseOnlyImplementedProfiles(t *testing.T) {
	config, _ := workloadCoreConfig(t)
	config.Discovery = discoveryEndpoints()
	config.Discovery.AuthorizationEndpoint = ""
	config.Discovery.IntrospectionEndpoint = "https://issuer.example/oauth2/introspect"
	config.OwningClientIntrospection = true
	service, err := oauth.NewService(config, oauth.Dependencies{Store: selectedIntrospectionStore{}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.DiscoveryOauth(context.Background(), oauth.DiscoveryOauthRequest{})
	m := result.Metadata
	if err != nil || m.AuthorizationEndpoint != "" || len(m.ResponseTypesSupported) != 0 || len(m.CodeChallengeMethodsSupported) != 0 || m.AuthorizationResponseISSParameterSupported || !slices.Equal(m.GrantTypesSupported, []string{"client_credentials"}) || !slices.Equal(m.TokenEndpointAuthMethodsSupported, []string{"client_secret_basic"}) || !slices.Equal(m.IntrospectionEndpointAuthMethodsSupported, []string{"client_secret_basic"}) || m.IntrospectionEndpoint != config.Discovery.IntrospectionEndpoint {
		t.Fatal("machine-only discovery advertised browser or refresh authority", err)
	}
	wire, _ := json.Marshal(m)
	if !strings.Contains(string(wire), `"response_types_supported":[]`) {
		t.Fatal("required empty response type list omitted or null")
	}
	invalid := config
	invalid.Discovery.AuthorizationEndpoint = discoveryEndpoints().AuthorizationEndpoint
	if _, err := invalid.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("machine-only metadata accepted nonexistent authorization endpoint")
	}
	invalid = config
	invalid.Discovery.IntrospectionEndpoint = ""
	if _, err := invalid.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("enabled introspection lacks endpoint")
	}
	// A mixed registration has the union of real grants/methods, not the full
	// catalog of methods that a general OAuth client might understand.
	sessions, _, now, _ := coreSessionFixture(t)
	public := coreConfig(t, now).Clients[0]
	public.ID = "public-only"
	config.Clients = append(config.Clients, public)
	config.Discovery.AuthorizationEndpoint = discoveryEndpoints().AuthorizationEndpoint
	service, err = oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: selectedIntrospectionStore{}})
	if err != nil {
		t.Fatal(err)
	}
	result, err = service.DiscoveryOauth(context.Background(), oauth.DiscoveryOauthRequest{})
	if err != nil || !slices.Equal(result.Metadata.GrantTypesSupported, []string{"authorization_code", "client_credentials", "refresh_token"}) || !slices.Equal(result.Metadata.TokenEndpointAuthMethodsSupported, []string{"client_secret_basic", "none"}) || !slices.Equal(result.Metadata.IntrospectionEndpointAuthMethodsSupported, []string{"client_secret_basic"}) {
		t.Fatal("mixed discovery widened or hid real capability", err)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 20 {
				projection, err := service.DiscoveryOauth(context.Background(), oauth.DiscoveryOauthRequest{})
				if err != nil || projection.Metadata.ScopesSupported[0] != "identity:read" {
					t.Error("concurrent metadata policy changed")
					return
				}
				projection.Metadata.ScopesSupported[0] = "caller-owned"
			}
		})
	}
	workers.Wait()
}

func FuzzDiscoveryEndpoint(f *testing.F) {
	for _, seed := range []string{"https://issuer.example/oauth2/token", "https://foreign.example/token", "https://issuer.example/a/../token", "https://issuer.example/%2Ftoken", "https://issuer.example/token?client_secret=untrusted"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, endpoint string) {
		config := coreConfig(t, time.Now().UTC())
		config.Discovery = discoveryEndpoints()
		config.Discovery.TokenEndpoint = endpoint
		out, err := config.Validated()
		if err == nil && (len(endpoint) > 2048 || out.Discovery.TokenEndpoint != endpoint || !strings.HasPrefix(endpoint, "https://issuer.example/")) {
			t.Fatal("discovery validation normalized or widened trusted endpoint")
		}
	})
}

func TestDiscoveryPublicClientMetadataIsUsableAndDoesNotLeakPolicy(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	config := coreConfig(t, now)
	config.Discovery = discoveryEndpoints()
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: authorizationStore{}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.DiscoveryOauth(context.Background(), oauth.DiscoveryOauthRequest{})
	if err != nil {
		t.Fatal(err)
	}
	m := result.Metadata
	if m.Issuer != config.Issuer.String() || m.AuthorizationEndpoint != config.Discovery.AuthorizationEndpoint || m.TokenEndpoint != config.Discovery.TokenEndpoint || m.RevocationEndpoint != config.Discovery.RevocationEndpoint || !slices.Equal(m.ScopesSupported, config.Scopes.Scopes()) || !slices.Equal(m.GrantTypesSupported, []string{"authorization_code", "refresh_token"}) || !slices.Equal(m.ResponseTypesSupported, []string{"code"}) || !slices.Equal(m.ResponseModesSupported, []string{"query"}) || !slices.Equal(m.CodeChallengeMethodsSupported, []string{"S256"}) || !slices.Equal(m.TokenEndpointAuthMethodsSupported, []string{"none"}) || !slices.Equal(m.RevocationEndpointAuthMethodsSupported, []string{"none"}) || !slices.Equal(m.ProtectedResources, []string{config.Resource}) || !m.AuthorizationResponseISSParameterSupported {
		t.Fatal("metadata cannot select the actual OAuth public/S256 profile")
	}
	wire, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"public-client", "platform", "test", "client_secret", "openid", "jwks_uri", "registration_endpoint", "device_authorization_endpoint", "introspection_endpoint"} {
		if strings.Contains(string(wire), forbidden) {
			t.Fatal("unselected capability or private configuration disclosed")
		}
	}
	// Returned metadata is caller-owned, not a mutable registration handle.
	m.ScopesSupported[0] = "expanded"
	m.TokenEndpointAuthMethodsSupported[0] = "private_key_jwt"
	config.Discovery.TokenEndpoint = "https://foreign.example/token"
	again, err := service.DiscoveryOauth(context.Background(), oauth.DiscoveryOauthRequest{})
	if err != nil || again.Metadata.TokenEndpoint != discoveryEndpoints().TokenEndpoint || !slices.Equal(again.Metadata.ScopesSupported, []string{"identity:read", "identity:write"}) || !slices.Equal(again.Metadata.TokenEndpointAuthMethodsSupported, []string{"none"}) {
		t.Fatal("caller changed retained discovery policy", err)
	}
}

func TestDiscoveryDisabledCanceledAndMalformedConfigurationFailClosed(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	config := coreConfig(t, now)
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: authorizationStore{}})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := service.DiscoveryOauth(context.Background(), oauth.DiscoveryOauthRequest{}); !errors.Is(err, oauth.ErrAccessDenied) || got.Metadata.Issuer != "" {
		t.Fatal("unselected discovery advertised metadata", err)
	}
	config.Discovery = discoveryEndpoints()
	service, _ = oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: authorizationStore{}})
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if got, err := service.DiscoveryOauth(canceled, oauth.DiscoveryOauthRequest{}); !errors.Is(err, context.Canceled) || got.Metadata.Issuer != "" {
		t.Fatal("canceled discovery disclosed metadata", err)
	}
	if _, err := service.DiscoveryOauth(nil, oauth.DiscoveryOauthRequest{}); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("nil context accepted")
	}
	if _, err := (*oauth.Service)(nil).DiscoveryOauth(context.Background(), oauth.DiscoveryOauthRequest{}); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("nil service accepted")
	}
	for _, change := range []func(*oauth.DiscoveryConfig){
		func(c *oauth.DiscoveryConfig) { c.Enabled = false },
		func(c *oauth.DiscoveryConfig) { c.AuthorizationEndpoint = "" },
		func(c *oauth.DiscoveryConfig) { c.TokenEndpoint = "" },
		func(c *oauth.DiscoveryConfig) { c.RevocationEndpoint = "" },
		func(c *oauth.DiscoveryConfig) { c.IntrospectionEndpoint = "https://issuer.example/oauth2/introspect" },
		func(c *oauth.DiscoveryConfig) { c.TokenEndpoint = c.AuthorizationEndpoint },
		func(c *oauth.DiscoveryConfig) { c.TokenEndpoint = "http://issuer.example/token" },
		func(c *oauth.DiscoveryConfig) { c.TokenEndpoint = "https://foreign.example/token" },
		func(c *oauth.DiscoveryConfig) { c.TokenEndpoint = "https://issuer.example:443/token" },
		func(c *oauth.DiscoveryConfig) { c.TokenEndpoint = "https://issuer.example/token?override=1" },
		func(c *oauth.DiscoveryConfig) { c.TokenEndpoint = "https://issuer.example/token#fragment" },
		func(c *oauth.DiscoveryConfig) { c.TokenEndpoint = "https://user@issuer.example/token" },
		func(c *oauth.DiscoveryConfig) { c.TokenEndpoint = "https://issuer.example/a/../token" },
		func(c *oauth.DiscoveryConfig) { c.TokenEndpoint = "https://issuer.example/%74oken" },
		func(c *oauth.DiscoveryConfig) { c.TokenEndpoint = "https://issuer.example//token" },
		func(c *oauth.DiscoveryConfig) {
			c.TokenEndpoint = "https://issuer.example/" + strings.Repeat("a", 2048)
		},
	} {
		candidate := config
		candidate.Discovery = discoveryEndpoints()
		change(&candidate.Discovery)
		if _, err := candidate.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("inconsistent endpoint/issuer profile accepted", err)
		}
	}
}
