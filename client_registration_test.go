package oauthserver_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	oauth "github.com/faustbrian/go-oauth-server"
)

// This native protocol request deliberately has no browser session, CSRF token,
// caller command ID or Idempotency-Key. None authenticates RFC7591 registration.
func registrationRequest() oauth.DynamicRegisterRequest {
	return oauth.DynamicRegisterRequest{
		InitialAccessToken:   strings.Repeat("a", 42) + "o",
		Public:               true,
		RedirectURIs:         []string{"https://client.example/cb"},
		GrantTypes:           []string{"authorization_code", "refresh_token"},
		ResponseTypes:        []string{"code"},
		AuthenticationMethod: "none",
		Scopes:               []string{"identity:read"},
		ClientName:           "Native public consumer",
		Network:              "192.0.2.1",
	}
}

func TestDynamicRegistrationMetadataIsAtomicAndPublicOnly(t *testing.T) {
	_, _, now, _ := coreSessionFixture(t)
	c := coreConfig(t, now)
	owner, _ := oauth.NewPlatformOwner("platform")
	p := oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes, PublicClients: true,
		DynamicRegistration: &oauth.DynamicRegistrationPolicy{Audience: c.Issuer.String() + "/oauth2/register", Version: 1, AllowedScopes: []string{"identity:read"}},
	}
	r := registrationRequest()
	accepted, err := oauth.ValidateDynamicRegisterRequest(r, p, c.Issuer)
	if err != nil || !accepted.Public || accepted.AuthenticationMethod != "none" {
		t.Fatal("header-free public metadata denied", err)
	}
	r.RedirectURIs[0] = "https://changed.example/cb"
	r.Scopes[0] = "identity:write"
	if !slices.Equal(accepted.RedirectURIs, []string{"https://client.example/cb"}) || !slices.Equal(accepted.Scopes, []string{"identity:read"}) {
		t.Fatal("validated request retained caller-owned metadata")
	}
	for name, change := range map[string]func(*oauth.DynamicRegisterRequest){
		"duplicate scope":  func(r *oauth.DynamicRegisterRequest) { r.Scopes = []string{"identity:read", "identity:read"} },
		"scope expansion":  func(r *oauth.DynamicRegisterRequest) { r.Scopes = []string{"identity:write"} },
		"unknown scope":    func(r *oauth.DynamicRegisterRequest) { r.Scopes = []string{"unknown"} },
		"foreign redirect": func(r *oauth.DynamicRegisterRequest) { r.RedirectURIs = []string{"https://foreign.example/cb"} },
		"duplicate redirect": func(r *oauth.DynamicRegisterRequest) {
			r.RedirectURIs = []string{"https://client.example/cb", "https://client.example/cb"}
		},
		"secret method":      func(r *oauth.DynamicRegisterRequest) { r.AuthenticationMethod = "client_secret_basic" },
		"implicit grant":     func(r *oauth.DynamicRegisterRequest) { r.GrantTypes = []string{"implicit"} },
		"token response":     func(r *oauth.DynamicRegisterRequest) { r.ResponseTypes = []string{"token"} },
		"missing code grant": func(r *oauth.DynamicRegisterRequest) { r.GrantTypes = []string{"refresh_token"} },
		"unbounded name":     func(r *oauth.DynamicRegisterRequest) { r.ClientName = strings.Repeat("n", 257) },
		"invalid token":      func(r *oauth.DynamicRegisterRequest) { r.InitialAccessToken = "bad token" },
	} {
		t.Run(name, func(t *testing.T) {
			r := registrationRequest()
			change(&r)
			if _, err := oauth.ValidateDynamicRegisterRequest(r, p, c.Issuer); err == nil {
				t.Fatal("invalid complete registration admitted")
			}
		})
	}
	confidential := registrationRequest()
	confidential.Public, confidential.AuthenticationMethod = false, "client_secret_basic"
	if _, err := oauth.ValidateDynamicRegisterRequest(confidential, p, c.Issuer); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("valid confidential class must be unselected, not a malformed zero value", err)
	}
	p.DynamicRegistration = nil
	if _, err := oauth.ValidateDynamicRegisterRequest(registrationRequest(), p, c.Issuer); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("disabled registration admitted")
	}
}
