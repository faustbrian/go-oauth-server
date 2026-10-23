package oauthserver_test

import (
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestLogoutRedirectRegistrationIsIndependentExactAndOwned(t *testing.T) {
	client := coreConfig(t, time.Now()).Clients[0]
	client.PostLogoutRedirects = []string{"https://client.example/signed-out?view=original"}
	selected, err := oauth.ValidateClient(client)
	if err != nil || len(selected.PostLogoutRedirects) != 1 || selected.PostLogoutRedirects[0] != client.PostLogoutRedirects[0] {
		t.Fatal("explicit logout registration rejected or changed", err)
	}
	client.PostLogoutRedirects[0] = "https://foreign.example/changed"
	if selected.PostLogoutRedirects[0] != "https://client.example/signed-out?view=original" {
		t.Fatal("caller mutation changed retained logout policy")
	}
	for _, uri := range []string{"https://client.example/cb", "https://client.example/signed-out?view=original&extra=1", "https://client.example/signed-out?view=original#fragment", "https://client.example/signed%2Dout?view=original"} {
		if oauth.PostLogoutRedirectAllowed(selected, uri) {
			t.Fatal("authorization callback or non-exact logout URI admitted")
		}
	}
	if !oauth.PostLogoutRedirectAllowed(selected, "https://client.example/signed-out?view=original") || oauth.PostLogoutRedirectAllowed(selected, "") {
		t.Fatal("registered exact logout URI or absent-target policy changed")
	}
	legacy, err := oauth.ValidateClient(coreConfig(t, time.Now()).Clients[0])
	if err != nil || len(legacy.PostLogoutRedirects) != 0 || oauth.PostLogoutRedirectAllowed(legacy, legacy.Redirects[0]) {
		t.Fatal("legacy authorization redirect implicitly became logout policy", err)
	}
	for _, targets := range [][]string{{"https://client.example/out#fragment"}, {"https://client.example/out", "https://client.example/out"}, {"http://foreign.example/out"}, {"https://client.example/out\n"}} {
		invalid := selected
		invalid.PostLogoutRedirects = targets
		if _, err := oauth.ValidateClient(invalid); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("invalid independent logout registration admitted", err)
		}
	}
}

func TestManagedLogoutRedirectsUseAnIndependentImmutableCeiling(t *testing.T) {
	_, browser, now, _ := coreSessionFixture(t)
	config := coreConfig(t, now)
	owner := config.Clients[0].Owner
	policy := oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, PostLogoutRedirects: []string{"https://client.example/out"}, Scopes: config.Scopes}
	csrf, _ := session.NewCSRFToken()
	key, _ := identity.NewIdempotencyKey([]byte("logout-client-registration"))
	request := oauth.ClientManagementRequest{Owner: owner, TenantID: "tenant", Session: browser, CSRF: csrf, Origin: config.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Redirects: []string{"https://client.example/cb"}, PostLogoutRedirects: []string{"https://client.example/out"}, Scopes: []string{"identity:read"}}
	accepted, err := oauth.ValidateClientManagementRequest(request, false, policy, config.Issuer)
	if err != nil || len(accepted.PostLogoutRedirects) != 1 || accepted.PostLogoutRedirects[0] != "https://client.example/out" {
		t.Fatal("selected managed logout metadata rejected", err)
	}
	request.PostLogoutRedirects[0] = "https://foreign.example/out"
	if accepted.PostLogoutRedirects[0] != "https://client.example/out" {
		t.Fatal("managed logout registration aliases caller metadata")
	}
	for _, target := range []string{"https://client.example/cb", "https://foreign.example/out"} {
		invalid := accepted
		invalid.PostLogoutRedirects = []string{target}
		if _, err := oauth.ValidateClientManagementRequest(invalid, false, policy, config.Issuer); !errors.Is(err, oauth.ErrAccessDenied) {
			t.Fatal("authorization ceiling silently allowed a logout target", err)
		}
	}
	legacyPolicy := policy
	legacyPolicy.PostLogoutRedirects = nil
	if _, err := oauth.ValidateClientManagementRequest(accepted, false, legacyPolicy, config.Issuer); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("absent logout ceiling admitted managed logout registration", err)
	}
}
