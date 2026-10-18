package oauthserver_test

import (
	"errors"
	"slices"
	"testing"

	oauthserver "github.com/faustbrian/go-oauth-server"
)

func TestIssuerAndScopePolicyFailClosed(t *testing.T) {
	issuer, err := oauthserver.NewIssuer("https://issuer.example")
	if err != nil || issuer.String() != "https://issuer.example" {
		t.Fatal("explicit issuer rejected", err)
	}
	for _, value := range []string{"", "http://issuer.example", "https://issuer.example/path", "https://issuer.example/", "https://user@issuer.example", "https://issuer.example?tenant=x", "https://issuer.example#fragment"} {
		if _, err := oauthserver.NewIssuer(value); !errors.Is(err, oauthserver.ErrInvalidRequest) {
			t.Fatal("non-origin or untrusted issuer accepted")
		}
	}
	input := []string{"identity:write", "identity:read"}
	catalog, err := oauthserver.NewScopeCatalog(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = "unapproved"
	projection := catalog.Scopes()
	if !slices.Equal(projection, []string{"identity:read", "identity:write"}) {
		t.Fatal("caller changed frozen scope policy")
	}
	projection[0] = "another"
	if !catalog.Contains("identity:read") || catalog.Contains("another") {
		t.Fatal("scope projection became policy authority")
	}
	for _, values := range [][]string{nil, {"identity:read", "identity:read"}, {"read write"}, {"openid"}, {"profile"}, {"email"}, {"address"}, {"phone"}, {"offline_access"}} {
		if _, err := oauthserver.NewScopeCatalog(values); !errors.Is(err, oauthserver.ErrInvalidRequest) {
			t.Fatal("invalid/OIDC-only core scope accepted")
		}
	}
}

func TestClientPublicFalseIsValidButNeverMethodDowngrade(t *testing.T) {
	owner, err := oauthserver.NewPlatformOwner("platform-a")
	if err != nil {
		t.Fatal(err)
	}
	base := oauthserver.Client{ID: "client", Owner: owner, Version: 1, Public: false, AuthenticationMethod: "client_secret_basic", Redirects: []string{"https://client.example/cb"}, Scopes: []string{"identity:read"}, Resource: "https://resource.example"}
	client, err := oauthserver.ValidateClient(base)
	if err != nil || client.Public || client.AuthenticationMethod != "client_secret_basic" {
		t.Fatal("confidential false incorrectly rejected", err)
	}
	base.Redirects[0] = "https://attacker.example/cb"
	if client.Redirects[0] != "https://client.example/cb" {
		t.Fatal("caller mutated validated client")
	}
	for _, change := range []func(*oauthserver.Client){
		func(c *oauthserver.Client) { c.Public = true },
		func(c *oauthserver.Client) { c.AuthenticationMethod = "none" },
		func(c *oauthserver.Client) { c.AuthenticationMethod = "private_key_jwt" },
		func(c *oauthserver.Client) { c.Owner = oauthserver.Owner{} },
		func(c *oauthserver.Client) { c.Version = 0 },
		func(c *oauthserver.Client) { c.Scopes = []string{"identity:read", "identity:read"} },
		func(c *oauthserver.Client) { c.Resource = "https://resource.example/unselected-path" },
	} {
		changed := client
		change(&changed)
		if _, err := oauthserver.ValidateClient(changed); !errors.Is(err, oauthserver.ErrInvalidRequest) {
			t.Fatal("invalid client policy accepted")
		}
	}
	client.Public, client.AuthenticationMethod = true, "none"
	if _, err := oauthserver.ValidateClient(client); err != nil {
		t.Fatal("explicit no-secret public client rejected", err)
	}
}
