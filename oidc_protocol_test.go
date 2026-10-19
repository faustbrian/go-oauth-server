package oauthserver_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestConfigSeparatesOAuthAndOIDCCatalogOwnership(t *testing.T) {
	c := coreConfig(t, time.Now())
	reserved, _ := oauth.NewOIDCScopeCatalog([]string{"openid"})
	c.OIDCScopes = reserved
	c.Clients[0].Scopes = append(c.Clients[0].Scopes, "openid")
	if _, err := c.Validated(); err != nil {
		t.Fatal("valid split catalogs rejected", err)
	}
	for _, change := range []func(*oauth.Config){
		func(c *oauth.Config) {
			c.Scopes, c.OIDCScopes = reserved, oauth.ScopeCatalog{}
			c.Clients[0].Scopes = []string{"openid"}
		},
		func(c *oauth.Config) { c.Scopes = reserved; c.Clients[0].Scopes = []string{"openid"} },
		func(c *oauth.Config) { c.OIDCScopes = c.Scopes; c.Clients[0].Scopes = []string{"identity:read"} },
	} {
		invalid := c
		invalid.Clients = append([]oauth.Client(nil), c.Clients...)
		change(&invalid)
		if _, err := invalid.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("catalog cross-assignment or duplicate ownership admitted", err)
		}
	}
}

func TestOIDCCodeParserPreservesNonce(t *testing.T) {
	q := url.Values{"response_type": {"code"}, "client_id": {"rp"}, "redirect_uri": {"https://rp.example/callback"}, "scope": {"openid"}, "nonce": {"original-rp-nonce"}, "code_challenge_method": {"S256"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "resource": {"https://resource.example"}}
	parsed, err := oauth.ParseAuthorizationQueryWithOIDC(q.Encode())
	if err != nil || parsed.Nonce != "original-rp-nonce" {
		t.Fatal("selected OIDC code nonce rejected or changed", err)
	}
	for _, nonce := range []string{"", strings.Repeat("a", 257), "line\nfeed"} {
		q.Set("nonce", nonce)
		if _, err := oauth.ParseAuthorizationQueryWithOIDC(q.Encode()); err == nil {
			t.Fatal("invalid nonce accepted")
		}
	}
	q.Set("nonce", "one")
	q.Add("nonce", "two")
	if _, err := oauth.ParseAuthorizationQueryWithOIDC(q.Encode()); err == nil {
		t.Fatal("duplicate nonce accepted")
	}
}
