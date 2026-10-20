//go:build integration && oauthflow

package oauthpostgres_test

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"golang.org/x/oauth2"
)

func TestNativeOIDCSectorURIMultiHostIndependentRelyingParty(t *testing.T) {
	f := passwordFixture(t)
	_, _, signer, _, _ := oidcFixture(t, &f)
	installPairwiseMigration(t, f)
	redirects := []string{"https://client.example/callback", "https://other.example/callback"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/registered-sector.json" {
			t.Error("wrong sector URI fetched")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(redirects)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	uri := "https://example.com:" + u.Port() + "/registered-sector.json"
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	validator, err := oauth.NewSectorValidator(oauth.SectorValidatorConfig{Issuer: f.oauth.Protocol.Issuer, Environment: f.oauth.Protocol.Environment, Endpoints: []oauth.SectorEndpoint{{URI: uri, Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}, RootCAs: roots, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var selected int
	for i := range f.oauth.Protocol.Clients {
		if f.oauth.Protocol.Clients[i].ID == "public-web" {
			selected = i
		}
	}
	f.oauth.Protocol.Clients[selected].Redirects = redirects
	proof, err := validator.Validate(f.ctx, oauth.SectorRegistrationRequest{Client: f.oauth.Protocol.Clients[selected], URI: uri, PolicyID: "subjects", PolicyVersion: 1})
	if err != nil {
		t.Fatal("actual registration HTTPS fetch failed", err)
	}
	registration := proof.SubjectRegistration()
	f.oauth.Protocol.Clients[selected].SubjectRegistration = &registration
	if _, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("native owner admitted multi-host policy without fetched provenance", err)
	}
	f.oauth.Protocol.SectorRegistrations = []oauth.ValidatedSectorRegistration{proof}
	for _, mutate := range []func(*oauth.Client){
		func(c *oauth.Client) { c.Version++ },
		func(c *oauth.Client) {
			c.Redirects = []string{"https://client.example/changed", "https://other.example/callback"}
		},
	} {
		foreign := f.oauth
		foreign.Protocol.Clients = append([]oauth.Client(nil), f.oauth.Protocol.Clients...)
		mutate(&foreign.Protocol.Clients[selected])
		if _, err := oauthpostgres.NewStore(f.pool, foreign, f.keys); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("native owner reused stale/changed registration proof", err)
		}
	}
	policy := pairwisePolicy(t, f, 1, [32]byte{1, 2, 3})
	service, child, store := pairwiseService(t, f, signer, policy)
	key, _ := policy.KeyRegistration(1)
	if err := store.InstallSubjectKey(f.ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateSubjectKey(f.ctx, "subjects", 1, 1); err != nil {
		t.Fatal(err)
	}
	transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ctx := rp.ClientContext(f.ctx, client)
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal(err)
	}
	var original string
	for i, redirect := range redirects {
		nonce := []string{"sector-first-nonce", "sector-second-nonce"}[i]
		code, verifier := pairwiseCodeForClient(t, f, service, "public-web", redirect, nonce)
		issued, err := service.Token(ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", RedirectURI: redirect, Code: code, CodeVerifier: verifier, Network: "192.0.2.1"})
		if err != nil {
			t.Fatal("validated multi-host code/S256 exchange denied", err)
		}
		wire, err := issued.IDToken.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		verified, err := consumeIDToken(ctx, provider, wire, nonce, "public-web")
		if err != nil || verified.Subject == "" || i > 0 && verified.Subject != original {
			t.Fatal("independent RP rejected original same-sector multi-host identity", err)
		}
		original = verified.Subject
		access, err := issued.AccessToken.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: access, TokenType: "Bearer"}))
		if err != nil || info.Subject != original {
			t.Fatal("independent RP UserInfo did not preserve multi-host grant subject", err)
		}
	}
	var sector, persisted string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT sector_host,subject FROM oauth_store.subject_bindings`).Scan(&sector, &persisted); err != nil || sector != "example.com" || persisted != original {
		t.Fatal("native durable subject did not use validated URI host", err)
	}
	refetched, err := validator.Validate(ctx, oauth.SectorRegistrationRequest{Client: f.oauth.Protocol.Clients[selected], URI: uri, PolicyID: "subjects", PolicyVersion: 1})
	if err != nil || refetched.SubjectRegistration() != registration {
		t.Fatal("legitimate registration refetch changed immutable policy identity", err)
	}
}
