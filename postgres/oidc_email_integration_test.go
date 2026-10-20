//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"golang.org/x/oauth2"
)

func emailFixture(t *testing.T, f *authenticatedPasswordFixture) (*oauth.Service, *op.Service, *oauth.SigningService, *oauthpostgres.Store, *ecdsa.PrivateKey) {
	t.Helper()
	f.oauth.Protocol.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "email"})
	return oidcFixture(t, f)
}

func TestNativeOIDCEmailIndependentRelyingParty(t *testing.T) {
	for _, pairwise := range []bool{false, true} {
		name := "public"
		if pairwise {
			name = "pairwise"
		}
		t.Run(name, func(t *testing.T) { nativeEmailRelyingParty(t, pairwise) })
	}
}

func nativeEmailRelyingParty(t *testing.T, pairwise bool) {
	f := passwordFixture(t)
	service, child, signer, _, _ := emailFixture(t, &f)
	if pairwise {
		installPairwiseMigration(t, f)
		registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
		for i := range f.oauth.Protocol.Clients {
			f.oauth.Protocol.Clients[i].SubjectRegistration = &registration
		}
		policy := pairwisePolicy(t, f, 1, [32]byte{1, 2, 3})
		store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
		if err != nil {
			t.Fatal(err)
		}
		core, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
		if err != nil {
			t.Fatal(err)
		}
		issuer := f.oauth.Protocol.Issuer.String()
		child, err = op.NewService(op.Config{Issuer: f.oauth.Protocol.Issuer, JWKSURI: issuer + "/oauth2/jwks", UserInfoEndpoint: issuer + "/oauth2/userinfo", Signing: signer, SubjectKey: [32]byte{42}, SubjectPolicy: policy, Clock: clock.System{}, MaximumDuration: 4 * time.Second, EmailUserInfo: true}, core)
		if err != nil {
			t.Fatal(err)
		}
		service, err = core.WithOIDC(child)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := policy.KeyRegistration(1)
		if err := store.InstallSubjectKey(f.ctx, key); err != nil {
			t.Fatal(err)
		}
		if err := store.ActivateSubjectKey(f.ctx, "subjects", 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	discovery, err := child.Discovery(f.ctx)
	if err != nil || !slices.Contains(discovery.ScopesSupported, "email") || !slices.Contains(discovery.ClaimsSupported, "email_verified") {
		t.Fatal("selected email profile not advertised", err)
	}
	transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ctx := rp.ClientContext(f.ctx, client)
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := oidcCode(t, f, service, "email-rp-nonce")
	standard := oauth2.Config{ClientID: "public-web", RedirectURL: "https://client.example/callback", Scopes: []string{"openid", "email"}, Endpoint: provider.Endpoint()}
	standard.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	token, err := standard.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal("independent RP email code exchange failed", err)
	}
	wire, ok := token.Extra("id_token").(string)
	if !ok {
		t.Fatal("missing ID token")
	}
	verified, err := consumeIDToken(ctx, provider, wire, "email-rp-nonce", "public-web")
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]json.RawMessage
	if verified.Claims(&claims) != nil || claims["email"] != nil || claims["email_verified"] != nil {
		t.Fatal("email scope expanded ID token")
	}
	source, err := service.UserInfoSource(ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: token.AccessToken})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	state, err := owner.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: source.TenantID, UserID: source.UserID, MaximumIdentifiers: 128})
	if err != nil {
		t.Fatal(err)
	}
	var expected string
	for _, identifier := range state.Identifiers {
		if identifier.Kind == identity.IdentifierEmail && identifier.Verified && (expected == "" || identifier.Primary) {
			expected = identifier.CanonicalValue
		}
	}
	if expected == "" {
		t.Fatal("genuine signup did not establish verified email")
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil || info.Subject != verified.Subject || info.Email != expected || !info.EmailVerified {
		t.Fatal("RP did not receive exact authoritative consented email with unchanged sub", err)
	}
	var raw map[string]json.RawMessage
	if info.Claims(&raw) != nil || len(raw) != 3 {
		t.Fatal("email UserInfo exposed extra identity fields")
	}
	openid := f
	openid.oauth.Protocol.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
	openidCode, openidProof := oidcCode(t, openid, service, "no-email-consent")
	noEmail, err := standard.Exchange(ctx, openidCode, oauth2.VerifierOption(openidProof))
	if err != nil {
		t.Fatal(err)
	}
	onlySubject, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(noEmail))
	var minimal map[string]json.RawMessage
	if err != nil || onlySubject.Subject != verified.Subject || onlySubject.Claims(&minimal) != nil || len(minimal) != 1 {
		t.Fatal("openid-only consent disclosed email in enabled profile", err)
	}
	if out, err := child.UserInfo(ctx, oauth.UserInfoRequest{ClientID: "other-public-web", AccessToken: token.AccessToken}); err == nil || out.Subject != "" || out.Email != "" {
		t.Fatal("foreign client received email")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if out, err := child.UserInfo(canceled, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: token.AccessToken}); err == nil || out.Subject != "" || out.Email != "" {
		t.Fatal("canceled call returned partial claims")
	}
	if _, err := service.Revoke(ctx, oauth.RevokeRequest{ClientID: "public-web", Token: token.AccessToken, Hint: oauth.TokenAccess, Network: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token)); err == nil {
		t.Fatal("revoked token disclosed email")
	}
}

func TestNativeOIDCEmailCurrentAuthorityAndTransactions(t *testing.T) {
	t.Run("authority", func(t *testing.T) {
		nativeOIDCCurrentAuthority(t, emailFixture, []string{"credential", "subject", "consent", "grant"})
	})
	t.Run("transactions", func(t *testing.T) { nativeOIDCTokenCommitModes(t, emailFixture) })
}
