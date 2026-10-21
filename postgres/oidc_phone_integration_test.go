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
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"golang.org/x/oauth2"
)

func phoneFixture(t *testing.T, f *authenticatedPasswordFixture) (*oauth.Service, *op.Service, *oauth.SigningService, *oauthpostgres.Store, *ecdsa.PrivateKey) {
	t.Helper()
	f.oauth.Protocol.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "email", "phone"})
	return oidcFixture(t, f)
}

func TestNativeOIDCPhoneIndependentRelyingParty(t *testing.T) {
	for _, pairwise := range []bool{false, true} {
		name := "public"
		if pairwise {
			name = "pairwise"
		}
		t.Run(name, func(t *testing.T) { nativePhoneRelyingParty(t, pairwise) })
	}
}

func nativePhoneRelyingParty(t *testing.T, pairwise bool) {
	f := passwordFixture(t)
	phone := pendingNativePhone(t, f)
	f.browser, f.csrf = f.signInAgain()
	f.oauth.Protocol.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "email", "phone"})
	fixture := oidcFixture
	if pairwise {
		// Reuse the original pairwise native binding/key owner; only opt-in scope
		// configuration differs from the independently established subject path.
		fixture = pairwiseFixture
	}
	service, child, _, _, _ := fixture(t, &f)
	discovery, err := child.Discovery(f.ctx)
	if err != nil || !slices.Contains(discovery.ScopesSupported, "phone") || !slices.Contains(discovery.ClaimsSupported, "phone_number_verified") {
		t.Fatal("selected phone profile missing discovery", err)
	}
	transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ctx := rp.ClientContext(f.ctx, client)
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal(err)
	}
	standard := oauth2.Config{ClientID: "public-web", RedirectURL: "https://client.example/callback", Endpoint: provider.Endpoint()}
	standard.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	exchange := func(scopes []string, nonce string) (*oauth2.Token, string) {
		t.Helper()
		selected := f
		selected.oauth.Protocol.OIDCScopes, _ = oauth.NewOIDCScopeCatalog(scopes)
		code, verifier := oidcCode(t, selected, service, nonce)
		token, err := standard.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatal("independent phone RP code/S256 exchange", err)
		}
		wire, ok := token.Extra("id_token").(string)
		if !ok {
			t.Fatal("phone RP missing ID token")
		}
		verified, err := consumeIDToken(ctx, provider, wire, nonce, "public-web")
		if err != nil {
			t.Fatal("independent phone RP verification", err)
		}
		var claims map[string]json.RawMessage
		if verified.Claims(&claims) != nil || len(claims) != 9 || claims["phone_number"] != nil || claims["phone_number_verified"] != nil || claims["email"] != nil {
			t.Fatal("phone scope expanded minimized ID token")
		}
		return token, verified.Subject
	}
	read := func(token *oauth2.Token, subject, want string, email bool) {
		t.Helper()
		info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil || info.Subject != subject {
			t.Fatal("independent phone RP UserInfo subject equality", err)
		}
		var raw map[string]json.RawMessage
		if info.Claims(&raw) != nil {
			t.Fatal("RP phone claims not JSON")
		}
		if want == "" {
			if raw["phone_number"] != nil || raw["phone_number_verified"] != nil {
				t.Fatal("unapproved/unverified phone disclosed")
			}
		} else {
			var actual string
			if json.Unmarshal(raw["phone_number"], &actual) != nil || actual != want || string(raw["phone_number_verified"]) != "true" {
				t.Fatal("RP phone differs from canonical verified owner or Boolean")
			}
		}
		count := 1
		if want != "" {
			count += 2
		}
		if email {
			count += 2
			if raw["email"] == nil || string(raw["email_verified"]) != "true" {
				t.Fatal("email+phone lost independently approved email")
			}
		}
		if len(raw) != count {
			t.Fatal("phone UserInfo returned extra unapproved claims")
		}
	}
	// Pending native SendVerification is not possession. A genuinely wrong OTP
	// cannot make either phone claim appear or silently upgrade an existing grant.
	pending, sub := exchange([]string{"openid", "phone"}, "phone-pending")
	read(pending, sub, "", false)
	phone.verify(t, f, true)
	read(pending, sub, "", false)
	phone.verify(t, f, false)
	if out, err := child.UserInfo(ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: pending.AccessToken}); err == nil || out.Subject != "" || out.PhoneNumber != "" {
		t.Fatal("native verification epoch change renewed an old grant", err)
	}
	// Identifier mutation invalidates the old identifier-bound browser. Obtain
	// genuine fresh password-session custody; do not rewrite its sealed epoch.
	f.browser, f.csrf = f.signInAgain()
	transport.f = f
	token, verifiedSub := exchange([]string{"openid", "email", "phone"}, "phone-verified")
	if verifiedSub != sub {
		t.Fatal("phone verification reassigned RP subject")
	}
	owner, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	state, err := owner.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: f.tenant, UserID: phone.user, MaximumIdentifiers: 128})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for j, identifier := range state.Identifiers {
		if identifier.ID == phone.send.IdentifierID {
			found = identifier.Kind == identity.IdentifierPhone && identifier.CanonicalValue == "+12025550123" && identifier.Verified && state.Verifications[j].State == identity.VerificationVerified
		}
	}
	if !found {
		t.Fatal("actual purpose-bound OTP did not establish native canonical phone")
	}
	read(token, sub, "+12025550123", true)
	for _, scopes := range [][]string{{"openid"}, {"openid", "email"}} {
		control, subject := exchange(scopes, "phone-scope-control")
		read(control, subject, "", len(scopes) == 2)
	}
	refresh, err := service.Token(ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: token.RefreshToken, Scopes: []string{"openid"}, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("phone native refresh narrowing", err)
	}
	narrowed, err := refresh.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	read(&oauth2.Token{AccessToken: narrowed, TokenType: "Bearer"}, sub, "", false)
	for _, clientID := range []string{"other-public-web"} {
		if out, err := child.UserInfo(ctx, oauth.UserInfoRequest{ClientID: clientID, AccessToken: token.AccessToken}); err == nil || out.Subject != "" || out.PhoneNumber != "" {
			t.Fatal("foreign client received phone claims", err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if out, err := child.UserInfo(canceled, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: token.AccessToken}); err == nil || out.Subject != "" || out.PhoneNumber != "" {
		t.Fatal("cancellation returned partial phone claims", err)
	}
}
