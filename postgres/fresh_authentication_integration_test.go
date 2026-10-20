//go:build integration && oauthflow

package oauthpostgres_test

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	"golang.org/x/oauth2"
)

func TestNativeOIDCFreshLoginContinuationUsesGenuineNewPasswordSession(t *testing.T) {
	f := passwordFixture(t)
	service, child, _, _, _ := oidcFixture(t, &f)
	verifier := oauth2.GenerateVerifier()
	request := oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", State: "original-fresh-state", CodeChallenge: oauth2.S256ChallengeFromVerifier(verifier), Resource: f.oauth.Protocol.Resource, Scopes: []string{"identity:read", "openid"}, Nonce: "original-fresh-nonce", Prompt: "login"}
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Request: request, Network: "192.0.2.1"})
	if err != nil || begin.Outcome != oauth.FreshAuthenticationRequired {
		t.Fatal("prompt login did not retain original native fresh-authentication continuation", err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: request.ClientID, Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrLoginRequired) {
		t.Fatal("original old password session bypassed requested fresh authentication")
	}
	browser, csrf := f.signInAgain()
	token, err := session.ParseToken(browser.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	observed, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil || !observed.Authenticated {
		t.Fatal("actual newly authenticated password session unavailable", err)
	}
	bindings, err := observed.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	approved, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: browser, CSRF: csrf, ClientID: request.ClientID, Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"})
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect || approved.ExpiresAt.After(begin.ExpiresAt) {
		t.Fatal("genuine fresh login did not complete original protected continuation without renewing its deadline", err)
	}
	if replay, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: browser, CSRF: csrf, ClientID: request.ClientID, Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrAccessDenied) || replay.Outcome == oauth.FreshAuthenticationRequired {
		t.Fatal("spent fresh-login continuation restarted authentication instead of denying replay", err)
	}
	verifyOriginalAuthenticationOutcome(t, f, service, child, request, approved, verifier, bindings.Authentication.Proof.IssuedAt, "")
}

// This consumer checks signed claims and current UserInfo through the independent
// RP, not a decoded-but-unverified JWT or a test-constructed authentication.
func verifyOriginalAuthenticationOutcome(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service, child *op.Service, request oauth.AuthorizationRequest, approved oauth.AuthorizeResult, verifier string, authenticatedAt time.Time, expectedSubject string) string {
	t.Helper()
	location, err := approved.Location()
	if err != nil {
		t.Fatal(err)
	}
	callback, _ := url.Parse(location)
	if callback.Query().Get("state") != request.State || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() {
		t.Fatal("fresh login changed original callback correlation")
	}
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: request.ClientID, RedirectURI: request.RedirectURI, Code: callback.Query().Get("code"), CodeVerifier: verifier, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("original fresh-login code/S256 exchange denied", err)
	}
	transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child}
	ctx := rp.ClientContext(f.ctx, &http.Client{Transport: transport, Timeout: 5 * time.Second})
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal(err)
	}
	wire, err := issued.IDToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := consumeIDToken(ctx, provider, wire, request.Nonce, request.ClientID)
	if err != nil {
		t.Fatal("independent RP rejected original-intent fresh-login ID token", err)
	}
	var claims struct {
		AuthTime int64 `json:"auth_time"`
	}
	if verified.Claims(&claims) != nil || claims.AuthTime != authenticatedAt.Unix() || expectedSubject != "" && verified.Subject != expectedSubject {
		t.Fatal("signed auth_time did not come from genuine new password authentication")
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: access, TokenType: "Bearer"}))
	if err != nil || info.Subject != verified.Subject {
		t.Fatal("fresh-login grant UserInfo did not preserve independently verified subject", err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: request.ClientID, Token: refresh, Hint: oauth.TokenRefresh, Network: "192.0.2.1"}); err != nil {
		t.Fatal("fresh-login original grant withdrawal failed", err)
	}
	if info, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: request.ClientID, AccessToken: access}); err == nil || info.Subject != "" {
		t.Fatal("fresh-login UserInfo survived current original grant revocation")
	}
	return verified.Subject
}
