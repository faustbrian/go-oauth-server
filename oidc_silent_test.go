package oauthserver_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestOIDCSilentSelectedGrammarAndProtocolErrorLocation(t *testing.T) {
	base := "response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=https%3A%2F%2Fresource.example"
	if r, err := oauth.ParseAuthorizationQueryWithOIDC(base + "&prompt=none"); err != nil || r.Prompt != "none" {
		t.Fatal("selected silent prompt rejected", err)
	}
	for _, prompt := range []string{"", "none+login", "none+none", "none&prompt=none", "NONE"} {
		if _, err := oauth.ParseAuthorizationQueryWithOIDC(base + "&prompt=" + prompt); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("empty, duplicate or combined silent prompt accepted")
		}
	}
	if _, err := oauth.ParseAuthorizationQuery(base + "&prompt=none"); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("ordinary OAuth parser enabled silent OIDC")
	}
}

// These are contract seams, not native proof of reusable consent. Native tests
// must authenticate the session and exact stored consent independently.
func TestOIDCSilentCannotBecomeInteractionOrRenewOriginalAge(t *testing.T) {
	for _, mode := range []string{"code", "consent", "fresh", "login-required", "consent-required", "missing-session", "invalid-redirect", "expired-age", "unknown", "unknown-login-required", "unknown-consent-required"} {
		t.Run(mode, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			config := coreConfig(t, now)
			config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
			config.Clients[0].Scopes = append(config.Clients[0].Scopes, "openid")
			clock := now
			config.Clock = clockFunc(func() time.Time { return clock })
			r := coreAuthorization()
			r.Prompt, r.Scopes = "none", []string{"openid"}
			if mode == "expired-age" {
				r.MaxAge = uint32Pointer(120)
			}
			if mode == "invalid-redirect" {
				r.RedirectURI = "https://foreign.example/cb"
			}
			if mode == "missing-session" {
				bearer = auth.BearerCredential{}
			}
			calls := 0
			extension := subjectExtension{validate: func(oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error) {
				out := oauth.OIDCAuthorizationProjection{Accepted: true, Authentication: oauth.OIDCAuthenticationSilent}
				if r.MaxAge != nil {
					out.AuthenticationUntil = now.Add(time.Second)
				}
				return out, nil
			}}
			store := authorizationStore{call: func(_ context.Context, c oauth.AuthorizationCommand) (oauth.AuthorizeResult, error) {
				calls++
				if mode == "login-required" {
					return oauth.AuthorizeResult{}, oauth.ErrLoginRequired
				}
				if mode == "consent-required" {
					return oauth.AuthorizeResult{}, oauth.ErrConsentRequired
				}
				if mode == "unknown" {
					return oauth.AuthorizeResult{Outcome: oauth.AuthorizationUnknown}, oauth.ErrUnavailable
				}
				if mode == "unknown-login-required" {
					return oauth.AuthorizeResult{Outcome: oauth.AuthorizationUnknown}, oauth.ErrLoginRequired
				}
				if mode == "unknown-consent-required" {
					return oauth.AuthorizeResult{Outcome: oauth.AuthorizationUnknown}, oauth.ErrConsentRequired
				}
				out := oauth.AuthorizeResult{Outcome: oauth.AuthorizationRedirect, Request: c.Request, ExpiresAt: now.Add(time.Minute)}
				out.Code, _ = oauth.NewToken()
				if mode == "consent" || mode == "fresh" {
					out.Code = oauth.Token{}
					out.Continuation, _ = oauth.NewToken()
					out.Outcome = oauth.ConsentRequired
					if mode == "fresh" {
						out.Outcome = oauth.FreshAuthenticationRequired
					}
				}
				if mode == "expired-age" {
					clock = now.Add(2 * time.Second)
				}
				return out, nil
			}}
			service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store, OIDC: extension})
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.Authorize(context.Background(), oauth.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: r, Network: "192.0.2.1"})
			if mode == "login-required" || mode == "consent-required" || mode == "missing-session" {
				want := "login_required"
				if mode == "consent-required" {
					want = "consent_required"
				}
				location, locationErr := out.Location()
				parsed, parseErr := url.Parse(location)
				if err != nil || locationErr != nil || parseErr != nil || parsed.Query().Get("error") != want || parsed.Query().Get("state") != r.State || parsed.Query().Get("iss") != config.Issuer.String() || parsed.Host != "client.example" || len(parsed.Query()) != 3 || out.Code != (oauth.Token{}) || out.Continuation != (oauth.Token{}) {
					t.Fatal("silent protocol error lost exact validated redirect/state/issuer", err)
				}
			} else if mode == "code" {
				if err != nil || out.Outcome != oauth.AuthorizationRedirect || out.Code == (oauth.Token{}) || out.Continuation != (oauth.Token{}) {
					t.Fatal("silent current consent could not return fresh code", err)
				}
			} else if err == nil || out.Code != (oauth.Token{}) || out.Continuation != (oauth.Token{}) || out.RedirectURI != "" {
				t.Fatal("unaware, expired or unavailable silent result delivered interaction/material")
			}
			if (mode == "unknown" || mode == "unknown-login-required" || mode == "unknown-consent-required") && out.Outcome != oauth.AuthorizationUnknown {
				t.Fatal("unknown durability became a non-started standard error")
			}
			if (mode == "missing-session" || mode == "invalid-redirect") && calls != 0 {
				t.Fatal("invalid local request/session reached durable authorize")
			}
		})
	}
}
