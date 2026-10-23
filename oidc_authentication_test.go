package oauthserver_test

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestOIDCAuthenticationWirePresenceAndSelectedGrammar(t *testing.T) {
	base := "response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=https%3A%2F%2Fresource.example"
	for _, tc := range []struct {
		query, prompt string
		age           *uint32
	}{
		{"", "", nil},
		{"&prompt=login", "login", nil},
		{"&prompt=none", "none", nil},
		{"&prompt=consent", "consent", nil},
		{"&max_age=0", "", uint32Pointer(0)},
		{"&max_age=60", "", uint32Pointer(60)},
		{"&prompt=login&max_age=60", "login", uint32Pointer(60)},
	} {
		request, err := oauth.ParseAuthorizationQueryWithOIDC(base + tc.query)
		if err != nil || request.Prompt != tc.prompt || (request.MaxAge == nil) != (tc.age == nil) || tc.age != nil && *request.MaxAge != *tc.age {
			t.Fatal("OIDC authentication presence/value was lost", err)
		}
	}
	for _, suffix := range []string{"&prompt=", "&prompt=select_account", "&prompt=consent+none", "&prompt=consent+login", "&prompt=consent+consent", "&prompt=login+none", "&prompt=none+none", "&prompt=login+login", "&prompt=LOGIN", "&prompt=CONSENT", "&prompt=login&prompt=login", "&prompt=consent&prompt=consent", "&max_age=", "&max_age=-1", "&max_age=1.5", "&max_age=%2B1", "&max_age=4294967296", "&max_age=0&max_age=1"} {
		if _, err := oauth.ParseAuthorizationQueryWithOIDC(base + suffix); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("unselected/malformed authentication request admitted", err)
		}
	}
	for _, prompt := range []string{"login", "none", "consent"} {
		if _, err := oauth.ParseAuthorizationQuery(base + "&prompt=" + prompt); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("ordinary OAuth parser selected OIDC authentication semantics")
		}
	}
	if oauth.FreshAuthenticationRequired == oauth.LoginRequired || oauth.FreshAuthenticationRequired == oauth.ConsentRequired {
		t.Fatal("fresh authentication continuation collapsed into an unbound login or consent outcome")
	}
}

func TestOIDCConsentCannotSelectAnUncomposedService(t *testing.T) {
	sessions, bearer, now, _ := coreSessionFixture(t)
	config := coreConfig(t, now)
	config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
	config.Clients[0].Scopes = append(config.Clients[0].Scopes, "openid")
	store := authorizationStore{call: func(context.Context, oauth.AuthorizationCommand) (oauth.AuthorizeResult, error) {
		t.Fatal("uncomposed consent reached persistence")
		return oauth.AuthorizeResult{}, nil
	}}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	request := coreAuthorization()
	request.Prompt, request.Scopes = "consent", append(request.Scopes, "openid")
	out, err := service.Authorize(context.Background(), oauth.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: request, Network: "192.0.2.1"})
	if !errors.Is(err, oauth.ErrInvalidRequest) || out.Outcome != 0 || out.Code != (oauth.Token{}) || out.Continuation != (oauth.Token{}) {
		t.Fatal("uncomposed service selected consent semantics", err)
	}
}

func uint32Pointer(value uint32) *uint32 { return &value }

func FuzzOIDCAuthenticationQuery(f *testing.F) {
	base := "response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=https%3A%2F%2Fresource.example"
	for _, suffix := range []string{"", "&prompt=login", "&prompt=consent", "&prompt=consent+none", "&max_age=0", "&max_age=4294967295", "&max_age=4294967296", "&prompt=none", "&max_age=0&max_age=1", "&max_age=%00"} {
		f.Add(base + suffix)
	}
	f.Fuzz(func(t *testing.T, query string) {
		request, err := oauth.ParseAuthorizationQueryWithOIDC(query)
		if err == nil && request.Prompt != "" && request.Prompt != "login" && request.Prompt != "none" && request.Prompt != "consent" {
			t.Fatal("unselected prompt admitted")
		}
	})
}

// Only the callback/adapter projection seam is isolated here. The native
// consumer independently proves real password and stored-session authority.
func TestOIDCMaxAgeOwnershipAcrossExtensionAdapterAndReturnedRequest(t *testing.T) {
	sessions, bearer, now, _ := coreSessionFixture(t)
	config := coreConfig(t, now)
	config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
	config.Clients[0].Scopes = append(config.Clients[0].Scopes, "openid")
	value := uint32(0)
	request := coreAuthorization()
	request.Scopes = append(request.Scopes, "openid")
	request.MaxAge = &value
	extension := subjectExtension{validate: func(in oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error) {
		if in.Request.MaxAge == nil || *in.Request.MaxAge != 0 {
			t.Fatal("explicit max_age zero lost before child")
		}
		*in.Request.MaxAge = 99
		value = 7
		return oauth.OIDCAuthorizationProjection{Accepted: true, Authentication: oauth.OIDCAuthenticationFresh}, nil
	}}
	store := authorizationStore{call: func(_ context.Context, c oauth.AuthorizationCommand) (oauth.AuthorizeResult, error) {
		if c.Request.MaxAge == nil || *c.Request.MaxAge != 0 || c.OIDC == nil {
			t.Fatal("caller/child mutation changed original native request or lost child policy")
		}
		retained := c.Request
		retained.MaxAge = uint32Pointer(*c.Request.MaxAge)
		*c.Request.MaxAge = 88
		continuation, err := oauth.NewToken()
		if err != nil {
			t.Fatal(err)
		}
		return oauth.AuthorizeResult{Outcome: oauth.FreshAuthenticationRequired, Request: retained, Continuation: continuation, ExpiresAt: now.Add(time.Minute)}, nil
	}}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store, OIDC: extension})
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.Authorize(context.Background(), oauth.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: request, Network: "192.0.2.1"})
	if err != nil || out.Outcome != oauth.FreshAuthenticationRequired || out.Request.MaxAge == nil || *out.Request.MaxAge != 0 || value != 7 {
		t.Fatal("retained/result max_age aliased caller/adapter projections", err)
	}
}

func TestOIDCAuthenticationCannotBeDowngradedByUnawareAdapter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prompt  string
		age     *uint32
		policy  oauth.OIDCAuthenticationRequirement
		outcome oauth.AuthorizeOutcome
		echo    bool
		allowed bool
		after   time.Duration
	}{
		{"old-adapter-login", "login", nil, oauth.OIDCAuthenticationFresh, oauth.ConsentRequired, false, false, 0},
		{"fresh-policy-ordinary-consent", "login", nil, oauth.OIDCAuthenticationFresh, oauth.ConsentRequired, true, false, 0},
		{"old-adapter-positive-age", "", uint32Pointer(30), oauth.OIDCAuthenticationCurrent, oauth.ConsentRequired, false, false, 0},
		{"old-adapter-explicit-zero", "", uint32Pointer(0), oauth.OIDCAuthenticationFresh, oauth.FreshAuthenticationRequired, false, false, 0},
		{"selected-login", "login", nil, oauth.OIDCAuthenticationFresh, oauth.FreshAuthenticationRequired, true, true, 0},
		{"selected-positive-age", "", uint32Pointer(30), oauth.OIDCAuthenticationCurrent, oauth.ConsentRequired, true, true, 0},
		{"selected-consent", "consent", nil, oauth.OIDCAuthenticationCurrent, oauth.ConsentRequired, true, true, 0},
		{"old-adapter-consent", "consent", nil, oauth.OIDCAuthenticationCurrent, oauth.ConsentRequired, false, false, 0},
		{"consent-cannot-skip-interaction", "consent", nil, oauth.OIDCAuthenticationCurrent, oauth.AuthorizationRedirect, true, false, 0},
		{"late-positive-age", "", uint32Pointer(30), oauth.OIDCAuthenticationCurrent, oauth.ConsentRequired, true, false, 2 * time.Second},
		{"historical-metadata", "login", nil, oauth.OIDCAuthenticationFresh, oauth.AuthorizationHistorical, false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			config := coreConfig(t, now)
			clockNow := now
			config.Clock = clockFunc(func() time.Time { return clockNow })
			config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
			config.Clients[0].Scopes = append(config.Clients[0].Scopes, "openid")
			request := coreAuthorization()
			request.Scopes = append(request.Scopes, "openid")
			request.Prompt, request.MaxAge = tc.prompt, tc.age
			extension := subjectExtension{validate: func(oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error) {
				projection := oauth.OIDCAuthorizationProjection{Accepted: true, Authentication: tc.policy}
				if tc.policy == oauth.OIDCAuthenticationCurrent {
					projection.AuthenticationUntil = now.Add(time.Second)
				}
				return projection, nil
			}}
			store := authorizationStore{call: func(_ context.Context, c oauth.AuthorizationCommand) (oauth.AuthorizeResult, error) {
				clockNow = now.Add(tc.after)
				out := oauth.AuthorizeResult{Outcome: tc.outcome}
				if tc.echo {
					out.Request = c.Request
				}
				if tc.outcome != oauth.AuthorizationHistorical {
					out.Continuation, _ = oauth.NewToken()
					out.ExpiresAt = now.Add(time.Minute)
					if tc.outcome == oauth.AuthorizationRedirect {
						out.Code, out.Continuation = out.Continuation, oauth.Token{}
					}
				}
				return out, nil
			}}
			service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store, OIDC: extension})
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.Authorize(context.Background(), oauth.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: request, Network: "192.0.2.1"})
			if tc.allowed {
				if err != nil || out.Outcome != tc.outcome {
					t.Fatal("selected adapter or historical metadata denied", err)
				}
			} else {
				want := oauth.ErrUnavailable
				if tc.after > 0 {
					want = oauth.ErrLoginRequired
				}
				if !errors.Is(err, want) {
					t.Fatal("unaware adapter downgraded original authentication policy", err)
				}
				if _, err := out.Continuation.Reveal(); err == nil {
					t.Fatal("downgraded adapter delivered a policy-free continuation")
				}
				if _, err := out.Code.Reveal(); err == nil {
					t.Fatal("downgraded adapter delivered a code before requested consent")
				}
			}
		})
	}
}

type authenticationContinuationStore struct {
	oauth.Store
	call func(context.Context, oauth.ContinuationCommand) (oauth.AuthorizeResult, error)
}

func (s authenticationContinuationStore) Continue(ctx context.Context, command oauth.ContinuationCommand) (oauth.AuthorizeResult, error) {
	return s.call(ctx, command)
}

func TestOIDCAuthenticationContinuationConservesOriginalPolicyAfterStoreWait(t *testing.T) {
	for _, mode := range []string{"missing-policy", "ignored-fresh-policy", "expired-age", "renewed-age", "changed-intent", "valid-age", "historical", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			clockNow := now
			config := coreConfig(t, now)
			config.Clock = clockFunc(func() time.Time { return clockNow })
			config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
			config.Clients[0].Scopes = append(config.Clients[0].Scopes, "openid")
			original := coreAuthorization()
			original.Scopes = append(original.Scopes, "openid")
			original.MaxAge = uint32Pointer(30)
			if mode == "ignored-fresh-policy" {
				original.Prompt = "login"
			}
			calls := 0
			extension := subjectExtension{validate: func(oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error) {
				calls++
				if mode == "ignored-fresh-policy" {
					return oauth.OIDCAuthorizationProjection{Accepted: true, Authentication: oauth.OIDCAuthenticationFresh}, nil
				}
				until := now.Add(time.Second)
				if mode == "valid-age" || calls > 1 {
					until = now.Add(10 * time.Second)
				}
				return oauth.OIDCAuthorizationProjection{Accepted: true, Authentication: oauth.OIDCAuthenticationCurrent, AuthenticationUntil: until}, nil
			}}
			store := authenticationContinuationStore{call: func(ctx context.Context, command oauth.ContinuationCommand) (oauth.AuthorizeResult, error) {
				if mode != "missing-policy" && mode != "historical" && mode != "unknown" {
					if command.OIDC == nil {
						t.Fatal("composed policy callback missing")
					}
					if _, err := command.OIDC(ctx, oauth.OIDCAuthorizationInput{Request: original, Client: command.Client, Session: command.Session}); err != nil {
						t.Fatal(err)
					}
				}
				clockNow = now.Add(2 * time.Second)
				if mode == "renewed-age" {
					if _, err := command.OIDC(ctx, oauth.OIDCAuthorizationInput{Request: original, Client: command.Client, Session: command.Session}); err != nil {
						t.Fatal(err)
					}
				}
				out := oauth.AuthorizeResult{Outcome: oauth.AuthorizationRedirect, Request: original, ExpiresAt: now.Add(time.Minute)}
				out.Code, _ = oauth.NewToken()
				if mode == "changed-intent" {
					out.Request.MaxAge = nil
				}
				if mode == "historical" || mode == "unknown" {
					out.Request = oauth.AuthorizationRequest{}
					out.RedirectURI, out.State = "https://foreign.example/cb", "foreign-state"
					out.Outcome = oauth.AuthorizationHistorical
					if mode == "unknown" {
						out.Outcome = oauth.AuthorizationUnknown
					}
				}
				return out, nil
			}}
			service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store, OIDC: extension})
			if err != nil {
				t.Fatal(err)
			}
			continuation, _ := oauth.NewToken()
			wire, _ := continuation.Reveal()
			csrf, _ := session.NewCSRFToken()
			out, err := service.Continue(context.Background(), oauth.ContinueRequest{TenantID: "tenant", Session: bearer, CSRF: csrf, ClientID: original.ClientID, Continuation: wire, Origin: config.Issuer.String(), Approve: true, Network: "192.0.2.1"})
			if mode == "valid-age" {
				if err != nil || out.Outcome != oauth.AuthorizationRedirect {
					t.Fatal("current original policy control denied", err)
				}
				return
			}
			if mode == "historical" || mode == "unknown" {
				if err != nil || out.Outcome != oauth.AuthorizationHistorical && out.Outcome != oauth.AuthorizationUnknown || out.RedirectURI != "" || out.State != "" {
					t.Fatal("metadata-only result changed classification or retained redirect", err)
				}
			} else {
				want := oauth.ErrLoginRequired
				if mode == "missing-policy" || mode == "changed-intent" {
					want = oauth.ErrUnavailable
				}
				if !errors.Is(err, want) {
					t.Fatal("adapter bypassed original observed authentication policy/deadline", err)
				}
			}
			if _, err := out.Code.Reveal(); err == nil {
				t.Fatal("denied or historical policy result delivered code")
			}
		})
	}
}

func TestAuthorizationDeliveryExpiryRetainsOnlyValidKnownCorrelation(t *testing.T) {
	for _, mode := range []string{"consent-expired", "fresh-expired", "code-expired", "missing-continuation", "both-tokens", "zero-expiry", "overlong-expiry", "unaware-expired"} {
		t.Run(mode, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			config := coreConfig(t, now)
			clockNow := now
			config.Clock = clockFunc(func() time.Time { return clockNow })
			request := coreAuthorization()
			var extension oauth.OIDCExtension
			if mode == "fresh-expired" || mode == "unaware-expired" {
				config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
				config.Clients[0].Scopes = append(config.Clients[0].Scopes, "openid")
				request.Scopes = append(request.Scopes, "openid")
				request.Prompt = "login"
				extension = subjectExtension{validate: func(oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error) {
					return oauth.OIDCAuthorizationProjection{Accepted: true, Authentication: oauth.OIDCAuthenticationFresh}, nil
				}}
			}
			commandID, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			response := oauth.AuthorizeResult{Outcome: oauth.ConsentRequired, CommandID: commandID, Request: request, ExpiresAt: now.Add(time.Second)}
			response.Continuation, err = oauth.NewToken()
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "fresh-expired":
				response.Outcome = oauth.FreshAuthenticationRequired
			case "code-expired":
				response.Outcome = oauth.AuthorizationRedirect
				response.Code, response.Continuation = response.Continuation, oauth.Token{}
			case "missing-continuation":
				response.Continuation = oauth.Token{}
			case "both-tokens":
				response.Code = response.Continuation
			case "zero-expiry":
				response.ExpiresAt = time.Time{}
			case "overlong-expiry":
				response.ExpiresAt = now.Add(2 * time.Minute)
			case "unaware-expired":
				response.Request = oauth.AuthorizationRequest{}
			}
			var store oauth.Store = authorizationStore{call: func(context.Context, oauth.AuthorizationCommand) (oauth.AuthorizeResult, error) {
				clockNow = now.Add(2 * time.Second)
				return response, nil
			}}
			if mode == "code-expired" {
				store = authenticationContinuationStore{call: func(context.Context, oauth.ContinuationCommand) (oauth.AuthorizeResult, error) {
					clockNow = now.Add(2 * time.Second)
					return response, nil
				}}
			}
			service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store, OIDC: extension})
			if err != nil {
				t.Fatal(err)
			}
			var out oauth.AuthorizeResult
			if mode == "code-expired" {
				continuation, _ := oauth.NewToken()
				wire, _ := continuation.Reveal()
				csrf, _ := session.NewCSRFToken()
				out, err = service.Continue(context.Background(), oauth.ContinueRequest{TenantID: "tenant", Session: bearer, CSRF: csrf, ClientID: request.ClientID, Continuation: wire, Origin: config.Issuer.String(), Approve: true, Network: "192.0.2.1"})
			} else {
				out, err = service.Authorize(context.Background(), oauth.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: request, Network: "192.0.2.1"})
			}
			if !errors.Is(err, oauth.ErrUnavailable) || out.RedirectURI != "" || out.State != "" || out.Issuer.String() != "" || !out.ExpiresAt.IsZero() || out.Request.ClientID != "" {
				t.Fatal("expired or malformed delivery did not remain metadata-only", err)
			}
			known := mode == "consent-expired" || mode == "fresh-expired" || mode == "code-expired"
			if known && (out.Outcome != oauth.AuthorizationHistorical || out.CommandID != commandID) || !known && (out.Outcome != 0 || out.CommandID != "") {
				t.Fatal("delivery confused known expiry with an invalid/unaware adapter projection")
			}
			if _, err := out.Code.Reveal(); err == nil {
				t.Fatal("suppressed delivery revealed code")
			}
			if _, err := out.Continuation.Reveal(); err == nil {
				t.Fatal("suppressed delivery revealed continuation")
			}
		})
	}
}
