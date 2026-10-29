package oauthserver_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestManagedPublicOIDCSafePagePreservesMinimalRegistration(t *testing.T) {
	c := coreConfig(t, time.Now())
	client := c.Clients[0]
	client.ID = "managed.abcdefghijklmnopqrstuw"
	client.Scopes = []string{"openid"}
	page, err := oauth.NewClientListPage([]oauth.Client{client})
	if err != nil {
		t.Fatal("minimal managed public OIDC registration unavailable to safe reads", err)
	}
	items := page.Items()
	if len(items) != 1 || items[0].ID != client.ID || !items[0].Public || items[0].AuthenticationMethod != "none" || items[0].SubjectRegistration != nil || !slices.Equal(items[0].Scopes, []string{"openid"}) {
		t.Fatal("safe metadata changed minimal public OIDC registration")
	}
	items[0].Scopes[0] = "email"
	if !slices.Equal(page.Items()[0].Scopes, []string{"openid"}) {
		t.Fatal("safe OIDC page aliases caller scopes")
	}
}

func TestManagedPublicOIDCSafePageRejectsUnselectedClasses(t *testing.T) {
	c := coreConfig(t, time.Now())
	for _, variant := range []string{"extra-claim", "mixed-oauth", "device"} {
		t.Run(variant, func(t *testing.T) {
			client := c.Clients[0]
			client.ID = "managed.abcdefghijklmnopqrstuw"
			client.Scopes = []string{"openid"}
			switch variant {
			case "extra-claim":
				client.Scopes = []string{"openid", "email"}
			case "mixed-oauth":
				client.Scopes = []string{"openid", "identity:read"}
			case "device":
				client.DeviceAuthorization = true
			}
			if _, err := oauth.NewClientListPage([]oauth.Client{client}); err == nil {
				t.Fatal("safe read selected unsupported managed OIDC variant")
			}
		})
	}
}

type managedOIDCTestStore struct {
	readingClientStore
	client       oauth.Client
	authorize    func(context.Context, oauth.AuthorizationCommand) (oauth.AuthorizeResult, error)
	token        func(context.Context, oauth.TokenCommand) (oauth.TokenResult, error)
	continuation func(context.Context, oauth.ContinuationCommand) (oauth.AuthorizeResult, error)
}

func (s managedOIDCTestStore) CurrentClient(context.Context, string) (oauth.Client, error) {
	return s.client, nil
}

func (s managedOIDCTestStore) Authorize(ctx context.Context, c oauth.AuthorizationCommand) (oauth.AuthorizeResult, error) {
	return s.authorize(ctx, c)
}

func (s managedOIDCTestStore) AuthenticateCurrentClient(context.Context, oauth.Client, oauth.ClientAuthentication) error {
	return nil
}

func (s managedOIDCTestStore) Token(ctx context.Context, c oauth.TokenCommand) (oauth.TokenResult, error) {
	return s.token(ctx, c)
}

func (s managedOIDCTestStore) Continue(ctx context.Context, c oauth.ContinuationCommand) (oauth.AuthorizeResult, error) {
	return s.continuation(ctx, c)
}

func TestManagedPublicOIDCSelectionOwnsCreateReadAndAuthorization(t *testing.T) {
	testManagedOIDCSelectionOwnsCreateReadAndAuthorization(t, true)
}

func testManagedOIDCSelectionOwnsCreateReadAndAuthorization(t *testing.T, public bool) {
	t.Helper()
	for _, variant := range []string{"selected", "default", "other-class", "uncomposed"} {
		t.Run(variant, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			c := coreConfig(t, now)
			c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
			client := c.Clients[0]
			client.ID, client.Scopes = "managed.abcdefghijklmnopqrstuw", []string{"openid"}
			client.Public = public
			if !public {
				client.AuthenticationMethod = "client_secret_basic"
			}
			selectedPublic, selectedConfidential := public, !public
			switch variant {
			case "default":
				selectedPublic, selectedConfidential = false, false
			case "other-class":
				selectedPublic, selectedConfidential = !public, public
			}
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, PublicClients: true, PublicOIDC: selectedPublic, ConfidentialOIDC: selectedConfidential}
			store := managedOIDCTestStore{client: client}
			store.call = func(_ context.Context, e oauth.ClientManagementExecution) (oauth.ClientManagementResult, error) {
				if e.ValidateAt(now) != nil || e.Request.Public != public || !slices.Equal(e.Request.Scopes, []string{"openid"}) {
					t.Fatal("creation lost exact OIDC client class or original custody")
				}
				secret, _ := oauth.NewToken()
				return oauth.ClientManagementResult{Client: client, Secret: secret, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}, nil
			}
			store.get = func(context.Context, oauth.ClientReadExecution) (oauth.ClientGetResult, error) {
				return oauth.ClientGetResult{Client: client}, nil
			}
			store.list = func(context.Context, oauth.ClientReadExecution) (oauth.ClientListResult, error) {
				page, err := oauth.NewClientListPage([]oauth.Client{client})
				return oauth.ClientListResult{Page: page}, err
			}
			store.authorize = func(_ context.Context, command oauth.AuthorizationCommand) (oauth.AuthorizeResult, error) {
				if command.Client.ID != client.ID || command.OIDC == nil || !slices.Equal(command.Request.Scopes, []string{"openid"}) || command.Request.Nonce != "original-nonce" {
					t.Fatal("managed authorization lost actual child/client/scope/nonce")
				}
				continuation, _ := oauth.NewToken()
				return oauth.AuthorizeResult{Outcome: oauth.ConsentRequired, Continuation: continuation, ExpiresAt: now.Add(c.ContinuationTTL)}, nil
			}
			deps := oauth.Dependencies{Sessions: sessions, Store: store, Clients: store}
			if variant != "uncomposed" {
				deps.OIDC = subjectExtension{validate: func(oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error) {
					return oauth.OIDCAuthorizationProjection{Accepted: true}, nil
				}}
			}
			service, err := oauth.NewService(c, deps)
			if err != nil {
				t.Fatal(err)
			}
			csrf, _ := session.NewCSRFToken()
			key, _ := identity.NewIdempotencyKey([]byte("managed-oidc-create"))
			created, createErr := service.ClientCreate(context.Background(), oauth.ClientManagementRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Public: public, Redirects: client.Redirects, Scopes: []string{"openid"}})
			read := oauth.ClientReadRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, ClientID: client.ID}
			got, getErr := service.ClientGet(context.Background(), read)
			read.ClientID, read.Limit = "", 1
			listed, listErr := service.ClientList(context.Background(), read)
			request := coreAuthorization()
			request.ClientID, request.Scopes, request.Nonce = client.ID, []string{"openid"}, "original-nonce"
			authorized, authErr := service.Authorize(context.Background(), oauth.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: request, Network: "192.0.2.1"})
			if variant != "selected" {
				if createErr == nil || getErr == nil || listErr == nil || authErr == nil || created.Client.ID != "" || got.Client.ID != "" || len(listed.Page.Items()) != 0 || authorized.Outcome != 0 {
					t.Fatal("unselected managed OIDC escaped default-deny boundary", createErr, getErr, listErr, authErr)
				}
				return
			}
			if createErr != nil || getErr != nil || listErr != nil || authErr != nil || created.Client.ID != client.ID || got.Client.ID != client.ID || len(listed.Page.Items()) != 1 || authorized.Outcome != oauth.ConsentRequired {
				t.Fatal("selected managed OIDC public boundary disconnected", createErr, getErr, listErr, authErr)
			}
			if _, err := created.Secret.Reveal(); public != (err != nil) {
				t.Fatal("OIDC secret disclosure disagrees with selected client class")
			}
		})
	}
}

func TestManagedPublicOIDCCeilingDoesNotBroadenOAuthOrIdentityScopes(t *testing.T) {
	_, bearer, now, _ := coreSessionFixture(t)
	c := coreConfig(t, now)
	c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "email"})
	client := c.Clients[0]
	c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, PublicClients: true, PublicOIDC: true, DeviceAuthorization: true}
	validated, err := c.Validated()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(validated.ManagedClients.Scopes.Scopes(), c.Scopes.Scopes()) {
		t.Fatal("OIDC selection rewrote OAuth management ceiling")
	}
	csrf, _ := session.NewCSRFToken()
	key, _ := identity.NewIdempotencyKey([]byte("managed-oidc-ceiling"))
	base := oauth.ClientManagementRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Public: true, Redirects: client.Redirects}
	for _, tc := range []struct {
		name                    string
		public, device, allowed bool
		scopes                  []string
	}{
		{"openid", true, false, true, []string{"openid"}},
		{"confidential-oauth", false, false, true, []string{"identity:read"}},
		{"public-oauth", true, false, true, []string{"identity:read"}},
		{"confidential-oidc", false, false, false, []string{"openid"}},
		{"device-oidc", true, true, false, []string{"openid"}},
		{"email-only", true, false, false, []string{"email"}},
		{"extra-claim", true, false, false, []string{"openid", "email"}},
		{"mixed-oauth", true, false, false, []string{"openid", "identity:read"}},
		{"duplicate", true, false, false, []string{"openid", "openid"}},
		{"unknown", true, false, false, []string{"unknown"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			r.Public, r.DeviceAuthorization, r.Scopes = tc.public, tc.device, tc.scopes
			_, err := oauth.ValidateClientManagementRequest(r, false, *validated.ManagedClients, c.Issuer)
			if tc.allowed != (err == nil) || !tc.allowed && !errors.Is(err, oauth.ErrInvalidScope) {
				t.Fatal("registration scope selection differs from finite ceiling", err)
			}
		})
	}
	for _, variant := range []string{"no-public", "no-catalog"} {
		invalid := c
		policy := *c.ManagedClients
		invalid.ManagedClients = &policy
		if variant == "no-public" {
			policy.PublicClients = false
		} else {
			invalid.OIDCScopes = oauth.ScopeCatalog{}
		}
		if _, err := invalid.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("OIDC management accepted absent configured dependency", variant, err)
		}
	}
}

type managedOIDCUserInfoStore struct {
	managedOIDCTestStore
	source oauth.OIDCClaimsInput
}

func (s managedOIDCUserInfoStore) UserInfo(context.Context, oauth.UserInfoCommand) (oauth.OIDCClaimsInput, error) {
	return s.source, nil
}

func TestManagedPublicOIDCOriginalCoreSupportsChildUserInfoSource(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	c := coreConfig(t, now)
	c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
	client := c.Clients[0]
	client.ID, client.Scopes = "managed.abcdefghijklmnopqrstuw", []string{"openid"}
	c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, PublicClients: true, PublicOIDC: true}
	source := oauth.OIDCClaimsInput{Issuer: c.Issuer, Environment: c.Environment, TenantID: "tenant", UserID: "user", ClientID: client.ID, ExpectedSubject: "native-subject", Scopes: []string{"openid"}, UserInfo: true, IssuedAt: now, ExpiresAt: now.Add(time.Minute), AuthorityExpiresAt: now.Add(20 * time.Second)}
	store := managedOIDCUserInfoStore{managedOIDCTestStore: managedOIDCTestStore{client: client}, source: source}
	// The real child is constructed with this original core, then WithOIDC
	// returns a separate service. Native source custody has no claim semantics.
	core, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
	if err != nil {
		t.Fatal(err)
	}
	access, _ := oauth.NewToken()
	wire, _ := access.Reveal()
	got, err := core.UserInfoSource(context.Background(), oauth.UserInfoRequest{ClientID: client.ID, AccessToken: wire})
	if err != nil || got.ExpectedSubject != source.ExpectedSubject || got.UserID != source.UserID || !got.AuthorityExpiresAt.Equal(source.AuthorityExpiresAt) {
		t.Fatal("pre-WithOIDC core denied actual child native UserInfo source", err)
	}
}

func TestManagedPublicOIDCUncomposedTokenNeverConsumesCodeOrRefresh(t *testing.T) {
	for _, grant := range []oauth.GrantType{oauth.AuthorizationCodeGrant, oauth.RefreshTokenGrant} {
		for _, composed := range []bool{false, true} {
			t.Run(string(grant)+map[bool]string{false: "/uncomposed", true: "/composed"}[composed], func(t *testing.T) {
				sessions, _, now, _ := coreSessionFixture(t)
				c := coreConfig(t, now)
				c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
				client := c.Clients[0]
				client.ID, client.Scopes = "managed.abcdefghijklmnopqrstuw", []string{"openid"}
				c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, PublicClients: true, PublicOIDC: true}
				consumed := false
				store := managedOIDCTestStore{client: client, token: func(context.Context, oauth.TokenCommand) (oauth.TokenResult, error) {
					consumed = true
					return oauth.TokenResult{}, oauth.ErrUnavailable
				}}
				deps := oauth.Dependencies{Sessions: sessions, Store: store, Clients: store}
				if composed {
					deps.OIDC = subjectExtension{}
				}
				core, err := oauth.NewService(c, deps)
				if err != nil {
					t.Fatal(err)
				}
				credential, _ := oauth.NewToken()
				wire, _ := credential.Reveal()
				r := oauth.TokenRequest{GrantType: grant, ClientID: client.ID, Network: "192.0.2.1"}
				if grant == oauth.AuthorizationCodeGrant {
					r.Code, r.CodeVerifier, r.RedirectURI = wire, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", client.Redirects[0]
				} else {
					r.RefreshToken = wire
				}
				_, err = core.Token(context.Background(), r)
				if consumed != composed || !composed && !errors.Is(err, oauth.ErrAccessDenied) || composed && !errors.Is(err, oauth.ErrUnavailable) {
					t.Fatal("uncomposed managed OIDC token mutated native custody", err)
				}
			})
		}
	}
}

func TestManagedPublicOIDCUncomposedContinuationNeverCommitsApproval(t *testing.T) {
	for _, composed := range []bool{false, true} {
		t.Run(map[bool]string{false: "uncomposed", true: "composed"}[composed], func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			c := coreConfig(t, now)
			c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
			client := c.Clients[0]
			client.ID, client.Scopes = "managed.abcdefghijklmnopqrstuw", []string{"openid"}
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, PublicClients: true, PublicOIDC: true}
			consumed := false
			store := managedOIDCTestStore{client: client, continuation: func(_ context.Context, command oauth.ContinuationCommand) (oauth.AuthorizeResult, error) {
				consumed = true
				if command.Client.ID != client.ID || !command.Request.Approve || command.Request.Scopes != nil {
					t.Fatal("continuation lost actual client/approval/original-scope intent")
				}
				request := coreAuthorization()
				request.ClientID, request.Scopes, request.Nonce = client.ID, []string{"openid"}, "original-nonce"
				code, _ := oauth.NewToken()
				return oauth.AuthorizeResult{Outcome: oauth.AuthorizationRedirect, Code: code, Request: request, ExpiresAt: now.Add(c.CodeTTL)}, nil
			}}
			deps := oauth.Dependencies{Sessions: sessions, Store: store, Clients: store}
			if composed {
				deps.OIDC = subjectExtension{}
			}
			core, err := oauth.NewService(c, deps)
			if err != nil {
				t.Fatal(err)
			}
			continuation, _ := oauth.NewToken()
			wire, _ := continuation.Reveal()
			csrf, _ := session.NewCSRFToken()
			out, err := core.Continue(context.Background(), oauth.ContinueRequest{TenantID: "tenant", Session: bearer, CSRF: csrf, ClientID: client.ID, Continuation: wire, Origin: c.Issuer.String(), Network: "192.0.2.1", Approve: true})
			if !composed {
				if consumed || err == nil || out.Outcome != 0 || out.Code != (oauth.Token{}) || out.Continuation != (oauth.Token{}) {
					t.Fatal("uncomposed continuation committed native approval before denial", err)
				}
				return
			}
			if !consumed || err != nil || out.Outcome != oauth.AuthorizationRedirect || out.Request.Nonce != "original-nonce" {
				t.Fatal("composed minimal OIDC continuation control failed", err)
			}
			if _, err := out.Location(); err != nil {
				t.Fatal("composed continuation did not deliver its code redirect", err)
			}
		})
	}
}
