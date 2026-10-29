package oauthserver_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestManagedWorkloadCreateRetainsGenuineManagerAndExactMachinePolicy(t *testing.T) {
	sessions, bearer, now, _ := coreSessionFixture(t)
	c := coreConfig(t, now)
	owner, _ := oauth.NewPlatformOwner("platform")
	w, _ := oauth.NewWorkload("tenant", "service-account", 30*time.Second)
	c.ManagedClients = &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes, Workloads: []*oauth.Workload{w}}
	csrf, _ := session.NewCSRFToken()
	key, _ := identity.NewIdempotencyKey([]byte("managed-workload-original"))
	r := oauth.ClientManagementRequest{Owner: owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Scopes: []string{"identity:read"}, Workload: w}
	calls := 0
	store := managedStore{call: func(_ context.Context, e oauth.ClientManagementExecution) (oauth.ClientManagementResult, error) {
		calls++
		if e.ValidateAt(now) != nil || e.Delete || e.Request.Workload == nil || e.Request.Workload.ID() != "service-account" || e.Request.Workload.TenantID() != "tenant" || e.Request.Workload.AccessTTL() != 30*time.Second {
			t.Fatal("original manager or machine binding lost")
		}
		other, _ := oauth.NewWorkload("tenant", "other", time.Minute)
		*e.Request.Workload = *other
		secret, _ := oauth.NewToken()
		return oauth.ClientManagementResult{Secret: secret, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}, nil
	}}
	s, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		out, err := s.ClientCreate(context.Background(), r)
		if err != nil {
			t.Fatal("trusted managed machine create denied", err)
		}
		if _, err := out.Secret.Reveal(); err != nil {
			t.Fatal("fresh committed creation withheld reveal", err)
		}
		if w.ID() != "service-account" {
			t.Fatal("adapter could mutate caller/startup policy")
		}
	}
	for _, mutate := range []func(*oauth.ClientManagementRequest){
		func(r *oauth.ClientManagementRequest) { r.Public = true },
		func(r *oauth.ClientManagementRequest) { r.DeviceAuthorization = true },
		func(r *oauth.ClientManagementRequest) { r.Redirects = []string{"https://client.example/cb"} },
		func(r *oauth.ClientManagementRequest) { r.PostLogoutRedirects = []string{"https://client.example/cb"} },
		func(r *oauth.ClientManagementRequest) {
			r.Workload, _ = oauth.NewWorkload("other", "service-account", 30*time.Second)
		},
		func(r *oauth.ClientManagementRequest) {
			r.Workload, _ = oauth.NewWorkload("tenant", "other", 30*time.Second)
		},
		func(r *oauth.ClientManagementRequest) {
			r.Workload, _ = oauth.NewWorkload("tenant", "service-account", time.Minute)
		},
		func(r *oauth.ClientManagementRequest) { r.Scopes = []string{"openid"} },
		func(r *oauth.ClientManagementRequest) { r.TenantID = "other" },
		func(r *oauth.ClientManagementRequest) { r.CSRF = session.CSRFToken{} },
	} {
		bad := r
		mutate(&bad)
		if _, err := s.ClientCreate(context.Background(), bad); err == nil {
			t.Fatal("unselected machine variant admitted")
		}
	}
	if calls != 2 {
		t.Fatal("denied registration reached manager")
	}
}

func TestManagedWorkloadComposesOnlyWithExplicitGlobalWorkloadExchange(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "unselected", true: "selected"}[enabled], func(t *testing.T) {
			sessions, _, _, _ := coreSessionFixture(t)
			c, staticBasic := workloadCoreConfig(t)
			w, _ := oauth.NewWorkload("tenant", "managed-worker", 30*time.Second)
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: c.Clients[0].Owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes, Workloads: []*oauth.Workload{w}}
			if enabled {
				c.WorkloadExchange = &oauth.WorkloadExchangePolicy{MaximumDepth: 4, ClockUncertainty: time.Second}
			}
			managed := oauth.Client{ID: "managed.abcdefghijklmnopqrstuw", Owner: c.Clients[0].Owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: c.Resource, Scopes: []string{"identity:read"}, Workload: w}
			managedBasic, _ := oauth.ParseClientAuthentication([]string{clientBasicHeader(managed.ID, strings.Repeat("A", 43))})
			calls := 0
			outputShape := "access"
			store := managedWorkloadTokenStore{client: managed, token: func(_ context.Context, command oauth.TokenCommand) (oauth.TokenResult, error) {
				calls++
				if command.Client.Workload == nil || command.Request.GrantType != oauth.TokenExchangeGrant || command.Request.SubjectTokenType != oauth.AccessTokenType || command.Request.Resource != command.Client.Resource || !slices.Equal(command.Request.Scopes, []string{"identity:read"}) {
					t.Fatal("exchange lost original client/type/resource/scope selection")
				}
				access, _ := oauth.NewToken()
				out := oauth.TokenResult{Outcome: identity.CommitOutcomeCommitted, AccessToken: access, Resource: c.Resource, Scopes: []string{"identity:read"}, ExpiresAt: c.Clock.Now().Add(10 * time.Second), IssuedTokenType: oauth.AccessTokenType}
				switch outputShape {
				case "resource":
					out.Resource = "https://foreign.example"
				case "scope":
					out.Scopes = []string{"identity:write"}
				case "refresh":
					out.RefreshToken, _ = oauth.NewToken()
				case "id":
					out.IDToken, _ = oauth.ParseIDToken("a.b.c")
				}
				return out, nil
			}}
			s, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
			if err != nil {
				t.Fatal(err)
			}
			for _, caller := range []struct {
				client oauth.Client
				basic  oauth.ClientAuthentication
			}{{c.Clients[0], staticBasic}, {managed, managedBasic}} {
				r := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: caller.client.ID, ClientAuthentication: caller.basic, SubjectToken: strings.Repeat("A", 43), SubjectTokenType: oauth.AccessTokenType, Resource: c.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.1"}
				before := calls
				out, err := s.Token(context.Background(), r)
				if !enabled {
					if !errors.Is(err, oauth.ErrUnsupportedGrant) || calls != before || out.AccessToken != (oauth.Token{}) {
						t.Fatal("managed selection implicitly enabled global exchange", err)
					}
					continue
				}
				if err != nil || calls != before+1 || out.IssuedTokenType != oauth.AccessTokenType || out.AccessToken == (oauth.Token{}) || out.RefreshToken != (oauth.Token{}) || out.IDToken != (oauth.IDToken{}) {
					t.Fatal("explicit global access-to-access exchange did not compose", err)
				}
				before = calls
				for _, mutate := range []func(*oauth.TokenRequest){
					func(r *oauth.TokenRequest) { r.Resource = "https://foreign.example" },
					func(r *oauth.TokenRequest) { r.Scopes = []string{"identity:write"} },
					func(r *oauth.TokenRequest) { r.RequestedTokenType = "urn:ietf:params:oauth:token-type:id_token" },
				} {
					bad := r
					mutate(&bad)
					if _, err := s.Token(context.Background(), bad); err == nil || calls != before {
						t.Fatal("expanded exchange selection reached adapter")
					}
				}
				for _, shape := range []string{"resource", "scope", "refresh", "id"} {
					outputShape = shape
					out, err := s.Token(context.Background(), r)
					if err == nil || out.AccessToken != (oauth.Token{}) || out.RefreshToken != (oauth.Token{}) || out.IDToken != (oauth.IDToken{}) {
						t.Fatal("expanded/non-access exchange output escaped", shape, err)
					}
				}
				outputShape = "access"
			}
		})
	}
}

type managedWorkloadTokenStore struct {
	managedStore
	client oauth.Client
	token  func(context.Context, oauth.TokenCommand) (oauth.TokenResult, error)
}

func (s managedWorkloadTokenStore) CurrentClient(context.Context, string) (oauth.Client, error) {
	return s.client, nil
}
func (managedWorkloadTokenStore) AuthenticateCurrentClient(context.Context, oauth.Client, oauth.ClientAuthentication) error {
	return nil // Only the deliberate native boundary is replaced in this core test.
}
func (s managedWorkloadTokenStore) Token(ctx context.Context, c oauth.TokenCommand) (oauth.TokenResult, error) {
	return s.token(ctx, c)
}

func TestManagedWorkloadCurrentRegistryIssuesOnlySelectedAccessProfile(t *testing.T) {
	for _, mode := range []string{"access", "refresh-output", "id-output", "foreign-binding", "foreign-resource", "foreign-scope"} {
		t.Run(mode, func(t *testing.T) {
			sessions, _, now, _ := coreSessionFixture(t)
			c := coreConfig(t, now)
			owner, _ := oauth.NewPlatformOwner("platform")
			w, _ := oauth.NewWorkload("tenant", "service-account", 30*time.Second)
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes, Workloads: []*oauth.Workload{w}}
			c.Discovery = discoveryEndpoints()
			client := oauth.Client{ID: "managed.test", Owner: owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: c.Resource, Scopes: []string{"identity:read"}, Workload: w}
			switch mode {
			case "foreign-binding":
				client.Workload, _ = oauth.NewWorkload("tenant", "other", 30*time.Second)
			case "foreign-resource":
				client.Resource = "https://foreign.example"
			case "foreign-scope":
				client.Scopes = []string{"identity:foreign"}
			}
			called := false
			store := managedWorkloadTokenStore{client: client, token: func(_ context.Context, command oauth.TokenCommand) (oauth.TokenResult, error) {
				called = true
				if command.Client.Workload.ID() != "service-account" || command.Client.Workload.TenantID() != "tenant" {
					t.Fatal("registry lost original machine authority")
				}
				access, _ := oauth.NewToken()
				out := oauth.TokenResult{Outcome: identity.CommitOutcomeCommitted, AccessToken: access, Resource: c.Resource, Scopes: []string{"identity:read"}, ExpiresAt: now.Add(30 * time.Second)}
				if mode == "refresh-output" {
					out.RefreshToken, _ = oauth.NewToken()
				}
				if mode == "id-output" {
					out.IDToken, _ = oauth.ParseIDToken(strings.Repeat("A", 16) + "." + strings.Repeat("A", 16) + "." + strings.Repeat("A", 86))
				}
				return out, nil
			}}
			s, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := s.DiscoveryOauth(context.Background(), oauth.DiscoveryOauthRequest{})
			if err != nil || !slices.Contains(metadata.Metadata.GrantTypesSupported, "client_credentials") {
				t.Fatal("managed machine capability absent", err)
			}
			basic, _ := oauth.ParseClientAuthentication([]string{clientBasicHeader(client.ID, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")})
			out, err := s.Token(context.Background(), oauth.TokenRequest{GrantType: oauth.ClientCredentialsGrant, ClientID: client.ID, ClientAuthentication: basic, Network: "192.0.2.1"})
			if mode == "access" {
				if err != nil || !called {
					t.Fatal("current managed machine could not issue", err)
				}
				if _, err := out.AccessToken.Reveal(); err != nil {
					t.Fatal("missing committed access", err)
				}
			} else if err == nil || out.AccessToken != (oauth.Token{}) {
				t.Fatal("unselected authority/output admitted", err)
			}
			for _, grant := range []oauth.GrantType{oauth.AuthorizationCodeGrant, oauth.RefreshTokenGrant} {
				if _, err := s.Token(context.Background(), oauth.TokenRequest{GrantType: grant, ClientID: client.ID, ClientAuthentication: basic, Network: "192.0.2.1"}); err == nil {
					t.Fatal("machine accepted human grant")
				}
			}
		})
	}
}

func TestManagedWorkloadPolicyRejectsInvalidAndConflictingEntries(t *testing.T) {
	for _, mode := range []string{"nil", "zero", "foreign-tenant", "duplicate", "conflicting-ttl", "overlong", "unbounded"} {
		t.Run(mode, func(t *testing.T) {
			c := coreConfig(t, time.Now().UTC())
			owner, _ := oauth.NewPlatformOwner("platform")
			w, _ := oauth.NewWorkload("tenant", "service-account", time.Second)
			p := &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes, Workloads: []*oauth.Workload{w}}
			switch mode {
			case "nil":
				p.Workloads = []*oauth.Workload{nil}
			case "zero":
				p.Workloads = []*oauth.Workload{{}}
			case "foreign-tenant":
				p.Workloads[0], _ = oauth.NewWorkload("other", "service-account", time.Second)
			case "duplicate":
				p.Workloads = append(p.Workloads, w)
			case "conflicting-ttl":
				other, _ := oauth.NewWorkload("tenant", "service-account", 2*time.Second)
				p.Workloads = append(p.Workloads, other)
			case "overlong":
				c.AccessTTL = time.Second
				p.Workloads[0], _ = oauth.NewWorkload("tenant", "service-account", 2*time.Second)
			case "unbounded":
				p.Workloads = make([]*oauth.Workload, 65)
			}
			c.ManagedClients = p
			if _, err := c.Validated(); err == nil {
				t.Fatal("unsafe trusted workload allowlist admitted")
			}
		})
	}
}

func TestManagedWorkloadValidationSnapshotsAndExplicitlyOptsIn(t *testing.T) {
	_, bearer, now, _ := coreSessionFixture(t)
	c := coreConfig(t, now)
	owner, _ := oauth.NewPlatformOwner("platform")
	w, _ := oauth.NewWorkload("tenant", "service-account", 30*time.Second)
	p := oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes, Workloads: []*oauth.Workload{w}}
	c.ManagedClients = &p
	owned, err := c.Validated()
	if err != nil {
		t.Fatal(err)
	}
	csrf, _ := session.NewCSRFToken()
	key, _ := identity.NewIdempotencyKey([]byte("explicit-machine-adapter"))
	r := oauth.ClientManagementRequest{Owner: owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Scopes: []string{"identity:read"}, Workload: w}
	validated, err := oauth.ValidateWorkloadClientManagementRequest(r, *owned.ManagedClients, c.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := oauth.NewWorkload("tenant", "other", time.Minute)
	*w = *other
	if validated.Workload.ID() != "service-account" || owned.ManagedClients.Workloads[0].ID() != "service-account" {
		t.Fatal("whole-value replacement changed admitted policy")
	}
	r.Workload = validated.Workload
	if _, err := oauth.ValidateClientManagementRequest(r, false, *owned.ManagedClients, c.Issuer); err == nil {
		t.Fatal("older adapter silently discarded workload")
	}
	if _, err := oauth.ValidateClientManagementRequest(r, true, *owned.ManagedClients, c.Issuer); err == nil {
		t.Fatal("delete accepted workload replacement")
	}
	r.Workload = nil
	if _, err := oauth.ValidateWorkloadClientManagementRequest(r, *owned.ManagedClients, c.Issuer); err == nil {
		t.Fatal("workload validator admitted browser profile")
	}
}

func TestManagedWorkloadPrivateGetAndListUseExistingSelectedOwner(t *testing.T) {
	for _, selected := range []bool{false, true} {
		t.Run(map[bool]string{false: "unselected", true: "selected"}[selected], func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			c := coreConfig(t, now)
			owner, _ := oauth.NewPlatformOwner("platform")
			w, _ := oauth.NewWorkload("tenant", "service-account", 30*time.Second)
			p := &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes}
			if selected {
				p.Workloads = []*oauth.Workload{w}
			}
			c.ManagedClients = p
			machine := oauth.Client{ID: "managed.abcdefghijklmnopqrstuw", Owner: owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: c.Resource, Scopes: []string{"identity:read"}, Workload: w}
			store := readingClientStore{get: func(_ context.Context, e oauth.ClientReadExecution) (oauth.ClientGetResult, error) {
				if e.ValidateAt(now) != nil {
					t.Fatal("read lost original human manager custody")
				}
				return oauth.ClientGetResult{Client: machine}, nil
			}, list: func(_ context.Context, e oauth.ClientReadExecution) (oauth.ClientListResult, error) {
				if e.ValidateAt(now) != nil {
					t.Fatal("list lost original human manager custody")
				}
				page, err := oauth.NewWorkloadClientListPage([]oauth.Client{machine})
				return oauth.ClientListResult{Page: page}, err
			}}
			s, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
			if err != nil {
				t.Fatal(err)
			}
			r := oauth.ClientReadRequest{Owner: owner, TenantID: "tenant", Session: bearer, ClientID: machine.ID}
			got, err := s.ClientGet(context.Background(), r)
			if selected {
				if err != nil || got.Client.Workload == nil || got.Client.Workload.ID() != "service-account" {
					t.Fatal("selected manager cannot account for machine registration", err)
				}
			} else if err == nil {
				t.Fatal("unselected manager observed machine metadata")
			}
			r.ClientID, r.Limit = "", 100
			listed, err := s.ClientList(context.Background(), r)
			if !selected {
				if err == nil || len(listed.Page.Items()) != 0 {
					t.Fatal("unselected composition disclosed machine page")
				}
				return
			}
			items := listed.Page.Items()
			if err != nil || len(items) != 1 || items[0].Workload.ID() != "service-account" {
				t.Fatal("selected manager machine inventory unavailable", err)
			}
			other, _ := oauth.NewWorkload("tenant", "other", time.Minute)
			*items[0].Workload = *other
			*got.Client.Workload = *other
			if listed.Page.Items()[0].Workload.ID() != "service-account" || w.ID() != "service-account" {
				t.Fatal("private metadata aliases stored policy")
			}
		})
	}
}

func TestManagedWorkloadPagePreservesHumanOnlyDefault(t *testing.T) {
	c := coreConfig(t, time.Now())
	w, _ := oauth.NewWorkload("tenant", "service-account", 30*time.Second)
	machine := oauth.Client{ID: "managed.abcdefghijklmnopqrstuw", Owner: c.Clients[0].Owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: c.Resource, Scopes: []string{"identity:read"}, Workload: w}
	if _, err := oauth.NewClientListPage([]oauth.Client{machine}); err == nil {
		t.Fatal("original human-only page constructor silently widened")
	}
	human := c.Clients[0]
	human.ID = "managed.bbcdefghijklmnopqrstuw"
	page, err := oauth.NewWorkloadClientListPage([]oauth.Client{machine, human})
	if err != nil || len(page.Items()) != 2 || page.Items()[0].Workload == nil || page.Items()[1].Workload != nil {
		t.Fatal("explicit mixed page lost distinct classes", err)
	}
	other, _ := oauth.NewWorkload("tenant", "other", time.Minute)
	*w = *other
	items := page.Items()
	if items[0].Workload.ID() != "service-account" {
		t.Fatal("page retained caller pointer")
	}
	*items[0].Workload = *other
	if page.Items()[0].Workload.ID() != "service-account" {
		t.Fatal("page exposed retained workload policy")
	}
}
