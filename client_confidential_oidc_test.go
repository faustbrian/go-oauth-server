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

func TestManagedConfidentialOIDCSelectionOwnsCreateReadAndAuthorization(t *testing.T) {
	testManagedOIDCSelectionOwnsCreateReadAndAuthorization(t, false)
}

func TestManagedConfidentialOIDCDoesNotSelectMetadataReplacement(t *testing.T) {
	_, bearer, now, _ := coreSessionFixture(t)
	c := coreConfig(t, now)
	c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
	client := c.Clients[0]
	policy := oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, ConfidentialOIDC: true}
	csrf, _ := session.NewCSRFToken()
	key, _ := identity.NewIdempotencyKey([]byte("confidential-oidc-update-denied"))
	r := oauth.ClientUpdateRequest{Management: oauth.ClientManagementRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, ClientID: "managed.abcdefghijklmnopqrstuw", Version: 1}, Redirects: client.Redirects, Scopes: []string{"openid"}}
	if _, err := oauth.ValidateClientUpdateRequest(r, policy, c.Issuer); !errors.Is(err, oauth.ErrInvalidScope) {
		t.Fatal("confidential OIDC creation selection also selected metadata replacement", err)
	}
	r.Scopes = []string{"identity:read"}
	if _, err := oauth.ValidateClientUpdateRequest(r, policy, c.Issuer); err != nil {
		t.Fatal("confidential OIDC selection disabled existing OAuth replacement", err)
	}
}

type confidentialOIDCUpdatingStore struct {
	updatingClientStore
	client     oauth.Client
	currentErr error
	onCurrent  func()
}

func (s confidentialOIDCUpdatingStore) CurrentClient(context.Context, string) (oauth.Client, error) {
	if s.onCurrent != nil {
		s.onCurrent()
	}
	return s.client, s.currentErr
}

func TestManagedConfidentialOIDCLeavesMissingClientRetryWithItsExistingOwner(t *testing.T) {
	for _, mode := range []string{"original-replay", "fresh-missing", "unavailable", "unknown", "expired", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			c := coreConfig(t, now)
			currentTime := now
			c.Clock = clockFunc(func() time.Time { return currentTime })
			c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
			client := c.Clients[0]
			client.ID = "managed.abcdefghijklmnopqrstuw"
			client.Public, client.AuthenticationMethod = false, "client_secret_basic"
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, ConfidentialOIDC: true}
			csrf, _ := session.NewCSRFToken()
			key, _ := identity.NewIdempotencyKey([]byte("original-deleted-oauth-update"))
			r := oauth.ClientUpdateRequest{Management: oauth.ClientManagementRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, ClientID: client.ID, Version: client.Version}, Redirects: client.Redirects, Scopes: []string{"identity:read"}}
			called := false
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store := confidentialOIDCUpdatingStore{currentErr: oauth.ErrInvalidClient, updatingClientStore: updatingClientStore{update: func(context.Context, oauth.ClientUpdateExecution) (oauth.ClientUpdateResult, error) {
				called = true
				if mode != "original-replay" {
					return oauth.ClientUpdateResult{}, oauth.ErrInvalidClient
				}
				result := client
				result.Version++
				result.Scopes = r.Scopes
				return oauth.ClientUpdateResult{Client: result, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted, Replayed: true}}, nil
			}}}
			switch mode {
			case "unavailable":
				store.currentErr = oauth.ErrUnavailable
			case "unknown":
				store.currentErr = errors.New("unexpected registry failure")
			case "expired":
				store.onCurrent = func() { currentTime = now.Add(20 * time.Second) }
			case "canceled":
				store.onCurrent = cancel
			}
			service, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.ClientUpdate(ctx, r)
			if mode == "original-replay" {
				if err != nil || !called || !out.Completion.Replayed || out.Completion.Outcome != identity.CommitOutcomeCommitted || out.Client.Version != client.Version+1 {
					t.Fatal("live-client admission stranded existing original update history", err)
				}
			} else if err == nil || out.Client.ID != "" || called != (mode == "fresh-missing") {
				t.Fatal("missing/unavailable admission bypassed existing update authority", err)
			}
		})
	}
}

func TestManagedConfidentialOIDCSourceCannotReachMetadataMutation(t *testing.T) {
	for _, originalOIDC := range []bool{false, true} {
		for _, composed := range []bool{false, true} {
			t.Run(map[bool]string{false: "oauth", true: "oidc"}[originalOIDC]+map[bool]string{false: "/uncomposed", true: "/composed"}[composed], func(t *testing.T) {
				sessions, bearer, now, _ := coreSessionFixture(t)
				c := coreConfig(t, now)
				c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
				client := c.Clients[0]
				client.ID = "managed.abcdefghijklmnopqrstuw"
				client.Public, client.AuthenticationMethod = false, "client_secret_basic"
				if originalOIDC {
					client.Scopes = []string{"openid"}
				}
				c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, ConfidentialOIDC: true}
				csrf, _ := session.NewCSRFToken()
				key, _ := identity.NewIdempotencyKey([]byte("confidential-oidc-original-update"))
				r := oauth.ClientUpdateRequest{Management: oauth.ClientManagementRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, ClientID: client.ID, Version: client.Version}, Redirects: client.Redirects, Scopes: []string{"identity:read"}}
				mutations := 0
				store := confidentialOIDCUpdatingStore{client: client, updatingClientStore: updatingClientStore{update: func(context.Context, oauth.ClientUpdateExecution) (oauth.ClientUpdateResult, error) {
					mutations++
					result := client
					result.Version++
					result.Scopes = r.Scopes
					return oauth.ClientUpdateResult{Client: result, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}, nil
				}}}
				deps := oauth.Dependencies{Sessions: sessions, Store: store, Clients: store}
				if composed {
					deps.OIDC = subjectExtension{}
				}
				service, err := oauth.NewService(c, deps)
				if err != nil {
					t.Fatal(err)
				}
				out, err := service.ClientUpdate(context.Background(), r)
				if originalOIDC {
					if !errors.Is(err, oauth.ErrAccessDenied) || mutations != 0 || out.Client.ID != "" || out.Completion.Outcome != identity.CommitOutcomeInvalid {
						t.Fatal("excluded original OIDC class reached metadata mutation", err)
					}
				} else if err != nil || mutations != 1 || out.Client.Version != client.Version+1 {
					t.Fatal("confidential OIDC selection broke existing OAuth metadata replacement", err)
				}
			})
		}
	}
}

func TestManagedConfidentialOIDCRequiresItsOwnScopeSelection(t *testing.T) {
	c := coreConfig(t, time.Now())
	c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "email"})
	client := c.Clients[0]
	c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, ConfidentialOIDC: true, DeviceAuthorization: true}
	validated, err := c.Validated()
	if err != nil {
		t.Fatal("confidential OIDC incorrectly requires public-client selection", err)
	}
	if !slices.Equal(validated.ManagedClients.Scopes.Scopes(), c.Scopes.Scopes()) {
		t.Fatal("confidential OIDC rewrote the OAuth management ceiling")
	}
	for _, tc := range []struct {
		name           string
		public, device bool
		scopes         []string
		allowed        bool
	}{
		{"minimal", false, false, []string{"openid"}, true},
		{"existing-oauth", false, false, []string{"identity:read"}, true},
		{"public", true, false, []string{"openid"}, false},
		{"device", false, true, []string{"openid"}, false},
		{"extra-claim", false, false, []string{"openid", "email"}, false},
		{"email-only", false, false, []string{"email"}, false},
		{"mixed-oauth", false, false, []string{"openid", "identity:read"}, false},
		{"duplicate", false, false, []string{"openid", "openid"}, false},
		{"unknown", false, false, []string{"unknown"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validated.ManagedClients.AllowsRegistrationScopes(tc.public, tc.device, tc.scopes) != tc.allowed {
				t.Fatal("confidential OIDC escaped its exact browser/scope class")
			}
		})
	}
	c.OIDCScopes = oauth.ScopeCatalog{}
	if _, err := c.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("confidential OIDC accepted missing configured child scope", err)
	}
}

func TestManagedConfidentialOIDCSafePagePreservesMinimalRegistration(t *testing.T) {
	c := coreConfig(t, time.Now())
	client := c.Clients[0]
	client.ID = "managed.abcdefghijklmnopqrstuw"
	client.Public, client.AuthenticationMethod = false, "client_secret_basic"
	client.Scopes = []string{"openid"}
	page, err := oauth.NewClientListPage([]oauth.Client{client})
	if err != nil {
		t.Fatal("minimal confidential OIDC registration unavailable to safe reads", err)
	}
	items := page.Items()
	if len(items) != 1 || items[0].ID != client.ID || items[0].Public || items[0].AuthenticationMethod != "client_secret_basic" || items[0].SubjectRegistration != nil || !slices.Equal(items[0].Scopes, []string{"openid"}) {
		t.Fatal("safe metadata changed minimal confidential OIDC registration")
	}
	items[0].Scopes[0] = "email"
	if !slices.Equal(page.Items()[0].Scopes, []string{"openid"}) {
		t.Fatal("safe confidential OIDC page aliases caller scopes")
	}
}
