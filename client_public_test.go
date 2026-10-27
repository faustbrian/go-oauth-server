package oauthserver_test

import (
	"context"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestManagedPublicClientCreationNeverRevealsSecret(t *testing.T) {
	for _, public := range []bool{false, true} {
		t.Run(map[bool]string{false: "confidential", true: "public"}[public], func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			c := coreConfig(t, now)
			owner, _ := oauth.NewPlatformOwner("platform")
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes, PublicClients: true}
			csrf, _ := session.NewCSRFToken()
			key, _ := identity.NewIdempotencyKey([]byte("public-create"))
			r := oauth.ClientManagementRequest{Owner: owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Public: public, Redirects: []string{"https://client.example/cb"}, Scopes: []string{"identity:read"}}
			called := false
			store := managedStore{call: func(_ context.Context, e oauth.ClientManagementExecution) (oauth.ClientManagementResult, error) {
				called = true
				if e.Request.Public != public || e.ValidateAt(now) != nil {
					t.Fatal("client class or original custody lost")
				}
				// Even an erroneous adapter result must not disclose a public secret.
				secret, _ := oauth.NewToken()
				return oauth.ClientManagementResult{Secret: secret, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}, nil
			}}
			service, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.ClientCreate(context.Background(), r)
			if err != nil || !called {
				t.Fatal("explicit client class denied", err)
			}
			_, reveal := out.Secret.Reveal()
			if public != (reveal != nil) {
				t.Fatal("secret disclosure disagrees with selected class")
			}
			// Public is a create selection, not a delete/rotation metadata edit.
			r.ClientID, r.Version, r.Redirects, r.Scopes = "managed.abcdefghijklmnopqrstuw", 1, nil, nil
			if _, err := oauth.ValidateClientManagementRequest(r, true, *c.ManagedClients, c.Issuer); public && err == nil {
				t.Fatal("delete accepted class edit")
			}
		})
	}
}

type publicRegistryStore struct {
	authorizationStore
	client oauth.Client
}

func (s publicRegistryStore) CurrentClient(context.Context, string) (oauth.Client, error) {
	return s.client, nil
}
func (s publicRegistryStore) AuthenticateCurrentClient(context.Context, oauth.Client, oauth.ClientAuthentication) error {
	return nil
}

func TestManagedPublicClientCurrentRegistryAndPrivateMetadata(t *testing.T) {
	sessions, bearer, now, _ := coreSessionFixture(t)
	c := coreConfig(t, now)
	client := c.Clients[0]
	client.ID = "managed.abcdefghijklmnopqrstuw"
	c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, PublicClients: true}
	called := false
	store := publicRegistryStore{client: client, authorizationStore: authorizationStore{call: func(_ context.Context, command oauth.AuthorizationCommand) (oauth.AuthorizeResult, error) {
		called = true
		if !command.Client.Public || command.Client.AuthenticationMethod != "none" {
			t.Fatal("public registration changed class")
		}
		continuation, _ := oauth.NewToken()
		return oauth.AuthorizeResult{Outcome: oauth.ConsentRequired, Continuation: continuation, ExpiresAt: now.Add(c.ContinuationTTL)}, nil
	}}}
	service, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
	if err != nil {
		t.Fatal(err)
	}
	r := coreAuthorization()
	r.ClientID = client.ID
	if _, err := service.Authorize(context.Background(), oauth.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: r, Network: "192.0.2.1"}); err != nil || !called {
		t.Fatal("managed public client unavailable to authorization", err)
	}
	page, err := oauth.NewClientListPage([]oauth.Client{client})
	if err != nil || len(page.Items()) != 1 || !page.Items()[0].Public {
		t.Fatal("private metadata lost managed public class", err)
	}
	c.ManagedClients.PublicClients = false
	service, err = oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
	if err != nil {
		t.Fatal(err)
	}
	called = false
	if _, err := service.Authorize(context.Background(), oauth.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: r, Network: "192.0.2.1"}); err == nil || called {
		t.Fatal("unselected managed public client reached authorization persistence")
	}
}

func TestManagedPublicClientServicePrivateReadsEnforceSelectedClass(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			c := coreConfig(t, now)
			client := c.Clients[0]
			client.ID = "managed.abcdefghijklmnopqrstuw"
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, PublicClients: enabled}
			store := readingClientStore{get: func(context.Context, oauth.ClientReadExecution) (oauth.ClientGetResult, error) {
				return oauth.ClientGetResult{Client: client}, nil
			}, list: func(context.Context, oauth.ClientReadExecution) (oauth.ClientListResult, error) {
				page, err := oauth.NewClientListPage([]oauth.Client{client})
				return oauth.ClientListResult{Page: page}, err
			}}
			service, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
			if err != nil {
				t.Fatal(err)
			}
			r := oauth.ClientReadRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, ClientID: client.ID}
			got, getErr := service.ClientGet(context.Background(), r)
			r.ClientID, r.Limit = "", 1
			listed, listErr := service.ClientList(context.Background(), r)
			if !enabled {
				if getErr == nil || listErr == nil || got.Client.ID != "" || len(listed.Page.Items()) != 0 || listed.NextCursor.String() != "" {
					t.Fatal("disabled public class disclosed private metadata")
				}
				return
			}
			items := listed.Page.Items()
			if getErr != nil || listErr != nil || got.Client.ID != client.ID || !got.Client.Public || got.Client.AuthenticationMethod != "none" || len(items) != 1 || !items[0].Public || items[0].AuthenticationMethod != "none" {
				t.Fatal("enabled private get/list lost public none metadata", getErr, listErr)
			}
		})
	}
}

func TestManagedPublicClientRequiresExplicitCeilingAndAdvertisesNone(t *testing.T) {
	sessions, bearer, now, _ := coreSessionFixture(t)
	c, _ := workloadCoreConfig(t)
	c.Clock = clockFunc(func() time.Time { return now })
	owner, _ := oauth.NewPlatformOwner("platform")
	c.ManagedClients = &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes}
	csrf, _ := session.NewCSRFToken()
	key, _ := identity.NewIdempotencyKey([]byte("public-ceiling"))
	r := oauth.ClientManagementRequest{Owner: owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Public: true, Redirects: c.ManagedClients.Redirects, Scopes: []string{"identity:read"}}
	if _, err := oauth.ValidateClientManagementRequest(r, false, *c.ManagedClients, c.Issuer); err == nil {
		t.Fatal("unselected public class admitted")
	}
	c.ManagedClients.PublicClients = true
	c.Discovery = discoveryEndpoints()
	store := managedDiscoveryStore{}
	service, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.DiscoveryOauth(context.Background(), oauth.DiscoveryOauthRequest{})
	if err != nil || !slices.Equal(out.Metadata.TokenEndpointAuthMethodsSupported, []string{"client_secret_basic", "none"}) {
		t.Fatal("selected managed public method missing from metadata", err)
	}
}
