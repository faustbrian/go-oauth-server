package oauthserver_test

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

type managedStore struct {
	consentStore
	call func(context.Context, oauth.ClientManagementExecution) (oauth.ClientManagementResult, error)
}

func TestClientManagementConservesOriginalReadDeadlineAndScrubsHistoricalSecrets(t *testing.T) {
	for _, mode := range []string{"live", "expired", "backward", "unknown", "replay"} {
		t.Run(mode, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			c := coreConfig(t, now)
			clock := now
			c.Clock = clockFunc(func() time.Time { return clock })
			owner, _ := oauth.NewPlatformOwner("platform")
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes}
			csrf, _ := session.NewCSRFToken()
			key, _ := identity.NewIdempotencyKey([]byte("management-deadline"))
			r := oauth.ClientManagementRequest{Owner: owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Redirects: []string{"https://client.example/cb"}, Scopes: []string{"identity:read"}}
			store := managedStore{call: func(context.Context, oauth.ClientManagementExecution) (oauth.ClientManagementResult, error) {
				out := oauth.ClientManagementResult{Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}
				out.Secret, _ = oauth.NewToken()
				switch mode {
				case "expired":
					clock = now.Add(20 * time.Second)
				case "backward":
					clock = now.Add(-time.Nanosecond)
				case "unknown":
					out.Completion.Outcome = identity.CommitOutcomeUnknown
				case "replay":
					out.Completion.Replayed = true
				}
				return out, nil
			}}
			service, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.ClientCreate(context.Background(), r)
			if mode == "expired" || mode == "backward" {
				if err == nil {
					t.Fatal("original session read validity renewed")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			_, reveal := out.Secret.Reveal()
			if mode == "live" {
				if reveal != nil {
					t.Fatal("known committed delivery withheld")
				}
			} else if reveal == nil {
				t.Fatal("non-live or historical result disclosed secret")
			}
		})
	}
}

func (s managedStore) ManageClient(ctx context.Context, e oauth.ClientManagementExecution) (oauth.ClientManagementResult, error) {
	return s.call(ctx, e)
}
func (managedStore) CurrentClient(context.Context, string) (oauth.Client, error) {
	return oauth.Client{}, oauth.ErrAccessDenied
}
func (managedStore) AuthenticateCurrentClient(context.Context, oauth.Client, oauth.ClientAuthentication) error {
	return oauth.ErrInvalidClient
}

func TestClientManagementDelegatesOriginalHumanCustodyAndCopiesCreatePolicy(t *testing.T) {
	sessions, bearer, now, _ := coreSessionFixture(t)
	c := coreConfig(t, now)
	owner, _ := oauth.NewPlatformOwner("platform")
	scopes, _ := oauth.NewScopeCatalog([]string{"identity:read"})
	c.ManagedClients = &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: scopes}
	csrf, _ := session.NewCSRFToken()
	key, _ := identity.NewIdempotencyKey([]byte("client-create-original"))
	r := oauth.ClientManagementRequest{Owner: owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Redirects: []string{"https://client.example/cb"}, Scopes: []string{"identity:read"}}
	called := false
	store := managedStore{call: func(_ context.Context, e oauth.ClientManagementExecution) (oauth.ClientManagementResult, error) {
		called = true
		if e.ValidateAt(now) != nil || e.Delete {
			t.Fatal("original management custody lost")
		}
		e.Request.Scopes[0] = "changed"
		return oauth.ClientManagementResult{Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}, nil
	}}
	s, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClientCreate(context.Background(), r); err != nil || !called || r.Scopes[0] != "identity:read" {
		t.Fatal("genuine confidential create did not delegate safely", err)
	}
	for _, mode := range []string{"owner", "tenant", "origin", "csrf", "public", "id", "scope", "redirect"} {
		bad := r
		switch mode {
		case "owner":
			bad.Owner, _ = oauth.NewPlatformOwner("foreign")
		case "tenant":
			bad.TenantID = "foreign"
		case "origin":
			bad.Origin = "https://foreign.example"
		case "csrf":
			bad.CSRF = session.CSRFToken{}
		case "public":
			bad.Public = true
		case "id":
			bad.ClientID = "caller-selected"
		case "scope":
			bad.Scopes = []string{"identity:write"}
		case "redirect":
			bad.Redirects = []string{"https://foreign.example/cb"}
		}
		called = false
		if _, err := s.ClientCreate(context.Background(), bad); err == nil || called {
			t.Fatal("invalid management request delegated", mode)
		}
	}
}
