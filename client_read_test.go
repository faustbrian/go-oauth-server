package oauthserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

type readingClientStore struct {
	managedStore
	get  func(context.Context, oauth.ClientReadExecution) (oauth.ClientGetResult, error)
	list func(context.Context, oauth.ClientReadExecution) (oauth.ClientListResult, error)
}

func (s readingClientStore) ClientGet(ctx context.Context, e oauth.ClientReadExecution) (oauth.ClientGetResult, error) {
	return s.get(ctx, e)
}
func (s readingClientStore) ClientList(ctx context.Context, e oauth.ClientReadExecution) (oauth.ClientListResult, error) {
	return s.list(ctx, e)
}

func TestClientReadSafeOriginalCustodyAndNonSensitiveProof(t *testing.T) {
	sessions, bearer, now, observation := coreSessionFixture(t)
	bindings, _ := observation.Session.Bindings()
	bindings.Remember, _ = session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	bindings.Authentication.Proof.IssuedAt = now.Add(-16 * time.Minute)
	record, err := session.NewSession(bindings)
	if err != nil {
		t.Fatal(err)
	}
	observation.Session = record
	if life, err := record.Lifetime(now); err != nil || life.Fresh {
		t.Fatal("read fixture must be current but not mutation-fresh", err)
	}
	c := coreConfig(t, now)
	owner, _ := oauth.NewPlatformOwner("platform")
	c.ManagedClients = &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes}
	client := oauth.Client{ID: "managed.abcdefghijklmnopqrstuw", Version: 2, Owner: owner, AuthenticationMethod: "client_secret_basic", Resource: c.Resource, Redirects: []string{"https://client.example/cb"}, Scopes: []string{"identity:read"}}
	called := 0
	store := readingClientStore{get: func(ctx context.Context, e oauth.ClientReadExecution) (oauth.ClientGetResult, error) {
		called++
		if _, ok := ctx.Deadline(); !ok || e.ValidateAt(now) != nil || e.Request.Session.Token() != bearer.Token() {
			t.Fatal("original current non-sensitive read custody lost")
		}
		return oauth.ClientGetResult{Client: client}, nil
	}, list: func(_ context.Context, e oauth.ClientReadExecution) (oauth.ClientListResult, error) {
		called++
		if e.ValidateAt(now) != nil || e.Request.Limit != 100 {
			t.Fatal("bounded list lost original custody")
		}
		page, err := oauth.NewClientListPage([]oauth.Client{client})
		return oauth.ClientListResult{Page: page}, err
	}}
	s, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
	if err != nil {
		t.Fatal(err)
	}
	r := oauth.ClientReadRequest{Owner: owner, TenantID: "tenant", Session: bearer, ClientID: client.ID}
	if out, err := s.ClientGet(context.Background(), r); err != nil || out.Client.Version != 2 {
		t.Fatal("current manager private read requires mutation freshness", err)
	}
	r.ClientID = ""
	r.Limit = 100
	out, err := s.ClientList(context.Background(), r)
	if err != nil || len(out.Page.Items()) != 1 || called != 2 {
		t.Fatal("current manager list unavailable", err)
	}
	items := out.Page.Items()
	items[0].Scopes[0] = "changed"
	items[0].Redirects[0] = "https://foreign.example/cb"
	if out.Page.Items()[0].Scopes[0] != "identity:read" || client.Redirects[0] != "https://client.example/cb" {
		t.Fatal("read page aliases authority")
	}
	if strings.Contains(fmt.Sprintf("%+v", r), bearer.Token()) {
		t.Fatal("read request logged bearer")
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("read request serialized bearer")
	}
	for _, limit := range []uint16{0, 101} {
		bad := r
		bad.Limit = limit
		if _, err := s.ClientList(context.Background(), bad); err == nil {
			t.Fatal("unbounded list admitted")
		}
	}
	bad := r
	bad.ClientID = client.ID
	if _, err := s.ClientList(context.Background(), bad); err == nil {
		t.Fatal("list accepted get-only field")
	}
}

func TestClientReadWithholdsFailedExpiredAndCrossPolicyResults(t *testing.T) {
	for _, mode := range []string{"unavailable", "cancel", "expired", "backward", "foreign-owner", "static", "over-limit"} {
		t.Run(mode, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			c := coreConfig(t, now)
			clock := now
			c.Clock = clockFunc(func() time.Time { return clock })
			owner, _ := oauth.NewPlatformOwner("platform")
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes}
			client := oauth.Client{ID: "managed.abcdefghijklmnopqrstuw", Version: 1, Owner: owner, AuthenticationMethod: "client_secret_basic", Resource: c.Resource, Redirects: []string{"https://client.example/cb"}, Scopes: []string{"identity:read"}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store := readingClientStore{list: func(context.Context, oauth.ClientReadExecution) (oauth.ClientListResult, error) {
				resultErr := error(nil)
				switch mode {
				case "unavailable":
					resultErr = oauth.ErrUnavailable
				case "cancel":
					cancel()
				case "expired":
					clock = now.Add(20 * time.Second)
				case "backward":
					clock = now.Add(-time.Nanosecond)
				case "foreign-owner":
					client.Owner, _ = oauth.NewPlatformOwner("foreign")
				case "static":
					client.ID = "configured"
				}
				items := []oauth.Client{client}
				if mode == "over-limit" {
					next := client
					next.ID = "managed.bbcdefghijklmnopqrstuw"
					items = append(items, next)
				}
				page, err := oauth.NewClientListPage(items)
				if err != nil {
					return oauth.ClientListResult{}, err
				}
				return oauth.ClientListResult{Page: page}, resultErr
			}}
			s, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
			if err != nil {
				t.Fatal(err)
			}
			out, err := s.ClientList(ctx, oauth.ClientReadRequest{Owner: owner, TenantID: "tenant", Session: bearer, Limit: 1})
			if err == nil || len(out.Page.Items()) != 0 || out.NextCursor.String() != "" {
				t.Fatal("failed read disclosed partial metadata")
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation classification lost", err)
			}
		})
	}
}
