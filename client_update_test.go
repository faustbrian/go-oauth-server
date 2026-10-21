package oauthserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

func FuzzClientUpdateReplacementBounds(f *testing.F) {
	owner, _ := oauth.NewPlatformOwner("platform")
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	scopes, _ := oauth.NewScopeCatalog([]string{"identity:read"})
	policy := oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: scopes}
	token, _ := session.NewToken(32)
	wire, _ := token.Reveal()
	csrf, _ := session.NewCSRFToken()
	key, _ := identity.NewIdempotencyKey([]byte("fuzz-update"))
	base := oauth.ClientManagementRequest{Owner: owner, TenantID: "tenant", Session: auth.NewBearerCredential(wire), CSRF: csrf, Origin: issuer.String(), Network: "192.0.2.1", RequestKey: key, Version: 1}
	for _, seed := range []struct {
		id, redirect, scope string
		n                   uint8
	}{
		{"managed.abcdefghijklmnopqrstuw", "https://client.example/cb", "identity:read", 1},
		{"managed.", "https://foreign.example/cb", "openid", 1},
		{"managed.abcdefghijklmnopqrstuw", "https://client.example/cb", "identity:read", 17},
		{"", "", "", 0},
	} {
		f.Add(seed.id, seed.redirect, seed.scope, seed.n)
	}
	f.Fuzz(func(t *testing.T, id, redirect, scope string, n uint8) {
		r := oauth.ClientUpdateRequest{Management: base, Redirects: make([]string, int(n)), Scopes: []string{scope}}
		r.Management.ClientID = id
		for i := range r.Redirects {
			r.Redirects[i] = redirect
		}
		out, err := oauth.ValidateClientUpdateRequest(r, policy, issuer)
		if err != nil {
			return
		}
		if n != 1 || redirect != "https://client.example/cb" || scope != "identity:read" || !strings.HasPrefix(id, oauth.ManagedClientPrefix) {
			t.Fatal("out-of-ceiling or unbounded replacement accepted")
		}
		if _, err := identity.ParseSubjectID(strings.TrimPrefix(id, oauth.ManagedClientPrefix)); err != nil {
			t.Fatal("noncanonical managed ID accepted")
		}
		r.Redirects[0] = "changed"
		r.Scopes[0] = "changed"
		if out.Redirects[0] != redirect || out.Scopes[0] != scope {
			t.Fatal("validated replacement aliases hostile input")
		}
	})
}

type updatingClientStore struct {
	managedStore
	update func(context.Context, oauth.ClientUpdateExecution) (oauth.ClientUpdateResult, error)
}

func (s updatingClientStore) UpdateClient(ctx context.Context, e oauth.ClientUpdateExecution) (oauth.ClientUpdateResult, error) {
	return s.update(ctx, e)
}

func TestClientUpdateCompleteReplacementOriginalCustodyAndImmutableCeilings(t *testing.T) {
	for _, mode := range []string{"replace", "empty-redirects", "empty-scopes", "expanded-redirect", "expanded-scope", "duplicate-scope", "public", "static", "zero-version", "overflow", "missing-csrf", "embedded-edit", "foreign-owner", "expired", "backward", "cancel", "unavailable", "conflict", "wrong-result-version", "wrong-result-scope", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			c := coreConfig(t, now)
			clock := now
			c.Clock = clockFunc(func() time.Time { return clock })
			owner, _ := oauth.NewPlatformOwner("platform")
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb", "https://client.example/new"}, Scopes: c.Scopes}
			csrf, _ := session.NewCSRFToken()
			key, _ := identity.NewIdempotencyKey([]byte("update-original"))
			r := oauth.ClientUpdateRequest{Management: oauth.ClientManagementRequest{Owner: owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, ClientID: "managed.abcdefghijklmnopqrstuw", Version: 7}, Redirects: []string{"https://client.example/new"}, Scopes: []string{"identity:read"}}
			switch mode {
			case "empty-redirects":
				r.Redirects = nil
			case "empty-scopes":
				r.Scopes = nil
			case "expanded-redirect":
				r.Redirects = []string{"https://foreign.example/cb"}
			case "expanded-scope":
				r.Scopes = []string{"privileged:write"}
			case "duplicate-scope":
				r.Scopes = []string{"identity:read", "identity:read"}
			case "public":
				r.Management.Public = true
			case "static":
				r.Management.ClientID = "static"
			case "zero-version":
				r.Management.Version = 0
			case "overflow":
				r.Management.Version = ^uint64(0)
			case "missing-csrf":
				r.Management.CSRF = session.CSRFToken{}
			case "embedded-edit":
				r.Management.Redirects = slices.Clone(r.Redirects)
			case "foreign-owner":
				r.Management.Owner, _ = oauth.NewPlatformOwner("foreign")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := false
			store := updatingClientStore{update: func(ctx context.Context, e oauth.ClientUpdateExecution) (oauth.ClientUpdateResult, error) {
				called = true
				if _, ok := ctx.Deadline(); !ok || e.ValidateAt(now) != nil || e.Request.Management.Version != 7 || len(e.Request.Management.Scopes) != 0 || !slices.Equal(e.Request.Redirects, []string{"https://client.example/new"}) {
					t.Fatal("original bounded update custody lost")
				}
				// Mutation of caller input after admission cannot retarget native input.
				r.Redirects[0] = "https://foreign.example/cb"
				r.Scopes[0] = "privileged:write"
				if e.Request.Redirects[0] != "https://client.example/new" || e.Request.Scopes[0] != "identity:read" {
					t.Fatal("update aliases caller collections")
				}
				out := oauth.ClientUpdateResult{Client: oauth.Client{ID: e.Request.Management.ClientID, Owner: owner, Version: 8, Resource: c.Resource, AuthenticationMethod: "client_secret_basic", Redirects: slices.Clone(e.Request.Redirects), Scopes: slices.Clone(e.Request.Scopes)}, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}
				switch mode {
				case "expired":
					clock = now.Add(20 * time.Second)
				case "backward":
					clock = now.Add(-time.Nanosecond)
				case "cancel":
					cancel()
				case "unavailable":
					return out, oauth.ErrUnavailable
				case "conflict":
					out.Completion.Outcome = identity.CommitOutcomeConflict
					return out, oauth.ErrAccessDenied
				case "wrong-result-version":
					out.Client.Version = 7
				case "wrong-result-scope":
					out.Client.Scopes = []string{"privileged:write"}
				case "unknown":
					out.Completion.Outcome = identity.CommitOutcomeUnknown
				}
				return out, nil
			}}
			service, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.ClientUpdate(ctx, r)
			invalid := slices.Contains([]string{"empty-redirects", "empty-scopes", "expanded-redirect", "expanded-scope", "duplicate-scope", "public", "static", "zero-version", "overflow", "missing-csrf", "embedded-edit", "foreign-owner"}, mode)
			if invalid {
				if err == nil || called || out.Client.ID != "" {
					t.Fatal("invalid metadata replacement delegated")
				}
				return
			}
			if mode == "replace" {
				if err != nil || !called || out.Client.Version != 8 {
					t.Fatal("valid metadata replacement denied", err)
				}
			} else if mode == "unknown" {
				if err != nil || out.Client.ID != "" || out.Completion.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("unknown update disclosed uncommitted metadata", err)
				}
			} else if err == nil || out.Client.ID != "" {
				t.Fatal("failed/late update disclosed metadata")
			}
			if mode == "conflict" && !errors.Is(err, oauth.ErrClientConflict) || mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("update error classification lost", err)
			}
			if strings.Contains(fmt.Sprintf("%+v", r), bearer.Token()) {
				t.Fatal("update request exposed credential")
			}
			if _, err := json.Marshal(r); err == nil {
				t.Fatal("update request serialized credential")
			}
		})
	}
}
