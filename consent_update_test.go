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

type narrowingStore struct {
	consentStore
	update func(context.Context, oauth.ConsentUpdateExecution) (oauth.ConsentUpdateResult, error)
}

func (s narrowingStore) ConsentUpdate(ctx context.Context, in oauth.ConsentUpdateExecution) (oauth.ConsentUpdateResult, error) {
	return s.update(ctx, in)
}

func TestConsentUpdateDelegatesOnlyGenuineFreshBoundScopeInput(t *testing.T) {
	sessions, bearer, now, _ := coreSessionFixture(t)
	csrf, _ := session.NewCSRFToken()
	command, err := oauth.NewConsentCommand(oauth.ConsentCommandSpec{Operation: oauth.ConsentNarrow, TenantID: "tenant", Session: bearer, ID: "abcdefghijklmnopqrstuw", Version: 2, Origin: "https://issuer.example", CSRF: csrf, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("narrow-original-key"))
	r := oauth.ConsentUpdateRequest{Consent: command, ClientID: "public-client", ClientVersion: 1, Resource: "https://resource.example", Scopes: []string{"identity:read"}, RequestKey: key}
	called := false
	store := narrowingStore{update: func(ctx context.Context, in oauth.ConsentUpdateExecution) (oauth.ConsentUpdateResult, error) {
		called = true
		if in.Session.ValidateAt(now) != nil || in.Client.ID != r.ClientID || in.Request.Scopes[0] != "identity:read" {
			t.Fatal("unbound native input")
		}
		in.Request.Scopes[0] = "changed"
		return oauth.ConsentUpdateResult{Updated: true, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}, nil
	}}
	service, err := oauth.NewService(coreConfig(t, now), oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := service.ConsentUpdate(context.Background(), r); err != nil || !out.Updated || !called || r.Scopes[0] != "identity:read" {
		t.Fatal("valid narrowing was not safely delegated", err)
	}
	for _, mode := range []string{"client", "client-version", "resource", "empty-scopes", "expanded-scopes", "missing-key"} {
		changed := r
		switch mode {
		case "client":
			changed.ClientID = "foreign"
		case "client-version":
			changed.ClientVersion = 2
		case "resource":
			changed.Resource = "https://foreign.example"
		case "empty-scopes":
			changed.Scopes = nil
		case "expanded-scopes":
			changed.Scopes = []string{"identity:write"}
		case "missing-key":
			changed.RequestKey = identity.IdempotencyKey{}
		}
		called = false
		if out, err := service.ConsentUpdate(context.Background(), changed); err == nil || out.Updated || called {
			t.Fatal("invalid narrowing delegated", mode)
		}
	}
	legacy, _ := oauth.NewService(coreConfig(t, now), oauth.Dependencies{Sessions: sessions, Store: consentStore{}})
	if _, err := legacy.ConsentUpdate(context.Background(), r); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("legacy owner acquired mandatory update capability", err)
	}
}

func TestConsentUpdateRetainsOriginalSensitiveProofAge(t *testing.T) {
	for _, age := range []time.Duration{15*time.Minute - time.Millisecond, 15 * time.Minute, 16 * time.Minute} {
		t.Run(age.String(), func(t *testing.T) {
			sessions, bearer, now, observation := coreSessionFixture(t)
			spec, _ := observation.Session.Bindings()
			spec.Remember, _ = session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: 24 * time.Hour})
			spec.Authentication.Proof.IssuedAt = now.Add(-age)
			record, err := session.NewSession(spec)
			if err != nil {
				t.Fatal(err)
			}
			observation.Session = record
			lifetime, err := record.Lifetime(now)
			if err != nil || !lifetime.Fresh {
				t.Fatal("fixture must remain generally fresh", err)
			}
			called := false
			store := narrowingStore{update: func(context.Context, oauth.ConsentUpdateExecution) (oauth.ConsentUpdateResult, error) {
				called = true
				return oauth.ConsentUpdateResult{Updated: true, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}, nil
			}}
			service, err := oauth.NewService(coreConfig(t, now), oauth.Dependencies{Sessions: sessions, Store: store})
			if err != nil {
				t.Fatal(err)
			}
			csrf, _ := session.NewCSRFToken()
			command, err := oauth.NewConsentCommand(oauth.ConsentCommandSpec{Operation: oauth.ConsentNarrow, TenantID: "tenant", Session: bearer, ID: "abcdefghijklmnopqrstuw", Version: 1, CSRF: csrf, Origin: "https://issuer.example", Network: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			key, _ := identity.NewIdempotencyKey([]byte("original-proof-key"))
			out, err := service.ConsentUpdate(context.Background(), oauth.ConsentUpdateRequest{Consent: command, ClientID: "public-client", ClientVersion: 1, Resource: "https://resource.example", Scopes: []string{"identity:read"}, RequestKey: key})
			if age < 15*time.Minute {
				if err != nil || !called || !out.Updated {
					t.Fatal("recent original proof denied", err)
				}
			} else if !errors.Is(err, oauth.ErrAccessDenied) || called || out.Updated {
				t.Fatal("general freshness renewed sensitive proof", err)
			}
		})
	}
}
