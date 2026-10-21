package oauthserver_test

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

type rotatingStore struct {
	managedStore
	rotate func(context.Context, oauth.ClientSecretRotationExecution) (oauth.ClientSecretRotationResult, error)
}

func (s rotatingStore) RotateClientSecret(ctx context.Context, e oauth.ClientSecretRotationExecution) (oauth.ClientSecretRotationResult, error) {
	return s.rotate(ctx, e)
}

func TestClientSecretRotationOriginalCustodyBoundedOverlapAndReveal(t *testing.T) {
	for _, mode := range []string{"zero", "overlap", "expired", "backward", "replay", "unknown", "negative", "too-long", "precision", "registration-edit", "public", "static", "missing-version"} {
		t.Run(mode, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			c := coreConfig(t, now)
			clock := now
			c.Clock = clockFunc(func() time.Time { return clock })
			owner, _ := oauth.NewPlatformOwner("platform")
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes}
			csrf, _ := session.NewCSRFToken()
			key, _ := identity.NewIdempotencyKey([]byte("rotation-original"))
			r := oauth.ClientSecretRotationRequest{Management: oauth.ClientManagementRequest{Owner: owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, ClientID: "managed.original", Version: 1}}
			switch mode {
			case "overlap":
				r.Overlap = 24 * time.Hour
			case "negative":
				r.Overlap = -time.Microsecond
			case "too-long":
				r.Overlap = 24*time.Hour + time.Microsecond
			case "precision":
				r.Overlap = time.Nanosecond
			case "registration-edit":
				r.Management.Scopes = []string{"identity:read"}
			case "public":
				r.Management.Public = true
			case "static":
				r.Management.ClientID = "static"
			case "missing-version":
				r.Management.Version = 0
			}
			called := false
			store := rotatingStore{rotate: func(_ context.Context, e oauth.ClientSecretRotationExecution) (oauth.ClientSecretRotationResult, error) {
				called = true
				if e.ValidateAt(now) != nil || e.Request.Management.Version != 1 || e.Request.Overlap != r.Overlap {
					t.Fatal("original rotation custody lost")
				}
				out := oauth.ClientSecretRotationResult{Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}
				out.Secret, _ = oauth.NewToken()
				switch mode {
				case "expired":
					clock = now.Add(20 * time.Second)
				case "backward":
					clock = now.Add(-time.Nanosecond)
				case "replay":
					out.Completion.Replayed = true
				case "unknown":
					out.Completion.Outcome = identity.CommitOutcomeUnknown
				}
				return out, nil
			}}
			service, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store})
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.ClientRotateSecret(context.Background(), r)
			invalid := mode == "negative" || mode == "too-long" || mode == "precision" || mode == "registration-edit" || mode == "public" || mode == "static" || mode == "missing-version"
			if invalid {
				if err == nil || called {
					t.Fatal("invalid rotation delegated")
				}
				return
			}
			if mode == "expired" || mode == "backward" {
				if err == nil {
					t.Fatal("rotation renewed original observation")
				}
			} else if err != nil || !called {
				t.Fatal("valid rotation denied", err)
			}
			_, reveal := out.Secret.Reveal()
			if (mode == "zero" || mode == "overlap") != (reveal == nil) {
				t.Fatal("rotation reveal not limited to live known fresh commit")
			}
		})
	}
}
