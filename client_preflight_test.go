package oauthserver_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

// These callbacks exercise the declared current-registry seam, not native
// persistence. Static Basic tests below use the actual configured verifier.
type preflightRegistry struct {
	oauth.Store
	lookup  func(context.Context, string) (oauth.Client, error)
	check   func(context.Context, oauth.Client, oauth.ClientAuthentication) error
	effects *int
}

func (r preflightRegistry) CurrentClient(ctx context.Context, id string) (oauth.Client, error) {
	return r.lookup(ctx, id)
}
func (r preflightRegistry) AuthenticateCurrentClient(ctx context.Context, c oauth.Client, a oauth.ClientAuthentication) error {
	return r.check(ctx, c, a)
}
func (r preflightRegistry) Token(context.Context, oauth.TokenCommand) (oauth.TokenResult, error) {
	if r.effects != nil {
		(*r.effects)++
	}
	return oauth.TokenResult{}, oauth.ErrAccessDenied
}
func (r preflightRegistry) Revoke(context.Context, oauth.RevocationCommand) (oauth.RevokeResult, error) {
	if r.effects != nil {
		(*r.effects)++
	}
	return oauth.RevokeResult{}, oauth.ErrAccessDenied
}

func preflightBasic(t *testing.T, id, secret string) oauth.ClientAuthentication {
	t.Helper()
	a, err := oauth.ParseClientAuthentication([]string{clientBasicHeader(id, secret)})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestClientPreflightUsesActualStaticNoneAndBasicMatrix(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	public, err := oauth.NewService(coreConfig(t, now), oauth.Dependencies{Sessions: sessions, Store: consentStore{}})
	if err != nil {
		t.Fatal(err)
	}
	config, secret := confidentialCoreConfig(t)
	confidential, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: consentStore{}})
	if err != nil {
		t.Fatal(err)
	}
	valid := preflightBasic(t, "public-client", secret)
	if err := public.AuthenticateClient(context.Background(), "public-client", oauth.ClientAuthentication{}); err != nil {
		t.Fatal("registered public none denied", err)
	}
	if err := confidential.AuthenticateClient(context.Background(), "public-client", valid); err != nil {
		t.Fatal("actual configured Basic secret denied", err)
	}
	for _, c := range []struct {
		service *oauth.Service
		id      string
		input   oauth.ClientAuthentication
	}{
		{public, "public-client", valid},
		{confidential, "public-client", oauth.ClientAuthentication{}},
		{confidential, "public-client", preflightBasic(t, "public-client", strings.Repeat("w", 43))},
		{confidential, "public-client", preflightBasic(t, "foreign", secret)},
		{confidential, "missing", valid},
		{public, "missing", oauth.ClientAuthentication{}},
		{public, "", oauth.ClientAuthentication{}},
	} {
		if err := c.service.AuthenticateClient(context.Background(), c.id, c.input); err == nil {
			t.Fatal("unregistered or mismatched client authenticated")
		}
	}
}

func preflightManagedFixture(t *testing.T, r preflightRegistry, public bool) (*oauth.Service, oauth.Client) {
	t.Helper()
	sessions, _, now, _ := coreSessionFixture(t)
	c := coreConfig(t, now)
	owner, _ := oauth.NewPlatformOwner("platform")
	w, _ := oauth.NewWorkload("tenant", "worker", 30*time.Second)
	c.ManagedClients = &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: c.Scopes, PublicClients: public, Workloads: []*oauth.Workload{w}}
	client := oauth.Client{ID: "managed.abcdefghijklmnopqrstuw", Owner: owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: c.Resource, Scopes: []string{"identity:read"}, Workload: w}
	if public {
		client.Public, client.AuthenticationMethod, client.Workload, client.Redirects = true, "none", nil, []string{"https://client.example/cb"}
	}
	s, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: r, Clients: r})
	if err != nil {
		t.Fatal(err)
	}
	return s, client
}

func TestClientPreflightRechecksLiveRegistryInsteadOfCachingSuccess(t *testing.T) {
	var current oauth.Client
	var digest oauth.ClientSecretDigest
	deleted := false
	reads, checks := 0, 0
	effects := 0
	r := preflightRegistry{lookup: func(_ context.Context, id string) (oauth.Client, error) {
		reads++
		if deleted || id != current.ID {
			return oauth.Client{}, oauth.ErrInvalidClient
		}
		return current, nil
	}, check: func(ctx context.Context, c oauth.Client, input oauth.ClientAuthentication) error {
		checks++
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if deleted || c.ID != current.ID || c.Version != current.Version {
			return oauth.ErrInvalidClient
		}
		return input.VerifySecretDigest(c.ID, current.Version, digest)
	}, effects: &effects}
	s, client := preflightManagedFixture(t, r, false)
	current = client
	token, _ := oauth.NewToken()
	secret, _ := token.Reveal()
	digest, _ = oauth.DigestClientSecret(current.ID, current.Version, secret)
	input := preflightBasic(t, current.ID, secret)
	if err := s.AuthenticateClient(context.Background(), current.ID, input); err != nil {
		t.Fatal("current registry credential denied", err)
	}
	current.Version++
	token, _ = oauth.NewToken()
	replacement, _ := token.Reveal()
	digest, _ = oauth.DigestClientSecret(current.ID, current.Version, replacement)
	if err := s.AuthenticateClient(context.Background(), current.ID, input); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatal("prior successful credential cached after live registry change", err)
	}
	if err := s.AuthenticateClient(context.Background(), current.ID, preflightBasic(t, current.ID, replacement)); err != nil {
		t.Fatal("actual successor registry credential denied", err)
	}
	deleted = true
	if err := s.AuthenticateClient(context.Background(), current.ID, input); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatal("deleted registry client authenticated", err)
	}
	if reads != 4 || checks != 3 {
		t.Fatal("preflight did not use current registry for each invocation")
	}
	// Preflight returns no authorization artifact. Existing token/revocation
	// paths must still consult the live registry before the embedded Store.
	if _, err := s.Token(context.Background(), oauth.TokenRequest{GrantType: oauth.ClientCredentialsGrant, ClientID: current.ID, ClientAuthentication: input, Network: "192.0.2.1"}); err == nil {
		t.Fatal("preflight bypassed later token authentication")
	}
	if _, err := s.Revoke(context.Background(), oauth.RevokeRequest{ClientID: current.ID, ClientAuthentication: input, Token: secret, Network: "192.0.2.1"}); err == nil {
		t.Fatal("preflight bypassed later revocation authentication")
	}
	if effects != 0 || reads != 6 || checks != 3 {
		t.Fatal("prior preflight success skipped current protocol admission or invoked durable effects")
	}
}

func TestClientPreflightManagedPublicUsesRegisteredNone(t *testing.T) {
	var client oauth.Client
	r := preflightRegistry{lookup: func(context.Context, string) (oauth.Client, error) { return client, nil }, check: func(_ context.Context, c oauth.Client, a oauth.ClientAuthentication) error {
		if !c.Public || a.Method() != "none" {
			return oauth.ErrInvalidClient
		}
		return nil
	}}
	s, c := preflightManagedFixture(t, r, true)
	client = c
	if err := s.AuthenticateClient(context.Background(), c.ID, oauth.ClientAuthentication{}); err != nil {
		t.Fatal("registered public none denied", err)
	}
	if err := s.AuthenticateClient(context.Background(), c.ID, preflightBasic(t, c.ID, strings.Repeat("A", 43))); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatal("public client changed authentication method", err)
	}
}

func TestClientPreflightBoundsContextsAndRedactsRegistryFailures(t *testing.T) {
	for _, mode := range []string{"foreign", "unsupported", "unavailable", "lookup-panic", "auth-panic", "expired", "canceled-during-lookup", "canceled-during-auth", "deadline-during-auth", "earlier-deadline", "bounded-deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var deadline time.Time
			if mode == "earlier-deadline" {
				var stop context.CancelFunc
				deadline = time.Now().Add(100 * time.Millisecond)
				ctx, stop = context.WithDeadline(ctx, deadline)
				defer stop()
			}
			if mode == "deadline-during-auth" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 10*time.Millisecond)
				defer stop()
			}
			var client oauth.Client
			r := preflightRegistry{lookup: func(call context.Context, _ string) (oauth.Client, error) {
				if mode == "lookup-panic" {
					panic("private registry detail")
				}
				if mode == "unavailable" {
					return oauth.Client{}, errors.New("private registry detail")
				}
				if mode == "canceled-during-lookup" {
					cancel()
				}
				if got, ok := call.Deadline(); !ok || mode == "earlier-deadline" && !got.Equal(deadline) || mode == "bounded-deadline" && time.Until(got) > time.Second {
					t.Fatal("bounded/original caller deadline lost")
				}
				c := client
				if mode == "foreign" {
					c.ID = "managed.foreign"
				}
				if mode == "unsupported" {
					c.AuthenticationMethod = "unsupported"
				}
				return c, nil
			}, check: func(call context.Context, _ oauth.Client, _ oauth.ClientAuthentication) error {
				if mode == "auth-panic" {
					panic("private registry detail")
				}
				if mode == "expired" {
					return oauth.ErrInvalidClient
				}
				if mode == "canceled-during-auth" {
					cancel()
				}
				if mode == "deadline-during-auth" {
					<-call.Done()
				}
				return nil
			}}
			s, c := preflightManagedFixture(t, r, false)
			client = c
			err := s.AuthenticateClient(ctx, client.ID, oauth.ClientAuthentication{})
			switch mode {
			case "bounded-deadline", "earlier-deadline":
				if err != nil {
					t.Fatal("live bounded admission denied", err)
				}
			case "lookup-panic", "auth-panic", "unavailable":
				if !errors.Is(err, oauth.ErrUnavailable) || strings.Contains(err.Error(), "private registry detail") {
					t.Fatal("registry failure not redacted")
				}
			case "canceled-during-lookup", "canceled-during-auth":
				if !errors.Is(err, context.Canceled) {
					t.Fatal("late caller cancellation ignored", err)
				}
			case "deadline-during-auth":
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("late caller deadline ignored", err)
				}
			default:
				if err == nil {
					t.Fatal("invalid current registry state admitted")
				}
			}
		})
	}
	sessions, _, now, _ := coreSessionFixture(t)
	s, _ := oauth.NewService(coreConfig(t, now), oauth.Dependencies{Sessions: sessions, Store: consentStore{}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.AuthenticateClient(ctx, "public-client", oauth.ClientAuthentication{}); !errors.Is(err, context.Canceled) {
		t.Fatal("initial cancellation ignored", err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if err := s.AuthenticateClient(expired, "public-client", oauth.ClientAuthentication{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired caller deadline ignored", err)
	}
	if err := s.AuthenticateClient(nil, "public-client", oauth.ClientAuthentication{}); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("nil context admitted", err)
	}
	var absent *oauth.Service
	if err := absent.AuthenticateClient(context.Background(), "public-client", oauth.ClientAuthentication{}); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("nil service admitted", err)
	}
}
