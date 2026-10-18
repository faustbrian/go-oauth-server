package oauthserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

type selectedIntrospectionStore struct {
	oauth.Store
	read func(context.Context, oauth.IntrospectionCommand) (oauth.IntrospectResult, error)
}

func (s selectedIntrospectionStore) Introspect(ctx context.Context, c oauth.IntrospectionCommand) (oauth.IntrospectResult, error) {
	return s.read(ctx, c)
}

func TestIntrospectionAuthenticatesSeparateConfidentialCallerAndScrubsInactive(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	config, secret := confidentialCoreConfig(t)
	config.OwningClientIntrospection = true
	credential, err := oauth.ParseClientAuthentication([]string{clientBasicHeader(config.Clients[0].ID, secret)})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	active := oauth.IntrospectResult{Active: true, ClientID: config.Clients[0].ID, Subject: "user", Resource: config.Resource, Issuer: config.Issuer, Scopes: []string{"identity:read"}, ExpiresAt: now.Add(time.Minute)}
	store := selectedIntrospectionStore{read: func(ctx context.Context, c oauth.IntrospectionCommand) (oauth.IntrospectResult, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok || c.Client.Public || c.Request.ClientAuthentication.Method() != "client_secret_basic" {
			t.Fatal("unbounded or unauthenticated read")
		}
		return active, nil
	}}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	r := oauth.IntrospectRequest{ClientID: config.Clients[0].ID, Token: strings.Repeat("A", 43), ClientAuthentication: credential}
	got, err := service.Introspect(context.Background(), r)
	if err != nil || !got.Active || got.Subject != "user" || calls != 1 {
		t.Fatal("authenticated owning-client introspection unavailable", err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var projection map[string]any
	if err := json.Unmarshal(encoded, &projection); err != nil {
		t.Fatal(err)
	}
	if len(projection) != 7 || projection["active"] != true || projection["client_id"] != r.ClientID || projection["sub"] != "user" || projection["aud"] != config.Resource || projection["iss"] != config.Issuer.String() || projection["scope"] != "identity:read" || projection["exp"] != float64(now.Add(time.Minute).Unix()) || strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), r.Token) {
		t.Fatal("active JSON widened metadata disclosure")
	}
	active.Active = false // A hostile adapter must not leak inactive metadata.
	got, err = service.Introspect(context.Background(), r)
	if err != nil || got.Active || got.ClientID != "" || got.Subject != "" || got.Resource != "" || got.Scopes != nil || !got.ExpiresAt.IsZero() || got.Issuer.String() != "" {
		t.Fatal("inactive projection leaked metadata", err)
	}
	wire, err := json.Marshal(got)
	if err != nil || string(wire) != `{"active":false}` {
		t.Fatal("inactive wire metadata was not absent", err)
	}
	for _, auth := range []oauth.ClientAuthentication{{}, mustClientAuth(t, r.ClientID, strings.Repeat("w", 43)), mustClientAuth(t, "foreign", secret)} {
		r.ClientAuthentication = auth
		before := calls
		got, err = service.Introspect(context.Background(), r)
		if !errors.Is(err, oauth.ErrInvalidClient) || got.Active || calls != before {
			t.Fatal("invalid caller reached token lookup", err)
		}
	}
	r.ClientAuthentication = credential
	config.OwningClientIntrospection = false
	disabled, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	before := calls
	if _, err := disabled.Introspect(context.Background(), r); !errors.Is(err, oauth.ErrAccessDenied) || calls != before {
		t.Fatal("configuration implicitly enabled introspection")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Introspect(ctx, r); !errors.Is(err, context.Canceled) || calls != before {
		t.Fatal("canceled read reached adapter", err)
	}
}

func mustClientAuth(t *testing.T, id, secret string) oauth.ClientAuthentication {
	t.Helper()
	c, err := oauth.ParseClientAuthentication([]string{clientBasicHeader(id, secret)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIntrospectionRejectsPublicMissingReadersAndInvalidAdapterDisclosure(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	public := coreConfig(t, now)
	public.OwningClientIntrospection = true
	called := false
	store := selectedIntrospectionStore{read: func(context.Context, oauth.IntrospectionCommand) (oauth.IntrospectResult, error) {
		called = true
		return oauth.IntrospectResult{}, nil
	}}
	s, err := oauth.NewService(public, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Introspect(context.Background(), oauth.IntrospectRequest{ClientID: public.Clients[0].ID, Token: strings.Repeat("A", 43)}); !errors.Is(err, oauth.ErrInvalidClient) || called {
		t.Fatal("public client became introspection authority")
	}
	if _, err := oauth.NewService(public, oauth.Dependencies{Sessions: sessions, Store: authorizationStore{}}); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("selected missing native reader accepted")
	}
	config, secret := confidentialCoreConfig(t)
	config.OwningClientIntrospection = true
	r := oauth.IntrospectRequest{ClientID: config.Clients[0].ID, Token: strings.Repeat("A", 43), ClientAuthentication: mustClientAuth(t, config.Clients[0].ID, secret)}
	for _, invalid := range []string{"client", "subject", "resource", "issuer", "scope", "expiry", "error", "panic", "canceled"} {
		t.Run(invalid, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store.read = func(context.Context, oauth.IntrospectionCommand) (oauth.IntrospectResult, error) {
				out := oauth.IntrospectResult{Active: true, ClientID: r.ClientID, Subject: "user", Resource: config.Resource, Issuer: config.Issuer, Scopes: []string{"identity:read"}, ExpiresAt: now.Add(time.Minute)}
				switch invalid {
				case "client":
					out.ClientID = "foreign"
				case "subject":
					out.Subject = ""
				case "resource":
					out.Resource = "https://foreign.example"
				case "issuer":
					out.Issuer, _ = oauth.NewIssuer("https://foreign.example")
				case "scope":
					out.Scopes = []string{"identity:write"}
				case "expiry":
					out.ExpiresAt = now
				case "error":
					return out, errors.New("private dependency diagnostics")
				case "panic":
					panic("private dependency diagnostics")
				case "canceled":
					cancel()
				}
				return out, nil
			}
			s, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Introspect(ctx, r)
			if err == nil || got.Active || got.ClientID != "" || got.Scopes != nil || strings.Contains(err.Error(), "private") {
				t.Fatal("unsafe adapter result exposed", err)
			}
		})
	}
}

func TestIntrospectionFormsUseExclusiveBasicAndAdvisoryHints(t *testing.T) {
	header := clientBasicHeader("confidential-client", strings.Repeat("A", 43))
	for _, hint := range []string{"", "access_token", "refresh_token", "unrecognized"} {
		raw := "token=unknown-token"
		if hint != "" {
			raw += "&token_type_hint=" + hint
		}
		r, err := oauth.ParseIntrospectionForm(raw, []string{header})
		if err != nil || r.ClientID != "confidential-client" || r.Token != "unknown-token" || r.ClientAuthentication.Method() != "client_secret_basic" {
			t.Fatal("valid introspection form rejected", err)
		}
		if strings.Contains(fmt.Sprintf("%#v", r), "unknown-token") {
			t.Fatal("token leaked through formatting")
		}
		if _, err := json.Marshal(r); err == nil {
			t.Fatal("request credential serialized")
		}
	}
	for _, raw := range []string{"", "token=", "token=%00", "token=a&token=b", "token=a&token_type_hint=x&token_type_hint=y", "token=a&client_id=confidential-client", "token=a&client_secret=secret", "token=a&client_assertion=x", "token=" + strings.Repeat("A", 2049), strings.Repeat("x", 16385)} {
		if _, err := oauth.ParseIntrospectionForm(raw, []string{header}); err == nil {
			t.Fatal("invalid or multiple-channel form accepted")
		}
	}
	for _, headers := range [][]string{nil, {header, header}, {"Bearer unsupported"}, {"Basic %zz"}, {strings.Repeat("x", 1025)}} {
		if _, err := oauth.ParseIntrospectionForm("token=a", headers); err == nil {
			t.Fatal("missing, duplicate or unsupported authentication accepted")
		}
	}
}

func FuzzIntrospectionForm(f *testing.F) {
	header := clientBasicHeader("confidential-client", strings.Repeat("A", 43))
	f.Add("token="+strings.Repeat("A", 43), header)
	f.Add("token=a&token_type_hint=unknown", header)
	f.Add("token=a&token=a", header)
	f.Add("token=%00", "Basic %zz")
	f.Fuzz(func(t *testing.T, raw, header string) {
		r, err := oauth.ParseIntrospectionForm(raw, []string{header})
		if err != nil {
			return
		}
		if len(raw) > 16384 || len(r.Token) == 0 || len(r.Token) > 2048 || r.ClientID == "" || r.ClientID != r.ClientAuthentication.ClientID() || r.ClientAuthentication.Method() != "client_secret_basic" {
			t.Fatal("parser widened resource/auth bounds")
		}
		if _, err := oauth.ParseIntrospectionForm(raw+"&client_secret=forbidden", []string{header}); err == nil {
			t.Fatal("multiple authentication locations accepted")
		}
		if _, err := oauth.ParseIntrospectionForm(raw, []string{header, header}); err == nil {
			t.Fatal("duplicate authorization fields accepted")
		}
	})
}
