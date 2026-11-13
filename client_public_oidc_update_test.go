package oauthserver_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

type publicOIDCUpdateStore struct {
	updatingClientStore
	current oauth.Client
}

func (s publicOIDCUpdateStore) CurrentClient(context.Context, string) (oauth.Client, error) {
	return s.current, nil
}

func TestPublicOIDCUpdateExplicitSelectionAndOriginalClass(t *testing.T) {
	for _, variant := range []string{"selected", "unselected", "uncomposed", "confidential-source", "oauth-source", "pairwise-source", "claims-source", "device-source", "claims-replacement", "oauth-replacement", "pairwise-result", "device-result"} {
		t.Run(variant, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			config := coreConfig(t, now)
			config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "profile", "email", "phone"})
			client := config.Clients[0]
			client.ID, client.Scopes = "managed.abcdefghijklmnopqrstuw", []string{"openid"}
			pairwise, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
			config.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb", "https://client.example/new"}, PostLogoutRedirects: []string{"https://client.example/logout"}, Scopes: config.Scopes, PublicClients: true, PublicOIDC: true, ConfidentialOIDC: true, PublicOIDCScopes: config.OIDCScopes.Scopes(), PublicPairwiseRegistrations: []oauth.OIDCSubjectRegistration{pairwise}, PublicOIDCUpdates: true}
			csrf, _ := session.NewCSRFToken()
			key, _ := identity.NewIdempotencyKey([]byte("public-oidc-update-" + variant))
			request := oauth.ClientUpdateRequest{Management: oauth.ClientManagementRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: config.Issuer.String(), Network: "192.0.2.1", RequestKey: key, ClientID: client.ID, Version: client.Version, Public: true}, Redirects: []string{"https://client.example/new"}, PostLogoutRedirects: []string{"https://client.example/logout"}, Scopes: []string{"openid"}}
			switch variant {
			case "unselected":
				config.ManagedClients.PublicOIDCUpdates = false
			case "confidential-source":
				client.Public, client.AuthenticationMethod = false, "client_secret_basic"
			case "oauth-source":
				client.Scopes = []string{"identity:read"}
			case "pairwise-source":
				client.SubjectRegistration = &pairwise
			case "claims-source":
				client.Scopes = []string{"email", "openid"}
			case "device-source":
				client.DeviceAuthorization = true
			case "claims-replacement":
				request.Scopes = []string{"openid", "email"}
			case "oauth-replacement":
				request.Scopes = []string{"identity:read"}
			}
			called := false
			store := publicOIDCUpdateStore{current: client, updatingClientStore: updatingClientStore{update: func(_ context.Context, execution oauth.ClientUpdateExecution) (oauth.ClientUpdateResult, error) {
				called = true
				if execution.ValidateAt(now) != nil || !execution.Request.Management.Public || !slices.Equal(execution.Request.Scopes, []string{"openid"}) {
					t.Fatal("public OIDC replacement lost exact original custody/profile")
				}
				updated := client
				updated.Version++
				updated.Redirects, updated.PostLogoutRedirects = slices.Clone(request.Redirects), slices.Clone(request.PostLogoutRedirects)
				if variant == "pairwise-result" {
					updated.SubjectRegistration = &pairwise
				}
				if variant == "device-result" {
					updated.DeviceAuthorization = true
				}
				return oauth.ClientUpdateResult{Client: updated, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}, nil
			}}}
			deps := oauth.Dependencies{Sessions: sessions, Store: store, Clients: store, OIDC: publicClaimsExtension{}}
			if variant == "uncomposed" {
				deps.OIDC = nil
			}
			service, err := oauth.NewService(config, deps)
			if err != nil {
				t.Fatal("public-boundary configuration", err)
			}
			out, err := service.ClientUpdate(context.Background(), request)
			if variant == "selected" {
				if err != nil || !called || out.Client.ID != client.ID || !out.Client.Public || out.Client.AuthenticationMethod != "none" || out.Client.SubjectRegistration != nil || !slices.Equal(out.Client.Scopes, []string{"openid"}) || !slices.Equal(out.Client.PostLogoutRedirects, request.PostLogoutRedirects) {
					t.Fatal("selected public OIDC replacement unavailable", err)
				}
			} else if err == nil || out.Client.ID != "" {
				t.Fatal("unselected/changed OIDC registration escaped immutable profile", err)
			}
			// Invalid current metadata is classified like absence by the current
			// registry; only the native owner can distinguish original history and
			// deny fresh mutation. The integration consumer fences that boundary.
			if variant != "selected" && variant != "pairwise-result" && variant != "device-result" && variant != "device-source" && called {
				t.Fatal("invalid original/profile reached mutation")
			}
		})
	}
}

func TestPublicOIDCUpdatePolicyRequiresExistingClassAndPreservesDefaultBytes(t *testing.T) {
	_, _, now, _ := coreSessionFixture(t)
	config := coreConfig(t, now)
	policy := oauth.ManagedClientPolicy{Owner: config.Clients[0].Owner, TenantID: "tenant", Redirects: config.Clients[0].Redirects, Scopes: config.Scopes}
	wire, err := json.Marshal(policy)
	if err != nil || strings.Contains(string(wire), "PublicOIDCUpdates") {
		t.Fatal("default policy canonical bytes expanded", err)
	}
	config.ManagedClients = &policy
	policy.PublicOIDCUpdates = true
	if _, err := config.Validated(); err == nil {
		t.Fatal("OIDC update selected without existing public OIDC class")
	}
	policy.PublicClients, policy.PublicOIDC = true, true
	config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
	if _, err := config.Validated(); err != nil {
		t.Fatal("explicit update selection rejected", err)
	}
}

func FuzzPublicOIDCUpdateReplacementBounds(f *testing.F) {
	owner, _ := oauth.NewPlatformOwner("platform")
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	scopes, _ := oauth.NewScopeCatalog([]string{"identity:read"})
	policy := oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: scopes, PublicClients: true, PublicOIDC: true, PublicOIDCUpdates: true}
	token, _ := session.NewToken(32)
	wire, _ := token.Reveal()
	csrf, _ := session.NewCSRFToken()
	key, _ := identity.NewIdempotencyKey([]byte("public-oidc-update-fuzz"))
	base := oauth.ClientManagementRequest{Owner: owner, TenantID: "tenant", Session: auth.NewBearerCredential(wire), CSRF: csrf, Origin: issuer.String(), Network: "192.0.2.1", RequestKey: key, Version: 1, Public: true}
	for _, seed := range []struct {
		id, redirect, scope string
		count               uint8
	}{
		{"managed.abcdefghijklmnopqrstuw", "https://client.example/cb", "openid", 1},
		{"managed.abcdefghijklmnopqrstuw", "https://client.example/cb", "email", 1},
		{"managed.abcdefghijklmnopqrstuw", "https://foreign.example/cb", "openid", 1},
		{"managed.", "", "", 0},
	} {
		f.Add(seed.id, seed.redirect, seed.scope, seed.count)
	}
	f.Fuzz(func(t *testing.T, id, redirect, scope string, count uint8) {
		request := oauth.ClientUpdateRequest{Management: base, Redirects: make([]string, int(count)), Scopes: []string{scope}}
		request.Management.ClientID = id
		for i := range request.Redirects {
			request.Redirects[i] = redirect
		}
		out, err := oauth.ValidateClientUpdateRequest(request, policy, issuer)
		if err != nil {
			return
		}
		if count != 1 || redirect != "https://client.example/cb" || scope != "openid" || !out.Management.Public {
			t.Fatal("OIDC replacement expanded bounds/class/scope")
		}
		if _, err := identity.ParseSubjectID(strings.TrimPrefix(id, oauth.ManagedClientPrefix)); err != nil {
			t.Fatal("noncanonical managed ID admitted")
		}
		request.Redirects[0], request.Scopes[0] = "changed", "changed"
		if out.Redirects[0] != redirect || out.Scopes[0] != scope {
			t.Fatal("OIDC replacement aliases hostile input")
		}
	})
}
