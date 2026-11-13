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

func TestConfidentialOIDCUpdateExplicitOriginalClass(t *testing.T) {
	for _, variant := range []string{"selected", "unselected", "uncomposed", "public-source", "oauth-source", "pairwise-source", "claims-replacement", "oauth-replacement", "pairwise-result", "public-result"} {
		t.Run(variant, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			config := coreConfig(t, now)
			config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "profile", "email", "phone"})
			client := config.Clients[0]
			client.ID, client.Public, client.AuthenticationMethod, client.Scopes = "managed.abcdefghijklmnopqrstuw", false, "client_secret_basic", []string{"openid"}
			pairwise, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
			config.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb", "https://client.example/new"}, PostLogoutRedirects: []string{"https://client.example/logout"}, Scopes: config.Scopes, ConfidentialOIDC: true, ConfidentialOIDCUpdates: true, PairwiseRegistrations: []oauth.OIDCSubjectRegistration{pairwise}, PublicClients: true, PublicOIDC: true}
			csrf, _ := session.NewCSRFToken()
			key, _ := identity.NewIdempotencyKey([]byte("confidential-oidc-update-" + variant))
			request := oauth.ClientUpdateRequest{Management: oauth.ClientManagementRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: config.Issuer.String(), Network: "192.0.2.1", RequestKey: key, ClientID: client.ID, Version: client.Version}, Redirects: []string{"https://client.example/new"}, PostLogoutRedirects: []string{"https://client.example/logout"}, Scopes: []string{"openid"}}
			switch variant {
			case "unselected":
				config.ManagedClients.ConfidentialOIDCUpdates = false
			case "public-source":
				client.Public, client.AuthenticationMethod = true, "none"
			case "oauth-source":
				client.Scopes = []string{"identity:read"}
			case "pairwise-source":
				client.SubjectRegistration = &pairwise
			case "claims-replacement":
				request.Scopes = []string{"email", "openid"}
			case "oauth-replacement":
				request.Scopes = []string{"identity:read"}
			}
			called := false
			store := confidentialOIDCUpdatingStore{client: client, updatingClientStore: updatingClientStore{update: func(_ context.Context, e oauth.ClientUpdateExecution) (oauth.ClientUpdateResult, error) {
				called = true
				if e.ValidateAt(now) != nil || e.Request.Management.Public || !slices.Equal(e.Request.Scopes, []string{"openid"}) {
					t.Fatal("confidential replacement lost borrowed exact-class custody")
				}
				updated := client
				updated.Version++
				updated.Redirects, updated.PostLogoutRedirects = slices.Clone(request.Redirects), slices.Clone(request.PostLogoutRedirects)
				if variant == "pairwise-result" {
					updated.SubjectRegistration = &pairwise
				}
				if variant == "public-result" {
					updated.Public, updated.AuthenticationMethod = true, "none"
				}
				return oauth.ClientUpdateResult{Client: updated, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}, nil
			}}}
			deps := oauth.Dependencies{Sessions: sessions, Store: store, Clients: store, OIDC: publicClaimsExtension{}}
			if variant == "uncomposed" {
				deps.OIDC = nil
			}
			service, err := oauth.NewService(config, deps)
			if err != nil {
				t.Fatal("confidential update configuration", err)
			}
			out, err := service.ClientUpdate(context.Background(), request)
			if variant == "selected" {
				if err != nil || !called || out.Client.ID != client.ID || out.Client.Public || out.Client.AuthenticationMethod != "client_secret_basic" || out.Client.SubjectRegistration != nil || !slices.Equal(out.Client.Scopes, []string{"openid"}) {
					t.Fatal("selected confidential OIDC replacement unavailable", err)
				}
			} else if err == nil || out.Client.ID != "" {
				t.Fatal("unselected/changed confidential profile escaped", err)
			} else if variant != "pairwise-result" && variant != "public-result" && called {
				t.Fatal("invalid original/profile reached updater")
			}
		})
	}
}

func TestConfidentialOIDCUpdatePolicyAndDefaultCanonicalBytes(t *testing.T) {
	_, _, now, _ := coreSessionFixture(t)
	config := coreConfig(t, now)
	policy := oauth.ManagedClientPolicy{Owner: config.Clients[0].Owner, TenantID: "tenant", Redirects: config.Clients[0].Redirects, Scopes: config.Scopes, ConfidentialOIDC: true}
	wire, err := json.Marshal(policy)
	const original = `{"Owner":{},"TenantID":"tenant","Redirects":["https://client.example/cb"],"PostLogoutRedirects":null,"Scopes":{},"ConfidentialOIDC":true,"DeviceAuthorization":false}`
	if err != nil || string(wire) != original {
		t.Fatal("false update selector changed original policy bytes", err)
	}
	policy.ConfidentialOIDCUpdates, policy.ConfidentialOIDC = true, false
	config.ManagedClients = &policy
	config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
	if _, err := config.Validated(); err == nil {
		t.Fatal("update opt-in accepted without original confidential creation class")
	}
	policy.ConfidentialOIDC = true
	validated, err := config.Validated()
	if err != nil || !validated.ManagedClients.ConfidentialOIDCUpdates {
		t.Fatal("confidential update incorrectly requires public selection", err)
	}
	wire, err = json.Marshal(validated.ManagedClients)
	if err != nil || !strings.Contains(string(wire), `"ConfidentialOIDCUpdates":true`) {
		t.Fatal("validated canonical policy lost explicit update selection", err)
	}
}

func FuzzConfidentialOIDCUpdateReplacementBounds(f *testing.F) {
	owner, _ := oauth.NewPlatformOwner("platform")
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	scopes, _ := oauth.NewScopeCatalog([]string{"identity:read"})
	policy := oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: scopes, ConfidentialOIDC: true, ConfidentialOIDCUpdates: true, PublicClients: true, PublicOIDC: true}
	token, _ := session.NewToken(32)
	wire, _ := token.Reveal()
	csrf, _ := session.NewCSRFToken()
	key, _ := identity.NewIdempotencyKey([]byte("confidential-update-fuzz"))
	base := oauth.ClientManagementRequest{Owner: owner, TenantID: "tenant", Session: auth.NewBearerCredential(wire), CSRF: csrf, Origin: issuer.String(), Network: "192.0.2.1", RequestKey: key, Version: 1}
	f.Add("managed.abcdefghijklmnopqrstuw", "https://client.example/cb", "openid", uint8(1), false)
	f.Add("managed.abcdefghijklmnopqrstuw", "https://client.example/cb", "openid", uint8(1), true)
	f.Add("managed.abcdefghijklmnopqrstuw", "https://foreign.example/cb", "email", uint8(0), false)
	f.Fuzz(func(t *testing.T, id, redirect, scope string, count uint8, public bool) {
		request := oauth.ClientUpdateRequest{Management: base, Redirects: make([]string, int(count)), Scopes: []string{scope}}
		request.Management.ClientID, request.Management.Public = id, public
		for i := range request.Redirects {
			request.Redirects[i] = redirect
		}
		out, err := oauth.ValidateClientUpdateRequest(request, policy, issuer)
		if err != nil {
			return
		}
		allowedScope := scope == "openid" || scope == "identity:read"
		if count != 1 || redirect != "https://client.example/cb" || !allowedScope || out.Management.Public != public || scope == "openid" && public {
			t.Fatal("confidential update escaped exact bounds/class/scope")
		}
		if _, err := identity.ParseSubjectID(strings.TrimPrefix(id, oauth.ManagedClientPrefix)); err != nil {
			t.Fatal("noncanonical confidential client ID admitted")
		}
		request.Redirects[0], request.Scopes[0] = "changed", "changed"
		if out.Redirects[0] != redirect || out.Scopes[0] != scope {
			t.Fatal("confidential replacement retained mutable caller slices")
		}
	})
}
