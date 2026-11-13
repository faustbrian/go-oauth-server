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

func TestRetainedOIDCUpdateOriginalClassAndSubjectPolicy(t *testing.T) {
	for _, mode := range []string{"pairwise", "claims", "pairwise-unselected", "claims-unselected", "sector", "subject-edit", "subject-result", "subject-removed", "public-pairwise"} {
		t.Run(mode, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			config := coreConfig(t, now)
			config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "profile", "email", "phone"})
			client := config.Clients[0]
			client.ID, client.Public, client.AuthenticationMethod, client.Scopes = "managed.abcdefghijklmnopqrstuw", false, "client_secret_basic", []string{"openid"}
			registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
			other, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "other-key", 1)
			client.SubjectRegistration = &registration
			policy := &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb", "https://client.example/new", "https://foreign.example/new"}, PostLogoutRedirects: []string{"https://client.example/logout"}, Scopes: config.Scopes, ConfidentialOIDC: true, ConfidentialOIDCUpdates: true, ConfidentialPairwiseUpdates: true, PairwiseRegistrations: []oauth.OIDCSubjectRegistration{registration, other}, PublicClients: true, PublicOIDC: true, PublicOIDCUpdates: true, PublicOIDCClaimsUpdates: true, PublicOIDCScopes: []string{"openid", "profile", "email", "phone"}, PublicPairwiseRegistrations: []oauth.OIDCSubjectRegistration{registration}}
			config.ManagedClients = policy
			csrf, _ := session.NewCSRFToken()
			key, _ := identity.NewIdempotencyKey([]byte("retained-oidc-update-" + mode))
			request := oauth.ClientUpdateRequest{Management: oauth.ClientManagementRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: config.Issuer.String(), Network: "192.0.2.1", RequestKey: key, ClientID: client.ID, Version: client.Version}, Redirects: []string{"https://client.example/new"}, PostLogoutRedirects: []string{"https://client.example/logout"}, Scopes: []string{"openid"}}
			switch mode {
			case "claims", "claims-unselected":
				client.Public, client.AuthenticationMethod, client.SubjectRegistration = true, "none", nil
				client.Scopes = []string{"email", "openid", "phone", "profile"}
				request.Management.Public = true
				request.Scopes = []string{"email", "openid", "profile"}
				policy.PublicOIDCClaimsUpdates = mode == "claims"
			case "pairwise-unselected":
				policy.ConfidentialPairwiseUpdates = false
			case "sector":
				request.Redirects = []string{"https://foreign.example/new"}
			case "subject-edit":
				request.Management.SubjectRegistration = &other
			case "public-pairwise":
				client.Public, client.AuthenticationMethod = true, "none"
				request.Management.Public = true
			}
			called := false
			store := confidentialOIDCUpdatingStore{client: client, updatingClientStore: updatingClientStore{update: func(_ context.Context, e oauth.ClientUpdateExecution) (oauth.ClientUpdateResult, error) {
				called = true
				if e.ValidateAt(now) != nil || e.Request.Management.SubjectRegistration != nil {
					t.Fatal("metadata replacement borrowed a subject edit or stale custody")
				}
				updated := client
				updated.Version++
				updated.Redirects, updated.PostLogoutRedirects, updated.Scopes = slices.Clone(request.Redirects), slices.Clone(request.PostLogoutRedirects), slices.Clone(request.Scopes)
				if mode == "subject-result" {
					updated.SubjectRegistration = &other
				}
				if mode == "subject-removed" {
					updated.SubjectRegistration = nil
				}
				return oauth.ClientUpdateResult{Client: updated, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}, nil
			}}}
			service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store, OIDC: publicClaimsExtension{}})
			if err != nil {
				t.Fatal("retained OIDC update configuration failed", err)
			}
			out, err := service.ClientUpdate(context.Background(), request)
			if mode == "pairwise" || mode == "claims" {
				if err != nil || !called || out.Client.Version != client.Version+1 || out.Client.Public != client.Public || out.Client.AuthenticationMethod != client.AuthenticationMethod || !slices.Equal(out.Client.Scopes, request.Scopes) {
					t.Fatal("selected existing OIDC class cannot replace exact metadata", err)
				}
				if mode == "pairwise" && (out.Client.SubjectRegistration == nil || *out.Client.SubjectRegistration != registration) {
					t.Fatal("pairwise replacement changed original subject registration")
				}
			} else if err == nil || out.Client.ID != "" {
				t.Fatal("unselected/changed subject policy escaped metadata replacement", err)
			} else if mode != "subject-result" && mode != "subject-removed" && called {
				t.Fatal("invalid original/sector/edit reached updater")
			}
		})
	}
}

func TestRetainedOIDCUpdateSelectorsKeepCanonicalDefaults(t *testing.T) {
	_, _, now, _ := coreSessionFixture(t)
	config := coreConfig(t, now)
	config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "profile", "email", "phone"})
	policy := oauth.ManagedClientPolicy{Owner: config.Clients[0].Owner, TenantID: "tenant", Redirects: config.Clients[0].Redirects, Scopes: config.Scopes, ConfidentialOIDC: true, ConfidentialOIDCUpdates: true}
	wire, err := json.Marshal(policy)
	const original = `{"Owner":{},"TenantID":"tenant","Redirects":["https://client.example/cb"],"PostLogoutRedirects":null,"Scopes":{},"ConfidentialOIDC":true,"ConfidentialOIDCUpdates":true,"DeviceAuthorization":false}`
	if err != nil || string(wire) != original {
		t.Fatal("omitted selectors changed original full policy bytes", err)
	}
	config.ManagedClients = &policy
	policy.ConfidentialPairwiseUpdates = true
	if _, err := config.Validated(); err == nil {
		t.Fatal("pairwise updates selected without trusted original registration ceiling")
	}
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	policy.PairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
	policy.ConfidentialOIDCUpdates = false
	if _, err := config.Validated(); err == nil {
		t.Fatal("pairwise operation bypassed the original confidential update selection")
	}
	policy.ConfidentialOIDCUpdates = true
	policy.PublicClients, policy.PublicOIDC, policy.PublicOIDCUpdates, policy.PublicOIDCClaimsUpdates = true, true, true, true
	if _, err := config.Validated(); err == nil {
		t.Fatal("claims updates selected without explicit existing claims ceiling")
	}
	policy.PublicOIDCScopes = []string{"openid", "email"}
	policy.PublicOIDCUpdates = false
	if _, err := config.Validated(); err == nil {
		t.Fatal("claims operation bypassed the original public update selection")
	}
	policy.PublicOIDCUpdates = true
	validated, err := config.Validated()
	if err != nil {
		t.Fatal("explicit existing OIDC class update selection rejected", err)
	}
	wire, err = json.Marshal(validated.ManagedClients)
	if err != nil || !strings.Contains(string(wire), `"ConfidentialPairwiseUpdates":true`) || !strings.Contains(string(wire), `"PublicOIDCClaimsUpdates":true`) {
		t.Fatal("canonical full policy lost explicit operation selection", err)
	}
}

func FuzzRetainedOIDCUpdateScopeCeilings(f *testing.F) {
	owner, _ := oauth.NewPlatformOwner("platform")
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	catalog, _ := oauth.NewScopeCatalog([]string{"identity:read"})
	p := oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: catalog, PublicClients: true, PublicOIDC: true, PublicOIDCUpdates: true, PublicOIDCClaimsUpdates: true, PublicOIDCScopes: []string{"openid", "profile", "email", "phone"}, ConfidentialOIDC: true, ConfidentialOIDCUpdates: true}
	token, _ := session.NewToken(32)
	wire, _ := token.Reveal()
	csrf, _ := session.NewCSRFToken()
	key, _ := identity.NewIdempotencyKey([]byte("retained-oidc-fuzz"))
	base := oauth.ClientManagementRequest{Owner: owner, TenantID: "tenant", Session: auth.NewBearerCredential(wire), CSRF: csrf, Origin: issuer.String(), Network: "192.0.2.1", RequestKey: key, ClientID: "managed.abcdefghijklmnopqrstuw", Version: 1}
	for _, extra := range []string{"", "profile", "email", "phone", "address", "openid", "identity:read"} {
		f.Add(extra, true)
		f.Add(extra, false)
	}
	f.Fuzz(func(t *testing.T, extra string, public bool) {
		request := oauth.ClientUpdateRequest{Management: base, Redirects: []string{"https://client.example/cb"}, Scopes: []string{"openid"}}
		request.Management.Public = public
		if extra != "" {
			request.Scopes = append(request.Scopes, extra)
		}
		out, err := oauth.ValidateClientUpdateRequest(request, p, issuer)
		if err != nil {
			return
		}
		allowedExtra := extra == "" || public && (extra == "profile" || extra == "email" || extra == "phone")
		if !allowedExtra || out.Management.Public != public || !slices.Contains(out.Scopes, "openid") {
			t.Fatal("retained OIDC metadata escaped its closed class/scope ceiling")
		}
		request.Scopes[0] = "changed"
		if !slices.Contains(out.Scopes, "openid") {
			t.Fatal("retained OIDC replacement borrowed mutable scopes")
		}
	})
}
