package oauthserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

type publicClaimsExtension struct{ subjectExtension }

func (publicClaimsExtension) Scopes() oauth.ScopeCatalog {
	catalog, _ := oauth.NewOIDCScopeCatalog([]string{"openid", "profile", "email", "phone"})
	return catalog
}

func TestManagedPublicClaimsSafePageRetainsRegistrationScopes(t *testing.T) {
	client := coreConfig(t, time.Now()).Clients[0]
	client.ID, client.Scopes = "managed.abcdefghijklmnopqrstuw", []string{"email", "openid", "phone", "profile"}
	page, err := oauth.NewClientListPage([]oauth.Client{client})
	if err != nil {
		t.Fatal("safe metadata rejected managed public account-claims registration", err)
	}
	items := page.Items()
	if len(items) != 1 || !items[0].Public || items[0].AuthenticationMethod != "none" || items[0].SubjectRegistration != nil || !slices.Equal(items[0].Scopes, client.Scopes) {
		t.Fatal("safe account-claims metadata changed registered class/scopes/subject")
	}
	items[0].Scopes[0] = "address"
	if !slices.Equal(page.Items()[0].Scopes, client.Scopes) {
		t.Fatal("safe account-claims metadata aliases returned scope slices")
	}
}

func TestManagedPublicClaimsExactCeilingOwnsCreateReadAndAuthorization(t *testing.T) {
	for _, variant := range []string{"selected", "selected-email", "selected-name", "selected-phone", "selected-openid", "default", "narrow-ceiling", "confidential", "pairwise", "device", "without-openid", "address", "offline", "mixed-oauth", "uncomposed"} {
		t.Run(variant, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			config := coreConfig(t, now)
			config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "profile", "email", "phone"})
			client := config.Clients[0]
			client.ID, client.Scopes = "managed.abcdefghijklmnopqrstuw", []string{"email", "openid", "phone", "profile"}
			policy := &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: config.Scopes, PublicClients: true, PublicOIDC: true, ConfidentialOIDC: true, PublicOIDCScopes: slices.Clone(client.Scopes), DeviceAuthorization: true}
			config.ManagedClients = policy
			switch variant {
			case "selected-email":
				client.Scopes = []string{"email", "openid"}
				policy.PublicOIDCScopes = slices.Clone(client.Scopes)
			case "selected-name":
				client.Scopes = []string{"openid", "profile"}
				policy.PublicOIDCScopes = slices.Clone(client.Scopes)
			case "selected-phone":
				client.Scopes = []string{"openid", "phone"}
				policy.PublicOIDCScopes = slices.Clone(client.Scopes)
			case "selected-openid":
				client.Scopes = []string{"openid"}
				policy.PublicOIDCScopes = slices.Clone(client.Scopes)
			case "default":
				policy.PublicOIDCScopes = nil
			case "narrow-ceiling":
				policy.PublicOIDCScopes = []string{"openid", "email"}
			case "confidential":
				client.Public, client.AuthenticationMethod = false, "client_secret_basic"
			case "pairwise":
				registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
				policy.PublicPairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
				client.SubjectRegistration = &registration
			case "device":
				client.DeviceAuthorization = true
			case "without-openid":
				client.Scopes = []string{"profile"}
			case "address":
				client.Scopes = []string{"openid", "address"}
			case "offline":
				client.Scopes = []string{"openid", "offline_access"}
			case "mixed-oauth":
				client.Scopes = []string{"openid", "identity:read"}
			}
			store := managedOIDCTestStore{client: client}
			store.call = func(_ context.Context, execution oauth.ClientManagementExecution) (oauth.ClientManagementResult, error) {
				if !execution.Request.Public || execution.Request.SubjectRegistration != nil || !slices.Equal(execution.Request.Scopes, client.Scopes) || execution.ValidateAt(now) != nil {
					t.Fatal("public account-claims creation lost exact registration/custody")
				}
				secret, _ := oauth.NewToken()
				return oauth.ClientManagementResult{Client: client, Secret: secret, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}, nil
			}
			store.get = func(context.Context, oauth.ClientReadExecution) (oauth.ClientGetResult, error) {
				return oauth.ClientGetResult{Client: client}, nil
			}
			store.list = func(context.Context, oauth.ClientReadExecution) (oauth.ClientListResult, error) {
				page, err := oauth.NewClientListPage([]oauth.Client{client})
				return oauth.ClientListResult{Page: page}, err
			}
			store.authorize = func(_ context.Context, command oauth.AuthorizationCommand) (oauth.AuthorizeResult, error) {
				if command.Client.ID != client.ID || command.OIDC == nil || !slices.Equal(command.Request.Scopes, client.Scopes) || command.Request.Nonce != "account-claims-nonce" {
					t.Fatal("managed account-claims authorization lost exact native/child bindings")
				}
				continuation, _ := oauth.NewToken()
				return oauth.AuthorizeResult{Outcome: oauth.ConsentRequired, Continuation: continuation, ExpiresAt: now.Add(config.ContinuationTTL)}, nil
			}
			dependencies := oauth.Dependencies{Sessions: sessions, Store: store, Clients: store}
			if variant != "uncomposed" {
				dependencies.OIDC = publicClaimsExtension{subjectExtension{validate: func(oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error) {
					return oauth.OIDCAuthorizationProjection{Accepted: true}, nil
				}}}
			}
			service, err := oauth.NewService(config, dependencies)
			if err != nil {
				t.Fatal(err)
			}
			csrf, _ := session.NewCSRFToken()
			key, _ := identity.NewIdempotencyKey([]byte("managed-public-account-claims"))
			request := oauth.ClientManagementRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: config.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Public: client.Public, Redirects: client.Redirects, Scopes: client.Scopes, DeviceAuthorization: client.DeviceAuthorization, SubjectRegistration: client.SubjectRegistration}
			created, createErr := service.ClientCreate(context.Background(), request)
			read := oauth.ClientReadRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, ClientID: client.ID}
			got, getErr := service.ClientGet(context.Background(), read)
			read.ClientID, read.Limit = "", 1
			listed, listErr := service.ClientList(context.Background(), read)
			authorization := coreAuthorization()
			authorization.ClientID, authorization.Scopes, authorization.Nonce = client.ID, client.Scopes, "account-claims-nonce"
			out, authorizeErr := service.Authorize(context.Background(), oauth.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: authorization, Network: "192.0.2.1"})
			if !slices.Contains([]string{"selected", "selected-email", "selected-name", "selected-phone", "selected-openid"}, variant) {
				if createErr == nil || getErr == nil || listErr == nil || authorizeErr == nil || created.Client.ID != "" || got.Client.ID != "" || len(listed.Page.Items()) != 0 || out.Outcome != 0 {
					t.Fatal("unselected managed account-claims variant escaped policy", createErr, getErr, listErr, authorizeErr)
				}
				return
			}
			if createErr != nil || getErr != nil || listErr != nil || authorizeErr != nil || created.Client.ID != client.ID || !slices.Equal(got.Client.Scopes, client.Scopes) || len(listed.Page.Items()) != 1 || out.Outcome != oauth.ConsentRequired {
				t.Fatal("selected managed public account-claims boundary disconnected", createErr, getErr, listErr, authorizeErr)
			}
			if _, err := created.Secret.Reveal(); err == nil {
				t.Fatal("public account-claims creation disclosed a client secret")
			}
		})
	}
}

func TestManagedPublicClaimsCeilingCopiesAndPreservesDefaultBytes(t *testing.T) {
	config := coreConfig(t, time.Now())
	config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "profile", "email", "phone"})
	client := config.Clients[0]
	policy := &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: config.Scopes, PublicClients: true, PublicOIDC: true}
	config.ManagedClients = policy
	wire, err := json.Marshal(policy)
	const original = `{"Owner":{},"TenantID":"tenant","Redirects":["https://client.example/cb"],"PostLogoutRedirects":null,"Scopes":{},"PublicClients":true,"PublicOIDC":true,"DeviceAuthorization":false}`
	if err != nil || string(wire) != original {
		t.Fatal("omitted public scope selection changed original policy bytes", err)
	}
	policy.PublicOIDCScopes = []string{"profile", "openid", "email", "phone"}
	validated, err := config.Validated()
	if err != nil {
		t.Fatal(err)
	}
	policy.PublicOIDCScopes[0] = "address"
	if !slices.Equal(validated.ManagedClients.PublicOIDCScopes, []string{"email", "openid", "phone", "profile"}) || !slices.Equal(validated.ManagedClients.Scopes.Scopes(), config.Scopes.Scopes()) {
		t.Fatal("public account-claims ceiling was not canonical/copied or altered OAuth scope ownership")
	}
}

func TestManagedPublicClaimsUnsupportedCeilingsFailConstruction(t *testing.T) {
	for _, variant := range []string{"without-public-oidc", "without-public-clients", "without-openid", "duplicate", "over-limit", "address", "offline", "mixed-oauth", "outside-global"} {
		t.Run(variant, func(t *testing.T) {
			config := coreConfig(t, time.Now())
			config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "profile", "email", "phone", "address", "offline_access"})
			client := config.Clients[0]
			policy := &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: config.Scopes, PublicClients: true, PublicOIDC: true, PublicOIDCScopes: []string{"openid", "profile", "email", "phone"}}
			config.ManagedClients = policy
			switch variant {
			case "without-public-oidc":
				policy.PublicOIDC = false
			case "without-public-clients":
				policy.PublicClients = false
			case "without-openid":
				policy.PublicOIDCScopes = []string{"profile"}
			case "duplicate":
				policy.PublicOIDCScopes = []string{"openid", "email", "email"}
			case "over-limit":
				policy.PublicOIDCScopes = []string{"openid", "profile", "email", "phone", "address"}
			case "address":
				policy.PublicOIDCScopes = []string{"openid", "address"}
			case "offline":
				policy.PublicOIDCScopes = []string{"openid", "offline_access"}
			case "mixed-oauth":
				policy.PublicOIDCScopes = []string{"openid", "identity:read"}
			case "outside-global":
				config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
			}
			if _, err := config.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
				t.Fatal("unsupported public account-claims ceiling constructed", err)
			}
		})
	}
}
