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

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestManagedConfidentialPairwiseSafePageRetainsImmutableRegistration(t *testing.T) {
	testManagedPairwiseSafePage(t, false)
}

func TestManagedPublicPairwiseSafePageRetainsImmutableRegistration(t *testing.T) {
	testManagedPairwiseSafePage(t, true)
}

func testManagedPairwiseSafePage(t *testing.T, public bool) {
	t.Helper()
	c := coreConfig(t, time.Now())
	client := c.Clients[0]
	client.ID = "managed.abcdefghijklmnopqrstuw"
	client.Public, client.AuthenticationMethod = false, "client_secret_basic"
	if public {
		client.Public, client.AuthenticationMethod = true, "none"
	}
	client.Scopes = []string{"openid"}
	registration, err := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	if err != nil {
		t.Fatal(err)
	}
	client.SubjectRegistration = &registration
	page, err := oauth.NewClientListPage([]oauth.Client{client})
	if err != nil {
		t.Fatal("safe managed metadata rejected the selected single-host pairwise class", err)
	}
	original := registration
	foreign, err := oauth.NewOIDCSubjectRegistration("pairwise", "other.example", "subjects", 1)
	if err != nil {
		t.Fatal(err)
	}
	registration = foreign
	items := page.Items()
	if len(items) != 1 || items[0].ID != client.ID || items[0].Public != public || items[0].AuthenticationMethod != client.AuthenticationMethod || items[0].SubjectRegistration == nil || *items[0].SubjectRegistration != original || !slices.Equal(items[0].Scopes, []string{"openid"}) {
		t.Fatal("safe pairwise metadata lost exact immutable class or registration")
	}
	*items[0].SubjectRegistration = foreign
	items[0].Scopes[0] = "email"
	if retained := page.Items(); retained[0].SubjectRegistration == nil || *retained[0].SubjectRegistration != original || !slices.Equal(retained[0].Scopes, []string{"openid"}) {
		t.Fatal("safe pairwise metadata aliases caller-owned registration or scopes")
	}
}

func TestManagedConfidentialPairwiseOldValidatorCannotDiscardRegistration(t *testing.T) {
	sessions, bearer, now, _ := coreSessionFixture(t)
	c := coreConfig(t, now)
	c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
	client := c.Clients[0]
	client.ID, client.Public, client.AuthenticationMethod, client.Scopes = "managed.abcdefghijklmnopqrstuw", false, "client_secret_basic", []string{"openid"}
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, ConfidentialOIDC: true, PairwiseRegistrations: []oauth.OIDCSubjectRegistration{registration}}
	writes := 0
	store := managedOIDCTestStore{}
	store.call = func(_ context.Context, e oauth.ClientManagementExecution) (oauth.ClientManagementResult, error) {
		// Existing native writers use this validator before constructing their
		// original registration shape, which has no subject-registration field.
		if _, err := oauth.ValidateClientManagementRequest(e.Request, false, *c.ManagedClients, c.Issuer); err != nil {
			return oauth.ClientManagementResult{}, err
		}
		writes++
		return oauth.ClientManagementResult{Client: client, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted}}, nil
	}
	service, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store, OIDC: subjectExtension{}})
	if err != nil {
		t.Fatal(err)
	}
	csrf, _ := session.NewCSRFToken()
	key, _ := identity.NewIdempotencyKey([]byte("old-pairwise-writer-denied"))
	out, err := service.ClientCreate(context.Background(), oauth.ClientManagementRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Redirects: client.Redirects, Scopes: client.Scopes, SubjectRegistration: &registration})
	if err == nil || writes != 0 || out.Client.ID != "" || out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("old native validation accepted a pairwise request before discarding its registration", err)
	}
}

func TestManagedConfidentialPairwiseRejectsUnsupportedConfiguration(t *testing.T) {
	for _, variant := range []string{"duplicate", "over-limit", "without-confidential-oidc", "sector-uri", "public-subject"} {
		t.Run(variant, func(t *testing.T) {
			c := coreConfig(t, time.Now())
			c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
			client := c.Clients[0]
			registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, ConfidentialOIDC: true, PairwiseRegistrations: []oauth.OIDCSubjectRegistration{registration}}
			switch variant {
			case "duplicate":
				c.ManagedClients.PairwiseRegistrations = append(c.ManagedClients.PairwiseRegistrations, registration)
			case "over-limit":
				c.ManagedClients.PairwiseRegistrations = make([]oauth.OIDCSubjectRegistration, 65)
				for i := range c.ManagedClients.PairwiseRegistrations {
					c.ManagedClients.PairwiseRegistrations[i], _ = oauth.NewOIDCSubjectRegistration("pairwise", fmt.Sprintf("client%d.example", i), "subjects", 1)
				}
			case "without-confidential-oidc":
				c.ManagedClients.ConfidentialOIDC = false
			case "sector-uri":
				wire := `{"Type":"pairwise","SectorHost":"client.example","PolicyID":"subjects","PolicyVersion":1,"SectorIdentifierURI":"https://client.example/sector.json","RedirectSet":"` + strings.Repeat("01", 32) + `"}`
				if err := json.Unmarshal([]byte(wire), &registration); err != nil {
					t.Fatal("stored URI registration setup failed", err)
				}
				c.ManagedClients.PairwiseRegistrations[0] = registration
			case "public-subject":
				c.ManagedClients.PairwiseRegistrations[0], _ = oauth.NewOIDCSubjectRegistration("public", "", "subjects", 1)
			}
			if _, err := c.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
				t.Fatal("unsupported managed pairwise ceiling constructed", err)
			}
		})
	}
}

func TestManagedConfidentialPairwiseNilPreservesDefaultPolicyBytes(t *testing.T) {
	c := coreConfig(t, time.Now())
	client := c.Clients[0]
	p := oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, ConfidentialOIDC: true}
	wire, err := json.Marshal(p)
	const original = `{"Owner":{},"TenantID":"tenant","Redirects":["https://client.example/cb"],"PostLogoutRedirects":null,"Scopes":{},"ConfidentialOIDC":true,"DeviceAuthorization":false}`
	if err != nil || string(wire) != original {
		t.Fatal("nil pairwise selection changed the original default-subject policy bytes", err)
	}
}

func TestManagedConfidentialPairwiseExactTrustOwnsCreateReadAndAuthorization(t *testing.T) {
	testManagedPairwiseExactTrust(t, false)
}

func TestManagedPublicPairwiseExactTrustOwnsCreateReadAndAuthorization(t *testing.T) {
	testManagedPairwiseExactTrust(t, true)
}

func testManagedPairwiseExactTrust(t *testing.T, public bool) {
	t.Helper()
	for _, variant := range []string{"selected", "default", "foreign-policy", "foreign-version", "other-class", "device", "extra-claim", "foreign-redirect", "uncomposed"} {
		t.Run(variant, func(t *testing.T) {
			sessions, bearer, now, _ := coreSessionFixture(t)
			c := coreConfig(t, now)
			c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
			client := c.Clients[0]
			client.ID, client.Scopes = "managed.abcdefghijklmnopqrstuw", []string{"openid"}
			client.Public, client.AuthenticationMethod = false, "client_secret_basic"
			if public {
				client.Public, client.AuthenticationMethod = true, "none"
			}
			registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
			client.SubjectRegistration = &registration
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, PublicClients: true, PublicOIDC: true, ConfidentialOIDC: true, DeviceAuthorization: true, PairwiseRegistrations: []oauth.OIDCSubjectRegistration{registration}}
			if public {
				c.ManagedClients.PairwiseRegistrations = nil
				c.ManagedClients.PublicPairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
			}
			switch variant {
			case "default":
				c.ManagedClients.PairwiseRegistrations = nil
				c.ManagedClients.PublicPairwiseRegistrations = nil
			case "foreign-policy":
				registration, _ = oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "foreign", 1)
			case "foreign-version":
				registration, _ = oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 2)
			case "other-class":
				client.Public, client.AuthenticationMethod = !public, "none"
				if public {
					client.AuthenticationMethod = "client_secret_basic"
				}
			case "device":
				client.DeviceAuthorization = true
			case "extra-claim":
				client.Scopes = []string{"openid", "email"}
			case "foreign-redirect":
				client.Redirects = []string{"https://other.example/callback"}
				c.ManagedClients.Redirects = append(slices.Clone(c.ManagedClients.Redirects), client.Redirects...)
			}
			calls := 0
			store := managedOIDCTestStore{client: client}
			store.call = func(_ context.Context, e oauth.ClientManagementExecution) (oauth.ClientManagementResult, error) {
				calls++
				if _, err := oauth.ValidatePairwiseClientManagementRequest(e.Request, *c.ManagedClients, c.Issuer); err != nil {
					t.Fatal("new native opt-in rejected exact pairwise request", err)
				}
				if e.Request.SubjectRegistration == nil || *e.Request.SubjectRegistration != registration || e.Request.SubjectRegistration == client.SubjectRegistration {
					t.Fatal("creation lost exact independently owned registration")
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
			candidate := oauth.OIDCSubjectCandidate{Registration: registration, Subject: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE", KeyVersion: 1, KeyCommitment: [32]byte{1}}
			store.authorize = func(_ context.Context, command oauth.AuthorizationCommand) (oauth.AuthorizeResult, error) {
				if command.SubjectCandidate == nil || *command.SubjectCandidate != candidate || command.Client.SubjectRegistration == nil || *command.Client.SubjectRegistration != registration {
					t.Fatal("authorization lost child-owned candidate or exact registration")
				}
				continuation, _ := oauth.NewToken()
				return oauth.AuthorizeResult{Outcome: oauth.ConsentRequired, Continuation: continuation, ExpiresAt: now.Add(c.ContinuationTTL)}, nil
			}
			deps := oauth.Dependencies{Sessions: sessions, Store: store, Clients: store}
			if variant != "uncomposed" {
				deps.OIDC = subjectExtension{validate: func(in oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error) {
					if in.Client.SubjectRegistration == nil || *in.Client.SubjectRegistration != registration {
						t.Fatal("OIDC child did not receive exact managed registration")
					}
					return oauth.OIDCAuthorizationProjection{Accepted: true, SubjectCandidate: &candidate}, nil
				}}
			}
			service, err := oauth.NewService(c, deps)
			if err != nil {
				t.Fatal(err)
			}
			csrf, _ := session.NewCSRFToken()
			key, _ := identity.NewIdempotencyKey([]byte("managed-pairwise-create"))
			created, createErr := service.ClientCreate(context.Background(), oauth.ClientManagementRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Public: client.Public, DeviceAuthorization: client.DeviceAuthorization, Redirects: client.Redirects, Scopes: client.Scopes, SubjectRegistration: client.SubjectRegistration})
			read := oauth.ClientReadRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, ClientID: client.ID}
			got, getErr := service.ClientGet(context.Background(), read)
			read.ClientID, read.Limit = "", 1
			listed, listErr := service.ClientList(context.Background(), read)
			request := coreAuthorization()
			request.ClientID, request.RedirectURI, request.Scopes, request.Nonce = client.ID, client.Redirects[0], client.Scopes, "pairwise-nonce"
			authorized, authErr := service.Authorize(context.Background(), oauth.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: request, Network: "192.0.2.1"})
			if variant != "selected" {
				if calls != 0 || createErr == nil || getErr == nil || listErr == nil || authErr == nil || created.Client.ID != "" || got.Client.ID != "" || len(listed.Page.Items()) != 0 || authorized.Outcome != 0 {
					t.Fatal("unselected pairwise registration escaped trusted policy", createErr, getErr, listErr, authErr)
				}
				return
			}
			if calls != 1 || createErr != nil || getErr != nil || listErr != nil || authErr != nil || created.Client.SubjectRegistration == nil || *created.Client.SubjectRegistration != registration || got.Client.SubjectRegistration == nil || *got.Client.SubjectRegistration != registration || len(listed.Page.Items()) != 1 || authorized.Outcome != oauth.ConsentRequired {
				t.Fatal("selected managed pairwise public path disconnected", createErr, getErr, listErr, authErr)
			}
			if _, err := created.Secret.Reveal(); (err == nil) == public {
				t.Fatal("pairwise creation did not preserve class-bound secret disclosure")
			}
		})
	}
}

func TestManagedConfidentialPairwiseConfigurationAndRequestCopies(t *testing.T) {
	testManagedPairwiseConfigurationAndRequestCopies(t, false)
}

func TestManagedPublicPairwiseConfigurationAndRequestCopies(t *testing.T) {
	testManagedPairwiseConfigurationAndRequestCopies(t, true)
}

func testManagedPairwiseConfigurationAndRequestCopies(t *testing.T, public bool) {
	t.Helper()
	_, bearer, now, _ := coreSessionFixture(t)
	c := coreConfig(t, now)
	c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
	client := c.Clients[0]
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, ConfidentialOIDC: true, PairwiseRegistrations: []oauth.OIDCSubjectRegistration{registration}}
	if public {
		c.ManagedClients.ConfidentialOIDC = false
		c.ManagedClients.PairwiseRegistrations = nil
		c.ManagedClients.PublicClients, c.ManagedClients.PublicOIDC = true, true
		c.ManagedClients.PublicPairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
	}
	validated, err := c.Validated()
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "foreign", 1)
	selected := c.ManagedClients.PairwiseRegistrations
	retained := validated.ManagedClients.PairwiseRegistrations
	if public {
		selected = c.ManagedClients.PublicPairwiseRegistrations
		retained = validated.ManagedClients.PublicPairwiseRegistrations
	}
	selected[0] = foreign
	if !slices.Equal(retained, []oauth.OIDCSubjectRegistration{registration}) {
		t.Fatal("trusted registration ceiling aliases mutable startup configuration")
	}
	csrf, _ := session.NewCSRFToken()
	key, _ := identity.NewIdempotencyKey([]byte("managed-pairwise-copy"))
	r := oauth.ClientManagementRequest{Owner: client.Owner, TenantID: "tenant", Session: bearer, CSRF: csrf, Origin: c.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Public: public, Redirects: client.Redirects, Scopes: []string{"openid"}, SubjectRegistration: &registration}
	request, err := oauth.ValidatePairwiseClientManagementRequest(r, *validated.ManagedClients, c.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	registration = foreign
	if request.SubjectRegistration == nil || request.SubjectRegistration.PolicyID() != "subjects" {
		t.Fatal("validated request aliases mutable submitted registration")
	}
	if validated.ManagedClients.AllowsRegistration(public, false, []string{"openid"}, &foreign) || !validated.ManagedClients.AllowsRegistration(public, false, []string{"openid"}, nil) {
		t.Fatal("pairwise ceiling broadened foreign policy or withdrew original default subjects")
	}
}

func TestManagedPublicPairwiseRejectsUnsupportedConfiguration(t *testing.T) {
	for _, variant := range []string{"without-public-clients", "without-public-oidc", "duplicate", "over-limit", "sector-uri", "public-subject"} {
		t.Run(variant, func(t *testing.T) {
			c := coreConfig(t, time.Now())
			c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
			client := c.Clients[0]
			registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
			c.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: c.Scopes, PublicClients: true, PublicOIDC: true, PublicPairwiseRegistrations: []oauth.OIDCSubjectRegistration{registration}}
			switch variant {
			case "without-public-clients":
				c.ManagedClients.PublicClients = false
			case "without-public-oidc":
				c.ManagedClients.PublicOIDC = false
			case "duplicate":
				c.ManagedClients.PublicPairwiseRegistrations = append(c.ManagedClients.PublicPairwiseRegistrations, registration)
			case "over-limit":
				c.ManagedClients.PublicPairwiseRegistrations = make([]oauth.OIDCSubjectRegistration, 65)
				for i := range c.ManagedClients.PublicPairwiseRegistrations {
					c.ManagedClients.PublicPairwiseRegistrations[i], _ = oauth.NewOIDCSubjectRegistration("pairwise", fmt.Sprintf("client%d.example", i), "subjects", 1)
				}
			case "sector-uri":
				wire := `{"Type":"pairwise","SectorHost":"client.example","PolicyID":"subjects","PolicyVersion":1,"SectorIdentifierURI":"https://client.example/sector.json","RedirectSet":"` + strings.Repeat("01", 32) + `"}`
				if err := json.Unmarshal([]byte(wire), &registration); err != nil {
					t.Fatal("stored URI registration setup failed", err)
				}
				c.ManagedClients.PublicPairwiseRegistrations[0] = registration
			case "public-subject":
				c.ManagedClients.PublicPairwiseRegistrations[0], _ = oauth.NewOIDCSubjectRegistration("public", "", "subjects", 1)
			}
			if _, err := c.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
				t.Fatal("unsupported public pairwise ceiling constructed", err)
			}
		})
	}
}
