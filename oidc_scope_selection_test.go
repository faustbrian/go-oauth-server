package oauthserver_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestOIDCClaimNarrowingRejectsBeforeConsentOrRefreshOwner(t *testing.T) {
	for _, managed := range []bool{false, true} {
		class := map[bool]string{false: "static", true: "managed"}[managed]
		for _, claim := range []string{"email", "profile", "phone"} {
			for _, operation := range []string{"consent", "refresh"} {
				t.Run(class+"/"+claim+"/"+operation, func(t *testing.T) {
					service, bearer, client, calls, selected := oidcScopeSelectionFixture(t, managed)
					material, _ := oauth.NewToken()
					wire, _ := material.Reveal()
					invoke := func(scopes []string) error {
						return invokeScopeSelection(t, service, bearer, client, operation, wire, scopes)
					}
					if err := invoke([]string{claim}); !errors.Is(err, oauth.ErrInvalidScope) || *calls != 0 {
						t.Fatalf("claim-only %s reached its consuming owner: invalid_scope=%t owner_calls=%d", operation, errors.Is(err, oauth.ErrInvalidScope), *calls)
					}
					if err := invoke([]string{"openid", claim}); err != nil || *calls != 1 || len(*selected) != 2 || !slices.Contains(*selected, "openid") || !slices.Contains(*selected, claim) {
						t.Fatal("rejected claim-only request stranded valid same-owner narrowing", err)
					}
				})
			}
		}
	}
}

func TestStaticOIDCGrantCanNarrowToPureOAuthWithoutOpenID(t *testing.T) {
	for _, operation := range []string{"consent", "refresh"} {
		t.Run(operation, func(t *testing.T) {
			service, bearer, client, calls, selected := oidcScopeSelectionFixture(t, false)
			material, _ := oauth.NewToken()
			wire, _ := material.Reveal()
			if err := invokeScopeSelection(t, service, bearer, client, operation, wire, []string{"identity:read"}); err != nil || *calls != 1 || !slices.Equal(*selected, []string{"identity:read"}) {
				t.Fatal("pure OAuth narrowing inherited an unwanted openid requirement", err)
			}
		})
	}
}

// This root-boundary fixture observes whether a request reaches the consuming
// adapter. Real native one-use/family persistence is exercised by integration.
func oidcScopeSelectionFixture(t *testing.T, managed bool) (*oauth.Service, auth.BearerCredential, oauth.Client, *int, *[]string) {
	t.Helper()
	sessions, bearer, now, _ := coreSessionFixture(t)
	config := coreConfig(t, now)
	config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "profile", "email", "phone"})
	client := config.Clients[0]
	client.Scopes = []string{"email", "openid", "phone", "profile"}
	if managed {
		client.ID = "managed.abcdefghijklmnopqrstuw"
		config.ManagedClients = &oauth.ManagedClientPolicy{Owner: client.Owner, TenantID: "tenant", Redirects: client.Redirects, Scopes: config.Scopes, PublicClients: true, PublicOIDC: true, PublicOIDCScopes: slices.Clone(client.Scopes)}
	} else {
		client.Scopes = append(client.Scopes, "identity:read")
		config.Clients[0] = client
	}
	calls, selected := 0, []string(nil)
	store := managedOIDCTestStore{client: client}
	store.continuation = func(_ context.Context, command oauth.ContinuationCommand) (oauth.AuthorizeResult, error) {
		calls++
		selected = slices.Clone(command.Request.Scopes)
		return oauth.AuthorizeResult{Outcome: oauth.AuthorizationHistorical}, nil
	}
	store.token = func(_ context.Context, command oauth.TokenCommand) (oauth.TokenResult, error) {
		calls++
		selected = slices.Clone(command.Request.Scopes)
		return oauth.TokenResult{Outcome: identity.CommitOutcomeUnknown}, nil
	}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store, Clients: store, OIDC: publicClaimsExtension{subjectExtension{}}})
	if err != nil {
		t.Fatal(err)
	}
	return service, bearer, client, &calls, &selected
}

func invokeScopeSelection(t *testing.T, service *oauth.Service, browser auth.BearerCredential, client oauth.Client, operation, wire string, scopes []string) error {
	t.Helper()
	if operation == "refresh" {
		_, err := service.Token(context.Background(), oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: wire, Scopes: scopes, Network: "192.0.2.1"})
		return err
	}
	csrf, _ := session.NewCSRFToken()
	_, err := service.Continue(context.Background(), oauth.ContinueRequest{TenantID: "tenant", ClientID: client.ID, Session: browser, CSRF: csrf, Continuation: wire, Scopes: scopes, Origin: "https://issuer.example", Network: "192.0.2.1", Approve: true})
	return err
}
