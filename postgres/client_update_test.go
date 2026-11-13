package oauthpostgres

import (
	"errors"
	"testing"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestManagedMetadataReplacementCannotChangeAnOIDCSource(t *testing.T) {
	store, execution, id := cursorReadFixture()
	store.config.Protocol.Resource = "https://api.example"
	client := oauth.Client{ID: id, Owner: execution.Request.Owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: store.config.Protocol.Resource, Redirects: store.config.Protocol.ManagedClients.Redirects, Scopes: []string{"openid"}}
	replacement := &clientReplacement{Redirects: client.Redirects, Scopes: []string{"identity:read"}}
	if out, err := store.updatedClient(client, replacement); !errors.Is(err, oauth.ErrAccessDenied) || out.ID != "" {
		t.Fatal("native replacement transformed an excluded original OIDC class", err)
	}
	client.Scopes = []string{"identity:read"}
	if out, err := store.updatedClient(client, replacement); err != nil || out.Version != client.Version+1 {
		t.Fatal("native OIDC exclusion broke existing OAuth replacement", err)
	}
}

func TestPublicOIDCMetadataReplacementUsesExplicitOriginalProfile(t *testing.T) {
	store, execution, id := cursorReadFixture()
	store.config.Protocol.Resource = "https://api.example"
	store.config.PublicClients = true
	policy := store.config.Protocol.ManagedClients
	policy.PublicClients, policy.PublicOIDC, policy.PublicOIDCUpdates = true, true, true
	client := oauth.Client{ID: id, Owner: execution.Request.Owner, Version: 1, Public: true, AuthenticationMethod: "none", Resource: store.config.Protocol.Resource, Redirects: policy.Redirects, Scopes: []string{"openid"}}
	replacement := &clientReplacement{Redirects: client.Redirects, Scopes: []string{"openid"}}
	selectedPolicy := store.managementPolicy()
	updated, err := store.updatedClient(client, replacement)
	if err != nil || updated.Version != 2 || !updated.Public || updated.AuthenticationMethod != "none" || updated.SubjectRegistration != nil || updated.Resource != client.Resource || updated.Owner != client.Owner {
		t.Fatal("selected native public OIDC replacement unavailable", err)
	}
	policy.PublicOIDCUpdates = false
	if store.managementPolicy() != selectedPolicy {
		t.Fatal("update-only selection stranded original policy fingerprints")
	}
	if out, err := store.updatedClient(client, replacement); !errors.Is(err, oauth.ErrAccessDenied) || out.ID != "" {
		t.Fatal("creation selection implicitly selected native replacement", err)
	}
}
