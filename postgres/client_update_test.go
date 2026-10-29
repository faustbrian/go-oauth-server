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
