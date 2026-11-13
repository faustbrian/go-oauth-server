package oauthserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestOwningClientIntrospectionAllowsAbsentSubjectWithoutInventingUSER(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	config, secret := confidentialCoreConfig(t)
	config.OwningClientIntrospection = true
	projection := oauth.IntrospectResult{Active: true, ClientID: config.Clients[0].ID, Resource: config.Resource, Issuer: config.Issuer, Scopes: []string{"identity:read"}, ExpiresAt: now.Add(time.Minute)}
	store := selectedIntrospectionStore{read: func(context.Context, oauth.IntrospectionCommand) (oauth.IntrospectResult, error) {
		return projection, nil
	}}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.IntrospectRequest{ClientID: config.Clients[0].ID, ClientAuthentication: mustClientAuth(t, config.Clients[0].ID, secret), Token: "borrowed-opaque-token"}
	out, err := service.Introspect(context.Background(), request)
	if err != nil || !out.Active || out.Subject != "" || out.ClientID != request.ClientID || out.Resource != config.Resource {
		t.Fatal("active integration metadata required an invented USER subject", err)
	}
	wire, err := json.Marshal(out)
	if err != nil || strings.Contains(string(wire), `"sub"`) {
		t.Fatal("absent subject was disclosed as a fabricated principal", err)
	}
	projection.Subject = "\x00"
	if out, err := service.Introspect(context.Background(), request); !errors.Is(err, oauth.ErrUnavailable) || out.Active || out.Subject != "" {
		t.Fatal("optional subject admitted malformed nonempty metadata", err)
	}
	projection.Subject = "actual-user"
	if out, err := service.Introspect(context.Background(), request); err != nil || out.Subject != "actual-user" {
		t.Fatal("optional integration subject changed existing actual USER metadata", err)
	}
}
