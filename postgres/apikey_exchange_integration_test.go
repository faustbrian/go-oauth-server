//go:build integration && oauthflow

package oauthpostgres_test

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestNativeAPIKeyExchangePreservesUserOwnerKeyActorAndRootRevocation(t *testing.T) {
	h := apiKeyExchangeFixture(t)
	id, err := identity.NewIdempotencyKey([]byte("m33-original-modern-user-source"))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := h.keys.Create(h.f.ctx, apikey.CreateRequest{Authentication: h.manager, IdempotencyKey: id, Name: "m33-source", Permissions: []string{"identity:read", "identity:write"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.10"})
	if err != nil {
		t.Fatal("genuine modern USER key creation", err)
	}
	key, ok := issued.Record()
	if !ok || key.Owner.Spec().Kind != apikey.OwnerUser || key.Owner.Spec().UserID != h.user {
		t.Fatal("actual issued source did not retain its user owner")
	}
	sourceWire, err := issued.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, SubjectToken: sourceWire, SubjectTokenType: oauth.APIKeyTokenType, Resource: h.client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.10"}
	started := time.Now()
	first, err := h.service.Token(h.f.ctx, request)
	request.SubjectToken, sourceWire = "", ""
	if err != nil || first.Outcome != identity.CommitOutcomeCommitted || first.IssuedTokenType != oauth.AccessTokenType || first.RefreshToken != (oauth.Token{}) || first.IDToken != (oauth.IDToken{}) || !slices.Equal(first.Scopes, []string{"identity:read"}) || first.ExpiresAt.After(started.Add(5*time.Minute)) || first.ExpiresAt.After(key.ExpiresAt) {
		t.Fatal("real USER key did not produce narrower access-only OAuth authority", err)
	}
	wire, err := first.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	wires := []string{wire}
	previousArtifact := checkAPIKeyLineage(t, h, first, key, 1, string(key.ID), oauth.APIKeyTokenType)
	parentExpiry := first.ExpiresAt
	for depth := uint8(2); depth <= 4; depth++ {
		request.SubjectToken, request.SubjectTokenType = wires[len(wires)-1], oauth.AccessTokenType
		child, err := h.service.Token(h.f.ctx, request)
		if err != nil || child.Outcome != identity.CommitOutcomeCommitted || child.ExpiresAt.After(parentExpiry) || child.RefreshToken != (oauth.Token{}) || !slices.Equal(child.Scopes, first.Scopes) {
			t.Fatal("derived API-key access changed authority or exceeded its parent", depth, err)
		}
		previousArtifact = checkAPIKeyLineage(t, h, child, key, depth, previousArtifact, oauth.AccessTokenType)
		parentExpiry = child.ExpiresAt
		wire, err := child.AccessToken.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		wires = append(wires, wire)
	}
	request.SubjectToken = wires[len(wires)-1]
	if out, err := h.service.Token(h.f.ctx, request); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("API-key lineage exceeded four exchanges")
	}
	request.SubjectToken, request.Scopes = wires[0], []string{"identity:write"}
	if out, err := h.service.Token(h.f.ctx, request); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("child recovered a root permission removed by its parent")
	}
	for _, token := range wires {
		out, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: token})
		if err != nil || !out.Active || out.Subject != string(h.user) || out.ClientID != h.client.ID || out.Resource != h.client.Resource || !slices.Equal(out.Scopes, []string{"identity:read"}) {
			t.Fatal("actual key descendant lost user/caller/resource separation", err)
		}
	}
	current, err := h.keys.Get(h.f.ctx, apikey.GetRequest{Authentication: h.manager, KeyID: key.ID})
	if err != nil || current.Record.AuthorityVersion != key.AuthorityVersion || current.Record.RootVersion != key.RootVersion || !slices.Equal(current.Record.Grant, key.Grant) {
		t.Fatal("OAuth delegation changed its API-key root or immutable grant", err)
	}
	revoke, err := identity.NewIdempotencyKey([]byte("m33-revoke-original-modern-source"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := h.keys.Revoke(h.f.ctx, apikey.Revocation{Authentication: h.manager, IdempotencyKey: revoke, KeyID: key.ID, ExpectedVersion: current.Record.Version, Network: "192.0.2.10"})
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual original key revocation", err)
	}
	for _, token := range wires {
		out, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: token})
		if err != nil || out.Active || out.ClientID != "" || out.Subject != "" || out.Resource != "" || out.Scopes != nil || !out.ExpiresAt.IsZero() || out.Issuer.String() != "" {
			t.Fatal("revoked API-key root retained descendant authority or inactive metadata", err)
		}
	}
	request.SubjectToken, request.Scopes = wires[0], []string{"identity:read"}
	if out, err := h.service.Token(h.f.ctx, request); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("revoked original root allowed another descendant")
	}
}

func checkAPIKeyLineage(t *testing.T, h apiKeyNativeExchange, issued oauth.TokenResult, key apikey.Record, depth uint8, parent, parentType string) string {
	t.Helper()
	var artifact, storedParent, user, client string
	var payload []byte
	err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT a.artifact_id,COALESCE(a.parent_artifact_id,''),g.user_id,g.client_id,a.payload FROM oauth_store.artifacts a JOIN oauth_store.grants g USING(grant_id) WHERE a.issued_by=$1 AND a.kind=$2`, string(issued.CommandID), int16(oauth.TokenAccess)).Scan(&artifact, &storedParent, &user, &client, &payload)
	if err != nil {
		t.Fatal("actual delegated artifact persistence", err)
	}
	var stored struct {
		APIKeyExchange *struct {
			RootID, ParentID, ParentTokenType string
			RootVersion                       uint64
			Depth                             uint8
		}
	}
	if json.Unmarshal(payload, &stored) != nil || stored.APIKeyExchange == nil || stored.APIKeyExchange.RootID != string(key.RootID) || stored.APIKeyExchange.RootVersion != key.RootVersion || stored.APIKeyExchange.ParentID != parent || stored.APIKeyExchange.ParentTokenType != parentType || stored.APIKeyExchange.Depth != depth || user != string(h.user) || client != h.client.ID || depth == 1 && storedParent != "" || depth > 1 && storedParent != parent {
		t.Fatal("durable API-key root/parent/owner/caller lineage changed")
	}
	return artifact
}
