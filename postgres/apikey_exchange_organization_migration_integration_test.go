//go:build integration && oauthflow

package oauthpostgres_test

import (
	"testing"

	"github.com/faustbrian/go-identity/apikey"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestNativeOrganizationAPIKeyHistoryGatesActivationAndPreservesPopulatedUSER(t *testing.T) {
	h := apiKeyExchangeFixture(t)
	_, wire := createAPIKeyExchangeSource(t, h, "m33-populated-user-before-organization")
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, SubjectToken: wire, SubjectTokenType: oauth.APIKeyTokenType, Resource: h.client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.10"}
	issued, err := h.service.Token(h.f.ctx, request)
	request.SubjectToken, wire = "", ""
	if err != nil {
		t.Fatal("genuine USER lineage before organization expansion", err)
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	const snapshot = `SELECT jsonb_build_object('grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY grant_id) FROM oauth_store.grants g),'artifacts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY artifact_id) FROM oauth_store.artifacts a))::text`
	var before, after string
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	base := oauthpostgres.APIKeyExchangeMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7200}
	source := oauthpostgres.OrganizationAPIKeyExchangeMigrationSource{Base: base, Schema: "oauth_store", Version: 7400}
	steps, err := source.Load(h.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := h.f.oauth
	c.APIKeyExchange = nil
	// This is a schema-activation probe, not an organization owner proof. No
	// token is issued through this selector and no source observation is forged.
	selected := oauthpostgres.OrganizationAPIKeyExchangeConfig{Source: *h.f.oauth.APIKeyExchange, OrganizationID: apikey.OrganizationID(h.user)}
	store, err := oauthpostgres.NewOrganizationAPIKeyExchangeStore(h.f.pool, c, h.f.keys, selected)
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*h.f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	for completed := 0; completed <= 4; completed++ {
		if completed > 0 {
			prefix := steps[:len(steps)-4+completed]
			applyOrganizationExchangeHistory(t, h.f.ctx, db, "oauth_server", fixtureHistory(prefix))
		}
		err := store.BootstrapAPIKeyExchangeClient(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic})
		if completed < 4 && err == nil || completed == 4 && err != nil {
			t.Fatal("org activation did not require both validated checks and nullable USER shape", completed, err)
		}
		out, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: access})
		if err != nil || !out.Active || out.Subject != string(h.user) {
			t.Fatal("old USER reader failed during expand/validate rollout", completed, err)
		}
	}
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, snapshot).Scan(&after); err != nil || before != after {
		t.Fatal("organization suffix rewrote populated USER lineage", err)
	}
	request.SubjectToken, request.SubjectTokenType = access, oauth.AccessTokenType
	if child, err := h.service.Token(h.f.ctx, request); err != nil || child.AccessToken == (oauth.Token{}) || child.ExpiresAt.After(issued.ExpiresAt) {
		t.Fatal("unchanged USER writer failed against organization-expanded schema", err)
	}
}

func TestNativeOrganizationAPIKeyHistoryPreservesOptionalWorkloadPrefix(t *testing.T) {
	f := passwordFixture(t)
	client, _, basic := addConfiguredConfidentialClient(t, &f)
	f.oauth.Protocol.OwningClientIntrospection = true
	old, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	access, _ := issuedConfidentialTokens(t, f, old, client, basic)
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	base := oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}
	workload := oauthpostgres.WorkloadMigrationSource{Base: base, Schema: "oauth_store", Version: 7100}
	applyOrganizationExchangeHistory(t, f.ctx, db, "oauth_server", workload)
	// An inert persisted workload row tests the already-supported schema arm;
	// it is never claimed as authenticated workload/OAuth consumer execution.
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO oauth_store.grants(grant_id,tenant_id,user_id,client_id,client_version,client_fingerprint,source_session,scopes,resource,state,created_at,expires_at,version,workload_source) SELECT 'inert-existing-workload',tenant_id,NULL,client_id,client_version,client_fingerprint,'[]'::jsonb,scopes,resource,state,created_at,expires_at,version,'{}'::jsonb FROM oauth_store.grants ORDER BY grant_id LIMIT 1`); err != nil {
		t.Fatal("existing optional workload storage shape", err)
	}
	const snapshot = `SELECT jsonb_agg(to_jsonb(g)-'api_key_source'-'api_key_only' ORDER BY grant_id)::text FROM oauth_store.grants g`
	var before, after string
	if err := f.pool.Raw().QueryRow(f.ctx, snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	keys := oauthpostgres.APIKeyExchangeMigrationSource{Base: workload, Schema: "oauth_store", Version: 7200}
	org := oauthpostgres.OrganizationAPIKeyExchangeMigrationSource{Base: keys, Schema: "oauth_store", Version: 7400}
	applyOrganizationExchangeHistory(t, f.ctx, db, "oauth_server", org)
	if err := f.pool.Raw().QueryRow(f.ctx, snapshot).Scan(&after); err != nil || before != after {
		t.Fatal("organization suffix changed populated USER/workload shape", err)
	}
	if out, err := old.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: basic, Token: access}); err != nil || !out.Active {
		t.Fatal("unchanged USER consumer failed with optional workload prefix", err)
	}
	var selected, devices bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM oauth_store.grants WHERE api_key_only),to_regclass('oauth_store.devices') IS NOT NULL`).Scan(&selected, &devices); err != nil || selected || devices {
		t.Fatal("schema extension enabled an unselected key/device capability", err)
	}
}
