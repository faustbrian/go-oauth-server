//go:build integration && oauthflow

package oauthpostgres_test

import (
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestAPIKeyExchangeHistoryPreservesPopulatedUnselectedProfile(t *testing.T) {
	f := passwordFixture(t)
	client, _, basic := addConfiguredConfidentialClient(t, &f)
	f.oauth.Protocol.OwningClientIntrospection = true
	old, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	access, _ := issuedConfidentialTokens(t, f, old, client, basic)
	// Neither credentials nor preparation ciphertext enter this bounded local
	// state comparison. New default discriminator columns are excluded so every
	// pre-existing protocol field must remain byte-for-byte equivalent.
	const snapshot = `SELECT jsonb_build_object('grants',(SELECT jsonb_agg(to_jsonb(g)-'api_key_source'-'api_key_only' ORDER BY grant_id) FROM oauth_store.grants g),'artifacts',(SELECT jsonb_agg(to_jsonb(a)-'api_key_only'-'api_key_root'-'metadata_version' ORDER BY artifact_id) FROM oauth_store.artifacts a),'consents',(SELECT jsonb_agg(to_jsonb(c) ORDER BY consent_id) FROM oauth_store.consents c))::text`
	var before, after string
	if err := f.pool.Raw().QueryRow(f.ctx, snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("oauth_server")
	if err != nil {
		t.Fatal(err)
	}
	source := oauthpostgres.APIKeyExchangeMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7200}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("populated API-key lineage expansion", err)
	}
	if replay, err := runner.Up(f.ctx); err != nil || len(replay.Records()) != 0 {
		t.Fatal("API-key history replay changed installed state", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, snapshot).Scan(&after); err != nil || before != after {
		t.Fatal("API-key expansion rewrote existing OAuth rows", err)
	}
	fresh, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []*oauth.Service{old, fresh} {
		out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: basic, Token: access})
		if err != nil || !out.Active || out.ClientID != client.ID {
			t.Fatal("schema expansion broke an unchanged configured Basic profile", err)
		}
	}
	var selected, work, device bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM oauth_store.grants WHERE api_key_only),to_regclass('oauth_store.devices') IS NOT NULL,EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='oauth_store' AND table_name='grants' AND column_name='workload_source')`).Scan(&selected, &device, &work); err != nil || selected || work || device {
		t.Fatal("shared lineage schema selected a key/workload/device capability", err)
	}
}
