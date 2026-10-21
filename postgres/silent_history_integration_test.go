//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/oauth2"
)

func TestNativeOIDCSilentExpiryForwardHistoryPreservesPopulatedAuthority(t *testing.T) {
	f := passwordFixture(t)
	enableConsentManagement(t, &f)
	legacy, child, _, _, _ := oidcFixture(t, &f)
	code, verifier := oidcCode(t, f, legacy, "populated-legacy-approval")
	issued, err := legacy.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, RedirectURI: "https://client.example/callback", CodeVerifier: verifier, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("legacy explicit code control", err)
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	var before, after string
	const snapshot = `SELECT jsonb_build_object('consents',(SELECT jsonb_agg(to_jsonb(c)-'expires_at' ORDER BY consent_id) FROM oauth_store.consents c),'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY grant_id) FROM oauth_store.grants g),'artifacts',(SELECT jsonb_agg(to_jsonb(a)-'silent_code' ORDER BY artifact_id) FROM oauth_store.artifacts a))::text`
	if err := f.pool.Raw().QueryRow(f.ctx, snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	installConsentExpiry(t, f)
	if err := f.pool.Raw().QueryRow(f.ctx, snapshot).Scan(&after); err != nil || after != before {
		t.Fatal("forward expiry rewrote populated approval/grant/artifact history", err)
	}
	var invented int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.consents WHERE expires_at IS NOT NULL)+(SELECT count(*) FROM oauth_store.artifacts WHERE silent_code)`).Scan(&invented); err != nil || invented != 0 {
		t.Fatal("forward history invented expiry or silent root authority", err)
	}
	f.oauth.ConsentReuseTTL = time.Minute
	fresh, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err = fresh.WithOIDC(child)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := fresh.Authorize(f.ctx, silentRequest(f, oauth2.GenerateVerifier())); err != nil || out.ProtocolError != oauth.AuthorizationConsentRequiredError || out.Code != (oauth.Token{}) || out.Continuation != (oauth.Token{}) {
		t.Fatal("migration fabricated reusable legacy approval", err)
	}
	if _, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}); err != nil {
		t.Fatal("forward history withdrew existing UserInfo", err)
	}
	if out, err := fresh.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("forward history withdrew existing refresh authority", err)
	}
}

func TestNativeOIDCSilentExpiryHistoryPreservesInstalledWorkloadParents(t *testing.T) {
	f := workloadFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Token(f.ctx, workloadRequest(f))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	backend, err := migrationdb.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("oauth_server")
	if err != nil {
		t.Fatal(err)
	}
	base := oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.WorkloadMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7001}, Schema: "oauth_store", Version: 7002}
	runner, err := migrations.NewRunner(oauthpostgres.ConsentExpiryMigrationSource{Base: base, Schema: "oauth_store", Version: 7004}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("expiry extension rejected genuine workload parent history", err)
	}
	if replay, err := runner.Up(f.ctx); err != nil || len(replay.Records()) != 0 {
		t.Fatal("expiry extension changed workload prefix", err)
	}
	if out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: wire}); err != nil || !out.Active {
		t.Fatal("expiry extension withdrew installed workload authority", err)
	}
	if out, err := service.Token(f.ctx, workloadRequest(f)); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("expiry history changed ordinary workload root issuance", err)
	}
	var roots, humans int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.artifacts WHERE kind=3 AND workload_only AND parent_artifact_id IS NULL AND NOT silent_code),(SELECT count(*) FROM oauth_store.consents)`).Scan(&roots, &humans); err != nil || roots != 2 || humans != 0 {
		t.Fatal("expiry history invented human/silent workload authority", err)
	}
}

func TestNativeOIDCSilentTypedRootMarkerPreservesOrdinaryParents(t *testing.T) {
	f := passwordFixture(t)
	service, _, _ := silentOIDCFixture(t, &f, time.Minute)
	oidcCode(t, f, service, "explicit-marker-original")
	silent, err := service.Authorize(f.ctx, silentRequest(f, oauth2.GenerateVerifier()))
	if err != nil || silent.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("genuine marked root control", err)
	}
	var root, continuation, nested string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT artifact_id FROM oauth_store.artifacts WHERE grant_id=$1 AND kind=2 AND parent_artifact_id IS NULL AND silent_code`, string(silent.CommandID)).Scan(&root); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT artifact_id FROM oauth_store.artifacts WHERE kind=1 AND parent_artifact_id IS NULL AND NOT silent_code`).Scan(&continuation); err != nil {
		t.Fatal("ordinary continuation root lost", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT artifact_id FROM oauth_store.artifacts WHERE kind=2 AND parent_artifact_id=$1 AND NOT silent_code`, continuation).Scan(&nested); err != nil {
		t.Fatal("ordinary approved code parent lost", err)
	}
	for _, tc := range []struct{ name, statement, id string }{
		{"unmarked-code-root", `UPDATE oauth_store.artifacts SET silent_code=false WHERE artifact_id=$1`, root},
		{"marked-access-root", `UPDATE oauth_store.artifacts SET kind=3 WHERE artifact_id=$1`, root},
		{"marked-refresh-root", `UPDATE oauth_store.artifacts SET kind=4 WHERE artifact_id=$1`, root},
		{"marked-continuation-root", `UPDATE oauth_store.artifacts SET silent_code=true WHERE artifact_id=$1`, continuation},
		{"marked-nested-code", `UPDATE oauth_store.artifacts SET silent_code=true WHERE artifact_id=$1`, nested},
		{"ordinary-code-without-parent", `UPDATE oauth_store.artifacts SET parent_artifact_id=NULL WHERE artifact_id=$1`, nested},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := f.pool.Raw().Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			_, err = tx.Exec(f.ctx, tc.statement, tc.id)
			var denied *pgconn.PgError
			if !errors.As(err, &denied) || denied.Code != "23514" {
				t.Fatal("wrong typed artifact root/kind/parent accepted or wrong failure")
			}
		})
	}
	var marked, ordinaryRoots, ordinaryCodes int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE silent_code AND kind=2 AND parent_artifact_id IS NULL),count(*) FILTER(WHERE NOT silent_code AND kind=1 AND parent_artifact_id IS NULL),count(*) FILTER(WHERE NOT silent_code AND kind=2 AND parent_artifact_id IS NOT NULL) FROM oauth_store.artifacts`).Scan(&marked, &ordinaryRoots, &ordinaryCodes); err != nil || marked != 1 || ordinaryRoots != 1 || ordinaryCodes != 1 {
		t.Fatal("typed rejection changed genuine ordinary/silent artifacts", err)
	}
}
