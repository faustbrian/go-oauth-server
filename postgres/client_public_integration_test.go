//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

func installPublicClients(t *testing.T, f *authenticatedPasswordFixture) {
	t.Helper()
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
	var base migrations.Source = oauthpostgres.ClientMigrationSource{Base: oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}, Schema: "oauth_store", Version: 7003}
	version := migrations.Version(7004)
	if f.oauth.ClientSecretRotation {
		base = oauthpostgres.ClientRotationMigrationSource{Base: base, Schema: "oauth_store", Version: 7004}
		version++
	}
	if f.oauth.ClientMetadataUpdates {
		base = oauthpostgres.ClientUpdateMigrationSource{Base: base, Schema: "oauth_store", Version: version}
		version++
	}
	runner, err := migrations.NewRunner(oauthpostgres.ClientPublicMigrationSource{Base: base, Schema: "oauth_store", Version: version}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if installed, err := runner.Up(f.ctx); err != nil || len(installed.Records()) != 1 {
		t.Fatal("public forward install", err)
	}
	if replay, err := runner.Up(f.ctx); err != nil || len(replay.Records()) != 0 {
		t.Fatal("public forward prefix changed", err)
	}
	f.oauth.PublicClients = true
	f.oauth.Protocol.ManagedClients.PublicClients = true
}

func TestNativeManagedPublicClientFreshAndPopulatedNoSecretJourney(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated-rotation"}[populated], func(t *testing.T) {
			f := passwordFixture(t)
			denied := enableClientManagement(t, &f)
			var legacy oauth.ClientManagementResult
			var legacyRequest oauth.ClientManagementRequest
			var registration, digest []byte
			var legacyRefresh string
			var legacyBasic oauth.ClientAuthentication
			if populated {
				installClientRotation(t, &f)
				old, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				legacyRequest = clientCreateRequest(t, f, "before-public")
				legacy, err = old.ClientCreate(f.ctx, legacyRequest)
				if err != nil {
					t.Fatal(err)
				}
				secret, err := legacy.Secret.Reveal()
				if err != nil {
					t.Fatal(err)
				}
				legacyBasic = confidentialBasic(t, legacy.Client.ID, secret)
				_, legacyRefresh = issuedConfidentialTokens(t, f, old, legacy.Client, legacyBasic)
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, legacy.Client.ID).Scan(&registration, &digest); err != nil {
					t.Fatal(err)
				}
			}
			installPublicClients(t, &f)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			if populated {
				replayed, err := service.ClientCreate(f.ctx, legacyRequest)
				if err != nil || !replayed.Completion.Replayed || replayed.Completion.CommandID != legacy.Completion.CommandID {
					t.Fatal("public activation changed original confidential intent", err)
				}
				if _, err := replayed.Secret.Reveal(); err == nil {
					t.Fatal("original confidential retry revealed custody after activation")
				}
				store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				if recovered, err := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-create", CommandID: legacy.Completion.CommandID, ClientID: legacy.Client.ID, TenantID: f.tenant, Session: f.browser}); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("public activation stranded original confidential metadata recovery", err)
				}
				var afterRegistration, afterDigest []byte
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, legacy.Client.ID).Scan(&afterRegistration, &afterDigest); err != nil || !bytes.Equal(registration, afterRegistration) || !bytes.Equal(digest, afterDigest) {
					t.Fatal("public migration changed installed confidential custody", err)
				}
				if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: legacy.Client.ID, ClientAuthentication: legacyBasic, RefreshToken: legacyRefresh, Network: "192.0.2.1"}); err != nil {
					t.Fatal("public activation stranded confidential grant", err)
				}
				if _, err := service.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, legacy.Client, "after-public-rotation", 0)); err != nil {
					t.Fatal("confidential rotation changed", err)
				}
			}
			r := clientCreateRequest(t, f, "public-client")
			r.Public = true
			denied.Store(true)
			if _, err := service.ClientCreate(f.ctx, r); err == nil {
				t.Fatal("public flag bypassed manager permission")
			}
			denied.Store(false)
			created, err := service.ClientCreate(f.ctx, r)
			if err != nil || !created.Client.Public || created.Client.AuthenticationMethod != "none" || created.Completion.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("explicit public registration not committed", err)
			}
			if _, err := created.Secret.Reveal(); err == nil {
				t.Fatal("public create revealed secret")
			}
			var noSecret bool
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT secret_digest IS NULL AND registration->>'Public'='true' AND registration->>'AuthenticationMethod'='none' FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&noSecret); err != nil || !noSecret {
				t.Fatal("public registry persisted secret or wrong class", err)
			}
			fresh, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			read := oauth.ClientReadRequest{Owner: r.Owner, TenantID: f.tenant, Session: f.browser, ClientID: created.Client.ID}
			current, err := fresh.ClientGet(f.ctx, read)
			if err != nil || !current.Client.Public || current.Client.AuthenticationMethod != "none" {
				t.Fatal("fresh service did not discover public registration", err)
			}
			listed, err := fresh.ClientList(f.ctx, oauth.ClientReadRequest{Owner: r.Owner, TenantID: f.tenant, Session: f.browser, Limit: 100})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, item := range listed.Page.Items() {
				if item.ID == current.Client.ID {
					found = item.Public && item.AuthenticationMethod == "none"
				}
			}
			if !found {
				t.Fatal("public registration missing from safe private list")
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.managed_clients SET secret_digest=decode(repeat('00',32),'hex') WHERE client_id=$1`, current.Client.ID); err == nil {
				t.Fatal("schema allowed a public client secret")
			}
			retry, err := fresh.ClientCreate(f.ctx, r)
			if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != created.Completion.CommandID || !retry.Client.Public {
				t.Fatal("public original retry lost class", err)
			}
			if _, err := retry.Secret.Reveal(); err == nil {
				t.Fatal("public retry invented secret")
			}
			changed := r
			changed.Public = false
			if _, err := fresh.ClientCreate(f.ctx, changed); !errors.Is(err, oauth.ErrClientConflict) {
				t.Fatal("request key crossed public/confidential classes", err)
			}
			confidential := clientCreateRequest(t, f, "confidential-after-public")
			private, err := fresh.ClientCreate(f.ctx, confidential)
			if err != nil {
				t.Fatal(err)
			}
			confidential.Public = true
			if _, err := fresh.ClientCreate(f.ctx, confidential); !errors.Is(err, oauth.ErrClientConflict) {
				t.Fatal("confidential request key crossed into public", err)
			}
			privateSecret, err := private.Secret.Reveal()
			if err != nil {
				t.Fatal("false confidential selection stopped revealing", err)
			}
			code, verifier := confidentialCode(t, f, fresh, current.Client)
			request := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: current.Client.ID, Code: code, CodeVerifier: strings.Repeat("z", 43), RedirectURI: current.Client.Redirects[0], Network: "192.0.2.1"}
			if _, err := fresh.Token(f.ctx, request); err == nil {
				t.Fatal("public code accepted mismatched S256")
			}
			request.CodeVerifier = verifier
			request.ClientAuthentication = confidentialBasic(t, current.Client.ID, privateSecret)
			if _, err := fresh.Token(f.ctx, request); err == nil {
				t.Fatal("public client accepted forbidden secret authentication")
			}
			request.ClientAuthentication = oauth.ClientAuthentication{}
			issued, err := fresh.Token(f.ctx, request)
			if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("public code required secret or failed redemption", err)
			}
			if _, err := fresh.Token(f.ctx, request); err == nil {
				t.Fatal("public code replay issued again")
			}
			refresh, _ := issued.RefreshToken.Reveal()
			if _, err := fresh.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: current.Client.ID, RefreshToken: refresh, Network: "192.0.2.1"}); err == nil {
				t.Fatal("code replay left public descendants active")
			}
			// Replay withdraws that original family; a new genuine approval is
			// required before proving the independent refresh/revocation path.
			_, refresh = issuedConfidentialTokens(t, f, fresh, current.Client, oauth.ClientAuthentication{})
			rotated, err := fresh.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: current.Client.ID, RefreshToken: refresh, Network: "192.0.2.1"})
			if err != nil {
				t.Fatal("public refresh required secret", err)
			}
			access, _ := rotated.AccessToken.Reveal()
			nextRefresh, _ := rotated.RefreshToken.Reveal()
			if _, err := fresh.Revoke(f.ctx, oauth.RevokeRequest{ClientID: current.Client.ID, Token: nextRefresh, Network: "192.0.2.1"}); err != nil {
				t.Fatal("public revocation required secret", err)
			}
			if _, err := fresh.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: current.Client.ID, RefreshToken: nextRefresh, Network: "192.0.2.1"}); err == nil {
				t.Fatal("revoked public refresh issued")
			}
			resource, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, resourcePolicy(f, current.Client))
			if err != nil {
				t.Fatal(err)
			}
			requireInvalidResource(t, resource, f.ctx, access)
			if populated {
				if _, err := fresh.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, current.Client, "public-rotation", 0)); err == nil {
					t.Fatal("public client acquired secret rotation")
				}
			}
			_, pendingRefresh := issuedConfidentialTokens(t, f, fresh, current.Client, oauth.ClientAuthentication{})
			remove := clientRotationRequest(t, f, current.Client, "public-delete", 0).Management
			if _, err := fresh.ClientDelete(f.ctx, remove); err != nil {
				t.Fatal("public terminal deletion failed", err)
			}
			store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			if recovered, err := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-create", CommandID: created.Completion.CommandID, ClientID: current.Client.ID, TenantID: f.tenant, Session: f.browser}); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("public deletion stranded original create metadata", err)
			}
			for _, warm := range []*oauth.Service{service, fresh} {
				if _, err := warm.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: current.Client.ID, RefreshToken: pendingRefresh, Network: "192.0.2.1"}); err == nil {
					t.Fatal("warm service accepted deleted public descendant")
				}
			}
			var effects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects WHERE client_id=$1`, current.Client.ID).Scan(&effects); err != nil || effects != 2 {
				t.Fatal("public client effects duplicated", err)
			}
		})
	}
}

func TestNativeManagedPublicClientUnknownCreateRecoversOnlyOriginalMetadata(t *testing.T) {
	fault := &oauthCommitFault{}
	f := passwordFixture(t, fault)
	denied := enableClientManagement(t, &f)
	installPublicClients(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	r := clientCreateRequest(t, f, "public-unknown")
	r.Public = true
	fault.armed.Store(true)
	lost, err := service.ClientCreate(f.ctx, r)
	if err == nil || !fault.hit.Load() || lost.Completion.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("public unknown COMMIT seam missed", err)
	}
	if _, err := lost.Secret.Reveal(); err == nil {
		t.Fatal("unknown public creation invented secret")
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	rr := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-create", CommandID: lost.Completion.CommandID, ClientID: oauth.ManagedClientPrefix + string(lost.Completion.CommandID), TenantID: f.tenant, Session: f.browser}
	denied.Store(true)
	if _, err := store.Recover(f.ctx, rr); err == nil {
		t.Fatal("original public recovery bypassed current manager authority")
	}
	denied.Store(false)
	for i := 0; i < 2; i++ {
		recovered, err := store.Recover(f.ctx, rr)
		if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.CommandID != lost.Completion.CommandID {
			t.Fatal("public original metadata recovery failed", err)
		}
	}
	fresh, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := fresh.ClientCreate(f.ctx, r)
	if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != lost.Completion.CommandID || !retry.Client.Public {
		t.Fatal("public unknown retry changed original result", err)
	}
	if _, err := retry.Secret.Reveal(); err == nil {
		t.Fatal("public recovery generated secret")
	}
	var clients, effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.managed_clients WHERE secret_digest IS NULL`).Scan(&clients); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-create'`).Scan(&effects); err != nil || clients != 1 || effects != 1 {
		t.Fatal("public recovery duplicated creation", err)
	}
}

func TestNativeManagedPublicClientRequiredEffectsRollbackAndOriginalRecovery(t *testing.T) {
	testNativeManagedClientRequiredEffectsRollbackAndOriginalRecovery(t, true)
}

func TestNativeManagedPublicClientDeniesMetadataReplacementWithoutEffects(t *testing.T) {
	f := passwordFixture(t)
	enableClientUpdates(t, &f)
	installPublicClients(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	r := clientCreateRequest(t, f, "public-update-denial-create")
	r.Public = true
	created, err := service.ClientCreate(f.ctx, r)
	if err != nil || !created.Client.Public {
		t.Fatal("actual public update target not created", err)
	}
	var before, beforeDigest []byte
	var beforeVersion string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,version::text,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&before, &beforeVersion, &beforeDigest); err != nil {
		t.Fatal(err)
	}
	update := clientUpdateRequest(t, f, created.Client, "public-update-denial")
	if update.Management.Public {
		t.Fatal("closed update request unexpectedly edits class")
	}
	if _, err := oauth.ValidateClientUpdateRequest(update, *f.oauth.Protocol.ManagedClients, f.oauth.Protocol.Issuer); err != nil {
		t.Fatal("normal update request was not admitted structurally", err)
	}
	if out, err := service.ClientUpdate(f.ctx, update); !errors.Is(err, oauth.ErrAccessDenied) || out.Client.ID != "" {
		t.Fatal("actual public metadata replacement did not deny", err)
	}
	var after, afterDigest []byte
	var afterVersion string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,version::text,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&after, &afterVersion, &afterDigest); err != nil || !bytes.Equal(before, after) || beforeVersion != afterVersion || !bytes.Equal(beforeDigest, afterDigest) {
		t.Fatal("denied public update changed durable registration, version or digest", err)
	}
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-update' AND client_id=$1`, created.Client.ID).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("denied public update produced effects", err)
	}
}

func TestNativeManagedPublicClientActivationRequiresMatchingPolicyAndForwardSchema(t *testing.T) {
	f := passwordFixture(t)
	enableClientManagement(t, &f)
	f.oauth.Protocol.ManagedClients.PublicClients = true
	if _, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys); err == nil {
		t.Fatal("public policy without native activation accepted")
	}
	f.oauth.PublicClients = true
	f.oauth.Protocol.ManagedClients.PublicClients = false
	if _, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys); err == nil {
		t.Fatal("native activation without public policy accepted")
	}
	f.oauth.Protocol.ManagedClients.PublicClients = true
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	r := clientCreateRequest(t, f, "uninstalled-public-schema")
	r.Public = true
	created, err := service.ClientCreate(f.ctx, r)
	if err == nil {
		t.Fatal("public client committed without required forward schema")
	}
	if _, err := created.Secret.Reveal(); err == nil {
		t.Fatal("failed public creation disclosed a secret")
	}
	var clients, effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.managed_clients`).Scan(&clients); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-create'`).Scan(&effects); err != nil || clients != 0 || effects != 0 {
		t.Fatal("uninstalled public schema left registration/effects", err)
	}
}
