//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

func enableClientRotation(t *testing.T, f *authenticatedPasswordFixture) *atomic.Bool {
	t.Helper()
	denied := enableClientManagement(t, f)
	installClientRotation(t, f)
	return denied
}

func installClientRotation(t *testing.T, f *authenticatedPasswordFixture) {
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
	base := oauthpostgres.ClientMigrationSource{Base: oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}, Schema: "oauth_store", Version: 7003}
	runner, err := migrations.NewRunner(oauthpostgres.ClientRotationMigrationSource{Base: base, Schema: "oauth_store", Version: 7004}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if installed, err := runner.Up(f.ctx); err != nil || len(installed.Records()) != 1 {
		t.Fatal("rotation forward install", err)
	}
	if replay, err := runner.Up(f.ctx); err != nil || len(replay.Records()) != 0 {
		t.Fatal("rotation forward history replay changed prefix", err)
	}
	f.oauth.ClientSecretRotation = true
}

func TestNativeClientRotationForwardHistoryPreservesExistingActiveAndDeletedClients(t *testing.T) {
	f := passwordFixture(t)
	enableClientManagement(t, &f)
	legacy, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	active, err := legacy.ClientCreate(f.ctx, clientCreateRequest(t, f, "forward-active"))
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := legacy.ClientCreate(f.ctx, clientCreateRequest(t, f, "forward-deleted"))
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := active.Secret.Reveal()
	basic := confidentialBasic(t, active.Client.ID, secret)
	_, refresh := issuedConfidentialTokens(t, f, legacy, active.Client, basic)
	remove := clientRotationRequest(t, f, deleted.Client, "forward-delete", 0).Management
	if out, err := legacy.ClientDelete(f.ctx, remove); err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original client tombstone", err)
	}
	var registration, digest [2][]byte
	clients := []oauth.Client{active.Client, deleted.Client}
	for i, c := range clients {
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, c.ID).Scan(&registration[i], &digest[i]); err != nil {
			t.Fatal(err)
		}
	}
	installClientRotation(t, &f)
	for i, c := range clients {
		var currentRegistration, currentDigest []byte
		var version, state, secretVersion string
		var absent bool
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest,version::text,state,secret_version::text,previous_secret_digest IS NULL AND previous_secret_version IS NULL AND previous_secret_expires_at IS NULL FROM oauth_store.managed_clients WHERE client_id=$1`, c.ID).Scan(&currentRegistration, &currentDigest, &version, &state, &secretVersion, &absent); err != nil {
			t.Fatal(err)
		}
		wantVersion, wantState := "1", "active"
		if i == 1 {
			wantVersion, wantState = "2", "deleted"
		}
		if !bytes.Equal(currentRegistration, registration[i]) || !bytes.Equal(currentDigest, digest[i]) || version != wantVersion || state != wantState || secretVersion != "1" || !absent {
			t.Fatal("forward history rewrote existing client authority")
		}
	}
	current, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := current.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: active.Client.ID, ClientAuthentication: basic, RefreshToken: refresh, Network: "192.0.2.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("forward history stranded unchanged current-version grant", err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CurrentClient(f.ctx, deleted.Client.ID); err == nil {
		t.Fatal("forward history revived tombstone")
	}
	if _, err := current.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, active.Client, "forward-first-rotation", 0)); err != nil {
		t.Fatal("populated migrated client could not rotate", err)
	}
}

func clientRotationRequest(t *testing.T, f authenticatedPasswordFixture, client oauth.Client, label string, overlap time.Duration) oauth.ClientSecretRotationRequest {
	r := clientCreateRequest(t, f, label)
	r.ClientID, r.Version, r.Redirects, r.Scopes = client.ID, client.Version, nil, nil
	return oauth.ClientSecretRotationRequest{Management: r, Overlap: overlap}
}

func TestNativeClientRotationAdvancesAuthorityAndPermitsOnlyNewExplicitGrants(t *testing.T) {
	f := passwordFixture(t)
	enableClientRotation(t, &f)
	first, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	second, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := first.ClientCreate(f.ctx, clientCreateRequest(t, f, "rotation-create"))
	if err != nil {
		t.Fatal(err)
	}
	oldSecret, err := created.Secret.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	oldBasic := confidentialBasic(t, created.Client.ID, oldSecret)
	access, refresh := issuedConfidentialTokens(t, f, first, created.Client, oldBasic)
	page, err := first.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
	if err != nil || len(page.Page.Items()) != 1 {
		t.Fatal("original consent unavailable", err)
	}
	oldConsent := page.Page.Items()[0]
	oldVerifier, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, resourcePolicy(f, created.Client))
	if err != nil {
		t.Fatal(err)
	}
	code, proof := confidentialCode(t, f, second, created.Client)
	r := clientRotationRequest(t, f, created.Client, "rotation-original", time.Minute)
	rotated, err := first.ClientRotateSecret(f.ctx, r)
	if err != nil || rotated.Client.Version != 2 || rotated.Completion.Outcome != identity.CommitOutcomeCommitted || rotated.PredecessorExpiresAt.IsZero() {
		t.Fatal("genuine rotation", err)
	}
	newSecret, err := rotated.Secret.Reveal()
	if err != nil || newSecret == oldSecret {
		t.Fatal("fresh independent successor not revealed")
	}
	newBasic := confidentialBasic(t, created.Client.ID, newSecret)
	requireInvalidResource(t, oldVerifier, f.ctx, access)
	if out, err := first.ConsentGet(f.ctx, oauth.ConsentGetRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRead, oldConsent.ID(), 0)}); err == nil || out.Consent.ID() != "" {
		t.Fatal("old client consent remained current")
	}
	for _, service := range []*oauth.Service{first, second} {
		for _, basic := range []oauth.ClientAuthentication{oldBasic, newBasic} {
			if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: created.Client.ID, ClientAuthentication: basic, Code: code, CodeVerifier: proof, RedirectURI: created.Client.Redirects[0], Network: "192.0.2.1"}); err == nil {
				t.Fatal("pre-rotation code accepted")
			}
			if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: created.Client.ID, ClientAuthentication: basic, RefreshToken: refresh, Network: "192.0.2.1"}); err == nil {
				t.Fatal("pre-rotation refresh accepted")
			}
			if got, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: created.Client.ID, ClientAuthentication: basic, Token: access}); err == nil && got.Active {
				t.Fatal("pre-rotation access accepted")
			}
		}
	}
	for _, basic := range []oauth.ClientAuthentication{oldBasic, newBasic} {
		fresh, _ := issuedConfidentialTokens(t, f, second, rotated.Client, basic)
		verifier, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, resourcePolicy(f, rotated.Client))
		if err != nil {
			t.Fatal(err)
		}
		if p, err := verifier.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: fresh, Scope: "identity:read"}); err != nil || p.RequireScope("identity:read") != nil {
			t.Fatal("new explicitly authorized resource denied", err)
		}
	}
	retry, err := second.ClientRotateSecret(f.ctx, r)
	if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != rotated.Completion.CommandID {
		t.Fatal("original rotation retry", err)
	}
	if _, err := retry.Secret.Reveal(); err == nil {
		t.Fatal("retry revealed successor")
	}
	changed := r
	changed.Overlap = 2 * time.Minute
	if _, err := second.ClientRotateSecret(f.ctx, changed); !errors.Is(err, oauth.ErrClientConflict) {
		t.Fatal("same-key changed overlap did not conflict", err)
	}
	third, err := second.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, rotated.Client, "rotation-next", time.Minute))
	if err != nil || third.Client.Version != 3 || !time.Now().Before(rotated.PredecessorExpiresAt) {
		t.Fatal("second overlap rotation missed live original window", err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AuthenticateCurrentClient(f.ctx, third.Client, oldBasic); err == nil {
		t.Fatal("second rotation retained older live predecessor")
	}
	latest, _ := third.Secret.Reveal()
	for _, basic := range []oauth.ClientAuthentication{newBasic, confidentialBasic(t, third.Client.ID, latest)} {
		if err := store.AuthenticateCurrentClient(f.ctx, third.Client, basic); err != nil {
			t.Fatal("immediate predecessor or successor denied", err)
		}
	}
}

func TestNativeClientRotationPredecessorExclusiveExpiryAndSecondRotation(t *testing.T) {
	f := passwordFixture(t)
	enableClientRotation(t, &f)
	s, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.ClientCreate(f.ctx, clientCreateRequest(t, f, "expiry-create"))
	if err != nil {
		t.Fatal(err)
	}
	old, _ := created.Secret.Reveal()
	oldBasic := confidentialBasic(t, created.Client.ID, old)
	rotated, err := s.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, created.Client, "expiry-first", time.Second))
	if err != nil {
		t.Fatal(err)
	}
	current, _ := rotated.Secret.Reveal()
	currentBasic := confidentialBasic(t, created.Client.ID, current)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AuthenticateCurrentClient(f.ctx, rotated.Client, oldBasic); err != nil {
		t.Fatal("live predecessor rejected", err)
	}
	// Do not move the client clock ahead of genuine primary evidence. Let the
	// actual deadline elapse, then select its exact microsecond boundary.
	waitAuthenticationBoundary(t, f, rotated.PredecessorExpiresAt)
	exact := f.oauth
	exact.Protocol.Clock = emailClock(func() time.Time { return rotated.PredecessorExpiresAt })
	exactStore, err := oauthpostgres.NewStore(f.pool, exact, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := exactStore.AuthenticateCurrentClient(f.ctx, rotated.Client, oldBasic); err == nil {
		t.Fatal("predecessor valid at exclusive exact expiry")
	}
	if err := exactStore.AuthenticateCurrentClient(f.ctx, rotated.Client, currentBasic); err != nil {
		t.Fatal("successor unavailable at predecessor expiry", err)
	}
	second, err := s.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, rotated.Client, "expiry-second", 0))
	if err != nil || second.Client.Version != 3 || !second.PredecessorExpiresAt.IsZero() {
		t.Fatal("zero-overlap second rotation", err)
	}
	latest, _ := second.Secret.Reveal()
	latestBasic := confidentialBasic(t, created.Client.ID, latest)
	for _, basic := range []oauth.ClientAuthentication{oldBasic, currentBasic} {
		if err := store.AuthenticateCurrentClient(f.ctx, second.Client, basic); err == nil {
			t.Fatal("older secret survived second zero rotation")
		}
	}
	issuedConfidentialTokens(t, f, s, second.Client, latestBasic)
	remove := clientRotationRequest(t, f, second.Client, "expiry-delete", 0).Management
	if out, err := s.ClientDelete(f.ctx, remove); err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("current rotated client deletion", err)
	}
	if err := store.AuthenticateCurrentClient(f.ctx, second.Client, latestBasic); err == nil {
		t.Fatal("terminal deletion retained successor")
	}
}

// This oracle blocks the actual client SHARE fence, not an unrelated callback.
// The original predecessor matched before the wait; no source proof is forged,
// and only its naturally elapsed <=1s overlap expires. The unchanged code can
// then be consumed using the live successor, proving denial caused no effects.
func TestNativeClientRotationPredecessorExpiresDuringActualClientLockWait(t *testing.T) {
	f := passwordFixture(t)
	enableClientRotation(t, &f)
	s, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.ClientCreate(f.ctx, clientCreateRequest(t, f, "wait-create"))
	if err != nil {
		t.Fatal(err)
	}
	old, _ := created.Secret.Reveal()
	oldBasic := confidentialBasic(t, created.Client.ID, old)
	rotated, err := s.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, created.Client, "wait-rotate", time.Second))
	if err != nil {
		t.Fatal(err)
	}
	successor, _ := rotated.Secret.Reveal()
	currentBasic := confidentialBasic(t, created.Client.ID, successor)
	code, proof := confidentialCode(t, f, s, rotated.Client)
	var before int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	conn, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	tx, err := conn.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(f.ctx, `SELECT client_id FROM oauth_store.managed_clients WHERE client_id=$1 FOR UPDATE`, created.Client.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	type answer struct {
		out oauth.TokenResult
		err error
	}
	done := make(chan answer, 1)
	request := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: created.Client.ID, ClientAuthentication: oldBasic, Code: code, CodeVerifier: proof, RedirectURI: created.Client.Redirects[0], Network: "192.0.2.1"}
	go func() { out, err := s.Token(ctx, request); done <- answer{out, err} }()
	joined := false
	defer func() {
		cancel()
		_ = tx.Rollback(context.Background())
		if !joined {
			<-done
		}
	}()
	for {
		var waiting int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, conn.Conn().PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		select {
		case early := <-done:
			joined = true
			t.Fatal("token never reached client row wait", early.err)
		case <-time.After(time.Millisecond * 5):
		case <-f.ctx.Done():
			t.Fatal("client wait canceled")
		}
	}
	waitAuthenticationBoundary(t, f, rotated.PredecessorExpiresAt)
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	denied := <-done
	joined = true
	if denied.err == nil {
		t.Fatal("expired predecessor authorized late exchange")
	}
	if _, err := denied.out.AccessToken.Reveal(); err == nil {
		t.Fatal("expired predecessor received access")
	}
	var after int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects`).Scan(&after); err != nil || after != before {
		t.Fatal("expiry denial changed effects", err)
	}
	request.ClientAuthentication = currentBasic
	if out, err := s.Token(f.ctx, request); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("expiry denial consumed live code", err)
	}
}

func TestNativeClientRotationIntrospectionAndRevocationPreservePredecessorExpiry(t *testing.T) {
	for _, operation := range []string{"introspect", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			f := passwordFixture(t)
			enableClientRotation(t, &f)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			created, err := service.ClientCreate(f.ctx, clientCreateRequest(t, f, "separate-expiry-create"))
			if err != nil {
				t.Fatal(err)
			}
			old, _ := created.Secret.Reveal()
			oldBasic := confidentialBasic(t, created.Client.ID, old)
			rotated, err := service.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, created.Client, "separate-expiry-rotate", 2*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			successor, _ := rotated.Secret.Reveal()
			currentBasic := confidentialBasic(t, created.Client.ID, successor)
			access, _ := issuedConfidentialTokens(t, f, service, rotated.Client, currentBasic)
			store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			request := oauth.IntrospectRequest{ClientID: created.Client.ID, ClientAuthentication: oldBasic, Token: access}
			if out, err := store.Introspect(f.ctx, oauth.IntrospectionCommand{Client: rotated.Client, Request: request}); err != nil || !out.Active {
				t.Fatal("live predecessor introspection positive control", err)
			}
			if out, err := store.Revoke(f.ctx, oauth.RevocationCommand{Client: rotated.Client, Request: oauth.RevokeRequest{ClientID: created.Client.ID, ClientAuthentication: oldBasic, Token: "unknown", Network: "192.0.2.1"}}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("live predecessor unknown-revoke positive control", err)
			}
			var before int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if operation == "introspect" {
				gate := &resourceReadGate{reached: make(chan struct{}), proceed: make(chan struct{})}
				original := f.pool.Raw().Config().ConnConfig
				pool, err := database.Connect(f.ctx, database.Config{DSN: original.ConnString(), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = original.Database
					c.ConnConfig.RuntimeParams = maps.Clone(original.RuntimeParams)
					c.ConnConfig.Tracer = gate
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if pool.Close(cleanup) != nil {
						t.Error("introspection expiry pool cleanup")
					}
				}()
				late, err := oauthpostgres.NewStore(pool, f.oauth, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.WithValue(f.ctx, resourceReadKey{}, true))
				defer cancel()
				type answer struct {
					out oauth.IntrospectResult
					err error
				}
				done := make(chan answer, 1)
				joined := false
				defer func() {
					cancel()
					select {
					case <-gate.proceed:
					default:
						close(gate.proceed)
					}
					if !joined {
						<-done
					}
				}()
				go func() {
					out, err := late.Introspect(ctx, oauth.IntrospectionCommand{Client: rotated.Client, Request: request})
					done <- answer{out, err}
				}()
				select {
				case <-gate.reached:
				case out := <-done:
					joined = true
					t.Fatal("introspection did not reach genuine second primary lookup", out.err)
				case <-f.ctx.Done():
					t.Fatal("bounded introspection expiry canceled")
				}
				if !time.Now().Before(rotated.PredecessorExpiresAt) {
					t.Fatal("introspection predecessor expired before late gate")
				}
				waitAuthenticationBoundary(t, f, rotated.PredecessorExpiresAt)
				close(gate.proceed)
				out := <-done
				joined = true
				if out.err == nil || out.out.Active || out.out.ClientID != "" {
					t.Fatal("late introspection renewed predecessor authority")
				}
			} else {
				conn, err := f.pool.Raw().Acquire(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Release()
				tx, err := conn.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := tx.Exec(f.ctx, `SELECT client_id FROM oauth_store.managed_clients WHERE client_id=$1 FOR UPDATE`, created.Client.ID); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(f.ctx)
				defer cancel()
				done := make(chan error, 1)
				joined := false
				defer func() {
					cancel()
					_ = tx.Rollback(context.Background())
					if !joined {
						<-done
					}
				}()
				go func() {
					_, err := store.Revoke(ctx, oauth.RevocationCommand{Client: rotated.Client, Request: oauth.RevokeRequest{ClientID: created.Client.ID, ClientAuthentication: oldBasic, Token: access, Network: "192.0.2.1"}})
					done <- err
				}()
				for {
					var waiting int
					if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, conn.Conn().PgConn().PID()).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting > 0 {
						break
					}
					select {
					case err := <-done:
						joined = true
						t.Fatal("revoke did not reach genuine client lock wait", err)
					case <-time.After(5 * time.Millisecond):
					case <-f.ctx.Done():
						t.Fatal("bounded revoke expiry canceled")
					}
				}
				if !time.Now().Before(rotated.PredecessorExpiresAt) {
					t.Fatal("revoke predecessor expired before actual client wait")
				}
				waitAuthenticationBoundary(t, f, rotated.PredecessorExpiresAt)
				if err := tx.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				err = <-done
				joined = true
				if err == nil {
					t.Fatal("late revoke renewed predecessor authority")
				}
			}
			var after int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects`).Scan(&after); err != nil || after != before {
				t.Fatal("predecessor expiry changed effects", err)
			}
			request.ClientAuthentication = currentBasic
			if out, err := store.Introspect(f.ctx, oauth.IntrospectionCommand{Client: rotated.Client, Request: request}); err != nil || !out.Active {
				t.Fatal("expiry denial changed still-live access", err)
			}
			if out, err := store.Revoke(f.ctx, oauth.RevocationCommand{Client: rotated.Client, Request: oauth.RevokeRequest{ClientID: created.Client.ID, ClientAuthentication: currentBasic, Token: access, Network: "192.0.2.1"}}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("live successor revoke denied", err)
			}
		})
	}
}

func TestNativeClientRotationRequiredEffectsAndOriginalPrePostCommitRecovery(t *testing.T) {
	for _, mode := range []string{"audit", "outbox", "before", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			var provisional atomic.Bool
			fault := &oauthCommitFault{before: mode == "before", beforeWrite: func(wire []byte) {
				if bytes.Contains(wire, []byte(`UPDATE "oauth_store".managed_clients SET version=version+1,registration=`)) {
					provisional.Store(true)
				}
			}}
			f := passwordFixture(t, fault)
			enableClientRotation(t, &f)
			s, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			created, err := s.ClientCreate(f.ctx, clientCreateRequest(t, f, "fault-create"))
			if err != nil {
				t.Fatal(err)
			}
			old, _ := created.Secret.Reveal()
			oldBasic := confidentialBasic(t, created.Client.ID, old)
			switch mode {
			case "audit":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE audit.records ADD CONSTRAINT refuse_rotation CHECK(action<>'identity.oauth_server.rotate_client_secret')`)
			case "outbox":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_rotation CHECK(topic<>'oauth_client.secret_rotated.v1') NOT VALID`)
			default:
				fault.armed.Store(true)
			}
			if err != nil {
				t.Fatal(err)
			}
			r := clientRotationRequest(t, f, created.Client, "fault-original", time.Minute)
			out, err := s.ClientRotateSecret(f.ctx, r)
			if err == nil || !provisional.Load() {
				t.Fatal("required failure not reached after provisional rotation")
			}
			if _, err := out.Secret.Reveal(); err == nil {
				t.Fatal("failed/unknown rotation revealed secret")
			}
			store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "before" || mode == "unknown" {
				if !fault.hit.Load() || out.Completion.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("actual COMMIT seam missed")
				}
				rr := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-rotate-secret", CommandID: out.Completion.CommandID, ClientID: created.Client.ID, TenantID: f.tenant, Session: f.browser}
				metadata, err := store.Recover(f.ctx, rr)
				want := identity.CommitOutcomeCommitted
				if mode == "before" {
					want = identity.CommitOutcomeNotCommitted
					if err != nil || metadata.Outcome != identity.CommitOutcomeInProgress {
						t.Fatal("original live pending not observational", err)
					}
				}
				deadline := time.Now().Add(8 * time.Second)
				for metadata.Outcome != want {
					if time.Now().After(deadline) {
						t.Fatal("original recovery did not reconcile", err)
					}
					select {
					case <-time.After(100 * time.Millisecond):
					case <-f.ctx.Done():
						t.Fatal("bounded recovery canceled")
					}
					metadata, err = store.Recover(f.ctx, rr)
					if err != nil && !errors.Is(err, oauth.ErrUnavailable) {
						t.Fatal("original recovery custody rejected", err)
					}
				}
				for i := 0; i < 2; i++ {
					again, err := store.Recover(f.ctx, rr)
					if err != nil && !(mode == "before" && errors.Is(err, oauth.ErrUnavailable)) || again.Outcome != want || again.CommandID != rr.CommandID {
						t.Fatal("terminal metadata unstable", err)
					}
				}
			}
			var version string
			var effects, audits, events int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-rotate-secret'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.rotate_client_secret' AND outcome=1),(SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_client.secret_rotated.v1') FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&version, &effects, &audits, &events); err != nil {
				t.Fatal(err)
			}
			want := 0
			wantVersion := "1"
			if mode == "unknown" {
				want = 1
				wantVersion = "2"
			}
			if version != wantVersion || effects != want || audits != want || events != want {
				t.Fatal("atomic rotation/effect/audit/event mismatch")
			}
			if mode != "unknown" {
				if err := store.AuthenticateCurrentClient(f.ctx, created.Client, oldBasic); err != nil {
					t.Fatal("noncommit withdrew predecessor authority", err)
				}
			}
			fresh, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			retry, err := fresh.ClientRotateSecret(f.ctx, r)
			if mode == "unknown" && (err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != out.Completion.CommandID) {
				t.Fatal("original committed retry diverged", err)
			}
			if _, err := retry.Secret.Reveal(); err == nil {
				t.Fatal("original retry redelivered secret")
			}
			var again string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&again); err != nil || again != version {
				t.Fatal("retry repeated generation", err)
			}
		})
	}
}
