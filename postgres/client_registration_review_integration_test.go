//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type registrationTraceSQLKey struct{}

// These scheduling seams retain real pgx/SQL and native authority. They change
// only scan representation or the timing of an actual failure/cancellation.
type registrationQueryTrace struct {
	start func(context.Context, string)
	end   func(context.Context, string, error)
}

func (t *registrationQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if t.start != nil {
		t.start(ctx, d.SQL)
	}
	return context.WithValue(ctx, registrationTraceSQLKey{}, d.SQL)
}

func (t *registrationQueryTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	sql, _ := ctx.Value(registrationTraceSQLKey{}).(string)
	if t.end != nil {
		t.end(ctx, sql, d.Err)
	}
}

func registrationTestPool(t *testing.T, f authenticatedPasswordFixture, location *time.Location, trace *registrationQueryTrace) *database.Pool {
	t.Helper()
	pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("OAUTH_POSTGRES_TEST_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
		if trace != nil {
			c.ConnConfig.Tracer = trace
		}
		if location != nil {
			c.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
				conn.TypeMap().RegisterType(&pgtype.Type{Name: "timestamptz", OID: pgtype.TimestamptzOID, Codec: &pgtype.TimestamptzCodec{ScanLocation: location}})
				return nil
			}
		}
		return nil
	}})
	if err != nil {
		t.Fatal("owned registration pool", err)
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := pool.Close(ctx); err != nil {
			t.Error("owned registration pool cleanup", err)
		}
	})
	return pool
}

func TestNativeDynamicRegistrationRecoveryPreservesCommandAcrossScanLocations(t *testing.T) {
	f, _, request := nativeRegistrationFixture(t)
	utcPool := registrationTestPool(t, f, time.UTC, nil)
	utc, err := oauthpostgres.NewStore(utcPool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := utc.DynamicRegister(f.ctx, request)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("UTC registration", err)
	}
	offsetPool := registrationTestPool(t, f, time.FixedZone("registration-server-east", 2*60*60), nil)
	var scanned time.Time
	if err := offsetPool.Raw().QueryRow(f.ctx, `SELECT created_at FROM oauth_store.initial_registration_tokens`).Scan(&scanned); err != nil {
		t.Fatal(err)
	}
	if _, offset := scanned.Zone(); offset != 2*60*60 {
		t.Fatal("different actual pgx scan location was not selected")
	}
	offset, err := oauthpostgres.NewStore(offsetPool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := offset.RecoverDynamicRegistration(f.ctx, request)
	if err != nil || recovered.Completion.Outcome != identity.CommitOutcomeCommitted || recovered.Completion.CommandID != created.Completion.CommandID {
		t.Fatal("same stored instants changed original command/recovery identity", err)
	}
	if recovered.Client.ID != "" || recovered.ClientSecret != (oauth.Token{}) {
		t.Fatal("timezone recovery fabricated current client or secret")
	}
	requireRegistrationCounts(t, f, 1, 1)
}

func registrationTokenRead(sql string) bool {
	return strings.HasPrefix(sql, "SELECT created_at,expires_at,") && strings.Contains(sql, ".initial_registration_tokens")
}

func TestNativeDynamicRegistrationStorageFailureClassification(t *testing.T) {
	t.Run("storage-unavailable", func(t *testing.T) {
		f, store, request := nativeRegistrationFixture(t)
		service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE oauth_store.initial_registration_tokens RENAME TO unavailable_registration_tokens`); err != nil {
			t.Fatal(err)
		}
		if out, err := store.DynamicRegister(f.ctx, request); !errors.Is(err, oauth.ErrUnavailable) || out.Client.ID != "" {
			t.Error("native storage failure became credential denial", err)
		}
		if out, err := service.DynamicRegister(f.ctx, request); !errors.Is(err, oauth.ErrUnavailable) || out.Client.ID != "" {
			t.Error("root storage failure became credential denial", err)
		}
		var clients, consumed int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.managed_clients),(SELECT count(*) FROM oauth_store.unavailable_registration_tokens WHERE consumed_command IS NOT NULL)`).Scan(&clients, &consumed); err != nil || clients != 0 || consumed != 0 {
			t.Fatal("unavailable storage changed registration", err)
		}
	})
	t.Run("invalid-authority", func(t *testing.T) {
		f, store, request := nativeRegistrationFixture(t)
		wrong, err := oauth.NewToken()
		if err != nil {
			t.Fatal(err)
		}
		request.InitialAccessToken, err = wrong.Reveal()
		if err != nil {
			t.Fatal("wrong-token fixture custody")
		}
		if _, err := store.DynamicRegister(f.ctx, request); !errors.Is(err, oauth.ErrAccessDenied) {
			t.Fatal("invalid authority not denied", err)
		}
		if _, err := store.RecoverDynamicRegistration(f.ctx, request); !errors.Is(err, oauth.ErrAccessDenied) {
			t.Fatal("absent initial authority misclassified as storage outage", err)
		}
		requireRegistrationCounts(t, f, 0, 0)
	})
	t.Run("cancellation-during-read", func(t *testing.T) {
		f, _, request := nativeRegistrationFixture(t)
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		trace := &registrationQueryTrace{start: func(_ context.Context, sql string) {
			if registrationTokenRead(sql) {
				cancel()
			}
		}}
		pool := registrationTestPool(t, f, nil, trace)
		store, err := oauthpostgres.NewStore(pool, f.oauth, f.keys)
		if err != nil {
			t.Fatal(err)
		}
		if out, err := store.DynamicRegister(ctx, request); !errors.Is(err, context.Canceled) || out.Client.ID != "" {
			t.Fatal("native query cancellation became credential denial", err)
		}
		requireRegistrationCounts(t, f, 0, 0)
	})
}

func TestNativeDynamicRegistrationPopulatedManagedCompatibilityAcrossSelection(t *testing.T) {
	f := passwordFixture(t)
	enableClientManagement(t, &f)
	installPublicClients(t, &f)
	disabled, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	privateRequest := clientCreateRequest(t, f, "dcr-preexisting-confidential")
	private, err := disabled.ClientCreate(f.ctx, privateRequest)
	if err != nil || private.Client.Public {
		t.Fatal("existing Public=false confidential creation", err)
	}
	secret, err := private.Secret.Reveal()
	if err != nil {
		t.Fatal("original confidential secret custody")
	}
	basic := confidentialBasic(t, private.Client.ID, secret)
	_, privateRefresh := issuedConfidentialTokens(t, f, disabled, private.Client, basic)
	publicRequest := clientCreateRequest(t, f, "dcr-preexisting-public")
	publicRequest.Public = true
	public, err := disabled.ClientCreate(f.ctx, publicRequest)
	if err != nil || !public.Client.Public || public.Secret != (oauth.Token{}) {
		t.Fatal("existing public creation", err)
	}
	_, publicRefresh := issuedConfidentialTokens(t, f, disabled, public.Client, oauth.ClientAuthentication{})
	var beforeRegistration, beforeDigest []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, private.Client.ID).Scan(&beforeRegistration, &beforeDigest); err != nil {
		t.Fatal(err)
	}
	store, request := enableNativeRegistration(t, &f)
	enabled, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := enabled.DynamicRegister(f.ctx, request)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("enabled registration after populated migration", err)
	}
	if out, err := disabled.DynamicRegister(f.ctx, request); !errors.Is(err, oauth.ErrAccessDenied) || out.Client.ID != "" {
		t.Fatal("original disabled instance admitted registration", err)
	}
	for _, selected := range []bool{true, false, true} {
		config := f.oauth
		managed := *config.Protocol.ManagedClients
		config.Protocol.ManagedClients = &managed
		if !selected {
			managed.DynamicRegistration = nil
		}
		service, err := oauthpostgres.NewService(f.pool, config, f.keys)
		if err != nil {
			t.Fatal(err)
		}
		read := oauth.ClientReadRequest{Owner: managed.Owner, TenantID: f.tenant, Session: f.browser, ClientID: created.Client.ID}
		if got, err := service.ClientGet(f.ctx, read); err != nil || !got.Client.Public || got.Client.ID != created.Client.ID {
			t.Fatal("profile selection stranded durable public registration", err)
		}
		for _, original := range []oauth.ClientManagementRequest{privateRequest, publicRequest} {
			if replay, err := service.ClientCreate(f.ctx, original); err != nil || !replay.Completion.Replayed || replay.Secret != (oauth.Token{}) {
				t.Fatal("profile selection stranded original manager command", err)
			}
		}
		privateTokens, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: private.Client.ID, ClientAuthentication: basic, RefreshToken: privateRefresh, Network: request.Network})
		if err != nil {
			t.Fatal("profile selection broke existing confidential token authority", err)
		}
		privateRefresh, err = privateTokens.RefreshToken.Reveal()
		if err != nil {
			t.Fatal("confidential successor custody")
		}
		publicTokens, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: public.Client.ID, RefreshToken: publicRefresh, Network: request.Network})
		if err != nil {
			t.Fatal("profile selection broke existing public token authority", err)
		}
		publicRefresh, err = publicTokens.RefreshToken.Reveal()
		if err != nil {
			t.Fatal("public successor custody")
		}
		current, err := oauthpostgres.NewStore(f.pool, config, f.keys)
		if err != nil {
			t.Fatal(err)
		}
		recovered, err := current.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-create", CommandID: private.Completion.CommandID, ClientID: private.Client.ID, TenantID: f.tenant, Session: f.browser})
		if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("profile selection changed original confidential recovery", err)
		}
		if !selected {
			if _, err := service.DynamicRegister(f.ctx, request); !errors.Is(err, oauth.ErrAccessDenied) {
				t.Fatal("disabled registration remained callable", err)
			}
		}
	}
	var afterRegistration, afterDigest []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, private.Client.ID).Scan(&afterRegistration, &afterDigest); err != nil || !bytes.Equal(beforeRegistration, afterRegistration) || !bytes.Equal(beforeDigest, afterDigest) {
		t.Fatal("DCR activation rewrote existing confidential custody", err)
	}
	if recovered, err := store.RecoverDynamicRegistration(f.ctx, request); err != nil || recovered.Completion.CommandID != created.Completion.CommandID || recovered.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("populated registration lost original recovery", err)
	}
	requireRegistrationCounts(t, f, 3, 1)
}

func TestNativeDynamicRegistrationExpiryAcrossActualCustodyLockWait(t *testing.T) {
	f, store, request := nativeRegistrationFixture(t)
	digest := sha256.Sum256([]byte(request.InitialAccessToken))
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.initial_registration_tokens SET expires_at=clock_timestamp()+interval '2 seconds' WHERE digest=$1`, digest[:]); err != nil {
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
	if _, err := tx.Exec(f.ctx, `SELECT digest FROM oauth_store.initial_registration_tokens WHERE digest=$1 FOR UPDATE`, digest[:]); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	type answer struct {
		out oauth.DynamicRegisterResult
		err error
	}
	done := make(chan answer, 1)
	go func() { out, err := store.DynamicRegister(ctx, request); done <- answer{out, err} }()
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
			t.Fatal("registration never reached actual custody row wait", early.err)
		case <-time.After(5 * time.Millisecond):
		case <-f.ctx.Done():
			t.Fatal("custody lock observation canceled")
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM(expires_at-clock_timestamp())))+0.02) FROM oauth_store.initial_registration_tokens WHERE digest=$1`, digest[:]); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	result := <-done
	joined = true
	if !errors.Is(result.err, oauth.ErrAccessDenied) || result.out.Client.ID != "" || result.out.ClientSecret != (oauth.Token{}) {
		t.Fatal("expired original custody survived real lock wait", result.err)
	}
	requireRegistrationCounts(t, f, 0, 0)
}

func TestNativeDynamicRegistrationInterruptedBeforeRetainedPreparationRecoversOriginal(t *testing.T) {
	testNativeDynamicRegistrationInterruptedBeforeRetainedPreparationRecoversOriginal(t, false)
}

func TestNativeConfidentialDynamicRegistrationInterruptedBeforeRetainedPreparationRecoversOriginal(t *testing.T) {
	testNativeDynamicRegistrationInterruptedBeforeRetainedPreparationRecoversOriginal(t, true)
}

func TestNativeConfidentialDynamicRegistrationCanceledCommittedDeliveryWithholdsSecret(t *testing.T) {
	f, original, request := nativeRegistrationClassFixture(t, true)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	var committed atomic.Bool
	trace := &registrationQueryTrace{
		end: func(_ context.Context, sql string, err error) {
			if err != nil || !strings.EqualFold(sql, "commit") {
				return
			}
			// Protected Work uses raw extended protocol, outside QueryTracer.
			// Observe its actual committed row from the independent fixture pool
			// only after COMMIT, when no protected lock remains held.
			var count int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.managed_clients`).Scan(&count); err == nil && count == 1 && committed.CompareAndSwap(false, true) {
				cancel()
			}
		},
	}
	pool := registrationTestPool(t, f, nil, trace)
	store, err := oauthpostgres.NewStore(pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	lost, err := store.DynamicRegister(ctx, request)
	if !committed.Load() {
		t.Fatal("actual final COMMIT cancellation seam missed")
	}
	if !errors.Is(err, context.Canceled) || lost.Client.ID != "" || lost.ClientSecret != (oauth.Token{}) {
		t.Fatal("canceled direct-store delivery disclosed client or secret", err)
	}
	recovered, err := original.RecoverDynamicRegistration(f.ctx, request)
	if err != nil || recovered.Completion.CommandID != lost.Completion.CommandID || recovered.Completion.Outcome != identity.CommitOutcomeCommitted || recovered.ClientSecret != (oauth.Token{}) {
		t.Fatal("canceled committed delivery lost original metadata-only recovery", err)
	}
	requireRegistrationCounts(t, f, 1, 1)
}

func testNativeDynamicRegistrationInterruptedBeforeRetainedPreparationRecoversOriginal(t *testing.T, confidential bool) {
	f, original, request := nativeRegistrationClassFixture(t, confidential)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	var hit atomic.Bool
	trace := &registrationQueryTrace{start: func(_ context.Context, sql string) {
		if strings.HasPrefix(sql, "UPDATE identity.commands SET preparation_ciphertext=") && hit.CompareAndSwap(false, true) {
			cancel()
		}
	}}
	pool := registrationTestPool(t, f, nil, trace)
	store, err := oauthpostgres.NewStore(pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	lost, err := store.DynamicRegister(ctx, request)
	if !hit.Load() || !errors.Is(err, context.Canceled) || lost.Completion.Outcome != identity.CommitOutcomeUnknown || lost.Completion.CommandID == "" || lost.Client.ID != "" || lost.ClientSecret != (oauth.Token{}) {
		t.Fatal("actual pre-retention interruption seam missed", err)
	}
	if lost.Completion.Replayed {
		t.Error("first interrupted invocation fabricated replay")
	}
	var state string
	var started, absent, unattached bool
	commandBytes, decodeErr := base64.RawURLEncoding.DecodeString(string(lost.Completion.CommandID))
	if decodeErr != nil {
		t.Fatal("original command syntax")
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state,preparation_started_generation IS NOT NULL,preparation_ciphertext IS NULL,command_plan IS NULL FROM identity.commands WHERE command_id=$1 AND purpose='identity.oauth-server.dynamic-register'`, commandBytes).Scan(&state, &started, &absent, &unattached); err != nil || state != "pending" || !started || !absent || !unattached {
		t.Fatal("interruption did not preserve started-without-output journal", err)
	}
	requireRegistrationCounts(t, f, 0, 0)
	changed := request
	changed.ClientName = "different original intent"
	if result, err := original.RecoverDynamicRegistration(f.ctx, changed); !errors.Is(err, oauth.ErrAccessDenied) || result.Completion.Replayed || result.Client.ID != "" {
		t.Fatal("changed intent acquired original pending history", err)
	}
	recovered, err := original.RecoverDynamicRegistration(f.ctx, request)
	if err != nil || recovered.Completion.Outcome != identity.CommitOutcomeInProgress || recovered.Completion.CommandID != lost.Completion.CommandID {
		t.Fatal("original live pre-retention recovery stranded", err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for recovered.Completion.Outcome == identity.CommitOutcomeInProgress && time.Now().Before(deadline) {
		select {
		case <-time.After(100 * time.Millisecond):
		case <-f.ctx.Done():
			t.Fatal("original pre-retention recovery deadline")
		}
		recovered, err = original.RecoverDynamicRegistration(f.ctx, request)
	}
	if !errors.Is(err, oauth.ErrUnavailable) || recovered.Completion.Outcome != identity.CommitOutcomeNotCommitted || recovered.Completion.CommandID != lost.Completion.CommandID || !recovered.Completion.Replayed || recovered.Client.ID != "" || recovered.ClientSecret != (oauth.Token{}) {
		t.Fatal("original pre-retention recovery lost exact noncommit classification", err)
	}
	retried, err := original.DynamicRegister(f.ctx, request)
	if !errors.Is(err, oauth.ErrUnavailable) || retried.Completion.Outcome != identity.CommitOutcomeNotCommitted || retried.Completion.CommandID != lost.Completion.CommandID || !retried.Completion.Replayed || retried.Client.ID != "" {
		t.Fatal("original pre-retention retry regenerated a command or client", err)
	}
	requireRegistrationCounts(t, f, 0, 0)
}

func TestNativeDynamicRegistrationBootstrapReadbackFailureClassification(t *testing.T) {
	for _, mode := range []string{"storage-unavailable", "cancellation"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _ := nativeRegistrationFixture(t)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			var once sync.Once
			var mutationErr error
			trace := &registrationQueryTrace{}
			if mode == "storage-unavailable" {
				trace.end = func(_ context.Context, sql string, err error) {
					if err == nil && strings.HasPrefix(sql, "INSERT INTO ") && strings.Contains(sql, ".initial_registration_tokens(") {
						once.Do(func() {
							_, mutationErr = f.pool.Raw().Exec(f.ctx, `ALTER TABLE oauth_store.initial_registration_tokens RENAME TO unavailable_registration_tokens`)
						})
					}
				}
			} else {
				trace.start = func(_ context.Context, sql string) {
					if registrationTokenRead(sql) {
						once.Do(cancel)
					}
				}
			}
			pool := registrationTestPool(t, f, nil, trace)
			store, err := oauthpostgres.NewStore(pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			token, err := oauth.NewToken()
			if err != nil {
				t.Fatal(err)
			}
			wire, err := token.Reveal()
			if err != nil {
				t.Fatal("bootstrap fixture custody")
			}
			err = store.BootstrapRegistrationToken(ctx, wire, time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond))
			if mutationErr != nil {
				t.Fatal("actual bootstrap readback fault", mutationErr)
			}
			want := oauth.ErrUnavailable
			if mode == "cancellation" {
				want = context.Canceled
			}
			if !errors.Is(err, want) {
				t.Fatal("classified bootstrap readback failure overwritten", err)
			}
			table := "initial_registration_tokens"
			if mode == "storage-unavailable" {
				table = "unavailable_registration_tokens"
			}
			var tokens, consumed int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),count(consumed_command) FROM oauth_store.`+table).Scan(&tokens, &consumed); err != nil || tokens != 2 || consumed != 0 {
				t.Fatal("bootstrap readback failure lost committed provisioning or consumed custody", err)
			}
		})
	}
}
