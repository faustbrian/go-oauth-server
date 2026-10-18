//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	password "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/jackc/pgx/v5/stdlib"
)

// Only actual configured machine requests are authorized. The real public
// engine/service owns decisions; native primary epochs remain separately read.
type workloadPolicy struct{}

func (workloadPolicy) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	decision := authorization.Decision{Outcome: authorization.Deny}
	if err := ctx.Err(); err != nil {
		return decision, err
	}
	_, flowErr := identity.ParseCommandID(string(r.Resource.ID))
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == "oauth-worker" && r.Resource.Type == "identity.anonymous-flow" && flowErr == nil {
		switch r.Action {
		case "identity.oauth-server.token", "identity.oauth-server.token.recover", "identity.oauth-server.revoke", "identity.oauth-server.revoke.recover":
			decision.Outcome = authorization.Allow
		}
	}
	return decision, nil
}

type workloadNativeFixture struct {
	ctx        context.Context
	pool       *database.Pool
	db         *sql.DB
	config     oauthpostgres.Config
	keys       *keyring.Provider
	client     oauth.Client
	credential oauth.ClientAuthentication
}

// Existing public reference owners install their actual histories, but no
// signup, confirmation, password verification or session issuance is performed.
// The workload service below has a zero Session config and no browser custody.
func workloadFixture(t *testing.T, faults ...*oauthCommitFault) workloadNativeFixture {
	t.Helper()
	ctx, pool, db := isolatedPostgres(t, true, faults...)
	keyNames := []string{"fingerprint", "request", "counter", "risk-evidence", "risk-seal", "preauth-cookie", "session-token", "session-csrf", "http-device", "delivery-envelope", "dummy-password", "capability-binding", "capability-signing", "signin-proof", "migration", "counter-replay", "http-rate", "otp-lockout", "otp-wrap", "otp-attempt", "otp-code", "otp-intent", "identifier", "delivery-digest", "delivery-namespace", "password-flow", "signup-binding", "signup-intent", "verification-scope", "capability-replay", "capability-envelope", "counter-envelope", "verification-http", "oauth-intent", "oauth-token", "oauth-envelope", "oauth-envelope-next"}
	keys := make(map[string][32]byte, len(keyNames))
	for _, name := range keyNames {
		var value [32]byte
		if _, err := rand.Read(value[:]); err != nil {
			t.Fatal("fixture entropy unavailable")
		}
		keys[name] = value
	}
	t.Cleanup(func() { clear(keys) })
	graph, err := fixtureGraph(ctx, "https://issuer.example", keys, pool, &registrationMailbox{}, hibpTransport{}, false)
	if err != nil {
		t.Fatal("actual public owner graph unavailable", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := graph.close(bounded); err != nil {
			t.Error("owner graph cleanup failed")
		}
	})
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity"}
	plan, err := graph.stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules})
	if err != nil {
		t.Fatal("real owner migration plan failed", err)
	}
	idempotency, err := identity.NewIdempotencyKey([]byte("oauth-workload-native-install"))
	if err != nil {
		t.Fatal(err)
	}
	installed, err := graph.stores.ReferenceMigrationApply(ctx, reference.ReferenceMigrationApplyRequest{CommandID: "oauth_workload_fixture_install", Plan: plan.Plan, IdempotencyKey: idempotency})
	if err != nil || installed.Result.State() != reference.MigrationApplied {
		t.Fatal("actual owner installation failed", err)
	}
	if err := graph.features.Initialize(ctx); err != nil {
		t.Fatal("actual owner initialization failed", err)
	}
	preparation, err := (kernel.CounterPreparationMigrationSource{Base: graph.stores.MigrationSource(), Version: 1700}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	riskBase := riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "risk_store", Version: 1}, Version: 2}, Version: 3}, Version: 4}
	lockouts, err := (riskpg.LockoutMigrationSource{Base: riskBase, Version: 5}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, extension := range []struct {
		namespace string
		source    migrations.Source
	}{
		{"identity_password_change_kernel", fixtureHistory(preparation[len(preparation)-1:])},
		{"identity_risk_lockouts", fixtureHistory(lockouts[len(lockouts)-1:])},
		{"oauth_server", oauthpostgres.WorkloadMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7001}},
	} {
		backend, err := migrationdb.New(db)
		if err != nil {
			t.Fatal(err)
		}
		backend, err = backend.ForNamespace(extension.namespace)
		if err != nil {
			t.Fatal(err)
		}
		runner, err := migrations.NewRunner(extension.source, backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal("actual owner extension failed", err)
		}
	}
	material := func(name string) []byte { k := keys[name]; return append([]byte(nil), k[:]...) }
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	owner, _ := oauth.NewPlatformOwner("deployment")
	scopes, _ := oauth.NewScopeCatalog([]string{"workload:read", "workload:write"})
	workload, err := oauth.NewWorkload(baselineTenant, "oauth-worker", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := oauth.Client{ID: "machine-client", Owner: owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: "https://resource.example", Scopes: scopes.Scopes(), Workload: workload}
	token, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := password.NewSecret([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oauth.NewClientSecretVerifier(client.ID, client.Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	protocol := oauth.Config{Issuer: issuer, Environment: "native-test", Resource: client.Resource, Scopes: scopes, Clients: []oauth.Client{client}, ClientSecrets: []oauth.ClientSecretVerifier{verifier}, OwningClientIntrospection: true, Clock: clock.System{}, MaximumDuration: 4 * time.Second, CodeTTL: time.Minute, ContinuationTTL: time.Minute, AccessTTL: time.Minute, RefreshTTL: time.Hour}
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "workload-consumer", Revision: 9, Evaluator: workloadPolicy{}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	decisions, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Clock: clock.System{}, Authorization: decisions, PolicyVersion: 9}
	coordinator := kernel.CoordinatorConfig{MaximumDuration: 4 * time.Second, LeaseDuration: 5 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}
	requestKeys, err := kernel.NewRequestKeyConfig("oauth-workload", keys["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := baselineRiskPolicy(9, false, false)
	if err != nil {
		t.Fatal(err)
	}
	digestKey, err := risk.NewCounterDigestKey(1, material("counter"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := risk.NewEvidenceKey(1, material("risk-evidence"), material("risk-seal"))
	if err != nil {
		t.Fatal(err)
	}
	tokenKey, err := oauth.NewTokenDigestKey(1, material("oauth-token"))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := keyring.New(map[string][]byte{"oauth-envelope": material("oauth-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	config := oauthpostgres.Config{Schema: "oauth_store", Protocol: protocol, WorkloadAuthority: oauthpostgres.WorkloadAuthorityConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "oauth-workloads"}, TokenKeys: []oauth.TokenDigestKey{tokenKey}, ActiveTokenKeyVersion: 1, IntentKey: keys["oauth-intent"], ActiveEnvelopeKeyID: "oauth-envelope", Coordinator: coordinator, RequestKeys: requestKeys, PolicyID: "oauth-native", Counters: riskpg.Config{Schema: "risk_store", PolicyVersion: 9, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": material("counter-envelope")}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: protected, Keys: []risk.CounterDigestKey{digestKey}}, EnforceLockouts: true}}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := authority.InitializeAuthority(ctx, tx, authority.AuthorityScope{TenantID: authorization.TenantID(baselineTenant), PolicyNamespace: "oauth-workloads", SubjectID: "oauth-worker"}, time.Second); err != nil {
		t.Fatal("explicit workload authority bootstrap failed", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return workloadNativeFixture{ctx, pool, db, config, provider, client, confidentialBasic(t, client.ID, wire)}
}

func TestNativeWorkloadClientCredentialsIntrospectAndRevokeWithoutHuman(t *testing.T) {
	f := workloadFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal("machine-only native constructor required a human session", err)
	}
	request := oauth.TokenRequest{GrantType: oauth.ClientCredentialsGrant, ClientID: f.client.ID, ClientAuthentication: f.credential, Scopes: []string{"workload:read"}, Resource: f.client.Resource, Network: "192.0.2.1"}
	issued, err := service.Token(f.ctx, request)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual machine grant did not issue access", err)
	}
	if _, err := issued.RefreshToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("machine issuance manufactured refresh")
	}
	wire, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, Token: wire, ClientAuthentication: f.credential})
	if err != nil || !metadata.Active || metadata.Subject != "oauth-worker" || metadata.ClientID != f.client.ID || metadata.Resource != f.client.Resource || len(metadata.Scopes) != 1 || metadata.Scopes[0] != "workload:read" {
		t.Fatal("machine introspection lost exact service/ceiling binding", err)
	}
	if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: f.client.ID, Token: wire, ClientAuthentication: f.credential, Network: "192.0.2.1"}); err != nil {
		t.Fatal("owning machine revocation failed", err)
	}
	requireInactiveIntrospection(t, service, f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, Token: wire, ClientAuthentication: f.credential})
	var users, consents, roots, serviceAudits, created, revoked int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM oauth_store.consents),(SELECT count(*) FROM oauth_store.artifacts WHERE kind=3 AND parent_artifact_id IS NULL AND workload_only),(SELECT count(*) FROM audit.records WHERE action LIKE 'identity.oauth_server.%' AND outcome=1 AND actor_kind=$1 AND actor_id='oauth-worker'),(SELECT count(*) FROM public.outbox_messages WHERE topic='grant.created.v1'),(SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_access.revoked.v1')`, int16(audit.ActorService)).Scan(&users, &consents, &roots, &serviceAudits, &created, &revoked); err != nil || users != 0 || consents != 0 || roots != 1 || serviceAudits != 2 || created != 1 || revoked != 1 {
		t.Fatal("machine flow fabricated human/consent/lineage or omitted atomic effects", err)
	}
}

func TestNativeWorkloadConstructorOwnsOriginalCallerPolicy(t *testing.T) {
	f := workloadFixture(t)
	originalClient := f.client
	originalValue := *f.client.Workload
	originalClient.Workload = &originalValue
	store, err := oauthpostgres.NewStore(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	next, err := oauth.NewWorkload("foreign-tenant", "foreign-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	*f.client.Workload = *next
	r := workloadRequest(f)
	out, err := store.Token(f.ctx, oauth.TokenCommand{Client: originalClient, Request: r})
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("caller replacement changed native frozen policy/fingerprint", err)
	}
	var tenant, sourceID string
	var lifetime bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT tenant_id,workload_source->>'ID',expires_at-created_at=interval '30 seconds' FROM oauth_store.grants`).Scan(&tenant, &sourceID, &lifetime); err != nil || tenant != baselineTenant || sourceID != "oauth-worker" || !lifetime {
		t.Fatal("native issuance used replaced caller workload", err)
	}
}

func workloadRequest(f workloadNativeFixture) oauth.TokenRequest {
	return oauth.TokenRequest{GrantType: oauth.ClientCredentialsGrant, ClientID: f.client.ID, ClientAuthentication: f.credential, Resource: f.client.Resource, Network: "192.0.2.1"}
}

func TestNativeWorkloadDenialPrecedesEffectsAndCurrentAuthorityWithdrawal(t *testing.T) {
	f := workloadFixture(t)
	store, err := oauthpostgres.NewStore(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*oauth.TokenRequest){
		func(r *oauth.TokenRequest) { r.ClientAuthentication = oauth.ClientAuthentication{} },
		func(r *oauth.TokenRequest) {
			r.ClientAuthentication = confidentialBasic(t, f.client.ID, strings.Repeat("w", 43))
		},
		func(r *oauth.TokenRequest) {
			r.ClientAuthentication = confidentialBasic(t, "foreign-client", strings.Repeat("w", 43))
		},
		func(r *oauth.TokenRequest) { r.Scopes = []string{"foreign:write"} },
		func(r *oauth.TokenRequest) { r.Resource = "https://foreign.example" },
		func(r *oauth.TokenRequest) {
			r.GrantType = oauth.RefreshTokenGrant
			r.RefreshToken = strings.Repeat("A", 43)
		},
		func(r *oauth.TokenRequest) { r.Code = strings.Repeat("A", 43) },
	} {
		r := workloadRequest(f)
		change(&r)
		if _, err := service.Token(f.ctx, r); err == nil {
			t.Fatal("core admitted invalid machine variant")
		}
		if _, err := store.Token(f.ctx, oauth.TokenCommand{Client: f.client, Request: r}); err == nil {
			t.Fatal("direct native caller bypassed machine boundary")
		}
	}
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects`).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("invalid machine request left protocol effects", err)
	}
	issued, err := service.Token(f.ctx, workloadRequest(f))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := authority.AdvanceAuthority(f.ctx, tx, authority.AuthorityScope{TenantID: authorization.TenantID(baselineTenant), PolicyNamespace: "oauth-workloads", SubjectID: "oauth-worker"}, 1, time.Second); err != nil {
		t.Fatal("real authority withdrawal failed", err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	requireInactiveIntrospection(t, service, f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, Token: wire, ClientAuthentication: f.credential})
	// Revocation remains possible after authority withdrawal; it cannot issue.
	if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: f.client.ID, Token: wire, ClientAuthentication: f.credential, Network: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	current, err := service.Token(f.ctx, workloadRequest(f))
	if err != nil {
		t.Fatal("current machine epoch did not issue", err)
	}
	currentWire, err := current.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.authorization_subject_authorities RENAME TO unavailable_workload_authorities`); err != nil {
		t.Fatal(err)
	}
	if out, err := service.Token(f.ctx, workloadRequest(f)); !errors.Is(err, oauth.ErrUnavailable) || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("authority outage admitted machine issuance", err)
	}
	if out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, Token: wire, ClientAuthentication: f.credential}); err != nil || out.Active {
		t.Fatal("already revoked token disclosed stale metadata", err)
	}
	if out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, Token: currentWire, ClientAuthentication: f.credential}); !errors.Is(err, oauth.ErrUnavailable) || out.Active {
		t.Fatal("active machine token survived authority outage", err)
	}
}

func TestNativeWorkloadPopulatedForwardUpgradePreservesPublicCodeAndRefresh(t *testing.T) {
	f := passwordFixture(t)
	legacy, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := consentedCode(t, f, legacy)
	issued, err := legacy.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	pending, pendingVerifier := consentedCode(t, f, legacy)
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
	source := oauthpostgres.WorkloadMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7001}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	// A conflicting unowned column must fail, not adopt or partly relax the
	// populated legacy schema. Correcting that exact fixture obstruction is a
	// normal retry of the original forward history, not rewritten migration SQL.
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE oauth_store.grants ADD COLUMN workload_only boolean`); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err == nil {
		t.Fatal("workload migration adopted an existing conflicting object")
	}
	var partial int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='oauth_store' AND table_name='grants' AND (column_name='workload_source' OR column_name='user_id' AND is_nullable='YES')`).Scan(&partial); err != nil || partial != 0 {
		t.Fatal("failed workload migration partly changed legacy authority", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE oauth_store.grants DROP COLUMN workload_only`); err != nil {
		t.Fatal(err)
	}
	first, err := runner.Up(f.ctx)
	if err != nil || len(first.Records()) != 1 {
		t.Fatal("populated workload extension failed", err)
	}
	replayed, err := runner.Up(f.ctx)
	if err != nil || len(replayed.Records()) != 0 {
		t.Fatal("workload upgrade changed original migration history", err)
	}
	workload, err := oauth.NewWorkload(f.tenant, "oauth-worker", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := f.oauth.Protocol.Clients[0]
	client.ID = "machine-client"
	client.Public = false
	client.AuthenticationMethod = "client_secret_basic"
	client.Redirects = nil
	client.Workload = workload
	token, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := password.NewSecret([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	secretVerifier, err := oauth.NewClientSecretVerifier(client.ID, client.Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	f.oauth.Protocol.Clients = append(f.oauth.Protocol.Clients, client)
	f.oauth.Protocol.ClientSecrets = append(f.oauth.Protocol.ClientSecrets, secretVerifier)
	f.oauth.WorkloadAuthority = oauthpostgres.WorkloadAuthorityConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "oauth-workloads"}
	// The installed source's actual policy remains in charge of human requests;
	// this test adds configuration without minting a machine actor via that policy.
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"}); err != nil {
		t.Fatal("workload adoption invalidated installed public refresh", err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: pending, CodeVerifier: pendingVerifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"}); err != nil {
		t.Fatal("workload adoption invalidated installed public code", err)
	}
	// An unchanged web-only process remains able to use the populated schema.
	fresh, freshVerifier := consentedCode(t, f, legacy)
	if _, err := legacy.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: fresh, CodeVerifier: freshVerifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"}); err != nil {
		t.Fatal("typed extension broke unchanged web-only client", err)
	}
	var machineRoots int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.grants WHERE workload_only OR user_id IS NULL`).Scan(&machineRoots); err != nil || machineRoots != 0 {
		t.Fatal("workload adoption relabeled populated human lineage", err)
	}
}

func TestNativeWorkloadUnknownIssuanceRecoversOnlyOriginalMetadata(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed", true: "rolled_back"}[before], func(t *testing.T) {
			fault := &oauthCommitFault{before: before}
			f := workloadFixture(t, fault)
			store, err := oauthpostgres.NewStore(f.pool, f.config, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			service, err := oauth.NewService(f.config.Protocol, oauth.Dependencies{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			fault.armed.Store(true)
			lost, err := service.Token(f.ctx, workloadRequest(f))
			if !fault.hit.Load() || !errors.Is(err, oauth.ErrUnavailable) || lost.Outcome != identity.CommitOutcomeUnknown || lost.CommandID == "" {
				t.Fatal("machine commit loss not unknown", err)
			}
			if _, err := lost.AccessToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
				t.Fatal("unknown machine issuance disclosed access")
			}
			recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: lost.CommandID, ClientID: f.client.ID}
			if _, err := store.Recover(f.ctx, recovery); !errors.Is(err, oauth.ErrInvalidClient) {
				t.Fatal("unauthed machine recovery disclosed metadata", err)
			}
			recovery.ClientAuthentication = f.credential
			want := identity.CommitOutcomeCommitted
			if before {
				want = identity.CommitOutcomeNotCommitted
			}
			if before {
				deadline := time.Now().Add(8 * time.Second)
				for {
					out, err := store.Recover(f.ctx, recovery)
					if err != nil && !errors.Is(err, oauth.ErrUnavailable) {
						t.Fatal("precommit recovery failed", err)
					}
					if out.Outcome == want {
						break
					}
					if out.Outcome != identity.CommitOutcomeInProgress && out.Outcome != identity.CommitOutcomeUnknown || time.Now().After(deadline) {
						t.Fatal("noncommit could not reconcile original lease")
					}
					timer := time.NewTimer(100 * time.Millisecond)
					select {
					case <-timer.C:
					case <-f.ctx.Done():
						timer.Stop()
						t.Fatal("recovery cancelled")
					}
				}
			}
			for range 2 {
				out, err := store.Recover(f.ctx, recovery)
				// Native noncommit retains the original dependency-failure error;
				// its terminal NotCommitted outcome, not nil error, proves rollback.
				if err != nil && !(before && errors.Is(err, oauth.ErrUnavailable)) || out.Outcome != want {
					t.Fatal("original machine recovery failed", err)
				}
			}
			var effects, roots int
			expected := 1
			if before {
				expected = 0
			}
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.effects),(SELECT count(*) FROM oauth_store.artifacts)`).Scan(&effects, &roots); err != nil || effects != expected || roots != expected {
				t.Fatal("recovery issued or changed original effects", err)
			}
		})
	}
}

func TestNativeWorkloadExpiryAndConfiguredTenantOwnerIsolation(t *testing.T) {
	f := workloadFixture(t)
	short, err := oauth.NewWorkload(f.client.Workload.TenantID(), f.client.Workload.ID(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f.client.Workload = short
	f.config.Protocol.Clients = []oauth.Client{f.client}
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
	r := oauth.IntrospectRequest{ClientID: f.client.ID, Token: wire, ClientAuthentication: f.credential}
	foreign := f.config
	foreign.Protocol.Clients = append([]oauth.Client(nil), f.config.Protocol.Clients...)
	foreign.Protocol.Clients[0].Owner, err = oauth.NewPlatformOwner("different-platform")
	if err != nil {
		t.Fatal(err)
	}
	foreignService, err := oauthpostgres.NewService(f.pool, foreign, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	requireInactiveIntrospection(t, foreignService, f.ctx, r)
	foreign.Protocol.Clients[0] = f.client
	foreign.Protocol.Clients[0].Workload, err = oauth.NewWorkload("different-tenant", f.client.Workload.ID(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	foreignService, err = oauthpostgres.NewService(f.pool, foreign, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	requireInactiveIntrospection(t, foreignService, f.ctx, r)
	if out, err := foreignService.Token(f.ctx, workloadRequest(f)); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("missing configured tenant acquired machine authority")
	}
	timer := time.NewTimer(time.Until(issued.ExpiresAt))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal("expiry observation cancelled")
	}
	requireInactiveIntrospection(t, service, f.ctx, r)
	var grants int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.grants`).Scan(&grants); err != nil || grants != 1 {
		t.Fatal("foreign configuration changed original issuance", err)
	}
}

func TestNativeWorkloadOutboxFailureRollsBackAndConcurrentRevocationIsNarrow(t *testing.T) {
	f := workloadFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT reject_workload_created CHECK(topic<>'grant.created.v1')`); err != nil {
		t.Fatal(err)
	}
	if out, err := service.Token(f.ctx, workloadRequest(f)); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("outbox failure did not abort workload grant")
	}
	var grants, artifacts, effects, audits int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.artifacts),(SELECT count(*) FROM oauth_store.effects),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.authorize' AND outcome=1)`).Scan(&grants, &artifacts, &effects, &audits); err != nil || grants+artifacts+effects+audits != 0 {
		t.Fatal("failed paired workload effect escaped rollback", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages DROP CONSTRAINT reject_workload_created`); err != nil {
		t.Fatal(err)
	}
	wires := make([]string, 2)
	for i := range wires {
		out, err := service.Token(f.ctx, workloadRequest(f))
		if err != nil {
			t.Fatal(err)
		}
		wires[i], err = out.AccessToken.Reveal()
		if err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	type revoked struct {
		out oauth.RevokeResult
		err error
	}
	results := make(chan revoked, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: f.client.ID, Token: wires[0], ClientAuthentication: f.credential, Network: "192.0.2.1"})
			results <- revoked{out, err}
		}()
	}
	wg.Wait()
	close(results)
	committed := 0
	for result := range results {
		if result.err == nil && result.out.Outcome == identity.CommitOutcomeCommitted {
			committed++
			continue
		}
		if !errors.Is(result.err, oauth.ErrUnavailable) || result.out.Outcome != identity.CommitOutcomeConflict || result.out.CommandID == "" {
			t.Fatal("concurrent revoke misclassified uncompleted command", result.err)
		}
	}
	if committed == 0 {
		t.Fatal("neither concurrent owner completed withdrawal")
	}
	requireInactiveIntrospection(t, service, f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, Token: wires[0], ClientAuthentication: f.credential})
	active, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, Token: wires[1], ClientAuthentication: f.credential})
	if err != nil || !active.Active {
		t.Fatal("machine revocation overreached independent issuance", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_access.revoked.v1'`).Scan(&effects); err != nil || effects != 1 {
		t.Fatal("concurrent revoke duplicated lifecycle effect", err)
	}
	if out, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: f.client.ID, Token: wires[0], ClientAuthentication: f.credential, Network: "192.0.2.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("already revoked token did not return successful no-op", err)
	}
}
