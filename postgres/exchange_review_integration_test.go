//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	password "github.com/faustbrian/go-password/v2"
	"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/oauth2"
)

func TestNativeRestrictedExchangeSourceReusableAndExplicitIntentBoundRetry(t *testing.T) {
	f := exchangeFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	original, err := service.Token(f.ctx, workloadRequest(f))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := original.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	read := exchangeRequest(f, wire, []string{"workload:read"})
	read.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Token(f.ctx, read)
	if err != nil {
		t.Fatal(err)
	}
	if first.CommandID != read.CommandID {
		t.Fatal("trusted explicit command was not retained")
	}
	firstWire, err := first.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	write, err := service.Token(f.ctx, exchangeRequest(f, wire, []string{"workload:write"}))
	if err != nil || write.Replayed {
		t.Fatal("active standard source was capped to one exchange", err)
	}
	writeWire, err := write.AccessToken.Reveal()
	if err != nil {
		t.Fatal("second legitimate exchange did not issue access", err)
	}
	for _, token := range []string{wire, firstWire, writeWire} {
		metadata, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: token})
		if err != nil || !metadata.Active {
			t.Fatal("reusable source or independent child withdrawn", err)
		}
	}
	for _, changed := range []bool{false, true} {
		retry := read
		if changed {
			retry.Scopes = []string{"workload:write"}
		}
		out, err := service.Token(f.ctx, retry)
		if changed {
			if err == nil || out.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("terminal retry reported another intent as committed")
			}
		} else if err != nil || out.Outcome != identity.CommitOutcomeCommitted || !out.Replayed {
			t.Fatal("exact original command did not return metadata", err)
		}
		if _, err := out.AccessToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("terminal retry disclosed original/new token")
		}
	}
	// An equivalent destination expressed through another RFC field is still
	// a different retained request, not permission to report it as committed.
	changedTarget := read
	changedTarget.Resource, changedTarget.Audience = "", read.Resource
	if out, err := service.Token(f.ctx, changedTarget); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.AccessToken != (oauth.Token{}) {
		t.Fatal("changed target selector reused original command metadata", err)
	}
	otherRoot, err := service.Token(f.ctx, workloadRequest(f))
	if err != nil {
		t.Fatal(err)
	}
	otherWire, err := otherRoot.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	changedSource := read
	changedSource.SubjectToken = otherWire
	if out, err := service.Token(f.ctx, changedSource); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.AccessToken != (oauth.Token{}) {
		t.Fatal("changed source reused original command metadata", err)
	}
	var children int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE workload_exchange`).Scan(&children); err != nil || children != 2 {
		t.Fatal("retry duplicated or source reuse suppressed child", err)
	}
}

func TestNativeRestrictedExchangeBeforeCommitAndOriginalObservationRetry(t *testing.T) {
	fault := &oauthCommitFault{before: true}
	f := exchangeFixture(t, fault)
	long, err := oauth.NewWorkload(f.client.Workload.TenantID(), f.client.Workload.ID(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.client.Workload = long
	f.config.Protocol.Clients = []oauth.Client{f.client}
	store, err := oauthpostgres.NewStore(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := oauth.NewService(f.config.Protocol, oauth.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	original, err := service.Token(f.ctx, workloadRequest(f))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := original.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	r := exchangeRequest(f, wire, []string{"workload:read"})
	r.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	fault.armed.Store(true)
	lost, err := service.Token(f.ctx, r)
	if !fault.hit.Load() || !errors.Is(err, oauth.ErrUnavailable) || lost.Outcome != identity.CommitOutcomeUnknown || lost.CommandID != r.CommandID {
		t.Fatal("actual pre-COMMIT loss did not retain original command", err)
	}
	r.CommandID = lost.CommandID
	commandBytes, err := base64.RawURLEncoding.Strict().DecodeString(string(r.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	type custody struct {
		started, preparation string
		created              time.Time
		digest               [32]byte
	}
	readCustody := func() custody {
		t.Helper()
		var c custody
		var ciphertext []byte
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT preparation_started_generation::text,preparation_ciphertext_generation::text,created_at,preparation_ciphertext FROM identity.commands WHERE command_id=$1`, commandBytes).Scan(&c.started, &c.preparation, &c.created, &ciphertext); err != nil {
			t.Fatal("original pending custody unavailable", err)
		}
		c.digest = sha256.Sum256(ciphertext)
		clear(ciphertext)
		return c
	}
	before := readCustody()
	// Leave the actual encrypted preparation pending past its original maximum
	// 20s observation, while its real source credential remains usable for 60s.
	timer := time.NewTimer(time.Until(started.Add(21 * time.Second)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal("original observation wait cancelled")
	}
	metadata, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: wire})
	if err != nil || !metadata.Active {
		t.Fatal("source could not obtain a distinct fresh current-owner observation", err)
	}
	retried, retryErr := service.Token(f.ctx, r)
	if retried.Outcome != identity.CommitOutcomeNotCommitted || retried.AccessToken != (oauth.Token{}) {
		t.Fatal("retry renewed original pending admission or issued a second token", retryErr)
	}
	if after := readCustody(); after != before {
		t.Fatal("expired retry renewed original preparation, admission time or encrypted deadline")
	}
	// Metadata recovery takes the coordinator's own new fence generation/lease
	// to prove rollback under locks. That is not renewed issuance admission:
	// original encrypted input/observation and preparation generation stay fixed.
	recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: r.CommandID, ClientID: f.client.ID, ClientAuthentication: f.credential, Token: wire}
	for range 2 {
		out, err := store.Recover(f.ctx, recovery)
		if out.Outcome != identity.CommitOutcomeNotCommitted || err != nil && !errors.Is(err, oauth.ErrUnavailable) {
			t.Fatal("expired real pending command could not prove original rollback", err)
		}
	}
	var children, effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.artifacts WHERE workload_exchange),(SELECT count(*) FROM oauth_store.effects WHERE command_id=$1)`, string(r.CommandID)).Scan(&children, &effects); err != nil || children != 0 || effects != 0 {
		t.Fatal("pending retry/recovery created delegated effects", err)
	}
}

func TestNativeRestrictedExchangeChangedTerminalIntentDenied(t *testing.T) {
	f := exchangeFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	original, err := service.Token(f.ctx, workloadRequest(f))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := original.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	r := exchangeRequest(f, wire, []string{"workload:read"})
	r.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Token(f.ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Scopes = []string{"workload:write"}
	out, err := service.Token(f.ctx, r)
	if err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.AccessToken != (oauth.Token{}) {
		t.Fatal("changed terminal intent reused another scope's committed metadata", err)
	}
}

type mixedOAuthPolicy struct{}

func (mixedOAuthPolicy) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == "oauth-worker" {
		return (workloadPolicy{}).Evaluate(ctx, r)
	}
	return (&baselineEvaluator{}).Evaluate(ctx, r)
}

func TestNativeRestrictedExchangePopulatedSilentHistoryAndSubsequentBothProfiles(t *testing.T) {
	f := passwordFixture(t)
	base := oauthpostgres.WorkloadMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7001}
	consent := oauthpostgres.ConsentMigrationSource{Base: base, Schema: "oauth_store", Version: 7002}
	signing := oauthpostgres.SigningMigrationSource{Base: consent, Schema: "oauth_store", Version: 7003}
	expiry := oauthpostgres.ConsentExpiryMigrationSource{Base: signing, Schema: "oauth_store", Version: 7004}
	f.oauth.ConsentManagement = true
	f.oauth.ConsentReuseTTL = time.Minute
	machine := f.oauth.Protocol.Clients[0]
	machine.ID = "mixed-machine"
	machine.Public = false
	machine.AuthenticationMethod = "client_secret_basic"
	machine.Redirects = nil
	var err error
	machine.Workload, err = oauth.NewWorkload(f.tenant, "oauth-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	secretWire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := password.NewSecret([]byte(secretWire))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oauth.NewClientSecretVerifier(machine.ID, machine.Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	f.oauth.Protocol.Clients = append(f.oauth.Protocol.Clients, machine)
	f.oauth.Protocol.ClientSecrets = append(f.oauth.Protocol.ClientSecrets, verifier)
	f.oauth.WorkloadAuthority = oauthpostgres.WorkloadAuthorityConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "oauth-workloads"}
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "mixed-profile", Revision: 9, Evaluator: mixedOAuthPolicy{}})
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
	query := *f.oauth.Coordinator.QueryPolicy
	query.Authorization = decisions
	f.oauth.Coordinator.QueryPolicy = &query
	f.oauth.Coordinator.AdmissionPolicy = &query
	service, child, _, _, _ := oidcFixtureWithLifecycle(t, &f, clock.System{}, nil, expiry)
	oidcCode(t, f, service, "mixed-explicit")
	proof := oauth2.GenerateVerifier()
	silent, err := service.Authorize(f.ctx, silentRequest(f, proof))
	if err != nil || silent.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("real populated silent root failed", err)
	}
	code, err := silent.Code.Reveal()
	if err != nil {
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
	source := oauthpostgres.WorkloadExchangeMigrationSource{Base: expiry, Schema: "oauth_store", Version: 7005}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("exchange suffix rejected real populated silent root", err)
	}
	f.oauth.Protocol.WorkloadExchange = &oauth.WorkloadExchangePolicy{MaximumDepth: 4, ClockUncertainty: time.Second}
	f.oauth.WorkloadExchangeClientNamespace = "oauth-exchange-clients"
	f.oauth.Protocol.OwningClientIntrospection = true
	f.oauth.Protocol.Discovery.IntrospectionEndpoint = f.oauth.Protocol.Issuer.String() + "/oauth2/introspect"
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	for _, scope := range []authority.AuthorityScope{{TenantID: authorization.TenantID(f.tenant), PolicyNamespace: "oauth-workloads", SubjectID: "oauth-worker"}, {TenantID: authorization.TenantID(f.tenant), PolicyNamespace: f.oauth.WorkloadExchangeClientNamespace, SubjectID: authorization.SubjectID(machine.ID)}} {
		if _, err := authority.InitializeAuthority(f.ctx, tx, scope, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	selected, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	selected, err = selected.WithOIDC(child)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := selected.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: proof, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("populated silent code became unusable", err)
	}
	if out, err := selected.Authorize(f.ctx, silentRequest(f, oauth2.GenerateVerifier())); err != nil || out.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("new suffix rejected subsequent actual silent issuance", err)
	}
	credential := confidentialBasic(t, machine.ID, secretWire)
	root, err := selected.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.ClientCredentialsGrant, ClientID: machine.ID, ClientAuthentication: credential, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("mixed root issuance", err)
	}
	rootWire, err := root.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	derived, err := selected.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: machine.ID, ClientAuthentication: credential, SubjectToken: rootWire, SubjectTokenType: oauth.AccessTokenType, Resource: machine.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.1"})
	if err != nil || derived.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("mixed silent history rejected delegated workload issuance", err)
	}
	derivedWire, err := derived.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if current, err := selected.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: machine.ID, ClientAuthentication: credential, Token: derivedWire}); err != nil || !current.Active {
		t.Fatal("mixed history delegated access was not usable", err)
	}
}

func TestNativeRestrictedExchangeLaterConsentExpiryRejectedBeforeMutation(t *testing.T) {
	f := exchangeFixture(t)
	base := oauthpostgres.WorkloadExchangeMigrationSource{Base: oauthpostgres.WorkloadMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7001}, Schema: "oauth_store", Version: 7002}
	consent := oauthpostgres.ConsentMigrationSource{Base: base, Schema: "oauth_store", Version: 7003}
	later := oauthpostgres.ConsentExpiryMigrationSource{Base: consent, Schema: "oauth_store", Version: 7004}
	if _, err := later.Load(f.ctx); err == nil {
		t.Fatal("unsupported later consent expiry was not rejected before migration")
	} else {
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) || invalid.Field != "oauth_consent_expiry_migration_order" {
			t.Fatal("history order rejection was not typed", err)
		}
	}
	var columns int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='oauth_store' AND table_name='artifacts' AND column_name='silent_code'`).Scan(&columns); err != nil || columns != 0 {
		t.Fatal("rejected pure history changed schema", err)
	}
}
