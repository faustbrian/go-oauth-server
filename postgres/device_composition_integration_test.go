//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	device "github.com/faustbrian/go-oauth-server/device"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	password "github.com/faustbrian/go-password/v2"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/oauth2"
)

type deviceCompositionPolicy struct{}

func (deviceCompositionPolicy) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	decision, err := (workloadPolicy{}).Evaluate(ctx, r)
	if err != nil || decision.Outcome == authorization.Allow {
		return decision, err
	}
	if string(r.Tenant) == baselineTenant {
		switch r.Action {
		case "identity.oauth-server.device-authorize", "identity.oauth-server.device-authorize.recover", "identity.oauth-server.device-token", "identity.oauth-server.device-token.recover":
			if r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == "other-public-web" && r.Resource.Type == "identity.anonymous-flow" && r.Resource.ID != "" {
				return authorization.Decision{Outcome: authorization.Allow}, nil
			}
		case "identity.oauth-server.device-approve", "identity.oauth-server.device-approve.recover", "identity.oauth-server.device-deny", "identity.oauth-server.device-deny.recover":
			if r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(r.Subject.ID) {
				return authorization.Decision{Outcome: authorization.Allow}, nil
			}
		}
	}
	return (&baselineEvaluator{}).Evaluate(ctx, r)
}

type deviceCompositionFixture struct {
	human                               authenticatedPasswordFixture
	history                             migrations.Source
	child                               *op.Service
	workload                            workloadNativeFixture
	access, refresh, machine, delegated string
	snapshot                            string
}

func populatedDeviceComposition(t *testing.T, faults ...*oauthCommitFault) deviceCompositionFixture {
	t.Helper()
	f := passwordFixture(t, faults...)
	enableConsentManagement(t, &f)
	f.oauth.Protocol.Clients[1].DeviceAuthorization = true
	f.oauth.Protocol.Scopes, _ = oauth.NewScopeCatalog(append(f.oauth.Protocol.Scopes.Scopes(), "workload:read"))
	owner, _ := oauth.NewPlatformOwner("deployment")
	workload, err := oauth.NewWorkload(baselineTenant, "oauth-worker", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := oauth.Client{ID: "machine-client", Owner: owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: f.oauth.Protocol.Resource, Scopes: []string{"workload:read"}, Workload: workload}
	secretToken, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	secretWire, err := secretToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := password.NewSecret([]byte(secretWire))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oauth.NewClientSecretVerifier(client.ID, client.Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	f.oauth.Protocol.Clients = append(f.oauth.Protocol.Clients, client)
	f.oauth.Protocol.ClientSecrets = append(f.oauth.Protocol.ClientSecrets, verifier)
	f.oauth.WorkloadAuthority = oauthpostgres.WorkloadAuthorityConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "oauth-workloads"}
	f.oauth.Protocol.WorkloadExchange = &oauth.WorkloadExchangePolicy{MaximumDepth: 4, ClockUncertainty: time.Second}
	f.oauth.WorkloadExchangeClientNamespace = "oauth-exchange-clients"
	f.oauth.ConsentReuseTTL = time.Minute
	query, admission := *f.oauth.Coordinator.QueryPolicy, *f.oauth.Coordinator.AdmissionPolicy
	snapshotPolicy, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "device-composition-consumer", Revision: 9, Evaluator: deviceCompositionPolicy{}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshotPolicy)
	if err != nil {
		t.Fatal(err)
	}
	decisions, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	query.Authorization, admission.Authorization = decisions, decisions
	f.oauth.Coordinator.QueryPolicy, f.oauth.Coordinator.AdmissionPolicy = &query, &admission
	base := oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}
	machines := oauthpostgres.WorkloadMigrationSource{Base: base, Schema: "oauth_store", Version: 7010}
	signing := oauthpostgres.SigningMigrationSource{Base: machines, Schema: "oauth_store", Version: 7011}
	expiry := oauthpostgres.ConsentExpiryMigrationSource{Base: signing, Schema: "oauth_store", Version: 7012}
	history := oauthpostgres.WorkloadExchangeMigrationSource{Base: expiry, Schema: "oauth_store", Version: 7013}
	core, oidc := deviceCompositionOIDC(t, &f, history)
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	for _, scope := range []authority.AuthorityScope{
		{TenantID: authorization.TenantID(baselineTenant), PolicyNamespace: "oauth-workloads", SubjectID: "oauth-worker"},
		{TenantID: authorization.TenantID(baselineTenant), PolicyNamespace: f.oauth.WorkloadExchangeClientNamespace, SubjectID: authorization.SubjectID(client.ID)},
	} {
		if _, err := authority.InitializeAuthority(f.ctx, tx, scope, time.Second); err != nil {
			t.Fatal("real workload authority bootstrap", err)
		}
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	code, pkce := oidcCode(t, f, core, "device-coexistence-original")
	issued, err := core.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, RedirectURI: "https://client.example/callback", CodeVerifier: pkce, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("genuine preupgrade human issuance", err)
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	silent, err := core.Authorize(f.ctx, silentRequest(f, oauth2.GenerateVerifier()))
	if err != nil || silent.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("genuine preupgrade silent root", err)
	}
	w := workloadNativeFixture{ctx: f.ctx, pool: f.pool, config: f.oauth, keys: f.keys, client: client, credential: confidentialBasic(t, client.ID, secretWire)}
	root, err := core.Token(f.ctx, workloadRequest(w))
	if err != nil {
		t.Fatal("genuine preupgrade workload root", err)
	}
	machine, err := root.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	child, err := core.Token(f.ctx, exchangeRequest(w, machine, []string{"workload:read"}))
	if err != nil {
		t.Fatal("genuine preupgrade workload child", err)
	}
	delegated, err := child.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot string
	if err := f.pool.Raw().QueryRow(f.ctx, deviceCompositionSnapshot).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return deviceCompositionFixture{human: f, history: history, child: oidc, workload: w, access: access, refresh: refresh, machine: machine, delegated: delegated, snapshot: snapshot}
}

const deviceCompositionSnapshot = `SELECT jsonb_build_object('consents',(SELECT jsonb_agg(to_jsonb(c) ORDER BY consent_id) FROM oauth_store.consents c),'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY grant_id) FROM oauth_store.grants g),'artifacts',(SELECT jsonb_agg(to_jsonb(a)-'device_root'-'device_root_grant' ORDER BY artifact_id) FROM oauth_store.artifacts a))::text`

func deviceCompositionOIDC(t *testing.T, f *authenticatedPasswordFixture, history migrations.Source) (*oauth.Service, *op.Service) {
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
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("selected current OAuth history install", err)
	}
	f.oauth.Protocol.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
	f.oauth.Protocol.Clients[0].Scopes = append(f.oauth.Protocol.Clients[0].Scopes, "openid")
	issuer := f.oauth.Protocol.Issuer.String()
	f.oauth.Protocol.Discovery = oauth.DiscoveryConfig{Enabled: true, AuthorizationEndpoint: issuer + "/oauth2/authorize", TokenEndpoint: issuer + "/oauth2/token", RevocationEndpoint: issuer + "/oauth2/revoke"}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	core, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := oauth.NewSigningAuthority(f.oauth.Protocol.Clock, f.oauth.Protocol.AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := oauth.NewSigningService(keys, store)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.Install(f.ctx, "initial", key); err != nil {
		t.Fatal(err)
	}
	var subjectKey [32]byte
	if _, err := rand.Read(subjectKey[:]); err != nil {
		t.Fatal(err)
	}
	child, err := op.NewService(op.Config{Issuer: f.oauth.Protocol.Issuer, JWKSURI: issuer + "/oauth2/jwks", UserInfoEndpoint: issuer + "/oauth2/userinfo", Signing: signing, SubjectKey: subjectKey, Clock: f.oauth.Protocol.Clock, MaximumDuration: f.oauth.Protocol.MaximumDuration}, core)
	clear(subjectKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := child.JWKS(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := signing.Activate(f.ctx, "initial"); err != nil {
		t.Fatal(err)
	}
	composed, err := core.WithOIDC(child)
	if err != nil {
		t.Fatal(err)
	}
	return composed, child
}

func TestNativeDeviceCompositionPopulatedWorkloadSilentExchangeHistory(t *testing.T) {
	c := populatedDeviceComposition(t)
	f := c.human
	source := oauthpostgres.DeviceCompositionMigrationSource{Base: c.history, Schema: "oauth_store", Version: 7020}
	d, core := nativeDeviceFixtureWithHistory(t, &f, source)
	for _, request := range []device.DeviceRequest{
		{ClientID: "public-web", Scopes: []string{"openid"}, Network: "192.0.2.1"},
		{ClientID: "other-public-web", Scopes: []string{"openid"}, Network: "192.0.2.1"},
		{ClientID: c.workload.client.ID, ClientAuthentication: c.workload.credential, Scopes: []string{"workload:read"}, Network: "192.0.2.1"},
	} {
		if out, err := d.Authorize(f.ctx, request); err == nil || out.Completion.Outcome == identity.CommitOutcomeCommitted || out.UserCode != "" {
			t.Fatal("mixed composition admitted an unselected OIDC/workload device grant")
		}
	}
	var after string
	if err := f.pool.Raw().QueryRow(f.ctx, deviceCompositionSnapshot).Scan(&after); err != nil || after != c.snapshot {
		t.Fatal("device extension changed populated original grant/consent/artifact authority", err)
	}
	if user, err := c.child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: c.access}); err != nil || user.Subject == "" {
		t.Fatal("device history withdrew original OIDC access authority", err)
	}
	composed, err := core.WithOIDC(c.child)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := composed.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: c.refresh, Network: "192.0.2.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("device history withdrew original human refresh authority", err)
	}
	for _, original := range []string{c.machine, c.delegated} {
		if out, err := core.Token(f.ctx, exchangeRequest(c.workload, original, []string{"workload:read"})); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("device history withdrew original workload root or delegated child", err)
		}
	}
	if out, err := composed.Authorize(f.ctx, silentRequest(f, oauth2.GenerateVerifier())); err != nil || out.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("device history changed silent-code root semantics", err)
	}
	issued, wire := issueNativeDeviceForClient(t, f, d, "other-public-web")
	verification := device.Verification{Session: f.browser, UserCode: issued.UserCode, Network: "192.0.2.1"}
	if prompt, err := d.Inspect(f.ctx, verification); err != nil || prompt.ClientID != "other-public-web" || prompt.UserCode != issued.UserCode {
		t.Fatal("genuine session inspection after populated upgrade", err)
	}
	if _, err := d.Approve(f.ctx, device.Approval{Verification: verification, Origin: f.oauth.Protocol.Issuer.String(), CSRF: f.csrf, ConfirmedUserCode: issued.UserCode}); err != nil {
		t.Fatal("genuine explicit approval after populated upgrade", err)
	}
	devicePollDue(t, f)
	polled, err := d.Poll(f.ctx, device.TokenExchange{ClientID: "other-public-web", DeviceCode: wire, Network: "192.0.2.1"})
	if err != nil || polled.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real device token issuance after populated upgrade", err)
	}
	access, err := polled.Tokens.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	client := f.oauth.Protocol.Clients[1]
	policy := resourcePolicy(f, client)
	policy.Scopes, err = oauth.NewScopeCatalog(client.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	v, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, policy)
	if err != nil {
		t.Fatal(err)
	}
	if principal, err := v.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"}); err != nil || principal.Subject() == "" || principal.TenantID() != f.tenant {
		t.Fatal("device access was not actual current human resource authority", err)
	}
	refresh, err := polled.Tokens.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := core.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "other-public-web", RefreshToken: refresh, Network: "192.0.2.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("device root did not retain actual refresh authority", err)
	}
	if user, err := c.child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: c.access}); err != nil || user.Subject == "" {
		t.Fatal("device approval or issuance changed the independent original OIDC grant", err)
	}
	requireDeviceCompositionConstraints(t, f)
}

func requireDeviceCompositionConstraints(t *testing.T, f authenticatedPasswordFixture) {
	t.Helper()
	for _, tc := range []struct{ name, sql, code string }{
		{"delegated-workload-needs-parent", `UPDATE oauth_store.artifacts SET parent_artifact_id=NULL WHERE workload_exchange`, "23514"},
		{"ordinary-child-needs-parent", `UPDATE oauth_store.artifacts SET parent_artifact_id=NULL WHERE kind=3 AND NOT workload_only AND NOT device_root`, "23514"},
		{"silent-root-needs-marker", `UPDATE oauth_store.artifacts SET silent_code=false WHERE silent_code`, "23514"},
		{"device-root-needs-marker", `UPDATE oauth_store.artifacts SET device_root=false WHERE device_root`, "23514"},
		{"device-root-cannot-be-code", `UPDATE oauth_store.artifacts SET kind=2 WHERE device_root`, "23514"},
		{"device-cannot-relabel-workload", `UPDATE oauth_store.artifacts SET device_root=true WHERE workload_only AND NOT workload_exchange`, "23514"},
		{"human-tenant-consent-binding", `UPDATE oauth_store.grants SET tenant_id='foreign-tenant' WHERE user_id IS NOT NULL`, "23503"},
		{"human-subject-consent-binding", `UPDATE oauth_store.grants SET user_id='foreign-user' WHERE user_id IS NOT NULL`, "23503"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := f.pool.Raw().Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			_, err = tx.Exec(f.ctx, tc.sql)
			var denied *pgconn.PgError
			if !errors.As(err, &denied) || denied.Code != tc.code {
				t.Fatal("selected root/owner invariant weakened or rejection absent")
			}
		})
	}
	var unvalidated int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid='oauth_store.artifacts'::regclass AND NOT convalidated`).Scan(&unvalidated); err != nil || unvalidated != 0 {
		t.Fatal("device composition enabled before all constraints validated", err)
	}
}

func TestNativeDeviceCompositionInstallContentionRollsBackThenReplays(t *testing.T) {
	c := populatedDeviceComposition(t)
	f := c.human
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
	source := oauthpostgres.DeviceCompositionMigrationSource{Base: c.history, Schema: "oauth_store", Version: 7020}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(f.ctx, `LOCK TABLE oauth_store.artifacts IN SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err == nil {
		t.Fatal("device install ignored conflicting populated-table lock")
	}
	var absent bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT to_regclass('oauth_store.devices') IS NULL AND NOT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='oauth_store' AND table_name='artifacts' AND column_name='device_root')`).Scan(&absent); err != nil || !absent {
		t.Fatal("failed bounded install retained partial device schema", err)
	}
	var after string
	if err := f.pool.Raw().QueryRow(f.ctx, deviceCompositionSnapshot).Scan(&after); err != nil || after != c.snapshot {
		t.Fatal("failed install changed populated authority", err)
	}
	if err := blocker.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if installed, err := runner.Up(f.ctx); err != nil || len(installed.Records()) != 2 {
		t.Fatal("original forward source could not resume after lock release", err)
	}
	if replay, err := runner.Up(f.ctx); err != nil || len(replay.Records()) != 0 {
		t.Fatal("replay changed installed predecessor or suffix identity", err)
	}
}

func TestNativeDeviceCompositionConsentWithdrawalDeniesOriginalApproval(t *testing.T) {
	c := populatedDeviceComposition(t)
	f := c.human
	d, core := nativeDeviceFixtureWithHistory(t, &f, oauthpostgres.DeviceCompositionMigrationSource{Base: c.history, Schema: "oauth_store", Version: 7020})
	issued, wire := issueNativeDeviceForClient(t, f, d, "other-public-web")
	if _, err := d.Approve(f.ctx, device.Approval{Verification: device.Verification{Session: f.browser, UserCode: issued.UserCode, Network: "192.0.2.1"}, Origin: f.oauth.Protocol.Issuer.String(), CSRF: f.csrf, ConfirmedUserCode: issued.UserCode}); err != nil {
		t.Fatal(err)
	}
	list := ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0).Input()
	list.Limit = 64
	command, err := oauth.NewConsentCommand(list)
	if err != nil {
		t.Fatal(err)
	}
	page, err := core.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: command})
	if err != nil || len(page.Page.Items()) != 2 {
		t.Fatal("real approving user's consent absent", err)
	}
	var consent oauth.Consent
	for _, item := range page.Page.Items() {
		if item.ClientID() == "other-public-web" {
			consent = item
		}
	}
	if consent.ID() == "" {
		t.Fatal("device approving user's actual consent absent")
	}
	if out, err := core.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRemove, consent.ID(), consent.Version())}); err != nil || !out.Deleted {
		t.Fatal("real consent withdrawal failed", err)
	}
	devicePollDue(t, f)
	if out, err := d.Poll(f.ctx, device.TokenExchange{ClientID: "other-public-web", DeviceCode: wire, Network: "192.0.2.1"}); !errors.Is(err, device.ErrAccessDenied) || out.Tokens.CommandID != "" {
		t.Fatal("withdrawn approval issued device tokens", err)
	}
	var roots int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE device_root`).Scan(&roots); err != nil || roots != 0 {
		t.Fatal("withdrawn approval persisted partial token roots", err)
	}
}

func TestNativeDeviceCompositionUnknownTokenCommitRecoversOnlyOriginalMetadata(t *testing.T) {
	fault := &oauthCommitFault{}
	c := populatedDeviceComposition(t, fault)
	f := c.human
	d, _ := nativeDeviceFixtureWithHistory(t, &f, oauthpostgres.DeviceCompositionMigrationSource{Base: c.history, Schema: "oauth_store", Version: 7020})
	issued, wire := issueNativeDeviceForClient(t, f, d, "other-public-web")
	if _, err := d.Approve(f.ctx, device.Approval{Verification: device.Verification{Session: f.browser, UserCode: issued.UserCode, Network: "192.0.2.1"}, Origin: f.oauth.Protocol.Issuer.String(), CSRF: f.csrf, ConfirmedUserCode: issued.UserCode}); err != nil {
		t.Fatal(err)
	}
	devicePollDue(t, f)
	fault.armed.Store(true)
	request := device.TokenExchange{ClientID: "other-public-web", DeviceCode: wire, Network: "192.0.2.1"}
	lost, err := d.Poll(f.ctx, request)
	if !fault.hit.Load() || err == nil || lost.Completion.Outcome != identity.CommitOutcomeUnknown || lost.Completion.CommandID == "" {
		t.Fatal("actual token COMMIT acknowledgement loss was guessed", err)
	}
	if _, err := lost.Tokens.AccessToken.Reveal(); err == nil {
		t.Fatal("unknown outcome revealed access custody")
	}
	if _, err := lost.Tokens.RefreshToken.Reveal(); err == nil {
		t.Fatal("unknown outcome revealed refresh custody")
	}
	for range 2 {
		metadata, err := d.Recover(f.ctx, device.Recovery{OperationID: "identity.oauth-server.device-token", CommandID: lost.Completion.CommandID, ClientID: "other-public-web", DeviceCode: wire})
		if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted || metadata.CommandID != lost.Completion.CommandID {
			t.Fatal("unknown token outcome did not recover exact original commitment", err)
		}
	}
	if _, err := d.Poll(f.ctx, request); !errors.Is(err, device.ErrAccessDenied) {
		t.Fatal("unknown committed poll redelivered credentials", err)
	}
	var roots, effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.artifacts WHERE device_root),(SELECT count(*) FROM oauth_store.device_effects WHERE operation_id='identity.oauth-server.device-token')`).Scan(&roots, &effects); err != nil || roots != 2 || effects != 1 {
		t.Fatal("metadata recovery duplicated actual device effects", err)
	}
}
