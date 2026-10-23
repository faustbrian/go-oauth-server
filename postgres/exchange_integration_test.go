//go:build integration && oauthflow

package oauthpostgres_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	password "github.com/faustbrian/go-password/v2"
)

func exchangeFixture(t *testing.T, faults ...*oauthCommitFault) workloadNativeFixture {
	t.Helper()
	f := workloadFixture(t, faults...)
	// Upgrade an already populated real workload root, not an empty structural
	// schema. Its original issuance remains usable after this optional history.
	old, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := old.Token(f.ctx, workloadRequest(f))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	base := oauthpostgres.WorkloadMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7001}
	source := oauthpostgres.WorkloadExchangeMigrationSource{Base: base, Schema: "oauth_store", Version: 7002}
	backend, err := migrationdb.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("oauth_server")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("populated exchange upgrade failed", err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("exchange migration replay failed", err)
	}
	out, err := old.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: wire})
	if err != nil || !out.Active {
		t.Fatal("optional exchange migration broke original workload", err)
	}
	f.config.Protocol.WorkloadExchange = &oauth.WorkloadExchangePolicy{MaximumDepth: 4, ClockUncertainty: time.Second}
	f.config.WorkloadExchangeClientNamespace = "oauth-exchange-clients"
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := authority.InitializeAuthority(f.ctx, tx, authority.AuthorityScope{TenantID: authorization.TenantID(baselineTenant), PolicyNamespace: f.config.WorkloadExchangeClientNamespace, SubjectID: authorization.SubjectID(f.client.ID)}, time.Second); err != nil {
		t.Fatal("explicit selected client owner bootstrap failed", err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	selected, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selected.Token(f.ctx, exchangeRequest(f, wire, []string{"workload:read"})); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("selected exchange silently adopted a preactivation root/client epoch", err)
	}
	return f
}

func addExchangeClient(t *testing.T, f *workloadNativeFixture, id string) (oauth.Client, oauth.ClientAuthentication) {
	t.Helper()
	client := f.client
	client.ID = id
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
	f.config.Protocol.Clients = append(f.config.Protocol.Clients, client)
	f.config.Protocol.ClientSecrets = append(f.config.Protocol.ClientSecrets, verifier)
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := authority.InitializeAuthority(f.ctx, tx, authority.AuthorityScope{TenantID: authorization.TenantID(baselineTenant), PolicyNamespace: f.config.WorkloadExchangeClientNamespace, SubjectID: authorization.SubjectID(client.ID)}, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return client, confidentialBasic(t, client.ID, wire)
}

func TestNativeRestrictedExchangeWithdrawsOneClientNotSharedWorkload(t *testing.T) {
	f := exchangeFixture(t)
	other, otherCredential := addExchangeClient(t, &f, "other-machine")
	service, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	a, err := service.Token(f.ctx, workloadRequest(f))
	if err != nil {
		t.Fatal(err)
	}
	aWire, err := a.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	child, err := service.Token(f.ctx, exchangeRequest(f, aWire, []string{"workload:read"}))
	if err != nil {
		t.Fatal(err)
	}
	childWire, err := child.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	bRequest := workloadRequest(f)
	bRequest.ClientID = other.ID
	bRequest.ClientAuthentication = otherCredential
	b, err := service.Token(f.ctx, bRequest)
	if err != nil {
		t.Fatal(err)
	}
	bWire, err := b.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := authority.AdvanceAuthority(f.ctx, tx, authority.AuthorityScope{TenantID: authorization.TenantID(baselineTenant), PolicyNamespace: f.config.WorkloadExchangeClientNamespace, SubjectID: authorization.SubjectID(f.client.ID)}, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	for _, wire := range []string{aWire, childWire} {
		requireInactiveIntrospection(t, service, f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: wire})
	}
	if _, err := service.Token(f.ctx, exchangeRequest(f, childWire, nil)); err == nil {
		t.Fatal("withdrawn client lineage exchanged")
	}
	if _, err := service.Token(f.ctx, workloadRequest(f)); err == nil {
		t.Fatal("unchanged withdrawn client registration adopted advanced epoch")
	}
	current, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: other.ID, ClientAuthentication: bRequest.ClientAuthentication, Token: bWire})
	if err != nil || !current.Active {
		t.Fatal("client A withdrawal disabled independent B/shared workload", err)
	}
}

func TestNativeRestrictedExchangeForeignClientAndAuthorityOutageDeny(t *testing.T) {
	f := exchangeFixture(t)
	foreign, foreignCredential := addExchangeClient(t, &f, "foreign-machine")
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
	foreignRequest := exchangeRequest(f, wire, []string{"workload:read"})
	foreignRequest.ClientID = foreign.ID
	foreignRequest.ClientAuthentication = foreignCredential
	if _, err := service.Token(f.ctx, foreignRequest); err == nil {
		t.Fatal("valid foreign client exchanged source token")
	}
	child, err := service.Token(f.ctx, exchangeRequest(f, wire, []string{"workload:read"}))
	if err != nil {
		t.Fatal(err)
	}
	childWire, err := child.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.authorization_subject_authorities RENAME TO unavailable_exchange_authority`); err != nil {
		t.Fatal(err)
	}
	if out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: childWire}); !errors.Is(err, oauth.ErrUnavailable) || out.Active {
		t.Fatal("derived access survived required-owner outage", err)
	}
	if out, err := service.Token(f.ctx, exchangeRequest(f, childWire, nil)); !errors.Is(err, oauth.ErrUnavailable) || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("exchange survived required-owner outage", err)
	}
}

func TestNativeRestrictedExchangeLostCommitRecoversOriginalMetadataOnly(t *testing.T) {
	fault := &oauthCommitFault{}
	f := exchangeFixture(t, fault)
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
	request := exchangeRequest(f, wire, []string{"workload:read"})
	request.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	fault.armed.Store(true)
	lost, err := service.Token(f.ctx, request)
	if !fault.hit.Load() || !errors.Is(err, oauth.ErrUnavailable) || lost.Outcome != identity.CommitOutcomeUnknown || lost.CommandID == "" {
		t.Fatal("actual exchange COMMIT acknowledgement loss not unknown", err)
	}
	if _, err := lost.AccessToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("unknown exchange disclosed token")
	}
	recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: lost.CommandID, ClientID: f.client.ID, Token: wire, ClientAuthentication: f.credential}
	for range 2 {
		out, err := store.Recover(f.ctx, recovery)
		if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("original exchange did not recover metadata", err)
		}
	}
	replayed, err := service.Token(f.ctx, request)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || !replayed.Replayed {
		t.Fatal("exchange replay failed metadata-only reconciliation", err)
	}
	if _, err := replayed.AccessToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("committed replay re-revealed source output")
	}
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE parent_artifact_id IS NOT NULL`).Scan(&count); err != nil || count != 1 {
		t.Fatal("lost COMMIT/recovery created independent child", err)
	}
}

func exchangeRequest(f workloadNativeFixture, token string, scopes []string) oauth.TokenRequest {
	return oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: f.client.ID, ClientAuthentication: f.credential, SubjectToken: token, SubjectTokenType: oauth.AccessTokenType, Resource: f.client.Resource, Scopes: scopes, Network: "192.0.2.1"}
}

func TestNativeRestrictedExchangeNarrowsIntrospectsAndAncestorRevocationDenies(t *testing.T) {
	f := exchangeFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	original, err := service.Token(f.ctx, workloadRequest(f))
	if err != nil {
		t.Fatal(err)
	}
	root, err := original.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	child, err := service.Token(f.ctx, exchangeRequest(f, root, []string{"workload:read"}))
	if err != nil || child.Outcome != identity.CommitOutcomeCommitted || child.IssuedTokenType != oauth.AccessTokenType || child.ExpiresAt.After(original.ExpiresAt) {
		t.Fatal("native workload narrowing failed", err)
	}
	if _, err := child.RefreshToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("exchange manufactured refresh")
	}
	first, err := child.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	grandchild, err := service.Token(f.ctx, exchangeRequest(f, first, nil))
	if err != nil {
		t.Fatal("delegated source rejected", err)
	}
	last, err := grandchild.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	var revisions int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts c JOIN oauth_store.artifacts p ON p.artifact_id=c.parent_artifact_id JOIN oauth_store.artifacts r ON r.artifact_id=c.payload->'Exchange'->>'RootID' JOIN oauth_store.grants g ON g.grant_id=c.grant_id WHERE c.workload_exchange AND (c.payload->'Exchange'->>'RootVersion')::integer=r.metadata_version AND (c.payload->'Exchange'->>'ParentVersion')::integer=p.metadata_version AND (c.payload->'Exchange'->>'GrantVersion')::numeric=g.version`).Scan(&revisions); err != nil || revisions != 2 {
		t.Fatal("root/parent revisions do not identify actual stored metadata and separate grant", err)
	}
	for _, wire := range []string{first, last} {
		metadata, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: wire})
		if err != nil || !metadata.Active || metadata.Subject != "oauth-worker" || len(metadata.Scopes) != 1 || metadata.Scopes[0] != "workload:read" {
			t.Fatal("derived metadata lost workload/ceiling", err)
		}
	}
	if _, err := service.Token(f.ctx, exchangeRequest(f, last, []string{"workload:write"})); !errors.Is(err, oauth.ErrInvalidScope) {
		t.Fatal("source expansion accepted", err)
	}
	if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: first, Network: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	requireInactiveIntrospection(t, service, f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: last})
	if _, err := service.Token(f.ctx, exchangeRequest(f, last, nil)); err == nil {
		t.Fatal("revoked ancestor authorized descendant exchange")
	}
}

func TestNativeRestrictedExchangeDepthAndMissingRootFailClosed(t *testing.T) {
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
	for range 4 {
		out, err := service.Token(f.ctx, exchangeRequest(f, wire, []string{"workload:read"}))
		if err != nil {
			t.Fatal("supported depth rejected", err)
		}
		wire, err = out.AccessToken.Reveal()
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.Token(f.ctx, exchangeRequest(f, wire, nil)); err == nil {
		t.Fatal("fifth exchange accepted")
	}
	// Corrupt only this disposable OAuth-owned projection: the real reader must
	// reject missing/cyclic lineage, never trust the caller or the leaf alone.
	missing, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{Exchange,RootID}',to_jsonb($1::text)) WHERE parent_artifact_id IS NOT NULL`, string(missing)); err != nil {
		t.Fatal(err)
	}
	requireInactiveIntrospection(t, service, f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: wire})
}

func TestNativeRestrictedExchangeConfiguredLowerDepthIsEnforced(t *testing.T) {
	f := exchangeFixture(t)
	f.config.Protocol.WorkloadExchange.MaximumDepth = 1
	service, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	original, err := service.Token(f.ctx, workloadRequest(f))
	if err != nil {
		t.Fatal(err)
	}
	root, err := original.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	child, err := service.Token(f.ctx, exchangeRequest(f, root, []string{"workload:read"}))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := child.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Token(f.ctx, exchangeRequest(f, wire, nil)); err == nil {
		t.Fatal("configured lower depth was ignored")
	}
}

func TestNativeRestrictedExchangeRequiredEffectFailureRollsBack(t *testing.T) {
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
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT reject_exchange CHECK(topic<>'oauth_access.exchanged.v1')`); err != nil {
		t.Fatal(err)
	}
	if out, err := service.Token(f.ctx, exchangeRequest(f, wire, []string{"workload:read"})); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("missing required effect committed exchange")
	}
	var derived int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE parent_artifact_id IS NOT NULL`).Scan(&derived); err != nil || derived != 0 {
		t.Fatal("failed effect left usable derived access", err)
	}
}

func TestNativeRestrictedExchangeRefreshesCurrentAuthorityWithoutRenewingOrigin(t *testing.T) {
	f := exchangeFixture(t)
	long, err := oauth.NewWorkload(f.client.Workload.TenantID(), f.client.Workload.ID(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.client.Workload = long
	f.config.Protocol.Clients = []oauth.Client{f.client}
	service, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	original, err := service.Token(f.ctx, workloadRequest(f))
	if err != nil {
		t.Fatal(err)
	}
	root, err := original.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	child, err := service.Token(f.ctx, exchangeRequest(f, root, []string{"workload:read"}))
	if err != nil {
		t.Fatal(err)
	}
	first, err := child.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	var start, until time.Time
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (payload->'Exchange'->>'SourceReadStartedAt')::timestamptz,(payload->'Exchange'->>'SourceValidUntil')::timestamptz FROM oauth_store.artifacts WHERE parent_artifact_id IS NOT NULL`).Scan(&start, &until); err != nil {
		t.Fatal(err)
	}
	if until.After(start.Add(20*time.Second)) || !child.ExpiresAt.After(until) || !child.ExpiresAt.Equal(original.ExpiresAt) {
		t.Fatal("credential expiry was conflated with original evidence lease")
	}
	timer := time.NewTimer(time.Until(until) + 100*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal("current observation test cancelled")
	}
	current, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: first})
	if err != nil || !current.Active {
		t.Fatal("expired old observation prevented genuine current-owner refresh", err)
	}
	next, err := service.Token(f.ctx, exchangeRequest(f, first, nil))
	if err != nil {
		t.Fatal("fresh primary owner observation did not authorize remaining credential lifetime", err)
	}
	var starts, deadlines int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(DISTINCT payload->'Exchange'->>'SourceReadStartedAt'),count(DISTINCT payload->'Exchange'->>'SourceValidUntil') FROM oauth_store.artifacts WHERE parent_artifact_id IS NOT NULL`).Scan(&starts, &deadlines); err != nil || starts != 1 || deadlines != 1 || !next.ExpiresAt.Equal(child.ExpiresAt) {
		t.Fatal("exchange/copy renewed original provenance or credential ceiling", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.authorization_subject_authorities RENAME TO unavailable_expired_exchange_authority`); err != nil {
		t.Fatal(err)
	}
	nextWire, err := next.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: nextWire}); !errors.Is(err, oauth.ErrUnavailable) || out.Active {
		t.Fatal("expired evidence survived failed mandatory refresh", err)
	}
}

func TestNativeRestrictedExchangeConcurrentRetryHasOneUsableChild(t *testing.T) {
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
	var wg sync.WaitGroup
	type result struct {
		out oauth.TokenResult
		err error
	}
	results := make(chan result, 2)
	request := exchangeRequest(f, wire, []string{"workload:read"})
	request.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := service.Token(f.ctx, request)
			results <- result{out, err}
		}()
	}
	wg.Wait()
	close(results)
	usable := 0
	for r := range results {
		if _, err := r.out.AccessToken.Reveal(); err == nil {
			if r.err != nil || r.out.Replayed || r.out.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("uncertain exchange disclosed access")
			}
			usable++
		}
	}
	var stored int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE parent_artifact_id IS NOT NULL`).Scan(&stored); err != nil || usable != 1 || stored != 1 {
		t.Fatal("concurrent same-source exchange duplicated usable child", err)
	}
}

func TestNativeRestrictedExchangeCorruptLineageAndRootWithdrawalDeny(t *testing.T) {
	for _, scenario := range []string{"cycle", "environment", "expiry", "metadata_version", "grant_version", "root_revoked"} {
		t.Run(scenario, func(t *testing.T) {
			f := exchangeFixture(t)
			service, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			original, err := service.Token(f.ctx, workloadRequest(f))
			if err != nil {
				t.Fatal(err)
			}
			root, err := original.AccessToken.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			child, err := service.Token(f.ctx, exchangeRequest(f, root, []string{"workload:read"}))
			if err != nil {
				t.Fatal(err)
			}
			first, err := child.AccessToken.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			grandchild, err := service.Token(f.ctx, exchangeRequest(f, first, nil))
			if err != nil {
				t.Fatal(err)
			}
			last, err := grandchild.AccessToken.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			var statement string
			switch scenario {
			case "cycle":
				statement = `WITH leaf AS (SELECT artifact_id FROM oauth_store.artifacts WHERE (payload->'Exchange'->>'Depth')::integer=2) UPDATE oauth_store.artifacts SET parent_artifact_id=leaf.artifact_id,payload=jsonb_set(payload,'{Exchange,ParentID}',to_jsonb(leaf.artifact_id)) FROM leaf WHERE (payload->'Exchange'->>'Depth')::integer=1`
			case "environment":
				statement = `UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{Exchange,Environment}','"foreign"') WHERE parent_artifact_id IS NOT NULL`
			case "expiry":
				statement = `UPDATE oauth_store.artifacts SET expires_at=expires_at+interval '1 second' WHERE (payload->'Exchange'->>'Depth')::integer=2`
			case "metadata_version":
				statement = `UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{Exchange,ParentVersion}','2') WHERE parent_artifact_id IS NOT NULL`
			case "grant_version":
				statement = `UPDATE oauth_store.grants SET version=version+1`
			case "root_revoked":
				if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: root, Network: "192.0.2.1"}); err != nil {
					t.Fatal(err)
				}
			}
			if statement != "" {
				if _, err := f.pool.Raw().Exec(f.ctx, statement); err != nil {
					t.Fatal("disposable corruption fixture failed", err)
				}
			}
			requireInactiveIntrospection(t, service, f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: last})
			if _, err := service.Token(f.ctx, exchangeRequest(f, last, nil)); err == nil {
				t.Fatal("invalid root/ancestor metadata authorized exchange")
			}
		})
	}
}
