//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

// Compose the existing real public decision service for machines with the
// original genuine-human manager service; neither identity substitutes for the other.
type managedWorkloadDecisions struct {
	authorization.Service
	machines authorization.Service
}

func TestNativeManagedWorkloadExactManagerAndTokenDenials(t *testing.T) {
	f := passwordFixture(t)
	denied := enableClientManagement(t, &f)
	w := installManagedWorkloadProfile(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	r := managedWorkloadCreateRequest(t, f, w, "machine-denied-creation")
	other, otherCSRF := f.anotherUser()
	for _, mode := range []string{"owner", "tenant", "user", "csrf", "origin", "redirect", "scope", "public", "device", "workload", "policy"} {
		bad := r
		switch mode {
		case "owner":
			bad.Owner, _ = oauth.NewPlatformOwner("foreign")
		case "tenant":
			bad.TenantID = "foreign"
		case "user":
			bad.Session, bad.CSRF = other, otherCSRF
		case "csrf":
			bad.CSRF, _ = session.NewCSRFToken()
		case "origin":
			bad.Origin = "https://foreign.example"
		case "redirect":
			bad.Redirects = []string{"https://managed.example/callback"}
		case "scope":
			bad.Scopes = []string{"administration"}
		case "public":
			bad.Public = true
		case "device":
			bad.DeviceAuthorization = true
		case "workload":
			bad.Workload, _ = oauth.NewWorkload(f.tenant, "foreign-worker", 30*time.Second)
		case "policy":
			denied.Store(true)
		}
		if out, err := service.ClientCreate(f.ctx, bad); err == nil || out.Client.ID != "" {
			t.Fatal("invalid machine registration admitted", mode)
		}
		denied.Store(false)
	}
	var clients int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.managed_clients`).Scan(&clients); err != nil || clients != 0 {
		t.Fatal("denied manager created machine state", err)
	}
	created, err := service.ClientCreate(f.ctx, r)
	if err != nil {
		t.Fatal("genuine manager positive control", err)
	}
	secret, _ := created.Secret.Reveal()
	basic := confidentialBasic(t, created.Client.ID, secret)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*oauth.TokenRequest){
		func(r *oauth.TokenRequest) { r.ClientAuthentication = oauth.ClientAuthentication{} },
		func(r *oauth.TokenRequest) { r.Scopes = []string{"administration"} },
		func(r *oauth.TokenRequest) { r.Resource = "https://foreign.example" },
		func(r *oauth.TokenRequest) {
			r.GrantType = oauth.AuthorizationCodeGrant
			r.Code = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
		func(r *oauth.TokenRequest) {
			r.GrantType = oauth.RefreshTokenGrant
			r.RefreshToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
	} {
		bad := managedWorkloadTokenRequest(created.Client, basic)
		mutate(&bad)
		if _, err := service.Token(f.ctx, bad); err == nil {
			t.Fatal("invalid machine token variant admitted")
		}
		if _, err := store.Token(f.ctx, oauth.TokenCommand{Client: created.Client, Request: bad}); err == nil {
			t.Fatal("native direct caller bypassed machine variant")
		}
	}
	issued, err := service.Token(f.ctx, managedWorkloadTokenRequest(created.Client, basic))
	if err != nil {
		t.Fatal(err)
	}
	access, _ := issued.AccessToken.Reveal()
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := authority.AdvanceAuthority(f.ctx, tx, authority.AuthorityScope{TenantID: authorization.TenantID(f.tenant), PolicyNamespace: "oauth-workloads", SubjectID: "oauth-worker"}, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	requireInactiveIntrospection(t, service, f.ctx, oauth.IntrospectRequest{ClientID: created.Client.ID, ClientAuthentication: basic, Token: access})
	current, err := service.Token(f.ctx, managedWorkloadTokenRequest(created.Client, basic))
	if err != nil {
		t.Fatal("actual current machine epoch denied", err)
	}
	currentAccess, _ := current.AccessToken.Reveal()
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.authorization_subject_authorities RENAME TO unavailable_managed_workload_authorities`); err != nil {
		t.Fatal(err)
	}
	if out, err := service.Token(f.ctx, managedWorkloadTokenRequest(created.Client, basic)); !errors.Is(err, oauth.ErrUnavailable) || out.AccessToken != (oauth.Token{}) {
		t.Fatal("authority outage issued machine token", err)
	}
	if out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: created.Client.ID, ClientAuthentication: basic, Token: currentAccess}); !errors.Is(err, oauth.ErrUnavailable) || out.Active {
		t.Fatal("authority outage disclosed stale machine token", err)
	}
}

func TestNativeManagedWorkloadRequiredEffectsAndOriginalUnknownRecovery(t *testing.T) {
	for _, mode := range []string{"audit", "outbox", "unknown-create", "unknown-token"} {
		t.Run(mode, func(t *testing.T) {
			fault := &oauthCommitFault{}
			f := passwordFixture(t, fault)
			enableClientManagement(t, &f)
			w := installManagedWorkloadProfile(t, &f)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "audit" {
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE audit.records ADD CONSTRAINT refuse_managed_machine_audit CHECK(action<>'identity.oauth_server.create_client')`)
			}
			if mode == "outbox" {
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_managed_machine_event CHECK(topic<>'oauth_client.created.v1') NOT VALID`)
			}
			if err != nil {
				t.Fatal(err)
			}
			r := managedWorkloadCreateRequest(t, f, w, "machine-required-effects-"+mode)
			fault.armed.Store(mode == "unknown-create")
			created, createErr := service.ClientCreate(f.ctx, r)
			if mode != "unknown-token" {
				if createErr == nil || created.Secret != (oauth.Token{}) {
					t.Fatal("failed/unknown creation disclosed client secret", createErr)
				}
			}
			store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown-create" {
				if !fault.hit.Load() || created.Completion.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("actual creation COMMIT loss missed", createErr)
				}
				recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-create", CommandID: created.Completion.CommandID, ClientID: oauth.ManagedClientPrefix + string(created.Completion.CommandID), TenantID: f.tenant, Session: f.browser}
				for range 2 {
					if out, err := store.Recover(f.ctx, recovery); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("original machine registration metadata recovery failed", err)
					}
				}
				retry, err := service.ClientCreate(f.ctx, r)
				if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != created.Completion.CommandID || retry.Secret != (oauth.Token{}) {
					t.Fatal("unknown registration retry replaced original secret/client", err)
				}
			}
			if mode == "unknown-token" {
				if createErr != nil {
					t.Fatal(createErr)
				}
				secret, _ := created.Secret.Reveal()
				basic := confidentialBasic(t, created.Client.ID, secret)
				fault.armed.Store(true)
				lost, err := service.Token(f.ctx, managedWorkloadTokenRequest(created.Client, basic))
				if !fault.hit.Load() || !errors.Is(err, oauth.ErrUnavailable) || lost.Outcome != identity.CommitOutcomeUnknown || lost.AccessToken != (oauth.Token{}) {
					t.Fatal("actual machine issuance COMMIT loss missed", err)
				}
				recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: lost.CommandID, ClientID: created.Client.ID, ClientAuthentication: basic}
				for range 2 {
					if out, err := store.Recover(f.ctx, recovery); err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.CommandID != lost.CommandID {
						t.Fatal("original machine issuance metadata recovery failed", err)
					}
				}
			}
			var clients, effects, artifacts int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.managed_clients),(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-create'),(SELECT count(*) FROM oauth_store.artifacts)`).Scan(&clients, &effects, &artifacts); err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "unknown-create" || mode == "unknown-token" {
				want = 1
			}
			wantArtifacts := 0
			if mode == "unknown-token" {
				wantArtifacts = 1
			}
			if clients != want || effects != want || artifacts != wantArtifacts {
				t.Fatal("required effects/recovery changed original machine cardinality")
			}
		})
	}
}

func (p managedWorkloadDecisions) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Subject.Kind == authorization.SubjectServiceAccount {
		return p.machines.Decide(ctx, c)
	}
	return p.Service.Decide(ctx, c)
}

func installManagedWorkloadProfile(t *testing.T, f *authenticatedPasswordFixture) *oauth.Workload {
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
		version = 7005
	}
	if f.oauth.ClientMetadataUpdates {
		base = oauthpostgres.ClientUpdateMigrationSource{Base: base, Schema: "oauth_store", Version: 7005}
		version = 7006
	}
	runner, err := migrations.NewRunner(oauthpostgres.WorkloadMigrationSource{Base: base, Schema: "oauth_store", Version: version}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("forward machine history failed", err)
	}
	if replay, err := runner.Up(f.ctx); err != nil || len(replay.Records()) != 0 {
		t.Fatal("machine history replay changed installed prefix", err)
	}
	w, err := oauth.NewWorkload(f.tenant, "oauth-worker", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	p := *f.oauth.Protocol.ManagedClients
	p.Workloads = []*oauth.Workload{w}
	f.oauth.Protocol.ManagedClients = &p
	f.oauth.WorkloadAuthority = oauthpostgres.WorkloadAuthorityConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "oauth-workloads"}
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "managed-workload-consumer", Revision: 9, Evaluator: workloadPolicy{}})
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
	combined := managedWorkloadDecisions{Service: f.oauth.Coordinator.AdmissionPolicy.Authorization, machines: decisions}
	query, admission := *f.oauth.Coordinator.QueryPolicy, *f.oauth.Coordinator.AdmissionPolicy
	query.Authorization, admission.Authorization = combined, combined
	f.oauth.Coordinator.QueryPolicy, f.oauth.Coordinator.AdmissionPolicy = &query, &admission
	f.oauth.RequestKeys.Policy.Authorization = combined
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := authority.InitializeAuthority(f.ctx, tx, authority.AuthorityScope{TenantID: authorization.TenantID(f.tenant), PolicyNamespace: "oauth-workloads", SubjectID: "oauth-worker"}, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestNativeManagedWorkloadDoesNotSelectRotationOrMetadataReplacement(t *testing.T) {
	f := passwordFixture(t)
	enableClientUpdates(t, &f)
	w := installManagedWorkloadProfile(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.ClientCreate(f.ctx, managedWorkloadCreateRequest(t, f, w, "machine-no-rotation-update"))
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := created.Secret.Reveal()
	rotate := clientRotationRequest(t, f, created.Client, "unsupported-machine-rotation", 0)
	if out, err := service.ClientRotateSecret(f.ctx, rotate); err == nil || out.Secret != (oauth.Token{}) {
		t.Fatal("machine selected global human secret rotation")
	}
	if _, err := service.ClientUpdate(f.ctx, clientUpdateRequest(t, f, created.Client, "unsupported-machine-update")); err == nil {
		t.Fatal("machine converted to human metadata class")
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	current, err := store.CurrentClient(f.ctx, created.Client.ID)
	if err != nil || current.Version != 1 || current.Workload == nil || current.Workload.ID() != "oauth-worker" || len(current.Redirects) != 0 {
		t.Fatal("unsupported management changed machine identity", err)
	}
	if out, err := service.Token(f.ctx, managedWorkloadTokenRequest(current, confidentialBasic(t, current.ID, secret))); err != nil || out.AccessToken == (oauth.Token{}) {
		t.Fatal("denied management changed original machine secret", err)
	}
	human, err := service.ClientCreate(f.ctx, clientCreateRequest(t, f, "retained-human-management"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := service.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, human.Client, "retained-human-rotation", 0))
	if err != nil || rotated.Client.Version != 2 {
		t.Fatal("machine selection disabled supported human rotation", err)
	}
	if updated, err := service.ClientUpdate(f.ctx, clientUpdateRequest(t, f, rotated.Client, "retained-human-update")); err != nil || updated.Client.Version != 3 || updated.Client.Workload != nil {
		t.Fatal("machine selection changed supported human metadata replacement", err)
	}
}

func managedWorkloadCreateRequest(t *testing.T, f authenticatedPasswordFixture, w *oauth.Workload, label string) oauth.ClientManagementRequest {
	t.Helper()
	r := clientCreateRequest(t, f, label)
	r.Redirects, r.Workload = nil, w
	return r
}

func managedWorkloadTokenRequest(c oauth.Client, basic oauth.ClientAuthentication) oauth.TokenRequest {
	return oauth.TokenRequest{GrantType: oauth.ClientCredentialsGrant, ClientID: c.ID, ClientAuthentication: basic, Resource: c.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.1"}
}

func TestNativeManagedWorkloadCreateUseInventoryAndDeletePreservePopulatedWebClients(t *testing.T) {
	f := passwordFixture(t)
	enableClientManagement(t, &f)
	oldConfig := f.oauth
	before, err := oauthpostgres.NewService(f.pool, oldConfig, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	humanRequest := clientCreateRequest(t, f, "machine-retained-human")
	human, err := before.ClientCreate(f.ctx, humanRequest)
	if err != nil {
		t.Fatal(err)
	}
	humanSecret, _ := human.Secret.Reveal()
	humanBasic := confidentialBasic(t, human.Client.ID, humanSecret)
	_, originalRefresh := issuedConfidentialTokens(t, f, before, human.Client, humanBasic)
	w := installManagedWorkloadProfile(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal("selected managed machine constructor failed", err)
	}
	if original, err := service.ClientCreate(f.ctx, humanRequest); err != nil || !original.Completion.Replayed || original.Completion.CommandID != human.Completion.CommandID || original.Secret != (oauth.Token{}) {
		t.Fatal("machine activation stranded original human keyed preparation", err)
	}
	r := managedWorkloadCreateRequest(t, f, w, "original-managed-machine")
	created, err := service.ClientCreate(f.ctx, r)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted || created.Client.Workload == nil {
		t.Fatal("genuine manager could not register workload", err)
	}
	secret, err := created.Secret.Reveal()
	if err != nil {
		t.Fatal("fresh known commitment withheld secret", err)
	}
	if _, err := created.Secret.Reveal(); err == nil {
		t.Fatal("same secret revealed twice")
	}
	basic := confidentialBasic(t, created.Client.ID, secret)
	restarted, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restarted.ClientCreate(f.ctx, r)
	if err != nil || !replay.Completion.Replayed || replay.Completion.CommandID != created.Completion.CommandID {
		t.Fatal("restart lost original management result", err)
	}
	if _, err := replay.Secret.Reveal(); err == nil {
		t.Fatal("restart replay re-delivered client secret")
	}
	issued, err := restarted.Token(f.ctx, managedWorkloadTokenRequest(created.Client, basic))
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original managed secret could not issue access", err)
	}
	if issued.RefreshToken != (oauth.Token{}) || issued.IDToken != (oauth.IDToken{}) {
		t.Fatal("machine manufactured refresh or identity token")
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := restarted.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: created.Client.ID, ClientAuthentication: basic, Token: access})
	if err != nil || !metadata.Active || metadata.Subject != "oauth-worker" || metadata.ClientID != created.Client.ID || metadata.Resource != created.Client.Resource || !slices.Equal(metadata.Scopes, []string{"identity:read"}) {
		t.Fatal("owning introspection lost machine binding", err)
	}
	read := oauth.ClientReadRequest{Owner: created.Client.Owner, TenantID: f.tenant, Session: f.browser, ClientID: created.Client.ID}
	if got, err := restarted.ClientGet(f.ctx, read); err != nil || got.Client.Workload == nil || got.Client.Workload.ID() != "oauth-worker" {
		t.Fatal("selected manager cannot read machine inventory", err)
	}
	read.ClientID, read.Limit = "", 100
	listed, err := restarted.ClientList(f.ctx, read)
	if err != nil || len(listed.Page.Items()) != 2 {
		t.Fatal("mixed current inventory lost retained human or machine", err)
	}
	humanOnly, err := oauthpostgres.NewService(f.pool, oldConfig, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	legacyPage, err := humanOnly.ClientList(f.ctx, read)
	if err != nil || len(legacyPage.Page.Items()) != 1 || legacyPage.Page.Items()[0].ID != human.Client.ID {
		t.Fatal("unselected human-only inventory regressed after machine creation", err)
	}
	if _, err := restarted.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: human.Client.ID, ClientAuthentication: humanBasic, RefreshToken: originalRefresh, Network: "192.0.2.1"}); err != nil {
		t.Fatal("populated original human authority changed on machine activation", err)
	}
	if _, err := restarted.Revoke(f.ctx, oauth.RevokeRequest{ClientID: created.Client.ID, ClientAuthentication: basic, Token: access, Network: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	requireInactiveIntrospection(t, restarted, f.ctx, oauth.IntrospectRequest{ClientID: created.Client.ID, ClientAuthentication: basic, Token: access})
	second, err := restarted.Token(f.ctx, managedWorkloadTokenRequest(created.Client, basic))
	if err != nil {
		t.Fatal(err)
	}
	secondAccess, _ := second.AccessToken.Reveal()
	remove := r
	remove.ClientID, remove.Version, remove.Scopes, remove.Workload = created.Client.ID, created.Client.Version, nil, nil
	remove.RequestKey, _ = identity.NewIdempotencyKey([]byte("terminal-managed-machine-delete"))
	if out, err := restarted.ClientDelete(f.ctx, remove); err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("current manager could not terminally delete machine", err)
	}
	if _, err := restarted.Token(f.ctx, managedWorkloadTokenRequest(created.Client, basic)); err == nil {
		t.Fatal("deleted machine issued access")
	}
	if out, err := restarted.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: created.Client.ID, ClientAuthentication: basic, Token: secondAccess}); err == nil || out.Active {
		t.Fatal("deleted machine retained token use")
	}
	var machineUsers, consents, invalidArtifacts int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.grants WHERE client_id=$1 AND user_id IS NOT NULL),(SELECT count(*) FROM oauth_store.consents WHERE client_id=$1),(SELECT count(*) FROM oauth_store.artifacts WHERE client_id=$1 AND kind<>3)`, created.Client.ID).Scan(&machineUsers, &consents, &invalidArtifacts); err != nil || machineUsers != 0 || consents != 0 || invalidArtifacts != 0 {
		t.Fatal("machine acquired fabricated human/consent/non-access state", err)
	}
}
