//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

func enableConsentManagement(t *testing.T, f *authenticatedPasswordFixture) {
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
	source := oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("consent forward install failed", err)
	}
	if replay, err := runner.Up(f.ctx); err != nil || len(replay.Records()) != 0 {
		t.Fatal("consent migration replay changed installed history", err)
	}
	f.oauth.ConsentManagement = true
}

func TestNativeConsentForwardFailureRollsBackAndPreservesInstalledPrefix(t *testing.T) {
	f := passwordFixture(t)
	legacy, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	refresh := freshRefresh(t, f, legacy)
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
	source := oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE oauth_store.consents ADD COLUMN generation text`); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err == nil {
		t.Fatal("forward migration adopted conflicting object")
	}
	var partial int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='oauth_store' AND ((table_name='consents' AND column_name IN('state','client_fingerprint')) OR (table_name='grants' AND column_name='consent_id') OR (table_name='effects' AND column_name='consent_id'))`).Scan(&partial); err != nil || partial != 0 {
		t.Fatal("failed migration partly changed installed authority", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE oauth_store.consents DROP COLUMN generation`); err != nil {
		t.Fatal(err)
	}
	if first, err := runner.Up(f.ctx); err != nil || len(first.Records()) != 1 {
		t.Fatal("original successor could not install after exact fixture obstruction removed", err)
	}
	if replay, err := runner.Up(f.ctx); err != nil || len(replay.Records()) != 0 {
		t.Fatal("installed prefix checksum/replay changed", err)
	}
	f.oauth.ConsentManagement = true
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("backfill replaced original approved authority", err)
	}
}

func TestNativeConsentForwardExtensionPreservesInstalledWorkloadAuthority(t *testing.T) {
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
	base := oauthpostgres.WorkloadMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7001}
	runner, err := migrations.NewRunner(oauthpostgres.ConsentMigrationSource{Base: base, Schema: "oauth_store", Version: 7002}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("consent extension required a human substitute", err)
	}
	if replay, err := runner.Up(f.ctx); err != nil || len(replay.Records()) != 0 {
		t.Fatal("installed workload prefix changed", err)
	}
	if out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: wire}); err != nil || !out.Active {
		t.Fatal("consent extension withdrew unrelated machine authority", err)
	}
	if out, err := service.Token(f.ctx, workloadRequest(f)); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("machine issuance acquired human consent dependency", err)
	}
	var humans, bindings int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.consents),(SELECT count(*) FROM oauth_store.grants WHERE consent_id IS NOT NULL OR consent_generation IS NOT NULL)`).Scan(&humans, &bindings); err != nil || humans != 0 || bindings != 0 {
		t.Fatal("migration invented human consent for workload", err)
	}
}

type consentRaceKey struct{}

// This seam schedules only the already-authenticated native command after its
// actual target lookup. Every authorization result remains the real owner's.
type consentRaceBarrier struct {
	owner          authorization.Service
	action         authorization.Action
	ready, release chan struct{}
	once           sync.Once
}

func (b *consentRaceBarrier) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	d, err := b.owner.Decide(ctx, c)
	selected, _ := ctx.Value(consentRaceKey{}).(bool)
	if err == nil && selected && c.Request.Action == b.action && c.CorrelationID != "" {
		b.once.Do(func() {
			close(b.ready)
			select {
			case <-b.release:
			case <-ctx.Done():
			}
		})
	}
	if ctx.Err() != nil {
		return authorization.Decision{}, ctx.Err()
	}
	return d, err
}

func TestNativeConsentWithdrawalSerializesWithRefreshWithoutResurrectingChildren(t *testing.T) {
	for _, refreshFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "withdrawal-wins", true: "refresh-wins"}[refreshFirst], func(t *testing.T) {
			f := passwordFixture(t)
			enableConsentManagement(t, &f)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			refresh := freshRefresh(t, f, service)
			page, err := service.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
			if err != nil {
				t.Fatal(err)
			}
			consent := page.Page.Items()[0]
			barrier := &consentRaceBarrier{owner: f.oauth.Coordinator.AdmissionPolicy.Authorization, action: "identity.oauth-server.token", ready: make(chan struct{}), release: make(chan struct{})}
			if refreshFirst {
				barrier.action = "identity.oauth-server.consent-delete"
			}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(barrier.release) }) }
			t.Cleanup(release)
			raceContext, cancel := context.WithTimeout(f.ctx, 8*time.Second)
			defer cancel()
			admission := *f.oauth.Coordinator.AdmissionPolicy
			admission.Authorization = barrier
			f.oauth.Coordinator.AdmissionPolicy = &admission
			service, err = oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			type tokenResult struct {
				out oauth.TokenResult
				err error
			}
			type deleteResult struct {
				out oauth.ConsentDeleteResult
				err error
			}
			tokens := make(chan tokenResult, 1)
			deletions := make(chan deleteResult, 1)
			tokenCall := func(ctx context.Context) {
				out, err := service.Token(ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"})
				tokens <- tokenResult{out, err}
			}
			deleteCall := func(ctx context.Context) {
				out, err := service.ConsentDelete(ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRemove, consent.ID(), consent.Version())})
				deletions <- deleteResult{out, err}
			}
			if refreshFirst {
				go deleteCall(context.WithValue(raceContext, consentRaceKey{}, true))
			} else {
				go tokenCall(context.WithValue(raceContext, consentRaceKey{}, true))
			}
			select {
			case <-barrier.ready:
			case <-raceContext.Done():
				t.Fatal("actual target did not reach bounded native admission")
			}
			if refreshFirst {
				tokenCall(raceContext)
			} else {
				deleteCall(raceContext)
			}
			release()
			var token tokenResult
			var removed deleteResult
			select {
			case token = <-tokens:
			case <-raceContext.Done():
				t.Fatal("refresh goroutine did not terminate")
			}
			select {
			case removed = <-deletions:
			case <-raceContext.Done():
				t.Fatal("withdrawal goroutine did not terminate")
			}
			if removed.err != nil || !removed.out.Deleted {
				t.Fatal("contended withdrawal failed", removed.err)
			}
			if refreshFirst {
				if token.err != nil || token.out.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("scheduled refresh winner failed", token.err)
				}
				child, err := token.out.RefreshToken.Reveal()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: child, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrInvalidGrant) {
					t.Fatal("withdrawal failed to deny refresh winner child", err)
				}
			} else if !errors.Is(token.err, oauth.ErrInvalidGrant) {
				t.Fatal("stale active lookup committed after withdrawal", token.err)
			}
			var count int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.consent-delete'`).Scan(&count); err != nil || count != 1 {
				t.Fatal("contention duplicated consent effects", err)
			}
		})
	}
}

func TestNativeConsentSubjectPaginationCurrentAuthorityAndOutage(t *testing.T) {
	f := passwordFixture(t)
	enableConsentManagement(t, &f)
	client, _, credential := addConfiguredConfidentialClient(t, &f)
	f.oauth.Protocol.OwningClientIntrospection = true
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	publicRefresh := freshRefresh(t, f, service)
	access, refresh := issuedConfidentialTokens(t, f, service, client, credential)
	first, err := service.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
	if err != nil || len(first.Page.Items()) != 1 || first.NextCursor.String() == "" {
		t.Fatal("first bounded own page missing continuation", err)
	}
	spec := ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0).Input()
	spec.Cursor = first.NextCursor
	nextCommand, err := oauth.NewConsentCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: nextCommand})
	if err != nil || len(second.Page.Items()) != 1 || second.NextCursor.String() != "" || second.Page.Items()[0].ID() <= first.Page.Items()[0].ID() {
		t.Fatal("keyset page repeated/skipped consent", err)
	}
	own := first.Page.Items()[0]
	if own.ClientID() != client.ID {
		own = second.Page.Items()[0]
	}
	otherBrowser, otherCSRF := f.anotherUser()
	for _, change := range []func(*oauth.ConsentCommandSpec){
		func(s *oauth.ConsentCommandSpec) { s.Session = otherBrowser; s.CSRF = otherCSRF },
		func(s *oauth.ConsentCommandSpec) { s.TenantID = "foreign-tenant" },
		func(s *oauth.ConsentCommandSpec) { s.Version++ },
		func(s *oauth.ConsentCommandSpec) { s.Origin = "https://foreign.example" },
		func(s *oauth.ConsentCommandSpec) { s.CSRF, _ = session.NewCSRFToken() },
	} {
		invalid := ownConsentCommand(t, f, oauth.ConsentRemove, own.ID(), own.Version()).Input()
		change(&invalid)
		command, err := oauth.NewConsentCommand(invalid)
		if err != nil {
			t.Fatal("denial fixture malformed", err)
		}
		if out, err := service.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: command}); err == nil || out.Deleted {
			t.Fatal("foreign/stale/mismatched consent withdrawal admitted")
		}
	}
	foreign := ownConsentCommand(t, f, oauth.ConsentRead, own.ID(), 0).Input()
	foreign.Session = otherBrowser
	foreignRead, _ := oauth.NewConsentCommand(foreign)
	if out, err := service.ConsentGet(f.ctx, oauth.ConsentGetRequest{Consent: foreignRead}); !errors.Is(err, oauth.ErrAccessDenied) || out.Consent.ID() != "" {
		t.Fatal("foreign actor read consent", err)
	}
	foreign = ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0).Input()
	foreign.Session = otherBrowser
	foreign.Cursor = first.NextCursor
	foreignPage, _ := oauth.NewConsentCommand(foreign)
	if out, err := service.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: foreignPage}); !errors.Is(err, oauth.ErrAccessDenied) || len(out.Page.Items()) != 0 {
		t.Fatal("foreign actor reused cursor", err)
	}
	// Direct Store callers cannot replace the sealed reader output with public
	// authenticated/session flags. Actual browser possession remains separately read.
	if out, err := store.ConsentGet(f.ctx, oauth.ConsentExecution{Command: ownConsentCommand(t, f, oauth.ConsentRead, own.ID(), 0), Session: session.GetResult{Authenticated: true}}); !errors.Is(err, oauth.ErrAccessDenied) || out.Consent.ID() != "" {
		t.Fatal("direct native forged admission disclosed consent", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE oauth_store.consents RENAME TO unavailable_consents`); err != nil {
		t.Fatal(err)
	}
	if out, err := service.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)}); !errors.Is(err, oauth.ErrUnavailable) || len(out.Page.Items()) != 0 {
		t.Fatal("failed query became successful empty page", err)
	}
	if out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: credential, Token: access}); !errors.Is(err, oauth.ErrUnavailable) || out.Active {
		t.Fatal("unavailable consent accepted cached token", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE oauth_store.unavailable_consents RENAME TO consents`); err != nil {
		t.Fatal(err)
	}
	if out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: credential, Token: access}); err != nil || !out.Active {
		t.Fatal("read outage mutated legitimate authority", err)
	}
	removed, err := service.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRemove, own.ID(), own.Version())})
	if err != nil || !removed.Deleted {
		t.Fatal("own consent revoke failed", err)
	}
	for _, wire := range []string{access, refresh} {
		requireInactiveIntrospection(t, service, f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: credential, Token: wire})
	}
	var other oauth.Consent
	for _, c := range []oauth.Consent{first.Page.Items()[0], second.Page.Items()[0]} {
		if c.ID() != own.ID() {
			other = c
		}
	}
	if out, err := service.ConsentGet(f.ctx, oauth.ConsentGetRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRead, other.ID(), 0)}); err != nil || out.Consent.ID() != other.ID() {
		t.Fatal("withdrawal affected unrelated own consent", err)
	}
	if out, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: publicRefresh, Network: "192.0.2.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("withdrawal affected unrelated grant", err)
	}
	f.signOut()
	if out, err := service.ConsentGet(f.ctx, oauth.ConsentGetRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRead, other.ID(), 0)}); !errors.Is(err, oauth.ErrAccessDenied) || out.Consent.ID() != "" {
		t.Fatal("withdrawn session read consent", err)
	}
	canceled, stop := context.WithCancel(f.ctx)
	stop()
	if _, err := service.ConsentList(canceled, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation swallowed", err)
	}
}

func TestNativeConsentWithdrawalRollsBackWithRealOutboxFailure(t *testing.T) {
	f := passwordFixture(t)
	enableConsentManagement(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	refresh := freshRefresh(t, f, service)
	listed, err := service.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	consent := listed.Page.Items()[0]
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT reject_consent_withdrawal CHECK(topic<>'consent.revoked.v1') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	removed, err := service.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRemove, consent.ID(), consent.Version())})
	if err == nil || removed.Deleted || removed.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("outbox failure claimed committed withdrawal")
	}
	var roots, effects, events, audits int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.consents WHERE consent_id=$1 AND state='active' AND version=$2::numeric AND generation=1 AND revoked_command IS NULL),(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.consent-delete'),(SELECT count(*) FROM public.outbox_messages WHERE topic='consent.revoked.v1'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.revoke_consent' AND outcome=1)`, consent.ID(), consent.Version()).Scan(&roots, &effects, &events, &audits); err != nil || roots != 1 || effects != 0 || events != 0 || audits != 0 {
		t.Fatal("failed withdrawal leaked domain/receipt/audit/lifecycle effects", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages DROP CONSTRAINT reject_consent_withdrawal`); err != nil {
		t.Fatal(err)
	}
	if out, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("rolled-back withdrawal denied valid refresh", err)
	}
	removed, err = service.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRemove, consent.ID(), consent.Version())})
	if err != nil || !removed.Deleted {
		t.Fatal("real original withdrawal could not complete after obstruction removed", err)
	}
}

func TestNativeConsentCurrentCredentialWithdrawalRejectsOldSealedSession(t *testing.T) {
	f := passwordFixtureWithChange(t, true)
	enableConsentManagement(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	_ = freshRefresh(t, f, service)
	page, err := service.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	consent := page.Page.Items()[0]
	token, _ := session.ParseToken(f.browser.Token())
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	observed, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil || !observed.Authenticated {
		t.Fatal("real original session missing", err)
	}
	f.changePassword()
	if out, err := store.ConsentGet(f.ctx, oauth.ConsentExecution{Command: ownConsentCommand(t, f, oauth.ConsentRead, consent.ID(), 0), Session: observed}); !errors.Is(err, oauth.ErrAccessDenied) || out.Consent.ID() != "" {
		t.Fatal("old sealed observation bypassed current credential withdrawal", err)
	}
	if out, err := service.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRemove, consent.ID(), consent.Version())}); !errors.Is(err, oauth.ErrAccessDenied) || out.Deleted {
		t.Fatal("withdrawn credential deleted consent", err)
	}
}

func ownConsentCommand(t *testing.T, f authenticatedPasswordFixture, operation oauth.ConsentOperation, id string, version uint64) oauth.ConsentCommand {
	t.Helper()
	spec := oauth.ConsentCommandSpec{Operation: operation, TenantID: f.tenant, Session: f.browser, ID: id}
	if operation == oauth.ConsentEnumerate {
		spec.Limit = 1
	}
	if operation == oauth.ConsentRemove || operation == oauth.ConsentNarrow {
		spec.Version = version
		spec.Origin = f.oauth.Protocol.Issuer.String()
		spec.CSRF = f.csrf
		spec.Network = "192.0.2.1"
	}
	command, err := oauth.NewConsentCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestNativeConsentOwnReadDeletePopulatedUpgradeAndReconfirmation(t *testing.T) {
	f := passwordFixture(t)
	legacy, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	refresh := freshRefresh(t, f, legacy)
	second := freshRefresh(t, f, legacy)
	pendingCode, pendingVerifier := consentedCode(t, f, legacy)
	enableConsentManagement(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := service.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
	if err != nil || len(listed.Page.Items()) != 1 {
		t.Fatal("own approved consent missing", err)
	}
	consent := listed.Page.Items()[0]
	read, err := service.ConsentGet(f.ctx, oauth.ConsentGetRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRead, consent.ID(), 0)})
	if err != nil || read.Consent.ID() != consent.ID() || read.Consent.Version() != consent.Version() {
		t.Fatal("own consent read lost exact identity/version", err)
	}
	command := ownConsentCommand(t, f, oauth.ConsentRemove, consent.ID(), consent.Version())
	removed, err := service.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: command})
	if err != nil || !removed.Deleted || removed.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("atomic consent withdrawal failed", err)
	}
	for _, wire := range []string{refresh, second} {
		out, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: wire, Network: "192.0.2.1"})
		if !errors.Is(err, oauth.ErrInvalidGrant) || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("consent root failed to deny an approved grant", err)
		}
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: pendingCode, CodeVerifier: pendingVerifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("consent root failed to deny unexchanged approved code", err)
	}
	if out, err := service.ConsentGet(f.ctx, oauth.ConsentGetRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRead, consent.ID(), 0)}); !errors.Is(err, oauth.ErrAccessDenied) || out.Consent.ID() != "" {
		t.Fatal("revoked consent remained visible", err)
	}
	repeated, err := service.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: command})
	if err != nil || !repeated.Deleted || !repeated.Completion.Replayed || repeated.Completion.CommandID != removed.Completion.CommandID {
		t.Fatal("delete replay changed original metadata", err)
	}
	badRepeat := command.Input()
	badRepeat.CSRF, _ = session.NewCSRFToken()
	badCommand, err := oauth.NewConsentCommand(badRepeat)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := service.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: badCommand}); !errors.Is(err, oauth.ErrAccessDenied) || out.Deleted || out.Completion.CommandID != "" {
		t.Fatal("repeat bypassed same-browser synchronizer", err)
	}
	fresh := freshRefresh(t, f, service)
	if out, err := service.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: command}); !errors.Is(err, oauth.ErrAccessDenied) || out.Deleted {
		t.Fatal("stale delete withdrew reconfirmed generation", err)
	}
	if out, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: fresh, Network: "192.0.2.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("explicit new consent did not authorize new generation", err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("reconfirmation resurrected old grant", err)
	}
	var events, audits int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM public.outbox_messages WHERE topic='consent.revoked.v1'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.revoke_consent' AND outcome=1)`).Scan(&events, &audits); err != nil || events != 1 || audits != 1 {
		t.Fatal("withdrawal lacked exactly one truthful durable lifecycle/audit", err)
	}
}

func TestNativeConsentDeleteLostAcknowledgementRecoversOriginalMetadataOnly(t *testing.T) {
	fault := &oauthCommitFault{}
	f := passwordFixture(t, fault)
	enableConsentManagement(t, &f)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	_ = freshRefresh(t, f, service)
	page, err := service.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
	if err != nil || len(page.Page.Items()) != 1 {
		t.Fatal("consent setup failed", err)
	}
	consent := page.Page.Items()[0]
	command := ownConsentCommand(t, f, oauth.ConsentRemove, consent.ID(), consent.Version())
	fault.armed.Store(true)
	lost, err := service.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: command})
	if !fault.hit.Load() || err == nil || lost.Deleted || lost.Completion.Outcome != identity.CommitOutcomeUnknown || lost.Completion.CommandID == "" {
		t.Fatal("actual consent COMMIT acknowledgement loss was misreported", err)
	}
	request := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.consent-delete", CommandID: lost.Completion.CommandID, ClientID: "public-web", ConsentID: consent.ID(), TenantID: f.tenant, Session: f.browser}
	for range 2 {
		recovered, err := store.Recover(f.ctx, request)
		if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.CommandID != lost.Completion.CommandID {
			t.Fatal("original consent metadata recovery failed", err)
		}
	}
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.consent-delete'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("recovery duplicated consent withdrawal", err)
	}
}
