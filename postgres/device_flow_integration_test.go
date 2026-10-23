//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	device "github.com/faustbrian/go-oauth-server/device"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

type deviceReadClock struct{ drift atomic.Bool }

func (c *deviceReadClock) Now() time.Time {
	now := time.Now().UTC()
	if c.drift.Load() {
		now = now.Add(21 * time.Second)
	}
	return now
}

func TestNativeDeviceFinalBrowserReadDeadlineCannotCommitAfterOwnerWaits(t *testing.T) {
	var armed atomic.Bool
	var updated atomic.Bool
	var finalReads atomic.Uint32
	clock := &deviceReadClock{}
	fault := &oauthCommitFault{beforeWrite: func(wire []byte) {
		if armed.Load() && bytes.Contains(wire, []byte(`UPDATE "oauth_store".devices SET`)) {
			updated.Store(true)
		}
		// ApplyFeature checks provisionally, then the actual coordinator calls
		// CheckFeatureCommit again. Cross the deadline on that final row read.
		if updated.Load() && bytes.Contains(wire, []byte(`FROM "oauth_store".devices WHERE device_id=`)) && finalReads.Add(1) == 2 {
			clock.drift.Store(true)
		}
	}}
	f := passwordFixture(t, fault)
	f.oauth.Protocol.Clock = clock
	d, _ := nativeDeviceFixture(t, &f)
	issued, _ := issueNativeDevice(t, f, d)
	armed.Store(true)
	out, err := d.Approve(f.ctx, device.Approval{Verification: device.Verification{Session: f.browser, UserCode: issued.UserCode, Network: "192.0.2.1"}, Origin: f.oauth.Protocol.Issuer.String(), CSRF: f.csrf, ConfirmedUserCode: issued.UserCode})
	if !clock.drift.Load() {
		t.Fatal("test did not cross original read deadline after real owner checks")
	}
	if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("late original browser read committed device approval", err)
	}
	var pending, grants int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.devices WHERE state='pending' AND version=1),(SELECT count(*) FROM oauth_store.grants)`).Scan(&pending, &grants); err != nil || pending != 1 || grants != 0 {
		t.Fatal("expired original read retained protected human authority", err)
	}
}

func TestNativeDeviceRecoveryContradictoryLastCommandCannotProveNoncommit(t *testing.T) {
	fault := &oauthCommitFault{before: true}
	f := passwordFixture(t, fault)
	d, _ := nativeDeviceFixture(t, &f)
	_, _ = issueNativeDevice(t, f, d)
	fault.armed.Store(true)
	lost, err := d.Authorize(f.ctx, device.DeviceRequest{ClientID: "public-web", Scopes: []string{"identity:read"}, Network: "192.0.2.1"})
	if !fault.hit.Load() || err == nil || lost.Completion.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("actual second issuance did not lose pre-COMMIT transport")
	}
	var digests [64]byte
	if _, err := rand.Read(digests[:]); err != nil {
		t.Fatal(err)
	}
	// Deliberate storage-corruption partition, not a fabricated successful
	// journey: the real lost command has no marker, yet an owned device row
	// claims it was the last writer. Other participant evidence stays absent.
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO oauth_store.devices(device_id,tenant_id,client_id,lookup_version,device_digest,user_digest,state,version,last_command,created_at,expires_at,next_poll_at,interval_seconds,details) SELECT $1,tenant_id,client_id,lookup_version,$2,$3,state,version,$1,created_at,expires_at,next_poll_at,interval_seconds,details FROM oauth_store.devices LIMIT 1`, string(lost.Completion.CommandID), digests[:32], digests[32:]); err != nil {
		t.Fatal(err)
	}
	clear(digests[:])
	raw, err := base64.RawURLEncoding.DecodeString(string(lost.Completion.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1 AND state='pending'`, raw); err != nil {
		t.Fatal(err)
	}
	metadata, err := d.Recover(f.ctx, device.Recovery{OperationID: "identity.oauth-server.device-authorize", CommandID: lost.Completion.CommandID, ClientID: "public-web"})
	if err == nil || metadata.Outcome == identity.CommitOutcomeNotCommitted || metadata.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("contradictory owned state was certified as original rollback or success")
	}
}

// This selected application's exact policy admits registered client actors only
// for its two anonymous device operations. Real client credentials and all
// original-human authority remain independently checked by the native owners.
type deviceConsumerPolicy struct {
	authorization.Service
	clients map[authorization.SubjectID]bool
}

func (p deviceConsumerPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	r := c.Request
	if r.Tenant == baselineTenant {
		switch r.Action {
		case "identity.oauth-server.device-authorize", "identity.oauth-server.device-authorize.recover", "identity.oauth-server.device-token", "identity.oauth-server.device-token.recover":
			if r.Subject.Kind == authorization.SubjectServiceAccount && p.clients[r.Subject.ID] && r.Resource.Type == "identity.anonymous-flow" && r.Resource.ID != "" {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		case "identity.oauth-server.device-approve", "identity.oauth-server.device-approve.recover", "identity.oauth-server.device-deny", "identity.oauth-server.device-deny.recover":
			if r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(r.Subject.ID) {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		}
	}
	return p.Service.Decide(ctx, c)
}

func nativeDeviceFixture(t *testing.T, f *authenticatedPasswordFixture, configure ...func(*oauthpostgres.DeviceConfig)) (*device.Service, *oauth.Service) {
	t.Helper()
	if !f.oauth.ConsentManagement {
		enableConsentManagement(t, f)
	}
	f.oauth.Protocol.Clients[0].DeviceAuthorization = true
	clients := make(map[authorization.SubjectID]bool)
	for _, client := range f.oauth.Protocol.Clients {
		if client.DeviceAuthorization {
			clients[authorization.SubjectID(client.ID)] = true
		}
	}
	query, admission := *f.oauth.Coordinator.QueryPolicy, *f.oauth.Coordinator.AdmissionPolicy
	query.Authorization = deviceConsumerPolicy{Service: query.Authorization, clients: clients}
	admission.Authorization = deviceConsumerPolicy{Service: admission.Authorization, clients: clients}
	f.oauth.Coordinator.QueryPolicy, f.oauth.Coordinator.AdmissionPolicy = &query, &admission
	var base migrations.Source = oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}
	if f.oauth.Protocol.ManagedClients != nil {
		base = oauthpostgres.ClientMigrationSource{Base: base, Schema: "oauth_store", Version: 7003}
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
	runner, err := migrations.NewRunner(oauthpostgres.DeviceMigrationSource{Base: base, Schema: "oauth_store", Version: 7020}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("optional device forward install failed", err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	deps := oauth.Dependencies{Sessions: f.sessions, Store: store}
	if f.oauth.Protocol.ManagedClients != nil {
		deps.Clients = store
	}
	core, err := oauth.NewService(f.oauth.Protocol, deps)
	if err != nil {
		t.Fatal(err)
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal("device lookup entropy unavailable")
	}
	key, err := oauth.NewTokenDigestKey(1, raw[:])
	clear(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	config := device.Config{Enabled: true, TenantID: f.tenant, VerificationURI: f.oauth.Protocol.Issuer.String() + "/device", TokenEndpoint: f.oauth.Protocol.Issuer.String() + "/oauth2/token", AuthorizationEndpoint: f.oauth.Protocol.Issuer.String() + "/oauth2/device_authorization", TTL: time.Minute, PollInterval: 5 * time.Second, VerificationURICompleteBytes: 512, LookupLimit: 32}
	nativeConfig := oauthpostgres.DeviceConfig{Policy: config, LookupKeys: []oauth.TokenDigestKey{key}, ActiveLookupKeyVersion: 1}
	for _, change := range configure {
		change(&nativeConfig)
	}
	native, err := store.DeviceStore(nativeConfig)
	if err != nil {
		t.Fatal("native device factory rejected actual composition", err)
	}
	service, err := device.NewService(core, config, native)
	if err != nil {
		t.Fatal("public device consumer rejected native owner", err)
	}
	return service, core
}

func TestNativeDeviceUserCodeCollisionAcrossRetainedLookupKeysCannotShadowOriginal(t *testing.T) {
	f := passwordFixture(t)
	var retained oauthpostgres.DeviceConfig
	d, core := nativeDeviceFixture(t, &f, func(c *oauthpostgres.DeviceConfig) { retained = *c })
	issued, _ := issueNativeDevice(t, f, d)
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		t.Fatal(err)
	}
	next, err := oauth.NewTokenDigestKey(2, material[:])
	clear(material[:])
	if err != nil {
		t.Fatal(err)
	}
	retained.LookupKeys = append(append([]oauth.TokenDigestKey(nil), retained.LookupKeys...), next)
	retained.ActiveLookupKeyVersion = next.Version()
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	native, err := store.DeviceStore(retained)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := core.DeviceClientSource(f.ctx, oauth.DeviceClientSourceRequest{ClientID: "public-web", Scopes: []string{"identity:read"}})
	if err != nil {
		t.Fatal(err)
	}
	code, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	// A deterministic generator collision is injected at the public native
	// projection boundary; client, source, transaction and lookup owners are real.
	out, err := native.ExecuteDevice(f.ctx, oauth.DeviceExecution{Action: oauth.DeviceIssue, Policy: retained.Policy, Client: projection, Network: "192.0.2.1", GeneratedDeviceCode: code, GeneratedUserCode: issued.UserCode})
	if err == nil || out.Completion.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("rotated-key collision issued a second request with ambiguous user lookup")
	}
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.devices`).Scan(&count); err != nil || count != 1 {
		t.Fatal("collision replaced or duplicated original pending authority", err)
	}
	if prompt, err := d.Inspect(f.ctx, device.Verification{Session: f.browser, UserCode: issued.UserCode, Network: "192.0.2.1"}); err != nil || prompt.UserCode != issued.UserCode {
		t.Fatal("collision corrupted original user-code inspection", err)
	}
}

func TestNativeDeviceConcurrentRetainedKeyIssuanceHasOneUserCodeOwner(t *testing.T) {
	f := passwordFixture(t)
	var configured oauthpostgres.DeviceConfig
	_, core := nativeDeviceFixture(t, &f, func(c *oauthpostgres.DeviceConfig) { configured = *c })
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		t.Fatal(err)
	}
	next, err := oauth.NewTokenDigestKey(2, material[:])
	clear(material[:])
	if err != nil {
		t.Fatal(err)
	}
	configured.LookupKeys = append(append([]oauth.TokenDigestKey(nil), configured.LookupKeys...), next)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := core.DeviceClientSource(f.ctx, oauth.DeviceClientSourceRequest{ClientID: "public-web", Scopes: []string{"identity:read"}})
	if err != nil {
		t.Fatal(err)
	}
	var natives [2]*oauthpostgres.DeviceStore
	var executions [2]oauth.DeviceExecution
	for i := range 2 {
		c := configured
		c.ActiveLookupKeyVersion = uint32(i + 1)
		selected := store
		if i == 1 {
			// A stable collision fence cannot depend on the native caller-intent
			// key or an unrelated configuration fingerprint during rotation.
			rotated := f.oauth
			if _, err := rand.Read(rotated.IntentKey[:]); err != nil {
				t.Fatal(err)
			}
			selected, err = oauthpostgres.NewStore(f.pool, rotated, f.keys)
			if err != nil {
				t.Fatal(err)
			}
		}
		natives[i], err = selected.DeviceStore(c)
		if err != nil {
			t.Fatal(err)
		}
		code, err := oauth.NewToken()
		if err != nil {
			t.Fatal(err)
		}
		executions[i] = oauth.DeviceExecution{Action: oauth.DeviceIssue, Policy: c.Policy, Client: projection, Network: "192.0.2.1", GeneratedDeviceCode: code, GeneratedUserCode: "BCDF-GHJK"}
	}
	type result struct {
		out oauth.DeviceResult
		err error
	}
	done := make(chan result, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Go(func() {
			<-start
			out, err := natives[i].ExecuteDevice(f.ctx, executions[i])
			done <- result{out, err}
		})
	}
	close(start)
	wg.Wait()
	close(done)
	winners := 0
	for r := range done {
		if r.err == nil && r.out.Completion.Outcome == identity.CommitOutcomeCommitted {
			winners++
		}
	}
	var rows int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.devices`).Scan(&rows); err != nil || winners != 1 || rows != 1 {
		t.Fatal("concurrent key-version issuance created ambiguous user-code ownership", err)
	}
}

func TestNativeDeviceConfidentialClientNeedsActualBasicCustody(t *testing.T) {
	f := passwordFixture(t)
	f.oauth.Protocol.Clients[0].DeviceAuthorization = true
	client, secret, credential := addConfiguredConfidentialClient(t, &f)
	d, _ := nativeDeviceFixture(t, &f)
	request := device.DeviceRequest{ClientID: client.ID, Scopes: []string{"identity:read"}, Network: "192.0.2.1"}
	wrong := "A" + secret[1:]
	if wrong == secret {
		wrong = "B" + secret[1:]
	}
	for _, invalid := range []oauth.ClientAuthentication{{}, confidentialBasic(t, client.ID, wrong), confidentialBasic(t, "public-web", secret)} {
		request.ClientAuthentication = invalid
		if out, err := d.Authorize(f.ctx, request); !errors.Is(err, oauth.ErrInvalidClient) || out.Completion.CommandID != "" {
			t.Fatal("device issuance bypassed confidential authentication", err)
		}
	}
	request.ClientAuthentication = credential
	issued, err := d.Authorize(f.ctx, request)
	if err != nil {
		t.Fatal("actual Basic custody did not issue device request", err)
	}
	wire, err := issued.DeviceCode.Reveal()
	if err != nil {
		t.Fatal("committed confidential device custody missing")
	}
	poll := device.TokenExchange{ClientID: client.ID, DeviceCode: wire, Network: "192.0.2.1"}
	if _, err := d.Poll(f.ctx, poll); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatal("confidential poll accepted absent secret", err)
	}
	poll.ClientAuthentication = credential
	devicePollDue(t, f)
	if _, err := d.Poll(f.ctx, poll); !errors.Is(err, device.ErrAuthorizationPending) {
		t.Fatal("legitimate confidential pending flow was consumed by rejected authentication", err)
	}
}

func TestNativeDeviceOtherAuthenticatedClientCannotPollOrCancelOriginal(t *testing.T) {
	f := passwordFixture(t)
	f.oauth.Protocol.Clients[0].DeviceAuthorization = true
	other, _, credential := addConfiguredConfidentialClient(t, &f)
	var configured oauthpostgres.DeviceConfig
	d, core := nativeDeviceFixture(t, &f, func(c *oauthpostgres.DeviceConfig) { configured = *c })
	issued, wire := issueNativeDevice(t, f, d)
	projection, err := core.DeviceClientSource(f.ctx, oauth.DeviceClientSourceRequest{ClientID: other.ID, ClientAuthentication: credential})
	if err != nil || projection.Client.ID != other.ID {
		t.Fatal("separately registered client B did not authenticate with its own actual Basic custody", err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	native, err := store.DeviceStore(configured)
	if err != nil {
		t.Fatal(err)
	}
	// Compare the complete original row (including its schedule, version and
	// state) and all owned grant/token/effect rows, not only returned errors.
	snapshot := func() string {
		t.Helper()
		var owned string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
		 'device',(SELECT to_jsonb(d) FROM oauth_store.devices d WHERE device_id=$1),
		 'grants',(SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY grant_id),'[]'::jsonb) FROM oauth_store.grants g),
		 'artifacts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY artifact_id),'[]'::jsonb) FROM oauth_store.artifacts a),
		 'effects',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY command_id),'[]'::jsonb) FROM oauth_store.effects e),
		 'device_effects',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY command_id),'[]'::jsonb) FROM oauth_store.device_effects e)
		)::text`, string(issued.Completion.CommandID)).Scan(&owned); err != nil {
			t.Fatal("could not observe original device and owned effects", err)
		}
		return owned
	}
	wrong := device.TokenExchange{ClientID: other.ID, ClientAuthentication: credential, DeviceCode: wire, Network: "192.0.2.1"}
	denyOtherClient := func() {
		t.Helper()
		before := snapshot()
		for _, action := range []oauth.DeviceAction{oauth.DevicePoll, oauth.DeviceCancel} {
			if action == oauth.DevicePoll {
				out, err := d.Poll(f.ctx, wrong)
				if !errors.Is(err, device.ErrAccessDenied) || out.Completion.Outcome == identity.CommitOutcomeCommitted || out.Tokens.CommandID != "" {
					t.Fatal("valid client B polled client A's device authority", err)
				}
			} else if out, err := d.Cancel(f.ctx, wrong); !errors.Is(err, device.ErrAccessDenied) || out.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("valid client B cancelled client A's device authority", err)
			}
			if snapshot() != before {
				t.Fatal("cross-client public request changed original row, polling schedule or owned effects")
			}
			out, err := native.ExecuteDevice(f.ctx, oauth.DeviceExecution{Action: action, Policy: configured.Policy, Client: projection, ClientAuthentication: credential, DeviceCode: wire, Network: "192.0.2.1"})
			if !errors.Is(err, oauth.ErrAccessDenied) || out.Completion.Outcome == identity.CommitOutcomeCommitted || out.Tokens.CommandID != "" {
				t.Fatal("direct native execution admitted client B against client A's device authority", err)
			}
			if snapshot() != before {
				t.Fatal("cross-client native request changed original row, polling schedule or owned effects")
			}
		}
	}
	denyOtherClient()
	original := device.TokenExchange{ClientID: "public-web", DeviceCode: wire, Network: "192.0.2.1"}
	devicePollDue(t, f)
	if _, err := d.Poll(f.ctx, original); !errors.Is(err, device.ErrAuthorizationPending) {
		t.Fatal("cross-client denials damaged genuine client A's pending request", err)
	}
	if _, err := d.Approve(f.ctx, device.Approval{Verification: device.Verification{Session: f.browser, UserCode: issued.UserCode, Network: "192.0.2.1"}, Origin: f.oauth.Protocol.Issuer.String(), CSRF: f.csrf, ConfirmedUserCode: issued.UserCode}); err != nil {
		t.Fatal("genuine session could not approve client A after cross-client denials", err)
	}
	devicePollDue(t, f)
	denyOtherClient()
	out, err := d.Poll(f.ctx, original)
	if err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted || out.Completion.Replayed {
		t.Fatal("genuine client A could not complete after cross-client denials", err)
	}
	if access, err := out.Tokens.AccessToken.Reveal(); err != nil || len(access) != 43 {
		t.Fatal("original client did not receive canonical access-token custody")
	}
	if refresh, err := out.Tokens.RefreshToken.Reveal(); err != nil || len(refresh) != 43 {
		t.Fatal("original client did not receive canonical refresh-token custody")
	}
	var consumed, grants, artifacts int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.devices WHERE client_id='public-web' AND state='consumed'),(SELECT count(*) FROM oauth_store.grants WHERE client_id='public-web'),(SELECT count(*) FROM oauth_store.artifacts WHERE client_id='public-web' AND device_root)`).Scan(&consumed, &grants, &artifacts); err != nil || consumed != 1 || grants != 1 || artifacts != 2 {
		t.Fatal("genuine completion lost original client-bound device/grant/token ownership", err)
	}
}

func TestNativeDeviceApprovalRequiresExplicitComparisonOriginAndRealCSRF(t *testing.T) {
	f := passwordFixture(t)
	d, _ := nativeDeviceFixture(t, &f)
	issued, _ := issueNativeDevice(t, f, d)
	valid := device.Approval{Verification: device.Verification{Session: f.browser, UserCode: issued.UserCode, Network: "192.0.2.1"}, Origin: f.oauth.Protocol.Issuer.String(), CSRF: f.csrf, ConfirmedUserCode: issued.UserCode}
	for _, mutation := range []func(*device.Approval){
		func(r *device.Approval) { r.ConfirmedUserCode = "" },
		func(r *device.Approval) {
			r.ConfirmedUserCode = "BCDF-GHJK"
			if r.ConfirmedUserCode == issued.UserCode {
				r.ConfirmedUserCode = "BCDF-GHJM"
			}
		},
		func(r *device.Approval) { r.Origin = "https://untrusted.example" },
		func(r *device.Approval) { r.CSRF = session.CSRFToken{} },
	} {
		r := valid
		mutation(&r)
		if _, err := d.Approve(f.ctx, r); !errors.Is(err, device.ErrAccessDenied) {
			t.Fatal("implicit or unauthenticated approval admitted", err)
		}
	}
	var state string
	var grants int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state,(SELECT count(*) FROM oauth_store.grants) FROM oauth_store.devices`).Scan(&state, &grants); err != nil || state != "pending" || grants != 0 {
		t.Fatal("rejected browser approval created human grant authority", err)
	}
	if _, err := d.Approve(f.ctx, valid); err != nil {
		t.Fatal("rejected browser input consumed legitimate pending request", err)
	}
}

func issueNativeDevice(t *testing.T, f authenticatedPasswordFixture, d *device.Service) (device.Authorization, string) {
	t.Helper()
	issued, err := d.Authorize(f.ctx, device.DeviceRequest{ClientID: "public-web", Scopes: []string{"identity:read"}, Network: "192.0.2.1"})
	if err != nil || issued.Completion.Outcome != identity.CommitOutcomeCommitted || issued.Completion.CommandID == "" || issued.UserCode == "" {
		t.Fatalf("actual registered device issuance failed: error=%v outcome=%v replay=%t command_present=%t user_code_present=%t", err, issued.Completion.Outcome, issued.Completion.Replayed, issued.Completion.CommandID != "", issued.UserCode != "")
	}
	wire, err := issued.DeviceCode.Reveal()
	if err != nil || len(wire) != 43 {
		t.Fatal("device code was not canonical32byte reveal-once custody")
	}
	if strings.Contains(issued.VerificationURIComplete, wire) || !strings.Contains(issued.VerificationURIComplete, issued.UserCode) || issued.VerificationURI != f.oauth.Protocol.Issuer.String()+"/device" {
		t.Fatal("configured verification URI authority or code separation lost")
	}
	var stored string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT row_to_json(d)::text FROM oauth_store.devices d`).Scan(&stored); err != nil || strings.Contains(stored, wire) || strings.Contains(stored, issued.UserCode) {
		t.Fatal("device bearer/user code persisted in plaintext", err)
	}
	return issued, wire
}

func devicePollDue(t *testing.T, f authenticatedPasswordFixture) {
	t.Helper()
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.devices SET next_poll_at=clock_timestamp()-interval '1 second' WHERE state IN('pending','approved')`); err != nil {
		t.Fatal(err)
	}
}

func TestNativeDevicePublicConsumerPendingSlowDownApprovalAndOneTokenWinner(t *testing.T) {
	f := passwordFixture(t)
	d, core := nativeDeviceFixture(t, &f)
	issued, wire := issueNativeDevice(t, f, d)
	verification := device.Verification{Session: f.browser, UserCode: issued.UserCode, Network: "192.0.2.1"}
	prompt, err := d.Inspect(f.ctx, verification)
	if err != nil || prompt.UserCode != issued.UserCode || prompt.ClientID != "public-web" || len(prompt.Scopes) != 1 || prompt.Resource != f.oauth.Protocol.Resource {
		t.Fatal("unbound device did not yield safe genuine-session prompt", err)
	}
	poll := device.TokenExchange{ClientID: "public-web", DeviceCode: wire, Network: "192.0.2.1"}
	devicePollDue(t, f)
	if out, err := d.Poll(f.ctx, poll); !errors.Is(err, device.ErrAuthorizationPending) || out.Interval != 5*time.Second {
		t.Fatal("pending protocol transition missing", err)
	}
	if out, err := d.Poll(f.ctx, poll); !errors.Is(err, device.ErrSlowDown) || out.Interval != 10*time.Second {
		t.Fatal("early poll did not add exactly5seconds", err)
	}
	if out, err := d.Poll(f.ctx, poll); !errors.Is(err, device.ErrSlowDown) || out.Interval != 15*time.Second {
		t.Fatal("repeated early poll did not add exactly5seconds", err)
	}
	approval := device.Approval{Verification: verification, Origin: f.oauth.Protocol.Issuer.String(), CSRF: f.csrf, ConfirmedUserCode: issued.UserCode}
	if _, err := d.Approve(f.ctx, approval); err != nil {
		t.Fatal("real current session/CSRF could not explicitly approve", err)
	}
	devicePollDue(t, f)
	var wg sync.WaitGroup
	results := make(chan device.PollResult, 2)
	for range 2 {
		wg.Go(func() { out, _ := d.Poll(f.ctx, poll); results <- out })
	}
	wg.Wait()
	close(results)
	winners := 0
	var refresh string
	for out := range results {
		if access, err := out.Tokens.AccessToken.Reveal(); err == nil && len(access) == 43 {
			winners++
			refresh, err = out.Tokens.RefreshToken.Reveal()
			if err != nil {
				t.Fatal("winning core grant lost refresh custody")
			}
		}
	}
	if winners != 1 {
		t.Fatal("concurrent polls did not yield exactly one native token winner")
	}
	if out, err := core.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("device success did not create actual core-owned refresh/token authority", err)
	}
	if _, err := d.Poll(f.ctx, poll); !errors.Is(err, device.ErrAccessDenied) {
		t.Fatal("consumed device grant replay became usable", err)
	}
	var issuedAudit, approvedAudit, polledAudit int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE action='identity.oauth_server.authorize_device'),count(*) FILTER(WHERE action='identity.oauth_server.approve_device'),count(*) FILTER(WHERE action='identity.oauth_server.poll_device') FROM audit.records`).Scan(&issuedAudit, &approvedAudit, &polledAudit); err != nil || issuedAudit != 1 || approvedAudit != 1 || polledAudit < 3 {
		t.Fatal("device state escaped required real audit composition", err)
	}
}

func TestNativeDeviceDenialCancellationAndExpiryPermanentlyWin(t *testing.T) {
	for _, action := range []string{"deny", "cancel", "expire"} {
		t.Run(action, func(t *testing.T) {
			f := passwordFixture(t)
			d, _ := nativeDeviceFixture(t, &f)
			issued, wire := issueNativeDevice(t, f, d)
			verification := device.Verification{Session: f.browser, UserCode: issued.UserCode, Network: "192.0.2.1"}
			poll := device.TokenExchange{ClientID: "public-web", DeviceCode: wire, Network: "192.0.2.1"}
			switch action {
			case "deny":
				r := device.Denial{Verification: verification, Origin: f.oauth.Protocol.Issuer.String(), CSRF: f.csrf}
				if _, err := d.Deny(f.ctx, r); err != nil {
					t.Fatal(err)
				}
				if _, err := d.Deny(f.ctx, r); err != nil {
					t.Fatal("denial not idempotent", err)
				}
			case "cancel":
				if _, err := d.Cancel(f.ctx, poll); err != nil {
					t.Fatal(err)
				}
			case "expire":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.devices SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute',next_poll_at=clock_timestamp()-interval '2 seconds'`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := d.Approve(f.ctx, device.Approval{Verification: verification, Origin: f.oauth.Protocol.Issuer.String(), CSRF: f.csrf, ConfirmedUserCode: issued.UserCode}); !errors.Is(err, device.ErrAccessDenied) {
				t.Fatal("terminal device state lost to later approval", err)
			}
			_, err := d.Poll(f.ctx, poll)
			want := device.ErrAccessDenied
			if action == "expire" {
				want = device.ErrExpiredToken
			}
			if !errors.Is(err, want) {
				t.Fatal("terminal device protocol classification lost", err)
			}
		})
	}
}

func TestNativeDevicePollingLimitTerminatesInsteadOfClampingSlowDown(t *testing.T) {
	f := passwordFixture(t)
	d, _ := nativeDeviceFixture(t, &f)
	_, wire := issueNativeDevice(t, f, d)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.devices SET interval_seconds=60,next_poll_at=clock_timestamp()+interval '20 seconds'`); err != nil {
		t.Fatal(err)
	}
	poll := device.TokenExchange{ClientID: "public-web", DeviceCode: wire, Network: "192.0.2.1"}
	if _, err := d.Poll(f.ctx, poll); !errors.Is(err, device.ErrAccessDenied) {
		t.Fatal("bounded server returned a clamped RFC slow_down instead of terminal denial", err)
	}
	devicePollDue(t, f)
	if _, err := d.Poll(f.ctx, poll); !errors.Is(err, device.ErrAccessDenied) {
		t.Fatal("polling limit terminal cancellation resurrected", err)
	}
}

func TestNativeDeviceContextCancellationDoesNotWithdrawDurableRequest(t *testing.T) {
	f := passwordFixture(t)
	d, _ := nativeDeviceFixture(t, &f)
	_, wire := issueNativeDevice(t, f, d)
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	poll := device.TokenExchange{ClientID: "public-web", DeviceCode: wire, Network: "192.0.2.1"}
	if _, err := d.Poll(ctx, poll); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled poll lost context classification", err)
	}
	devicePollDue(t, f)
	if _, err := d.Poll(f.ctx, poll); !errors.Is(err, device.ErrAuthorizationPending) {
		t.Fatal("call cancellation permanently withdrew durable request", err)
	}
}

func TestNativeDeviceApprovalSecondaryOutboxFailureRollsBackHumanAuthority(t *testing.T) {
	f := passwordFixture(t)
	d, _ := nativeDeviceFixture(t, &f)
	issued, _ := issueNativeDevice(t, f, d)
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT oauth_test_device_secondary_failure CHECK(topic NOT IN('consent.created.v1','consent.reconfirmed.v1')) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	approval := device.Approval{Verification: device.Verification{Session: f.browser, UserCode: issued.UserCode, Network: "192.0.2.1"}, Origin: f.oauth.Protocol.Issuer.String(), CSRF: f.csrf, ConfirmedUserCode: issued.UserCode}
	if out, err := d.Approve(f.ctx, approval); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("required secondary failure reported committed device approval")
	}
	var pending, grants, consents, effects, successAudits, notifications int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.devices WHERE state='pending' AND version=1),(SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.consents),(SELECT count(*) FROM oauth_store.device_effects WHERE operation_id='identity.oauth-server.device-approve'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.approve_device' AND outcome=1),(SELECT count(*) FROM public.outbox_messages WHERE topic IN('grant.authorized.v1','consent.created.v1','consent.reconfirmed.v1'))`).Scan(&pending, &grants, &consents, &effects, &successAudits, &notifications); err != nil || pending != 1 || grants != 0 || consents != 0 || effects != 0 || successAudits != 0 || notifications != 0 {
		t.Fatal("required device approval failure retained provisional authority", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages DROP CONSTRAINT oauth_test_device_secondary_failure`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Approve(f.ctx, approval); err != nil {
		t.Fatal("rolled-back approval consumed legitimate pending request", err)
	}
}

func TestNativeDeviceOriginalCommitRecoveryNeverRedeliversIssuance(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed-ack-loss", true: "precommit-expired-reservation"}[before], func(t *testing.T) {
			fault := &oauthCommitFault{before: before}
			f := passwordFixture(t, fault)
			d, _ := nativeDeviceFixture(t, &f)
			fault.armed.Store(true)
			lost, err := d.Authorize(f.ctx, device.DeviceRequest{ClientID: "public-web", Scopes: []string{"identity:read"}, Network: "192.0.2.1"})
			if !fault.hit.Load() || err == nil || lost.Completion.Outcome != identity.CommitOutcomeUnknown || lost.Completion.CommandID == "" || lost.UserCode != "" {
				t.Fatal("actual uncertain device COMMIT was misclassified or disclosed user code", err)
			}
			if _, err := lost.DeviceCode.Reveal(); err == nil {
				t.Fatal("uncertain device issuance disclosed bearer")
			}
			request := device.Recovery{OperationID: "identity.oauth-server.device-authorize", CommandID: lost.Completion.CommandID, ClientID: "public-web"}
			want := identity.CommitOutcomeCommitted
			if before {
				want = identity.CommitOutcomeNotCommitted
			}
			deadline := time.Now().Add(8 * time.Second)
			for {
				metadata, err := d.Recover(f.ctx, request)
				// The original dependency failure remains classified even after
				// authoritative recovery proves noncommit; nil is not that proof.
				if metadata.Outcome == want && (err == nil || before && errors.Is(err, device.ErrUnavailable)) {
					break
				}
				if !before || time.Now().After(deadline) || err != nil && !errors.Is(err, device.ErrUnavailable) {
					t.Fatal("original device participant recovery did not prove exact commitment", err)
				}
				timer := time.NewTimer(100 * time.Millisecond)
				select {
				case <-timer.C:
				case <-f.ctx.Done():
					timer.Stop()
					t.Fatal("bounded device recovery canceled")
				}
			}
			metadata, err := d.Recover(f.ctx, request)
			if metadata.Outcome != want || err != nil && !(before && errors.Is(err, device.ErrUnavailable)) {
				t.Fatal("repeated recovery changed original outcome", err)
			}
			var rows, effects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.devices),(SELECT count(*) FROM oauth_store.device_effects)`).Scan(&rows, &effects); err != nil {
				t.Fatal(err)
			}
			count := 1
			if before {
				count = 0
			}
			if rows != count || effects != count {
				t.Fatal("original recovery duplicated or retained rolled-back device authority")
			}
		})
	}
}

func TestNativeDeviceApprovedHumanCredentialAndConsentWithdrawalDenyPoll(t *testing.T) {
	for _, withdrawal := range []string{"credential", "consent"} {
		t.Run(withdrawal, func(t *testing.T) {
			f := passwordFixtureWithChange(t, withdrawal == "credential")
			d, core := nativeDeviceFixture(t, &f)
			issued, wire := issueNativeDevice(t, f, d)
			approval := device.Approval{Verification: device.Verification{Session: f.browser, UserCode: issued.UserCode, Network: "192.0.2.1"}, Origin: f.oauth.Protocol.Issuer.String(), CSRF: f.csrf, ConfirmedUserCode: issued.UserCode}
			if _, err := d.Approve(f.ctx, approval); err != nil {
				t.Fatal(err)
			}
			if withdrawal == "credential" {
				f.changePassword()
			} else {
				page, err := core.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
				if err != nil || len(page.Page.Items()) != 1 {
					t.Fatal("real device approval did not create own consent", err)
				}
				consent := page.Page.Items()[0]
				if out, err := core.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRemove, consent.ID(), consent.Version())}); err != nil || !out.Deleted {
					t.Fatal("actual consent owner could not withdraw device approval", err)
				}
			}
			devicePollDue(t, f)
			if out, err := d.Poll(f.ctx, device.TokenExchange{ClientID: "public-web", DeviceCode: wire, Network: "192.0.2.1"}); !errors.Is(err, device.ErrAccessDenied) || out.Tokens.CommandID != "" {
				t.Fatal("withdrawn original human authority still issued a device token", err)
			}
			var tokens int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE kind IN(3,4)`).Scan(&tokens); err != nil || tokens != 0 {
				t.Fatal("failed original-source fence persisted token material", err)
			}
		})
	}
}

func TestNativeManagedDevicePermissionUsesActualCreationCeilingAndDeletionAuthority(t *testing.T) {
	f := passwordFixture(t)
	enableClientManagement(t, &f)
	ordinary, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	create := clientCreateRequest(t, f, "managed-device-create")
	create.DeviceAuthorization = true
	if out, err := ordinary.ClientCreate(f.ctx, create); err == nil || out.Client.ID != "" {
		t.Fatal("managed creation bypassed false-default device ceiling")
	}
	f.oauth.Protocol.ManagedClients.DeviceAuthorization = true
	d, core := nativeDeviceFixture(t, &f)
	created, err := core.ClientCreate(f.ctx, create)
	if err != nil || !created.Client.DeviceAuthorization || created.Client.Version != 1 {
		t.Fatal("actual managed registration lost explicit device permission", err)
	}
	secret, err := created.Secret.Reveal()
	if err != nil {
		t.Fatal("managed confidential secret custody missing")
	}
	// The selected application admits only this now-created concrete client ID.
	policy := f.oauth.Coordinator.QueryPolicy.Authorization.(deviceConsumerPolicy)
	policy.clients[authorization.SubjectID(created.Client.ID)] = true
	credential := confidentialBasic(t, created.Client.ID, secret)
	issued, err := d.Authorize(f.ctx, device.DeviceRequest{ClientID: created.Client.ID, ClientAuthentication: credential, Scopes: []string{"identity:read"}, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("persisted managed device registration unusable", err)
	}
	wire, err := issued.DeviceCode.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Approve(f.ctx, device.Approval{Verification: device.Verification{Session: f.browser, UserCode: issued.UserCode, Network: "192.0.2.1"}, Origin: f.oauth.Protocol.Issuer.String(), CSRF: f.csrf, ConfirmedUserCode: issued.UserCode}); err != nil {
		t.Fatal(err)
	}
	remove := create
	remove.RequestKey, err = identity.NewIdempotencyKey([]byte("managed-device-delete"))
	if err != nil {
		t.Fatal(err)
	}
	remove.ClientID, remove.Version = created.Client.ID, created.Client.Version
	remove.Redirects, remove.Scopes, remove.DeviceAuthorization = nil, nil, false
	if out, err := core.ClientDelete(f.ctx, remove); err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual manager could not delete device registration", err)
	}
	devicePollDue(t, f)
	if out, err := d.Poll(f.ctx, device.TokenExchange{ClientID: created.Client.ID, ClientAuthentication: credential, DeviceCode: wire, Network: "192.0.2.1"}); err == nil || out.Tokens.CommandID != "" {
		t.Fatal("warm device consumer trusted deleted managed registration")
	}
	var tokens int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE kind IN(3,4)`).Scan(&tokens); err != nil || tokens != 0 {
		t.Fatal("deleted device registration issued token artifacts", err)
	}
}

func TestNativeDeviceApprovalAndTokenAckLossRecoverOnlyOriginalMetadata(t *testing.T) {
	for _, stage := range []string{"approval", "token"} {
		t.Run(stage, func(t *testing.T) {
			fault := &oauthCommitFault{}
			f := passwordFixture(t, fault)
			d, _ := nativeDeviceFixture(t, &f)
			issued, wire := issueNativeDevice(t, f, d)
			approval := device.Approval{Verification: device.Verification{Session: f.browser, UserCode: issued.UserCode, Network: "192.0.2.1"}, Origin: f.oauth.Protocol.Issuer.String(), CSRF: f.csrf, ConfirmedUserCode: issued.UserCode}
			request := device.Recovery{OperationID: "identity.oauth-server.device-approve", Session: f.browser, UserCode: issued.UserCode}
			if stage == "approval" {
				fault.armed.Store(true)
				lost, err := d.Approve(f.ctx, approval)
				if !fault.hit.Load() || err == nil || lost.Outcome != identity.CommitOutcomeUnknown || lost.CommandID == "" {
					t.Fatal("actual device approval COMMIT loss was guessed", err)
				}
				request.CommandID = lost.CommandID
			} else {
				if _, err := d.Approve(f.ctx, approval); err != nil {
					t.Fatal(err)
				}
				devicePollDue(t, f)
				fault.armed.Store(true)
				lost, err := d.Poll(f.ctx, device.TokenExchange{ClientID: "public-web", DeviceCode: wire, Network: "192.0.2.1"})
				if !fault.hit.Load() || err == nil || lost.Completion.Outcome != identity.CommitOutcomeUnknown || lost.Completion.CommandID == "" {
					t.Fatal("actual device token COMMIT loss was guessed", err)
				}
				if _, err := lost.Tokens.AccessToken.Reveal(); err == nil {
					t.Fatal("unknown device token command disclosed access")
				}
				if _, err := lost.Tokens.RefreshToken.Reveal(); err == nil {
					t.Fatal("unknown device token command disclosed refresh")
				}
				request = device.Recovery{OperationID: "identity.oauth-server.device-token", CommandID: lost.Completion.CommandID, ClientID: "public-web", DeviceCode: wire}
			}
			for range 2 {
				metadata, err := d.Recover(f.ctx, request)
				if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted || metadata.CommandID != request.CommandID {
					t.Fatal("lost device operation did not recover exact original metadata", err)
				}
			}
			var effects, artifacts int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.device_effects WHERE operation_id=$1),(SELECT count(*) FROM oauth_store.artifacts WHERE kind IN(3,4))`, request.OperationID).Scan(&effects, &artifacts); err != nil || effects != 1 {
				t.Fatal("device recovery repeated a durable transition", err)
			}
			wantArtifacts := 0
			if stage == "token" {
				wantArtifacts = 2
				if _, err := d.Poll(f.ctx, device.TokenExchange{ClientID: "public-web", DeviceCode: wire, Network: "192.0.2.1"}); !errors.Is(err, device.ErrAccessDenied) {
					t.Fatal("unknown committed token operation redelivered custody", err)
				}
			}
			if artifacts != wantArtifacts {
				t.Fatal("historical recovery generated or lost core token artifacts")
			}
		})
	}
}
