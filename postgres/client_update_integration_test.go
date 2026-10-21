//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

func installClientUpdates(t *testing.T, f *authenticatedPasswordFixture) {
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
	clients := oauthpostgres.ClientMigrationSource{Base: oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}, Schema: "oauth_store", Version: 7003}
	rotation := oauthpostgres.ClientRotationMigrationSource{Base: clients, Schema: "oauth_store", Version: 7004}
	runner, err := migrations.NewRunner(oauthpostgres.ClientUpdateMigrationSource{Base: rotation, Schema: "oauth_store", Version: 7005}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := runner.Up(f.ctx); err != nil || len(out.Records()) != 1 {
		t.Fatal("metadata forward installation", err)
	}
	if out, err := runner.Up(f.ctx); err != nil || len(out.Records()) != 0 {
		t.Fatal("metadata history prefix changed", err)
	}
	f.oauth.ClientMetadataUpdates = true
}

func enableClientUpdates(t *testing.T, f *authenticatedPasswordFixture) {
	t.Helper()
	enableClientRotation(t, f)
	f.oauth.Protocol.ManagedClients.Redirects = []string{"https://managed.example/callback", "https://managed.example/new"}
	installClientUpdates(t, f)
}

func clientUpdateRequest(t *testing.T, f authenticatedPasswordFixture, c oauth.Client, key string) oauth.ClientUpdateRequest {
	t.Helper()
	return oauth.ClientUpdateRequest{Management: clientRotationRequest(t, f, c, key, 0).Management, Redirects: []string{"https://managed.example/new"}, Scopes: []string{"identity:read"}}
}

func TestNativeClientUpdateDiscoveredVersionReplacesMetadataWithoutChangingBasic(t *testing.T) {
	f := passwordFixture(t)
	enableClientUpdates(t, &f)
	seed, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := seed.ClientCreate(f.ctx, clientCreateRequest(t, f, "update-create"))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := created.Secret.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	old := created.Client
	basic := confidentialBasic(t, old.ID, secret)
	access, refresh := issuedConfidentialTokens(t, f, seed, old, basic)
	code, proof := confidentialCode(t, f, seed, old)
	consents, err := seed.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
	if err != nil || len(consents.Page.Items()) != 1 {
		t.Fatal("original consent", err)
	}
	originalConsent := consents.Page.Items()[0]
	verifier, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, resourcePolicy(f, old))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := verifier.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"}); err != nil || p.RequireScope("identity:read") != nil {
		t.Fatal("pre-update resource control", err)
	}
	challenge, _ := oauth.S256Challenge(strings.Repeat("a", 43))
	pending, err := seed.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: old.ID, RedirectURI: old.Redirects[0], Resource: old.Resource, Scopes: []string{"identity:write"}, CodeChallenge: challenge, State: "pending-update"}})
	if err != nil || pending.Outcome != oauth.ConsentRequired {
		t.Fatal("pre-update interaction", err)
	}
	continuation, _ := pending.Continuation.Reveal()
	var beforeDigest []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, old.ID).Scan(&beforeDigest); err != nil {
		t.Fatal(err)
	}
	fresh, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	page, err := fresh.ClientList(f.ctx, clientReadRequest(f, 1))
	if err != nil || len(page.Page.Items()) != 1 {
		t.Fatal("fresh manager discovery before replacement", err)
	}
	discovered := page.Page.Items()[0]
	out, err := fresh.ClientUpdate(f.ctx, clientUpdateRequest(t, f, discovered, "update-original"))
	if err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted || out.Client.Version != 2 || out.Client.ID != old.ID || out.Client.Owner != old.Owner || out.Client.Resource != old.Resource || out.Client.AuthenticationMethod != old.AuthenticationMethod {
		t.Fatal("discovered current client cannot replace metadata", err)
	}
	if !slices.Equal(out.Client.Redirects, []string{"https://managed.example/new"}) || !slices.Equal(out.Client.Scopes, []string{"identity:read"}) {
		t.Fatal("replacement merged old metadata")
	}
	var afterDigest []byte
	var generation string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT secret_digest,secret_version::text FROM oauth_store.managed_clients WHERE client_id=$1`, old.ID).Scan(&afterDigest, &generation); err != nil || generation != "1" || !bytes.Equal(beforeDigest, afterDigest) {
		t.Fatal("metadata replacement changed Basic digest generation", err)
	}
	if p, err := seed.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, Origin: f.oauth.Protocol.Issuer.String(), ClientID: old.ID, Continuation: continuation, Approve: true, Scopes: []string{"identity:write"}, Network: "192.0.2.1"}); err == nil || p.Outcome == oauth.AuthorizationRedirect {
		t.Fatal("old interaction survived metadata replacement")
	}
	if out, err := fresh.ConsentGet(f.ctx, oauth.ConsentGetRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRead, originalConsent.ID(), 0)}); err == nil || out.Consent.ID() != "" {
		t.Fatal("old consent survived metadata replacement")
	}
	requireInvalidResource(t, verifier, f.ctx, access)
	for _, r := range []oauth.TokenRequest{
		{GrantType: oauth.AuthorizationCodeGrant, ClientID: old.ID, ClientAuthentication: basic, Code: code, CodeVerifier: proof, RedirectURI: old.Redirects[0], Network: "192.0.2.1"},
		{GrantType: oauth.RefreshTokenGrant, ClientID: old.ID, ClientAuthentication: basic, RefreshToken: refresh, Network: "192.0.2.1"},
	} {
		if result, err := seed.Token(f.ctx, r); err == nil || result.AccessToken != (oauth.Token{}) {
			t.Fatal("old broader client generation still authorized")
		}
	}
	if result, err := seed.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: old.ID, ClientAuthentication: basic, Token: access}); err != nil || result.Active {
		t.Fatal("warm introspection retained pre-update access", err)
	}
	for _, request := range []oauth.AuthorizationRequest{
		{ClientID: old.ID, RedirectURI: old.Redirects[0], Resource: old.Resource, Scopes: []string{"identity:read"}, CodeChallenge: challenge, State: "removed-redirect"},
		{ClientID: old.ID, RedirectURI: out.Client.Redirects[0], Resource: old.Resource, Scopes: []string{"identity:write"}, CodeChallenge: challenge, State: "removed-scope"},
	} {
		if _, err := seed.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: request}); err == nil {
			t.Fatal("removed redirect/scope accepted")
		}
	}
	issuedConfidentialTokens(t, f, seed, out.Client, basic)
	retry, err := fresh.ClientUpdate(f.ctx, clientUpdateRequest(t, f, discovered, "update-original"))
	if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != out.Completion.CommandID || retry.Client.Version != 2 {
		t.Fatal("original replacement retry changed historical result", err)
	}
	changed := clientUpdateRequest(t, f, discovered, "update-original")
	changed.Redirects = []string{"https://managed.example/callback"}
	if _, err := fresh.ClientUpdate(f.ctx, changed); !errors.Is(err, oauth.ErrClientConflict) {
		t.Fatal("same key changed replacement intent", err)
	}
	var effects, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-update'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.update_client' AND outcome=1),(SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_client.configuration_changed.v1')`).Scan(&effects, &audits, &events); err != nil || effects != 1 || audits != 1 || events != 1 {
		t.Fatal("replacement lifecycle/audit/effect not exactly once", err)
	}
}

func TestNativeClientUpdatePreservesOverlapAndIndependentGenerations(t *testing.T) {
	f := passwordFixture(t)
	enableClientUpdates(t, &f)
	s, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.ClientCreate(f.ctx, clientCreateRequest(t, f, "generation-create"))
	if err != nil {
		t.Fatal(err)
	}
	initial, _ := created.Secret.Reveal()
	initialBasic := confidentialBasic(t, created.Client.ID, initial)
	rotated, err := s.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, created.Client, "generation-rotate", time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	successor, _ := rotated.Secret.Reveal()
	successorBasic := confidentialBasic(t, created.Client.ID, successor)
	type slotSnapshot struct {
		current, previous       []byte
		generation, predecessor string
		expiry                  time.Time
	}
	read := func() slotSnapshot {
		var r slotSnapshot
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT secret_digest,previous_secret_digest,secret_version::text,previous_secret_version::text,previous_secret_expires_at FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&r.current, &r.previous, &r.generation, &r.predecessor, &r.expiry); err != nil {
			t.Fatal(err)
		}
		return r
	}
	before := read()
	current := rotated.Client
	for i, key := range []string{"generation-update-a", "generation-update-b"} {
		r := clientUpdateRequest(t, f, current, key)
		if i == 1 {
			r.Redirects = []string{"https://managed.example/callback"}
			r.Scopes = []string{"identity:read", "identity:write"}
		}
		out, err := s.ClientUpdate(f.ctx, r)
		if err != nil || out.Client.Version != current.Version+1 {
			t.Fatal("repeated metadata authority update", err)
		}
		current = out.Client
		after := read()
		if !bytes.Equal(before.current, after.current) || !bytes.Equal(before.previous, after.previous) || before.generation != after.generation || before.predecessor != after.predecessor || !before.expiry.Equal(after.expiry) {
			t.Fatal("replacement changed original secret slots/overlap")
		}
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, basic := range []oauth.ClientAuthentication{initialBasic, successorBasic} {
		if err := store.AuthenticateCurrentClient(f.ctx, current, basic); err != nil {
			t.Fatal("unchanged current/predecessor Basic rejected after multiple metadata updates", err)
		}
	}
	issuedConfidentialTokens(t, f, s, current, successorBasic)
	third, err := s.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, current, "generation-third-secret", time.Minute))
	if err != nil || third.Client.Version != 5 {
		t.Fatal("rotation after separated registration generations", err)
	}
	thirdWire, _ := third.Secret.Reveal()
	thirdBasic := confidentialBasic(t, current.ID, thirdWire)
	after := read()
	if after.generation != "3" || after.predecessor != "2" {
		t.Fatal("rotation derived digest generation from registration authority")
	}
	if err := store.AuthenticateCurrentClient(f.ctx, third.Client, initialBasic); err == nil {
		t.Fatal("second rotation retained oldest live predecessor")
	}
	for _, basic := range []oauth.ClientAuthentication{successorBasic, thirdBasic} {
		if err := store.AuthenticateCurrentClient(f.ctx, third.Client, basic); err != nil {
			t.Fatal("actual independent generation authentication", err)
		}
	}
	issuedConfidentialTokens(t, f, s, third.Client, thirdBasic)
	fourth, err := s.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, third.Client, "generation-zero-overlap", 0))
	if err != nil || fourth.Client.Version != 6 {
		t.Fatal("zero overlap after metadata updates", err)
	}
	fourthWire, _ := fourth.Secret.Reveal()
	fourthBasic := confidentialBasic(t, current.ID, fourthWire)
	for _, basic := range []oauth.ClientAuthentication{initialBasic, successorBasic, thirdBasic} {
		if store.AuthenticateCurrentClient(f.ctx, fourth.Client, basic) == nil {
			t.Fatal("zero overlap retained retired secret")
		}
	}
	if err := store.AuthenticateCurrentClient(f.ctx, fourth.Client, fourthBasic); err != nil {
		t.Fatal("fourth actual secret generation denied", err)
	}
	if _, err := s.ClientDelete(f.ctx, clientRotationRequest(t, f, fourth.Client, "generation-delete", 0).Management); err != nil {
		t.Fatal(err)
	}
	if store.AuthenticateCurrentClient(f.ctx, fourth.Client, fourthBasic) == nil {
		t.Fatal("terminal deletion retained secret")
	}

	// A separate short overlap proves metadata replacement cannot renew the
	// original exclusive predecessor deadline, not merely its displayed value.
	expiring, err := s.ClientCreate(f.ctx, clientCreateRequest(t, f, "expiry-update-create"))
	if err != nil {
		t.Fatal(err)
	}
	old, _ := expiring.Secret.Reveal()
	overlap, err := s.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, expiring.Client, "expiry-update-rotate", 2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := s.ClientUpdate(f.ctx, clientUpdateRequest(t, f, overlap.Client, "expiry-update-replace"))
	if err != nil {
		t.Fatal(err)
	}
	oldBasic := confidentialBasic(t, updated.Client.ID, old)
	if err := store.AuthenticateCurrentClient(f.ctx, updated.Client, oldBasic); err != nil {
		t.Fatal("live original predecessor control", err)
	}
	timer := time.NewTimer(time.Until(overlap.PredecessorExpiresAt.Add(time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal("original overlap deadline canceled")
	}
	if store.AuthenticateCurrentClient(f.ctx, updated.Client, oldBasic) == nil {
		t.Fatal("metadata update renewed exclusive predecessor expiry")
	}
	live, _ := overlap.Secret.Reveal()
	if err := store.AuthenticateCurrentClient(f.ctx, updated.Client, confidentialBasic(t, updated.Client.ID, live)); err != nil {
		t.Fatal("current secret unavailable after unchanged predecessor expiry", err)
	}
}
