//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

func unchangedNarrowingState(t *testing.T, f authenticatedPasswordFixture, consent oauth.Consent) {
	t.Helper()
	var version, generation string
	var scopes []byte
	var effects, events, audits int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT c.version::text,c.generation::text,c.scopes,(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.consent-update'),(SELECT count(*) FROM public.outbox_messages WHERE topic='consent.scope_changed.v1'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.revoke_consent' AND outcome=1) FROM oauth_store.consents c WHERE consent_id=$1`, consent.ID()).Scan(&version, &generation, &scopes, &effects, &events, &audits); err != nil {
		t.Fatal(err)
	}
	var actual []string
	if json.Unmarshal(scopes, &actual) != nil || version != "1" || generation != "1" || !slices.Equal(actual, consent.Scopes()) || effects != 0 || events != 0 || audits != 0 {
		t.Fatal("noncommitted narrowing changed consent or retained success effects")
	}
}

func TestNativeConsentNarrowingPreCommitDisconnectReconcilesOriginalNoncommit(t *testing.T) {
	fault := &oauthCommitFault{before: true}
	f := passwordFixture(t, fault)
	enableConsentNarrowing(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = broadConsentCode(t, f, service, []string{"identity:read", "identity:write"})
	consent := currentNarrowConsent(t, f, service)
	request := narrowRequest(t, f, consent, "before-actual-narrow-commit", []string{"identity:read"})
	fault.armed.Store(true)
	lost, err := service.ConsentUpdate(f.ctx, request)
	if !fault.hit.Load() || !errors.Is(err, oauth.ErrUnavailable) || lost.Updated || lost.Completion.Outcome != identity.CommitOutcomeUnknown || lost.Completion.CommandID == "" {
		t.Fatal("pre-COMMIT narrowing disconnect was guessed or not exercised", err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.consent-update", CommandID: lost.Completion.CommandID, ConsentID: consent.ID(), ClientID: request.ClientID, TenantID: f.tenant, Session: f.browser}
	metadata, err := store.Recover(f.ctx, recovery)
	if err != nil || metadata.Outcome != identity.CommitOutcomeInProgress || metadata.CommandID != lost.Completion.CommandID {
		t.Fatal("fresh Store did not observe the live original lease", err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for metadata.Outcome != identity.CommitOutcomeNotCommitted {
		if time.Now().After(deadline) {
			t.Fatal("original narrowing participant could not reconcile expired pending noncommit", err)
		}
		waitAuthenticationBoundary(t, f, time.Now().Add(100*time.Millisecond))
		metadata, err = store.Recover(f.ctx, recovery)
		if err != nil && !errors.Is(err, oauth.ErrUnavailable) {
			t.Fatal("unexpected original noncommit recovery classification", err)
		}
	}
	// The kernel preserves dependency-failure with proven NotCommitted, rather
	// than presenting the original failed command as a successful operation.
	if !errors.Is(err, oauth.ErrUnavailable) {
		t.Fatal("proven noncommit lost the original dependency-failure classification", err)
	}
	var settledAudits int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM audit.records`).Scan(&settledAudits); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		again, err := store.Recover(f.ctx, recovery)
		if !errors.Is(err, oauth.ErrUnavailable) || again.Outcome != identity.CommitOutcomeNotCommitted || again.CommandID != lost.Completion.CommandID {
			t.Fatal("original noncommit metadata was not stable", err)
		}
	}
	restart, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := restart.ConsentUpdate(f.ctx, request)
	if !errors.Is(err, oauth.ErrUnavailable) || retry.Updated || retry.Completion.CommandID != lost.Completion.CommandID || retry.Completion.Outcome != identity.CommitOutcomeNotCommitted || !retry.Completion.Replayed {
		t.Fatal("same original key restarted the terminal noncommit")
	}
	var afterAudits int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM audit.records`).Scan(&afterAudits); err != nil || afterAudits != settledAudits {
		t.Fatal("metadata repetition or same-key retry appended audit effects", err)
	}
	unchangedNarrowingState(t, f, consent)
}

// This transport scheduler blocks only the second real consent-root lock query
// (Apply, after preparation-start committed). It never changes SQL, a session
// proof, a stored deadline, the journal or PostgreSQL's authoritative clock.
type narrowingApplyGate struct {
	armed       atomic.Bool
	queries     atomic.Uint32
	provisional atomic.Bool
	reached     chan struct{}
	proceed     chan struct{}
	done        <-chan struct{}
}

func (g *narrowingApplyGate) observe(wire []byte) {
	if bytes.Contains(wire, []byte(`UPDATE "oauth_store".consents SET scopes=`)) {
		g.provisional.Store(true)
	}
	if g.armed.Load() && bytes.Contains(wire, []byte(`FROM "oauth_store".consents WHERE consent_id=$1`)) && bytes.Contains(wire, []byte("FOR UPDATE")) && g.queries.Add(1) == 2 {
		close(g.reached)
		select {
		case <-g.proceed:
		case <-g.done:
		}
	}
}

func TestNativeConsentNarrowingOriginalAdmissionExpiresAcrossApplyRootWait(t *testing.T) {
	gate := &narrowingApplyGate{reached: make(chan struct{}), proceed: make(chan struct{})}
	f := passwordFixture(t, &oauthCommitFault{beforeWrite: gate.observe})
	gate.done = f.ctx.Done()
	enableConsentNarrowing(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = broadConsentCode(t, f, service, []string{"identity:read", "identity:write"})
	consent := currentNarrowConsent(t, f, service)
	token, _ := session.ParseToken(f.browser.Token())
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	original, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil || !original.Authenticated {
		t.Fatal("genuine original sealed session missing", err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	// Native session admission fixes its 20-second read cap. Age this genuine
	// sealed observation before starting the bounded call; a later native read
	// must not renew it. Only the final three seconds occur inside the call.
	waitAuthenticationBoundary(t, f, original.ValidUntil().Add(-3*time.Second))
	if original.ValidateAt(time.Now()) != nil {
		t.Fatal("positive original admission expired before the native call")
	}
	blocker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(f.ctx)
	var blockerID uint32
	if err := blocker.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&blockerID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	type result struct {
		out oauth.ConsentUpdateResult
		err error
	}
	finished := make(chan result, 1)
	request := narrowRequest(t, f, consent, "original-read-root-wait", []string{"identity:read"})
	gate.armed.Store(true)
	var released sync.Once
	release := func() { released.Do(func() { close(gate.proceed) }) }
	joined := false
	defer func() {
		cancel()
		release()
		_ = blocker.Rollback(f.ctx)
		if !joined {
			<-finished
		}
	}()
	go func() {
		out, err := store.ConsentUpdate(ctx, oauth.ConsentUpdateExecution{Request: request, Session: original, Client: f.oauth.Protocol.Clients[0]})
		finished <- result{out, err}
	}()
	select {
	case <-gate.reached:
	case premature := <-finished:
		joined = true
		t.Fatal("native call did not reach live Apply root fence", premature.err)
	case <-f.ctx.Done():
		t.Fatal("bounded native Apply gate canceled")
	}
	if original.ValidateAt(time.Now()) != nil {
		t.Fatal("original admission was not live at the positive Apply control")
	}
	if _, err := blocker.Exec(f.ctx, `SELECT consent_id FROM oauth_store.consents WHERE consent_id=$1 FOR UPDATE`, consent.ID()); err != nil {
		t.Fatal(err)
	}
	release()
	for {
		var waiting int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, blockerID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if !time.Now().Before(original.ValidUntil()) {
			t.Fatal("native call did not actually wait on the consent root while live")
		}
		waitAuthenticationBoundary(t, f, time.Now().Add(10*time.Millisecond))
	}
	waitAuthenticationBoundary(t, f, original.ValidUntil())
	if err := blocker.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	lost := <-finished
	joined = true
	if lost.err == nil || lost.out.Updated || gate.provisional.Load() {
		t.Fatal("expired original admission crossed the protected root wait into mutation", lost.err)
	}
	unchangedNarrowingState(t, f, consent)
	// The browser and persisted consent remain active: a fresh real owner read
	// plus a different explicitly requested key may still perform the narrowing.
	if positive, err := service.ConsentUpdate(f.ctx, narrowRequest(t, f, consent, "fresh-read-positive-control", []string{"identity:read"})); err != nil || !positive.Updated {
		t.Fatal("fresh native admission positive control failed", err)
	}
}
