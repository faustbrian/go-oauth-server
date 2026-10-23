//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"golang.org/x/oauth2"
)

func authenticationAt(t *testing.T, f authenticatedPasswordFixture, browser auth.BearerCredential) time.Time {
	t.Helper()
	token, err := session.ParseToken(browser.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil || !observed.Authenticated {
		t.Fatal("genuine current authentication unavailable", err)
	}
	bindings, err := observed.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	return bindings.Authentication.Proof.IssuedAt
}

func waitAuthenticationBoundary(t *testing.T, f authenticatedPasswordFixture, deadline time.Time) {
	t.Helper()
	if delay := time.Until(deadline); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-f.ctx.Done():
			t.Fatal("genuine authentication boundary wait cancelled")
		}
	}
}

func TestNativeOIDCAuthenticationAgePresenceAndExpiry(t *testing.T) {
	for _, mode := range []string{"absent", "positive-current", "positive-expired"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			service, child, _, _, _ := oidcFixture(t, &f)
			authenticatedAt := authenticationAt(t, f, f.browser)
			request := pairwiseBegin(f)
			request.Request.State = "age-original-state"
			verifier := oauth2.GenerateVerifier()
			request.Request.CodeChallenge = oauth2.S256ChallengeFromVerifier(verifier)
			if mode != "absent" {
				age := uint32(300)
				if mode == "positive-expired" {
					age = 2
					waitAuthenticationBoundary(t, f, authenticatedAt.Add(2*time.Second))
				}
				request.Request.MaxAge = &age
			}
			begin, err := service.Authorize(f.ctx, request)
			want := oauth.ConsentRequired
			if mode == "positive-expired" {
				want = oauth.FreshAuthenticationRequired
			}
			if err != nil || begin.Outcome != want || (begin.Request.MaxAge == nil) != (request.Request.MaxAge == nil) {
				t.Fatal("absence/positive age selected the wrong native authentication transition", err)
			}
			continuation, err := begin.Continuation.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			browser, csrf := f.browser, f.csrf
			if mode == "positive-expired" {
				if _, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: browser, CSRF: csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrLoginRequired) {
					t.Fatal("expired positive age accepted original authentication")
				}
				browser, csrf = f.signInAgain()
				authenticatedAt = authenticationAt(t, f, browser)
			}
			approved, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: browser, CSRF: csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"})
			if err != nil || approved.Outcome != oauth.AuthorizationRedirect || mode == "positive-expired" && approved.ExpiresAt.After(begin.ExpiresAt) {
				t.Fatal("selected age did not complete original native authorization", err)
			}
			verifyOriginalAuthenticationOutcome(t, f, service, child, request.Request, approved, verifier, authenticatedAt, "")
		})
	}
}

func TestNativeOIDCFreshLoginExplicitZeroPairwiseRetainsOriginalSubject(t *testing.T) {
	f := passwordFixture(t)
	service, child, _, _, _ := pairwiseFixture(t, &f)
	request := pairwiseBegin(f)
	age := uint32(0)
	request.Request.MaxAge = &age
	request.Request.State = "pairwise-zero-original-state"
	verifier := oauth2.GenerateVerifier()
	request.Request.CodeChallenge = oauth2.S256ChallengeFromVerifier(verifier)
	begin, err := service.Authorize(f.ctx, request)
	if err != nil || begin.Outcome != oauth.FreshAuthenticationRequired || begin.Request.MaxAge == nil || *begin.Request.MaxAge != 0 {
		t.Fatal("explicit zero did not retain original fresh-authentication intent", err)
	}
	var originalSubject string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT b.subject FROM oauth_store.grant_subject_bindings g JOIN oauth_store.subject_bindings b USING(context_id,tenant_id,sector_host,user_id)`).Scan(&originalSubject); err != nil || originalSubject == "" {
		t.Fatal("original native pending grant has no durable pairwise subject", err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	// A caller mutation after admission cannot replace encrypted explicit-zero
	// intent with a permissive positive maximum age during reconstruction.
	age = 300
	rebuiltStore, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	rebuiltCore, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: rebuiltStore})
	if err != nil {
		t.Fatal(err)
	}
	service, err = rebuiltCore.WithOIDC(child)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrLoginRequired) {
		t.Fatal("caller mutation/reconstruction replaced original explicit-zero intent")
	}
	browser, csrf := f.signInAgain()
	authenticatedAt := authenticationAt(t, f, browser)
	approved, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: browser, CSRF: csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"})
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect || approved.ExpiresAt.After(begin.ExpiresAt) || approved.Request.MaxAge == nil || *approved.Request.MaxAge != 0 {
		t.Fatal("pairwise explicit-zero continuation lost original request/deadline", err)
	}
	verifyOriginalAuthenticationOutcome(t, f, service, child, approved.Request, approved, verifier, authenticatedAt, originalSubject)
}

func TestNativeOIDCFreshLoginSubstitutionDoesNotConsumeOriginalFlow(t *testing.T) {
	f := passwordFixture(t)
	service, child, _, _, _ := oidcFixture(t, &f)
	preexisting, preexistingCSRF := f.signInAgain()
	request := pairwiseBegin(f)
	request.Request.Prompt = "login"
	request.Request.State = "substitution-original-state"
	verifier := oauth2.GenerateVerifier()
	request.Request.CodeChallenge = oauth2.S256ChallengeFromVerifier(verifier)
	begin, err := service.Authorize(f.ctx, request)
	if err != nil || begin.Outcome != oauth.FreshAuthenticationRequired {
		t.Fatal(err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	base := oauth.ContinueRequest{TenantID: f.tenant, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"}
	old := base
	old.Session, old.CSRF = preexisting, preexistingCSRF
	if _, err := service.Continue(f.ctx, old); err == nil {
		t.Fatal("different but pre-request session counted as fresh authentication")
	}
	foreign := base
	foreign.Session, foreign.CSRF = f.anotherUser()
	if _, err := service.Continue(f.ctx, foreign); err == nil {
		t.Fatal("genuine foreign-user login adopted another user's original authorization")
	}
	browser, csrf := f.signInAgain()
	base.Session, base.CSRF = browser, csrf
	for _, change := range []func(*oauth.ContinueRequest){
		func(r *oauth.ContinueRequest) { r.CSRF = f.csrf },
		func(r *oauth.ContinueRequest) { r.ClientID = "other-public-web" },
		func(r *oauth.ContinueRequest) { r.TenantID = "foreign-tenant" },
		func(r *oauth.ContinueRequest) { r.Origin = "https://foreign.example" },
	} {
		wrong := base
		change(&wrong)
		if _, err := service.Continue(f.ctx, wrong); err == nil {
			t.Fatal("fresh-login continuation accepted foreign CSRF/client/tenant/origin")
		}
	}
	approved, err := service.Continue(f.ctx, base)
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect || approved.ExpiresAt.After(begin.ExpiresAt) {
		t.Fatal("rejected substitutions consumed or renewed original continuation", err)
	}
	verifyOriginalAuthenticationOutcome(t, f, service, child, request.Request, approved, verifier, authenticationAt(t, f, browser), "")
}

func TestNativeOIDCFreshLoginExpiryAndOriginalRevocationDenyAdoption(t *testing.T) {
	for _, mode := range []string{"expired-flow", "revoked-original-session"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			if mode == "expired-flow" {
				f.oauth.Protocol.ContinuationTTL = time.Second
			}
			service, _, _, _, _ := oidcFixture(t, &f)
			request := pairwiseBegin(f)
			request.Request.Prompt = "login"
			begin, err := service.Authorize(f.ctx, request)
			if err != nil || begin.Outcome != oauth.FreshAuthenticationRequired {
				t.Fatal(err)
			}
			continuation, err := begin.Continuation.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			if mode == "revoked-original-session" {
				f.signOut()
			}
			browser, csrf := f.signInAgain()
			if mode == "expired-flow" {
				waitAuthenticationBoundary(t, f, begin.ExpiresAt)
			}
			out, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: browser, CSRF: csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"})
			if err == nil {
				t.Fatal("genuine new password authentication bypassed original expiry/revocation")
			}
			if _, err := out.Code.Reveal(); err == nil {
				t.Fatal("denied fresh-source adoption revealed code")
			}
			var codes, consumed int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE kind=2),count(*) FILTER(WHERE kind=1 AND state='consumed') FROM oauth_store.artifacts`).Scan(&codes, &consumed); err != nil || codes != 0 || consumed != 0 {
				t.Fatal("denied fresh-source adoption consumed or issued original flow", err)
			}
		})
	}
}

func TestNativeOIDCFreshLoginContentionAdoptsOnlyOneGenuineSession(t *testing.T) {
	f := passwordFixture(t)
	service, child, _, _, _ := oidcFixture(t, &f)
	request := pairwiseBegin(f)
	request.Request.Prompt = "login"
	request.Request.State = "contended-original-state"
	verifier := oauth2.GenerateVerifier()
	request.Request.CodeChallenge = oauth2.S256ChallengeFromVerifier(verifier)
	begin, err := service.Authorize(f.ctx, request)
	if err != nil || begin.Outcome != oauth.FreshAuthenticationRequired {
		t.Fatal(err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	first, firstCSRF := f.signInAgain()
	second, secondCSRF := f.signInAgain()
	requests := []oauth.ContinueRequest{
		{TenantID: f.tenant, Session: first, CSRF: firstCSRF, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"},
		{TenantID: f.tenant, Session: second, CSRF: secondCSRF, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"},
	}
	authenticated := []time.Time{authenticationAt(t, f, first), authenticationAt(t, f, second)}
	type attempt struct {
		index  int
		result oauth.AuthorizeResult
		err    error
	}
	start := make(chan struct{})
	results := make(chan attempt, 2)
	for index, request := range requests {
		go func() {
			<-start
			out, err := service.Continue(f.ctx, request)
			results <- attempt{index: index, result: out, err: err}
		}()
	}
	close(start)
	var winner attempt
	winners := 0
	joined := make([]attempt, 0, len(requests))
	for range requests {
		joined = append(joined, <-results) // Join both bounded calls before assertions/cleanup.
	}
	for _, result := range joined {
		if result.err == nil && result.result.Outcome == oauth.AuthorizationRedirect {
			winners++
			winner = result
		} else if _, err := result.result.Code.Reveal(); err == nil {
			t.Fatal("losing fresh-session contender delivered code")
		}
	}
	if winners != 1 {
		t.Fatal("one original fresh-login continuation did not have exactly one code winner")
	}
	var codes, consumed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE kind=2),count(*) FILTER(WHERE kind=1 AND state='consumed') FROM oauth_store.artifacts`).Scan(&codes, &consumed); err != nil || codes != 1 || consumed != 1 {
		t.Fatal("contended fresh-source adoption/code/consumption were not one atomic transition", err)
	}
	verifyOriginalAuthenticationOutcome(t, f, service, child, request.Request, winner.result, verifier, authenticated[winner.index], "")
}

func TestNativeOIDCPositiveAgeExpiresAfterProtectedGrantWait(t *testing.T) {
	positiveAgeExpiresAfterGrantWait(t, false)
}

func TestNativeOIDCPositiveAgeTerminalAttemptCanCompleteAfterFreshLogin(t *testing.T) {
	positiveAgeExpiresAfterGrantWait(t, true)
}

// This gate only schedules an actual PostgreSQL grant-row wait in Apply,
// after the real preparation-start transaction has committed. No journal,
// session proof, SQL result or timestamp is fabricated by the transport gate.
type authenticationApplyGate struct {
	armed   atomic.Bool
	grants  atomic.Uint32
	reached chan struct{}
	proceed chan struct{}
	done    <-chan struct{}
}

func (gate *authenticationApplyGate) observe(data []byte) {
	// Work deliberately uses direct ExecParams, so a pgx QueryTracer cannot
	// see these protected statements. Reuse the fixture's actual wire seam.
	if gate.armed.Load() && bytes.Contains(data, []byte(`FROM "oauth_store".grants WHERE grant_id=$1`)) && bytes.Contains(data, []byte("FOR UPDATE")) && gate.grants.Add(1) == 2 {
		close(gate.reached)
		select {
		case <-gate.proceed:
		case <-gate.done:
		}
	}
}

func positiveAgeExpiresAfterGrantWait(t *testing.T, afterStart bool, prompt ...string) {
	t.Helper()
	gate := &authenticationApplyGate{reached: make(chan struct{}), proceed: make(chan struct{})}
	f := passwordFixture(t, &oauthCommitFault{beforeWrite: gate.observe})
	gate.done = f.ctx.Done()
	service, child, _, store, _ := oidcFixture(t, &f)
	authenticatedAt := authenticationAt(t, f, f.browser)
	age := uint32(3)
	request := pairwiseBegin(f)
	if len(prompt) != 0 {
		request.Request.Prompt = prompt[0]
	}
	request.Request.MaxAge = &age
	verifier := oauth2.GenerateVerifier()
	request.Request.CodeChallenge = oauth2.S256ChallengeFromVerifier(verifier)
	begin, err := service.Authorize(f.ctx, request)
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("genuine young positive-age control unavailable", err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
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
	lockGrant := func() {
		if _, err := blocker.Exec(f.ctx, `SELECT grant_id FROM oauth_store.grants FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
	}
	if !afterStart {
		lockGrant()
	}
	ctx, cancel := context.WithCancel(f.ctx)
	type outcome struct {
		result oauth.AuthorizeResult
		err    error
	}
	finished := make(chan outcome, 1)
	gate.armed.Store(afterStart)
	var released sync.Once
	release := func() { released.Do(func() { close(gate.proceed) }) }
	defer release()
	go func() {
		result, err := service.Continue(ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"})
		finished <- outcome{result: result, err: err}
	}()
	joined := false
	defer func() {
		cancel()
		release()
		_ = blocker.Rollback(f.ctx)
		if !joined {
			<-finished // Cancellation bounds the native call before fixture cleanup.
		}
	}()
	if afterStart {
		select {
		case <-gate.reached:
		case <-f.ctx.Done():
			t.Fatal("positive-age call did not reach native Apply grant fence")
		case premature := <-finished:
			joined = true
			t.Fatalf("positive-age call returned before native Apply grant fence: grant_queries=%d outcome=%d err=%v", gate.grants.Load(), premature.result.Outcome, premature.err)
		}
		lockGrant()
		release()
	}
	deadline := authenticatedAt.Add(3 * time.Second)
	for {
		var waiting int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, blockerID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("positive-age control did not reach actual protected grant lock before expiry")
		}
		waitAuthenticationBoundary(t, f, time.Now().Add(10*time.Millisecond))
	}
	waitAuthenticationBoundary(t, f, deadline)
	if err := blocker.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	out := <-finished
	joined = true
	if !errors.Is(out.err, oauth.ErrLoginRequired) {
		t.Error("positive maximum age crossing did not retain login_required", out.err)
	}
	if _, err := out.result.Code.Reveal(); err == nil {
		t.Fatal("expired positive-age attempt revealed code")
	}
	var codes, consumed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE kind=2),count(*) FILTER(WHERE kind=1 AND state='consumed') FROM oauth_store.artifacts`).Scan(&codes, &consumed); err != nil || codes != 0 || consumed != 0 {
		t.Fatal("post-wait maximum age failed to fence atomic code/continuation mutation", err)
	}
	metadata, recoveryErr := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.continue", CommandID: out.result.CommandID, ClientID: "public-web", TenantID: f.tenant, Session: f.browser, Token: continuation})
	t.Logf("original age-crossing receipt: not_committed=%t login_required=%t unavailable=%t", metadata.Outcome == identity.CommitOutcomeNotCommitted, errors.Is(recoveryErr, oauth.ErrLoginRequired), errors.Is(recoveryErr, oauth.ErrUnavailable))
	if metadata.Outcome == identity.CommitOutcomeNotCommitted && !errors.Is(recoveryErr, oauth.ErrLoginRequired) {
		t.Error("retained noncommit erased original authentication-required classification", recoveryErr)
	}
	terminal := metadata.Outcome == identity.CommitOutcomeNotCommitted
	if afterStart && !terminal {
		t.Fatal("post-start grant wait did not prove the actual terminal noncommit predecessor", recoveryErr)
	}
	browser, csrf := f.signInAgain()
	authenticatedAt = authenticationAt(t, f, browser)
	approved, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: browser, CSRF: csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"})
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect || approved.ExpiresAt.After(begin.ExpiresAt) {
		t.Fatal("genuine fresh password login could not complete same original continuation after age crossing", err)
	}
	if terminal && (approved.CommandID == "" || approved.CommandID == out.result.CommandID) {
		t.Fatal("fresh completion reopened the immutable terminal predecessor")
	}
	var currentAttempt, consumedBy string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT transition_command,consumed_by FROM oauth_store.artifacts WHERE kind=1`).Scan(&currentAttempt, &consumedBy); err != nil || currentAttempt != string(approved.CommandID) || consumedBy != string(approved.CommandID) {
		t.Fatal("code commitment did not consume the current acknowledged continuation attempt", err)
	}
	if _, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: browser, CSRF: csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("completed post-expiry fresh-login continuation was not one use", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE kind=2),count(*) FILTER(WHERE kind=1 AND state='consumed') FROM oauth_store.artifacts`).Scan(&codes, &consumed); err != nil || codes != 1 || consumed != 1 {
		t.Fatal("post-expiry fresh login did not commit exactly one original code", err)
	}
	reconstructed, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	metadata, recoveryErr = reconstructed.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.continue", CommandID: out.result.CommandID, ClientID: "public-web", TenantID: f.tenant, Session: f.browser, Token: continuation})
	if terminal && (metadata.Outcome != identity.CommitOutcomeNotCommitted || metadata.CommandID != out.result.CommandID || !errors.Is(recoveryErr, oauth.ErrLoginRequired)) {
		t.Fatal("fresh completion rewrote or stranded the original noncommitted attempt", recoveryErr)
	}
	verifyOriginalAuthenticationOutcome(t, f, service, child, request.Request, approved, verifier, authenticatedAt, "")
}

// The decorator delays only a real native known-commit return. It does not
// fabricate persistence, authentication, command identity or a commit outcome.
type delayedAuthenticationReturn struct {
	oauth.Store
	authorize func(context.Context, oauth.AuthorizeResult)
	continued func(context.Context, oauth.AuthorizeResult)
}

func (s delayedAuthenticationReturn) Authorize(ctx context.Context, command oauth.AuthorizationCommand) (oauth.AuthorizeResult, error) {
	out, err := s.Store.Authorize(ctx, command)
	if err == nil && s.authorize != nil {
		s.authorize(ctx, out)
	}
	return out, err
}

func (s delayedAuthenticationReturn) Continue(ctx context.Context, command oauth.ContinuationCommand) (oauth.AuthorizeResult, error) {
	out, err := s.Store.Continue(ctx, command)
	if err == nil && s.continued != nil {
		s.continued(ctx, out)
	}
	return out, err
}

func TestNativeOIDCCommittedLateAuthenticationReturnRetainsRecoverableMetadata(t *testing.T) {
	for _, tc := range []struct{ name, operation, ceiling string }{
		{"authorize", "authorize", "authentication"},
		{"continue", "continue", "authentication"},
		{"continuation-expiry", "authorize", "continuation"},
		{"original-flow-expiry", "continue", "flow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			operation := tc.operation
			f := passwordFixture(t)
			if tc.ceiling != "authentication" {
				f.oauth.Protocol.MaximumDuration = 5 * time.Second
				switch tc.ceiling {
				case "continuation":
					f.oauth.Protocol.ContinuationTTL = time.Second
				case "flow":
					f.oauth.Protocol.ContinuationTTL = 5 * time.Second
					f.oauth.Protocol.CodeTTL = 10 * time.Second
				}
			}
			_, child, _, store, _ := oidcFixture(t, &f)
			authenticatedAt := authenticationAt(t, f, f.browser)
			age := uint32(3)
			deadline := authenticatedAt.Add(3 * time.Second)
			var originalFlowDeadline time.Time
			initialOutcome := oauth.ConsentRequired
			wantError := oauth.ErrLoginRequired
			if tc.ceiling != "authentication" {
				initialOutcome, wantError = oauth.FreshAuthenticationRequired, oauth.ErrUnavailable
			}
			var committedID identity.CommandID
			delay := func(ctx context.Context, out oauth.AuthorizeResult) {
				if out.CommandID == "" || operation == "authorize" && out.Outcome != initialOutcome || operation == "continue" && out.Outcome != oauth.AuthorizationRedirect {
					t.Fatal("decorator did not observe actual native known commitment")
				}
				if tc.ceiling != "authentication" {
					deadline = out.ExpiresAt
					if tc.ceiling == "flow" && !deadline.Equal(originalFlowDeadline) {
						t.Fatal("native code did not retain its distinct original selected deadline")
					}
				}
				var codes, consumed, continuations int
				if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FILTER(WHERE kind=2),count(*) FILTER(WHERE kind=1 AND state='consumed'),count(*) FILTER(WHERE kind=1) FROM oauth_store.artifacts`).Scan(&codes, &consumed, &continuations); err != nil || continuations != 1 || operation == "continue" && (codes != 1 || consumed != 1) || operation == "authorize" && (codes != 0 || consumed != 0) {
					t.Fatal("delay did not follow actual native atomic commitment", err)
				}
				if !time.Now().Before(deadline) {
					t.Fatal("native commitment missed the selected control deadline before return delay")
				}
				committedID = out.CommandID
				timer := time.NewTimer(time.Until(deadline.Add(20 * time.Millisecond)))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal("late-return fixture exceeded original caller budget")
				}
				if ctx.Err() != nil {
					t.Fatal("late-return fixture did not retain a live original caller")
				}
			}
			adapter := delayedAuthenticationReturn{Store: store}
			if operation == "authorize" {
				adapter.authorize = delay
			} else {
				adapter.continued = delay
			}
			core, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: adapter})
			if err != nil {
				t.Fatal(err)
			}
			service, err := core.WithOIDC(child)
			if err != nil {
				t.Fatal(err)
			}
			request := pairwiseBegin(f)
			if tc.ceiling == "authentication" {
				request.Request.MaxAge = &age
			} else {
				request.Request.Prompt = "login"
			}
			out, err := service.Authorize(f.ctx, request)
			continuation := ""
			browser, csrf := f.browser, f.csrf
			if operation == "continue" {
				if err != nil || out.Outcome != initialOutcome {
					t.Fatal("original initial control unavailable", err)
				}
				originalFlowDeadline = out.ExpiresAt
				continuation, err = out.Continuation.Reveal()
				if err != nil {
					t.Fatal(err)
				}
				if tc.ceiling != "authentication" {
					browser, csrf = f.signInAgain()
				}
				out, err = service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: browser, CSRF: csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"})
			}
			if !errors.Is(err, wantError) || out.Outcome != oauth.AuthorizationHistorical || out.CommandID != committedID || out.CommandID == "" || out.RedirectURI != "" || out.State != "" || out.Issuer.String() != "" || !out.ExpiresAt.IsZero() || out.Request.ClientID != "" {
				t.Fatal("post-commit delivery rejection lost historical durability/correlation or disclosed material", err)
			}
			if _, err := out.Code.Reveal(); err == nil {
				t.Fatal("late committed return revealed code")
			}
			if _, err := out.Continuation.Reveal(); err == nil {
				t.Fatal("late committed return revealed continuation")
			}
			reconstructed, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := reconstructed.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server." + operation, CommandID: out.CommandID, ClientID: "public-web", TenantID: f.tenant, Session: browser, Token: continuation})
			if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted || metadata.CommandID != committedID {
				t.Fatal("withheld actual commitment could not recover original historical metadata", err)
			}
			if operation == "continue" {
				if _, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: browser, CSRF: csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrAccessDenied) {
					t.Fatal("withheld committed continuation was replayed as pending/fresh", err)
				}
			}
		})
	}
}
