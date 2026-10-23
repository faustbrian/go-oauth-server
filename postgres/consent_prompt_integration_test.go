//go:build integration && oauthflow

package oauthpostgres_test

import (
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/oauth2"
)

func consentPromptFixture(t *testing.T, f *authenticatedPasswordFixture, pairwise bool) (*oauth.Service, *op.Service, *oauthpostgres.Store) {
	t.Helper()
	if !pairwise {
		return silentOIDCFixture(t, f, time.Minute)
	}
	enableConsentManagement(t, f)
	f.oauth.ConsentReuseTTL = time.Minute
	service, child, _, store, _ := pairwiseFixture(t, f)
	// Pairwise already occupies 7004. Append expiry after the actual installed
	// history, rather than attempting to rename that immutable migration.
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
	base := oauthpostgres.SigningMigrationSource{Base: oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}, Schema: "oauth_store", Version: 7003}
	pairwiseSource := oauthpostgres.PairwiseMigrationSource{Base: base, Schema: "oauth_store", Version: 7004}
	runner, err := migrations.NewRunner(oauthpostgres.ConsentExpiryMigrationSource{Base: pairwiseSource, Schema: "oauth_store", Version: 7005}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("pairwise consent expiry append", err)
	}
	return service, child, store
}

type consentPromptSnapshot struct {
	version, generation      string
	granted, expires         time.Time
	approvals, codes, tokens int
}

func consentPromptState(t *testing.T, f authenticatedPasswordFixture) consentPromptSnapshot {
	t.Helper()
	var out consentPromptSnapshot
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,generation::text,granted_at,expires_at,(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.grant_consent' AND outcome=1),(SELECT count(*) FROM oauth_store.artifacts WHERE kind=2),(SELECT count(*) FROM oauth_store.artifacts WHERE kind IN (3,4)) FROM oauth_store.consents`).Scan(&out.version, &out.generation, &out.granted, &out.expires, &out.approvals, &out.codes, &out.tokens); err != nil {
		t.Fatal("original native consent snapshot", err)
	}
	return out
}

func consentPromptRequest(f authenticatedPasswordFixture, verifier string) oauth.AuthorizeRequest {
	in := silentRequest(f, verifier)
	in.Request.Prompt, in.Request.State, in.Request.Nonce = "consent", "consent-original-state", "consent-original-nonce"
	return in
}

func TestNativeOIDCConsentPromptRequiresFreshApprovalAndIndependentRP(t *testing.T) {
	for _, pairwise := range []bool{false, true} {
		name := "public"
		if pairwise {
			name = "pairwise"
		}
		t.Run(name, func(t *testing.T) {
			f := passwordFixture(t)
			service, child, _ := consentPromptFixture(t, &f, pairwise)
			originalCode, originalVerifier := oidcCode(t, f, service, "original-approved-nonce")
			transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child}
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			ctx := rp.ClientContext(f.ctx, client)
			provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
			if err != nil {
				t.Fatal(err)
			}
			standard := oauth2.Config{ClientID: "public-web", RedirectURL: "https://client.example/callback", Endpoint: provider.Endpoint()}
			standard.Endpoint.AuthStyle = oauth2.AuthStyleInParams
			originalTokens, err := standard.Exchange(ctx, originalCode, oauth2.VerifierOption(originalVerifier))
			if err != nil {
				t.Fatal(err)
			}
			originalWire, ok := originalTokens.Extra("id_token").(string)
			if !ok {
				t.Fatal("original ID token absent")
			}
			originalID, err := consumeIDToken(ctx, provider, originalWire, "original-approved-nonce", "public-web")
			if err != nil {
				t.Fatal(err)
			}
			// Prove the stored approval is actually reusable before asking for
			// consent. Merely testing an account without consent misses the risk.
			control, err := service.Authorize(f.ctx, silentRequest(f, oauth2.GenerateVerifier()))
			if err != nil || control.Outcome != oauth.AuthorizationRedirect {
				t.Fatal("genuine reusable consent control did not issue silent code", err)
			}
			before := consentPromptState(t, f)
			verifier := oauth2.GenerateVerifier()
			request := consentPromptRequest(f, verifier)
			started := time.Now()
			pending, err := service.Authorize(f.ctx, request)
			if err != nil || pending.Outcome != oauth.ConsentRequired || pending.Request.Prompt != "consent" || pending.RedirectURI != "" || pending.Code != (oauth.Token{}) || !pending.ExpiresAt.After(started) || pending.ExpiresAt.After(time.Now().Add(f.oauth.Protocol.ContinuationTTL)) {
				t.Fatal("explicit consent reused approval or changed original request/deadline", err)
			}
			if after := consentPromptState(t, f); after != before {
				t.Fatal("requesting consent renewed approval or issued credentials before interaction")
			}
			continuation, err := pending.Continuation.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			// The same still-valid continuation survives unauthorized submissions.
			continueRequest := oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true}
			for _, mode := range []string{"csrf", "tenant", "client", "origin", "scope", "subject"} {
				invalid := continueRequest
				switch mode {
				case "csrf":
					invalid.CSRF, _ = session.NewCSRFToken()
				case "tenant":
					invalid.TenantID = "foreign"
				case "client":
					invalid.ClientID = "other-public-web"
				case "origin":
					invalid.Origin = "https://foreign.example"
				case "scope":
					invalid.Scopes = []string{"identity:read", "identity:write", "openid"}
				case "subject":
					invalid.Session, invalid.CSRF = f.anotherUser()
				}
				if out, err := service.Continue(f.ctx, invalid); err == nil || out.Code != (oauth.Token{}) || out.Continuation != (oauth.Token{}) {
					t.Fatal("invalid consent continuation issued credentials", mode, err)
				}
			}
			approved, err := service.Continue(f.ctx, continueRequest)
			if err != nil || approved.Outcome != oauth.AuthorizationRedirect || approved.Request.Prompt != "consent" || approved.ExpiresAt.After(pending.ExpiresAt) {
				t.Fatal("genuine explicit consent did not issue bounded code", err)
			}
			location, err := approved.Location()
			if err != nil {
				t.Fatal(err)
			}
			callback, err := url.Parse(location)
			if err != nil || callback.Scheme+"://"+callback.Host+callback.Path != request.Request.RedirectURI || callback.Query().Get("state") != request.Request.State || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() || callback.Query().Get("code") == "" {
				t.Fatal("consent callback lost original bindings")
			}
			if _, err := standard.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(oauth2.GenerateVerifier())); err == nil {
				t.Fatal("wrong S256 verifier exchanged consent code")
			}
			token, err := standard.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(verifier))
			if err != nil {
				t.Fatal("independent RP consent/S256 exchange", err)
			}
			wire, ok := token.Extra("id_token").(string)
			if !ok {
				t.Fatal("consent ID token absent")
			}
			verified, err := consumeIDToken(ctx, provider, wire, request.Request.Nonce, "public-web")
			if err != nil || verified.Subject != originalID.Subject {
				t.Fatal("consent reassigned independently verified subject", err)
			}
			info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
			if err != nil || info.Subject != verified.Subject {
				t.Fatal("consent UserInfo subject mismatch", err)
			}
			if _, err := standard.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(verifier)); err == nil {
				t.Fatal("consent code redeemed twice")
			}
			if out, err := service.Continue(f.ctx, continueRequest); err == nil || out.Code != (oauth.Token{}) {
				t.Fatal("consent approval replay redelivered code", err)
			}
		})
	}
}

func TestNativeOIDCConsentPromptDenialNeverFallsBackToReusableApproval(t *testing.T) {
	f := passwordFixture(t)
	service, _, _ := consentPromptFixture(t, &f, false)
	oidcCode(t, f, service, "consent-denial-prior-approval")
	before := consentPromptState(t, f)
	request := consentPromptRequest(f, oauth2.GenerateVerifier())
	pending, err := service.Authorize(f.ctx, request)
	if err != nil || pending.Outcome != oauth.ConsentRequired {
		t.Fatal("consent denial did not require interaction", err)
	}
	continuation, err := pending.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	deny := oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: false}
	denied, err := service.Continue(f.ctx, deny)
	if err != nil || denied.Outcome != oauth.AuthorizationDenied || denied.Code != (oauth.Token{}) || denied.Continuation != (oauth.Token{}) {
		t.Fatal("consent denial returned code/interaction", err)
	}
	location, err := denied.Location()
	if err != nil {
		t.Fatal(err)
	}
	callback, err := url.Parse(location)
	if err != nil || callback.Query().Get("error") != "access_denied" || callback.Query().Get("code") != "" || callback.Query().Get("state") != request.Request.State || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() {
		t.Fatal("denial callback lost original bindings")
	}
	if after := consentPromptState(t, f); after != before {
		t.Fatal("denial renewed prior consent or created credentials")
	}
	for _, approve := range []bool{false, true} {
		deny.Approve = approve
		if out, err := service.Continue(f.ctx, deny); err == nil || out.Code != (oauth.Token{}) {
			t.Fatal("denied continuation became usable", err)
		}
	}
}

func TestNativeOIDCConsentPromptOriginalContinuationRecovery(t *testing.T) {
	for _, mode := range []string{"rollback", "unknown", "contention", "outbox"} {
		t.Run(mode, func(t *testing.T) {
			fault := &oauthCommitFault{before: mode == "rollback"}
			f := passwordFixture(t, fault)
			service, _, _ := consentPromptFixture(t, &f, false)
			oidcCode(t, f, service, "consent-recovery-prior")
			before := consentPromptState(t, f)
			pending, err := service.Authorize(f.ctx, consentPromptRequest(f, oauth2.GenerateVerifier()))
			if err != nil || pending.Outcome != oauth.ConsentRequired {
				t.Fatal("consent recovery interaction", err)
			}
			wire, err := pending.Continuation.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			request := oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: wire, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true}
			if mode == "contention" {
				type result struct {
					out oauth.AuthorizeResult
					err error
				}
				results := make(chan result, 2)
				var workers sync.WaitGroup
				for range 2 {
					workers.Add(1)
					go func() {
						defer workers.Done()
						out, err := service.Continue(f.ctx, request)
						results <- result{out, err}
					}()
				}
				workers.Wait()
				fresh := 0
				for range 2 {
					result := <-results
					out, err := result.out, result.err
					if out.Code != (oauth.Token{}) {
						if _, err := out.Code.Reveal(); err == nil {
							fresh++
						}
					}
					if err != nil && !errorsIsDenied(err) {
						t.Fatal("consent contention result", err)
					}
				}
				if fresh != 1 {
					t.Fatal("consent contention did not reveal exactly one code", fresh)
				}
			} else if mode == "outbox" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_consent CHECK(topic<>'consent.reconfirmed.v1') NOT VALID`); err != nil {
					t.Fatal(err)
				}
				out, err := service.Continue(f.ctx, request)
				if err == nil || out.Code != (oauth.Token{}) || out.Continuation != (oauth.Token{}) || out.RedirectURI != "" {
					t.Fatal("required consent notification failure disclosed credentials", err)
				}
			} else {
				fault.armed.Store(true)
				out, err := service.Continue(f.ctx, request)
				if !fault.hit.Load() || err == nil || out.Outcome != oauth.AuthorizationUnknown || out.CommandID == "" || out.Code != (oauth.Token{}) || out.Continuation != (oauth.Token{}) || out.RedirectURI != "" {
					t.Fatal("consent actual COMMIT uncertainty exposed material", err)
				}
				restarted, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.continue", CommandID: out.CommandID, ClientID: "public-web", TenantID: f.tenant, Session: f.browser, Token: wire}
				recovered, err := restarted.Recover(f.ctx, recovery)
				want := identity.CommitOutcomeCommitted
				if mode == "rollback" {
					want = identity.CommitOutcomeNotCommitted
					if err != nil || recovered.Outcome != identity.CommitOutcomeInProgress {
						t.Fatal("live original consent preparation not observational", err)
					}
				}
				deadline := time.Now().Add(8 * time.Second)
				for recovered.Outcome != want {
					if time.Now().After(deadline) {
						t.Fatal("original consent recovery did not reconcile", err)
					}
					waitAuthenticationBoundary(t, f, time.Now().Add(100*time.Millisecond))
					recovered, err = restarted.Recover(f.ctx, recovery)
					if err != nil && !errors.Is(err, oauth.ErrUnavailable) {
						t.Fatal("original consent recovery rejected", err)
					}
				}
				if err != nil && !(mode == "rollback" && errors.Is(err, oauth.ErrUnavailable)) || recovered.CommandID != out.CommandID {
					t.Fatal("original consent recovery lost native outcome", err)
				}
			}
			after := consentPromptState(t, f)
			rollback := mode == "rollback" || mode == "outbox"
			if rollback && after != before || !rollback && (after.codes != before.codes+1 || after.approvals != before.approvals+1 || after.tokens != before.tokens) {
				t.Fatal("consent transaction effects were not atomic", before, after)
			}
		})
	}
}

func TestNativeOIDCConsentPromptStillRequiresCurrentOrFreshAuthentication(t *testing.T) {
	for _, mode := range []string{"no-prior-consent", "live-age", "zero-age", "expired-age", "logout"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			var service *oauth.Service
			var child *op.Service
			if mode == "no-prior-consent" {
				// Explicit consent does not make the optional silent-expiry or
				// consent-management installation a mandatory base prerequisite.
				service, child, _, _, _ = oidcFixture(t, &f)
			} else {
				service, child, _ = consentPromptFixture(t, &f, false)
			}
			if mode != "no-prior-consent" {
				oidcCode(t, f, service, "consent-authentication-prior")
			}
			authenticatedAt := authenticationAt(t, f, f.browser)
			verifier := oauth2.GenerateVerifier()
			request := consentPromptRequest(f, verifier)
			want := oauth.ConsentRequired
			if mode == "live-age" || mode == "zero-age" || mode == "expired-age" {
				age := uint32(300)
				if mode == "zero-age" {
					age, want = 0, oauth.FreshAuthenticationRequired
				}
				if mode == "expired-age" {
					age, want = 2, oauth.FreshAuthenticationRequired
					waitAuthenticationBoundary(t, f, authenticatedAt.Add(2*time.Second))
				}
				request.Request.MaxAge = &age
			}
			pending, err := service.Authorize(f.ctx, request)
			if err != nil || pending.Outcome != want || pending.Code != (oauth.Token{}) || pending.RedirectURI != "" {
				t.Fatal("consent replaced explicit approval or original authentication policy", err)
			}
			wire, err := pending.Continuation.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			completion := oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: wire, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true}
			if mode == "logout" {
				f.signOut()
				if out, err := service.Continue(f.ctx, completion); err == nil || out.Code != (oauth.Token{}) || out.Continuation != (oauth.Token{}) {
					t.Fatal("withdrawn original session approved consent", err)
				}
				return
			}
			if want == oauth.FreshAuthenticationRequired {
				if out, err := service.Continue(f.ctx, completion); !errors.Is(err, oauth.ErrLoginRequired) || out.Code != (oauth.Token{}) {
					t.Fatal("consent accepted stale original authentication", err)
				}
				completion.Session, completion.CSRF = f.signInAgain()
				authenticatedAt = authenticationAt(t, f, completion.Session)
			}
			approved, err := service.Continue(f.ctx, completion)
			if err != nil || approved.Outcome != oauth.AuthorizationRedirect || approved.ExpiresAt.After(pending.ExpiresAt) {
				t.Fatal("genuine explicit consent failed after required authentication", err)
			}
			verifyOriginalAuthenticationOutcome(t, f, service, child, request.Request, approved, verifier, authenticatedAt, "")
		})
	}
}

func errorsIsDenied(err error) bool {
	return errors.Is(err, oauth.ErrAccessDenied) || errors.Is(err, oauth.ErrInvalidGrant)
}

func TestNativeOIDCConsentPromptOriginalAgeSurvivesProtectedGrantWait(t *testing.T) {
	positiveAgeExpiresAfterGrantWait(t, false, "consent")
}
