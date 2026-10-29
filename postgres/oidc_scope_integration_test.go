//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

// This hook preserves the real native reservation and only controls a physical
// key-row lock so the final commit fence must wait across the signed deadline.
type signingReservationHook struct {
	oauth.SigningLifecycle
	after func(context.Context, string, time.Time) error
}

func (h signingReservationHook) ReserveSigningKey(ctx context.Context, kid string, expiry time.Time) error {
	if err := h.SigningLifecycle.ReserveSigningKey(ctx, kid, expiry); err != nil {
		return err
	}
	return h.after(ctx, kid, expiry)
}

func TestNativeOIDCSignedDeadlineCrossingKeyWaitRollsBack(t *testing.T) {
	f := passwordFixture(t)
	type heldKey struct {
		tx     pgx.Tx
		expiry time.Time
	}
	held := make(chan heldKey, 1)
	service, _, _, _, _ := oidcFixtureWithLifecycle(t, &f, clock.System{}, func(native oauth.SigningLifecycle) oauth.SigningLifecycle {
		return signingReservationHook{SigningLifecycle: native, after: func(ctx context.Context, kid string, expiry time.Time) error {
			tx, err := f.pool.Raw().Begin(ctx)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT kid FROM oauth_store.signing_keys WHERE kid=$1 FOR UPDATE`, kid); err != nil {
				_ = tx.Rollback(ctx)
				return err
			}
			held <- heldKey{tx: tx, expiry: expiry}
			return nil
		}}
	})
	code, proof := oidcCode(t, f, service, "crossing-signed-deadline")
	ceiling := time.Now().UTC().Add(2 * time.Second).Truncate(time.Second).Add(900 * time.Millisecond)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.grants SET expires_at=$1`, ceiling); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	type result struct {
		out oauth.TokenResult
		err error
	}
	results := make(chan result, 1)
	go func() {
		defer close(done)
		out, err := service.Token(ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: proof, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
		results <- result{out, err}
	}()
	defer func() { cancel(); <-done }()
	var lock heldKey
	select {
	case lock = <-held:
	case <-done:
		t.Fatal("issuance did not reach real signing reservation")
	case <-f.ctx.Done():
		t.Fatal("reservation timed out")
	}
	defer lock.tx.Rollback(f.ctx)
	deadline := time.Now().Add(time.Second)
	for {
		var waiting bool
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT state FROM %signing_keys%FOR SHARE%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("final native signing-key fence did not block")
		}
		time.Sleep(time.Millisecond)
	}
	// Exact deadline crossing, not an arbitrary delay: the precise native
	// ceiling remains future for another 800ms after the signed second expires.
	timer := time.NewTimer(time.Until(ceiling.Truncate(time.Second).Add(100 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal("deadline wait canceled")
	}
	var observed time.Time
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT clock_timestamp()`).Scan(&observed); err != nil || !observed.Before(ceiling) || observed.Before(ceiling.Truncate(time.Second)) {
		t.Fatal("test did not cross only signed deadline", err)
	}
	if err := lock.tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	got := <-results
	if got.err == nil || got.out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("code committed after signed expiry while precise native deadline remained future", got.err)
	}
	if _, err := got.out.IDToken.Reveal(); err == nil {
		t.Fatal("expired ID token delivered")
	}
	var state string
	var descendants int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state FROM oauth_store.artifacts WHERE kind=2`).Scan(&state); err != nil || state != "active" {
		t.Fatal("expired signing wait consumed code", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE kind IN(3,4)`).Scan(&descendants); err != nil || descendants != 0 {
		t.Fatal("expired signing wait committed descendants", err)
	}
}

func TestNativeOIDCRefreshRequiresComposedExtensionBeforeConsumption(t *testing.T) {
	f := passwordFixture(t)
	service, child, _, store, _ := oidcFixture(t, &f)
	original, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	code, proof := oidcCode(t, f, service, "refresh-composition")
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: proof, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	r := oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"}
	for _, scopes := range [][]string{nil, {"identity:read", "openid"}} {
		r.Scopes = scopes
		out, err := original.Token(f.ctx, r)
		if !errors.Is(err, oauth.ErrAccessDenied) || out.CommandID != "" {
			t.Fatal("uncomposed service consumed identity refresh", err)
		}
		out, err = store.Token(f.ctx, oauth.TokenCommand{Client: f.oauth.Protocol.Clients[0], Request: r})
		if !errors.Is(err, oauth.ErrAccessDenied) || out.CommandID != "" {
			t.Fatal("direct native identity refresh bypassed extension", err)
		}
	}
	r.Scopes = nil
	rotated, err := service.Token(f.ctx, r)
	if err != nil {
		t.Fatal("denial consumed original refresh", err)
	}
	access, _ := rotated.AccessToken.Reveal()
	if info, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}); err != nil || info.Subject == "" {
		t.Fatal("composed refresh lost original identity authority", err)
	}
	r.RefreshToken, err = rotated.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	r.Scopes = []string{"identity:read"}
	narrowed, err := original.Token(f.ctx, r)
	if err != nil {
		t.Fatal("OAuth-only narrowing rejected", err)
	}
	access, _ = narrowed.AccessToken.Reveal()
	if info, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}); err == nil || info.Subject != "" {
		t.Fatal("resource-only refresh retained UserInfo")
	}
}

func TestNativeOIDCNonceIngressIsBoundedBeforeEncoding(t *testing.T) {
	f := passwordFixture(t)
	_, _, _, store, _ := oidcFixture(t, &f)
	token, err := session.ParseToken(f.browser.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil {
		t.Fatal(err)
	}
	c := oauth.AuthorizationCommand{Client: f.oauth.Protocol.Clients[0], Browser: f.browser, Session: observed, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", Resource: "https://resource.example", Scopes: []string{"openid"}, CodeChallenge: oauth2.S256ChallengeFromVerifier(oauth2.GenerateVerifier())}}
	for _, nonce := range []string{strings.Repeat("%", 257), strings.Repeat("a", 1<<20), "bad\nnonce", "bad\x7fnonce", "bad\u0080nonce"} {
		c.Request.Nonce = nonce
		if out, err := store.Authorize(f.ctx, c); !errors.Is(err, oauth.ErrInvalidRequest) || out.CommandID != "" {
			t.Fatal("native nonce was not rejected at ingress", err)
		}
	}
	c.Request.Nonce = strings.Repeat("%", 256)
	if out, err := store.Authorize(f.ctx, c); err != nil || out.Outcome != oauth.ConsentRequired || out.Request.Nonce != c.Request.Nonce {
		t.Fatal("valid escaped nonce boundary rejected or changed", err)
	}
}

type oidcTestClock struct{ now time.Time }

func (c *oidcTestClock) Now() time.Time {
	if c.now.IsZero() {
		return time.Now().UTC()
	}
	return c.now
}

func TestNativeOIDCNumericDateExpiryDenialDoesNotConsumeCode(t *testing.T) {
	f := passwordFixture(t)
	// Native expiry is second+.900; child time second+.500 leaves 400ms
	// real lifetime, but no future whole-second NumericDate under that ceiling.
	childClock := &oidcTestClock{}
	service, _, _, _, _ := oidcFixtureWithClock(t, &f, childClock)
	code, proof := oidcCode(t, f, service, "subsecond-expiry")
	expiry := time.Now().UTC().Add(3 * time.Second).Truncate(time.Second).Add(900 * time.Millisecond)
	// A short, still-current native grant ceiling is authoritative even when
	// less than the configured access TTL remains.
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.grants SET expires_at=$1`, expiry); err != nil {
		t.Fatal(err)
	}
	childClock.now = expiry.Add(-400 * time.Millisecond)
	r := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: proof, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"}
	if out, err := service.Token(f.ctx, r); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("unrepresentable future JWT expiry consumed code", err)
	}
	var state string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state FROM oauth_store.artifacts WHERE kind=2`).Scan(&state); err != nil || state != "active" {
		t.Fatal("expiry denial spent code", err)
	}
	// A started native command is never a fresh issuance instruction on retry,
	// even if a caller later changes its clock. Preserve that recovery contract.
	retried, _ := service.Token(f.ctx, r)
	if _, err := retried.AccessToken.Reveal(); err == nil {
		t.Fatal("failed native preparation minted fresh access on retry")
	}
	if _, err := retried.IDToken.Reveal(); err == nil {
		t.Fatal("failed native preparation minted fresh ID token on retry")
	}
	childClock.now = time.Time{}
	code, proof = oidcCode(t, f, service, "representable-expiry-control")
	r.Code, r.CodeVerifier = code, proof
	if out, err := service.Token(f.ctx, r); err != nil {
		t.Fatal("representable expiry control failed", err)
	} else if _, err := out.IDToken.Reveal(); err != nil {
		t.Fatal("representable expiry omitted ID token", err)
	}
}

func TestNativeOIDCConsentNarrowingNeverIssuesIdentityAuthority(t *testing.T) {
	f := passwordFixture(t)
	service, child, _, _, _ := oidcFixture(t, &f)
	verifier := oauth2.GenerateVerifier()
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", Resource: "https://resource.example", Scopes: []string{"identity:read", "openid"}, Nonce: "narrowed-nonce", CodeChallenge: oauth2.S256ChallengeFromVerifier(verifier)}})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("original OIDC request did not reach consent", err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	approved, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true, Scopes: []string{"identity:read"}})
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("narrowed consent did not produce code", err)
	}
	code, err := approved.Code.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := out.IDToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("withdrawn openid scope issued ID token")
	}
	access, err := out.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if info, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}); err == nil || info.Subject != "" {
		t.Fatal("withdrawn openid scope retained UserInfo")
	}
}

func TestNativeOIDCClaimsOnlyNarrowingDoesNotConsumeDirectOwner(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, claim := range []string{"email", "profile", "phone"} {
			t.Run(map[bool]string{false: "static", true: "managed"}[managed]+"/"+claim, func(t *testing.T) {
				f := profilePasswordFixture(t, false)
				signer, key := managedClaimsFixture(t, &f, false)
				selectManagedClaims(&f)
				client := f.oauth.Protocol.Clients[0]
				if !managed {
					client.Scopes = []string{"identity:read", "openid", "email", "profile", "phone"}
					f.oauth.Protocol.Clients[0] = client
				}
				service, child, store := managedClaimsServices(t, f, signer, key)
				if managed {
					client = createManagedClaimsClient(t, f, service, "scope-complete-"+claim)
				}
				proof := oauth2.GenerateVerifier()
				pending, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: client.ID, RedirectURI: client.Redirects[0], Resource: client.Resource, Scopes: []string{"openid", claim}, Nonce: "complete-scope-" + claim, CodeChallenge: oauth2.S256ChallengeFromVerifier(proof)}})
				if err != nil || pending.Outcome != oauth.ConsentRequired {
					t.Fatal("scope completeness did not reach real consent owner", err)
				}
				continuation, _ := pending.Continuation.Reveal()
				request := oauth.ContinueRequest{TenantID: f.tenant, ClientID: client.ID, Session: f.browser, CSRF: f.csrf, Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true, Scopes: []string{claim}}
				observed := originalClientRead(t, f).Session
				id, artifacts, effects := originalScopeArtifact(t, f, client, oauth.TokenContinuation)
				denied, err := store.Continue(f.ctx, oauth.ContinuationCommand{Request: request, Client: client, Session: observed, OIDC: child.ValidateAuthorization})
				if !errors.Is(err, oauth.ErrInvalidScope) || denied.CommandID != "" || denied.Code != (oauth.Token{}) {
					t.Fatal("direct native claim-only consent reached consuming work", err)
				}
				assertScopeArtifactUnconsumed(t, f, id, artifacts, effects)
				request.Scopes = []string{"openid", claim}
				approved, err := service.Continue(f.ctx, request)
				if err != nil || approved.Outcome != oauth.AuthorizationRedirect {
					t.Fatal("claim-only denial stranded original continuation", err)
				}
				code, _ := approved.Code.Reveal()
				issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: code, CodeVerifier: proof, RedirectURI: client.Redirects[0], Network: "192.0.2.1"})
				if err != nil {
					t.Fatal("valid original continuation did not yield usable code", err)
				}
				refresh, _ := issued.RefreshToken.Reveal()
				id, artifacts, effects = originalScopeArtifact(t, f, client, oauth.TokenRefresh)
				refreshRequest := oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: refresh, Scopes: []string{claim}, Network: "192.0.2.1"}
				bad, err := store.Token(f.ctx, oauth.TokenCommand{Request: refreshRequest, Client: client, OIDC: child.Claims})
				if !errors.Is(err, oauth.ErrInvalidScope) || bad.CommandID != "" || bad.AccessToken != (oauth.Token{}) || bad.RefreshToken != (oauth.Token{}) {
					t.Fatal("direct native claim-only refresh reached consuming work", err)
				}
				assertScopeArtifactUnconsumed(t, f, id, artifacts, effects)
				refreshRequest.Scopes = []string{"openid", claim}
				rotated, err := service.Token(f.ctx, refreshRequest)
				if err != nil {
					t.Fatal("claim-only denial consumed original refresh", err)
				}
				access, _ := rotated.AccessToken.Reveal()
				if info, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: client.ID, AccessToken: access}); err != nil || info.Subject == "" {
					t.Fatal("valid same-source complete narrowing lost usable UserInfo", err)
				}
			})
		}
	}
}

func TestNativeOIDCInheritedClaimsOnlyContinuationDoesNotConsumeDirectOwner(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, claim := range []string{"email", "profile", "phone"} {
			t.Run(map[bool]string{false: "static", true: "managed"}[managed]+"/"+claim, func(t *testing.T) {
				f := profilePasswordFixture(t, false)
				signer, key := managedClaimsFixture(t, &f, false)
				selectManagedClaims(&f)
				client := f.oauth.Protocol.Clients[0]
				if !managed {
					client.Scopes = []string{"identity:read", "openid", "email", "profile", "phone"}
					f.oauth.Protocol.Clients[0] = client
				}
				service, child, store := managedClaimsServices(t, f, signer, key)
				if managed {
					client = createManagedClaimsClient(t, f, service, "inherited-scope-"+claim)
				}
				observed := originalClientRead(t, f).Session
				pending, err := store.Authorize(f.ctx, oauth.AuthorizationCommand{Client: client, Browser: f.browser, Session: observed, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: client.ID, RedirectURI: client.Redirects[0], Resource: client.Resource, Scopes: []string{claim}, CodeChallenge: oauth2.S256ChallengeFromVerifier(oauth2.GenerateVerifier())}})
				if err != nil || pending.Outcome != oauth.ConsentRequired || !slices.Equal(pending.Request.Scopes, []string{claim}) {
					t.Fatal("direct owner did not create genuine claim-only continuation", err)
				}
				continuation, err := pending.Continuation.Reveal()
				if err != nil {
					t.Fatal(err)
				}
				id, artifacts, effects := originalScopeArtifact(t, f, client, oauth.TokenContinuation)
				request := oauth.ContinueRequest{TenantID: f.tenant, ClientID: client.ID, Session: f.browser, CSRF: f.csrf, Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true}
				denied, err := store.Continue(f.ctx, oauth.ContinuationCommand{Request: request, Client: client, Session: observed, OIDC: child.ValidateAuthorization})
				if !errors.Is(err, oauth.ErrInvalidScope) || denied.CommandID != "" || denied.Code != (oauth.Token{}) {
					t.Fatal("inherited claim-only scopes reached native consuming work", err)
				}
				assertScopeArtifactUnconsumed(t, f, id, artifacts, effects)
			})
		}
	}
}

func originalScopeArtifact(t *testing.T, f authenticatedPasswordFixture, client oauth.Client, kind oauth.TokenKind) (string, int, int) {
	t.Helper()
	var id string
	var artifacts, effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT artifact_id,(SELECT count(*) FROM oauth_store.artifacts),(SELECT count(*) FROM oauth_store.effects) FROM oauth_store.artifacts WHERE client_id=$1 AND kind=$2 AND state='active'`, client.ID, int16(kind)).Scan(&id, &artifacts, &effects); err != nil {
		t.Fatal("original scope-bearing native custody unavailable", err)
	}
	return id, artifacts, effects
}

func assertScopeArtifactUnconsumed(t *testing.T, f authenticatedPasswordFixture, id string, artifacts, effects int) {
	t.Helper()
	var state string
	var actualArtifacts, actualEffects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state,(SELECT count(*) FROM oauth_store.artifacts),(SELECT count(*) FROM oauth_store.effects) FROM oauth_store.artifacts WHERE artifact_id=$1`, id).Scan(&state, &actualArtifacts, &actualEffects); err != nil || state != "active" || actualArtifacts != artifacts || actualEffects != effects {
		t.Fatal("invalid scope selection consumed custody or created native effects", err)
	}
}
