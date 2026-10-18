//go:build integration && oauthflow

package oauthpostgres_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

func TestNativeConstructorRejectsUnavailableRequiredRiskProvider(t *testing.T) {
	f := passwordFixture(t)
	configured := baselineRiskPolicyConfig(9, false, false)
	for i := range configured.Profiles {
		if configured.Profiles[i].Class == risk.Privileged {
			configured.Profiles[i].RequiredSignals = []string{"velocity", "captcha"}
		}
	}
	policy, err := risk.NewPolicy(configured)
	if err != nil {
		t.Fatal("genuine configured policy rejected provider selection", err)
	}
	counters := *f.oauth.Counters.CommandCounters
	counters.Policy = policy
	f.oauth.Counters.CommandCounters = &counters
	if _, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("velocity-only native profile accepted an unavailable mandatory provider")
	}
}

func TestNativeLostAuthorizationCommitAcknowledgementHasNoMaterial(t *testing.T) {
	fault := &oauthCommitFault{}
	f := passwordFixture(t, fault)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := oauth.S256Challenge(strings.Repeat("a", 43))
	if err != nil {
		t.Fatal(err)
	}
	fault.armed.Store(true)
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", CodeChallenge: challenge, Resource: "https://resource.example", Scopes: []string{"identity:read"}}})
	if !fault.hit.Load() {
		t.Fatal("fault did not intercept the actual final COMMIT acknowledgement")
	}
	if !errors.Is(err, oauth.ErrUnavailable) || begin.Outcome != oauth.AuthorizationUnknown || begin.CommandID == "" {
		t.Fatal("actual lost final COMMIT acknowledgement was not classified unknown")
	}
	if _, err := begin.Continuation.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("unknown commitment exposed continuation material")
	}
	var grant string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT grant_id FROM oauth_store.grants`).Scan(&grant); err != nil {
		t.Fatal("fault did not follow a real committed OAuth mutation", err)
	}
	if grant != string(begin.CommandID) {
		t.Fatal("unknown authorization cannot recover its exact original record from returned correlation")
	}
	request := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.authorize", CommandID: begin.CommandID, ClientID: "public-web", TenantID: f.tenant, Session: f.browser}
	for i := 0; i < 2; i++ {
		recovered, err := store.Recover(f.ctx, request)
		if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.CommandID != begin.CommandID {
			t.Fatal("original authenticated unknown command did not reconcile to metadata", err)
		}
	}
	request.ClientID = "other-public-web"
	if _, err := store.Recover(f.ctx, request); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("foreign configured client recovered original authorization metadata")
	}
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.grants`).Scan(&count); err != nil || count != 1 {
		t.Fatal("recovery duplicated durable authorization", err)
	}
}

func consentedCode(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service) (string, string) {
	t.Helper()
	verifier := strings.Repeat("a", 43)
	challenge, err := oauth.S256Challenge(verifier)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", CodeChallenge: challenge, Resource: "https://resource.example", Scopes: []string{"identity:read"}}})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("real authorization did not require consent", err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	approved, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true, Scopes: []string{"identity:read"}})
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("real consent did not issue code", err)
	}
	location, err := approved.Location()
	if err != nil {
		t.Fatal(err)
	}
	callback, err := url.Parse(location)
	if err != nil || callback.Query().Get("code") == "" {
		t.Fatal("known committed code was not deliverable")
	}
	return callback.Query().Get("code"), verifier
}

func TestNativeLostTokenCommitAcknowledgementRecoversOnlyMetadata(t *testing.T) {
	for _, grantType := range []oauth.GrantType{oauth.AuthorizationCodeGrant, oauth.RefreshTokenGrant} {
		t.Run(string(grantType), func(t *testing.T) {
			fault := &oauthCommitFault{}
			f := passwordFixture(t, fault)
			store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			service, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
			if err != nil {
				t.Fatal(err)
			}
			code, verifier := consentedCode(t, f, service)
			request := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"}
			original := code
			wantArtifacts := 2
			if grantType == oauth.RefreshTokenGrant {
				known, err := service.Token(f.ctx, request)
				if err != nil || known.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("real code exchange failed", err)
				}
				original, err = known.RefreshToken.Reveal()
				if err != nil {
					t.Fatal(err)
				}
				request = oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: original, Network: "192.0.2.1"}
				wantArtifacts = 4
			}
			fault.armed.Store(true)
			lost, err := service.Token(f.ctx, request)
			if !fault.hit.Load() || !errors.Is(err, oauth.ErrUnavailable) || lost.Outcome != identity.CommitOutcomeUnknown || lost.CommandID == "" {
				t.Fatal("real lost token COMMIT acknowledgement was not unknown")
			}
			if _, err := lost.AccessToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
				t.Fatal("unknown token commit exposed access token")
			}
			if _, err := lost.RefreshToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
				t.Fatal("unknown token commit exposed refresh token")
			}
			recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: lost.CommandID, ClientID: "public-web", Token: original}
			for i := 0; i < 2; i++ {
				metadata, err := store.Recover(f.ctx, recovery)
				if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted || metadata.CommandID != lost.CommandID {
					t.Fatal("original protocol bearer could not reconcile committed metadata", err)
				}
			}
			recovery.ClientID = "other-public-web"
			if _, err := store.Recover(f.ctx, recovery); !errors.Is(err, oauth.ErrAccessDenied) {
				t.Fatal("foreign client recovered token command")
			}
			var artifacts int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE kind IN(3,4)`).Scan(&artifacts); err != nil || artifacts != wantArtifacts {
				t.Fatal("recovery regenerated or lost token artifacts", err)
			}
			if _, err := service.Token(f.ctx, request); !errors.Is(err, oauth.ErrInvalidGrant) {
				t.Fatal("retry after unknown commit issued fresh token material")
			}
		})
	}
}

func TestNativeDisconnectBeforeCommitProvesAtomicNoncommitThroughOriginalRecovery(t *testing.T) {
	fault := &oauthCommitFault{before: true}
	f := passwordFixture(t, fault)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := consentedCode(t, f, service)
	fault.armed.Store(true)
	lost, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if !fault.hit.Load() || !errors.Is(err, oauth.ErrUnavailable) || lost.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("pre-COMMIT disconnect was guessed as rollback or exposed material")
	}
	if _, err := lost.AccessToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("uncertain commit exposed token")
	}
	request := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: lost.CommandID, ClientID: "public-web", Token: code}
	metadata, err := store.Recover(f.ctx, request)
	if err != nil || metadata.Outcome != identity.CommitOutcomeInProgress {
		t.Fatal("live original lease was not observational", err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for metadata.Outcome != identity.CommitOutcomeNotCommitted {
		if time.Now().After(deadline) {
			t.Fatal("original native participant evidence could not reconcile noncommit", err)
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-timer.C:
		case <-f.ctx.Done():
			timer.Stop()
			t.Fatal("bounded recovery cancelled")
		}
		metadata, err = store.Recover(f.ctx, request)
		if err != nil && !errors.Is(err, oauth.ErrUnavailable) {
			t.Fatal("recovery returned unexpected classification", err)
		}
	}
	var tokens, effects, successAudits int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE kind IN(3,4)`).Scan(&tokens); err != nil || tokens != 0 {
		t.Fatal("rolled-back issuance left a token artifact", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects`).Scan(&effects); err != nil || effects != 2 {
		t.Fatal("rolled-back issuance left participant effect", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.exchange_code' AND outcome=$1`, int16(audit.OutcomeSucceeded)).Scan(&successAudits); err != nil || successAudits != 0 {
		t.Fatal("rolled-back issuance retained success audit", err)
	}
}

func TestNativeOwningClientRevocationHasNarrowScopeAndRecoverableMetadata(t *testing.T) {
	for _, kind := range []oauth.TokenKind{oauth.TokenAccess, oauth.TokenRefresh} {
		t.Run(map[oauth.TokenKind]string{oauth.TokenAccess: "access", oauth.TokenRefresh: "refresh"}[kind], func(t *testing.T) {
			f := passwordFixture(t)
			store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			service, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
			if err != nil {
				t.Fatal(err)
			}
			code, verifier := consentedCode(t, f, service)
			issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			access, err := issued.AccessToken.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			refresh, err := issued.RefreshToken.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			wire, hint := access, oauth.TokenRefresh // Deliberately wrong advisory hint.
			if kind == oauth.TokenRefresh {
				wire, hint = refresh, oauth.TokenAccess
			}
			revoked, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: "public-web", Token: wire, Hint: hint, Network: "192.0.2.1"})
			if err != nil || revoked.Outcome != identity.CommitOutcomeCommitted || revoked.CommandID == "" {
				t.Fatal("possessed owning-client token was not revoked", err)
			}
			metadata, err := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.revoke", CommandID: revoked.CommandID, ClientID: "public-web", Token: wire})
			if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("own revoked token could not recover historical metadata", err)
			}
			var activeAccess, activeRefresh int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE kind=3),count(*) FILTER(WHERE kind=4) FROM oauth_store.artifacts WHERE state='active'`).Scan(&activeAccess, &activeRefresh); err != nil || activeAccess != 0 {
				t.Fatal("revocation retained its active access artifact", err)
			}
			if kind == oauth.TokenAccess {
				if activeRefresh != 1 {
					t.Fatal("access revocation changed its independent refresh authority")
				}
				rotated, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"})
				if err != nil || rotated.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("narrow access revocation killed the family", err)
				}
			} else {
				if activeRefresh != 0 {
					t.Fatal("refresh revocation retained active descendants")
				}
				if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrInvalidGrant) {
					t.Fatal("revoked refresh remained usable")
				}
			}
		})
	}
}

func TestNativeCredentialReplacementWithdrawsCodeAndRefreshAuthority(t *testing.T) {
	f := passwordFixtureWithChange(t, true)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := consentedCode(t, f, service)
	other, otherVerifier := consentedCode(t, f, service)
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: other, CodeVerifier: otherVerifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	f.changePassword()
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("withdrawn original credential epoch still redeemed code")
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("withdrawn original credential epoch still refreshed tokens")
	}
}

func TestNativeBrowserWithdrawalDeniesPendingConsentWithoutReplacingGrantAuthentication(t *testing.T) {
	f := passwordFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := consentedCode(t, f, service)
	challenge, err := oauth.S256Challenge(verifier)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", CodeChallenge: challenge, Resource: "https://resource.example", Scopes: []string{"identity:read"}}})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal(err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	f.signOut()
	if _, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true}); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("revoked original browser still approved consent")
	}
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("approved OAuth grant was incorrectly replaced with browser authentication", err)
	}
}

// This consumer starts with real signup, registration confirmation and password
// sign-in. It must not seed a Session, credential or user through SQL. The only
// substitutes are the explicit email and HIBP outbound transport seams.
func TestNativePasswordSessionCodeRefreshAndPublicClientRevocation(t *testing.T) {
	f := passwordFixture(t)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal("native OAuth composition rejected", err)
	}
	service, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal("public consumer composition rejected", err)
	}
	verifier := strings.Repeat("a", 43)
	challenge, err := oauth.S256Challenge(verifier)
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", State: "opaque-caller-state", CodeChallenge: challenge, Resource: "https://resource.example", Scopes: []string{"identity:read", "identity:write"}}
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Request: request, Network: "192.0.2.1"})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("genuine password session did not reach consent", err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal("committed consent interaction was not deliverable", err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: request.ClientID, Code: continuation, CodeVerifier: verifier, RedirectURI: request.RedirectURI, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("pending consent continuation acted as an authorization code")
	}
	approved, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: request.ClientID, Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true, Scopes: []string{"identity:read"}})
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("current browser/CSRF consent did not issue code", err)
	}
	metadata, err := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.continue", CommandID: approved.CommandID, ClientID: request.ClientID, TenantID: f.tenant, Session: f.browser, Token: continuation})
	if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original consent could not recover metadata without another issuance", err)
	}
	location, err := approved.Location()
	if err != nil {
		t.Fatal("committed exact callback was not deliverable", err)
	}
	callback, err := url.Parse(location)
	if err != nil || callback.Scheme+"://"+callback.Host+callback.Path != request.RedirectURI || callback.Query().Get("state") != request.State || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() {
		t.Fatal("authorization response escaped its exact original redirect/state/issuer")
	}
	code := callback.Query().Get("code")
	tokenRequest := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: request.ClientID, Code: code, RedirectURI: request.RedirectURI, CodeVerifier: strings.Repeat("b", 43), Network: "192.0.2.1"}
	if _, err := service.Token(f.ctx, tokenRequest); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("incorrect S256 proof authenticated or consumed the code")
	}
	tokenRequest.CodeVerifier = verifier
	issued, err := service.Token(f.ctx, tokenRequest)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted || issued.Replayed || len(issued.Scopes) != 1 || issued.Scopes[0] != "identity:read" {
		t.Fatal("code exchange did not preserve narrowed consent", err)
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal("fresh access token unavailable", err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal("fresh refresh token unavailable", err)
	}
	if _, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: request.ClientID, Token: access}); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("unselected unauthenticated introspection disclosed metadata")
	}
	if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: "other-public-web", Token: refresh, Hint: oauth.TokenRefresh, Network: "192.0.2.1"}); err != nil {
		t.Fatal("foreign token revocation was distinguishable", err)
	}
	rotated, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: request.ClientID, RefreshToken: refresh, Scopes: []string{"identity:read"}, Network: "192.0.2.1"})
	if err != nil || rotated.Outcome != identity.CommitOutcomeCommitted || rotated.Replayed {
		t.Fatal("refresh rotation failed or foreign revocation changed the family", err)
	}
	next, err := rotated.RefreshToken.Reveal()
	if err != nil || next == refresh {
		t.Fatal("refresh rotation retained the consumed bearer")
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: request.ClientID, RefreshToken: refresh, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("consumed refresh token issued material")
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: request.ClientID, RefreshToken: next, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("refresh replay did not revoke its related family")
	}
	var active, consented, audited, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.grants WHERE state='active'`).Scan(&active); err != nil || active != 0 {
		t.Fatal("revoked grant remained active", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.consents`).Scan(&consented); err != nil || consented != 1 {
		t.Fatal("explicit consent was missing or duplicated", err)
	}
	// The complete native effects check below uses the public owners' installed
	// schemas, rather than a fake recorder or an application-written transaction.
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects`).Scan(&events); err != nil || events < 4 {
		t.Fatal("owned transition evidence missing", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM audit.records WHERE action LIKE 'identity.oauth_server.%'`).Scan(&audited); err != nil || audited != events+2 {
		t.Fatal("OAuth security audit did not commit with each transition", err)
	}
	var unbound int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts c LEFT JOIN oauth_store.artifacts p ON p.artifact_id=c.parent_artifact_id AND p.grant_id=c.grant_id LEFT JOIN oauth_store.effects e ON e.command_id=c.issued_by AND e.grant_id=c.grant_id WHERE e.command_id IS NULL OR (c.kind=1 AND c.parent_artifact_id IS NOT NULL) OR (c.kind<>1 AND p.artifact_id IS NULL)`).Scan(&unbound); err != nil || unbound != 0 {
		t.Fatal("durable child lost exact original parent/root/issuance lineage", err)
	}
	for _, event := range []string{"grant.created.v1", "grant.scope_changed.v1", "consent.created.v1", "grant.code_exchanged.v1", "grant.refresh_rotated.v1", "grant.revoked.v1"} {
		var count int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM public.outbox_messages WHERE topic=$1`, event).Scan(&count); err != nil || count != 1 {
			t.Fatal("canonical native lifecycle notification missing or duplicated", event, err)
		}
	}
}
