//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/oauth2"
)

func installLogoutSessionHistory(t *testing.T, f authenticatedPasswordFixture) {
	t.Helper()
	// Genuine Reference sign-in/signout composition already installed the
	// single-session history. Append only its new owner's forward suffix.
	next, err := (sessionpg.OIDCEndSessionMigrationSource{Schema: "session_store", Version: 1418}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("identity_oauth_end_session")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(fixtureHistory(next), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(f.ctx); err != nil {
		t.Fatal("session-owned end-session suffix", err)
	}
}

func logoutSession(t *testing.T, f authenticatedPasswordFixture, browser auth.BearerCredential) session.GetResult {
	t.Helper()
	token, err := session.ParseToken(browser.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil {
		t.Fatal("native primary session observation", err)
	}
	return got
}

func TestNativeOIDCEndSessionExactSourceAndIndependentRP(t *testing.T) {
	f := passwordFixture(t)
	installLogoutSessionHistory(t, f)
	enableConsentManagement(t, &f)
	f.oauth.ConsentReuseTTL = time.Minute
	f.oauth.RPInitiatedLogout = true
	f.oauth.Protocol.Clients[0].PostLogoutRedirects = []string{"https://client.example/signed-out?view=original"}
	service, child, signer, _, _ := oidcFixture(t, &f)
	transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ctx := rp.ClientContext(f.ctx, client)
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal("independent discovery", err)
	}
	var metadata struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if provider.Claims(&metadata) != nil || metadata.EndSessionEndpoint != f.oauth.Protocol.Issuer.String()+"/oauth2/logout" {
		t.Fatal("selected logout endpoint unavailable to independent RP")
	}
	code, verifier := oidcCode(t, f, service, "logout-source-nonce")
	tokens, err := service.Token(f.ctx, oauth.TokenRequest{ClientID: "public-web", GrantType: "authorization_code", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Resource: f.oauth.Protocol.Resource, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := tokens.IDToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := consumeIDToken(ctx, provider, wire, "logout-source-nonce", "public-web")
	if err != nil || verified.Subject == "" {
		t.Fatal("independent RP hint verification", err)
	}
	access, _ := tokens.AccessToken.Reveal()
	refresh, _ := tokens.RefreshToken.Reveal()
	original := logoutSession(t, f, f.browser)
	if original.ValidateAt(time.Now()) != nil {
		t.Fatal("source session missing")
	}
	outstandingVerifier := oauth2.GenerateVerifier()
	outstanding, err := service.Authorize(f.ctx, silentRequest(f, outstandingVerifier))
	if err != nil || outstanding.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("source approval was not genuinely reusable before logout", err)
	}
	outstandingCode, err := outstanding.Code.Reveal()
	if err != nil {
		t.Fatal("pre-logout outstanding code absent", err)
	}
	resource, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, resourcePolicy(f, f.oauth.Protocol.Clients[0]))
	if err != nil {
		t.Fatal("native resource verifier composition", err)
	}
	principal, err := resource.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"})
	if err != nil || principal.Subject() == "" || principal.RequireScope("identity:read") != nil {
		t.Fatal("genuine pre-logout resource authority unavailable", err)
	}
	sibling, siblingCSRF := f.signInAgain()
	if logoutSession(t, f, sibling).ValidateAt(time.Now()) != nil {
		t.Fatal("genuine sibling session missing")
	}
	parameters := url.Values{"id_token_hint": {wire}, "client_id": {"public-web"}, "post_logout_redirect_uri": {"https://client.example/signed-out?view=original"}, "state": {"original +/%?=&"}}
	parsed, err := op.ParseEndSessionQuery(parameters.Encode())
	if err != nil {
		t.Fatal(err)
	}
	request := op.EndSessionRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Parameters: parsed}
	// Cryptographic validity is not durable issuance. Even the actual provider
	// signer cannot turn an unissued digest into authority over this session.
	packet, err := signer.VerifyCompact(f.ctx, wire)
	if err != nil {
		t.Fatal(err)
	}
	var unissuedClaims map[string]any
	if json.Unmarshal(packet.Payload(), &unissuedClaims) != nil {
		t.Fatal("issued hint payload")
	}
	unissuedClaims["nonce"] = "signed-but-never-issued"
	unissuedPayload, _ := json.Marshal(unissuedClaims)
	unissuedToken, _, err := signer.SignCompact(f.ctx, unissuedPayload, time.Unix(int64(unissuedClaims["exp"].(float64)), 0))
	if err != nil {
		t.Fatal("negative signed hint control", err)
	}
	unissuedWire, _ := unissuedToken.Reveal()
	unissuedRequest := request
	unissuedRequest.Parameters.IDTokenHint = unissuedWire
	if out, err := child.EndSession(f.ctx, unissuedRequest); err == nil || out.RedirectURI != "" || out.DeleteCookie != nil {
		t.Fatal("signed but unissued hint authorized logout", err)
	}
	foreign := request
	foreign.Session = sibling
	foreign.CSRF = siblingCSRF
	if denied, err := child.EndSession(f.ctx, foreign); err == nil || denied.RedirectURI != "" || denied.DeleteCookie != nil {
		t.Fatal("hint A terminated same-user/client sibling B", err)
	}
	if logoutSession(t, f, f.browser).ValidateAt(time.Now()) != nil || logoutSession(t, f, sibling).ValidateAt(time.Now()) != nil {
		t.Fatal("mismatched source changed live sessions")
	}
	beforeDenied := nativeLogoutState(t, f)
	for _, mode := range []string{"authorization-callback", "different-query", "encoded-path", "wrong-client", "wrong-tenant", "wrong-csrf", "wrong-signature"} {
		invalid := request
		switch mode {
		case "authorization-callback":
			invalid.Parameters.PostLogoutRedirectURI = "https://client.example/callback"
		case "different-query":
			invalid.Parameters.PostLogoutRedirectURI += "&extra=1"
		case "encoded-path":
			invalid.Parameters.PostLogoutRedirectURI = "https://client.example/%73igned-out?view=original"
		case "wrong-client":
			invalid.Parameters.ClientID = "other-public-web"
		case "wrong-tenant":
			invalid.TenantID = "foreign-tenant"
		case "wrong-csrf":
			invalid.CSRF, _ = session.NewCSRFToken()
		case "wrong-signature":
			parts := strings.Split(wire, ".")
			first := "A"
			if strings.HasPrefix(parts[2], first) {
				first = "B"
			}
			parts[2] = first + parts[2][1:]
			invalid.Parameters.IDTokenHint = strings.Join(parts, ".")
		}
		if denied, err := child.EndSession(f.ctx, invalid); err == nil || denied.RedirectURI != "" || denied.State != "" || denied.DeleteCookie != nil {
			t.Fatal("invalid logout binding disclosed success", mode, err)
		}
		if nativeLogoutState(t, f) != beforeDenied {
			t.Fatal("denied logout changed protected effects", mode)
		}
	}
	out, err := child.EndSession(f.ctx, request)
	if err != nil || out.Outcome != oauth.EndSessionRedirect || out.RedirectURI != parsed.PostLogoutRedirectURI || out.State != parsed.State || out.Completion.Outcome != identity.CommitOutcomeCommitted || out.DeleteCookie == nil || out.DeleteCookie.MaxAge != -1 || out.DeleteCookie.Name != "__Host-session" || out.DeleteCookie.Path != "/" || out.DeleteCookie.Domain != "" || !out.DeleteCookie.Secure || !out.DeleteCookie.HttpOnly || out.DeleteCookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("genuine exact-session logout did not commit exact RP outcome", err)
	}
	if logoutSession(t, f, f.browser).Authenticated || logoutSession(t, f, sibling).ValidateAt(time.Now()) != nil {
		t.Fatal("logout failed exact session/sibling isolation")
	}
	if info, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}); err == nil || info.Subject != "" {
		t.Fatal("explicit logout did not withdraw source UserInfo authority", err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{ClientID: "public-web", GrantType: "refresh_token", RefreshToken: refresh, Resource: f.oauth.Protocol.Resource, Network: "192.0.2.1"}); err == nil {
		t.Fatal("explicit logout left source refresh usable")
	}
	if redeemed, err := service.Token(f.ctx, oauth.TokenRequest{ClientID: "public-web", GrantType: "authorization_code", Code: outstandingCode, CodeVerifier: outstandingVerifier, RedirectURI: "https://client.example/callback", Resource: f.oauth.Protocol.Resource, Network: "192.0.2.1"}); err == nil || redeemed.AccessToken != (oauth.Token{}) || redeemed.RefreshToken != (oauth.Token{}) || redeemed.IDToken != (oauth.IDToken{}) {
		t.Fatal("explicit logout left pre-existing source code redeemable", err)
	}
	requireInvalidResource(t, resource, f.ctx, access)
	denied, err := service.Authorize(f.ctx, silentRequest(f, oauth2.GenerateVerifier()))
	if err != nil || denied.Outcome != oauth.AuthorizationProtocolError || denied.ProtocolError != oauth.AuthorizationLoginRequiredError || denied.Code != (oauth.Token{}) || denied.Continuation != (oauth.Token{}) || !denied.ExpiresAt.IsZero() {
		t.Fatal("explicit logout left source silent authorization usable", err)
	}
	denialLocation, err := denied.Location()
	if err != nil {
		t.Fatal("silent denial lost validated callback", err)
	}
	denialCallback, err := url.Parse(denialLocation)
	if err != nil || denialCallback.Query().Get("error") != "login_required" || denialCallback.Query().Has("code") {
		t.Fatal("silent callback disclosed successful authorization", err)
	}
	// The sibling must still complete a real OAuth journey, not merely retain
	// a live session row while a subject-wide grant fence blocks its consumers.
	siblingFixture := f
	siblingFixture.browser, siblingFixture.csrf = sibling, siblingCSRF
	siblingCode, siblingVerifier := oidcCode(t, siblingFixture, service, "logout-sibling-nonce")
	siblingTokens, err := service.Token(f.ctx, oauth.TokenRequest{ClientID: "public-web", GrantType: "authorization_code", Code: siblingCode, CodeVerifier: siblingVerifier, RedirectURI: "https://client.example/callback", Resource: f.oauth.Protocol.Resource, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("logout withdrew sibling OAuth continuation", err)
	}
	siblingWire, _ := siblingTokens.IDToken.Reveal()
	siblingID, err := consumeIDToken(ctx, provider, siblingWire, "logout-sibling-nonce", "public-web")
	if err != nil || siblingID.Subject != verified.Subject {
		t.Fatal("sibling independent RP subject changed", err)
	}
	siblingAccess, _ := siblingTokens.AccessToken.Reveal()
	if info, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: siblingAccess}); err != nil || info.Subject != siblingID.Subject {
		t.Fatal("logout withdrew unrelated sibling UserInfo", err)
	}
	if current, err := resource.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: siblingAccess, Scope: "identity:read"}); err != nil || current.Subject() != principal.Subject() || current.RequireScope("identity:read") != nil {
		t.Fatal("logout withdrew sibling resource authority", err)
	}
	// Opaque RP state is checked independently of the provider's result.
	accept := func(state string) bool { return state == "original +/%?=&" }
	if !accept(out.State) || accept("foreign-state") {
		t.Fatal("independent RP accepted substituted callback state")
	}
	repeat, err := child.EndSession(f.ctx, request)
	if err != nil || repeat.Outcome != oauth.EndSessionLocalOnly || !repeat.Completion.Replayed || repeat.RedirectURI != "" || repeat.State != "" || repeat.DeleteCookie != nil {
		t.Fatal("matching repeat became fresh execution/delivery", err)
	}
}

func TestNativeOIDCEndSessionHistoricalHintAndCurrentKeyEligibility(t *testing.T) {
	for _, mode := range []string{"expired-retired", "compromised"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			installLogoutSessionHistory(t, f)
			f.oauth.RPInitiatedLogout = true
			// A genuinely short issued lifetime reaches exp naturally. No SQL
			// timestamp or owner session/verification state is manufactured.
			f.oauth.Protocol.AccessTTL = 3 * time.Second
			service, child, signer, _, _ := oidcFixture(t, &f)
			request := nativeLogoutRequest(t, f, service)
			before := nativeLogoutState(t, f)
			if mode == "compromised" {
				if err := signer.Compromise(f.ctx, "initial"); err != nil {
					t.Fatal(err)
				}
				out, err := child.EndSession(f.ctx, request)
				if err == nil || out.RedirectURI != "" || out.DeleteCookie != nil || nativeLogoutState(t, f) != before {
					t.Fatal("compromised genuine hint disclosed logout success", err)
				}
				if logoutSession(t, f, f.browser).ValidateAt(time.Now()) != nil {
					t.Fatal("compromised-key denial mutated source session")
				}
				return
			}
			verified, err := signer.VerifyCompact(f.ctx, request.Parameters.IDTokenHint)
			if err != nil {
				t.Fatal(err)
			}
			var dates struct {
				Expiry int64 `json:"exp"`
			}
			if json.Unmarshal(verified.Payload(), &dates) != nil || dates.Expiry == 0 {
				t.Fatal("genuine issued expiry")
			}
			next, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil || signer.Install(f.ctx, "successor", next) != nil {
				t.Fatal("successor signing custody", err)
			}
			if _, err := child.JWKS(f.ctx); err != nil {
				t.Fatal(err)
			}
			if err := signer.Activate(f.ctx, "successor"); err != nil {
				t.Fatal(err)
			}
			waitAuthenticationBoundary(t, f, time.Unix(dates.Expiry, 0).Add(time.Millisecond))
			if err := signer.Retire(f.ctx, "initial"); err != nil {
				t.Fatal("genuinely expired original key retirement", err)
			}
			if logoutSession(t, f, f.browser).ValidateAt(time.Now()) != nil {
				t.Fatal("historical hint lacks current exact source session")
			}
			out, err := child.EndSession(f.ctx, request)
			if err != nil || out.Outcome != oauth.EndSessionLocalOnly || out.DeleteCookie == nil || logoutSession(t, f, f.browser).Authenticated {
				t.Fatal("genuine expired hint with retained retired public material denied", err)
			}
		})
	}
}

func TestNativeOIDCEndSessionPairwiseAndConfidentialClients(t *testing.T) {
	for _, mode := range []string{"pairwise", "confidential"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			installLogoutSessionHistory(t, f)
			f.oauth.RPInitiatedLogout = true
			clientID, redirect := "public-web", "https://client.example/callback"
			var authentication oauth.ClientAuthentication
			if mode == "confidential" {
				configured, _, basic := addConfiguredConfidentialClient(t, &f)
				clientID, redirect, authentication = configured.ID, configured.Redirects[0], basic
			}
			if mode == "pairwise" {
				registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
				for i := range f.oauth.Protocol.Clients {
					f.oauth.Protocol.Clients[i].SubjectRegistration = &registration
				}
			}
			service, child, signer, store, _ := oidcFixture(t, &f)
			if mode == "pairwise" {
				var err error
				store, err = oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				core, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
				if err != nil {
					t.Fatal(err)
				}
				policy := pairwisePolicy(t, f, 1, [32]byte{1, 2, 3})
				cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
				issuer := f.oauth.Protocol.Issuer.String()
				child, err = op.NewService(op.Config{Issuer: f.oauth.Protocol.Issuer, JWKSURI: issuer + "/oauth2/jwks", UserInfoEndpoint: issuer + "/oauth2/userinfo", EndSessionEndpoint: issuer + "/oauth2/logout", SessionCookie: cookie, Signing: signer, SubjectKey: [32]byte{42}, SubjectPolicy: policy, Clock: clock.System{}, MaximumDuration: 4 * time.Second}, core)
				if err != nil {
					t.Fatal(err)
				}
				service, err = core.WithOIDC(child)
				if err != nil {
					t.Fatal(err)
				}
				key, _ := policy.KeyRegistration(1)
				if err := store.InstallSubjectKey(f.ctx, key); err != nil {
					t.Fatal(err)
				}
				if err := store.ActivateSubjectKey(f.ctx, "subjects", 1, 1); err != nil {
					t.Fatal(err)
				}
			}
			code, verifier := pairwiseCodeForClient(t, f, service, clientID, redirect, "logout-client-variant")
			tokens, err := service.Token(f.ctx, oauth.TokenRequest{ClientID: clientID, ClientAuthentication: authentication, GrantType: "authorization_code", Code: code, CodeVerifier: verifier, RedirectURI: redirect, Resource: f.oauth.Protocol.Resource, Network: "192.0.2.1"})
			if err != nil {
				t.Fatal("actual selected client hint", err)
			}
			wire, _ := tokens.IDToken.Reveal()
			transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child}
			ctx := rp.ClientContext(f.ctx, &http.Client{Transport: transport, Timeout: 5 * time.Second})
			provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
			if err != nil {
				t.Fatal(err)
			}
			hint, err := consumeIDToken(ctx, provider, wire, "logout-client-variant", clientID)
			bindings, bindingErr := logoutSession(t, f, f.browser).Session.Bindings()
			if err != nil || bindingErr != nil || hint.Subject == "" || mode == "pairwise" && hint.Subject == string(bindings.UserID) {
				t.Fatal("independent RP variant subject", err)
			}
			request := op.EndSessionRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Parameters: op.EndSessionParameters{IDTokenHint: wire, ClientID: clientID}}
			out, err := child.EndSession(f.ctx, request)
			if err != nil || out.Outcome != oauth.EndSessionLocalOnly || out.DeleteCookie == nil || logoutSession(t, f, f.browser).Authenticated {
				t.Fatal("selected human client logout failed", err)
			}
		})
	}
}

func TestNativeOIDCEndSessionConcurrentRepeatHasOneTransition(t *testing.T) {
	f := passwordFixture(t)
	installLogoutSessionHistory(t, f)
	f.oauth.RPInitiatedLogout = true
	service, child, _, _, _ := oidcFixture(t, &f)
	request := nativeLogoutRequest(t, f, service)
	before := nativeLogoutState(t, f)
	type answer struct {
		out op.EndSessionResult
		err error
	}
	start := make(chan struct{})
	answers := make(chan answer, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			out, err := child.EndSession(f.ctx, request)
			answers <- answer{out, err}
		}()
	}
	close(start)
	workers.Wait()
	close(answers)
	fresh := 0
	for result := range answers {
		if result.out.RedirectURI != "" || result.out.State != "" {
			t.Fatal("local contention disclosed redirect")
		}
		if result.err == nil && result.out.DeleteCookie != nil {
			fresh++
		} else if result.out.DeleteCookie != nil {
			t.Fatal("failed contention cleared browser")
		}
	}
	if fresh != 1 || logoutSession(t, f, f.browser).Authenticated {
		t.Fatal("concurrent logout did not deliver exactly one fresh termination")
	}
	after := nativeLogoutState(t, f)
	for i := range before {
		if after[i] != before[i]+1 {
			t.Fatal("concurrent logout duplicated or omitted protected effects", i)
		}
	}
	repeat, err := child.EndSession(f.ctx, request)
	if err != nil || !repeat.Completion.Replayed || repeat.DeleteCookie != nil || repeat.Outcome != oauth.EndSessionLocalOnly {
		t.Fatal("post-contention repeat did not conserve historical outcome", err)
	}
}

func TestNativeOIDCEndSessionSelectionPreservesOrdinarySignoutGrantPolicy(t *testing.T) {
	f := passwordFixture(t)
	installLogoutSessionHistory(t, f)
	f.oauth.RPInitiatedLogout = true
	service, child, _, _, _ := oidcFixture(t, &f)
	code, verifier := oidcCode(t, f, service, "ordinary-signout-control")
	tokens, err := service.Token(f.ctx, oauth.TokenRequest{ClientID: "public-web", GrantType: "authorization_code", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Resource: f.oauth.Protocol.Resource, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	access, _ := tokens.AccessToken.Reveal()
	refresh, _ := tokens.RefreshToken.Reveal()
	before, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access})
	if err != nil || before.Subject == "" {
		t.Fatal("ordinary signout grant control", err)
	}
	f.signOut()
	after, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access})
	if err != nil || after.Subject != before.Subject {
		t.Fatal("enabling RP logout silently withdrew grants on ordinary signout", err)
	}
	rotated, err := service.Token(f.ctx, oauth.TokenRequest{ClientID: "public-web", GrantType: "refresh_token", RefreshToken: refresh, Resource: f.oauth.Protocol.Resource, Network: "192.0.2.1"})
	if err != nil || rotated.AccessToken == (oauth.Token{}) {
		t.Fatal("ordinary signout acquired RP-specific refresh withdrawal", err)
	}
}

func TestNativeOIDCEndSessionRequiresCurrentCredentialAuthority(t *testing.T) {
	f := passwordFixtureWithChange(t, true)
	installLogoutSessionHistory(t, f)
	f.oauth.RPInitiatedLogout = true
	service, child, _, _, _ := oidcFixture(t, &f)
	request := nativeLogoutRequest(t, f, service)
	f.changePassword()
	before := nativeLogoutState(t, f)
	if out, err := child.EndSession(f.ctx, request); err == nil || out.RedirectURI != "" || out.State != "" || out.DeleteCookie != nil {
		t.Fatal("withdrawn source credential authorized logout", err)
	}
	if nativeLogoutState(t, f) != before {
		t.Fatal("withdrawn credential changed protected logout effects")
	}
}

func TestNativeOIDCEndSessionLateAuthorityAndProtectedWaitDenyDelivery(t *testing.T) {
	for _, mode := range []string{"source-withdrawal", "key-withdrawal", "cancellation", "original-deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			installLogoutSessionHistory(t, f)
			f.oauth.RPInitiatedLogout = true
			var shift atomic.Int64
			f.oauth.Protocol.Clock = emailClock(func() time.Time { return time.Now().Add(time.Duration(shift.Load())) })
			gate := &consentRaceBarrier{owner: f.oauth.Coordinator.AdmissionPolicy.Authorization, action: "identity.oauth-server.end-session", ready: make(chan struct{}), release: make(chan struct{})}
			admission := *f.oauth.Coordinator.AdmissionPolicy
			admission.Authorization = gate
			f.oauth.Coordinator.AdmissionPolicy = &admission
			service, child, signer, _, _ := oidcFixture(t, &f)
			request := nativeLogoutRequest(t, f, service)
			ctx, cancel := context.WithCancel(context.WithValue(f.ctx, consentRaceKey{}, true))
			type answer struct {
				out op.EndSessionResult
				err error
			}
			done := make(chan answer, 1)
			joined := false
			var release sync.Once
			unlock := func() {}
			defer func() {
				cancel()
				release.Do(func() { close(gate.release) })
				unlock()
				if !joined {
					<-done
				}
			}()
			go func() {
				out, err := child.EndSession(ctx, request)
				done <- answer{out, err}
			}()
			select {
			case <-gate.ready:
			case result := <-done:
				joined = true
				t.Fatal("genuine logout did not reach admitted pre-Work boundary", result.err)
			case <-f.ctx.Done():
				t.Fatal("logout admission wait canceled")
			}
			// These are actual owners after genuine hint/session admission, not
			// substituted authorization decisions or manufactured revoked rows.
			if mode == "source-withdrawal" {
				f.signOut()
			} else if mode == "key-withdrawal" {
				if err := signer.Compromise(f.ctx, "initial"); err != nil {
					t.Fatal("actual key withdrawal", err)
				}
			}
			before := nativeLogoutState(t, f)
			if mode == "cancellation" || mode == "original-deadline" {
				blocker, err := f.pool.Raw().Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				unlock = func() { _ = blocker.Rollback(context.Background()) }
				var pid uint32
				if err := blocker.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
					t.Fatal(err)
				}
				if _, err := blocker.Exec(f.ctx, `SELECT kid FROM oauth_store.signing_keys WHERE kid='initial' FOR UPDATE`); err != nil {
					t.Fatal(err)
				}
				release.Do(func() { close(gate.release) })
				// Prove the real protected transaction is waiting on this lock;
				// elapsed sleep alone would not establish a crossed Work boundary.
				ticker := time.NewTicker(5 * time.Millisecond)
				defer ticker.Stop()
				for {
					var waiting int
					if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, pid).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting > 0 {
						break
					}
					select {
					case result := <-done:
						joined = true
						t.Fatal("logout never reached actual protected key lock", result.err)
					case <-ticker.C:
					case <-f.ctx.Done():
						t.Fatal("protected logout wait canceled")
					}
				}
				if mode == "cancellation" {
					cancel()
				} else {
					shift.Store(int64(21 * time.Second))
				}
				unlock()
			} else {
				release.Do(func() { close(gate.release) })
			}
			result := <-done
			joined = true
			if result.err == nil || result.out.RedirectURI != "" || result.out.State != "" || result.out.DeleteCookie != nil || !result.out.ValidUntil.IsZero() || nativeLogoutState(t, f) != before {
				t.Fatal("late authority/canceled/expired logout returned delivery or committed protected effects", result.err)
			}
			if mode == "cancellation" && !errors.Is(result.err, context.Canceled) {
				t.Fatal("caller cancellation was not preserved", result.err)
			}
			if mode != "source-withdrawal" && logoutSession(t, f, f.browser).ValidateAt(time.Now()) != nil {
				t.Fatal("denied protected wait revoked the current source")
			}
		})
	}
}

func TestNativeOIDCEndSessionDirectBoundaryConservesIssuingNamespaceAndReadStart(t *testing.T) {
	for _, changed := range []string{"issuer", "environment", "sealed-read-start"} {
		t.Run(changed, func(t *testing.T) {
			f := passwordFixture(t)
			installLogoutSessionHistory(t, f)
			f.oauth.RPInitiatedLogout = true
			service, _, signer, _, _ := oidcFixture(t, &f)
			request := nativeLogoutRequest(t, f, service)
			packet, err := signer.VerifyCompact(f.ctx, request.Parameters.IDTokenHint)
			if err != nil {
				t.Fatal(err)
			}
			var claims struct {
				Subject string `json:"sub"`
				Issued  int64  `json:"iat"`
				Expiry  int64  `json:"exp"`
			}
			if json.Unmarshal(packet.Payload(), &claims) != nil {
				t.Fatal("actual issued namespace control")
			}
			configured := f.oauth
			if changed == "issuer" {
				configured.Protocol.Issuer, err = oauth.NewIssuer("https://other-issuer.example")
				if err != nil {
					t.Fatal(err)
				}
				configured.Protocol.Discovery = oauth.DiscoveryConfig{}
			} else if changed == "environment" {
				configured.Protocol.Environment = "other-native-test"
			}
			native, err := oauthpostgres.NewStore(f.pool, configured, f.keys)
			if err != nil {
				t.Fatal("current trusted namespace composition", err)
			}
			if changed == "sealed-read-start" {
				// Control only the original verification clock. Signature, public
				// key eligibility, issued association and browser remain genuine.
				originalRead := &oidcTestClock{now: time.Now().Add(-21 * time.Second)}
				authority, err := oauth.NewSigningAuthority(originalRead, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				verifier, err := oauth.NewSigningService(authority, native)
				if err != nil {
					t.Fatal(err)
				}
				packet, err = verifier.VerifyCompact(f.ctx, request.Parameters.IDTokenHint)
				if err != nil {
					t.Fatal("genuine cryptographic proof with original read clock", err)
				}
			}
			before := nativeLogoutState(t, f)
			out, err := native.EndSession(f.ctx, oauth.EndSessionExecution{StartedAt: time.Now(), Client: configured.Protocol.Clients[0], Input: oauth.EndSessionInput{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, Origin: configured.Protocol.Issuer.String(), Network: "192.0.2.1", Hint: packet, ClientID: "public-web", Subject: claims.Subject, IssuedAt: time.Unix(claims.Issued, 0), ExpiresAt: time.Unix(claims.Expiry, 0)}})
			if err == nil || out.RedirectURI != "" || out.State != "" || nativeLogoutState(t, f) != before || logoutSession(t, f, f.browser).ValidateAt(time.Now()) != nil {
				t.Fatal("native boundary lost issuing namespace or renewed original sealed read", err)
			}
		})
	}
}

func TestNativeOIDCEndSessionDirectBoundaryBoundsOpaqueState(t *testing.T) {
	for _, mode := range []string{"over-limit", "control", "empty", "maximum"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			installLogoutSessionHistory(t, f)
			f.oauth.RPInitiatedLogout = true
			uri := "https://client.example/signed-out"
			f.oauth.Protocol.Clients[0].PostLogoutRedirects = []string{uri}
			service, _, signer, native, _ := oidcFixture(t, &f)
			request := nativeLogoutRequest(t, f, service)
			packet, err := signer.VerifyCompact(f.ctx, request.Parameters.IDTokenHint)
			if err != nil {
				t.Fatal("genuine issued hint verification", err)
			}
			var claims struct {
				Subject string `json:"sub"`
				Issued  int64  `json:"iat"`
				Expiry  int64  `json:"exp"`
			}
			if json.Unmarshal(packet.Payload(), &claims) != nil {
				t.Fatal("actual issued hint claims unavailable")
			}
			state := ""
			switch mode {
			case "over-limit":
				state = strings.Repeat("s", 1025)
			case "control":
				state = "original\nstate"
			case "maximum":
				state = strings.Repeat("s", 1024)
			}
			before := nativeLogoutState(t, f)
			out, err := native.EndSession(f.ctx, oauth.EndSessionExecution{StartedAt: time.Now(), Client: f.oauth.Protocol.Clients[0], Input: oauth.EndSessionInput{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Hint: packet, ClientID: "public-web", Subject: claims.Subject, IssuedAt: time.Unix(claims.Issued, 0), ExpiresAt: time.Unix(claims.Expiry, 0), PostLogoutRedirectURI: uri, State: state}})
			if mode == "over-limit" || mode == "control" {
				if err == nil || out.RedirectURI != "" || out.State != "" || nativeLogoutState(t, f) != before || logoutSession(t, f, f.browser).ValidateAt(time.Now()) != nil {
					t.Fatal("invalid direct-native state reached session/effect mutation or redirect", err)
				}
				return
			}
			if err != nil || out.Outcome != oauth.EndSessionRedirect || out.RedirectURI != uri || out.State != state || out.Validate() != nil || logoutSession(t, f, f.browser).Authenticated {
				t.Fatal("valid boundary state was rejected or changed", err)
			}
		})
	}
}

// Record the real child's first signed projection without substituting claims,
// signatures, session authority or preparation. Reveal/parse conserves the same
// signed bytes; later invocation counts detect accidental regeneration.
type recordedLogoutClaims struct {
	oauth.OIDCExtension
	mu     sync.Mutex
	calls  uint32
	digest [32]byte
	expiry time.Time
}

func (r *recordedLogoutClaims) Claims(ctx context.Context, in oauth.OIDCClaimsInput) (oauth.OIDCClaimsProjection, error) {
	out, err := r.OIDCExtension.Claims(ctx, in)
	if err != nil {
		return out, err
	}
	wire, err := out.IDToken.Reveal()
	if err != nil {
		return oauth.OIDCClaimsProjection{}, err
	}
	out.IDToken, err = oauth.ParseIDToken(wire)
	if err != nil {
		return oauth.OIDCClaimsProjection{}, err
	}
	r.mu.Lock()
	r.calls++
	if r.calls == 1 {
		r.digest, r.expiry = sha256.Sum256([]byte(wire)), in.ExpiresAt
	}
	r.mu.Unlock()
	return out, nil
}

func TestNativeOIDCEndSessionActivationResumesOriginalLegacyTokenPreparation(t *testing.T) {
	fault := &oauthCommitFault{before: true}
	f := passwordFixture(t, fault)
	installLogoutSessionHistory(t, f)
	_, child, signer, legacyStore, _ := oidcFixture(t, &f)
	recorded := &recordedLogoutClaims{OIDCExtension: child}
	legacy, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: legacyStore})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err = legacy.WithOIDC(recorded)
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := oidcCode(t, f, legacy, "activation-original-nonce")
	request := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Resource: f.oauth.Protocol.Resource, Network: "192.0.2.1"}
	fault.armed.Store(true)
	pending, err := legacy.Token(f.ctx, request)
	if err == nil || !fault.hit.Load() || pending.Outcome != identity.CommitOutcomeUnknown || pending.CommandID == "" || pending.IDToken != (oauth.IDToken{}) {
		t.Fatal("actual preactivation final-COMMIT fault did not retain undisclosed output", err)
	}
	fault.armed.Store(false)
	rawID, err := base64.RawURLEncoding.DecodeString(string(pending.CommandID))
	if err != nil {
		t.Fatal("original command encoding", err)
	}
	var ciphertext []byte
	var generation, state string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text,state FROM identity.commands WHERE command_id=$1`, rawID).Scan(&ciphertext, &generation, &state); err != nil || len(ciphertext) == 0 || generation == "" || state != "pending" {
		t.Fatal("actual original pending encrypted response missing", err)
	}
	defer clear(ciphertext)
	// Append only the selected forward suffix. The original clients, keys,
	// durations and configuration identity remain unchanged across activation.
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
	base := oauthpostgres.SigningMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7003}
	runner, err := migrations.NewRunner(oauthpostgres.EndSessionMigrationSource{Base: base, Schema: "oauth_store", Version: 7006}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("activation forward suffix", err)
	}
	f.oauth.RPInitiatedLogout = true
	native, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	activated, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: native})
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the immutable genuine claims policy/signing owner, not an off-profile
	// token executor. Every postactivation execution uses the new selected Store.
	activated, err = activated.WithOIDC(recorded)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	var resumed oauth.TokenResult
	for {
		resumed, err = activated.Token(f.ctx, request)
		if err != nil {
			t.Fatal("selected native owner rejected original retained preactivation response", err)
		}
		if resumed.Outcome == identity.CommitOutcomeCommitted {
			break
		}
		if resumed.Outcome != identity.CommitOutcomeInProgress || time.Now().After(deadline) {
			t.Fatal("original retained response did not resume within its existing lease")
		}
		waitAuthenticationBoundary(t, f, time.Now().Add(50*time.Millisecond))
	}
	wire, err := resumed.IDToken.Reveal()
	if err != nil || resumed.CommandID != pending.CommandID || resumed.Replayed {
		t.Fatal("original response did not complete as the original one-use execution", err)
	}
	recorded.mu.Lock()
	calls, digest, expiry := recorded.calls, recorded.digest, recorded.expiry
	recorded.mu.Unlock()
	if calls != 1 || sha256.Sum256([]byte(wire)) != digest || !resumed.ExpiresAt.Equal(expiry) {
		t.Fatal("activation regenerated or renewed original signed response")
	}
	var retained []byte
	var retainedGeneration string
	var associations, effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text,(SELECT count(*) FROM oauth_store.issued_id_token_hints),(SELECT count(*) FROM oauth_store.effects WHERE command_id=$2) FROM identity.commands WHERE command_id=$1`, rawID, string(pending.CommandID)).Scan(&retained, &retainedGeneration, &associations, &effects); err != nil || !bytes.Equal(retained, ciphertext) || retainedGeneration != generation || associations != 0 || effects != 1 {
		t.Fatal("activation replaced preparation or backfilled legacy logout authority", err)
	}
	clear(retained)
	transport := &discoveryConsumerTransport{f: f, service: activated, endpoints: f.oauth.Protocol.Discovery, oidc: child}
	ctx := rp.ClientContext(f.ctx, &http.Client{Transport: transport, Timeout: 5 * time.Second})
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := consumeIDToken(ctx, provider, wire, "activation-original-nonce", "public-web")
	if err != nil {
		t.Fatal("independent RP rejected original resumed signed response", err)
	}
	packet, err := signer.VerifyCompact(f.ctx, wire)
	if err != nil {
		t.Fatal(err)
	}
	before := nativeLogoutState(t, f)
	if out, err := native.EndSession(f.ctx, oauth.EndSessionExecution{StartedAt: time.Now(), Client: f.oauth.Protocol.Clients[0], Input: oauth.EndSessionInput{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Hint: packet, ClientID: "public-web", Subject: verified.Subject, IssuedAt: verified.IssuedAt, ExpiresAt: verified.Expiry}}); err == nil || out.RedirectURI != "" || nativeLogoutState(t, f) != before || logoutSession(t, f, f.browser).ValidateAt(time.Now()) != nil {
		t.Fatal("legacy resumed hint acquired new logout authority", err)
	}
	// A genuinely new selected preparation must still atomically associate its
	// actual issued token; compatibility is not permission to omit new custody.
	selected := nativeLogoutRequest(t, f, activated)
	var selectedAssociations int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.issued_id_token_hints WHERE digest=$1`, func() []byte { d := sha256.Sum256([]byte(selected.Parameters.IDTokenHint)); return d[:] }()).Scan(&selectedAssociations); err != nil || selectedAssociations != 1 {
		t.Fatal("new selected preparation omitted actual logout association", err)
	}
}

func nativeLogoutRequest(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service) op.EndSessionRequest {
	t.Helper()
	code, verifier := oidcCode(t, f, service, "logout-original")
	tokens, err := service.Token(f.ctx, oauth.TokenRequest{ClientID: "public-web", GrantType: "authorization_code", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Resource: f.oauth.Protocol.Resource, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("genuine native hint issuance", err)
	}
	wire, err := tokens.IDToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return op.EndSessionRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Parameters: op.EndSessionParameters{IDTokenHint: wire, ClientID: "public-web"}}
}

func nativeLogoutState(t *testing.T, f authenticatedPasswordFixture) [5]int {
	t.Helper()
	var counts [5]int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE state='revoked'),(SELECT count(*) FROM session_store.session_revocations WHERE purpose='identity.oauth-server.end-session'),(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.end-session'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.end_session' AND outcome=1),(SELECT count(*) FROM public.outbox_messages WHERE topic='session.revoked.v1')`).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4]); err != nil {
		t.Fatal("actual native logout state", err)
	}
	return counts
}

func TestNativeOIDCEndSessionRequiredEffectsAndOriginalRecovery(t *testing.T) {
	for _, mode := range []string{"local-only", "outbox", "before", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			var tracking, provisional, effectAttempt atomic.Bool
			fault := &oauthCommitFault{before: mode == "before", beforeWrite: func(wire []byte) {
				if tracking.Load() && bytes.Contains(wire, []byte(`UPDATE "session_store".sessions SET state='revoked'`)) {
					provisional.Store(true)
				}
				if tracking.Load() && provisional.Load() && bytes.Contains(wire, []byte("outbox_messages")) {
					effectAttempt.Store(true)
				}
			}}
			f := passwordFixture(t, fault)
			installLogoutSessionHistory(t, f)
			f.oauth.RPInitiatedLogout = true
			service, child, _, _, _ := oidcFixture(t, &f)
			request := nativeLogoutRequest(t, f, service)
			before := nativeLogoutState(t, f)
			if mode == "outbox" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_logout CHECK(topic<>'session.revoked.v1') NOT VALID`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "before" || mode == "unknown" {
				fault.armed.Store(true)
			}
			tracking.Store(true)
			out, err := child.EndSession(f.ctx, request)
			if mode == "local-only" {
				if err != nil || out.Outcome != oauth.EndSessionLocalOnly || out.RedirectURI != "" || out.State != "" || out.DeleteCookie == nil {
					t.Fatal("absent URI did not select genuine local-only logout", err)
				}
			} else {
				if err == nil || out.RedirectURI != "" || out.State != "" || out.DeleteCookie != nil || !provisional.Load() {
					t.Fatal("failed/ambiguous logout disclosed success or never reached session work", err)
				}
				if mode == "outbox" && !effectAttempt.Load() {
					t.Fatal("required outbox fault was not reached")
				}
			}
			if mode == "before" || mode == "unknown" {
				if !fault.hit.Load() || out.Outcome != oauth.EndSessionUnknownReconciliation || out.Completion.CommandID == "" {
					t.Fatal("actual COMMIT loss was not reported as original unknown")
				}
				fresh, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.end-session", CommandID: out.Completion.CommandID, ClientID: "public-web", TenantID: f.tenant, Session: f.browser, Token: request.Parameters.IDTokenHint}
				got, err := fresh.Recover(f.ctx, recovery)
				want := identity.CommitOutcomeCommitted
				if mode == "before" {
					want = identity.CommitOutcomeNotCommitted
				}
				deadline := time.Now().Add(8 * time.Second)
				for got.Outcome != want {
					if time.Now().After(deadline) {
						t.Fatal("original logout recovery did not reconcile", err)
					}
					if err != nil && !errors.Is(err, oauth.ErrUnavailable) {
						t.Fatal("original historical custody denied after self-revocation", err)
					}
					waitAuthenticationBoundary(t, f, time.Now().Add(100*time.Millisecond))
					got, err = fresh.Recover(f.ctx, recovery)
				}
				for range 2 {
					again, err := fresh.Recover(f.ctx, recovery)
					if err != nil && !(mode == "before" && errors.Is(err, oauth.ErrUnavailable)) || again.Outcome != want || again.CommandID != recovery.CommandID {
						t.Fatal("original logout recovery changed historical result", err)
					}
				}
				foreign := recovery
				foreign.ClientID = "other-public-web"
				if _, err := fresh.Recover(f.ctx, foreign); err == nil {
					t.Fatal("foreign client read logout result")
				}
			}
			after := nativeLogoutState(t, f)
			delta := 0
			if mode == "unknown" || mode == "local-only" {
				delta = 1
			}
			for i := range after {
				if after[i] != before[i]+delta {
					t.Fatal("session/evidence/audit/lifecycle did not commit exactly once together", i)
				}
			}
			if (mode == "before" || mode == "outbox") && logoutSession(t, f, f.browser).ValidateAt(time.Now()) != nil {
				t.Fatal("proven rollback revoked original session")
			}
		})
	}
}
