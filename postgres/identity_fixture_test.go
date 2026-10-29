//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

type authenticatedPasswordFixture struct {
	ctx            context.Context
	pool           *database.Pool
	tenant         identity.TenantID
	browser        auth.BearerCredential
	csrf           session.CSRFToken
	sessions       *session.SessionService
	keys           *keyring.Provider
	oauth          oauthpostgres.Config
	signOut        func()
	changePassword func()
	signInAgain    func() (auth.BearerCredential, session.CSRFToken)
	anotherUser    func() (auth.BearerCredential, session.CSRFToken)
	phoneInput     *nativePhoneInput
}

// The explicit provider seam records at most one bounded rendered registration
// message in process memory. It claims provider acceptance, not delivery. Domain
// routing, encrypted queue custody and worker transitions remain real owners.
type registrationMailbox struct {
	mu   sync.Mutex
	body string
}

func (m *registrationMailbox) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	if ctx == nil || ctx.Err() != nil || a.Validate() != nil || a.TenantID != baselineTenant || len(a.Body) > 4096 {
		return delivery.DeliveryResult{}, delivery.ErrInvalidInput
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.body != "" {
		return delivery.DeliveryResult{}, delivery.ErrUnavailable
	}
	m.body = strings.Clone(a.Body)
	return delivery.DeliveryResult{State: delivery.StateAccepted, ObservedAt: time.Now().UTC()}, nil
}

type hibpTransport struct{}

func (hibpTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Context().Err() != nil {
		return nil, r.Context().Err()
	}
	if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "api.pwnedpasswords.com" || !strings.HasPrefix(r.URL.Path, "/range/") || len(r.URL.Path) != 12 {
		return nil, io.ErrUnexpectedEOF
	}
	// A syntactically valid different suffix proves the real HIBP parser's
	// clean path; no password/signal/evaluator is replaced in this fixture.
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat("0", 35) + ":0\r\n")), Request: r}, nil
}

func passwordFixture(t *testing.T, faults ...*oauthCommitFault) authenticatedPasswordFixture {
	return passwordFixtureWithChange(t, false, faults...)
}

func passwordFixtureWithChange(t *testing.T, change bool, faults ...*oauthCommitFault) authenticatedPasswordFixture {
	return passwordFixtureWithProfileSchema(t, change, nil, faults...)
}

// The optional schema is selected before genuine signup. Existing immutable
// stored schemas are never rewritten to make a later profile read compatible.
func passwordFixtureWithProfileSchema(t *testing.T, change bool, profileSchema *identity.AttributeSchema, faults ...*oauthCommitFault) authenticatedPasswordFixture {
	return passwordFixtureWithSignupRecovery(t, change, profileSchema, true, faults...)
}

func passwordFixtureWithSignupRecovery(t *testing.T, change bool, profileSchema *identity.AttributeSchema, observeOriginalSignup bool, faults ...*oauthCommitFault) authenticatedPasswordFixture {
	t.Helper()
	ctx, pool, sqlDB := isolatedPostgres(t, true, faults...)
	keyNames := []string{"fingerprint", "request", "counter", "risk-evidence", "risk-seal", "preauth-cookie", "session-token", "session-csrf", "http-device", "delivery-envelope", "dummy-password", "capability-binding", "capability-signing", "signin-proof", "migration", "counter-replay", "http-rate", "otp-lockout", "otp-wrap", "otp-attempt", "otp-code", "otp-intent", "identifier", "delivery-digest", "delivery-namespace", "password-flow", "signup-binding", "signup-intent", "verification-scope", "capability-replay", "capability-envelope", "counter-envelope", "verification-http", "oauth-intent", "oauth-token", "oauth-envelope"}
	keyNames = append(keyNames, "oauth-envelope-next")
	if change {
		keyNames = append(keyNames, "reauth-proof", "reauth-identifier", "change-intent", "change-http-rate")
	}
	secrets := make(map[string][32]byte, len(keyNames))
	for _, name := range keyNames {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal("fixture entropy unavailable")
		}
		secrets[name] = key
	}
	t.Cleanup(func() {
		for name := range secrets {
			delete(secrets, name)
		}
	})
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	mailbox := &registrationMailbox{}
	t.Cleanup(func() { mailbox.mu.Lock(); mailbox.body = ""; mailbox.mu.Unlock() })
	var selectedSchema []identity.AttributeSchema
	if profileSchema != nil {
		selectedSchema = []identity.AttributeSchema{*profileSchema}
	}
	graph, err := fixtureGraph(ctx, origin, secrets, pool, mailbox, hibpTransport{}, change, selectedSchema...)
	if err != nil {
		var invalid identity.InvalidInputError
		if errors.As(err, &invalid) && len(invalid.Field) <= 128 && strings.IndexFunc(invalid.Field, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '.') }) < 0 {
			t.Fatalf("real public identity graph rejected configuration: field=%s deadline=%t canceled=%t invalid_input=%t parent_done=%t", invalid.Field, errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), errors.Is(err, identityhttp.ErrInvalidInput), ctx.Err() != nil)
		}
		t.Fatalf("real public identity graph rejected: deadline=%t canceled=%t invalid_input=%t parent_done=%t error_type=%T", errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), errors.Is(err, identityhttp.ErrInvalidInput), ctx.Err() != nil, err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if graph.close(bounded) != nil {
			t.Error("identity graph cleanup failed")
		}
	})
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity"}
	plan, err := graph.stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules})
	if err != nil {
		checked, checkErr := graph.stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: modules})
		if checkErr == nil {
			t.Fatal("owned identity migration planning rejected owner statuses", checked.Statuses)
		}
		t.Fatal("owned identity migration planning failed", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("oauth-native-fixture-install"))
	if err != nil {
		t.Fatal(err)
	}
	applied, err := graph.stores.ReferenceMigrationApply(ctx, reference.ReferenceMigrationApplyRequest{CommandID: "oauth_native_fixture_install", Plan: plan.Plan, IdempotencyKey: key})
	if err != nil || applied.Result.State() != reference.MigrationApplied {
		t.Fatal("owned identity migration apply failed", err)
	}
	backend, err := migrationdb.New(sqlDB)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("oauth_server")
	if err != nil {
		t.Fatal("OAuth migration namespace rejected", err)
	}
	runner, err := migrations.NewRunner(oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("OAuth schema install failed", err)
	}
	if err := graph.features.Initialize(ctx); err != nil {
		t.Fatal("native identity initialization failed", err)
	}
	server.Config.Handler = graph.server.Handler()
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 6 * time.Second
	client.Jar, _ = cookiejar.New(nil)
	call := func(path string, body any, idempotency string, csrf ...string) (int, []byte, http.Header, []*http.Cookie) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal("fixture request encoding failed")
		}
		defer clear(wire)
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal("fixture request failed")
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		if idempotency != "" {
			r.Header.Set("Idempotency-Key", idempotency)
		}
		if len(csrf) == 1 {
			r.Header.Set("X-CSRF-Token", csrf[0])
		}
		started := time.Now()
		response, err := client.Do(r)
		if err != nil {
			logPasswordFixtureObservation(t, graph.signupObservation.end())
			t.Fatalf("identity HTTPS request unavailable: signup=%t signin=%t preauth=%t confirmation=%t duration=%s deadline=%t canceled=%t parent_done=%t", path == "/v1/password/signup", path == "/v1/password/signin", path == "/v1/session/preauth-issue", path == "/v1/email/verification-confirm", time.Since(started), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), ctx.Err() != nil)
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("identity HTTPS response boundary failed")
		}
		return response.StatusCode, payload, response.Header, response.Cookies()
	}
	preauth := func(method string) sessionhttp.PreAuthResponse {
		t.Helper()
		status, body, _, _ := call("/v1/session/preauth-issue", map[string]string{"method": method}, "")
		var response sessionhttp.PreAuthResponse
		if status != 200 || json.Unmarshal(body, &response) != nil || !response.Issued {
			t.Fatal("real pre-auth flow failed", status)
		}
		return response
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("candidate entropy unavailable")
	}
	address := "oauth-" + hex.EncodeToString(random[:8]) + "@example.invalid"
	candidate := hex.EncodeToString(random[:])
	clear(random[:])
	flow := preauth("signup")
	var originalSignupCookies []*http.Cookie
	if observeOriginalSignup {
		originalURL, err := url.Parse(origin)
		if err != nil {
			t.Fatal("original signup origin unavailable")
		}
		originalSignupCookies = client.Jar.Cookies(originalURL)
		defer func() {
			for _, cookie := range originalSignupCookies {
				cookie.Value = ""
			}
		}()
	}
	expectSignupUnknown := observeOriginalSignup && len(faults) == 1 && faults[0].signup
	if expectSignupUnknown {
		faults[0].armed.Store(true)
	}
	graph.signupObservation.begin()
	status, body, _, cookies := call("/v1/password/signup", map[string]any{"flowID": string(flow.FlowID), "email": address, "password": candidate, "callbackURL": origin + "/confirm"}, "oauth-original-signup")
	signupObservation := graph.signupObservation.end()
	var signup passwordhttp.SignupResponse
	signupDecode := json.Unmarshal(body, &signup)
	if expectSignupUnknown && (!faults[0].hit.Load() || status != 503 || signupDecode != nil || signup.CommitOutcome != "unknown" || signup.Recovery == nil) {
		t.Fatalf("original signup did not reach unknown COMMIT boundary: hit=%t status=%d decoded=%t unknown=%t recovery_present=%t", faults[0].hit.Load(), status, signupDecode == nil, signup.CommitOutcome == "unknown", signup.Recovery != nil)
	}
	var signupEffects [4]int
	if expectSignupUnknown {
		signupEffects = originalSignupEffectCounts(t, ctx, pool)
		if signupEffects != ([4]int{1, 1, 1, 1}) {
			t.Fatal("unknown original signup did not retain exactly one registration, credential, delivery and capability")
		}
	}
	knownSignup := status == 200 && signupDecode == nil && signup.VerificationRequired && signup.CommitOutcome == "committed"
	if observeOriginalSignup && signupDecode == nil && signup.CommitOutcome == "unknown" {
		knownSignup = observeOriginalSignupRecovery(t, ctx, graph, origin, secrets["http-device"], flow.FlowID, originalSignupCookies, signup)
	}
	if !knownSignup || len(cookies) != 0 {
		if signupDecode == nil && signup.CommitOutcome == "unknown" {
			observeUnresolvedSignupJournal(t, ctx, pool, signup.CommandID)
			logPasswordFixtureObservation(t, signupObservation)
		}
		t.Fatalf("real signup did not require verification: status=%d decoded=%t unavailable=%t outcome_unknown=%t outcome_none=%t command_present=%t recovery_present=%t parent_done=%t", status, signupDecode == nil, signup.Error == "unavailable", signup.CommitOutcome == "unknown", signup.CommitOutcome == "none", signup.CommandID != "", signup.Recovery != nil, ctx.Err() != nil)
	}
	if expectSignupUnknown && originalSignupEffectCounts(t, ctx, pool) != signupEffects {
		t.Fatal("original signup recovery duplicated or changed protected effects")
	}
	if _, err := graph.workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("native registration worker failed", err)
	}
	mailbox.mu.Lock()
	link := mailbox.body
	mailbox.mu.Unlock()
	parsed, err := url.Parse(link)
	if err != nil || parsed.Query().Get("token") == "" {
		t.Fatal("registration email did not carry the real capability")
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	status, body, _, cookies = call("/v1/email/verification-confirm", map[string]string{"token": parsed.Query().Get("token"), "callback": origin + "/confirm", "commandID": string(command)}, "")
	var confirmation emailhttp.ConfirmationResponse
	if status != 200 || json.Unmarshal(body, &confirmation) != nil || !confirmation.Confirmed || confirmation.CommitOutcome != "committed" || len(cookies) != 0 {
		t.Fatal("real confirmation failed or minted a session", status)
	}
	flow = preauth("password")
	graph.signupObservation.begin()
	status, body, headers, cookies := call("/v1/password/signin", map[string]any{"flowID": string(flow.FlowID), "identifier": address, "password": candidate, "callbackURL": origin + "/confirm"}, "")
	signinObservation := graph.signupObservation.end()
	var signed passwordhttp.SigninResponse
	signinDecode := json.Unmarshal(body, &signed)
	if status != 200 || signinDecode != nil || !signed.SignedIn || signed.CommitOutcome != "committed" || len(cookies) != 1 {
		logPasswordFixtureObservation(t, signinObservation)
		t.Fatalf("real password sign-in failed: status=%d decoded=%t unavailable=%t outcome_unknown=%t outcome_none=%t command_present=%t recovery_present=%t parent_done=%t", status, signinDecode == nil, signed.Error == "unavailable", signed.CommitOutcome == "unknown", signed.CommitOutcome == "none", signed.CommandID != "", signed.Recovery != nil, ctx.Err() != nil)
	}
	// These are the existing native owners' standalone allocations, also used
	// by the reference password-change/enrollment composition. Selecting OAuth
	// must not require those feature implementations merely for common custody.
	kernelBase := kernel.CounterPreparationMigrationSource{Base: graph.stores.MigrationSource(), Version: 1700}
	kernelSteps, err := (kernel.OAuthReauthenticationMigrationSource{Base: kernelBase, Version: 1701}).Load(ctx)
	if err != nil {
		t.Fatal("native preparation source unavailable", err)
	}
	riskBase := riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "risk_store", Version: 1}, Version: 2}, Version: 3}, Version: 4}
	riskSteps, err := (riskpg.LockoutMigrationSource{Base: riskBase, Version: 5}).Load(ctx)
	if err != nil {
		t.Fatal("native lockout source unavailable", err)
	}
	extensions := []struct {
		namespace string
		steps     []migrations.Migration
	}{{"identity_risk_lockouts", riskSteps[len(riskSteps)-1:]}}
	if !change {
		extensions = append(extensions, struct {
			namespace string
			steps     []migrations.Migration
		}{"identity_password_change_kernel", kernelSteps[len(kernelSteps)-2 : len(kernelSteps)-1]})
	}
	extensions = append(extensions, struct {
		namespace string
		steps     []migrations.Migration
	}{"identity_oauth_reauthentication", kernelSteps[len(kernelSteps)-1:]})
	for _, extension := range extensions {
		var terminalBefore terminalMigrationSnapshot
		if extension.namespace == "identity_oauth_reauthentication" {
			terminalBefore = terminalMigrationState(t, ctx, pool)
		}
		owner, err := migrationdb.New(sqlDB)
		if err != nil {
			t.Fatal(err)
		}
		owner, err = owner.ForNamespace(extension.namespace)
		if err != nil {
			t.Fatal(err)
		}
		runner, err := migrations.NewRunner(fixtureHistory(extension.steps), owner)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal("native common-custody migration failed", err)
		}
		if extension.namespace == "identity_oauth_reauthentication" {
			requireTerminalMigrationPreserved(t, ctx, pool, terminalBefore)
		}
	}
	browser := auth.NewBearerCredential(cookies[0].Value)
	csrf, err := session.ParseCSRFToken(headers.Get("X-CSRF-Token"))
	if err != nil {
		t.Fatal("session synchronizer custody failed")
	}
	material := func(name string) []byte { key := secrets[name]; return append([]byte(nil), key[:]...) }
	lookup, err := session.NewDigestKey(11, material("session-token"))
	if err != nil {
		t.Fatal(err)
	}
	csrfKey, err := session.NewCSRFKey(12, material("session-csrf"))
	if err != nil {
		t.Fatal(err)
	}
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "local-baseline", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	sessionConfig := sessionpg.SessionServiceConfig{Repository: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "local-baseline", Clock: clock.System{}, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}}
	sessions, err := sessionpg.NewSessionService(pool, sessionConfig)
	if err != nil {
		t.Fatal("actual primary session reader failed", err)
	}
	issuer, err := oauth.NewIssuer(origin)
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := oauth.NewScopeCatalog([]string{"identity:read", "identity:write"})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := oauth.NewPlatformOwner("deployment")
	if err != nil {
		t.Fatal(err)
	}
	clients := []oauth.Client{{ID: "public-web", Public: true, AuthenticationMethod: "none", Owner: owner, Version: 1, Redirects: []string{"https://client.example/callback"}, Scopes: scopes.Scopes(), Resource: "https://resource.example"}}
	other := clients[0]
	other.ID = "other-public-web"
	clients = append(clients, other)
	protocol := oauth.Config{Issuer: issuer, Environment: "native-test", Resource: "https://resource.example", Scopes: scopes, Clients: clients, Clock: clock.System{}, MaximumDuration: 4 * time.Second, CodeTTL: time.Minute, ContinuationTTL: time.Minute, AccessTTL: time.Minute, RefreshTTL: time.Hour}
	authorize, err := fixtureAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Clock: clock.System{}, Authorization: authorize, PolicyVersion: 9}
	coordinator := kernel.CoordinatorConfig{MaximumDuration: 4 * time.Second, LeaseDuration: 5 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: secrets["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}
	requestKeys, err := kernel.NewRequestKeyConfig("oauth-native", secrets["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := baselineRiskPolicy(9, false, false)
	if err != nil {
		t.Fatal(err)
	}
	digestKey, err := risk.NewCounterDigestKey(1, material("counter"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := risk.NewEvidenceKey(1, material("risk-evidence"), material("risk-seal"))
	if err != nil {
		t.Fatal(err)
	}
	tokenKey, err := oauth.NewTokenDigestKey(1, material("oauth-token"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.New(map[string][]byte{"oauth-envelope": material("oauth-envelope"), "oauth-envelope-next": material("oauth-envelope-next")})
	if err != nil {
		t.Fatal(err)
	}
	config := oauthpostgres.Config{Schema: "oauth_store", Protocol: protocol, Session: sessionConfig, CSRFKeys: []session.CSRFKey{csrfKey}, TokenKeys: []oauth.TokenDigestKey{tokenKey}, ActiveTokenKeyVersion: 1, IntentKey: secrets["oauth-intent"], ActiveEnvelopeKeyID: "oauth-envelope", Coordinator: coordinator, RequestKeys: requestKeys, PolicyID: "oauth-native", Counters: riskpg.Config{Schema: "risk_store", PolicyVersion: 9, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": material("counter-envelope")}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: protected, Keys: []risk.CounterDigestKey{digestKey}}, EnforceLockouts: true}}
	signOut := func() {
		status, body, _, _ := call("/v1/session/signout", map[string]string{}, "", headers.Get("X-CSRF-Token"))
		var result sessionhttp.SignOutResponse
		if status != 200 || json.Unmarshal(body, &result) != nil || !result.SignedOut || result.CommitOutcome != "committed" {
			t.Fatal("real native browser signout failed", status)
		}
	}
	var changePassword func()
	if change {
		changePassword = func() {
			status, body, _, _ := call("/v1/password/verify", map[string]string{"password": candidate, "purpose": "identity.password.verify", "action": "identity.password.change", "audience": "oauth-credential-withdrawal"}, "", headers.Get("X-CSRF-Token"))
			var verified passwordhttp.VerificationResponse
			if status != 200 || json.Unmarshal(body, &verified) != nil || !verified.Verified || verified.Proof == nil || verified.CommitOutcome != "committed" {
				t.Fatal("real password reauthentication failed", status)
			}
			var fresh [32]byte
			if _, err := rand.Read(fresh[:]); err != nil {
				t.Fatal("replacement entropy unavailable")
			}
			status, body, _, _ = call("/v1/password/change", map[string]string{"proofID": verified.Proof.ProofID, "newPassword": hex.EncodeToString(fresh[:])}, "oauth-native-credential-withdrawal", headers.Get("X-CSRF-Token"))
			clear(fresh[:])
			var replaced passwordhttp.ChangeResponse
			if status != 200 || json.Unmarshal(body, &replaced) != nil || !replaced.Changed || replaced.CommitOutcome != "committed" {
				t.Fatal("real native credential replacement failed", status)
			}
		}
	}
	signInAgain := func() (auth.BearerCredential, session.CSRFToken) {
		flow := preauth("password")
		status, body, headers, cookies := call("/v1/password/signin", map[string]any{"flowID": string(flow.FlowID), "identifier": address, "password": candidate, "callbackURL": origin + "/confirm"}, "")
		var result passwordhttp.SigninResponse
		if status != 200 || json.Unmarshal(body, &result) != nil || !result.SignedIn || result.CommitOutcome != "committed" || len(cookies) != 1 {
			t.Fatal("second genuine browser sign-in failed", status)
		}
		csrf, err := session.ParseCSRFToken(headers.Get("X-CSRF-Token"))
		if err != nil {
			t.Fatal("second genuine browser synchronizer missing")
		}
		return auth.NewBearerCredential(cookies[0].Value), csrf
	}
	anotherUser := func() (auth.BearerCredential, session.CSRFToken) {
		// A separate browser performs the same public registration/confirmation/
		// sign-in journey. No identity/session rows or authority are fabricated.
		previous := client.Jar
		client.Jar, _ = cookiejar.New(nil)
		defer func() { client.Jar = previous }()
		mailbox.mu.Lock()
		mailbox.body = ""
		mailbox.mu.Unlock()
		var candidateBytes [32]byte
		if _, err := rand.Read(candidateBytes[:]); err != nil {
			t.Fatal("second-user entropy unavailable")
		}
		password := hex.EncodeToString(candidateBytes[:])
		address := "oauth-other-" + hex.EncodeToString(candidateBytes[:8]) + "@example.invalid"
		clear(candidateBytes[:])
		flow := preauth("signup")
		status, body, _, cookies := call("/v1/password/signup", map[string]any{"flowID": string(flow.FlowID), "email": address, "password": password, "callbackURL": origin + "/confirm"}, "oauth-other-signup")
		var registered passwordhttp.SignupResponse
		if status != 200 || json.Unmarshal(body, &registered) != nil || !registered.VerificationRequired || registered.CommitOutcome != "committed" || len(cookies) != 0 {
			t.Fatal("second-user real registration failed", status)
		}
		if _, err := graph.workers.ProcessDeliveryOne(ctx, 0); err != nil {
			t.Fatal("second-user native delivery failed", err)
		}
		mailbox.mu.Lock()
		link := mailbox.body
		mailbox.mu.Unlock()
		parsed, err := url.Parse(link)
		if err != nil || parsed.Query().Get("token") == "" {
			t.Fatal("second-user real confirmation missing")
		}
		command, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		status, body, _, cookies = call("/v1/email/verification-confirm", map[string]string{"token": parsed.Query().Get("token"), "callback": origin + "/confirm", "commandID": string(command)}, "")
		var confirmed emailhttp.ConfirmationResponse
		if status != 200 || json.Unmarshal(body, &confirmed) != nil || !confirmed.Confirmed || confirmed.CommitOutcome != "committed" || len(cookies) != 0 {
			t.Fatal("second-user real confirmation failed", status)
		}
		flow = preauth("password")
		status, body, headers, cookies := call("/v1/password/signin", map[string]any{"flowID": string(flow.FlowID), "identifier": address, "password": password, "callbackURL": origin + "/confirm"}, "")
		var signed passwordhttp.SigninResponse
		if status != 200 || json.Unmarshal(body, &signed) != nil || !signed.SignedIn || signed.CommitOutcome != "committed" || len(cookies) != 1 {
			t.Fatal("second-user real sign-in failed", status)
		}
		csrf, err := session.ParseCSRFToken(headers.Get("X-CSRF-Token"))
		if err != nil {
			t.Fatal(err)
		}
		return auth.NewBearerCredential(cookies[0].Value), csrf
	}
	phoneKeys, err := keyring.New(map[string][]byte{"delivery-envelope": material("delivery-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	phoneCandidate := []byte(candidate)
	phoneSessionKey := material("session-token")
	t.Cleanup(func() { clear(phoneCandidate); clear(phoneSessionKey) })
	return authenticatedPasswordFixture{ctx: ctx, pool: pool, tenant: baselineTenant, browser: browser, csrf: csrf, sessions: sessions, keys: keys, oauth: config, signOut: signOut, changePassword: changePassword, signInAgain: signInAgain, anotherUser: anotherUser,
		phoneInput: &nativePhoneInput{signin: graph.signin, signup: graph.signup, hibp: graph.hibp, keys: phoneKeys, password: phoneCandidate, sessionKey: phoneSessionKey}}
}

func logPasswordFixtureObservation(t *testing.T, o signupFixtureObservationValue) {
	t.Helper()
	t.Logf("password primitive observation: active=%t observed=%t hash_operation=%t verify_operation=%t success=%t canceled=%t resource_rejected=%t failed=%t mismatch=%t malformed=%t unsupported=%t upgraded=%t unexpected=%t duration=%s context_deadline=%t context_canceled=%t", o.active, o.hashObserved, o.hashOperation, o.verifyOperation, o.hashSuccess, o.hashCanceled, o.hashResourceRejected, o.hashFailed, o.hashMismatch, o.hashMalformed, o.hashUnsupported, o.hashUpgraded, o.hashUnexpected, o.hashDuration, o.hashDeadline, o.hashContextCanceled)
	t.Logf("password collect observation: active=%t entered=%t returned=%t failed=%t duration=%s context_deadline=%t context_canceled=%t", o.active, o.collectEntered, o.collectReturned, o.collectFailed, o.collectDuration, o.collectDeadline, o.collectCanceled)
}

func originalSignupEffectCounts(t *testing.T, ctx context.Context, pool *database.Pool) (counts [4]int) {
	t.Helper()
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.registration_bindings),(SELECT count(*) FROM identity_password.credentials),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM capability_identity_one_use)`).Scan(&counts[0], &counts[1], &counts[2], &counts[3]); err != nil {
		t.Fatal("original signup protected effect counts unavailable")
	}
	return counts
}

// An unresolved original observation must fail, but the fixture drops its DB
// during cleanup. Retain only closed state and custody-presence diagnostics so
// a failed signup can be located without retaining its input or retrying it.
func observeUnresolvedSignupJournal(t *testing.T, ctx context.Context, pool *database.Pool, command identity.CommandID) {
	t.Helper()
	if _, err := identity.ParseCommandID(string(command)); err != nil {
		t.Log("unresolved signup journal: command_valid=false")
		return
	}
	id, err := base64.RawURLEncoding.DecodeString(string(command))
	if err != nil {
		t.Log("unresolved signup journal: command_encoding_valid=false")
		return
	}
	defer clear(id)
	bounded, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	var state string
	var plan, profile, started, preparation, terminal, result, class, liveLease bool
	var counts [4]int
	err = pool.Raw().QueryRow(bounded, `SELECT
		CASE state WHEN 'pending' THEN 'pending' WHEN 'committed' THEN 'committed' WHEN 'aborted' THEN 'aborted' ELSE 'unexpected' END,
		command_plan IS NOT NULL,preparation_profile IS NOT NULL,preparation_started_generation IS NOT NULL,preparation_ciphertext IS NOT NULL,
		terminal_at IS NOT NULL,result IS NOT NULL,terminal_class IS NOT NULL,lease_until>clock_timestamp(),
		(SELECT count(*) FROM identity.registration_bindings),(SELECT count(*) FROM identity_password.credentials),
		(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM capability_identity_one_use)
		FROM identity.commands WHERE command_id=$1 AND tenant_id=$2 AND purpose='identity.password.signup'`, id, baselineTenant).Scan(&state, &plan, &profile, &started, &preparation, &terminal, &result, &class, &liveLease, &counts[0], &counts[1], &counts[2], &counts[3])
	if err != nil {
		t.Logf("unresolved signup journal: read=false deadline=%t canceled=%t error_type=%T", errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), err)
		return
	}
	switch state {
	case "pending", "committed", "aborted":
	default:
		state = "unexpected"
	}
	t.Logf("unresolved signup journal: read=true state=%s plan=%t profile=%t started=%t preparation=%t terminal=%t result=%t class=%t live_lease=%t registration_count=%d credential_count=%d delivery_count=%d capability_count=%d", state, plan, profile, started, preparation, terminal, result, class, liveLease, counts[0], counts[1], counts[2], counts[3])
}

// The public SignupService permits unknown; RecoverSignup authenticates original
// cookie possession without a password or reexecution (password@19670fe0ec13).
// A committed acknowledgement or this exact-original observation must precede
// verification; an uncertain observation cannot authorize fixture continuation.
func observeOriginalSignupRecovery(t *testing.T, ctx context.Context, graph *baselineGraph, origin string, deviceMaterial [32]byte, flow identity.PreAuthTransactionID, cookies []*http.Cookie, first passwordhttp.SignupResponse) bool {
	t.Helper()
	q := first.Recovery
	if q == nil || q.CommandID != first.CommandID || q.FlowID != flow || q.TenantID != baselineTenant || q.ActorID != baselineActor || q.ActorKind != authorization.SubjectServiceAccount {
		t.Fatal("unknown signup omitted original recovery binding")
	}
	recovery, err := password.NewSignupRecovery(identity.RecoveryQuery{CommandID: q.CommandID, TenantID: q.TenantID, AnonymousFlowID: string(flow), ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: "identity.password.signup"}, flow)
	if err != nil {
		t.Fatal("unknown signup recovery shape invalid")
	}
	var possessed auth.BearerCredential
	var deviceToken string
	for _, cookie := range cookies {
		switch cookie.Name {
		case "__Host-identity_flow":
			possessed = auth.NewBearerCredential(cookie.Value)
		case "__Host-identity_device":
			deviceToken = cookie.Value
		}
	}
	deviceCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal("original device policy unavailable")
	}
	deviceKey, err := session.NewBrowserDeviceKey(1, deviceMaterial[:])
	if err != nil {
		t.Fatal("original device key unavailable")
	}
	// This is the unchanged HTTPPreAuth device configuration in fixtureGraph;
	// Resolve authenticates the possessed cookie and cannot issue or renew it.
	devices, err := session.NewBrowserDeviceCodec(session.BrowserDeviceConfig{Namespace: "local-baseline", Keys: []session.BrowserDeviceKey{deviceKey}, ActiveVersion: 1, Lifetime: 24 * time.Hour, Cookie: deviceCookie})
	if err != nil {
		t.Fatal("original device codec unavailable")
	}
	device, err := devices.Resolve(ctx, time.Now().UTC(), baselineTenant, origin, deviceToken)
	if err != nil {
		t.Fatal("original device possession unavailable")
	}
	trustedOrigin, err := url.Parse(origin)
	if err != nil {
		t.Fatal("original signup provenance unavailable")
	}
	owner, err := graph.features.PasswordSignup()
	if err != nil {
		t.Fatal("original signup owner unavailable")
	}
	caller := authorization.DecisionContext{CorrelationID: "oauth-original-signup-recovery", PolicyRevision: authorization.Revision(graph.signup.Coordinator.QueryPolicy.PolicyVersion), Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: authorization.SubjectID(baselineActor)}, Tenant: authorization.TenantID(baselineTenant), Action: "identity.password.signup", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.signup"}}}
	history, recoveryErr := owner.RecoverSignup(ctx, password.SignupRecoveryRequest{Recovery: recovery, Cookie: possessed, Caller: caller, Origin: origin, Network: trustedOrigin.Hostname(), Device: device.DeviceID()})
	historyQuery, historyFlow, bindingErr := history.Recovery.Bindings()
	originalQuery, _, _ := recovery.Bindings()
	valid := history.Validate() == nil && bindingErr == nil && historyQuery == originalQuery && historyFlow == flow
	noCredentials := history.SubjectID == "" && history.SessionID == "" && history.Session.CommandID == "" && history.Session.Token == (session.Token{}) && history.CSRFToken == (session.CSRFToken{})
	committed := recoveryErr == nil && valid && noCredentials && history.Replayed && history.VerificationRequired && history.Outcome == identity.CommitOutcomeCommitted
	t.Logf("original signup recovery: valid=%t committed=%t not_committed=%t unknown=%t in_progress=%t replayed=%t no_credentials=%t error_type=%T parent_done=%t", valid, committed, history.Outcome == identity.CommitOutcomeNotCommitted, history.Outcome == identity.CommitOutcomeUnknown, history.Outcome == identity.CommitOutcomeInProgress, history.Replayed, noCredentials, recoveryErr, ctx.Err() != nil)
	return committed
}

// This bounded test-only Source composes immutable Migration values returned
// by their actual public owners; it contains no copied SQL or migration engine.
type fixtureHistory []migrations.Migration

func (s fixtureHistory) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil {
		return nil, identity.InvalidInputError{Field: "fixture_migrations"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]migrations.Migration(nil), s...), nil
}
