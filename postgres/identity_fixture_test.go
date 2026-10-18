//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
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
	graph, err := fixtureGraph(ctx, origin, secrets, pool, mailbox, hibpTransport{}, change)
	if err != nil {
		var invalid identity.InvalidInputError
		if errors.As(err, &invalid) && len(invalid.Field) <= 128 && strings.IndexFunc(invalid.Field, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '.') }) < 0 {
			t.Fatal("real public identity graph rejected configuration field", invalid.Field)
		}
		t.Fatal("real public identity graph rejected", err)
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
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("identity HTTPS request unavailable")
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
	status, body, _, cookies := call("/v1/password/signup", map[string]any{"flowID": string(flow.FlowID), "email": address, "password": candidate, "callbackURL": origin + "/confirm"}, "oauth-original-signup")
	var signup passwordhttp.SignupResponse
	if status != 200 || json.Unmarshal(body, &signup) != nil || !signup.VerificationRequired || signup.CommitOutcome != "committed" || len(cookies) != 0 {
		t.Fatal("real signup did not require verification", status)
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
	status, body, headers, cookies := call("/v1/password/signin", map[string]any{"flowID": string(flow.FlowID), "identifier": address, "password": candidate, "callbackURL": origin + "/confirm"}, "")
	var signed passwordhttp.SigninResponse
	if status != 200 || json.Unmarshal(body, &signed) != nil || !signed.SignedIn || signed.CommitOutcome != "committed" || len(cookies) != 1 {
		t.Fatal("real password sign-in failed", status)
	}
	// These are the existing native owners' standalone allocations, also used
	// by the reference password-change/enrollment composition. Selecting OAuth
	// must not require those feature implementations merely for common custody.
	kernelSteps, err := (kernel.CounterPreparationMigrationSource{Base: graph.stores.MigrationSource(), Version: 1700}).Load(ctx)
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
		}{"identity_password_change_kernel", kernelSteps[len(kernelSteps)-1:]})
	}
	for _, extension := range extensions {
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
	return authenticatedPasswordFixture{ctx: ctx, pool: pool, tenant: baselineTenant, browser: browser, csrf: csrf, sessions: sessions, keys: keys, oauth: config, signOut: signOut, changePassword: changePassword, signInAgain: signInAgain, anotherUser: anotherUser}
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
