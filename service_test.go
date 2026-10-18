package oauthserver_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauthserver "github.com/faustbrian/go-oauth-server"
)

type clockFunc func() time.Time

func (f clockFunc) Now() time.Time { return f() }

type sessionReader func(context.Context, session.SessionLookup) (session.SessionObservation, error)

func (f sessionReader) ObserveSession(ctx context.Context, q session.SessionLookup) (session.SessionObservation, error) {
	return f(ctx, q)
}

// This double exercises core delegation only. It is not OAuth persistence or
// evidence of native identity authentication; PostgreSQL consumers prove those.
type authorizationStore struct {
	oauthserver.Store
	call func(context.Context, oauthserver.AuthorizationCommand) (oauthserver.AuthorizeResult, error)
}

func (s authorizationStore) Authorize(ctx context.Context, c oauthserver.AuthorizationCommand) (oauthserver.AuthorizeResult, error) {
	return s.call(ctx, c)
}

func coreSessionFixture(t *testing.T) (*session.SessionService, auth.BearerCredential, time.Time, *session.SessionObservation) {
	t.Helper()
	now := time.Date(2026, 10, 18, 2, 0, 0, 0, time.UTC)
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	token, _ := session.NewToken(32)
	wire, _ := token.Reveal()
	digest, _ := token.Digest(key, "tenant")
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{
		Global: session.AuthorityBinding{ScopeKey: "global", Version: 1}, Tenant: session.AuthorityBinding{ScopeKey: "tenant", Version: 1}, User: session.AuthorityBinding{ScopeKey: "user", Version: 1}, Identifier: session.AuthorityBinding{ScopeKey: "identifier", Version: 1}, Credential: session.AuthorityBinding{ScopeKey: "credential", Version: 1}, SessionFamily: session.AuthorityBinding{ScopeKey: "family", Version: 1}, Session: session.AuthorityBinding{ScopeKey: "session", Version: 1}, Authorization: session.AuthorityBinding{ScopeKey: "authorization", Version: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(session.SessionSpec{SessionID: "session", FamilyID: "family", TenantID: "tenant", UserID: "user", Audience: "identity-service", Version: 1, FamilyVersion: 1, Remember: remember, Authority: snapshot, Lookup: digest, IssuedAt: now, LastActivityAt: now, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant", Subject: "user", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity-service", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	observation := &session.SessionObservation{Session: record, Current: snapshot, Active: true, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second)}
	reader := sessionReader(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		return *observation, nil
	})
	service, err := session.NewSessionService(reader, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity-service", Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	return service, auth.NewBearerCredential(wire), now, observation
}

func coreConfig(t *testing.T, now time.Time) oauthserver.Config {
	t.Helper()
	issuer, _ := oauthserver.NewIssuer("https://issuer.example")
	owner, _ := oauthserver.NewPlatformOwner("platform")
	scopes, _ := oauthserver.NewScopeCatalog([]string{"identity:read", "identity:write"})
	return oauthserver.Config{Issuer: issuer, Environment: "test", Resource: "https://resource.example", Scopes: scopes, Clients: []oauthserver.Client{{ID: "public-client", Owner: owner, Version: 1, Public: true, AuthenticationMethod: "none", Redirects: []string{"https://client.example/cb"}, Scopes: []string{"identity:read"}, Resource: "https://resource.example"}}, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second, CodeTTL: time.Minute, ContinuationTTL: time.Minute, AccessTTL: 5 * time.Minute, RefreshTTL: 24 * time.Hour}
}

func coreAuthorization() oauthserver.AuthorizationRequest {
	return oauthserver.AuthorizationRequest{ClientID: "public-client", RedirectURI: "https://client.example/cb", Resource: "https://resource.example", Scopes: []string{"identity:read"}, State: "original-state", CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}
}

func TestAuthorizeUsesActualSessionCustodyAndPreservesDeadline(t *testing.T) {
	sessions, bearer, now, observed := coreSessionFixture(t)
	calls := 0
	store := authorizationStore{call: func(ctx context.Context, c oauthserver.AuthorizationCommand) (oauthserver.AuthorizeResult, error) {
		calls++
		if _, bounded := ctx.Deadline(); !bounded || c.Session.ValidateAt(now) != nil || c.Session.ValidUntil() != observed.ValidUntil.Add(-time.Millisecond) || c.Request.State != "original-state" {
			t.Fatal("missing genuine custody or renewed original deadline")
		}
		spec, _ := c.Session.Session.Bindings()
		if spec.UserID != "user" || spec.TenantID != "tenant" || c.Request.Resource != "https://resource.example" {
			t.Fatal("caller selected another subject or audience")
		}
		continuation, err := oauthserver.NewToken()
		return oauthserver.AuthorizeResult{Outcome: oauthserver.ConsentRequired, Continuation: continuation, ExpiresAt: now.Add(time.Minute)}, err
	}}
	service, err := oauthserver.NewService(coreConfig(t, now), oauthserver.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Authorize(context.Background(), oauthserver.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: coreAuthorization(), Network: "127.0.0.1"})
	if err != nil || result.Outcome != oauthserver.ConsentRequired || calls != 1 {
		t.Fatal("authenticated authorization not delegated", err)
	}
	observed.Active = false
	result, err = service.Authorize(context.Background(), oauthserver.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: coreAuthorization(), Network: "127.0.0.1"})
	if err != nil || result.Outcome != oauthserver.LoginRequired || calls != 1 {
		t.Fatal("inactive source reached OAuth persistence", err)
	}
}

func TestAuthorizeRejectsForeignRedirectScopesBeforeStateMutation(t *testing.T) {
	sessions, bearer, now, _ := coreSessionFixture(t)
	store := authorizationStore{call: func(context.Context, oauthserver.AuthorizationCommand) (oauthserver.AuthorizeResult, error) {
		t.Fatal("invalid request reached persistence")
		return oauthserver.AuthorizeResult{}, nil
	}}
	service, err := oauthserver.NewService(coreConfig(t, now), oauthserver.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*oauthserver.AuthorizationRequest){
		func(r *oauthserver.AuthorizationRequest) { r.RedirectURI = "https://attacker.example/cb" },
		func(r *oauthserver.AuthorizationRequest) { r.ClientID = "foreign" },
		func(r *oauthserver.AuthorizationRequest) { r.Scopes = []string{"identity:write"} },
		func(r *oauthserver.AuthorizationRequest) { r.Resource = "https://unregistered.example" },
		func(r *oauthserver.AuthorizationRequest) { r.CodeChallenge = "plain" },
	} {
		r := coreAuthorization()
		change(&r)
		result, err := service.Authorize(context.Background(), oauthserver.AuthorizeRequest{TenantID: identity.TenantID("tenant"), Session: bearer, Request: r, Network: "127.0.0.1"})
		if err == nil || result.Outcome != 0 || result.RedirectURI != "" {
			t.Fatal("unvalidated redirect or request produced authority")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Authorize(ctx, oauthserver.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: coreAuthorization(), Network: "127.0.0.1"}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not preserved", err)
	}
}

func TestTypedAuthorizationPreservesWireScopeBudget(t *testing.T) {
	sessions, bearer, now, _ := coreSessionFixture(t)
	config := coreConfig(t, now)
	var scopes []string
	for _, prefix := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		scopes = append(scopes, prefix+strings.Repeat("x", 127))
	}
	var err error
	config.Scopes, err = oauthserver.NewScopeCatalog(scopes)
	if err != nil {
		t.Fatal(err)
	}
	config.Clients[0].Scopes = scopes
	called := false
	store := authorizationStore{call: func(context.Context, oauthserver.AuthorizationCommand) (oauthserver.AuthorizeResult, error) {
		called = true
		return oauthserver.AuthorizeResult{}, nil
	}}
	service, err := oauthserver.NewService(config, oauthserver.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	request := coreAuthorization()
	request.Scopes = scopes
	_, err = service.Authorize(context.Background(), oauthserver.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: request, Network: "127.0.0.1"})
	if !errors.Is(err, oauthserver.ErrInvalidRequest) || called {
		t.Fatal("typed authorization bypassed the 1024-byte protocol scope budget")
	}
}

type tokenStore struct {
	oauthserver.Store
	call func(context.Context, oauthserver.TokenCommand) (oauthserver.TokenResult, error)
}

func (s tokenStore) Token(ctx context.Context, c oauthserver.TokenCommand) (oauthserver.TokenResult, error) {
	return s.call(ctx, c)
}

func TestTokenServiceRejectsWideningAndSuppressesUnknownSecrets(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	calls := 0
	store := tokenStore{call: func(ctx context.Context, c oauthserver.TokenCommand) (oauthserver.TokenResult, error) {
		calls++
		if _, bounded := ctx.Deadline(); !bounded || c.Client.ID != "public-client" || c.Request.GrantType != oauthserver.AuthorizationCodeGrant {
			t.Fatal("token operation lost bounded registered-client intent")
		}
		secret, _ := oauthserver.NewToken()
		return oauthserver.TokenResult{Outcome: identity.CommitOutcomeUnknown, AccessToken: secret, Resource: "https://resource.example", ExpiresAt: now.Add(time.Minute), Scopes: []string{"identity:read"}}, nil
	}}
	service, err := oauthserver.NewService(coreConfig(t, now), oauthserver.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	request := oauthserver.TokenRequest{GrantType: oauthserver.AuthorizationCodeGrant, ClientID: "public-client", Code: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", RedirectURI: "https://client.example/cb", CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", Network: "192.0.2.1"}
	result, err := service.Token(context.Background(), request)
	if !errors.Is(err, oauthserver.ErrUnavailable) || result.Outcome != identity.CommitOutcomeUnknown || result.AccessToken != (oauthserver.Token{}) || result.RefreshToken != (oauthserver.Token{}) || calls != 1 {
		t.Fatal("uncertain storage result disclosed fresh bearer or lost classification", err)
	}
	for _, change := range []func(*oauthserver.TokenRequest){
		func(r *oauthserver.TokenRequest) { r.RefreshToken = r.Code },
		func(r *oauthserver.TokenRequest) { r.Scopes = []string{"identity:read"} },
		func(r *oauthserver.TokenRequest) { r.Resource = "https://foreign.example" },
		func(r *oauthserver.TokenRequest) { r.GrantType = "urn:ietf:params:oauth:grant-type:token-exchange" },
		func(r *oauthserver.TokenRequest) { r.ClientID = "foreign" },
	} {
		changed := request
		change(&changed)
		if _, err := service.Token(context.Background(), changed); err == nil || calls != 1 {
			t.Fatal("invalid grant variant reached storage")
		}
	}
	if _, err := service.Token(context.Background(), oauthserver.TokenRequest{GrantType: oauthserver.RefreshTokenGrant, ClientID: "public-client", RefreshToken: request.Code, Scopes: []string{"identity:write"}}); err == nil || calls != 1 {
		t.Fatal("refresh expanded client scope")
	}
}

type introspectionStore struct {
	oauthserver.Store
	called *bool
}

func TestTokenRequiresTrustedNetworkOutsideTheParsedOAuthForm(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	calls := 0
	store := tokenStore{call: func(context.Context, oauthserver.TokenCommand) (oauthserver.TokenResult, error) {
		calls++
		return oauthserver.TokenResult{}, nil
	}}
	service, err := oauthserver.NewService(coreConfig(t, now), oauthserver.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	request, err := oauthserver.ParseTokenForm("grant_type=refresh_token&client_id=public-client&refresh_token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Token(context.Background(), request); !errors.Is(err, oauthserver.ErrInvalidRequest) || calls != 0 {
		t.Fatal("missing trusted attribution reached protected token counters")
	}
}

func (s introspectionStore) Introspect(context.Context, oauthserver.IntrospectionCommand) (oauthserver.IntrospectResult, error) {
	*s.called = true
	return oauthserver.IntrospectResult{Active: false, ClientID: "must-not-be-disclosed", Subject: "must-not-be-disclosed", Resource: "https://resource.example", Scopes: []string{"identity:read"}, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestUnselectedIntrospectionRejectsUnauthenticatedCallerBeforeTokenLookup(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	called := false
	service, err := oauthserver.NewService(coreConfig(t, now), oauthserver.Dependencies{Sessions: sessions, Store: introspectionStore{called: &called}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Introspect(context.Background(), oauthserver.IntrospectRequest{ClientID: "public-client", Token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if !errors.Is(err, oauthserver.ErrAccessDenied) || called || result.Active || result.ClientID != "" || result.Subject != "" || result.Resource != "" || result.Scopes != nil || !result.ExpiresAt.IsZero() {
		t.Fatal("unselected introspection used inspected token as its own authority", err)
	}
}
