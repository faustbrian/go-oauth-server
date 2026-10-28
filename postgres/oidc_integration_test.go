//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-clock"
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

func oidcFixture(t *testing.T, f *authenticatedPasswordFixture) (*oauth.Service, *op.Service, *oauth.SigningService, *oauthpostgres.Store, *ecdsa.PrivateKey) {
	return oidcFixtureWithClock(t, f, clock.System{})
}

func oidcFixtureWithClock(t *testing.T, f *authenticatedPasswordFixture, childClock oauth.Clock) (*oauth.Service, *op.Service, *oauth.SigningService, *oauthpostgres.Store, *ecdsa.PrivateKey) {
	return oidcFixtureWithLifecycle(t, f, childClock, nil)
}

func oidcFixtureWithLifecycle(t *testing.T, f *authenticatedPasswordFixture, childClock oauth.Clock, decorate func(oauth.SigningLifecycle) oauth.SigningLifecycle, installed ...migrations.Source) (*oauth.Service, *op.Service, *oauth.SigningService, *oauthpostgres.Store, *ecdsa.PrivateKey) {
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
	var base migrations.Source = oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}
	if f.oauth.ConsentManagement {
		base = oauthpostgres.ConsentMigrationSource{Base: base, Schema: "oauth_store", Version: 7002}
	}
	var source migrations.Source = oauthpostgres.SigningMigrationSource{Base: base, Schema: "oauth_store", Version: 7003}
	if f.oauth.RPInitiatedLogout {
		for _, client := range f.oauth.Protocol.Clients {
			if client.SubjectRegistration != nil {
				source = oauthpostgres.PairwiseMigrationSource{Base: source, Schema: "oauth_store", Version: 7004}
				break
			}
		}
	}
	if f.oauth.RPInitiatedLogout {
		if f.oauth.ConsentReuseTTL > 0 {
			// Keep expiry before logout's append-only suffix, including when
			// pairwise subject history already occupies version 7004.
			source = oauthpostgres.ConsentExpiryMigrationSource{Base: source, Schema: "oauth_store", Version: 7005}
		}
		source = oauthpostgres.EndSessionMigrationSource{Base: source, Schema: "oauth_store", Version: 7006}
	}
	if len(installed) > 0 {
		source = installed[0]
	}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("signing migration failed", err)
	}
	email := slices.Contains(f.oauth.Protocol.OIDCScopes.Scopes(), "email")
	phone := slices.Contains(f.oauth.Protocol.OIDCScopes.Scopes(), "phone")
	selectedScopes := []string{"openid"}
	if email {
		selectedScopes = append(selectedScopes, "email")
	}
	if phone {
		selectedScopes = append(selectedScopes, "phone")
	}
	f.oauth.Protocol.OIDCScopes, _ = oauth.NewOIDCScopeCatalog(selectedScopes)
	for i := range f.oauth.Protocol.Clients {
		if f.oauth.Protocol.Clients[i].Workload == nil {
			f.oauth.Protocol.Clients[i].Scopes = append(f.oauth.Protocol.Clients[i].Scopes, selectedScopes...)
		}
	}
	issuer := f.oauth.Protocol.Issuer.String()
	f.oauth.Protocol.Discovery = oauth.DiscoveryConfig{Enabled: true, AuthorizationEndpoint: issuer + "/oauth2/authorize", TokenEndpoint: issuer + "/oauth2/token", RevocationEndpoint: issuer + "/oauth2/revoke"}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	core, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store, Clients: store})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := oauth.NewSigningAuthority(f.oauth.Protocol.Clock, f.oauth.Protocol.AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	var lifecycle oauth.SigningLifecycle = store
	if decorate != nil {
		lifecycle = decorate(lifecycle)
	}
	signer, err := oauth.NewSigningService(authority, lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Install(f.ctx, "initial", key); err != nil {
		t.Fatal("native signing key installation failed", err)
	}
	if err := signer.Activate(f.ctx, "initial"); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("native unpublished key activated", err)
	}
	var subjectKey [32]byte
	if _, err := rand.Read(subjectKey[:]); err != nil {
		t.Fatal(err)
	}
	childConfig := op.Config{Issuer: f.oauth.Protocol.Issuer, JWKSURI: issuer + "/oauth2/jwks", UserInfoEndpoint: issuer + "/oauth2/userinfo", Signing: signer, SubjectKey: subjectKey, Clock: childClock, MaximumDuration: 4 * time.Second, EmailUserInfo: email, PhoneUserInfo: phone}
	if f.oauth.RPInitiatedLogout {
		childConfig.EndSessionEndpoint = issuer + "/oauth2/logout"
		// The actual initiating cookie policy is fixtureGraph's sessionCookie;
		// deletion must retain its name/scope/security, not select another cookie.
		childConfig.SessionCookie, _ = session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	}
	child, err := op.NewService(childConfig, core)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := child.JWKS(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := signer.Activate(f.ctx, "initial"); err != nil {
		t.Fatal(err)
	}
	composed, err := core.WithOIDC(child)
	if err != nil {
		t.Fatal(err)
	}
	return composed, child, signer, store, key
}

func oidcCode(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service, nonce string) (string, string) {
	t.Helper()
	verifier := oauth2.GenerateVerifier()
	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	scopes := append([]string{"identity:read"}, f.oauth.Protocol.OIDCScopes.Scopes()...)
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", Resource: "https://resource.example", Scopes: scopes, Nonce: nonce, CodeChallenge: challenge}})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("OIDC did not reach native consent", err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	approved, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true})
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("OIDC consent did not commit code", err)
	}
	location, err := approved.Location()
	if err != nil {
		t.Fatal(err)
	}
	callback, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() {
		t.Fatal("code response issuer mismatch")
	}
	return callback.Query().Get("code"), verifier
}

// go-oidc intentionally delegates nonce matching to its relying-party caller.
// This consumer uses its independently parsed/verified token and rejects a nonce
// mismatch before accepting login; issuer/audience/signature checks stay in RP.
func consumeIDToken(ctx context.Context, provider *rp.Provider, wire, nonce, client string) (*rp.IDToken, error) {
	verified, err := provider.Verifier(&rp.Config{ClientID: client, SupportedSigningAlgs: []string{"ES256"}}).Verify(ctx, wire)
	if err != nil {
		return nil, err
	}
	if verified.Nonce != nonce {
		return nil, errors.New("RP nonce mismatch")
	}
	return verified, nil
}

func TestNativeOIDCIndependentRelyingPartyAndCurrentAuthority(t *testing.T) {
	f := passwordFixture(t)
	service, child, signer, _, _ := oidcFixture(t, &f)
	transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := rp.ClientContext(f.ctx, client)
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal("independent RP discovery failed", err)
	}
	standard := oauth2.Config{ClientID: "public-web", RedirectURL: "https://client.example/callback", Scopes: []string{"identity:read", "openid"}, Endpoint: provider.Endpoint()}
	standard.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	verifier := oauth2.GenerateVerifier()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, standard.AuthCodeURL("rp-state", oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", "rp-original-nonce"), oauth2.SetAuthURLParam("resource", "https://resource.example")), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("RP authorization failed", err)
	}
	response.Body.Close()
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil || callback.Query().Get("state") != "rp-state" || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() {
		t.Fatal("RP callback binding failed")
	}
	token, err := standard.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal("RP real token exchange failed", err)
	}
	wire, ok := token.Extra("id_token").(string)
	if !ok {
		t.Fatal("RP did not receive ID token")
	}
	verified, err := consumeIDToken(ctx, provider, wire, "rp-original-nonce", "public-web")
	if err != nil {
		t.Fatal("independent RP rejected ID token", err)
	}
	var rawUser string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT user_id FROM oauth_store.grants LIMIT 1`).Scan(&rawUser); err != nil {
		t.Fatal(err)
	}
	if verified.Subject == "" || verified.Subject == rawUser {
		t.Fatal("public subject leaks raw identity")
	}
	var claims map[string]json.RawMessage
	if verified.Claims(&claims) != nil || len(claims) != 9 {
		t.Fatal("ID token claim minimization failed")
	}
	var authorizedParty string
	var authTime int64
	var methods []string
	if json.Unmarshal(claims["azp"], &authorizedParty) != nil || authorizedParty != "public-web" || json.Unmarshal(claims["auth_time"], &authTime) != nil || json.Unmarshal(claims["amr"], &methods) != nil || len(methods) != 1 || methods[0] != "pwd" {
		t.Fatal("verified client or authentication claims mismatch")
	}
	browserToken, err := session.ParseToken(f.browser.Token())
	if err != nil {
		t.Fatal(err)
	}
	browserCredential, err := session.NewCredential(session.CredentialCookie, browserToken)
	if err != nil {
		t.Fatal(err)
	}
	original, err := f.sessions.Get(ctx, session.GetRequest{TenantID: f.tenant, Credential: browserCredential})
	if err != nil || !original.Authenticated {
		t.Fatal("original source session unavailable", err)
	}
	bindings, err := original.Session.Bindings()
	if err != nil || authTime != bindings.Authentication.Proof.IssuedAt.Unix() {
		t.Fatal("ID-token auth_time did not preserve original native authentication")
	}
	for _, name := range []string{"email", "name", "phone_number", "address", "tenant", "user_id", "session_id"} {
		if _, exists := claims[name]; exists {
			t.Fatal("unconsented identity attribute exposed")
		}
	}
	if _, err := consumeIDToken(ctx, provider, wire, "wrong-nonce", "public-web"); err == nil {
		t.Fatal("RP accepted wrong nonce")
	}
	if _, err := consumeIDToken(ctx, provider, wire, "rp-original-nonce", "other-public-web"); err == nil {
		t.Fatal("RP accepted wrong audience")
	}
	wrongIssuer := rp.NewVerifier("https://foreign.example", rp.NewRemoteKeySet(ctx, f.oauth.Protocol.Issuer.String()+"/oauth2/jwks"), &rp.Config{ClientID: "public-web", SupportedSigningAlgs: []string{"ES256"}})
	if _, err := wrongIssuer.Verify(ctx, wire); err == nil {
		t.Fatal("RP accepted wrong issuer")
	}
	parts := strings.Split(wire, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var altered map[string]any
	_ = json.Unmarshal(payload, &altered)
	altered["nonce"] = "forged"
	replacement, _ := json.Marshal(altered)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(replacement) + "." + parts[2]
	if _, err := consumeIDToken(ctx, provider, tampered, "forged", "public-web"); err == nil {
		t.Fatal("RP accepted modified signature-bound nonce")
	}
	userinfoSource, err := service.UserInfoSource(ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: token.AccessToken})
	if err != nil {
		t.Fatal("native UserInfo source denied current grant", err)
	}
	if _, err := child.Claims(ctx, userinfoSource); err != nil {
		t.Fatal("child UserInfo subject projection denied native source", err)
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil || info.Subject != verified.Subject {
		t.Fatal("independent RP UserInfo subject mismatch", err)
	}
	if _, err := child.UserInfo(ctx, oauth.UserInfoRequest{ClientID: "other-public-web", AccessToken: token.AccessToken}); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("foreign client read UserInfo")
	}
	next, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := signer.Install(ctx, "rotated", next); err != nil {
		t.Fatal(err)
	}
	if _, err := child.JWKS(ctx); err != nil {
		t.Fatal(err)
	}
	if err := signer.Activate(ctx, "rotated"); err != nil {
		t.Fatal(err)
	}
	if err := signer.Retire(ctx, "initial"); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("native overlap ended before expiry")
	}
	code, proof := oidcCode(t, f, service, "rotated-nonce")
	issued, err := service.Token(ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: proof, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := issued.IDToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	rotatedVerified, err := consumeIDToken(ctx, provider, rotated, "rotated-nonce", "public-web")
	if err != nil || rotatedVerified.Subject != verified.Subject {
		t.Fatal("RP could not refresh to published rotation key", err)
	}
	if !rotatedVerified.Expiry.Equal(issued.ExpiresAt) {
		t.Fatal("verified ID-token deadline differs from native access/return deadline")
	}
	if _, err := consumeIDToken(ctx, provider, wire, "rp-original-nonce", "public-web"); err != nil {
		t.Fatal("rotation broke earlier token verification", err)
	}
	if _, err := service.Revoke(ctx, oauth.RevokeRequest{ClientID: "public-web", Token: token.AccessToken, Hint: oauth.TokenAccess, Network: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token)); err == nil {
		t.Fatal("revoked access token retained UserInfo authority")
	}
	if err := signer.Compromise(ctx, "rotated"); err != nil {
		t.Fatal(err)
	}
	rotatedAccess, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := child.UserInfo(ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: rotatedAccess}); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("compromised signing authority retained UserInfo")
	}
}

func TestNativeOIDCUnknownRollbackAndContentionNeverRedeliver(t *testing.T) {
	nativeOIDCTokenCommitModes(t, oidcFixture)
}

func TestNativeOIDCPairwiseTokenUnknownRollbackAndContentionNeverRedeliver(t *testing.T) {
	nativeOIDCTokenCommitModes(t, pairwiseFixture)
}

type oidcFixtureBuilder func(*testing.T, *authenticatedPasswordFixture) (*oauth.Service, *op.Service, *oauth.SigningService, *oauthpostgres.Store, *ecdsa.PrivateKey)

func nativeOIDCTokenCommitModes(t *testing.T, fixture oidcFixtureBuilder) {
	for _, mode := range []string{"unknown", "rollback", "contention"} {
		t.Run(mode, func(t *testing.T) {
			fault := &oauthCommitFault{before: mode == "rollback"}
			f := passwordFixture(t, fault)
			service, _, _, store, _ := fixture(t, &f)
			code, verifier := oidcCode(t, f, service, "transaction-nonce")
			request := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"}
			if mode == "contention" {
				var wg sync.WaitGroup
				results := make(chan oauth.TokenResult, 2)
				errs := make(chan error, 2)
				for range 2 {
					wg.Add(1)
					go func() { defer wg.Done(); result, err := service.Token(f.ctx, request); results <- result; errs <- err }()
				}
				wg.Wait()
				close(results)
				close(errs)
				fresh := 0
				for out := range results {
					if _, err := out.IDToken.Reveal(); err == nil {
						fresh++
					}
				}
				if fresh != 1 {
					t.Fatal("contending code minted multiple or no ID tokens", fresh)
				}
				for err := range errs {
					if err != nil && !errors.Is(err, oauth.ErrInvalidGrant) {
						t.Fatal("contention result unexpected", err)
					}
				}
			} else {
				fault.armed.Store(true)
				out, err := service.Token(f.ctx, request)
				if !fault.hit.Load() || err == nil || out.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("actual token commit fault was not unknown", err)
				}
				if _, err := out.IDToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
					t.Fatal("uncertain token exposed ID token")
				}
				recovered, err := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: out.CommandID, ClientID: "public-web", Token: code})
				if err != nil || recovered.CommandID != out.CommandID {
					t.Fatal("original native token reconciliation failed", err)
				}
				var active int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE kind=3`).Scan(&active); err != nil {
					t.Fatal(err)
				}
				if mode == "rollback" && active != 0 || mode == "unknown" && active != 1 {
					t.Fatal("commit fault did not preserve atomic token effect", active)
				}
			}
			replay, err := service.Token(f.ctx, request)
			if _, exposed := replay.IDToken.Reveal(); exposed == nil {
				t.Fatal("historical/ambiguous replay minted fresh ID token")
			}
			if mode != "rollback" && err == nil {
				t.Fatal("spent code replay accepted")
			}
			if f.oauth.Protocol.Clients[0].SubjectRegistration != nil {
				var bindings int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.subject_bindings`).Scan(&bindings); err != nil || bindings != 1 {
					t.Fatal("token retry/fault changed the original durable subject binding", err)
				}
			}
		})
	}
}

func TestNativeOIDCUserInfoDeniesCurrentCredentialAndSubjectMismatch(t *testing.T) {
	nativeOIDCCurrentAuthority(t, oidcFixture, []string{"credential", "subject", "consent"})
}

func TestNativeOIDCPairwiseUserInfoDeniesCurrentAuthority(t *testing.T) {
	nativeOIDCCurrentAuthority(t, pairwiseFixture, []string{"credential", "subject", "consent", "grant"})
}

func nativeOIDCCurrentAuthority(t *testing.T, fixture oidcFixtureBuilder, modes []string) {
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixtureWithChange(t, mode == "credential")
			if mode == "consent" {
				enableConsentManagement(t, &f)
			}
			service, child, _, _, _ := fixture(t, &f)
			code, proof := oidcCode(t, f, service, "authority-nonce")
			issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: proof, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			access, err := issued.AccessToken.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			request := oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}
			if _, err := child.UserInfo(f.ctx, request); err != nil {
				t.Fatal("current genuine authority denied", err)
			}
			if mode == "credential" {
				f.changePassword()
			} else if mode == "consent" {
				listed, err := service.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
				if err != nil || len(listed.Page.Items()) != 1 {
					t.Fatal("native OIDC consent absent", err)
				}
				consent := listed.Page.Items()[0]
				removed, err := service.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRemove, consent.ID(), consent.Version())})
				if err != nil || !removed.Deleted {
					t.Fatal("native OIDC consent withdrawal failed", err)
				}
			} else if mode == "grant" {
				refresh, err := issued.RefreshToken.Reveal()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: "public-web", Token: refresh, Hint: oauth.TokenRefresh, Network: "192.0.2.1"}); err != nil {
					t.Fatal("native pairwise grant revocation failed", err)
				}
			} else {
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{Subject}','"foreign"'::jsonb) WHERE kind=3`); err != nil {
					t.Fatal(err)
				}
			}
			if out, err := child.UserInfo(f.ctx, request); err == nil || out.Subject != "" {
				t.Fatal("stale credential or mismatched subject returned claims")
			}
		})
	}
}

func TestNativeSigningRestartPreservesOverlapAndCompromise(t *testing.T) {
	f := passwordFixture(t)
	service, child, signer, store, key := oidcFixture(t, &f)
	code, proof := oidcCode(t, f, service, "restart-nonce")
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: proof, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issued.IDToken.Reveal(); err != nil {
		t.Fatal(err)
	}
	authority, err := oauth.NewSigningAuthority(clock.System{}, f.oauth.Protocol.AccessTTL)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := oauth.NewSigningService(authority, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Install(f.ctx, "initial", key); err != nil {
		t.Fatal("restart could not restore same private custody", err)
	}
	if err := restarted.Activate(f.ctx, "initial"); err != nil {
		t.Fatal(err)
	}
	next, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := restarted.Install(f.ctx, "next", next); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Activate(f.ctx, "next"); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("restart activated unpublished successor")
	}
	if _, err := child.JWKS(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Activate(f.ctx, "next"); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Retire(f.ctx, "initial"); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("restart reset durable verification overlap")
	}
	if err := signer.Compromise(f.ctx, "initial"); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Activate(f.ctx, "initial"); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("restart resurrected compromised signing key")
	}
	keys, err := restarted.PublicKeys(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if key.Kid == "initial" {
			t.Fatal("compromised key remained published")
		}
	}
	if err := restarted.Retire(f.ctx, "next"); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("retired selected active signer")
	}
}

func TestNativeSigningActivationAndRetirementSerialize(t *testing.T) {
	f := passwordFixture(t)
	_, _, signer, store, _ := oidcFixture(t, &f)
	next, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Install(f.ctx, "inactive", next); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.PublicKeys(f.ctx); err != nil {
		t.Fatal(err)
	}
	// Block selection mutation after the old implementation's unlocked state
	// read. Retirement must share that serialization point, not race past it.
	blocker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(f.ctx)
	if _, err := blocker.Exec(f.ctx, `SELECT singleton FROM oauth_store.signing_selection FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	activated := make(chan error, 1)
	retired := make(chan error, 1)
	go func() { activated <- store.ActivateSigningKey(f.ctx, "inactive") }()
	waitBlocked := func(minimum int) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			var n int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%signing_selection%'`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n >= minimum {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("signing mutation did not reach controlled lock")
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitBlocked(1)
	go func() { retired <- store.RetireSigningKey(f.ctx, "inactive") }()
	var retireErr error
	retireFinished := false
	deadline := time.Now().Add(2 * time.Second)
	for !retireFinished {
		select {
		case retireErr = <-retired:
			retireFinished = true
		default:
			var n int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%signing_selection%'`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n >= 2 {
				goto release
			}
			if time.Now().After(deadline) {
				t.Fatal("retirement neither completed nor reached selection lock")
			}
			time.Sleep(time.Millisecond)
		}
	}
release:
	if err := blocker.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	activateErr := <-activated
	if !retireFinished {
		retireErr = <-retired
	}
	if activateErr == nil && retireErr == nil {
		t.Fatal("activation and retirement both succeeded across one selection")
	}
	var selected, state string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT s.kid,k.state FROM oauth_store.signing_selection s JOIN oauth_store.signing_keys k ON k.kid=s.kid`).Scan(&selected, &state); err != nil || state != "published" {
		t.Fatal("selected key is not published", err)
	}
}
