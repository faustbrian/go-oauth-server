//go:build integration && oauthflow

package oauthpostgres_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	auth "github.com/faustbrian/go-authentication/v2"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/oauth2"
)

func silentOIDCFixture(t *testing.T, f *authenticatedPasswordFixture, ttl time.Duration) (*oauth.Service, *op.Service, *oauthpostgres.Store) {
	t.Helper()
	enableConsentManagement(t, f)
	f.oauth.ConsentReuseTTL = ttl
	service, child, _, store, _ := oidcFixture(t, f)
	installConsentExpiry(t, *f)
	return service, child, store
}

func installConsentExpiry(t *testing.T, f authenticatedPasswordFixture) {
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
	base := oauthpostgres.SigningMigrationSource{Base: oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}, Schema: "oauth_store", Version: 7003}
	source := oauthpostgres.ConsentExpiryMigrationSource{Base: base, Schema: "oauth_store", Version: 7004}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("consent expiry forward install", err)
	}
	if replay, err := runner.Up(f.ctx); err != nil || len(replay.Records()) != 0 {
		t.Fatal("consent expiry rewrote installed history", err)
	}
}

func silentRequest(f authenticatedPasswordFixture, verifier string) oauth.AuthorizeRequest {
	return oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", Resource: "https://resource.example", Scopes: []string{"identity:read", "openid"}, Prompt: "none", State: "silent-original-state", Nonce: "silent-original-nonce", CodeChallenge: oauth2.S256ChallengeFromVerifier(verifier)}}
}

func TestNativeOIDCSilentSelectedApprovalLifetimeBounds(t *testing.T) {
	f := passwordFixture(t)
	_, _, _ = silentOIDCFixture(t, &f, time.Minute)
	for _, ttl := range []time.Duration{-time.Second, time.Second - time.Microsecond, 24*time.Hour + time.Microsecond, time.Second + time.Nanosecond} {
		config := f.oauth
		config.ConsentReuseTTL = ttl
		if _, err := oauthpostgres.NewStore(f.pool, config, f.keys); err == nil {
			t.Fatal("unsupported silent approval lifetime accepted")
		}
	}
	for _, ttl := range []time.Duration{0, time.Second, 24 * time.Hour} {
		// Construction performs no IO. Zero is a preactivation writer selection,
		// not permission to accept mixed/zero writes on activated expiry history.
		config := f.oauth
		config.ConsentReuseTTL = ttl
		if _, err := oauthpostgres.NewStore(f.pool, config, f.keys); err != nil {
			t.Fatal("explicit silent selection boundary rejected", err)
		}
	}
	config := f.oauth
	config.ConsentManagement = false
	if _, err := oauthpostgres.NewStore(f.pool, config, f.keys); err == nil {
		t.Fatal("silent approval without actual managed consent selected")
	}
}

func TestNativeOIDCSilentExistingApprovalCodeAndIndependentRP(t *testing.T) {
	f := passwordFixture(t)
	service, child, _ := silentOIDCFixture(t, &f, time.Minute)
	oidcCode(t, f, service, "explicit-original-nonce")
	var originalVersion, originalGeneration string
	var granted time.Time
	var expiry *time.Time
	var continuations, approvals int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,generation::text,granted_at,expires_at,(SELECT count(*) FROM oauth_store.artifacts WHERE kind=1),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.grant_consent') FROM oauth_store.consents`).Scan(&originalVersion, &originalGeneration, &granted, &expiry, &continuations, &approvals); err != nil || expiry == nil || !expiry.Equal(granted.Add(time.Minute)) {
		t.Fatal("explicit original approval did not establish bounded expiry", err)
	}
	// A larger configured ceiling is not a fresh grant of approval. A fresh
	// service must preserve the row's ORIGINAL shorter expiry and grant bound.
	changed := f.oauth
	changed.ConsentReuseTTL = 2 * time.Minute
	service, err := oauthpostgres.NewService(f.pool, changed, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err = service.WithOIDC(child)
	if err != nil {
		t.Fatal(err)
	}
	verifier := oauth2.GenerateVerifier()
	request := silentRequest(f, verifier)
	out, err := service.Authorize(f.ctx, request)
	if err != nil || out.Outcome != oauth.AuthorizationRedirect || out.Continuation != (oauth.Token{}) || !out.ExpiresAt.After(time.Now()) || out.ExpiresAt.After(*expiry) {
		t.Fatal("current explicit approval did not issue silent bounded code", err)
	}
	location, err := out.Location()
	if err != nil {
		t.Fatal("silent code location", err)
	}
	callback, err := url.Parse(location)
	if err != nil || callback.Query().Get("state") != request.Request.State || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() || callback.Query().Get("error") != "" || callback.Query().Get("code") == "" {
		t.Fatal("silent response binding")
	}
	if _, err := out.Location(); err == nil {
		t.Fatal("silent response revealed original code twice")
	}
	var currentVersion, currentGeneration string
	var currentGranted, currentExpiry time.Time
	var currentContinuations, currentApprovals int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,generation::text,granted_at,expires_at,(SELECT count(*) FROM oauth_store.artifacts WHERE kind=1),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.grant_consent') FROM oauth_store.consents`).Scan(&currentVersion, &currentGeneration, &currentGranted, &currentExpiry, &currentContinuations, &currentApprovals); err != nil || currentVersion != originalVersion || currentGeneration != originalGeneration || !currentGranted.Equal(granted) || !currentExpiry.Equal(*expiry) || currentContinuations != continuations || currentApprovals != approvals {
		t.Fatal("silent issuance created interaction or renewed/mutated consent", err)
	}
	transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ctx := rp.ClientContext(f.ctx, client)
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal("independent silent RP discovery", err)
	}
	standard := oauth2.Config{ClientID: "public-web", RedirectURL: request.Request.RedirectURI, Endpoint: provider.Endpoint()}
	standard.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	tokens, err := standard.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal("independent silent S256 exchange", err)
	}
	wire, ok := tokens.Extra("id_token").(string)
	if !ok {
		t.Fatal("silent exchange omitted ID token")
	}
	verified, err := consumeIDToken(ctx, provider, wire, request.Request.Nonce, "public-web")
	if err != nil || verified.Subject == "" {
		t.Fatal("independent RP rejected silent ID token", err)
	}
	user, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tokens))
	if err != nil || user.Subject != verified.Subject {
		t.Fatal("independent silent UserInfo subject mismatch", err)
	}
	if _, err := standard.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(verifier)); err == nil {
		t.Fatal("silent code reused")
	}
}

func TestNativeOIDCSilentRequiresCurrentSessionAndUnexpiredExplicitConsent(t *testing.T) {
	for _, mode := range []string{"missing-consent", "missing-session", "withdrawn-session", "max-age-zero", "expired-consent", "insufficient-consent", "revoked-consent", "legacy-null", "stale-client", "stale-config", "foreign-tenant", "expanding-scope", "foreign-resource", "invalid-redirect"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			ttl := time.Minute
			if mode == "expired-consent" {
				ttl = 3 * time.Second
			}
			service, child, store := silentOIDCFixture(t, &f, ttl)
			if mode != "missing-consent" {
				if mode == "legacy-null" {
					legacy := f.oauth
					legacy.ConsentReuseTTL = 0
					old, err := oauthpostgres.NewService(f.pool, legacy, f.keys)
					if err != nil {
						t.Fatal(err)
					}
					old, err = old.WithOIDC(child)
					if err != nil {
						t.Fatal(err)
					}
					oidcCode(t, f, old, "legacy-explicit")
				} else if mode == "insufficient-consent" {
					request := silentRequest(f, oauth2.GenerateVerifier())
					request.Request.Prompt = ""
					begin, err := service.Authorize(f.ctx, request)
					if err != nil || begin.Outcome != oauth.ConsentRequired {
						t.Fatal("explicit narrow consent setup", err)
					}
					continuation, _ := begin.Continuation.Reveal()
					if out, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", ClientID: "public-web", Continuation: continuation, Approve: true, Scopes: []string{"openid"}}); err != nil || out.Outcome != oauth.AuthorizationRedirect {
						t.Fatal("explicit narrow approval", err)
					}
				} else {
					oidcCode(t, f, service, "explicit-denial-control")
				}
			}
			request := silentRequest(f, oauth2.GenerateVerifier())
			want := "consent_required"
			switch mode {
			case "missing-session":
				request.Session = auth.BearerCredential{}
				want = "login_required"
			case "withdrawn-session":
				f.signOut()
				want = "login_required"
			case "max-age-zero":
				zero := uint32(0)
				request.Request.MaxAge = &zero
				want = "login_required"
			case "expired-consent":
				var expiry time.Time
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT expires_at FROM oauth_store.consents`).Scan(&expiry); err != nil {
					t.Fatal(err)
				}
				if live, err := service.Authorize(f.ctx, request); err != nil || live.Outcome != oauth.AuthorizationRedirect {
					t.Fatal("live expiry-boundary positive control", err)
				}
				waitAuthenticationBoundary(t, f, expiry)
			case "revoked-consent":
				var id string
				var version uint64
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT consent_id,version::bigint FROM oauth_store.consents`).Scan(&id, &version); err != nil {
					t.Fatal(err)
				}
				if _, err := service.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRemove, id, version)}); err != nil {
					t.Fatal("actual own-consent withdrawal", err)
				}
			case "stale-client", "stale-config":
				current := f.oauth.Protocol
				current.Clients[0].Version++
				var err error
				if mode == "stale-config" {
					service, err = oauth.NewService(current, oauth.Dependencies{Sessions: f.sessions, Store: store, OIDC: child})
					want = "local"
				} else {
					config := f.oauth
					config.Protocol = current
					service, err = oauthpostgres.NewService(f.pool, config, f.keys)
					if err == nil {
						service, err = service.WithOIDC(child)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
			case "foreign-tenant":
				request.TenantID = "foreign"
				want = "login_required"
			case "expanding-scope":
				request.Request.Scopes = append(request.Request.Scopes, "privileged:unknown")
				want = "local"
			case "foreign-resource":
				request.Request.Resource = "https://foreign.example"
				want = "local"
			case "invalid-redirect":
				request.Request.RedirectURI = "https://foreign.example/cb"
				want = "local"
			}
			var grants, artifacts, commands int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.artifacts),(SELECT count(*) FROM oauth_store.effects)`).Scan(&grants, &artifacts, &commands); err != nil {
				t.Fatal(err)
			}
			out, err := service.Authorize(f.ctx, request)
			if out.Code != (oauth.Token{}) || out.Continuation != (oauth.Token{}) || out.CommandID != "" {
				t.Fatal("silent denial created interaction, command or credential")
			}
			location, locationErr := out.Location()
			if want == "local" {
				if err == nil || locationErr == nil || out.RedirectURI != "" {
					t.Fatal("invalid silent trust context redirected or succeeded")
				}
			} else {
				parsed, parseErr := url.Parse(location)
				if err != nil || locationErr != nil || parseErr != nil || parsed.Query().Get("error") != want || parsed.Query().Get("iss") != f.oauth.Protocol.Issuer.String() || parsed.Query().Get("state") != request.Request.State || parsed.Host != "client.example" || len(parsed.Query()) != 3 {
					t.Fatal("silent denial protocol binding/condition", err)
				}
			}
			var afterGrants, afterArtifacts, afterCommands int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.artifacts),(SELECT count(*) FROM oauth_store.effects)`).Scan(&afterGrants, &afterArtifacts, &afterCommands); err != nil || grants != afterGrants || artifacts != afterArtifacts || commands != afterCommands {
				t.Fatal("silent denial changed durable approval/issuance", err)
			}
			if mode == "expired-consent" {
				// Expiry cannot silently renew. Only another protected explicit
				// approval may establish a new bounded lifetime on this same root.
				oidcCode(t, f, service, "explicit-after-expiry")
				if fresh, err := service.Authorize(f.ctx, request); err != nil || fresh.Outcome != oauth.AuthorizationRedirect {
					t.Fatal("new explicit approval did not re-enable silent authorization", err)
				}
			}
		})
	}
}
