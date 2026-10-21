//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"golang.org/x/oauth2"
)

func resourcePolicy(f authenticatedPasswordFixture, client oauth.Client) oauth.ResourceVerificationConfig {
	return oauth.ResourceVerificationConfig{Issuer: f.oauth.Protocol.Issuer, Environment: f.oauth.Protocol.Environment, TenantID: f.tenant, ClientID: client.ID, ClientVersion: client.Version, Resource: client.Resource, Scopes: f.oauth.Protocol.Scopes, Clock: f.oauth.Protocol.Clock, MaximumDuration: f.oauth.Protocol.MaximumDuration}
}

func requireInvalidResource(t *testing.T, v *oauth.ResourceVerifier, ctx context.Context, token string) {
	t.Helper()
	p, err := v.Verify(ctx, oauth.ResourceVerifyRequest{AccessToken: token, Scope: "identity:read"})
	if !errors.Is(err, oauth.ErrInvalidResourceToken) || p.Subject() != "" || p.RequireScope("identity:read") == nil {
		t.Fatal("invalid custody produced resource authority", err)
	}
}

func TestNativeResourceVerifyFixedTrustContextAndScope(t *testing.T) {
	f := passwordFixture(t)
	enableConsentManagement(t, &f)
	client, _, basic := addConfiguredConfidentialClient(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	access, _ := issuedConfidentialTokens(t, f, service, client, basic)
	for _, mode := range []string{"tenant", "client", "issuer", "environment", "resource", "version"} {
		t.Run(mode, func(t *testing.T) {
			c, policy := f.oauth, resourcePolicy(f, client)
			c.Protocol.Clients = append([]oauth.Client(nil), c.Protocol.Clients...)
			switch mode {
			case "tenant":
				policy.TenantID = "foreign"
			case "client":
				policy.ClientID = "public-web"
			case "issuer":
				c.Protocol.Issuer, _ = oauth.NewIssuer("https://foreign.example")
				policy.Issuer = c.Protocol.Issuer
			case "environment":
				c.Protocol.Environment = "foreign"
				policy.Environment = c.Protocol.Environment
			case "resource":
				c.Protocol.Resource = "https://foreign.example"
				policy.Resource = c.Protocol.Resource
				for i := range c.Protocol.Clients {
					c.Protocol.Clients[i].Resource = c.Protocol.Resource
				}
			case "version":
				policy.ClientVersion++
			}
			v, err := oauthpostgres.NewResourceVerifier(f.pool, c, f.keys, policy)
			if mode == "version" {
				if err == nil {
					t.Fatal("unchecked configured client version admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			requireInvalidResource(t, v, f.ctx, access)
		})
	}
	v, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, resourcePolicy(f, client))
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"identity:write", "unsupported"} {
		if p, err := v.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: scope}); !errors.Is(err, oauth.ErrInvalidScope) || p.Subject() != "" {
			t.Fatal("unsupported or ungranted scope produced principal", err)
		}
	}
	code, proof := confidentialCode(t, f, service, client)
	requireInvalidResource(t, v, f.ctx, code)
	if issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, ClientAuthentication: basic, Code: code, CodeVerifier: proof, RedirectURI: client.Redirects[0], Network: "192.0.2.1"}); err != nil || issued.Outcome == 0 {
		t.Fatal("resource verification consumed authorization code", err)
	}
}

func TestNativeResourceVerifyOutageCancellationAndReadRecoveryDoNotMutate(t *testing.T) {
	f := passwordFixture(t)
	enableConsentManagement(t, &f)
	client, _, basic := addConfiguredConfidentialClient(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	access, _ := issuedConfidentialTokens(t, f, service, client, basic)
	v, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, resourcePolicy(f, client))
	if err != nil {
		t.Fatal(err)
	}
	counts := func() string {
		var value string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT concat_ws(':',(SELECT count(*) FROM oauth_store.artifacts),(SELECT count(*) FROM oauth_store.effects),(SELECT count(*) FROM identity.commands),(SELECT count(*) FROM audit.records),(SELECT count(*) FROM public.outbox_messages))`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := counts()
	request := oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"}
	if _, err := v.Verify(f.ctx, request); err != nil {
		t.Fatal("positive read unavailable", err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if p, err := v.Verify(ctx, request); !errors.Is(err, context.Canceled) || p.Subject() != "" {
		t.Fatal("cancellation reused positive principal", err)
	}
	for _, schema := range []string{"oauth_store", "identity"} {
		// Only task-owned fixture schema availability changes; no domain state
		// or primary evidence is fabricated, and every schema is restored.
		if _, err := f.pool.Raw().Exec(f.ctx, `ALTER SCHEMA `+schema+` RENAME TO resource_hidden`); err != nil {
			t.Fatal(err)
		}
		p, readErr := v.Verify(f.ctx, request)
		_, restoreErr := f.pool.Raw().Exec(f.ctx, `ALTER SCHEMA resource_hidden RENAME TO `+schema)
		if restoreErr != nil {
			t.Fatal("owned schema restoration failed", restoreErr)
		}
		if !errors.Is(readErr, oauth.ErrUnavailable) || p.Subject() != "" {
			t.Fatal("outage reused positive authority", schema, readErr)
		}
		if _, err := v.Verify(f.ctx, request); err != nil {
			t.Fatal("read recovery altered original live token", err)
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE authorization_subject_authorities RENAME TO resource_hidden_authority`); err != nil {
		t.Fatal(err)
	}
	p, readErr := v.Verify(f.ctx, request)
	_, restoreErr := f.pool.Raw().Exec(f.ctx, `ALTER TABLE resource_hidden_authority RENAME TO authorization_subject_authorities`)
	if restoreErr != nil {
		t.Fatal("authority table restoration failed", restoreErr)
	}
	if !errors.Is(readErr, oauth.ErrUnavailable) || p.Subject() != "" {
		t.Fatal("policy outage reused positive authority", readErr)
	}
	if _, err := v.Verify(f.ctx, request); err != nil {
		t.Fatal("policy read recovery altered original token", err)
	}
	if after := counts(); after != before {
		t.Fatal("read-only verification or outage recovery mutated native state")
	}
}

func TestNativeResourceVerifyRevocationAndConsentGeneration(t *testing.T) {
	for _, mode := range []string{"access", "family", "narrow"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			enableConsentNarrowing(t, &f)
			client, _, basic := addConfiguredConfidentialClient(t, &f)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			proof := oauth2.GenerateVerifier()
			begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: client.ID, RedirectURI: client.Redirects[0], Resource: client.Resource, Scopes: []string{"identity:read", "identity:write"}, CodeChallenge: oauth2.S256ChallengeFromVerifier(proof)}})
			if err != nil {
				t.Fatal(err)
			}
			continuation, _ := begin.Continuation.Reveal()
			approved, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: client.ID, Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true})
			if err != nil {
				t.Fatal(err)
			}
			location, _ := approved.Location()
			callback, err := url.Parse(location)
			if err != nil {
				t.Fatal(err)
			}
			issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, ClientAuthentication: basic, Code: callback.Query().Get("code"), CodeVerifier: proof, RedirectURI: client.Redirects[0], Network: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			access, _ := issued.AccessToken.Reveal()
			refresh, _ := issued.RefreshToken.Reveal()
			v, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, resourcePolicy(f, client))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"}); err != nil {
				t.Fatal("live pre-withdrawal control failed", err)
			}
			if mode == "narrow" {
				consent := currentNarrowConsent(t, f, service)
				r := narrowRequest(t, f, consent, "resource-narrow", []string{"identity:read"})
				if out, err := service.ConsentUpdate(f.ctx, r); err != nil || !out.Updated {
					t.Fatal("actual own-consent narrowing failed", err)
				}
			} else {
				token := access
				if mode == "family" {
					token = refresh
				}
				if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: client.ID, ClientAuthentication: basic, Token: token, Network: "192.0.2.1"}); err != nil {
					t.Fatal(err)
				}
			}
			requireInvalidResource(t, v, f.ctx, access)
			requireInvalidResource(t, v, f.ctx, access)
		})
	}
}

// This independent selected resource consumes the opaque verifier result, not
// a caller-supplied identity or introspection Active flag. Application ownership
// and business policy remain outside this OAuth credential-scope requirement.
func selectedResourceRead(p oauth.ResourcePrincipal) (string, error) {
	if err := p.RequireScope("identity:read"); err != nil {
		return "", err
	}
	return "private:" + string(p.TenantID()) + ":" + string(p.Subject()), nil
}

func TestNativeResourceVerifyGenuineCodeAccessOnlyConsumer(t *testing.T) {
	f := passwordFixture(t)
	enableConsentManagement(t, &f)
	client, _, basic := addConfiguredConfidentialClient(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	access, refresh := issuedConfidentialTokens(t, f, service, client, basic)
	verifier, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, resourcePolicy(f, client))
	if err != nil {
		t.Fatal(err)
	}
	principal, err := verifier.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"})
	if err != nil || principal.Subject() == "" || principal.TenantID() != f.tenant || principal.Resource() != client.Resource || !principal.ValidUntil().After(time.Now()) || principal.ValidUntil().After(time.Now().Add(20*time.Second)) {
		t.Fatal("real S256 access did not verify for selected resource", err)
	}
	if value, err := selectedResourceRead(principal); err != nil || value == "" {
		t.Fatal("independent resource could not consume scope-bound principal", err)
	}
	if principal.RequireScope("identity:write") == nil {
		t.Fatal("read principal expanded to write")
	}
	for _, token := range []string{refresh, "not-issued"} {
		p, err := verifier.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: token, Scope: "identity:read"})
		if !errors.Is(err, oauth.ErrInvalidResourceToken) || p.Subject() != "" {
			t.Fatal("non-access custody reached selected resource", err)
		}
	}
}
