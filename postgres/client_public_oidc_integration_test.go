//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"golang.org/x/oauth2"
)

func managedOIDCFixture(t *testing.T, f *authenticatedPasswordFixture, populated bool) (*oauth.SigningService, [32]byte) {
	t.Helper()
	enableClientManagement(t, f)
	if populated {
		installClientRotation(t, f)
	}
	installPublicClients(t, f)
	// This finite consumer does not select the unrelated introspection endpoint.
	f.oauth.Protocol.OwningClientIntrospection = false
	var source migrations.Source = oauthpostgres.ClientMigrationSource{Base: oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}, Schema: "oauth_store", Version: 7003}
	version := migrations.Version(7004)
	if populated {
		source = oauthpostgres.ClientRotationMigrationSource{Base: source, Schema: "oauth_store", Version: version}
		version++
	}
	source = oauthpostgres.ClientPublicMigrationSource{Base: source, Schema: "oauth_store", Version: version}
	version++
	source = oauthpostgres.SigningMigrationSource{Base: source, Schema: "oauth_store", Version: version}
	_, _, signer, _, _ := oidcFixtureWithLifecycle(t, f, clock.System{}, nil, source)
	var subjectKey [32]byte
	if _, err := rand.Read(subjectKey[:]); err != nil {
		t.Fatal(err)
	}
	return signer, subjectKey
}

func managedOIDCServices(t *testing.T, f authenticatedPasswordFixture, signer *oauth.SigningService, subjectKey [32]byte) (*oauth.Service, *op.Service, *oauthpostgres.Store) {
	t.Helper()
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	core, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store, Clients: store})
	if err != nil {
		t.Fatal(err)
	}
	issuer := f.oauth.Protocol.Issuer.String()
	child, err := op.NewService(op.Config{Issuer: f.oauth.Protocol.Issuer, JWKSURI: issuer + "/oauth2/jwks", UserInfoEndpoint: issuer + "/oauth2/userinfo", Signing: signer, SubjectKey: subjectKey, Clock: clock.System{}, MaximumDuration: 4 * time.Second}, core)
	if err != nil {
		t.Fatal(err)
	}
	service, err := core.WithOIDC(child)
	if err != nil {
		t.Fatal(err)
	}
	return service, child, store
}

func TestNativeManagedPublicOIDCFreshAndPopulatedIndependentConsumer(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated"}[populated], func(t *testing.T) {
			f := passwordFixture(t)
			signer, subjectKey := managedOIDCFixture(t, &f, populated)
			before, _, _ := managedOIDCServices(t, f, signer, subjectKey)
			var legacy oauth.ClientManagementResult
			var legacyRequest oauth.ClientManagementRequest
			var legacyRegistration, legacyDigest []byte
			var legacyRefresh string
			var basic oauth.ClientAuthentication
			if populated {
				legacyRequest = clientCreateRequest(t, f, "before-managed-oidc")
				var err error
				legacy, err = before.ClientCreate(f.ctx, legacyRequest)
				if err != nil {
					t.Fatal(err)
				}
				secret, err := legacy.Secret.Reveal()
				if err != nil {
					t.Fatal(err)
				}
				basic = confidentialBasic(t, legacy.Client.ID, secret)
				_, legacyRefresh = issuedConfidentialTokens(t, f, before, legacy.Client, basic)
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, legacy.Client.ID).Scan(&legacyRegistration, &legacyDigest); err != nil {
					t.Fatal(err)
				}
			}
			r := clientCreateRequest(t, f, "managed-oidc-public")
			r.Public, r.Scopes = true, []string{"openid"}
			if _, err := before.ClientCreate(f.ctx, r); err == nil {
				t.Fatal("default managed policy enabled OIDC")
			}
			f.oauth.Protocol.ManagedClients.PublicOIDC = true
			service, _, store := managedOIDCServices(t, f, signer, subjectKey)
			manager := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
			manager.denied.Store(true)
			if out, err := service.ClientCreate(f.ctx, r); err == nil || out.Client.ID != "" {
				t.Fatal("OIDC opt-in bypassed current manager authority")
			}
			manager.denied.Store(false)
			if populated {
				retry, err := service.ClientCreate(f.ctx, legacyRequest)
				if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != legacy.Completion.CommandID {
					t.Fatal("OIDC activation changed original confidential intent", err)
				}
				if _, err := retry.Secret.Reveal(); err == nil {
					t.Fatal("original confidential recovery redelivered secret")
				}
				recovered, err := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-create", CommandID: legacy.Completion.CommandID, ClientID: legacy.Client.ID, TenantID: f.tenant, Session: f.browser})
				if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("OIDC activation stranded original management recovery", err)
				}
				var registration, digest []byte
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, legacy.Client.ID).Scan(&registration, &digest); err != nil || !bytes.Equal(registration, legacyRegistration) || !bytes.Equal(digest, legacyDigest) {
					t.Fatal("OIDC activation changed installed confidential bytes", err)
				}
				if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: legacy.Client.ID, ClientAuthentication: basic, RefreshToken: legacyRefresh, Network: "192.0.2.1"}); err != nil {
					t.Fatal("OIDC activation broke existing confidential refresh", err)
				}
				if _, err := service.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, legacy.Client, "confidential-after-oidc", 0)); err != nil {
					t.Fatal("OIDC activation broke OAuth-only confidential rotation", err)
				}
			}
			created, err := service.ClientCreate(f.ctx, r)
			if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted || !created.Client.Public || created.Client.AuthenticationMethod != "none" || !slices.Equal(created.Client.Scopes, []string{"openid"}) || created.Client.SubjectRegistration != nil {
				t.Fatal("current manager did not create exact minimal public OIDC client", err)
			}
			if _, err := created.Secret.Reveal(); err == nil {
				t.Fatal("managed OIDC creation disclosed secret")
			}
			retry, err := service.ClientCreate(f.ctx, r)
			if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != created.Completion.CommandID || retry.Client.ID != created.Client.ID {
				t.Fatal("minimal OIDC original request did not retain one registration", err)
			}
			changed := r
			changed.Scopes = []string{"identity:read"}
			if _, err := service.ClientCreate(f.ctx, changed); !errors.Is(err, oauth.ErrClientConflict) {
				t.Fatal("OIDC request key accepted changed scopes", err)
			}
			var noSecret bool
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT secret_digest IS NULL FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&noSecret); err != nil || !noSecret {
				t.Fatal("managed OIDC persisted a client secret", err)
			}
			fresh, child, freshStore := managedOIDCServices(t, f, signer, subjectKey)
			read := oauth.ClientReadRequest{Owner: r.Owner, TenantID: f.tenant, Session: f.browser, ClientID: created.Client.ID}
			current, err := fresh.ClientGet(f.ctx, read)
			if err != nil || current.Client.ID != created.Client.ID || current.Client.Version != created.Client.Version || !current.Client.Public || current.Client.AuthenticationMethod != "none" || !slices.Equal(current.Client.Scopes, []string{"openid"}) {
				t.Fatal("fresh service could not discover managed OIDC metadata", err)
			}
			read.ClientID, read.Limit = "", 100
			listed, err := fresh.ClientList(f.ctx, read)
			if err != nil || !slices.ContainsFunc(listed.Page.Items(), func(c oauth.Client) bool {
				return c.ID == created.Client.ID && c.Version == created.Client.Version && c.Public && c.AuthenticationMethod == "none" && slices.Equal(c.Scopes, []string{"openid"})
			}) {
				t.Fatal("safe list omitted minimal managed OIDC registration", err)
			}
			transport := &discoveryConsumerTransport{f: f, service: fresh, endpoints: f.oauth.Protocol.Discovery, oidc: child, userInfoClientID: current.Client.ID}
			httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			ctx := rp.ClientContext(f.ctx, httpClient)
			provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
			if err != nil {
				t.Fatal("managed independent RP discovery", err)
			}
			standard := oauth2.Config{ClientID: current.Client.ID, RedirectURL: current.Client.Redirects[0], Scopes: []string{"openid"}, Endpoint: provider.Endpoint()}
			standard.Endpoint.AuthStyle = oauth2.AuthStyleInParams
			verifier := oauth2.GenerateVerifier()
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, standard.AuthCodeURL("managed-state", oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", "managed-original-nonce"), oauth2.SetAuthURLParam("resource", current.Client.Resource)), nil)
			response, err := httpClient.Do(request)
			if err != nil {
				t.Fatal("managed RP consent/S256 authorization", err)
			}
			response.Body.Close()
			callback, err := url.Parse(response.Header.Get("Location"))
			if err != nil || callback.Query().Get("state") != "managed-state" || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() {
				t.Fatal("managed callback lost issuer/state")
			}
			uncomposed, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			codeRequest := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: current.Client.ID, Code: callback.Query().Get("code"), CodeVerifier: verifier, RedirectURI: current.Client.Redirects[0], Network: "192.0.2.1"}
			if _, err := uncomposed.Token(f.ctx, codeRequest); !errors.Is(err, oauth.ErrAccessDenied) {
				t.Fatal("uncomposed native managed OIDC accepted code", err)
			}
			wrong := codeRequest
			wrong.CodeVerifier = strings.Repeat("z", 43)
			if _, err := fresh.Token(f.ctx, wrong); err == nil {
				t.Fatal("minimal OIDC code accepted wrong S256")
			}
			wrong = codeRequest
			secret, _ := oauth.NewToken()
			secretWire, _ := secret.Reveal()
			wrong.ClientAuthentication = confidentialBasic(t, current.Client.ID, secretWire)
			if _, err := fresh.Token(f.ctx, wrong); err == nil {
				t.Fatal("managed public OIDC accepted forbidden Basic authentication")
			}
			token, err := standard.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(verifier))
			if err != nil {
				t.Fatal("managed RP code exchange", err)
			}
			wire, ok := token.Extra("id_token").(string)
			if !ok {
				t.Fatal("managed RP received no ID token")
			}
			verified, err := consumeIDToken(ctx, provider, wire, "managed-original-nonce", current.Client.ID)
			if err != nil || verified.Subject == "" || !time.Now().Before(verified.Expiry) {
				t.Fatal("managed RP rejected actual signature/issuer/audience/nonce/expiry", err)
			}
			var rawUser string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT user_id FROM oauth_store.grants WHERE client_id=$1 LIMIT 1`, current.Client.ID).Scan(&rawUser); err != nil || verified.Subject == rawUser {
				t.Fatal("default managed public subject leaked raw user", err)
			}
			var claims map[string]json.RawMessage
			if verified.Claims(&claims) != nil || len(claims) != 9 {
				t.Fatal("minimal managed ID token expanded identity claims")
			}
			if _, err := consumeIDToken(ctx, provider, wire, "wrong", current.Client.ID); err == nil {
				t.Fatal("managed RP accepted wrong nonce")
			}
			if _, err := consumeIDToken(ctx, provider, wire, "managed-original-nonce", "public-web"); err == nil {
				t.Fatal("managed RP accepted wrong audience")
			}
			parts := strings.Split(wire, ".")
			altered := maps.Clone(claims)
			altered["nonce"] = json.RawMessage(`"forged"`)
			payload, err := json.Marshal(altered)
			if err != nil {
				t.Fatal(err)
			}
			parts[1] = base64.RawURLEncoding.EncodeToString(payload)
			if _, err := consumeIDToken(ctx, provider, strings.Join(parts, "."), "forged", current.Client.ID); err == nil {
				t.Fatal("managed RP accepted forged signed content")
			}
			info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
			if err != nil || info.Subject != verified.Subject {
				t.Fatal("managed RP UserInfo differs from verified ID-token sub", err)
			}
			var userClaims map[string]json.RawMessage
			if info.Claims(&userClaims) != nil || len(userClaims) != 1 || userClaims["sub"] == nil {
				t.Fatal("openid-only managed UserInfo returned additional identity claims")
			}
			restarted, restartedChild, _ := managedOIDCServices(t, f, signer, subjectKey)
			if next, err := restartedChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: current.Client.ID, AccessToken: token.AccessToken}); err != nil || next.Subject != verified.Subject {
				t.Fatal("default subject changed across service reconstruction", err)
			}
			if _, err := uncomposed.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: current.Client.ID, RefreshToken: token.RefreshToken, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrAccessDenied) {
				t.Fatal("uncomposed native managed OIDC accepted absent-scope refresh", err)
			}
			rotated, err := restarted.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: current.Client.ID, RefreshToken: token.RefreshToken, Network: "192.0.2.1"})
			if err != nil {
				t.Fatal("managed OIDC refresh required a secret", err)
			}
			refresh, _ := rotated.RefreshToken.Reveal()
			access, _ := rotated.AccessToken.Reveal()
			if info, err := restartedChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: current.Client.ID, AccessToken: access}); err != nil || info.Subject != verified.Subject {
				t.Fatal("refreshed managed OIDC access lost original UserInfo subject", err)
			}
			if _, err := restarted.Revoke(f.ctx, oauth.RevokeRequest{ClientID: current.Client.ID, Token: refresh, Network: "192.0.2.1"}); err != nil {
				t.Fatal("managed OIDC revocation required a secret", err)
			}
			if _, err := restarted.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: current.Client.ID, RefreshToken: refresh, Network: "192.0.2.1"}); err == nil {
				t.Fatal("revoked managed OIDC refresh issued")
			}
			if _, err := restartedChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: current.Client.ID, AccessToken: access}); !errors.Is(err, oauth.ErrAccessDenied) {
				t.Fatal("revoked managed OIDC access retained UserInfo", err)
			}
			remove := clientRotationRequest(t, f, current.Client, "managed-oidc-delete", 0).Management
			if _, err := restarted.ClientDelete(f.ctx, remove); err != nil {
				t.Fatal("managed OIDC terminal deletion failed", err)
			}
			if recovered, err := freshStore.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-create", CommandID: created.Completion.CommandID, ClientID: current.Client.ID, TenantID: f.tenant, Session: f.browser}); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("deleted managed OIDC original recovery lost metadata", err)
			}
			for _, service := range []*oauth.Service{service, fresh, restarted} {
				if got, err := service.ClientGet(f.ctx, oauth.ClientReadRequest{Owner: r.Owner, TenantID: f.tenant, Session: f.browser, ClientID: current.Client.ID}); err == nil || got.Client.ID != "" {
					t.Fatal("warm service disclosed deleted OIDC registration")
				}
				if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: current.Client.ID, RefreshToken: token.RefreshToken, Network: "192.0.2.1"}); err == nil {
					t.Fatal("deleted managed OIDC client regained descendants")
				}
			}
		})
	}
}

func TestNativeManagedPublicOIDCUnknownCreateRetainsCurrentAuthorizedRecovery(t *testing.T) {
	testNativeManagedOIDCUnknownCreateRetainsCurrentAuthorizedRecovery(t, true)
}

func testNativeManagedOIDCUnknownCreateRetainsCurrentAuthorizedRecovery(t *testing.T, public bool) {
	t.Helper()
	fault := &oauthCommitFault{}
	f := passwordFixture(t, fault)
	var signer *oauth.SigningService
	var subjectKey [32]byte
	if public {
		signer, subjectKey = managedOIDCFixture(t, &f, false)
		f.oauth.Protocol.ManagedClients.PublicOIDC = true
	} else {
		signer, subjectKey = managedConfidentialOIDCFixture(t, &f, false)
		f.oauth.Protocol.ManagedClients.ConfidentialOIDC = true
	}
	service, _, store := managedOIDCServices(t, f, signer, subjectKey)
	r := clientCreateRequest(t, f, "managed-oidc-unknown")
	r.Public, r.Scopes = public, []string{"openid"}
	fault.armed.Store(true)
	lost, err := service.ClientCreate(f.ctx, r)
	if err == nil || !fault.hit.Load() || lost.Completion.Outcome != identity.CommitOutcomeUnknown {
		t.Fatalf("managed OIDC unknown COMMIT seam missed: hit=%t outcome_unknown=%t command_present=%t unavailable=%t deadline=%t canceled=%t error_type=%T", fault.hit.Load(), lost.Completion.Outcome == identity.CommitOutcomeUnknown, lost.Completion.CommandID != "", errors.Is(err, oauth.ErrUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), err)
	}
	if _, err := lost.Secret.Reveal(); err == nil {
		t.Fatal("unknown managed OIDC creation exposed secret")
	}
	rr := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-create", CommandID: lost.Completion.CommandID, ClientID: oauth.ManagedClientPrefix + string(lost.Completion.CommandID), TenantID: f.tenant, Session: f.browser}
	manager := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
	manager.denied.Store(true)
	if _, err := store.Recover(f.ctx, rr); err == nil {
		t.Fatal("managed OIDC original recovery bypassed current manager")
	}
	manager.denied.Store(false)
	for i := 0; i < 2; i++ {
		recovered, err := store.Recover(f.ctx, rr)
		if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.CommandID != lost.Completion.CommandID {
			t.Fatal("managed OIDC exact original metadata recovery failed", err)
		}
	}
	fresh, _, _ := managedOIDCServices(t, f, signer, subjectKey)
	retry, err := fresh.ClientCreate(f.ctx, r)
	if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != lost.Completion.CommandID || retry.Client.ID != rr.ClientID {
		t.Fatal("unknown managed OIDC retry created different authority", err)
	}
	if _, err := retry.Secret.Reveal(); err == nil {
		t.Fatal("recovered managed OIDC result exposed secret")
	}
	var clients, effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.managed_clients WHERE client_id=$1 AND (secret_digest IS NULL)=$2`, rr.ClientID, public).Scan(&clients); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-create' AND client_id=$1`, rr.ClientID).Scan(&effects); err != nil || clients != 1 || effects != 1 {
		t.Fatal("unknown managed OIDC duplicated registration/effects", err)
	}
}

func TestNativeManagedPublicOIDCRequiredEffectsRollbackAndOriginalRecovery(t *testing.T) {
	testNativeManagedClientRequiredEffectsProfile(t, true, true)
}

func TestNativeManagedPublicOIDCDeletionFencesLateApprovalExchangeAndRefresh(t *testing.T) {
	testNativeManagedClientDeletionFences(t, true, true)
}

func TestNativeManagedPublicOIDCUncomposedContinuationPreservesOriginalInteraction(t *testing.T) {
	f := passwordFixture(t)
	signer, subjectKey := managedOIDCFixture(t, &f, false)
	f.oauth.Protocol.ManagedClients.PublicOIDC = true
	service, _, _ := managedOIDCServices(t, f, signer, subjectKey)
	r := clientCreateRequest(t, f, "managed-oidc-uncomposed-continue")
	r.Public, r.Scopes = true, []string{"openid"}
	created, err := service.ClientCreate(f.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	verifier := oauth2.GenerateVerifier()
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: created.Client.ID, RedirectURI: created.Client.Redirects[0], Resource: created.Client.Resource, Scopes: []string{"openid"}, Nonce: "continuation-original-nonce", CodeChallenge: oauth2.S256ChallengeFromVerifier(verifier)}})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("minimal OIDC did not reach original explicit consent", err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	uncomposed, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	approval := oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: created.Client.ID, Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true}
	if out, err := uncomposed.Continue(f.ctx, approval); !errors.Is(err, oauth.ErrAccessDenied) || out.Outcome != 0 {
		t.Fatal("uncomposed minimal OIDC committed approval", err)
	}
	approved, err := service.Continue(f.ctx, approval)
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect || approved.Request.Nonce != "continuation-original-nonce" {
		t.Fatal("uncomposed attempt consumed or changed the genuine original interaction", err)
	}
	location, err := approved.Location()
	if err != nil {
		t.Fatal(err)
	}
	callback, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: created.Client.ID, Code: callback.Query().Get("code"), CodeVerifier: verifier, RedirectURI: created.Client.Redirects[0], Network: "192.0.2.1"})
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("preserved genuine interaction did not issue usable OIDC tokens", err)
	}
	if _, err := issued.IDToken.Reveal(); err != nil {
		t.Fatal("preserved original interaction lost its OIDC result", err)
	}
}

func TestNativeManagedPublicOIDCDeletionFencesPausedUserInfo(t *testing.T) {
	f := passwordFixture(t)
	signer, subjectKey := managedOIDCFixture(t, &f, false)
	f.oauth.Protocol.ManagedClients.PublicOIDC = true
	service, _, _ := managedOIDCServices(t, f, signer, subjectKey)
	r := clientCreateRequest(t, f, "managed-oidc-late-userinfo")
	r.Public, r.Scopes = true, []string{"openid"}
	created, err := service.ClientCreate(f.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := confidentialCodeScopes(t, f, service, created.Client, []string{"openid"})
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: created.Client.ID, Code: code, CodeVerifier: verifier, RedirectURI: created.Client.Redirects[0], Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	access, _ := issued.AccessToken.Reveal()
	gate := &resourceReadGate{reached: make(chan struct{}), proceed: make(chan struct{})}
	original := f.pool.Raw().Config().ConnConfig
	pool, err := database.Connect(f.ctx, database.Config{DSN: original.ConnString(), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = original.Database
		c.ConnConfig.RuntimeParams = maps.Clone(original.RuntimeParams)
		c.ConnConfig.Tracer = gate
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if pool.Close(ctx) != nil {
			t.Error("owned managed OIDC traced pool cleanup")
		}
	}()
	traced := f
	traced.pool = pool
	_, child, _ := managedOIDCServices(t, traced, signer, subjectKey)
	request := oauth.UserInfoRequest{ClientID: created.Client.ID, AccessToken: access}
	if info, err := child.UserInfo(f.ctx, request); err != nil || info.Subject == "" {
		t.Fatal("managed OIDC UserInfo positive control", err)
	}
	ctx, cancel := context.WithCancel(context.WithValue(f.ctx, resourceReadKey{}, true))
	defer cancel()
	type result struct {
		info op.UserInfo
		err  error
	}
	done := make(chan result, 1)
	joined := false
	defer func() {
		cancel()
		select {
		case <-gate.proceed:
		default:
			close(gate.proceed)
		}
		if !joined {
			<-done
		}
	}()
	go func() { info, err := child.UserInfo(ctx, request); done <- result{info, err} }()
	select {
	case <-gate.reached:
	case out := <-done:
		joined = true
		t.Fatal("managed OIDC UserInfo missed actual second primary lookup", out.err)
	case <-f.ctx.Done():
		t.Fatal("bounded managed OIDC UserInfo gate canceled")
	}
	remove := clientRotationRequest(t, f, created.Client, "managed-oidc-late-delete", 0).Management
	if _, err := service.ClientDelete(f.ctx, remove); err != nil {
		t.Fatal(err)
	}
	close(gate.proceed)
	out := <-done
	joined = true
	denied := errors.Is(out.err, oauth.ErrAccessDenied) || errors.Is(out.err, oauth.ErrUnavailable)
	if !denied || out.info != (op.UserInfo{}) {
		t.Fatalf("late terminal deletion did not return a redacted denial with zero claims: denied=%t zero_claims=%t error_type=%T", denied, out.info == (op.UserInfo{}), out.err)
	}
}
