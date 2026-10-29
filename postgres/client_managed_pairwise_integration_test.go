//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/oauth2"
)

func managedPairwiseFixture(t *testing.T, f *authenticatedPasswordFixture) (*oauth.SigningService, [32]byte) {
	t.Helper()
	signer, defaultKey := managedConfidentialOIDCFixture(t, f, false)
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
	base = oauthpostgres.ConsentMigrationSource{Base: base, Schema: "oauth_store", Version: 7002}
	base = oauthpostgres.ClientMigrationSource{Base: base, Schema: "oauth_store", Version: 7003}
	base = oauthpostgres.ClientRotationMigrationSource{Base: base, Schema: "oauth_store", Version: 7004}
	base = oauthpostgres.SigningMigrationSource{Base: base, Schema: "oauth_store", Version: 7005}
	runner, err := migrations.NewRunner(oauthpostgres.PairwiseMigrationSource{Base: base, Schema: "oauth_store", Version: 7006}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("managed pairwise additive history failed", err)
	}
	f.oauth.Protocol.ManagedClients.ConfidentialOIDC = true
	return signer, defaultKey
}

func managedPairwiseServices(t *testing.T, f authenticatedPasswordFixture, signer *oauth.SigningService, defaultKey [32]byte, policy *op.SubjectPolicy) (*oauth.Service, *op.Service, *oauthpostgres.Store) {
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
	child, err := op.NewService(op.Config{Issuer: f.oauth.Protocol.Issuer, JWKSURI: issuer + "/oauth2/jwks", UserInfoEndpoint: issuer + "/oauth2/userinfo", Signing: signer, SubjectKey: defaultKey, SubjectPolicy: policy, Clock: clock.System{}, MaximumDuration: 4 * time.Second}, core)
	if err != nil {
		t.Fatal(err)
	}
	service, err := core.WithOIDC(child)
	if err != nil {
		t.Fatal(err)
	}
	return service, child, store
}

func randomPairwisePolicy(t *testing.T, f authenticatedPasswordFixture, version uint32) *op.SubjectPolicy {
	t.Helper()
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		t.Fatal("pairwise derivation custody unavailable")
	}
	defer clear(material[:])
	return pairwisePolicy(t, f, version, material)
}

func TestNativeManagedPairwisePolicyBootstrapsWithoutStaticRegistration(t *testing.T) {
	f := passwordFixture(t)
	signer, defaultKey := managedPairwiseFixture(t, &f)
	before, _, _ := managedOIDCServices(t, f, signer, defaultKey)
	originalRequest := clientCreateRequest(t, f, "before-managed-pairwise")
	originalRequest.Scopes = []string{"openid"}
	original, err := before.ClientCreate(f.ctx, originalRequest)
	if err != nil || original.Client.SubjectRegistration != nil {
		t.Fatal("original default-subject registration failed", err)
	}
	var originalWire, originalDigest []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, original.Client.ID).Scan(&originalWire, &originalDigest); err != nil {
		t.Fatal("original default registration custody unavailable", err)
	}
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "managed.example", "subjects", 1)
	f.oauth.Protocol.ManagedClients.PairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
	for _, client := range f.oauth.Protocol.Clients {
		if client.SubjectRegistration != nil {
			t.Fatal("managed key bootstrap fabricated static pairwise registration")
		}
	}
	policy := randomPairwisePolicy(t, f, 1)
	service, _, store := managedPairwiseServices(t, f, signer, defaultKey, policy)
	key, err := policy.KeyRegistration(1)
	if err != nil || store.InstallSubjectKey(f.ctx, key) != nil {
		t.Fatal("trusted managed-only policy cannot install actual encrypted subject custody")
	}
	if err := store.ActivateSubjectKey(f.ctx, "subjects", 1, 1); err != nil {
		t.Fatal("trusted managed-only policy cannot activate its existing writer", err)
	}
	replayed, err := service.ClientCreate(f.ctx, originalRequest)
	if err != nil || !replayed.Completion.Replayed || replayed.Completion.CommandID != original.Completion.CommandID || replayed.Client.SubjectRegistration != nil {
		t.Fatal("pairwise activation changed original default-subject recovery", err)
	}
	if _, err := replayed.Secret.Reveal(); err == nil {
		t.Fatal("original default-subject replay redelivered secret")
	}
	var retainedWire, retainedDigest []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, original.Client.ID).Scan(&retainedWire, &retainedDigest); err != nil || !bytes.Equal(originalWire, retainedWire) || !bytes.Equal(originalDigest, retainedDigest) {
		t.Fatal("pairwise activation rewrote original registration or confidential digest")
	}
	r := clientCreateRequest(t, f, "managed-pairwise-original")
	r.Scopes, r.SubjectRegistration = []string{"openid"}, &registration
	manager := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
	manager.denied.Store(true)
	if out, err := service.ClientCreate(f.ctx, r); err == nil || out.Client.ID != "" {
		t.Fatal("pairwise management bypassed current manager")
	}
	manager.denied.Store(false)
	created, err := service.ClientCreate(f.ctx, r)
	if err != nil || created.Client.Public || created.Client.AuthenticationMethod != "client_secret_basic" || created.Client.SubjectRegistration == nil || *created.Client.SubjectRegistration != registration {
		t.Fatal("genuine manager did not commit exact pairwise registration", err)
	}
	rebuilt, _, _ := managedPairwiseServices(t, f, signer, defaultKey, policy)
	read := oauth.ClientReadRequest{Owner: r.Owner, TenantID: f.tenant, Session: f.browser, ClientID: created.Client.ID}
	got, err := rebuilt.ClientGet(f.ctx, read)
	if err != nil || got.Client.SubjectRegistration == nil || *got.Client.SubjectRegistration != registration {
		t.Fatal("reconstructed safe read lost immutable pairwise metadata", err)
	}
	read.ClientID, read.Limit = "", 100
	listed, err := rebuilt.ClientList(f.ctx, read)
	if err != nil || !slices.ContainsFunc(listed.Page.Items(), func(c oauth.Client) bool {
		return c.ID == created.Client.ID && c.SubjectRegistration != nil && *c.SubjectRegistration == registration
	}) {
		t.Fatal("safe manager list lost exact pairwise registration", err)
	}
	retry, err := rebuilt.ClientCreate(f.ctx, r)
	if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != created.Completion.CommandID || retry.Client.SubjectRegistration == nil || *retry.Client.SubjectRegistration != registration {
		t.Fatal("pairwise exact original recovery lost policy binding", err)
	}
	if _, err := retry.Secret.Reveal(); err == nil {
		t.Fatal("pairwise replay redelivered confidential secret")
	}
	verifier := oauth2.GenerateVerifier()
	pending, err := rebuilt.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: created.Client.ID, RedirectURI: created.Client.Redirects[0], Resource: created.Client.Resource, Scopes: []string{"openid"}, Nonce: "pairwise-session-withdrawal", CodeChallenge: oauth2.S256ChallengeFromVerifier(verifier)}})
	if err != nil || pending.Outcome != oauth.ConsentRequired {
		t.Fatal("pairwise session withdrawal did not reach original consent", err)
	}
	continuation, err := pending.Continuation.Reveal()
	if err != nil {
		t.Fatal("original pairwise continuation unavailable")
	}
	f.signOut()
	if _, err := rebuilt.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: created.Client.ID, Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true}); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("withdrawn original browser approved pairwise consent", err)
	}
	if out, err := rebuilt.ClientCreate(f.ctx, r); err == nil || out.Client.ID != "" {
		t.Fatal("withdrawn original manager session recovered pairwise authority")
	}
	read.ClientID, read.Limit = created.Client.ID, 0
	if out, err := rebuilt.ClientGet(f.ctx, read); err == nil || out.Client.ID != "" {
		t.Fatal("withdrawn original manager session disclosed pairwise metadata")
	}
}

func consumeManagedPairwise(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service, child *op.Service, client oauth.Client, secret, nonce string) (*oauth2.Token, *rp.IDToken) {
	t.Helper()
	transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child, userInfoClientID: client.ID}
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := rp.ClientContext(f.ctx, httpClient)
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal("managed pairwise independent RP discovery failed", err)
	}
	standard := oauth2.Config{ClientID: client.ID, ClientSecret: secret, RedirectURL: client.Redirects[0], Scopes: []string{"openid"}, Endpoint: provider.Endpoint()}
	standard.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	verifier := oauth2.GenerateVerifier()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, standard.AuthCodeURL("pairwise-state", oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("resource", client.Resource)), nil)
	if err != nil {
		t.Fatal("managed pairwise RP request failed")
	}
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal("managed pairwise RP consent/S256 failed", err)
	}
	response.Body.Close()
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil || callback.Query().Get("state") != "pairwise-state" || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() || callback.Query().Get("code") == "" {
		t.Fatal("managed pairwise RP callback lost issuer/state/code")
	}
	token, err := standard.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal("managed pairwise RP confidential code exchange failed", err)
	}
	wire, ok := token.Extra("id_token").(string)
	if !ok {
		t.Fatal("managed pairwise RP received no signed ID token")
	}
	verified, err := consumeIDToken(ctx, provider, wire, nonce, client.ID)
	if err != nil || verified.Subject == "" || !time.Now().Before(verified.Expiry) {
		t.Fatal("independent RP rejected pairwise issuer/audience/nonce/signature/expiry", err)
	}
	if _, err := consumeIDToken(ctx, provider, wire, "foreign-nonce", client.ID); err == nil {
		t.Fatal("pairwise independent RP accepted a foreign nonce")
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	var claims map[string]json.RawMessage
	if err != nil || info.Subject != verified.Subject || info.Claims(&claims) != nil || len(claims) != 1 || claims["sub"] == nil {
		t.Fatal("managed pairwise UserInfo lost equal sub or disclosed unselected claims", err)
	}
	return token, verified
}

func managedPairwiseAuthorizationDenied(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service, client oauth.Client) {
	t.Helper()
	var beforeGrants, beforeBindings, afterGrants, afterBindings int
	read := func(grants, bindings *int) {
		t.Helper()
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.subject_bindings)`).Scan(grants, bindings); err != nil {
			t.Fatal("pairwise denial state unavailable", err)
		}
	}
	read(&beforeGrants, &beforeBindings)
	verifier := oauth2.GenerateVerifier()
	out, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: client.ID, RedirectURI: client.Redirects[0], Resource: client.Resource, Scopes: []string{"openid"}, Nonce: "pairwise-denial-nonce", CodeChallenge: oauth2.S256ChallengeFromVerifier(verifier)}})
	if err == nil || out.Outcome != 0 && out.Outcome != oauth.AuthorizationHistorical && out.Outcome != oauth.AuthorizationUnknown || out.Continuation != (oauth.Token{}) || out.Code != (oauth.Token{}) || out.RedirectURI != "" {
		t.Fatalf("missing, foreign or retired custody exposed authorization: error_present=%t historical=%t unknown=%t continuation=%t code=%t redirect=%t", err != nil, out.Outcome == oauth.AuthorizationHistorical, out.Outcome == oauth.AuthorizationUnknown, out.Continuation != (oauth.Token{}), out.Code != (oauth.Token{}), out.RedirectURI != "")
	}
	read(&afterGrants, &afterBindings)
	if beforeGrants != afterGrants || beforeBindings != afterBindings {
		t.Fatal("denied pairwise custody created grant or subject authority")
	}
}

func TestNativeManagedPairwiseFreshAndPopulatedIndependentConsumer(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated"}[populated], func(t *testing.T) {
			f := passwordFixture(t)
			signer, defaultKey := managedPairwiseFixture(t, &f)
			f.oauth.Protocol.ManagedClients.Redirects = append(f.oauth.Protocol.ManagedClients.Redirects, "https://other.example/callback")
			var legacy oauth.ClientManagementResult
			var legacyRequest oauth.ClientManagementRequest
			var legacyBasic oauth.ClientAuthentication
			var legacyRefresh string
			if populated {
				before, beforeChild, _ := managedOIDCServices(t, f, signer, defaultKey)
				legacyRequest = clientCreateRequest(t, f, "pairwise-baseline")
				legacyRequest.Scopes = []string{"openid"}
				var err error
				legacy, err = before.ClientCreate(f.ctx, legacyRequest)
				if err != nil {
					t.Fatal("original default-subject OIDC client failed", err)
				}
				secret, err := legacy.Secret.Reveal()
				if err != nil {
					t.Fatal("original default-subject secret unavailable")
				}
				legacyBasic = confidentialBasic(t, legacy.Client.ID, secret)
				originalToken, _ := consumeManagedPairwise(t, f, before, beforeChild, legacy.Client, secret, "pairwise-original-default-nonce")
				legacyRefresh = originalToken.RefreshToken
			}
			registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "managed.example", "subjects", 1)
			other, _ := oauth.NewOIDCSubjectRegistration("pairwise", "other.example", "subjects", 1)
			f.oauth.Protocol.ManagedClients.PairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration, other}
			policy := randomPairwisePolicy(t, f, 1)
			service, child, store := managedPairwiseServices(t, f, signer, defaultKey, policy)
			if populated {
				retry, err := service.ClientCreate(f.ctx, legacyRequest)
				if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != legacy.Completion.CommandID || retry.Client.SubjectRegistration != nil {
					t.Fatal("pairwise activation stranded original OIDC create", err)
				}
				if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: legacy.Client.ID, ClientAuthentication: legacyBasic, RefreshToken: legacyRefresh, Network: "192.0.2.1"}); err != nil {
					t.Fatal("pairwise activation stranded original OIDC grant", err)
				}
			}
			clients := make([]oauth.Client, 3)
			secrets := make([]string, 3)
			for i, label := range []string{"pairwise-first", "pairwise-same-sector", "pairwise-other-sector"} {
				r := clientCreateRequest(t, f, label)
				r.Scopes, r.SubjectRegistration = []string{"openid"}, &registration
				if i == 2 {
					r.Redirects, r.SubjectRegistration = []string{"https://other.example/callback"}, &other
				}
				created, err := service.ClientCreate(f.ctx, r)
				if err != nil {
					t.Fatal("managed pairwise registration failed", err)
				}
				clients[i] = created.Client
				secrets[i], err = created.Secret.Reveal()
				if err != nil {
					t.Fatal("new committed pairwise secret unavailable")
				}
			}
			managedPairwiseAuthorizationDenied(t, f, service, clients[0])
			key, _ := policy.KeyRegistration(1)
			foreignKey := key
			foreignKey.Environment = "foreign-environment"
			if err := store.InstallSubjectKey(f.ctx, foreignKey); err == nil {
				t.Fatal("foreign-context subject envelope acquired managed custody")
			}
			if err := store.InstallSubjectKey(f.ctx, key); err != nil {
				t.Fatal("managed policy key install failed", err)
			}
			if err := store.ActivateSubjectKey(f.ctx, "subjects", 1, 1); err != nil {
				t.Fatal(err)
			}
			foreign, _, _ := managedPairwiseServices(t, f, signer, defaultKey, randomPairwisePolicy(t, f, 1))
			managedPairwiseAuthorizationDenied(t, f, foreign, clients[0])
			token, first := consumeManagedPairwise(t, f, service, child, clients[0], secrets[0], "pairwise-first-nonce")
			sameToken, same := consumeManagedPairwise(t, f, service, child, clients[1], secrets[1], "pairwise-same-nonce")
			_, isolated := consumeManagedPairwise(t, f, service, child, clients[2], secrets[2], "pairwise-other-nonce")
			if first.Subject != same.Subject || first.Subject == isolated.Subject {
				t.Fatal("managed pairwise identity lost same-sector stability or sector isolation")
			}
			next := randomPairwisePolicy(t, f, 2)
			key2, _ := next.KeyRegistration(2)
			if err := store.InstallSubjectKey(f.ctx, key2); err != nil {
				t.Fatal(err)
			}
			if err := store.ActivateSubjectKey(f.ctx, "subjects", 1, 2); err != nil {
				t.Fatal(err)
			}
			if err := store.RetireSubjectKey(f.ctx, "subjects", 1, 1); err != nil {
				t.Fatal(err)
			}
			managedPairwiseAuthorizationDenied(t, f, service, clients[0])
			retained, active, err := store.SubjectKeyRegistrations(f.ctx, "subjects", 1)
			if err != nil || active != 2 || len(retained) != 1 || retained[0].KeyVersion != 2 {
				t.Fatal("managed policy reconstruction restored retired custody", err)
			}
			cipher, _ := envelope.NewService(f.keys)
			restored, err := op.NewSubjectPolicy(f.ctx, op.SubjectPolicyConfig{Issuer: f.oauth.Protocol.Issuer, Environment: f.oauth.Protocol.Environment, PolicyID: "subjects", PolicyVersion: 1, ActiveKeyVersion: active, Keys: []op.SubjectKeyEnvelope{{Version: retained[0].KeyVersion, Envelope: retained[0].Envelope}}}, cipher)
			if err != nil {
				t.Fatal(err)
			}
			rebuilt, rebuiltChild, _ := managedPairwiseServices(t, f, signer, defaultKey, restored)
			if info, err := rebuiltChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: clients[0].ID, AccessToken: token.AccessToken}); err != nil || info.Subject != first.Subject {
				t.Fatal("reconstruction/key retirement changed retained subject", err)
			}
			_, after := consumeManagedPairwise(t, f, rebuilt, rebuiltChild, clients[0], secrets[0], "pairwise-reconstructed-nonce")
			if after.Subject != first.Subject {
				t.Fatal("new grant after key rotation changed durable subject")
			}
			basic := confidentialBasic(t, clients[0].ID, secrets[0])
			refreshed, err := rebuilt.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: clients[0].ID, ClientAuthentication: basic, RefreshToken: token.RefreshToken, Network: "192.0.2.1"})
			if err != nil {
				t.Fatal("pairwise original refresh failed after reconstruction", err)
			}
			access, _ := refreshed.AccessToken.Reveal()
			if info, err := rebuiltChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: clients[0].ID, AccessToken: access}); err != nil || info.Subject != first.Subject {
				t.Fatal("pairwise refresh lost equal stable sub", err)
			}
			remove := clientRotationRequest(t, f, clients[0], "pairwise-delete", 0).Management
			if _, err := rebuilt.ClientDelete(f.ctx, remove); err != nil {
				t.Fatal("managed pairwise deletion failed", err)
			}
			if info, err := rebuiltChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: clients[0].ID, AccessToken: access}); err == nil || info != (op.UserInfo{}) {
				t.Fatal("terminal pairwise deletion retained claims")
			}
			bindings, err := originalClientRead(t, f).Session.Session.Bindings()
			if err != nil {
				t.Fatal("actual original user custody unavailable")
			}
			suspendResourceUser(t, f, bindings.UserID)
			if info, err := rebuiltChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: clients[1].ID, AccessToken: sameToken.AccessToken}); err == nil || info != (op.UserInfo{}) {
				t.Fatal("withdrawn actual user retained pairwise claims")
			}
			if _, err := rebuilt.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: clients[1].ID, ClientAuthentication: confidentialBasic(t, clients[1].ID, secrets[1]), RefreshToken: sameToken.RefreshToken, Network: "192.0.2.1"}); err == nil {
				t.Fatal("withdrawn actual user renewed pairwise grant")
			}
		})
	}
}

func TestNativeManagedPairwiseRequiredEffectsAndUnknownOriginalRecovery(t *testing.T) {
	for _, mode := range []string{"audit", "outbox", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			var provisional atomic.Bool
			fault := &oauthCommitFault{beforeWrite: func(wire []byte) {
				if bytes.Contains(wire, []byte(`INSERT INTO "oauth_store".managed_clients`)) {
					provisional.Store(true)
				}
			}}
			f := passwordFixture(t, fault)
			signer, defaultKey := managedPairwiseFixture(t, &f)
			registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "managed.example", "subjects", 1)
			f.oauth.Protocol.ManagedClients.PairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
			policy := randomPairwisePolicy(t, f, 1)
			service, _, store := managedPairwiseServices(t, f, signer, defaultKey, policy)
			if mode == "audit" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE audit.records ADD CONSTRAINT refuse_pairwise_audit CHECK(action<>'identity.oauth_server.create_client')`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "outbox" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_pairwise_event CHECK(topic<>'oauth_client.created.v1') NOT VALID`); err != nil {
					t.Fatal(err)
				}
			}
			r := clientCreateRequest(t, f, "managed-pairwise-required-"+mode)
			r.Scopes, r.SubjectRegistration = []string{"openid"}, &registration
			fault.armed.Store(mode == "unknown")
			out, err := service.ClientCreate(f.ctx, r)
			if err == nil || !provisional.Load() {
				t.Fatal("required pairwise failure did not reach protected native mutation")
			}
			if _, err := out.Secret.Reveal(); err == nil {
				t.Fatal("uncertain/failed pairwise creation delivered secret")
			}
			want := 0
			if mode == "unknown" {
				want = 1
				if !fault.hit.Load() || out.Completion.Outcome != identity.CommitOutcomeUnknown || out.Completion.CommandID == "" {
					t.Fatal("pairwise original COMMIT seam not reached")
				}
				rr := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-create", CommandID: out.Completion.CommandID, ClientID: oauth.ManagedClientPrefix + string(out.Completion.CommandID), TenantID: f.tenant, Session: f.browser}
				manager := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
				manager.denied.Store(true)
				if _, err := store.Recover(f.ctx, rr); err == nil {
					t.Fatal("pairwise original recovery bypassed current manager")
				}
				manager.denied.Store(false)
				metadata, err := store.Recover(f.ctx, rr)
				if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted || metadata.CommandID != rr.CommandID {
					t.Fatal("pairwise original metadata recovery failed", err)
				}
				rebuilt, _, _ := managedPairwiseServices(t, f, signer, defaultKey, policy)
				retry, err := rebuilt.ClientCreate(f.ctx, r)
				if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != rr.CommandID || retry.Client.SubjectRegistration == nil || *retry.Client.SubjectRegistration != registration {
					t.Fatal("pairwise original replay lost immutable registration", err)
				}
				if _, err := retry.Secret.Reveal(); err == nil {
					t.Fatal("pairwise unknown recovery redelivered secret")
				}
			}
			var clients, effects, audits, events int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.managed_clients),(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-create'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.create_client' AND outcome=1),(SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_client.created.v1')`).Scan(&clients, &effects, &audits, &events); err != nil || clients != want || effects != want || audits != want || events != want {
				t.Fatal("managed pairwise required effects were not atomic", err)
			}
		})
	}
}
