//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
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

func managedPublicPairwiseFixture(t *testing.T, f *authenticatedPasswordFixture, populated bool) (*oauth.SigningService, [32]byte) {
	t.Helper()
	signer, key := managedOIDCFixture(t, f, populated)
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
	var source migrations.Source = oauthpostgres.ClientMigrationSource{Base: oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}, Schema: "oauth_store", Version: 7003}
	version := migrations.Version(7004)
	if populated {
		source = oauthpostgres.ClientRotationMigrationSource{Base: source, Schema: "oauth_store", Version: version}
		version++
	}
	source = oauthpostgres.ClientPublicMigrationSource{Base: source, Schema: "oauth_store", Version: version}
	version++
	source = oauthpostgres.SigningMigrationSource{Base: source, Schema: "oauth_store", Version: version}
	version++
	runner, err := migrations.NewRunner(oauthpostgres.PairwiseMigrationSource{Base: source, Schema: "oauth_store", Version: version}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("public pairwise additive history failed", err)
	}
	f.oauth.Protocol.ManagedClients.PublicOIDC = true
	return signer, key
}

func consumeManagedPublicPairwise(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service, child *op.Service, client oauth.Client, nonce string) (*oauth2.Token, *rp.IDToken) {
	t.Helper()
	transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child, userInfoClientID: client.ID}
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := rp.ClientContext(f.ctx, httpClient)
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal("public pairwise independent RP discovery failed", err)
	}
	standard := oauth2.Config{ClientID: client.ID, RedirectURL: client.Redirects[0], Scopes: []string{"openid"}, Endpoint: provider.Endpoint()}
	standard.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	verifier := oauth2.GenerateVerifier()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, standard.AuthCodeURL("public-pairwise-state", oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("resource", client.Resource)), nil)
	if err != nil {
		t.Fatal("public pairwise RP request failed")
	}
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal("public pairwise RP consent/S256 failed", err)
	}
	response.Body.Close()
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil || callback.Query().Get("state") != "public-pairwise-state" || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() || callback.Query().Get("code") == "" {
		t.Fatal("public pairwise callback lost issuer/state/code")
	}
	code := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: callback.Query().Get("code"), CodeVerifier: verifier, RedirectURI: client.Redirects[0], Network: "192.0.2.1"}
	wrong := code
	wrong.CodeVerifier = strings.Repeat("z", 43)
	if out, err := service.Token(f.ctx, wrong); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("public pairwise accepted invalid PKCE")
	}
	wrong = code
	secret, _ := oauth.NewToken()
	wireSecret, _ := secret.Reveal()
	wrong.ClientAuthentication = confidentialBasic(t, client.ID, wireSecret)
	if out, err := service.Token(f.ctx, wrong); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("public pairwise accepted forbidden Basic authentication")
	}
	token, err := standard.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal("public pairwise secretless code exchange failed", err)
	}
	wire, ok := token.Extra("id_token").(string)
	if !ok {
		t.Fatal("public pairwise RP received no signed ID token")
	}
	verified, err := consumeIDToken(ctx, provider, wire, nonce, client.ID)
	if err != nil || verified.Subject == "" || !time.Now().Before(verified.Expiry) {
		t.Fatal("independent RP rejected public pairwise issuer/audience/nonce/signature/expiry", err)
	}
	if _, err := consumeIDToken(ctx, provider, wire, "foreign-nonce", client.ID); err == nil {
		t.Fatal("public pairwise RP accepted a foreign nonce")
	}
	if _, err := consumeIDToken(ctx, provider, wire, nonce, "foreign-client"); err == nil {
		t.Fatal("public pairwise RP accepted a foreign audience")
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	var claims map[string]json.RawMessage
	if err != nil || info.Subject != verified.Subject || info.Claims(&claims) != nil || len(claims) != 1 || claims["sub"] == nil {
		t.Fatal("public pairwise UserInfo lost equal sub or disclosed unselected claims", err)
	}
	return token, verified
}

func TestNativeManagedPublicPairwiseFreshAndPopulatedIndependentConsumer(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated"}[populated], func(t *testing.T) {
			f := passwordFixture(t)
			signer, defaultKey := managedPublicPairwiseFixture(t, &f, populated)
			f.oauth.Protocol.ManagedClients.Redirects = append(f.oauth.Protocol.ManagedClients.Redirects, "https://other.example/callback")
			var legacy oauth.ClientManagementResult
			var legacyRequest oauth.ClientManagementRequest
			var legacyToken *oauth2.Token
			var legacySubject string
			var legacyBytes []byte
			if populated {
				before, child, _ := managedOIDCServices(t, f, signer, defaultKey)
				legacyRequest = clientCreateRequest(t, f, "public-pairwise-default-baseline")
				legacyRequest.Public, legacyRequest.Scopes = true, []string{"openid"}
				var err error
				legacy, err = before.ClientCreate(f.ctx, legacyRequest)
				if err != nil {
					t.Fatal("original default-public OIDC creation failed", err)
				}
				var verified *rp.IDToken
				legacyToken, verified = consumeManagedPublicPairwise(t, f, before, child, legacy.Client, "public-pairwise-default-nonce")
				legacySubject = verified.Subject
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration FROM oauth_store.managed_clients WHERE client_id=$1`, legacy.Client.ID).Scan(&legacyBytes); err != nil {
					t.Fatal("original public registration unavailable", err)
				}
			}
			registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "managed.example", "subjects", 1)
			other, _ := oauth.NewOIDCSubjectRegistration("pairwise", "other.example", "subjects", 1)
			f.oauth.Protocol.ManagedClients.PublicPairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration, other}
			if f.oauth.Protocol.ManagedClients.ConfidentialOIDC || len(f.oauth.Protocol.ManagedClients.PairwiseRegistrations) != 0 {
				t.Fatal("public pairwise fixture borrowed confidential selection")
			}
			for _, c := range f.oauth.Protocol.Clients {
				if c.SubjectRegistration != nil {
					t.Fatal("public pairwise fixture fabricated a static registration")
				}
			}
			policy := randomPairwisePolicy(t, f, 1)
			service, child, store := managedPairwiseServices(t, f, signer, defaultKey, policy)
			key, _ := policy.KeyRegistration(1)
			if err := store.InstallSubjectKey(f.ctx, key); err != nil {
				t.Fatal("public-only policy cannot install genuine subject custody", err)
			}
			if err := store.ActivateSubjectKey(f.ctx, "subjects", 1, 1); err != nil {
				t.Fatal("public-only policy cannot activate existing subject owner", err)
			}
			if populated {
				retry, err := service.ClientCreate(f.ctx, legacyRequest)
				if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != legacy.Completion.CommandID || retry.Client.SubjectRegistration != nil {
					t.Fatal("public pairwise activation stranded original default recovery", err)
				}
				var retained []byte
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration FROM oauth_store.managed_clients WHERE client_id=$1`, legacy.Client.ID).Scan(&retained); err != nil || !bytes.Equal(retained, legacyBytes) {
					t.Fatal("public pairwise activation changed original registration bytes", err)
				}
				rotated, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: legacy.Client.ID, RefreshToken: legacyToken.RefreshToken, Network: "192.0.2.1"})
				access, _ := rotated.AccessToken.Reveal()
				if err != nil {
					t.Fatal("public pairwise activation stranded original default refresh", err)
				}
				if info, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: legacy.Client.ID, AccessToken: access}); err != nil || info.Subject != legacySubject {
					t.Fatal("public pairwise activation changed original default subject", err)
				}
			}
			clients := make([]oauth.Client, 3)
			for i, label := range []string{"public-pairwise-first", "public-pairwise-same", "public-pairwise-other"} {
				r := clientCreateRequest(t, f, label)
				r.Public, r.Scopes, r.SubjectRegistration = true, []string{"openid"}, &registration
				if i == 2 {
					r.Redirects, r.SubjectRegistration = []string{"https://other.example/callback"}, &other
				}
				created, err := service.ClientCreate(f.ctx, r)
				if err != nil || !created.Client.Public || created.Client.AuthenticationMethod != "none" || created.Client.SubjectRegistration == nil || *created.Client.SubjectRegistration != *r.SubjectRegistration {
					t.Fatal("genuine manager did not commit exact public pairwise registration", err)
				}
				if _, err := created.Secret.Reveal(); err == nil {
					t.Fatal("public pairwise creation revealed a client secret")
				}
				var absent bool
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT secret_digest IS NULL FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&absent); err != nil || !absent {
					t.Fatal("public pairwise persisted confidential custody", err)
				}
				clients[i] = created.Client
			}
			rebuilt, rebuiltChild, _ := managedPairwiseServices(t, f, signer, defaultKey, policy)
			read := oauth.ClientReadRequest{Owner: clients[0].Owner, TenantID: f.tenant, Session: f.browser, ClientID: clients[0].ID}
			got, err := rebuilt.ClientGet(f.ctx, read)
			if err != nil || !got.Client.Public || got.Client.SubjectRegistration == nil || *got.Client.SubjectRegistration != registration {
				t.Fatal("fresh safe get lost public pairwise registration", err)
			}
			read.ClientID, read.Limit = "", 100
			listed, err := rebuilt.ClientList(f.ctx, read)
			if err != nil || !slices.ContainsFunc(listed.Page.Items(), func(c oauth.Client) bool {
				return c.ID == clients[0].ID && c.Public && c.SubjectRegistration != nil && *c.SubjectRegistration == registration
			}) {
				t.Fatal("fresh safe list lost public pairwise registration", err)
			}
			foreign, _, _ := managedPairwiseServices(t, f, signer, defaultKey, randomPairwisePolicy(t, f, 1))
			managedPairwiseAuthorizationDenied(t, f, foreign, clients[0])
			token, first := consumeManagedPublicPairwise(t, f, rebuilt, rebuiltChild, clients[0], "public-pairwise-first-nonce")
			sameToken, same := consumeManagedPublicPairwise(t, f, rebuilt, rebuiltChild, clients[1], "public-pairwise-same-nonce")
			_, isolated := consumeManagedPublicPairwise(t, f, rebuilt, rebuiltChild, clients[2], "public-pairwise-other-nonce")
			if first.Subject != same.Subject || first.Subject == isolated.Subject {
				t.Fatal("public pairwise lost same-sector stability or cross-sector isolation")
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
			managedPairwiseAuthorizationDenied(t, f, rebuilt, clients[0])
			retained, active, err := store.SubjectKeyRegistrations(f.ctx, "subjects", 1)
			if err != nil || active != 2 || len(retained) != 1 {
				t.Fatal("public pairwise reconstruction retained invalid custody", err)
			}
			cipher, _ := envelope.NewService(f.keys)
			restored, err := op.NewSubjectPolicy(f.ctx, op.SubjectPolicyConfig{Issuer: f.oauth.Protocol.Issuer, Environment: f.oauth.Protocol.Environment, PolicyID: "subjects", PolicyVersion: 1, ActiveKeyVersion: active, Keys: []op.SubjectKeyEnvelope{{Version: retained[0].KeyVersion, Envelope: retained[0].Envelope}}}, cipher)
			if err != nil {
				t.Fatal(err)
			}
			restarted, restartedChild, _ := managedPairwiseServices(t, f, signer, defaultKey, restored)
			_, after := consumeManagedPublicPairwise(t, f, restarted, restartedChild, clients[0], "public-pairwise-reconstructed-nonce")
			if after.Subject != first.Subject {
				t.Fatal("public pairwise key rotation changed durable identity")
			}
			refresh := token.RefreshToken
			var access string
			for range 2 {
				rotated, err := restarted.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: clients[0].ID, RefreshToken: refresh, Network: "192.0.2.1"})
				if err != nil {
					t.Fatal("public pairwise refresh required secret custody", err)
				}
				refresh, _ = rotated.RefreshToken.Reveal()
				access, _ = rotated.AccessToken.Reveal()
				if info, err := restartedChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: clients[0].ID, AccessToken: access}); err != nil || info.Subject != first.Subject {
					t.Fatal("public pairwise refresh lost original subject", err)
				}
			}
			if _, err := restarted.Revoke(f.ctx, oauth.RevokeRequest{ClientID: clients[0].ID, Token: refresh, Network: "192.0.2.1"}); err != nil {
				t.Fatal("public pairwise revocation required secret custody", err)
			}
			if info, err := restartedChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: clients[0].ID, AccessToken: access}); err == nil || info != (op.UserInfo{}) {
				t.Fatal("revoked public pairwise family returned claims")
			}
			remove := clientRotationRequest(t, f, clients[0], "public-pairwise-delete", 0).Management
			if _, err := restarted.ClientDelete(f.ctx, remove); err != nil {
				t.Fatal("public pairwise deletion failed", err)
			}
			managedPairwiseAuthorizationDenied(t, f, restarted, clients[0])
			bindings, err := originalClientRead(t, f).Session.Session.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			suspendResourceUser(t, f, bindings.UserID)
			if info, err := restartedChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: clients[1].ID, AccessToken: sameToken.AccessToken}); err == nil || info != (op.UserInfo{}) {
				t.Fatal("withdrawn actual user retained public pairwise claims")
			}
		})
	}
}

func TestNativeManagedPublicPairwiseRequiredEffectsAndUnknownOriginalRecovery(t *testing.T) {
	for _, mode := range []string{"audit", "outbox", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			var provisional atomic.Bool
			fault := &oauthCommitFault{beforeWrite: func(wire []byte) {
				if bytes.Contains(wire, []byte(`INSERT INTO "oauth_store".managed_clients`)) {
					provisional.Store(true)
				}
			}}
			f := passwordFixture(t, fault)
			signer, defaultKey := managedPublicPairwiseFixture(t, &f, false)
			registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "managed.example", "subjects", 1)
			f.oauth.Protocol.ManagedClients.PublicPairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
			policy := randomPairwisePolicy(t, f, 1)
			service, _, store := managedPairwiseServices(t, f, signer, defaultKey, policy)
			if mode == "audit" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE audit.records ADD CONSTRAINT refuse_public_pairwise_audit CHECK(action<>'identity.oauth_server.create_client')`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "outbox" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_public_pairwise_event CHECK(topic<>'oauth_client.created.v1') NOT VALID`); err != nil {
					t.Fatal(err)
				}
			}
			r := clientCreateRequest(t, f, "public-pairwise-required-"+mode)
			r.Public, r.Scopes, r.SubjectRegistration = true, []string{"openid"}, &registration
			fault.armed.Store(mode == "unknown")
			out, err := service.ClientCreate(f.ctx, r)
			if err == nil || !provisional.Load() {
				t.Fatal("required public pairwise failure did not reach protected mutation")
			}
			if _, err := out.Secret.Reveal(); err == nil {
				t.Fatal("failed/uncertain public pairwise creation exposed a secret")
			}
			want := 0
			if mode == "unknown" {
				want = 1
				if !fault.hit.Load() || out.Completion.Outcome != identity.CommitOutcomeUnknown || out.Completion.CommandID == "" {
					t.Fatal("public pairwise original COMMIT seam not reached")
				}
				rr := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-create", CommandID: out.Completion.CommandID, ClientID: oauth.ManagedClientPrefix + string(out.Completion.CommandID), TenantID: f.tenant, Session: f.browser}
				manager := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
				manager.denied.Store(true)
				if _, err := store.Recover(f.ctx, rr); err == nil {
					t.Fatal("public pairwise recovery bypassed current manager")
				}
				manager.denied.Store(false)
				metadata, err := store.Recover(f.ctx, rr)
				if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted || metadata.CommandID != rr.CommandID {
					t.Fatal("public pairwise original metadata recovery failed", err)
				}
				rebuilt, _, _ := managedPairwiseServices(t, f, signer, defaultKey, policy)
				retry, err := rebuilt.ClientCreate(f.ctx, r)
				if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != rr.CommandID || !retry.Client.Public || retry.Client.SubjectRegistration == nil || *retry.Client.SubjectRegistration != registration {
					t.Fatal("public pairwise original retry lost immutable class/registration", err)
				}
				if _, err := retry.Secret.Reveal(); err == nil {
					t.Fatal("public pairwise recovery revealed secret custody")
				}
			}
			var clients, effects, audits, events, secrets int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.managed_clients),(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-create'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.create_client' AND outcome=1),(SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_client.created.v1'),(SELECT count(*) FROM oauth_store.managed_clients WHERE secret_digest IS NOT NULL)`).Scan(&clients, &effects, &audits, &events, &secrets); err != nil || clients != want || effects != want || audits != want || events != want || secrets != 0 {
				t.Fatal("public pairwise required effects/secret absence were not atomic", err)
			}
		})
	}
}

func TestNativeManagedPublicPairwiseCurrentManagerAndSessionWithdrawal(t *testing.T) {
	f := passwordFixture(t)
	signer, defaultKey := managedPublicPairwiseFixture(t, &f, false)
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "managed.example", "subjects", 1)
	f.oauth.Protocol.ManagedClients.PublicPairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
	policy := randomPairwisePolicy(t, f, 1)
	service, _, store := managedPairwiseServices(t, f, signer, defaultKey, policy)
	key, _ := policy.KeyRegistration(1)
	if err := store.InstallSubjectKey(f.ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateSubjectKey(f.ctx, "subjects", 1, 1); err != nil {
		t.Fatal(err)
	}
	r := clientCreateRequest(t, f, "public-pairwise-current-manager")
	r.Public, r.Scopes, r.SubjectRegistration = true, []string{"openid"}, &registration
	manager := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
	manager.denied.Store(true)
	if out, err := service.ClientCreate(f.ctx, r); err == nil || out.Client.ID != "" {
		t.Fatal("public pairwise creation bypassed current manager")
	}
	manager.denied.Store(false)
	created, err := service.ClientCreate(f.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	verifier := oauth2.GenerateVerifier()
	pending, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: created.Client.ID, RedirectURI: created.Client.Redirects[0], Resource: created.Client.Resource, Scopes: []string{"openid"}, Nonce: "public-pairwise-session-withdrawal", CodeChallenge: oauth2.S256ChallengeFromVerifier(verifier)}})
	if err != nil || pending.Outcome != oauth.ConsentRequired {
		t.Fatal("public pairwise did not reach genuine consent", err)
	}
	continuation, _ := pending.Continuation.Reveal()
	f.signOut()
	if _, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: created.Client.ID, Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true}); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("withdrawn original browser approved public pairwise consent", err)
	}
	if out, err := service.ClientCreate(f.ctx, r); err == nil || out.Client.ID != "" {
		t.Fatal("withdrawn manager session recovered public pairwise authority")
	}
	if out, err := service.ClientGet(f.ctx, oauth.ClientReadRequest{Owner: r.Owner, TenantID: f.tenant, Session: f.browser, ClientID: created.Client.ID}); err == nil || out.Client.ID != "" {
		t.Fatal("withdrawn manager session disclosed public pairwise metadata")
	}
}

func TestNativeManagedPublicPairwiseTrustAndCustodyDenials(t *testing.T) {
	f := passwordFixture(t)
	signer, defaultKey := managedPublicPairwiseFixture(t, &f, false)
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "managed.example", "subjects", 1)
	f.oauth.Protocol.ManagedClients.PublicPairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
	policy := randomPairwisePolicy(t, f, 1)
	service, _, store := managedPairwiseServices(t, f, signer, defaultKey, policy)
	for _, variant := range []string{"confidential", "foreign-policy", "foreign-version", "foreign-host", "additional-claim", "device"} {
		t.Run(variant, func(t *testing.T) {
			r := clientCreateRequest(t, f, "public-pairwise-denied-"+variant)
			r.Public, r.Scopes, r.SubjectRegistration = true, []string{"openid"}, &registration
			switch variant {
			case "confidential":
				r.Public = false
			case "foreign-policy":
				foreign, _ := oauth.NewOIDCSubjectRegistration("pairwise", "managed.example", "foreign", 1)
				r.SubjectRegistration = &foreign
			case "foreign-version":
				foreign, _ := oauth.NewOIDCSubjectRegistration("pairwise", "managed.example", "subjects", 2)
				r.SubjectRegistration = &foreign
			case "foreign-host":
				r.Redirects = []string{"https://foreign.example/callback"}
			case "additional-claim":
				r.Scopes = []string{"openid", "email"}
			case "device":
				r.DeviceAuthorization = true
			}
			if out, err := service.ClientCreate(f.ctx, r); err == nil || out.Client.ID != "" || out.Secret != (oauth.Token{}) {
				t.Fatal("unselected public pairwise variant escaped immutable native policy")
			}
		})
	}
	r := clientCreateRequest(t, f, "public-pairwise-missing-custody")
	r.Public, r.Scopes, r.SubjectRegistration = true, []string{"openid"}, &registration
	created, err := service.ClientCreate(f.ctx, r)
	if err != nil {
		t.Fatal("valid public pairwise registration failed", err)
	}
	managedPairwiseAuthorizationDenied(t, f, service, created.Client)
	key, _ := policy.KeyRegistration(1)
	foreign := key
	foreign.Environment = "foreign-environment"
	if err := store.InstallSubjectKey(f.ctx, foreign); err == nil {
		t.Fatal("public-only policy accepted foreign encrypted key custody")
	}
	if err := store.InstallSubjectKey(f.ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateSubjectKey(f.ctx, "subjects", 1, 1); err != nil {
		t.Fatal(err)
	}
	childService, child, _ := managedPairwiseServices(t, f, signer, defaultKey, policy)
	token, _ := consumeManagedPublicPairwise(t, f, childService, child, created.Client, "public-pairwise-withdrawal")
	f.oauth.Protocol.ManagedClients.PublicPairwiseRegistrations = nil
	withdrawn, withdrawnChild, withdrawnStore := managedPairwiseServices(t, f, signer, defaultKey, policy)
	if _, _, err := withdrawnStore.SubjectKeyRegistrations(f.ctx, "subjects", 1); err == nil {
		t.Fatal("withdrawn public-only policy disclosed key custody")
	}
	if info, err := withdrawnChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: created.Client.ID, AccessToken: token.AccessToken}); err == nil || info != (op.UserInfo{}) {
		t.Fatal("withdrawn public-only registration returned claims")
	}
	managedPairwiseAuthorizationDenied(t, f, withdrawn, created.Client)
	if out, err := withdrawn.ClientCreate(f.ctx, r); err == nil || out.Client.ID != "" {
		t.Fatal("withdrawn public-only selection recovered registration")
	}
}
