//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"golang.org/x/oauth2"
)

type confidentialUpdateFixture struct {
	f             authenticatedPasswordFixture
	core          *oauth.Service
	child         *op.Service
	signer        *oauth.SigningService
	subjectKey    [32]byte
	client        oauth.Client
	secret        string
	createRequest oauth.ClientManagementRequest
}

func newConfidentialUpdateFixture(t *testing.T, faults ...*oauthCommitFault) confidentialUpdateFixture {
	t.Helper()
	f := passwordFixture(t, faults...)
	signer, subjectKey := managedConfidentialOIDCFixture(t, &f, true)
	policy := f.oauth.Protocol.ManagedClients
	policy.ConfidentialOIDC, policy.ConfidentialOIDCUpdates = true, true
	policy.Redirects = []string{"https://managed.example/callback", "https://managed.example/new"}
	policy.PostLogoutRedirects = []string{"https://managed.example/logout", "https://managed.example/signed-out"}
	core, child, _ := managedOIDCServices(t, f, signer, subjectKey)
	request := clientCreateRequest(t, f, "confidential-update-create")
	request.Scopes, request.PostLogoutRedirects = []string{"openid"}, []string{"https://managed.example/logout"}
	created, err := core.ClientCreate(f.ctx, request)
	if err != nil || created.Client.Public || created.Client.AuthenticationMethod != "client_secret_basic" || created.Client.SubjectRegistration != nil {
		t.Fatal("genuine confidential OIDC creation failed", err)
	}
	secret, err := created.Secret.Reveal()
	if err != nil {
		t.Fatal("fresh known client creation omitted Basic custody")
	}
	return confidentialUpdateFixture{f, core, child, signer, subjectKey, created.Client, secret, request}
}

func confidentialOIDCReplacement(t *testing.T, x confidentialUpdateFixture, client oauth.Client, key string) oauth.ClientUpdateRequest {
	t.Helper()
	request := clientUpdateRequest(t, x.f, client, key)
	request.Scopes, request.PostLogoutRedirects = []string{"openid"}, []string{"https://managed.example/signed-out"}
	return request
}

func confidentialUpdateRP(t *testing.T, x confidentialUpdateFixture, core *oauth.Service, child *op.Service, client oauth.Client, nonce string) (*oauth2.Token, string) {
	t.Helper()
	transport := &discoveryConsumerTransport{f: x.f, service: core, endpoints: x.f.oauth.Protocol.Discovery, oidc: child, userInfoClientID: client.ID}
	ctx := rp.ClientContext(x.f.ctx, &http.Client{Transport: transport, Timeout: 5 * time.Second})
	provider, err := rp.NewProvider(ctx, x.f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal("independent confidential discovery failed", err)
	}
	code, proof := publicOIDCUpdateCode(t, x.f, core, client, nonce)
	withoutAuthentication := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: code, CodeVerifier: proof, RedirectURI: client.Redirects[0], Network: "192.0.2.1"}
	if out, err := core.Token(ctx, withoutAuthentication); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("confidential OIDC code accepted without unchanged client authentication")
	}
	standard := oauth2.Config{ClientID: client.ID, ClientSecret: x.secret, Endpoint: provider.Endpoint(), RedirectURL: client.Redirects[0], Scopes: []string{"openid"}}
	standard.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	token, err := standard.Exchange(ctx, code, oauth2.VerifierOption(proof))
	if err != nil {
		t.Fatal("independent S256 exchange rejected original Basic custody", err)
	}
	wire, ok := token.Extra("id_token").(string)
	if !ok {
		t.Fatal("confidential response omitted signed ID token")
	}
	verified, err := consumeIDToken(ctx, provider, wire, nonce, client.ID)
	if err != nil || verified.Subject == "" {
		t.Fatal("independent confidential ID token validation failed", err)
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil || info.Subject != verified.Subject {
		t.Fatal("confidential UserInfo did not preserve equal subject", err)
	}
	return token, verified.Subject
}

type confidentialUpdateState struct {
	digest                     []byte
	version, generation, state string
	noPredecessor              bool
	effects, audits, events    int
}

func readConfidentialUpdateState(t *testing.T, x confidentialUpdateFixture) confidentialUpdateState {
	t.Helper()
	var out confidentialUpdateState
	err := x.f.pool.Raw().QueryRow(x.f.ctx, `SELECT secret_digest,version::text,secret_version::text,state,previous_secret_digest IS NULL AND previous_secret_version IS NULL AND previous_secret_expires_at IS NULL,(SELECT count(*) FROM oauth_store.effects WHERE client_id=$1 AND operation_id='identity.oauth-server.client-update'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.update_client' AND outcome=1),(SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_client.configuration_changed.v1') FROM oauth_store.managed_clients WHERE client_id=$1`, x.client.ID).Scan(&out.digest, &out.version, &out.generation, &out.state, &out.noPredecessor, &out.effects, &out.audits, &out.events)
	if err != nil {
		t.Fatal("confidential update state unavailable", err)
	}
	return out
}

func requireConfidentialUpdateState(t *testing.T, x confidentialUpdateFixture, before confidentialUpdateState, version string, effects int) {
	t.Helper()
	after := readConfidentialUpdateState(t, x)
	if !bytes.Equal(after.digest, before.digest) || after.generation != before.generation || !after.noPredecessor || after.version != version || after.state != "active" || after.effects != effects || after.audits != effects || after.events != effects {
		t.Fatal("metadata replacement changed secret generation/custody or duplicated effects")
	}
}

func TestNativeConfidentialOIDCClientUpdateCompleteBasicConsumer(t *testing.T) {
	x := newConfidentialUpdateFixture(t)
	before := readConfidentialUpdateState(t, x)
	token, subject := confidentialUpdateRP(t, x, x.core, x.child, x.client, "before-confidential-update")
	code, proof := publicOIDCUpdateCode(t, x.f, x.core, x.client, "old-confidential-pending")
	consents, err := x.core.ConsentList(x.f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, x.f, oauth.ConsentEnumerate, "", 0)})
	if err != nil || len(consents.Page.Items()) != 1 {
		t.Fatal("original confidential consent unavailable", err)
	}
	oldConsent := consents.Page.Items()[0]
	fresh, child, _ := managedOIDCServices(t, x.f, x.signer, x.subjectKey)
	read := oauth.ClientReadRequest{Owner: x.client.Owner, TenantID: x.f.tenant, Session: x.f.browser, ClientID: x.client.ID}
	current, err := fresh.ClientGet(x.f.ctx, read)
	if err != nil || current.Client.Version != 1 || current.Client.Public || current.Client.AuthenticationMethod != "client_secret_basic" {
		t.Fatal("real manager could not discover current confidential version", err)
	}
	request := confidentialOIDCReplacement(t, x, current.Client, "confidential-update-original")
	updated, err := fresh.ClientUpdate(x.f.ctx, request)
	if err != nil || updated.Completion.Outcome != identity.CommitOutcomeCommitted || updated.Completion.Replayed || updated.Client.Version != 2 || updated.Client.Public || updated.Client.AuthenticationMethod != "client_secret_basic" || updated.Client.SubjectRegistration != nil || updated.Client.Owner != x.client.Owner || updated.Client.Resource != x.client.Resource || !slices.Equal(updated.Client.Redirects, request.Redirects) || !slices.Equal(updated.Client.PostLogoutRedirects, request.PostLogoutRedirects) || !slices.Equal(updated.Client.Scopes, []string{"openid"}) {
		t.Fatal("exact confidential OIDC replacement unavailable or changed immutable class", err)
	}
	requireConfidentialUpdateState(t, x, before, "2", 1)
	challenge := oauth2.S256ChallengeFromVerifier(oauth2.GenerateVerifier())
	if _, err := x.core.Authorize(x.f.ctx, oauth.AuthorizeRequest{TenantID: x.f.tenant, Session: x.f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: x.client.ID, RedirectURI: x.client.Redirects[0], Resource: x.client.Resource, Scopes: []string{"openid"}, CodeChallenge: challenge, Nonce: "removed-confidential-redirect"}}); err == nil {
		t.Fatal("warm confidential service accepted removed redirect")
	}
	if out, err := x.core.ConsentGet(x.f.ctx, oauth.ConsentGetRequest{Consent: ownConsentCommand(t, x.f, oauth.ConsentRead, oldConsent.ID(), 0)}); err == nil || out.Consent.ID() != "" {
		t.Fatal("old confidential consent survived client-version replacement")
	}
	basic := confidentialBasic(t, x.client.ID, x.secret)
	for _, old := range []oauth.TokenRequest{
		{GrantType: oauth.AuthorizationCodeGrant, ClientID: x.client.ID, ClientAuthentication: basic, Code: code, CodeVerifier: proof, RedirectURI: x.client.Redirects[0], Network: "192.0.2.1"},
		{GrantType: oauth.RefreshTokenGrant, ClientID: x.client.ID, ClientAuthentication: basic, RefreshToken: token.RefreshToken, Network: "192.0.2.1"},
	} {
		if out, err := x.core.Token(x.f.ctx, old); err == nil || out.AccessToken != (oauth.Token{}) {
			t.Fatal("old confidential code/refresh retained authority")
		}
	}
	if _, err := x.child.UserInfo(x.f.ctx, oauth.UserInfoRequest{ClientID: x.client.ID, AccessToken: token.AccessToken}); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("old confidential access retained UserInfo", err)
	}
	_, newSubject := confidentialUpdateRP(t, x, fresh, child, updated.Client, "after-confidential-update")
	if newSubject != subject {
		t.Fatal("confidential metadata replacement changed stable default subject")
	}
	for i := 0; i < 2; i++ {
		replay, err := fresh.ClientUpdate(x.f.ctx, request)
		if err != nil || !replay.Completion.Replayed || replay.Completion.CommandID != updated.Completion.CommandID || replay.Client.Version != 2 {
			t.Fatal("confidential original update replay changed its result", err)
		}
	}
	createdAgain, err := fresh.ClientCreate(x.f.ctx, x.createRequest)
	if err != nil || !createdAgain.Completion.Replayed {
		t.Fatal("metadata replacement stranded original client creation history", err)
	}
	if _, err := createdAgain.Secret.Reveal(); err == nil {
		t.Fatal("client creation retry revealed retained Basic secret")
	}
	requireConfidentialUpdateState(t, x, before, "2", 1)
}

func TestNativeConfidentialOIDCClientUpdateRequiresCurrentManagerAndExactProfile(t *testing.T) {
	x := newConfidentialUpdateFixture(t)
	before := readConfidentialUpdateState(t, x)
	for _, variant := range []string{"owner", "csrf", "stale", "class", "withdrawn", "claims", "oauth", "origin"} {
		t.Run(variant, func(t *testing.T) {
			request := confidentialOIDCReplacement(t, x, x.client, "confidential-denial-"+variant)
			policy := x.f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
			switch variant {
			case "owner":
				request.Management.Owner, _ = oauth.NewPlatformOwner("foreign")
			case "csrf":
				request.Management.CSRF, _ = session.NewCSRFToken()
			case "stale":
				request.Management.Version++
			case "class":
				request.Management.Public = true
			case "withdrawn":
				policy.denied.Store(true)
				defer policy.denied.Store(false)
			case "claims":
				request.Scopes = []string{"email", "openid"}
			case "oauth":
				request.Scopes = []string{"identity:read"}
			case "origin":
				request.Management.Origin = "https://foreign.example"
			}
			if out, err := x.core.ClientUpdate(x.f.ctx, request); err == nil || out.Client.ID != "" {
				t.Fatal("confidential update escaped current authority/profile", err)
			}
			requireConfidentialUpdateState(t, x, before, "1", 0)
		})
	}
	request := confidentialOIDCReplacement(t, x, x.client, "confidential-unselected")
	unselected := x.f
	policy := *x.f.oauth.Protocol.ManagedClients
	policy.ConfidentialOIDCUpdates = false
	unselected.oauth.Protocol.ManagedClients = &policy
	old, _, oldStore := managedOIDCServices(t, unselected, x.signer, x.subjectKey)
	if out, err := old.ClientUpdate(x.f.ctx, request); err == nil || out.Client.ID != "" {
		t.Fatal("creation enablement implicitly authorized confidential update", err)
	}
	if out, err := oldStore.UpdateClient(x.f.ctx, oauth.ClientUpdateExecution{Request: request, Session: originalClientRead(t, x.f).Session}); err == nil || out.Client.ID != "" {
		t.Fatal("direct native owner ignored explicit update selection", err)
	}
	uncomposed, err := oauthpostgres.NewService(x.f.pool, x.f.oauth, x.f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := uncomposed.ClientUpdate(x.f.ctx, request); err == nil || out.Client.ID != "" {
		t.Fatal("uncomposed confidential OIDC update reached native owner", err)
	}
	requireConfidentialUpdateState(t, x, before, "1", 0)
	if _, err := x.core.ClientUpdate(x.f.ctx, confidentialOIDCReplacement(t, x, x.client, "confidential-denial-positive")); err != nil {
		t.Fatal("denials stranded selected current manager positive", err)
	}
	requireConfidentialUpdateState(t, x, before, "2", 1)
}

func TestNativeConfidentialOIDCClientUpdateRollbackAndLostCommitOriginalRecovery(t *testing.T) {
	for _, mode := range []string{"outbox", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			fault := &oauthCommitFault{}
			x := newConfidentialUpdateFixture(t, fault)
			before := readConfidentialUpdateState(t, x)
			if mode == "outbox" {
				if _, err := x.f.pool.Raw().Exec(x.f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_confidential_update CHECK(topic<>'oauth_client.configuration_changed.v1') NOT VALID`); err != nil {
					t.Fatal(err)
				}
			} else {
				fault.armed.Store(true)
			}
			request := confidentialOIDCReplacement(t, x, x.client, "confidential-outcome-original")
			out, err := x.core.ClientUpdate(x.f.ctx, request)
			if err == nil || out.Client.ID != "" {
				t.Fatal("unknown/rolled-back update disclosed confidential metadata", err)
			}
			if mode == "outbox" {
				requireConfidentialUpdateState(t, x, before, "1", 0)
				return
			}
			if !fault.hit.Load() || out.Completion.Outcome != identity.CommitOutcomeUnknown || out.Completion.CommandID == "" {
				t.Fatal("actual confidential lost COMMIT seam missed")
			}
			store, err := oauthpostgres.NewStore(x.f.pool, x.f.oauth, x.f.keys)
			if err != nil {
				t.Fatal(err)
			}
			recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-update", CommandID: out.Completion.CommandID, ClientID: x.client.ID, TenantID: x.f.tenant, Session: x.f.browser}
			deadline := time.Now().Add(8 * time.Second)
			for {
				known, err := store.Recover(x.f.ctx, recovery)
				if err == nil && known.Outcome == identity.CommitOutcomeCommitted {
					break
				}
				if err != nil && !errors.Is(err, oauth.ErrUnavailable) || time.Now().After(deadline) {
					t.Fatal("original confidential update failed to reconcile", err)
				}
				select {
				case <-time.After(100 * time.Millisecond):
				case <-x.f.ctx.Done():
					t.Fatal("confidential original recovery canceled")
				}
			}
			policy := x.f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
			policy.denied.Store(true)
			denied, deniedErr := x.core.ClientUpdate(x.f.ctx, request)
			policy.denied.Store(false)
			if deniedErr == nil || denied.Client.ID != "" {
				t.Fatal("historical update bypassed currently withdrawn manager")
			}
			for i := 0; i < 2; i++ {
				known, err := x.core.ClientUpdate(x.f.ctx, request)
				if err != nil || !known.Completion.Replayed || known.Completion.CommandID != recovery.CommandID || known.Client.Version != 2 || known.Client.Public || known.Client.AuthenticationMethod != "client_secret_basic" {
					t.Fatal("original confidential recovery changed class/result", err)
				}
			}
			requireConfidentialUpdateState(t, x, before, "2", 1)
		})
	}
}
