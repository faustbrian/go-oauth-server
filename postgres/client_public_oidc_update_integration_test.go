//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"golang.org/x/oauth2"
)

func publicOIDCUpdateFixture(t *testing.T, faults ...*oauthCommitFault) (authenticatedPasswordFixture, *oauth.Service, *op.Service, *oauth.SigningService, [32]byte, oauth.Client) {
	t.Helper()
	f := passwordFixture(t, faults...)
	enableClientUpdates(t, &f)
	installPublicClients(t, &f)
	f.oauth.Protocol.OwningClientIntrospection = false
	f.oauth.Protocol.ManagedClients.PublicOIDC = true
	f.oauth.Protocol.ManagedClients.PublicOIDCUpdates = true
	f.oauth.Protocol.ManagedClients.PostLogoutRedirects = []string{"https://managed.example/logout", "https://managed.example/signed-out"}
	var source migrations.Source = oauthpostgres.ClientMigrationSource{Base: oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}, Schema: "oauth_store", Version: 7003}
	source = oauthpostgres.ClientRotationMigrationSource{Base: source, Schema: "oauth_store", Version: 7004}
	source = oauthpostgres.ClientUpdateMigrationSource{Base: source, Schema: "oauth_store", Version: 7005}
	source = oauthpostgres.ClientPublicMigrationSource{Base: source, Schema: "oauth_store", Version: 7006}
	source = oauthpostgres.SigningMigrationSource{Base: source, Schema: "oauth_store", Version: 7007}
	_, _, signer, _, _ := oidcFixtureWithLifecycle(t, &f, clock.System{}, nil, source)
	var subjectKey [32]byte
	if _, err := rand.Read(subjectKey[:]); err != nil {
		t.Fatal(err)
	}
	service, child, _ := managedOIDCServices(t, f, signer, subjectKey)
	request := clientCreateRequest(t, f, "public-oidc-update-create")
	request.Public, request.Scopes = true, []string{"openid"}
	request.PostLogoutRedirects = []string{"https://managed.example/logout"}
	created, err := service.ClientCreate(f.ctx, request)
	if err != nil || !created.Client.Public || created.Secret != (oauth.Token{}) {
		t.Fatal("real public OIDC update fixture issuance", err)
	}
	return f, service, child, signer, subjectKey, created.Client
}

func publicOIDCReplacement(t *testing.T, f authenticatedPasswordFixture, client oauth.Client, key string) oauth.ClientUpdateRequest {
	t.Helper()
	request := publicClientUpdateRequest(t, f, client, key)
	request.Scopes = []string{"openid"}
	request.PostLogoutRedirects = []string{"https://managed.example/signed-out"}
	return request
}

func publicOIDCUpdateCode(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service, client oauth.Client, nonce string) (string, string) {
	t.Helper()
	proof := oauth2.GenerateVerifier()
	request := oauth.AuthorizationRequest{ClientID: client.ID, RedirectURI: client.Redirects[0], Resource: client.Resource, Scopes: []string{"openid"}, CodeChallenge: oauth2.S256ChallengeFromVerifier(proof), Nonce: nonce, State: nonce}
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: request})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("real OIDC client did not require explicit consent", err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	approved, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: client.ID, Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true})
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("real OIDC explicit approval failed", err)
	}
	location, err := approved.Location()
	if err != nil {
		t.Fatal(err)
	}
	callback, err := url.Parse(location)
	if err != nil || callback.Scheme+"://"+callback.Host+callback.Path != client.Redirects[0] || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() || callback.Query().Get("state") != nonce || callback.Query().Get("code") == "" {
		t.Fatal("OIDC authorization lost exact issuer/redirect/state")
	}
	return callback.Query().Get("code"), proof
}

func publicOIDCUpdateRP(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service, child *op.Service, client oauth.Client, nonce string) (*oauth2.Token, string) {
	t.Helper()
	transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child, userInfoClientID: client.ID}
	ctx := rp.ClientContext(f.ctx, &http.Client{Transport: transport, Timeout: 5 * time.Second})
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal("independent OIDC discovery", err)
	}
	code, proof := publicOIDCUpdateCode(t, f, service, client, nonce)
	standard := oauth2.Config{ClientID: client.ID, Endpoint: provider.Endpoint(), RedirectURL: client.Redirects[0], Scopes: []string{"openid"}}
	token, err := standard.Exchange(ctx, code, oauth2.VerifierOption(proof))
	if err != nil {
		t.Fatal("independent public S256 exchange", err)
	}
	wire, ok := token.Extra("id_token").(string)
	if !ok {
		t.Fatal("OIDC token response omitted ID token")
	}
	verified, err := consumeIDToken(ctx, provider, wire, nonce, client.ID)
	if err != nil || verified.Subject == "" {
		t.Fatal("independent ID token validation", err)
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil || info.Subject != verified.Subject {
		t.Fatal("independent UserInfo subject mismatch", err)
	}
	return token, verified.Subject
}

func TestNativePublicOIDCClientUpdateCompleteNoSecretConsumer(t *testing.T) {
	f, original, child, signer, subjectKey, client := publicOIDCUpdateFixture(t)
	token, subject := publicOIDCUpdateRP(t, f, original, child, client, "before-public-oidc-update")
	code, proof := publicOIDCUpdateCode(t, f, original, client, "old-pending-code")
	consents, err := original.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
	if err != nil || len(consents.Page.Items()) != 1 {
		t.Fatal("original public OIDC consent", err)
	}
	oldConsent := consents.Page.Items()[0]
	if info, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: client.ID, AccessToken: token.AccessToken}); err != nil || info.Subject != subject {
		t.Fatal("pre-update issued access was not active", err)
	}
	fresh, freshChild, _ := managedOIDCServices(t, f, signer, subjectKey)
	read := oauth.ClientReadRequest{Owner: client.Owner, TenantID: f.tenant, Session: f.browser, ClientID: client.ID}
	discovered, err := fresh.ClientGet(f.ctx, read)
	if err != nil || discovered.Client.Version != client.Version {
		t.Fatal("real manager could not discover OIDC version", err)
	}
	request := publicOIDCReplacement(t, f, discovered.Client, "public-oidc-original-update")
	updated, err := fresh.ClientUpdate(f.ctx, request)
	if err != nil || updated.Completion.Outcome != identity.CommitOutcomeCommitted || updated.Completion.Replayed || updated.Client.Version != client.Version+1 || !updated.Client.Public || updated.Client.AuthenticationMethod != "none" || updated.Client.SubjectRegistration != nil || updated.Client.Owner != client.Owner || updated.Client.Resource != client.Resource || !slices.Equal(updated.Client.Redirects, request.Redirects) || !slices.Equal(updated.Client.PostLogoutRedirects, request.PostLogoutRedirects) || !slices.Equal(updated.Client.Scopes, []string{"openid"}) {
		t.Fatal("actual public OIDC replacement changed immutable profile or was unavailable", err)
	}
	requirePublicUpdateState(t, f, client, "2", "active", 1)
	challenge := oauth2.S256ChallengeFromVerifier(oauth2.GenerateVerifier())
	if _, err := original.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: client.ID, RedirectURI: client.Redirects[0], Resource: client.Resource, Scopes: []string{"openid"}, CodeChallenge: challenge, Nonce: "removed-redirect"}}); err == nil {
		t.Fatal("warm service accepted removed OIDC redirect")
	}
	if out, err := original.ConsentGet(f.ctx, oauth.ConsentGetRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRead, oldConsent.ID(), 0)}); err == nil || out.Consent.ID() != "" {
		t.Fatal("old OIDC consent survived replacement")
	}
	for _, old := range []oauth.TokenRequest{
		{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: code, CodeVerifier: proof, RedirectURI: client.Redirects[0], Network: "192.0.2.1"},
		{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: token.RefreshToken, Network: "192.0.2.1"},
	} {
		if _, err := original.Token(f.ctx, old); err == nil {
			t.Fatal("old client-version code/refresh retained authority")
		}
	}
	if _, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: client.ID, AccessToken: token.AccessToken}); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("old access token retained OIDC UserInfo", err)
	}
	newToken, newSubject := publicOIDCUpdateRP(t, f, fresh, freshChild, updated.Client, "after-public-oidc-update")
	if newSubject != subject {
		t.Fatal("metadata replacement changed default OIDC subject")
	}
	for i := 0; i < 2; i++ {
		replay, err := fresh.ClientUpdate(f.ctx, request)
		if err != nil || !replay.Completion.Replayed || replay.Completion.CommandID != updated.Completion.CommandID || replay.Client.Version != 2 {
			t.Fatal("exact OIDC update replay changed original result", err)
		}
	}
	requirePublicUpdateState(t, f, client, "2", "active", 1)
	remove := clientRotationRequest(t, f, updated.Client, "public-oidc-updated-delete", 0).Management
	if _, err := fresh.ClientDelete(f.ctx, remove); err != nil {
		t.Fatal("updated OIDC client deletion", err)
	}
	if _, err := freshChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: client.ID, AccessToken: newToken.AccessToken}); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("deleted updated OIDC client retained UserInfo", err)
	}
}

func TestNativePublicOIDCClientUpdateRejectsUnselectedAndForeignAuthority(t *testing.T) {
	f, service, _, signer, subjectKey, client := publicOIDCUpdateFixture(t)
	base := publicOIDCReplacement(t, f, client, "public-oidc-denied")
	for _, variant := range []string{"csrf", "owner", "origin", "class", "stale", "claims", "oauth", "manager"} {
		t.Run(variant, func(t *testing.T) {
			request := base
			request.Management.RequestKey, _ = identity.NewIdempotencyKey([]byte("public-oidc-denied-" + variant))
			policy := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
			switch variant {
			case "csrf":
				request.Management.CSRF, _ = session.NewCSRFToken()
			case "owner":
				request.Management.Owner, _ = oauth.NewPlatformOwner("foreign")
			case "origin":
				request.Management.Origin = "https://foreign.example"
			case "class":
				request.Management.Public = false
			case "stale":
				request.Management.Version++
			case "claims":
				request.Scopes = []string{"email", "openid"}
			case "oauth":
				request.Scopes = []string{"identity:read"}
			case "manager":
				policy.denied.Store(true)
				defer policy.denied.Store(false)
			}
			if out, err := service.ClientUpdate(f.ctx, request); err == nil || out.Client.ID != "" {
				t.Fatal("unselected/foreign public OIDC replacement admitted", err)
			}
			requirePublicUpdateState(t, f, client, "1", "active", 0)
		})
	}
	unselected := f
	policy := *f.oauth.Protocol.ManagedClients
	policy.PublicOIDCUpdates = false
	unselected.oauth.Protocol.ManagedClients = &policy
	old, _, oldStore := managedOIDCServices(t, unselected, signer, subjectKey)
	if out, err := old.ClientUpdate(f.ctx, base); err == nil || out.Client.ID != "" {
		t.Fatal("creation-only service selected OIDC update", err)
	}
	execution := oauth.ClientUpdateExecution{Request: base, Session: originalClientRead(t, f).Session}
	if out, err := oldStore.UpdateClient(f.ctx, execution); err == nil || out.Client.ID != "" {
		t.Fatal("unselected direct native owner admitted OIDC update", err)
	}
	uncomposed, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := uncomposed.ClientUpdate(f.ctx, base); err == nil || out.Client.ID != "" {
		t.Fatal("uncomposed OIDC update reached native mutation", err)
	}
	requirePublicUpdateState(t, f, client, "1", "active", 0)
	if _, err := service.ClientUpdate(f.ctx, publicOIDCReplacement(t, f, client, "public-oidc-denial-positive")); err != nil {
		t.Fatal("denials broke selected genuine positive", err)
	}
	requirePublicUpdateState(t, f, client, "2", "active", 1)
}

func TestNativePublicOIDCClientUpdateRollbackAndUnknownOriginalRecovery(t *testing.T) {
	for _, mode := range []string{"outbox", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			fault := &oauthCommitFault{}
			f, service, _, _, _, client := publicOIDCUpdateFixture(t, fault)
			if mode == "outbox" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_oidc_update CHECK(topic<>'oauth_client.configuration_changed.v1') NOT VALID`); err != nil {
					t.Fatal(err)
				}
			} else {
				fault.armed.Store(true)
			}
			request := publicOIDCReplacement(t, f, client, "public-oidc-outcome-original")
			out, err := service.ClientUpdate(f.ctx, request)
			if err == nil || out.Client.ID != "" {
				t.Fatal("required effect/unknown commit disclosed OIDC metadata", err)
			}
			if mode == "outbox" {
				requirePublicUpdateState(t, f, client, "1", "active", 0)
				return
			}
			if !fault.hit.Load() || out.Completion.Outcome != identity.CommitOutcomeUnknown || out.Completion.CommandID == "" {
				t.Fatal("actual lost OIDC update COMMIT seam missed")
			}
			store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-update", CommandID: out.Completion.CommandID, ClientID: client.ID, TenantID: f.tenant, Session: f.browser}
			deadline := time.Now().Add(8 * time.Second)
			for {
				known, err := store.Recover(f.ctx, recovery)
				if known.Outcome == identity.CommitOutcomeCommitted && err == nil {
					break
				}
				if err != nil && !errors.Is(err, oauth.ErrUnavailable) || time.Now().After(deadline) {
					t.Fatal("original OIDC update did not reconcile", err)
				}
				select {
				case <-time.After(100 * time.Millisecond):
				case <-f.ctx.Done():
					t.Fatal("OIDC recovery canceled")
				}
			}
			for i := 0; i < 2; i++ {
				known, err := service.ClientUpdate(f.ctx, request)
				if err != nil || !known.Completion.Replayed || known.Completion.CommandID != recovery.CommandID || known.Client.Version != 2 || !known.Client.Public {
					t.Fatal("original OIDC update replay changed metadata", err)
				}
			}
			requirePublicUpdateState(t, f, client, "2", "active", 1)
		})
	}
}

func TestNativePublicOIDCClientUpdateFencesContendersAndWithdrawnAuthority(t *testing.T) {
	for _, mode := range []string{"update", "delete", "epoch"} {
		t.Run(mode, func(t *testing.T) {
			f, winner, child, _, _, client := publicOIDCUpdateFixture(t)
			lateCore, gate := updateBarrierService(t, f, "identity.oauth-server.client-update")
			late, err := lateCore.WithOIDC(child)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.WithValue(f.ctx, consentRaceKey{}, true))
			defer cancel()
			type answer struct {
				out oauth.ClientUpdateResult
				err error
			}
			done := make(chan answer, 1)
			joined := false
			defer func() {
				cancel()
				select {
				case <-gate.release:
				default:
					close(gate.release)
				}
				if !joined {
					<-done
				}
			}()
			go func() {
				out, err := late.ClientUpdate(ctx, publicOIDCReplacement(t, f, client, "public-oidc-late-update"))
				done <- answer{out, err}
			}()
			select {
			case <-gate.ready:
			case out := <-done:
				joined = true
				t.Fatal("OIDC contender failed before actual authority barrier", out.err)
			case <-f.ctx.Done():
				t.Fatal("OIDC contender barrier canceled")
			}
			version, state, effects := "1", "active", 0
			switch mode {
			case "update":
				if _, err := winner.ClientUpdate(f.ctx, publicOIDCReplacement(t, f, client, "public-oidc-winning-update")); err != nil {
					t.Fatal(err)
				}
				version, effects = "2", 1
			case "delete":
				if _, err := winner.ClientDelete(f.ctx, clientRotationRequest(t, f, client, "public-oidc-winning-delete", 0).Management); err != nil {
					t.Fatal(err)
				}
				version, state = "2", "deleted"
			case "epoch":
				owner, err := authority.NewAuthorityStore(f.pool.Raw(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				manager := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy).manager
				scope := authority.AuthorityScope{TenantID: authorization.TenantID(f.tenant), PolicyNamespace: f.oauth.Session.Profile.PolicyNamespace, SubjectID: manager}
				current, err := owner.Get(f.ctx, scope)
				if err != nil {
					t.Fatal(err)
				}
				tx, err := f.pool.Raw().Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := authority.AdvanceAuthority(f.ctx, tx, scope, current.Version, time.Second); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
			}
			close(gate.release)
			out := <-done
			joined = true
			if !errors.Is(out.err, oauth.ErrAccessDenied) || out.out.Client.ID != "" {
				t.Fatal("stale/withdrawn OIDC update disclosed metadata", out.err)
			}
			requirePublicUpdateState(t, f, client, version, state, effects)
		})
	}
}
