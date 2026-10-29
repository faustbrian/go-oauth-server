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
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"golang.org/x/oauth2"
)

func managedConfidentialOIDCFixture(t *testing.T, f *authenticatedPasswordFixture, updates bool) (*oauth.SigningService, [32]byte) {
	t.Helper()
	enableClientRotation(t, f)
	f.oauth.Protocol.OwningClientIntrospection = false
	var source migrations.Source = oauthpostgres.ClientRotationMigrationSource{Base: oauthpostgres.ClientMigrationSource{Base: oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}, Schema: "oauth_store", Version: 7003}, Schema: "oauth_store", Version: 7004}
	version := migrations.Version(7005)
	if updates {
		installClientUpdates(t, f)
		source = oauthpostgres.ClientUpdateMigrationSource{Base: source, Schema: "oauth_store", Version: version}
		version++
	}
	source = oauthpostgres.SigningMigrationSource{Base: source, Schema: "oauth_store", Version: version}
	_, _, signer, _, _ := oidcFixtureWithLifecycle(t, f, clock.System{}, nil, source)
	var subjectKey [32]byte
	if _, err := rand.Read(subjectKey[:]); err != nil {
		t.Fatal("confidential OIDC subject custody unavailable")
	}
	return signer, subjectKey
}

func TestNativeManagedConfidentialOIDCRequiredEffectsRollbackAndOriginalRecovery(t *testing.T) {
	testNativeManagedClientRequiredEffectsProfile(t, false, true)
}

func TestNativeManagedConfidentialOIDCUnknownCreateRetainsCurrentAuthorizedRecovery(t *testing.T) {
	testNativeManagedOIDCUnknownCreateRetainsCurrentAuthorizedRecovery(t, false)
}

func TestNativeManagedConfidentialOIDCDeletionFencesLateApprovalExchangeAndRefresh(t *testing.T) {
	testNativeManagedClientDeletionFences(t, true, false)
}

func TestNativeManagedConfidentialOIDCFreshAndPopulatedIndependentConsumer(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated"}[populated], func(t *testing.T) {
			f := passwordFixture(t)
			signer, subjectKey := managedConfidentialOIDCFixture(t, &f, false)
			before, _, _ := managedOIDCServices(t, f, signer, subjectKey)
			var legacy oauth.ClientManagementResult
			var legacyRequest oauth.ClientManagementRequest
			var legacyRegistration, legacyDigest []byte
			var legacyRefresh string
			var legacyBasic oauth.ClientAuthentication
			if populated {
				legacyRequest = clientCreateRequest(t, f, "before-confidential-oidc")
				var err error
				legacy, err = before.ClientCreate(f.ctx, legacyRequest)
				if err != nil {
					t.Fatal("original confidential registration failed", err)
				}
				secret, err := legacy.Secret.Reveal()
				if err != nil {
					t.Fatal("original confidential secret unavailable")
				}
				legacyBasic = confidentialBasic(t, legacy.Client.ID, secret)
				_, legacyRefresh = issuedConfidentialTokens(t, f, before, legacy.Client, legacyBasic)
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, legacy.Client.ID).Scan(&legacyRegistration, &legacyDigest); err != nil {
					t.Fatal("original confidential custody unavailable")
				}
			}
			r := clientCreateRequest(t, f, "managed-confidential-oidc")
			r.Scopes = []string{"openid"}
			if out, err := before.ClientCreate(f.ctx, r); err == nil || out.Client.ID != "" {
				t.Fatal("default management selected confidential OIDC")
			}
			f.oauth.Protocol.ManagedClients.ConfidentialOIDC = true
			service, _, store := managedOIDCServices(t, f, signer, subjectKey)
			manager := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
			manager.denied.Store(true)
			if out, err := service.ClientCreate(f.ctx, r); err == nil || out.Client.ID != "" {
				t.Fatal("confidential OIDC selection bypassed current manager")
			}
			manager.denied.Store(false)
			if populated {
				retry, err := service.ClientCreate(f.ctx, legacyRequest)
				if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != legacy.Completion.CommandID {
					t.Fatal("confidential OIDC activation changed original OAuth intent", err)
				}
				if _, err := retry.Secret.Reveal(); err == nil {
					t.Fatal("original OAuth retry redelivered secret")
				}
				var registration, digest []byte
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, legacy.Client.ID).Scan(&registration, &digest); err != nil || !bytes.Equal(registration, legacyRegistration) || !bytes.Equal(digest, legacyDigest) {
					t.Fatal("confidential OIDC activation rewrote original OAuth bytes")
				}
				if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: legacy.Client.ID, ClientAuthentication: legacyBasic, RefreshToken: legacyRefresh, Network: "192.0.2.1"}); err != nil {
					t.Fatal("confidential OIDC activation stranded original OAuth refresh", err)
				}
			}
			created, err := service.ClientCreate(f.ctx, r)
			if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted || created.Client.Public || created.Client.AuthenticationMethod != "client_secret_basic" || !slices.Equal(created.Client.Scopes, []string{"openid"}) || created.Client.SubjectRegistration != nil {
				t.Fatal("manager could not provision exact confidential OIDC class", err)
			}
			secret, err := created.Secret.Reveal()
			if err != nil {
				t.Fatal("fresh known confidential commitment omitted its secret")
			}
			oldBasic := confidentialBasic(t, created.Client.ID, secret)
			var digest []byte
			wantDigest, err := oauth.DigestClientSecret(created.Client.ID, 1, secret)
			if err != nil {
				t.Fatal("confidential digest binding failed")
			}
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&digest); err != nil || !bytes.Equal(digest, wantDigest[:]) {
				t.Fatal("confidential OIDC did not persist existing digest-only custody")
			}
			fresh, child, _ := managedOIDCServices(t, f, signer, subjectKey)
			read := oauth.ClientReadRequest{Owner: r.Owner, TenantID: f.tenant, Session: f.browser, ClientID: created.Client.ID}
			current, err := fresh.ClientGet(f.ctx, read)
			if err != nil || current.Client.ID != created.Client.ID || current.Client.Public || current.Client.AuthenticationMethod != "client_secret_basic" || !slices.Equal(current.Client.Scopes, []string{"openid"}) {
				t.Fatal("fresh service lost safe confidential OIDC metadata", err)
			}
			read.ClientID, read.Limit = "", 100
			listed, err := fresh.ClientList(f.ctx, read)
			if err != nil || !slices.ContainsFunc(listed.Page.Items(), func(c oauth.Client) bool {
				return c.ID == current.Client.ID && !c.Public && c.AuthenticationMethod == "client_secret_basic" && slices.Equal(c.Scopes, []string{"openid"})
			}) {
				t.Fatal("safe list omitted confidential OIDC metadata", err)
			}
			transport := &discoveryConsumerTransport{f: f, service: fresh, endpoints: f.oauth.Protocol.Discovery, oidc: child, userInfoClientID: current.Client.ID}
			httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			ctx := rp.ClientContext(f.ctx, httpClient)
			provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
			if err != nil {
				t.Fatal("independent confidential RP discovery failed", err)
			}
			standard := oauth2.Config{ClientID: current.Client.ID, ClientSecret: secret, RedirectURL: current.Client.Redirects[0], Scopes: []string{"openid"}, Endpoint: provider.Endpoint()}
			standard.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
			authorize := func(nonce string) (string, string) {
				t.Helper()
				verifier := oauth2.GenerateVerifier()
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, standard.AuthCodeURL("confidential-state", oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("resource", current.Client.Resource)), nil)
				if err != nil {
					t.Fatal("confidential RP authorization request failed")
				}
				response, err := httpClient.Do(request)
				if err != nil {
					t.Fatal("confidential RP actual consent/S256 failed", err)
				}
				response.Body.Close()
				callback, err := url.Parse(response.Header.Get("Location"))
				if err != nil || callback.Query().Get("state") != "confidential-state" || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() || callback.Query().Get("code") == "" {
					t.Fatal("confidential RP callback lost issuer/state/code")
				}
				return callback.Query().Get("code"), verifier
			}
			exchange := func(code, verifier, nonce string) (*oauth2.Token, *rp.IDToken) {
				t.Helper()
				token, err := standard.Exchange(ctx, code, oauth2.VerifierOption(verifier))
				if err != nil {
					t.Fatal("confidential RP Basic code exchange failed", err)
				}
				wire, ok := token.Extra("id_token").(string)
				if !ok {
					t.Fatal("confidential RP received no signed ID token")
				}
				verified, err := consumeIDToken(ctx, provider, wire, nonce, current.Client.ID)
				if err != nil || verified.Subject == "" || !time.Now().Before(verified.Expiry) {
					t.Fatal("confidential RP rejected issuer/audience/nonce/signature/expiry", err)
				}
				if _, err := consumeIDToken(ctx, provider, wire, "wrong-nonce", current.Client.ID); err == nil {
					t.Fatal("confidential RP accepted another nonce")
				}
				info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
				var claims map[string]json.RawMessage
				if err != nil || info.Subject != verified.Subject || info.Claims(&claims) != nil || len(claims) != 1 || claims["sub"] == nil {
					t.Fatal("confidential openid UserInfo lost equal sub or disclosed other claims", err)
				}
				return token, verified
			}
			code, verifier := authorize("confidential-original-nonce")
			uncomposed, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			request := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: current.Client.ID, Code: code, CodeVerifier: verifier, RedirectURI: current.Client.Redirects[0], Network: "192.0.2.1"}
			if _, err := fresh.Token(f.ctx, request); err == nil {
				t.Fatal("confidential OIDC code accepted absent client authentication")
			}
			request.ClientAuthentication = oldBasic
			if _, err := uncomposed.Token(f.ctx, request); !errors.Is(err, oauth.ErrAccessDenied) {
				t.Fatal("uncomposed confidential OIDC consumed original code", err)
			}
			token, verified := exchange(code, verifier, "confidential-original-nonce")
			rotation := clientRotationRequest(t, f, current.Client, "confidential-oidc-rotate", 0)
			manager.denied.Store(true)
			if out, err := fresh.ClientRotateSecret(f.ctx, rotation); err == nil || out.Client.ID != "" {
				t.Fatal("confidential OIDC rotation bypassed current manager")
			}
			manager.denied.Store(false)
			rotated, err := fresh.ClientRotateSecret(f.ctx, rotation)
			if err != nil || rotated.Client.Version != current.Client.Version+1 || !rotated.PredecessorExpiresAt.IsZero() {
				t.Fatal("confidential OIDC zero-overlap rotation failed", err)
			}
			successor, err := rotated.Secret.Reveal()
			if err != nil || successor == secret {
				t.Fatal("confidential OIDC rotation did not reveal a fresh successor")
			}
			newBasic := confidentialBasic(t, current.Client.ID, successor)
			if err := store.AuthenticateCurrentClient(f.ctx, rotated.Client, oldBasic); err == nil {
				t.Fatal("confidential OIDC zero-overlap retained predecessor")
			}
			if _, err := fresh.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: current.Client.ID, ClientAuthentication: newBasic, RefreshToken: token.RefreshToken, Network: "192.0.2.1"}); err == nil {
				t.Fatal("confidential OIDC rotation preserved an older grant")
			}
			if info, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: current.Client.ID, AccessToken: token.AccessToken}); err == nil || info != (op.UserInfo{}) {
				t.Fatal("confidential OIDC rotation retained earlier UserInfo")
			}
			replayed, err := fresh.ClientRotateSecret(f.ctx, rotation)
			if err != nil || !replayed.Completion.Replayed || replayed.Completion.CommandID != rotated.Completion.CommandID {
				t.Fatal("confidential OIDC rotation lost original metadata-only replay", err)
			}
			if _, err := replayed.Secret.Reveal(); err == nil {
				t.Fatal("confidential OIDC rotation replay redelivered secret")
			}
			standard.ClientSecret = successor
			code, verifier = authorize("confidential-successor-nonce")
			request.Code, request.CodeVerifier = code, verifier
			if _, err := fresh.Token(f.ctx, request); err == nil {
				t.Fatal("confidential OIDC successor code accepted old secret")
			}
			next, nextID := exchange(code, verifier, "confidential-successor-nonce")
			if nextID.Subject != verified.Subject {
				t.Fatal("confidential OIDC subject changed after secret rotation")
			}
			restarted, restartedChild, _ := managedOIDCServices(t, f, signer, subjectKey)
			refreshRequest := oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: current.Client.ID, ClientAuthentication: newBasic, RefreshToken: next.RefreshToken, Network: "192.0.2.1"}
			if _, err := uncomposed.Token(f.ctx, refreshRequest); !errors.Is(err, oauth.ErrAccessDenied) {
				t.Fatal("uncomposed confidential OIDC consumed absent-scope refresh", err)
			}
			refreshed, err := restarted.Token(f.ctx, refreshRequest)
			if err != nil {
				t.Fatal("reconstructed confidential OIDC refresh failed", err)
			}
			access, _ := refreshed.AccessToken.Reveal()
			refresh, _ := refreshed.RefreshToken.Reveal()
			if info, err := restartedChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: current.Client.ID, AccessToken: access}); err != nil || info.Subject != verified.Subject {
				t.Fatal("refreshed confidential UserInfo changed original subject", err)
			}
			if _, err := restarted.Revoke(f.ctx, oauth.RevokeRequest{ClientID: current.Client.ID, ClientAuthentication: newBasic, Token: refresh, Network: "192.0.2.1"}); err != nil {
				t.Fatal("confidential OIDC revocation failed", err)
			}
			if info, err := restartedChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: current.Client.ID, AccessToken: access}); err == nil || info != (op.UserInfo{}) {
				t.Fatal("revoked confidential OIDC retained claims")
			}
			remove := clientRotationRequest(t, f, rotated.Client, "confidential-oidc-delete", 0).Management
			if _, err := restarted.ClientDelete(f.ctx, remove); err != nil {
				t.Fatal("confidential OIDC terminal deletion failed", err)
			}
			for _, warm := range []*oauth.Service{service, fresh, restarted} {
				read.ClientID, read.Limit = current.Client.ID, 0
				if got, err := warm.ClientGet(f.ctx, read); err == nil || got.Client.ID != "" {
					t.Fatal("warm service disclosed terminal confidential OIDC registration")
				}
				refreshRequest.RefreshToken = refresh
				if _, err := warm.Token(f.ctx, refreshRequest); err == nil {
					t.Fatal("terminal confidential OIDC deletion retained token authority")
				}
			}
		})
	}
}

func TestNativeManagedConfidentialOIDCMetadataReplacementDeniesBeforeMutation(t *testing.T) {
	f := passwordFixture(t)
	signer, subjectKey := managedConfidentialOIDCFixture(t, &f, true)
	f.oauth.Protocol.ManagedClients.ConfidentialOIDC = true
	service, _, store := managedOIDCServices(t, f, signer, subjectKey)
	uncomposed, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	request := clientCreateRequest(t, f, "confidential-oidc-update-source")
	request.Scopes = []string{"openid"}
	created, err := service.ClientCreate(f.ctx, request)
	if err != nil {
		t.Fatal("genuine original OIDC registration unavailable", err)
	}
	control, err := service.ClientCreate(f.ctx, clientCreateRequest(t, f, "confidential-oidc-update-control"))
	if err != nil {
		t.Fatal("genuine original OAuth registration unavailable", err)
	}
	original := originalClientRead(t, f).Session
	type snapshot struct {
		registration, digest    []byte
		version, generation     string
		effects, audits, events int
	}
	read := func(id string) snapshot {
		t.Helper()
		var out snapshot
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest,version::text,secret_version::text,(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-update'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.update_client'),(SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_client.updated.v1') FROM oauth_store.managed_clients WHERE client_id=$1`, id).Scan(&out.registration, &out.digest, &out.version, &out.generation, &out.effects, &out.audits, &out.events); err != nil {
			t.Fatal("current metadata mutation snapshot unavailable")
		}
		return out
	}
	for _, tc := range []struct {
		name   string
		client oauth.Client
		scopes []string
	}{
		{"oidc-source", created.Client, []string{"identity:read"}},
		{"oidc-target", control.Client, []string{"openid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := read(tc.client.ID)
			r := oauth.ClientUpdateRequest{Management: clientRotationRequest(t, f, tc.client, "excluded-"+tc.name, 0).Management, Redirects: tc.client.Redirects, Scopes: tc.scopes}
			for _, core := range []*oauth.Service{service, uncomposed} {
				if out, err := core.ClientUpdate(f.ctx, r); err == nil || out.Client.ID != "" {
					t.Fatal("excluded OIDC metadata replacement escaped core admission", err)
				}
			}
			out, updateErr := store.UpdateClient(f.ctx, oauth.ClientUpdateExecution{Request: r, Session: original})
			after := read(tc.client.ID)
			if updateErr == nil || out.Client.ID != "" {
				t.Fatalf("excluded OIDC replacement reached native mutation: committed=%t version_changed=%t effects_changed=%t error_type=%T", out.Completion.Outcome == identity.CommitOutcomeCommitted, after.version != before.version, after.effects != before.effects, updateErr)
			}
			if !bytes.Equal(after.registration, before.registration) || !bytes.Equal(after.digest, before.digest) || after.version != before.version || after.generation != before.generation || after.effects != before.effects || after.audits != before.audits || after.events != before.events {
				t.Fatal("denied OIDC metadata replacement committed protected state or effects")
			}
		})
	}
	r := oauth.ClientUpdateRequest{Management: clientRotationRequest(t, f, control.Client, "ordinary-update-control", 0).Management, Redirects: control.Client.Redirects, Scopes: []string{"identity:read"}}
	if out, err := uncomposed.ClientUpdate(f.ctx, r); err != nil || out.Client.Version != control.Client.Version+1 {
		t.Fatal("confidential OIDC selection disabled actual original OAuth update", err)
	}
}

func TestNativeManagedConfidentialOIDCRetainsOriginalOAuthUpdateRetryAfterDeletion(t *testing.T) {
	f := passwordFixture(t)
	signer, subjectKey := managedConfidentialOIDCFixture(t, &f, true)
	service, _, _ := managedOIDCServices(t, f, signer, subjectKey)
	created, err := service.ClientCreate(f.ctx, clientCreateRequest(t, f, "historical-oauth-update"))
	if err != nil {
		t.Fatal("original OAuth client unavailable", err)
	}
	r := oauth.ClientUpdateRequest{Management: clientRotationRequest(t, f, created.Client, "historical-original-update", 0).Management, Redirects: created.Client.Redirects, Scopes: []string{"identity:read"}}
	updated, err := service.ClientUpdate(f.ctx, r)
	if err != nil || updated.Completion.Outcome != identity.CommitOutcomeCommitted || updated.Client.Version != 2 {
		t.Fatal("original OAuth update did not commit", err)
	}
	f.oauth.Protocol.ManagedClients.ConfidentialOIDC = true
	selected, _, _ := managedOIDCServices(t, f, signer, subjectKey)
	remove := clientRotationRequest(t, f, updated.Client, "historical-update-delete", 0).Management
	if _, err := selected.ClientDelete(f.ctx, remove); err != nil {
		t.Fatal("original updated client deletion failed", err)
	}
	fresh, _, store := managedOIDCServices(t, f, signer, subjectKey)
	if _, err := store.CurrentClient(f.ctx, created.Client.ID); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatal("deleted client unexpectedly retained active metadata", err)
	}
	for _, core := range []*oauth.Service{service, selected, fresh} {
		replayed, err := core.ClientUpdate(f.ctx, r)
		if err != nil || !replayed.Completion.Replayed || replayed.Completion.CommandID != updated.Completion.CommandID || replayed.Completion.Outcome != identity.CommitOutcomeCommitted || replayed.Client.Version != updated.Client.Version || !slices.Equal(replayed.Client.Scopes, updated.Client.Scopes) {
			t.Fatal("confidential OIDC selection stranded original OAuth update metadata", err)
		}
	}
	r.Management.RequestKey, _ = identity.NewIdempotencyKey([]byte("historical-fresh-update-denied"))
	if out, err := fresh.ClientUpdate(f.ctx, r); err == nil || out.Client.ID != "" {
		t.Fatal("historical retry admission permitted a fresh deleted-client update", err)
	}
	var state, version string
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state,version::text,(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-update') FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&state, &version, &effects); err != nil || state != "deleted" || version != "3" || effects != 1 {
		t.Fatal("original replay changed the tombstone or duplicated mutation effects")
	}
}
