//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	password "github.com/faustbrian/go-password/v2"
)

func confidentialBasic(t *testing.T, id, wire string) oauth.ClientAuthentication {
	t.Helper()
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(wire)))
	credential, err := oauth.ParseClientAuthentication([]string{header})
	if err != nil {
		t.Fatal("bounded Basic fixture rejected", err)
	}
	return credential
}

func addConfiguredConfidentialClient(t *testing.T, f *authenticatedPasswordFixture) (oauth.Client, string, oauth.ClientAuthentication) {
	t.Helper()
	client := f.oauth.Protocol.Clients[0]
	client.ID = "confidential-web"
	client.Public = false
	client.AuthenticationMethod = "client_secret_basic"
	client.Redirects = []string{"https://confidential.example/callback"}
	token, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := password.NewSecret([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oauth.NewClientSecretVerifier(client.ID, client.Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	f.oauth.Protocol.Clients = append(f.oauth.Protocol.Clients, client)
	f.oauth.Protocol.ClientSecrets = append(f.oauth.Protocol.ClientSecrets, verifier)
	return client, wire, confidentialBasic(t, client.ID, wire)
}

func confidentialCode(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service, client oauth.Client) (string, string) {
	t.Helper()
	verifier := strings.Repeat("a", 43)
	challenge, err := oauth.S256Challenge(verifier)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: client.ID, RedirectURI: client.Redirects[0], CodeChallenge: challenge, Resource: client.Resource, Scopes: []string{"identity:read"}, State: "confidential-original-state"}})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("genuine user did not reach confidential-client explicit consent", err)
	}
	wire, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	approved, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: client.ID, Continuation: wire, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true, Scopes: []string{"identity:read"}})
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("confidential client consent did not issue S256 code", err)
	}
	location, err := approved.Location()
	if err != nil {
		t.Fatal(err)
	}
	callback, err := url.Parse(location)
	if err != nil || callback.Scheme+"://"+callback.Host+callback.Path != client.Redirects[0] || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() || callback.Query().Get("state") != "confidential-original-state" {
		t.Fatal("confidential code lost exact original redirect/state/issuer")
	}
	return callback.Query().Get("code"), verifier
}

func TestNativeConfidentialDirectStoreRequiresActualClientSecretBeforeEffects(t *testing.T) {
	f := passwordFixture(t)
	client, wire, credential := addConfiguredConfidentialClient(t, &f)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := confidentialCode(t, f, service, client)
	var before int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	wrongWire := "A" + wire[1:]
	if wrongWire == wire {
		wrongWire = "B" + wire[1:]
	}
	for _, rejected := range []oauth.ClientAuthentication{{}, confidentialBasic(t, client.ID, wrongWire), confidentialBasic(t, "public-web", wire)} {
		out, err := store.Token(f.ctx, oauth.TokenCommand{Client: client, Request: oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: code, CodeVerifier: verifier, RedirectURI: client.Redirects[0], Network: "192.0.2.1", ClientAuthentication: rejected}})
		if !errors.Is(err, oauth.ErrInvalidClient) || out.CommandID != "" {
			t.Fatal("direct native code path bypassed actual confidential authentication", err)
		}
		revoked, err := store.Revoke(f.ctx, oauth.RevocationCommand{Client: client, Request: oauth.RevokeRequest{ClientID: client.ID, Token: wire, Network: "192.0.2.1", ClientAuthentication: rejected}})
		if !errors.Is(err, oauth.ErrInvalidClient) || revoked.CommandID != "" {
			t.Fatal("direct native revocation bypassed confidential authentication", err)
		}
		var after int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects`).Scan(&after); err != nil || after != before {
			t.Fatal("rejected confidential credential changed durable effects", err)
		}
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: code, CodeVerifier: verifier, RedirectURI: client.Redirects[0], Network: "192.0.2.1", ClientAuthentication: credential}); err != nil {
		t.Fatal("rejected credentials consumed legitimate code", err)
	}
}

func TestNativeConfidentialBasicFlowPreservesInstalledPublicGrants(t *testing.T) {
	f := passwordFixture(t)
	public, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	publicCode, publicVerifier := consentedCode(t, f, public)
	publicRefresh := freshRefresh(t, f, public)
	client, wire, credential := addConfiguredConfidentialClient(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: publicCode, CodeVerifier: publicVerifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"}); err != nil {
		t.Fatal("adding confidential client stranded installed public code", err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: publicRefresh, Network: "192.0.2.1"}); err != nil {
		t.Fatal("adding confidential client stranded installed public refresh", err)
	}
	code, verifier := confidentialCode(t, f, service, client)
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(client.ID)+":"+url.QueryEscape(wire)))
	request, err := oauth.ParseTokenFormWithClientAuthentication(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {client.Redirects[0]}}.Encode(), []string{header})
	if err != nil {
		t.Fatal("exclusive confidential code form rejected", err)
	}
	request.Network = "192.0.2.1"
	issued, err := service.Token(f.ctx, request)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("authenticated code exchange failed", err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: client.ID, Token: publicRefresh, Network: "192.0.2.1", ClientAuthentication: credential}); err != nil {
		t.Fatal("confidential foreign-token revocation was enumerable", err)
	}
	if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: client.ID, Token: access, Network: "192.0.2.1", ClientAuthentication: credential}); err != nil {
		t.Fatal("confidential access revocation failed", err)
	}
	request, err = oauth.ParseTokenFormWithClientAuthentication(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}.Encode(), []string{header})
	if err != nil {
		t.Fatal(err)
	}
	request.Network = "192.0.2.1"
	rotated, err := service.Token(f.ctx, request)
	if err != nil || rotated.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("access revocation invalidated confidential refresh", err)
	}
	child, err := rotated.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	revocation, err := oauth.ParseRevocationForm(url.Values{"token": {refresh}, "token_type_hint": {"refresh_token"}}.Encode(), []string{header})
	if err != nil {
		t.Fatal(err)
	}
	revocation.Network = "192.0.2.1"
	revoked, err := service.Revoke(f.ctx, revocation)
	if err != nil {
		t.Fatal("confidential consumed refresh revocation failed", err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.revoke", CommandID: revoked.CommandID, ClientID: client.ID, Token: refresh}
	if _, err := store.Recover(f.ctx, recovery); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatal("confidential revocation metadata lacked client authentication", err)
	}
	recovery.ClientAuthentication = credential
	if metadata, err := store.Recover(f.ctx, recovery); err != nil || metadata.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("authenticated revocation metadata unavailable", err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: child, Network: "192.0.2.1", ClientAuthentication: credential}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("confidential family survived owning consumed-token revocation", err)
	}
	var grantEvents, consentEvents, tokenEvents, revokeEvents, audits int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM public.outbox_messages WHERE topic='grant.created.v1'),(SELECT count(*) FROM public.outbox_messages WHERE topic='consent.created.v1'),(SELECT count(*) FROM public.outbox_messages WHERE topic='grant.code_exchanged.v1'),(SELECT count(*) FROM public.outbox_messages WHERE topic='grant.revoked.v1'),(SELECT count(*) FROM audit.records WHERE action LIKE 'identity.oauth_server.%' AND outcome=1)`).Scan(&grantEvents, &consentEvents, &tokenEvents, &revokeEvents, &audits); err != nil || grantEvents < 3 || consentEvents < 2 || tokenEvents < 3 || revokeEvents != 1 || audits == 0 {
		t.Fatal("real confidential/public flow lacked required audit/lifecycle effects", err)
	}
}

func TestNativeConfidentialRecoveryRequiresSecret(t *testing.T) {
	f := passwordFixture(t)
	client, _, credential := addConfiguredConfidentialClient(t, &f)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := confidentialCode(t, f, service, client)
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: code, CodeVerifier: verifier, RedirectURI: client.Redirects[0], Network: "192.0.2.1", ClientAuthentication: credential})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: issued.CommandID, ClientID: client.ID, Token: code})
	if !errors.Is(err, oauth.ErrInvalidClient) || metadata.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("confidential recovery disclosed historical state without secret", err)
	}
	recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: issued.CommandID, ClientID: client.ID, Token: code, ClientAuthentication: credential}
	metadata, err = store.Recover(f.ctx, recovery)
	if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("authenticated confidential recovery denied historical metadata", err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: refresh, Network: "192.0.2.1", ClientAuthentication: credential}); err != nil {
		t.Fatal("metadata read revoked live confidential grant", err)
	}
}

func TestNativeConfidentialLostCommitRecoversAuthenticatedMetadataOnly(t *testing.T) {
	for _, grant := range []oauth.GrantType{oauth.AuthorizationCodeGrant, oauth.RefreshTokenGrant} {
		t.Run(string(grant), func(t *testing.T) {
			fault := &oauthCommitFault{}
			f := passwordFixture(t, fault)
			client, wire, credential := addConfiguredConfidentialClient(t, &f)
			store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			service, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
			if err != nil {
				t.Fatal(err)
			}
			code, verifier := confidentialCode(t, f, service, client)
			request := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: code, CodeVerifier: verifier, RedirectURI: client.Redirects[0], Network: "192.0.2.1", ClientAuthentication: credential}
			original := code
			if grant == oauth.RefreshTokenGrant {
				known, err := service.Token(f.ctx, request)
				if err != nil {
					t.Fatal(err)
				}
				original, err = known.RefreshToken.Reveal()
				if err != nil {
					t.Fatal(err)
				}
				request = oauth.TokenRequest{GrantType: grant, ClientID: client.ID, RefreshToken: original, Network: "192.0.2.1", ClientAuthentication: credential}
			}
			fault.armed.Store(true)
			lost, err := service.Token(f.ctx, request)
			if !fault.hit.Load() || !errors.Is(err, oauth.ErrUnavailable) || lost.Outcome != identity.CommitOutcomeUnknown || lost.CommandID == "" {
				t.Fatal("confidential lost COMMIT was not classified unknown", err)
			}
			if _, err := lost.AccessToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
				t.Fatal("unknown confidential issuance revealed access")
			}
			if _, err := lost.RefreshToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
				t.Fatal("unknown confidential issuance revealed refresh")
			}
			var before int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			wrong := "A" + wire[1:]
			if wrong == wire {
				wrong = "B" + wire[1:]
			}
			recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: lost.CommandID, ClientID: client.ID, Token: original}
			for _, denied := range []oauth.ClientAuthentication{{}, confidentialBasic(t, client.ID, wrong), confidentialBasic(t, "public-web", wire)} {
				recovery.ClientAuthentication = denied
				if metadata, err := store.Recover(f.ctx, recovery); !errors.Is(err, oauth.ErrInvalidClient) || metadata.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("wrong client secret disclosed unknown-command metadata", err)
				}
			}
			recovery.ClientAuthentication = credential
			for range 2 {
				metadata, err := store.Recover(f.ctx, recovery)
				if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted || metadata.CommandID != lost.CommandID {
					t.Fatal("actual client could not recover historical metadata", err)
				}
			}
			var after int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects`).Scan(&after); err != nil || after != before {
				t.Fatal("metadata recovery changed confidential grant effects", err)
			}
			if _, err := service.Token(f.ctx, request); !errors.Is(err, oauth.ErrInvalidGrant) {
				t.Fatal("authenticated retry after lost COMMIT redelivered credentials", err)
			}
		})
	}
}

func TestNativeConfidentialContendedRefreshRevokesOnlyWinningFamily(t *testing.T) {
	f := passwordFixture(t)
	client, _, credential := addConfiguredConfidentialClient(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := confidentialCode(t, f, service, client)
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: code, CodeVerifier: verifier, RedirectURI: client.Redirects[0], Network: "192.0.2.1", ClientAuthentication: credential})
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	other := freshRefresh(t, f, service)
	barrier := &tokenAdmissionBarrier{owner: f.oauth.Coordinator.AdmissionPolicy.Authorization, ready: make(chan int, 2), release: [2]chan struct{}{make(chan struct{}), make(chan struct{})}}
	policy := *f.oauth.Coordinator.AdmissionPolicy
	policy.Authorization = barrier
	f.oauth.Coordinator.AdmissionPolicy = &policy
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err = oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		output oauth.TokenResult
		err    error
	}
	done := [2]chan result{make(chan result, 1), make(chan result, 1)}
	for i := range done {
		go func(index int) {
			out, err := service.Token(context.WithValue(f.ctx, tokenCallIndex{}, index), oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: refresh, Network: []string{"192.0.2.1", "192.0.2.2"}[index], ClientAuthentication: credential})
			done[index] <- result{out, err}
		}(i)
	}
	for range 2 {
		select {
		case <-barrier.ready:
		case <-f.ctx.Done():
			t.Fatal("confidential calls did not both observe active parent")
		}
	}
	close(barrier.release[0])
	winner := <-done[0]
	if winner.err != nil || winner.output.Outcome != identity.CommitOutcomeCommitted || winner.output.Replayed {
		t.Fatal("confidential winner failed", winner.err)
	}
	metadata, err := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: winner.output.CommandID, ClientID: client.ID, Token: refresh, ClientAuthentication: credential})
	if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("authenticated winner recovery failed", err)
	}
	close(barrier.release[1])
	loser := <-done[1]
	if !errors.Is(loser.err, oauth.ErrInvalidGrant) {
		t.Fatal("confidential duplicate escaped replay denial", loser.err)
	}
	if _, err := loser.output.RefreshToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("confidential loser redelivered refresh")
	}
	child, err := winner.output.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: child, Network: "192.0.2.1", ClientAuthentication: credential}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("confidential replay retained winning descendants", err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: other, Network: "192.0.2.1"}); err != nil {
		t.Fatal("confidential replay revoked unrelated public family", err)
	}
}

func TestNativeConfidentialCredentialsCannotReplaceWithdrawnUserAuthority(t *testing.T) {
	f := passwordFixtureWithChange(t, true)
	client, _, credential := addConfiguredConfidentialClient(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := confidentialCode(t, f, service, client)
	other, otherVerifier := confidentialCode(t, f, service, client)
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: other, CodeVerifier: otherVerifier, RedirectURI: client.Redirects[0], Network: "192.0.2.1", ClientAuthentication: credential})
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	f.changePassword()
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: code, CodeVerifier: verifier, RedirectURI: client.Redirects[0], Network: "192.0.2.1", ClientAuthentication: credential}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("correct client secret replaced withdrawn credential epoch for code", err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: refresh, Network: "192.0.2.1", ClientAuthentication: credential}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("correct client secret replaced withdrawn credential epoch for refresh", err)
	}
}

func TestNativeConfidentialSecretReplacementRequiresNewVersionAndNewGrant(t *testing.T) {
	f := passwordFixture(t)
	client, _, oldCredential := addConfiguredConfidentialClient(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := confidentialCode(t, f, service, client)
	client.Version++
	token, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := password.NewSecret([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	currentVerifier, err := oauth.NewClientSecretVerifier(client.ID, client.Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.oauth.Protocol.Clients {
		if f.oauth.Protocol.Clients[i].ID == client.ID {
			f.oauth.Protocol.Clients[i] = client
		}
	}
	f.oauth.Protocol.ClientSecrets = []oauth.ClientSecretVerifier{currentVerifier}
	current, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: code, CodeVerifier: verifier, RedirectURI: client.Redirects[0], Network: "192.0.2.1", ClientAuthentication: oldCredential}
	if _, err := current.Token(f.ctx, request); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatal("replacement snapshot accepted old client secret", err)
	}
	request.ClientAuthentication = confidentialBasic(t, client.ID, wire)
	if _, err := current.Token(f.ctx, request); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("new client policy silently inherited old grant", err)
	}
	request.Code, request.CodeVerifier = confidentialCode(t, f, current, client)
	if _, err := current.Token(f.ctx, request); err != nil {
		t.Fatal("current configured secret could not redeem newly consented grant", err)
	}
}

func TestNativeConfidentialConsentSecondaryFailureRollsBackAllEffects(t *testing.T) {
	f := passwordFixture(t)
	client, _, _ := addConfiguredConfidentialClient(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := oauth.S256Challenge(strings.Repeat("a", 43))
	if err != nil {
		t.Fatal(err)
	}
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: client.ID, RedirectURI: client.Redirects[0], CodeChallenge: challenge, Resource: client.Resource, Scopes: []string{"identity:read"}}})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("confidential interaction unavailable", err)
	}
	wire, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT oauth_test_confidential_secondary_failure CHECK(topic NOT IN('consent.created.v1','consent.reconfirmed.v1')) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	failed, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: client.ID, Continuation: wire, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true})
	if err == nil || failed.Outcome == oauth.AuthorizationRedirect {
		t.Fatal("confidential consent committed without secondary lifecycle")
	}
	if _, err := failed.Code.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("rolled-back confidential consent exposed code")
	}
	var codes, consents, effects, notifications, audits int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.artifacts WHERE kind=2),(SELECT count(*) FROM oauth_store.consents),(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.continue'),(SELECT count(*) FROM public.outbox_messages WHERE topic IN('grant.authorized.v1','grant.scope_changed.v1','consent.created.v1','consent.reconfirmed.v1')),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.grant_consent' AND outcome=1)`).Scan(&codes, &consents, &effects, &notifications, &audits); err != nil || codes != 0 || consents != 0 || effects != 0 || notifications != 0 || audits != 0 {
		t.Fatal("failed confidential lifecycle retained provisional effects", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages DROP CONSTRAINT oauth_test_confidential_secondary_failure`); err != nil {
		t.Fatal(err)
	}
	_, _ = confidentialCode(t, f, service, client)
}
