//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"golang.org/x/oauth2"
)

func managedClaimsFixture(t *testing.T, f *authenticatedPasswordFixture, populated bool) (*oauth.SigningService, [32]byte) {
	t.Helper()
	signer, subjectKey := managedOIDCFixture(t, f, populated)
	f.oauth.Protocol.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "profile", "email", "phone"})
	schema := nativeProfileSchema()
	f.oauth.ProfileUserInfo = &oauthpostgres.ProfileUserInfoConfig{AttributeSchemas: []identity.AttributeSchema{schema}, ProfileSchema: kernel.ProfileSchemaRef{ID: schema.ID, Version: schema.Version}}
	f.oauth.Protocol.ManagedClients.PublicOIDC = true
	return signer, subjectKey
}

func managedClaimsServices(t *testing.T, f authenticatedPasswordFixture, signer *oauth.SigningService, subjectKey [32]byte) (*oauth.Service, *op.Service, *oauthpostgres.Store) {
	t.Helper()
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal("native managed account-claims composition failed", err)
	}
	core, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store, Clients: store})
	if err != nil {
		t.Fatal(err)
	}
	issuer := f.oauth.Protocol.Issuer.String()
	child, err := op.NewService(op.Config{Issuer: f.oauth.Protocol.Issuer, JWKSURI: issuer + "/oauth2/jwks", UserInfoEndpoint: issuer + "/oauth2/userinfo", Signing: signer, SubjectKey: subjectKey, Clock: clock.System{}, MaximumDuration: 4 * time.Second, ProfileUserInfo: true, EmailUserInfo: true, PhoneUserInfo: true}, core)
	if err != nil {
		t.Fatal(err)
	}
	service, err := core.WithOIDC(child)
	if err != nil {
		t.Fatal(err)
	}
	return service, child, store
}

func selectManagedClaims(f *authenticatedPasswordFixture) {
	f.oauth.Protocol.ManagedClients.PublicOIDCScopes = []string{"openid", "profile", "email", "phone"}
}

func createManagedClaimsClient(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service, label string) oauth.Client {
	t.Helper()
	r := clientCreateRequest(t, f, label)
	r.Public, r.Scopes = true, []string{"openid", "profile", "email", "phone"}
	created, err := service.ClientCreate(f.ctx, r)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted || !created.Client.Public || created.Client.AuthenticationMethod != "none" || created.Client.SubjectRegistration != nil || !slices.Equal(created.Client.Scopes, []string{"email", "openid", "phone", "profile"}) {
		t.Fatal("genuine manager did not commit exact public account-claims registration", err)
	}
	if _, err := created.Secret.Reveal(); err == nil {
		t.Fatal("public account-claims creation exposed a secret")
	}
	var absent bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT secret_digest IS NULL FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&absent); err != nil || !absent {
		t.Fatal("public account-claims registration persisted secret custody", err)
	}
	return created.Client
}

type managedClaimsRP struct {
	ctx       context.Context
	provider  *rp.Provider
	client    oauth2.Config
	http      *http.Client
	transport *discoveryConsumerTransport
	resource  string
}

func newManagedClaimsRP(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service, child *op.Service, client oauth.Client) managedClaimsRP {
	t.Helper()
	transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child, userInfoClientID: client.ID}
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx := rp.ClientContext(f.ctx, httpClient)
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal("managed account-claims independent RP discovery failed", err)
	}
	standard := oauth2.Config{ClientID: client.ID, RedirectURL: client.Redirects[0], Endpoint: provider.Endpoint()}
	standard.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	return managedClaimsRP{ctx: ctx, provider: provider, client: standard, http: httpClient, transport: transport, resource: client.Resource}
}

func (p managedClaimsRP) issue(t *testing.T, scopes []string, nonce string) (*oauth2.Token, *rp.IDToken) {
	t.Helper()
	standard := p.client
	standard.Scopes = scopes
	proof := oauth2.GenerateVerifier()
	request, err := http.NewRequestWithContext(p.ctx, http.MethodGet, standard.AuthCodeURL("claims-state", oauth2.S256ChallengeOption(proof), oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("resource", p.resource)), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := p.http.Do(request)
	if err != nil {
		t.Fatal("managed account-claims real consent/S256 failed", err)
	}
	response.Body.Close()
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil || callback.Query().Get("state") != "claims-state" || callback.Query().Get("iss") != p.transport.f.oauth.Protocol.Issuer.String() || callback.Query().Get("code") == "" {
		t.Fatal("managed account-claims callback lost issuer/state/code")
	}
	token, err := standard.Exchange(p.ctx, callback.Query().Get("code"), oauth2.VerifierOption(proof))
	if err != nil {
		t.Fatal("managed account-claims secretless code exchange failed", err)
	}
	wire, ok := token.Extra("id_token").(string)
	if !ok {
		t.Fatal("managed account-claims omitted signed ID token")
	}
	verified, err := consumeIDToken(p.ctx, p.provider, wire, nonce, standard.ClientID)
	if err != nil || verified.Subject == "" || !time.Now().Before(verified.Expiry) {
		t.Fatal("independent RP rejected managed account-claims issuer/audience/nonce/signature/expiry", err)
	}
	var claims map[string]json.RawMessage
	if verified.Claims(&claims) != nil || len(claims) != 9 || claims["name"] != nil || claims["email"] != nil || claims["phone_number"] != nil {
		t.Fatal("account-claim selection expanded minimized ID token")
	}
	if _, err := consumeIDToken(p.ctx, p.provider, wire, "foreign-nonce", standard.ClientID); err == nil {
		t.Fatal("managed account-claims RP accepted foreign nonce")
	}
	return token, verified
}

func (p managedClaimsRP) userInfo(t *testing.T, token *oauth2.Token, subject string, scopes []string, name, email, phone string) {
	t.Helper()
	info, err := p.provider.UserInfo(p.ctx, oauth2.StaticTokenSource(token))
	var claims map[string]json.RawMessage
	if err != nil || info.Subject != subject || info.Claims(&claims) != nil {
		t.Fatal("managed account-claims independent UserInfo lost equal subject", err)
	}
	count := 1
	for _, field := range []struct{ scope, key, value string }{{"profile", "name", name}, {"email", "email", email}, {"phone", "phone_number", phone}} {
		if !slices.Contains(scopes, field.scope) || field.value == "" {
			if claims[field.key] != nil || field.scope == "email" && claims["email_verified"] != nil || field.scope == "phone" && claims["phone_number_verified"] != nil {
				t.Fatal("UserInfo disclosed absent, unverified or unconsented account claim")
			}
			continue
		}
		var actual string
		if json.Unmarshal(claims[field.key], &actual) != nil || actual != field.value {
			t.Fatal("UserInfo account claim differs from current native owner", field.key)
		}
		count++
		if field.scope == "email" || field.scope == "phone" {
			if string(claims[field.key+"_verified"]) != "true" {
				t.Fatal("UserInfo did not preserve actual contact verification")
			}
			count++
		}
	}
	if len(claims) != count {
		t.Fatal("UserInfo exposed additional private profile/contact fields")
	}
}

func managedClaimsEmail(t *testing.T, f authenticatedPasswordFixture, user identity.UserID) string {
	t.Helper()
	owner, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	state, err := owner.GetIdentifierState(f.ctx, identity.IdentifierQuery{TenantID: f.tenant, UserID: user, MaximumIdentifiers: 128})
	if err != nil {
		t.Fatal(err)
	}
	var selected string
	for j, identifier := range state.Identifiers {
		if identifier.Kind == identity.IdentifierEmail && identifier.Verified && state.Verifications[j].State == identity.VerificationVerified && (selected == "" || identifier.Primary) {
			selected = identifier.CanonicalValue
		}
	}
	if selected == "" {
		t.Fatal("genuine signup did not establish verified email")
	}
	return selected
}

func TestNativeManagedPublicClaimsFreshAndPopulatedIndependentConsumer(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated"}[populated], func(t *testing.T) {
			f := profilePasswordFixture(t, false)
			profile := mutateNativeProfile(t, f, "Original managed account")
			phone := pendingNativePhone(t, f)
			f.browser, f.csrf = f.signInAgain()
			signer, subjectKey := managedClaimsFixture(t, &f, populated)
			email := managedClaimsEmail(t, f, profile.ID)
			before, beforeChild, _ := managedClaimsServices(t, f, signer, subjectKey)
			var legacy oauth.ClientManagementResult
			var legacyRequest oauth.ClientManagementRequest
			var legacyToken *oauth2.Token
			var legacyBytes []byte
			if populated {
				legacyRequest = clientCreateRequest(t, f, "claims-original-openid")
				legacyRequest.Public, legacyRequest.Scopes = true, []string{"openid"}
				var err error
				legacy, err = before.ClientCreate(f.ctx, legacyRequest)
				if err != nil {
					t.Fatal(err)
				}
				consumer := newManagedClaimsRP(t, f, before, beforeChild, legacy.Client)
				var verified *rp.IDToken
				legacyToken, verified = consumer.issue(t, []string{"openid"}, "claims-original-openid")
				consumer.userInfo(t, legacyToken, verified.Subject, []string{"openid"}, profile.Name, email, "")
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration FROM oauth_store.managed_clients WHERE client_id=$1`, legacy.Client.ID).Scan(&legacyBytes); err != nil {
					t.Fatal(err)
				}
			}
			unselected := clientCreateRequest(t, f, "claims-unselected")
			unselected.Public, unselected.Scopes = true, []string{"openid", "profile", "email", "phone"}
			if out, err := before.ClientCreate(f.ctx, unselected); !errors.Is(err, oauth.ErrInvalidScope) || out.Client.ID != "" {
				t.Fatal("PublicOIDC alone enabled managed account-claims scopes")
			}
			selectManagedClaims(&f)
			service, _, _ := managedClaimsServices(t, f, signer, subjectKey)
			if populated {
				retry, err := service.ClientCreate(f.ctx, legacyRequest)
				if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != legacy.Completion.CommandID || retry.Client.SubjectRegistration != nil || !slices.Equal(retry.Client.Scopes, []string{"openid"}) {
					t.Fatal("claims selection changed original default-public recovery", err)
				}
				var retained []byte
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration FROM oauth_store.managed_clients WHERE client_id=$1`, legacy.Client.ID).Scan(&retained); err != nil || !bytes.Equal(retained, legacyBytes) {
					t.Fatal("claims selection rewrote original public registration", err)
				}
				if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: legacy.Client.ID, RefreshToken: legacyToken.RefreshToken, Network: "192.0.2.1"}); err != nil {
					t.Fatal("claims selection stranded original openid refresh", err)
				}
			}
			client := createManagedClaimsClient(t, f, service, "managed-account-claims")
			rebuilt, rebuiltChild, _ := managedClaimsServices(t, f, signer, subjectKey)
			read := oauth.ClientReadRequest{Owner: client.Owner, TenantID: f.tenant, Session: f.browser, ClientID: client.ID}
			got, err := rebuilt.ClientGet(f.ctx, read)
			if err != nil || !got.Client.Public || !slices.Equal(got.Client.Scopes, client.Scopes) || got.Client.SubjectRegistration != nil {
				t.Fatal("fresh safe account-claims read lost exact registration", err)
			}
			read.ClientID, read.Limit = "", 100
			listed, err := rebuilt.ClientList(f.ctx, read)
			if err != nil || !slices.ContainsFunc(listed.Page.Items(), func(c oauth.Client) bool {
				return c.ID == client.ID && c.Public && slices.Equal(c.Scopes, client.Scopes)
			}) {
				t.Fatal("safe list lost managed account-claims registration", err)
			}
			consumer := newManagedClaimsRP(t, f, rebuilt, rebuiltChild, client)
			pending, verified := consumer.issue(t, client.Scopes, "managed-claims-pending-phone")
			consumer.userInfo(t, pending, verified.Subject, client.Scopes, profile.Name, email, "")
			phone.verify(t, f, true)
			consumer.userInfo(t, pending, verified.Subject, client.Scopes, profile.Name, email, "")
			phone.verify(t, f, false)
			if out, err := rebuiltChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: client.ID, AccessToken: pending.AccessToken}); err == nil || out != (op.UserInfo{}) {
				t.Fatal("contact verification silently renewed original account-claims grant")
			}
			f.browser, f.csrf = f.signInAgain()
			consumer.transport.f = f
			token, current := consumer.issue(t, client.Scopes, "managed-claims-verified-phone")
			if current.Subject != verified.Subject {
				t.Fatal("contact verification reassigned the RP subject")
			}
			consumer.userInfo(t, token, current.Subject, client.Scopes, profile.Name, email, "+12025550123")
			profile = mutateNativeProfile(t, f, "Current committed managed name")
			consumer.userInfo(t, token, current.Subject, client.Scopes, profile.Name, email, "+12025550123")
			for i, scopes := range [][]string{{"openid"}, {"openid", "profile"}, {"openid", "email"}, {"openid", "phone"}} {
				control, subject := consumer.issue(t, scopes, []string{"claims-sub-only", "claims-name-only", "claims-email-only", "claims-phone-only"}[i])
				consumer.userInfo(t, control, subject.Subject, scopes, profile.Name, email, "+12025550123")
			}
			restarted, restartedChild, _ := managedClaimsServices(t, f, signer, subjectKey)
			consumer.transport.service, consumer.transport.oidc = restarted, restartedChild
			refreshed, err := restarted.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: token.RefreshToken, Network: "192.0.2.1"})
			if err != nil {
				t.Fatal("reconstructed account-claims refresh failed", err)
			}
			access, _ := refreshed.AccessToken.Reveal()
			refresh, _ := refreshed.RefreshToken.Reveal()
			consumer.userInfo(t, &oauth2.Token{AccessToken: access, TokenType: "Bearer"}, current.Subject, client.Scopes, profile.Name, email, "+12025550123")
			narrowed, err := restarted.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: refresh, Scopes: []string{"openid", "email"}, Network: "192.0.2.1"})
			if err != nil {
				t.Fatal("valid account-claims refresh narrowing failed", err)
			}
			access, _ = narrowed.AccessToken.Reveal()
			refresh, _ = narrowed.RefreshToken.Reveal()
			consumer.userInfo(t, &oauth2.Token{AccessToken: access, TokenType: "Bearer"}, current.Subject, []string{"openid", "email"}, profile.Name, email, "+12025550123")
			inherited, err := restarted.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: refresh, Network: "192.0.2.1"})
			if err != nil || !slices.Equal(inherited.Scopes, []string{"email", "openid"}) {
				t.Fatal("omitted refresh scope renewed broader registration authority", err)
			}
			access, _ = inherited.AccessToken.Reveal()
			refresh, _ = inherited.RefreshToken.Reveal()
			consumer.userInfo(t, &oauth2.Token{AccessToken: access, TokenType: "Bearer"}, current.Subject, []string{"openid", "email"}, profile.Name, email, "+12025550123")
			if _, err := restarted.Revoke(f.ctx, oauth.RevokeRequest{ClientID: client.ID, Token: refresh, Network: "192.0.2.1"}); err != nil {
				t.Fatal(err)
			}
			if out, err := restartedChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: client.ID, AccessToken: access}); err == nil || out != (op.UserInfo{}) {
				t.Fatal("revoked account-claims family returned partial claims")
			}
			remove := clientRotationRequest(t, f, client, "account-claims-delete", 0).Management
			if _, err := restarted.ClientDelete(f.ctx, remove); err != nil {
				t.Fatal(err)
			}
			if out, err := rebuiltChild.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: client.ID, AccessToken: token.AccessToken}); err == nil || out != (op.UserInfo{}) {
				t.Fatal("warm service disclosed claims after terminal client deletion")
			}
		})
	}
}

func TestNativeManagedPublicClaimsRequiredEffectsAndUnknownOriginalRecovery(t *testing.T) {
	for _, mode := range []string{"audit", "outbox", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			var provisional atomic.Bool
			fault := &oauthCommitFault{beforeWrite: func(wire []byte) {
				if bytes.Contains(wire, []byte(`INSERT INTO "oauth_store".managed_clients`)) {
					provisional.Store(true)
				}
			}}
			schema := nativeProfileSchema()
			f := passwordFixtureWithProfileSchema(t, false, &schema, fault)
			signer, key := managedClaimsFixture(t, &f, false)
			selectManagedClaims(&f)
			service, _, store := managedClaimsServices(t, f, signer, key)
			if mode == "audit" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE audit.records ADD CONSTRAINT refuse_claims_audit CHECK(action<>'identity.oauth_server.create_client')`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "outbox" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_claims_event CHECK(topic<>'oauth_client.created.v1') NOT VALID`); err != nil {
					t.Fatal(err)
				}
			}
			r := clientCreateRequest(t, f, "claims-required-"+mode)
			r.Public, r.Scopes = true, []string{"openid", "profile", "email", "phone"}
			fault.armed.Store(mode == "unknown")
			out, err := service.ClientCreate(f.ctx, r)
			if err == nil || !provisional.Load() || out.Secret != (oauth.Token{}) {
				t.Fatal("account-claims required failure did not preserve atomic secret-free outcome")
			}
			want := 0
			if mode == "unknown" {
				want = 1
				if !fault.hit.Load() || out.Completion.Outcome != identity.CommitOutcomeUnknown || out.Completion.CommandID == "" {
					t.Fatal("account-claims actual COMMIT acknowledgement seam not reached")
				}
				recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-create", CommandID: out.Completion.CommandID, ClientID: oauth.ManagedClientPrefix + string(out.Completion.CommandID), TenantID: f.tenant, Session: f.browser}
				manager := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
				manager.denied.Store(true)
				if _, err := store.Recover(f.ctx, recovery); err == nil {
					t.Fatal("account-claims original recovery bypassed current manager")
				}
				manager.denied.Store(false)
				metadata, err := store.Recover(f.ctx, recovery)
				if err != nil || metadata.CommandID != recovery.CommandID || metadata.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("account-claims original metadata reconciliation failed", err)
				}
				rebuilt, _, _ := managedClaimsServices(t, f, signer, key)
				retry, err := rebuilt.ClientCreate(f.ctx, r)
				if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != recovery.CommandID || retry.Client.ID != recovery.ClientID || !retry.Client.Public || !slices.Equal(retry.Client.Scopes, []string{"email", "openid", "phone", "profile"}) || retry.Secret != (oauth.Token{}) {
					t.Fatal("account-claims original retry changed registration or disclosed credentials", err)
				}
			}
			var clients, effects, audits, events, secrets int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.managed_clients),(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-create'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.create_client' AND outcome=1),(SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_client.created.v1'),(SELECT count(*) FROM oauth_store.managed_clients WHERE secret_digest IS NOT NULL)`).Scan(&clients, &effects, &audits, &events, &secrets); err != nil || clients != want || effects != want || audits != want || events != want || secrets != 0 {
				t.Fatal("account-claims required effects were not atomic", err)
			}
		})
	}
}

func TestNativeManagedPublicClaimsActualContactRemovalWithdrawsOriginalGrant(t *testing.T) {
	f := profilePasswordFixture(t, false)
	phone := pendingNativePhone(t, f)
	phone.verify(t, f, false)
	f.browser, f.csrf = f.signInAgain()
	signer, key := managedClaimsFixture(t, &f, false)
	selectManagedClaims(&f)
	profile := mutateNativeProfile(t, f, "Managed contact owner")
	email := managedClaimsEmail(t, f, profile.ID)
	service, child, _ := managedClaimsServices(t, f, signer, key)
	client := createManagedClaimsClient(t, f, service, "claims-contact-removal")
	consumer := newManagedClaimsRP(t, f, service, child, client)
	token, verified := consumer.issue(t, client.Scopes, "managed-claims-before-removal")
	consumer.userInfo(t, token, verified.Subject, client.Scopes, profile.Name, email, "+12025550123")
	phoneLifecycleMigrations(t, f)
	removed := phone.remove(t, f)
	if removed.Cascade == nil || removed.Cascade.Status != identity.RevocationPending {
		t.Fatal("actual contact removal did not retain the owning pending cascade")
	}
	if out, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: client.ID, AccessToken: token.AccessToken}); err == nil || out != (op.UserInfo{}) {
		t.Fatal("removed contact retained any original managed account claims")
	}
	if out, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: token.RefreshToken, Network: "192.0.2.1"}); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("removed contact renewed original managed account-claims authority")
	}
	f.browser, f.csrf = f.signInAgain()
	consumer.transport.f = f
	fresh, after := consumer.issue(t, client.Scopes, "managed-claims-after-removal")
	if after.Subject != verified.Subject {
		t.Fatal("actual contact removal reassigned the managed RP subject")
	}
	consumer.userInfo(t, fresh, after.Subject, client.Scopes, profile.Name, email, "")
}

func TestNativeManagedPublicClaimsCurrentWithdrawalReturnsZeroClaims(t *testing.T) {
	for _, mode := range []string{"client", "user", "consent", "key", "profile-snapshot", "deadline", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := profilePasswordFixture(t, false)
			signer, key := managedClaimsFixture(t, &f, false)
			selectManagedClaims(&f)
			profile := mutateNativeProfile(t, f, "Current managed account")
			email := managedClaimsEmail(t, f, profile.ID)
			service, child, _ := managedClaimsServices(t, f, signer, key)
			client := createManagedClaimsClient(t, f, service, "claims-withdrawal-"+mode)
			consumer := newManagedClaimsRP(t, f, service, child, client)
			token, verified := consumer.issue(t, client.Scopes, "managed-claims-current-"+mode)
			consumer.userInfo(t, token, verified.Subject, client.Scopes, profile.Name, email, "")
			if out, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: token.AccessToken}); err == nil || out != (op.UserInfo{}) {
				t.Fatal("foreign client received managed account claims")
			}
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			var shift atomic.Int64
			f.oauth.Protocol.Clock = emailClock(func() time.Time { return time.Now().Add(time.Duration(shift.Load())) })
			trace := &profileReadTrace{at: 2}
			if mode == "profile-snapshot" {
				trace.at = 1
			}
			trace.late = func() {
				switch mode {
				case "profile-snapshot":
					mutateNativeProfile(t, f, "Committed name during claims read")
				case "deadline":
					shift.Store(int64(21 * time.Second))
				case "cancel":
					cancel()
				}
			}
			if mode == "profile-snapshot" || mode == "deadline" || mode == "cancel" {
				pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("OAUTH_POSTGRES_TEST_DSN"), MaxConns: 2, Configure: func(config *database.PoolConfig) error {
					config.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
					config.ConnConfig.Tracer = trace
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					if err := pool.Close(cleanup); err != nil {
						t.Error("managed claims traced pool cleanup failed")
					}
				})
				f.pool = pool
			}
			rebuilt, rebuiltChild, _ := managedClaimsServices(t, f, signer, key)
			switch mode {
			case "client":
				if _, err := rebuilt.ClientDelete(f.ctx, clientRotationRequest(t, f, client, "claims-withdraw-client", 0).Management); err != nil {
					t.Fatal(err)
				}
			case "user":
				suspendResourceUser(t, f, profile.ID)
			case "consent":
				consent := currentNarrowConsent(t, f, rebuilt)
				if _, err := rebuilt.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRemove, consent.ID(), consent.Version())}); err != nil {
					t.Fatal(err)
				}
			case "key":
				if err := signer.Compromise(f.ctx, "initial"); err != nil {
					t.Fatal(err)
				}
			}
			if out, err := rebuiltChild.UserInfo(ctx, oauth.UserInfoRequest{ClientID: client.ID, AccessToken: token.AccessToken}); err == nil || out != (op.UserInfo{}) {
				t.Fatal("withdrawal, mixed snapshots or original expiry returned partial managed claims")
			}
		})
	}
}
