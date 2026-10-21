//go:build integration && oauthflow

package oauthpostgres_test

import (
	"crypto/ecdsa"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-clock"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/oauth2"
)

func pairwiseFixture(t *testing.T, f *authenticatedPasswordFixture) (*oauth.Service, *op.Service, *oauth.SigningService, *oauthpostgres.Store, *ecdsa.PrivateKey) {
	t.Helper()
	_, _, signer, _, signingKey := oidcFixture(t, f)
	installPairwiseMigration(t, *f)
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	for i := range f.oauth.Protocol.Clients {
		f.oauth.Protocol.Clients[i].SubjectRegistration = &registration
	}
	policy := pairwisePolicy(t, *f, 1, [32]byte{1, 2, 3})
	service, child, store := pairwiseService(t, *f, signer, policy)
	key, _ := policy.KeyRegistration(1)
	if err := store.InstallSubjectKey(f.ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateSubjectKey(f.ctx, "subjects", 1, 1); err != nil {
		t.Fatal(err)
	}
	return service, child, signer, store, signingKey
}

func pairwiseCodeForClient(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service, clientID, redirect, nonce string) (string, string) {
	t.Helper()
	verifier := oauth2.GenerateVerifier()
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: clientID, RedirectURI: redirect, Resource: f.oauth.Protocol.Resource, Scopes: []string{"identity:read", "openid"}, Nonce: nonce, CodeChallenge: oauth2.S256ChallengeFromVerifier(verifier)}})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("pairwise client did not reach genuine native consent", err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	approved, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: clientID, Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true})
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("pairwise client consent did not commit code", err)
	}
	location, err := approved.Location()
	if err != nil {
		t.Fatal(err)
	}
	callback, err := url.Parse(location)
	if err != nil || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() {
		t.Fatal("pairwise client issuer-bound callback invalid", err)
	}
	return callback.Query().Get("code"), verifier
}

func pairwisePolicy(t *testing.T, f authenticatedPasswordFixture, keyVersion uint32, material [32]byte) *op.SubjectPolicy {
	return pairwisePolicyNamed(t, f, "subjects", 1, keyVersion, material)
}

func pairwisePolicyNamed(t *testing.T, f authenticatedPasswordFixture, policyID string, policyVersion uint64, keyVersion uint32, material [32]byte) *op.SubjectPolicy {
	t.Helper()
	cipher, err := envelope.NewService(f.keys)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := envelope.NewContext(map[string]string{"profile": "golib.oidc.pairwise-key.v1", "issuer": f.oauth.Protocol.Issuer.String(), "environment": f.oauth.Protocol.Environment, "policy_id": policyID, "policy_version": strconv.FormatUint(policyVersion, 10), "key_version": strconv.FormatUint(uint64(keyVersion), 10)})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cipher.Encrypt(f.ctx, envelope.EncryptRequest{Plaintext: material[:], KeyReference: "oauth-envelope", Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := op.NewSubjectPolicy(f.ctx, op.SubjectPolicyConfig{Issuer: f.oauth.Protocol.Issuer, Environment: f.oauth.Protocol.Environment, PolicyID: policyID, PolicyVersion: policyVersion, ActiveKeyVersion: keyVersion, Keys: []op.SubjectKeyEnvelope{{Version: keyVersion, Envelope: wire}}}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func pairwiseService(t *testing.T, f authenticatedPasswordFixture, signer *oauth.SigningService, policy *op.SubjectPolicy) (*oauth.Service, *op.Service, *oauthpostgres.Store) {
	t.Helper()
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	core, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	issuer := f.oauth.Protocol.Issuer.String()
	child, err := op.NewService(op.Config{Issuer: f.oauth.Protocol.Issuer, JWKSURI: issuer + "/oauth2/jwks", UserInfoEndpoint: issuer + "/oauth2/userinfo", Signing: signer, SubjectKey: [32]byte{42}, SubjectPolicy: policy, Clock: clock.System{}, MaximumDuration: 4 * time.Second, EmailUserInfo: slices.Contains(f.oauth.Protocol.OIDCScopes.Scopes(), "email"), PhoneUserInfo: slices.Contains(f.oauth.Protocol.OIDCScopes.Scopes(), "phone")}, core)
	if err != nil {
		t.Fatal(err)
	}
	service, err := core.WithOIDC(child)
	if err != nil {
		t.Fatal(err)
	}
	return service, child, store
}

func installPairwiseMigration(t *testing.T, f authenticatedPasswordFixture) {
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
	var base migrations.Source = oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}
	if f.oauth.ConsentManagement {
		base = oauthpostgres.ConsentMigrationSource{Base: base, Schema: "oauth_store", Version: 7002}
	}
	base = oauthpostgres.SigningMigrationSource{Base: base, Schema: "oauth_store", Version: 7003}
	runner, err := migrations.NewRunner(oauthpostgres.PairwiseMigrationSource{Base: base, Schema: "oauth_store", Version: 7004}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNativeOIDCPairwiseIndependentRelyingPartyAndStableBinding(t *testing.T) {
	f := passwordFixture(t)
	_, _, signer, _, _ := oidcFixture(t, &f)
	installPairwiseMigration(t, f)
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	for i := range f.oauth.Protocol.Clients {
		f.oauth.Protocol.Clients[i].SubjectRegistration = &registration
	}
	otherSector := f.oauth.Protocol.Clients[0]
	otherRegistration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "other.example", "subjects", 1)
	otherSector.ID = "other-sector-client"
	otherSector.Redirects = []string{"https://other.example/callback"}
	otherSector.SubjectRegistration = &otherRegistration
	f.oauth.Protocol.Clients = append(f.oauth.Protocol.Clients, otherSector)
	policy := pairwisePolicy(t, f, 1, [32]byte{1, 2, 3})
	service, child, store := pairwiseService(t, f, signer, policy)
	key, err := policy.KeyRegistration(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.InstallSubjectKey(f.ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateSubjectKey(f.ctx, "subjects", 1, 1); err != nil {
		t.Fatal(err)
	}
	transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	ctx := rp.ClientContext(f.ctx, client)
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal("pairwise independent discovery denied", err)
	}
	var discovery struct {
		Subjects []string `json:"subject_types_supported"`
	}
	if provider.Claims(&discovery) != nil || len(discovery.Subjects) != 2 || discovery.Subjects[1] != "pairwise" {
		t.Fatal("selected pairwise support was not accurately advertised")
	}
	code, verifier := oidcCode(t, f, service, "pairwise-original-nonce")
	issued, err := service.Token(ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("pairwise code exchange denied", err)
	}
	wire, err := issued.IDToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := consumeIDToken(ctx, provider, wire, "pairwise-original-nonce", "public-web")
	if err != nil {
		t.Fatal("independent RP rejected pairwise ID token", err)
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: access, TokenType: "Bearer"}))
	if err != nil || info.Subject != verified.Subject {
		t.Fatal("pairwise UserInfo departed from original grant subject", err)
	}
	var persisted string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT subject FROM oauth_store.subject_bindings`).Scan(&persisted); err != nil || persisted != verified.Subject {
		t.Fatal("ID preparation did not consume native durable subject binding", err)
	}
	originalRefresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	var originalRefreshID string
	var originalRefreshExpiry, originalGrantExpiry time.Time
	if err := f.pool.Raw().QueryRow(ctx, `SELECT a.artifact_id,a.expires_at,g.expires_at FROM oauth_store.artifacts a JOIN oauth_store.grants g USING(grant_id) WHERE a.kind=4`).Scan(&originalRefreshID, &originalRefreshExpiry, &originalGrantExpiry); err != nil {
		t.Fatal("original refresh authority unavailable", err)
	}
	// Key versions change new writers, not existing RP identities. Reconstruct
	// from only key2 custody after explicitly retiring key1; old access and a
	// fresh authenticated grant must still reference the original binding.
	next := pairwisePolicy(t, f, 2, [32]byte{9, 8, 7})
	key2, _ := next.KeyRegistration(2)
	if err := store.InstallSubjectKey(ctx, key2); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateSubjectKey(ctx, "subjects", 1, 2); err != nil {
		t.Fatal(err)
	}
	if err := store.RetireSubjectKey(ctx, "subjects", 1, 1); err != nil {
		t.Fatal(err)
	}
	retained, active, err := store.SubjectKeyRegistrations(ctx, "subjects", 1)
	if err != nil || active != 2 || len(retained) != 1 || retained[0].KeyVersion != 2 {
		t.Fatal("durable key reconstruction restored retired custody or lost active writer", err)
	}
	cipher, _ := envelope.NewService(f.keys)
	restoredPolicy, err := op.NewSubjectPolicy(ctx, op.SubjectPolicyConfig{Issuer: f.oauth.Protocol.Issuer, Environment: f.oauth.Protocol.Environment, PolicyID: "subjects", PolicyVersion: 1, ActiveKeyVersion: active, Keys: []op.SubjectKeyEnvelope{{Version: retained[0].KeyVersion, Envelope: retained[0].Envelope}}}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, rebuiltChild, _ := pairwiseService(t, f, signer, restoredPolicy)
	oldInfo, err := rebuiltChild.UserInfo(ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access})
	if err != nil || oldInfo.Subject != verified.Subject {
		t.Fatal("key migration changed retained grant identity", err)
	}
	rotated, err := rebuilt.Token(ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: originalRefresh, Network: "192.0.2.1"})
	if err != nil || rotated.Replayed {
		t.Fatal("original pairwise refresh denied after derivation-key retirement/reconstruction", err)
	}
	rotatedAccess, err := rotated.AccessToken.Reveal()
	if err != nil {
		t.Fatal("pairwise refresh did not deliver fresh access", err)
	}
	rotatedRefresh, err := rotated.RefreshToken.Reveal()
	if err != nil || rotatedRefresh == originalRefresh {
		t.Fatal("pairwise refresh did not rotate its credential", err)
	}
	if rotated.IDToken != (oauth.IDToken{}) {
		rotatedWire, err := rotated.IDToken.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		rotatedVerified, err := consumeIDToken(ctx, provider, rotatedWire, "pairwise-original-nonce", "public-web")
		if err != nil || rotatedVerified.Subject != verified.Subject || rotatedVerified.Expiry.After(rotated.ExpiresAt) {
			t.Fatal("refreshed ID token changed original independently verified identity or exceeded native access deadline", err)
		}
	}
	transport.service, transport.oidc = rebuilt, rebuiltChild
	rotatedInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: rotatedAccess, TokenType: "Bearer"}))
	if err != nil || rotatedInfo.Subject != verified.Subject {
		t.Fatal("independent RP UserInfo lost original pairwise subject on refresh after key retirement", err)
	}
	var nativeAccessExpiry, nativeRefreshExpiry, grantAfterRefresh time.Time
	if err := f.pool.Raw().QueryRow(ctx, `SELECT a.expires_at,r.expires_at,g.expires_at FROM oauth_store.artifacts a JOIN oauth_store.artifacts r ON r.parent_artifact_id=a.parent_artifact_id AND r.kind=4 JOIN oauth_store.grants g ON g.grant_id=a.grant_id WHERE a.parent_artifact_id=$1 AND a.kind=3`, originalRefreshID).Scan(&nativeAccessExpiry, &nativeRefreshExpiry, &grantAfterRefresh); err != nil {
		t.Fatal("rotated native deadlines unavailable", err)
	}
	if !nativeRefreshExpiry.Equal(originalRefreshExpiry) || !grantAfterRefresh.Equal(originalGrantExpiry) || !nativeAccessExpiry.Equal(rotated.ExpiresAt) || nativeAccessExpiry.After(originalRefreshExpiry) || nativeAccessExpiry.After(originalGrantExpiry) {
		t.Fatal("pairwise refresh renewed its original native authority ceiling")
	}
	code2, proof2 := oidcCode(t, f, rebuilt, "pairwise-after-migration")
	issued2, err := rebuilt.Token(ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code2, CodeVerifier: proof2, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	wire2, err := issued2.IDToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	verified2, err := consumeIDToken(ctx, provider, wire2, "pairwise-after-migration", "public-web")
	if err != nil || verified2.Subject != verified.Subject {
		t.Fatal("fresh grant after reconstruction/key migration reassigned RP identity", err)
	}
	for _, client := range []struct {
		id, redirect string
		same         bool
	}{
		{"other-public-web", "https://client.example/callback", true},
		{"other-sector-client", "https://other.example/callback", false},
	} {
		code, proof := pairwiseCodeForClient(t, f, rebuilt, client.id, client.redirect, "sector-nonce")
		issued, err := rebuilt.Token(ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.id, Code: code, CodeVerifier: proof, RedirectURI: client.redirect, Network: "192.0.2.1"})
		if err != nil {
			t.Fatal(err)
		}
		wire, err := issued.IDToken.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		other, err := consumeIDToken(ctx, provider, wire, "sector-nonce", client.id)
		if err != nil || (other.Subject == verified.Subject) != client.same {
			t.Fatal("registered sector isolation/client independence failed", err)
		}
	}
}
