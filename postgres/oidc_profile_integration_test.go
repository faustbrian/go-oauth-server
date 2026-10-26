//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	rp "github.com/coreos/go-oidc/v3/oidc"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"golang.org/x/oauth2"
)

func nativeProfileSchema() identity.AttributeSchema {
	return identity.AttributeSchema{ID: "oidc-profile-fields", Version: 1, Fields: []identity.FieldPolicy{{Name: "display_tag", Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar, Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteSystem, Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1, Default: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "private-custom-value"}}}}}
}

func profilePasswordFixture(t *testing.T, change bool) authenticatedPasswordFixture {
	t.Helper()
	schema := nativeProfileSchema()
	return passwordFixtureWithProfileSchema(t, change, &schema)
}

func profileFixture(t *testing.T, f *authenticatedPasswordFixture) (*oauth.Service, *op.Service, *oauth.SigningService, *oauthpostgres.Store, *ecdsa.PrivateKey) {
	t.Helper()
	_, _, signer, _, key := oidcFixture(t, f)
	f.oauth.Protocol.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "profile"})
	for i := range f.oauth.Protocol.Clients {
		f.oauth.Protocol.Clients[i].Scopes = append(f.oauth.Protocol.Clients[i].Scopes, "profile")
	}
	schema := nativeProfileSchema()
	f.oauth.ProfileUserInfo = &oauthpostgres.ProfileUserInfoConfig{AttributeSchemas: []identity.AttributeSchema{schema}, ProfileSchema: kernel.ProfileSchemaRef{ID: schema.ID, Version: schema.Version}}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	core, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	issuer := f.oauth.Protocol.Issuer.String()
	child, err := op.NewService(op.Config{Issuer: f.oauth.Protocol.Issuer, JWKSURI: issuer + "/oauth2/jwks", UserInfoEndpoint: issuer + "/oauth2/userinfo", Signing: signer, SubjectKey: [32]byte{42}, Clock: clock.System{}, MaximumDuration: 4 * time.Second, ProfileUserInfo: true}, core)
	if err != nil {
		t.Fatal(err)
	}
	service, err := core.WithOIDC(child)
	if err != nil {
		t.Fatal(err)
	}
	return service, child, signer, store, key
}

// This is a bounded application policy for an already authenticated actual
// native subject. It does not stand in for a session, domain store or authority.
type profileConsumerPolicy struct {
	tenant identity.TenantID
	user   identity.UserID
}

func (p profileConsumerPolicy) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	outcome := authorization.Deny
	if r.Tenant == authorization.TenantID(p.tenant) && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == authorization.SubjectID(p.user) && r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(p.user) && (r.Action == "identity.profile.get" || r.Action == "identity.profile.update") {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome, Revision: 9}, nil
}

func mutateNativeProfile(t *testing.T, f authenticatedPasswordFixture, name string) identity.UserProfile {
	t.Helper()
	token, err := session.ParseToken(f.browser.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil {
		t.Fatal("actual profile mutation session unavailable", err)
	}
	bindings, err := observed.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	schema := nativeProfileSchema()
	domain, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{schema}, ProfileSchema: kernel.ProfileSchemaRef{ID: schema.ID, Version: 1}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := domain.GetProfile(f.ctx, identity.ProfileQuery{TenantID: f.tenant, UserID: bindings.UserID})
	if err != nil {
		t.Fatal("immutable native profile schema not ready", err)
	}
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "oidc-profile-consumer", Revision: 9, Evaluator: profileConsumerPolicy{tenant: f.tenant, user: bindings.UserID}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	authorize, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, lifecycle})
	if err != nil {
		t.Fatal(err)
	}
	configuration := f.oauth.Coordinator
	query := kernel.CommandQueryPolicy{Clock: clock.System{}, Authorization: authorize, PolicyVersion: 9}
	configuration.QueryPolicy, configuration.AdmissionPolicy = &query, &query
	coordinator, err := kernel.NewCoordinator(f.pool, registry, configuration)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := kernel.NewProfileUnitOfWork(coordinator, domain, kernel.CreationUnitOfWorkConfig{RetentionPolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewProfileService(domain, owner, authorize, func(ctx context.Context, in identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		return identity.RedactionPolicyDecision{PolicyID: "oidc-profile-consumer", PolicyVersion: 9, Reason: "visible", VisibleFields: in.Fields}, ctx.Err()
	}, identity.ProfileConfig{AllowedImageOrigins: []string{"https://images.example.test"}, Fields: identity.UserCreationConfig{Query: identity.UserQueryConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyID: "oidc-profile-consumer", PolicyVersion: 9, RedactionReasons: []identity.PolicyReason{"visible"}, ValidateCanonicalUserID: func(ctx context.Context, id identity.UserID) error {
		_, err := identity.ParseSubjectID(string(id))
		return err
	}}, Schema: schema, Normalize: func(ctx context.Context, _ identity.NormalizationPolicy, value identity.AttributeScalar) (identity.AttributeScalar, error) {
		return value, ctx.Err()
	}, ValidateValue: func(ctx context.Context, _ identity.FieldPolicy, _ identity.AttributeValue) error { return ctx.Err() }}})
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	dc := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: authorization.TenantID(f.tenant), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(bindings.UserID)}, Action: "identity.profile.update", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(bindings.UserID)}}}
	updated, err := service.ProfileUpdate(f.ctx, identity.ProfileUpdateRequest{TenantID: f.tenant, Context: dc, CommandID: command, SchemaVersion: 1, ExpectedVersion: current.Profile.Version, Name: name, Image: "https://images.example.test/private-avatar.png", CorrelationID: string(command)})
	if err != nil || updated.CommitOutcome != identity.CommitOutcomeCommitted || updated.User.Name != name || updated.User.Image == "" || len(updated.User.AdditionalFields) != 1 {
		t.Fatal("actual native profile mutation did not commit", err)
	}
	dc.Request.Action = "identity.profile.get"
	read, err := service.ProfileGet(f.ctx, identity.ProfileGetRequest{TenantID: f.tenant, Context: dc})
	if err != nil || read.User.Name != name || read.Version != updated.User.Version {
		t.Fatal("native current profile read differs from commitment", err)
	}
	return read.User
}

func TestNativeOIDCProfileIndependentRelyingPartyAndCurrentMutation(t *testing.T) {
	f := profilePasswordFixture(t, false)
	service, child, _, _, _ := profileFixture(t, &f)
	discovery, err := child.Discovery(f.ctx)
	if err != nil || !slices.Contains(discovery.ScopesSupported, "profile") || !slices.Contains(discovery.ClaimsSupported, "name") {
		t.Fatal("selected profile name absent from discovery", err)
	}
	for _, field := range []string{"given_name", "family_name", "nickname", "picture", "image", "display_tag", "email"} {
		if slices.Contains(discovery.ClaimsSupported, field) {
			t.Fatal("name selection advertised another profile field", field)
		}
	}
	transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery, oidc: child}
	ctx := rp.ClientContext(f.ctx, &http.Client{Transport: transport, Timeout: 5 * time.Second})
	provider, err := rp.NewProvider(ctx, f.oauth.Protocol.Issuer.String())
	if err != nil {
		t.Fatal(err)
	}
	standard := oauth2.Config{ClientID: "public-web", RedirectURL: "https://client.example/callback", Scopes: []string{"openid", "profile"}, Endpoint: provider.Endpoint()}
	standard.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	code, verifier := oidcCode(t, f, service, "profile-rp-nonce")
	token, err := standard.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal("independent profile code/S256 exchange failed", err)
	}
	wire, ok := token.Extra("id_token").(string)
	if !ok {
		t.Fatal("ID token missing")
	}
	verified, err := consumeIDToken(ctx, provider, wire, "profile-rp-nonce", "public-web")
	if err != nil {
		t.Fatal(err)
	}
	var idClaims map[string]json.RawMessage
	if verified.Claims(&idClaims) != nil || idClaims["name"] != nil || idClaims["image"] != nil || idClaims["display_tag"] != nil || idClaims["email"] != nil {
		t.Fatal("profile expanded minimized ID token")
	}
	for _, name := range []string{"", "First native name", "Changed native name"} {
		if name != "" {
			mutateNativeProfile(t, f, name)
		}
		info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		var claims map[string]json.RawMessage
		if err != nil || info.Subject != verified.Subject || info.Claims(&claims) != nil {
			t.Fatal("RP profile subject validation failed", err)
		}
		var actual string
		if claims["name"] != nil && json.Unmarshal(claims["name"], &actual) != nil {
			t.Fatal("invalid name claim")
		}
		wantFields := 1
		if name != "" {
			wantFields++
		}
		if actual != name || len(claims) != wantFields {
			t.Fatal("current native name omitted/changed or unrelated fields leaked")
		}
	}
	openid := f
	openid.oauth.Protocol.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
	code, verifier = oidcCode(t, openid, service, "no-profile-consent")
	minimal, err := standard.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal(err)
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(minimal))
	var claims map[string]json.RawMessage
	if err != nil || info.Subject != verified.Subject || info.Claims(&claims) != nil || len(claims) != 1 {
		t.Fatal("unconsented profile leaked name", err)
	}
}
