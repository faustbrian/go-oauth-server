//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	password "github.com/faustbrian/go-password/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

func issuedConfidentialTokens(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service, client oauth.Client, credential oauth.ClientAuthentication) (string, string) {
	t.Helper()
	code, verifier := confidentialCode(t, f, service, client)
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: code, CodeVerifier: verifier, RedirectURI: client.Redirects[0], ClientAuthentication: credential, Network: "192.0.2.1"})
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real confidential issuance failed", err)
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return access, refresh
}

func TestNativeIntrospectionRequiresSeparateOwningClientAndExplicitSelection(t *testing.T) {
	f := passwordFixture(t)
	client, secretWire, credential := addConfiguredConfidentialClient(t, &f)
	other := client
	other.ID = "other-confidential-web"
	secret, err := password.NewSecret([]byte(secretWire))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oauth.NewClientSecretVerifier(other.ID, other.Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	f.oauth.Protocol.Clients = append(f.oauth.Protocol.Clients, other)
	f.oauth.Protocol.ClientSecrets = append(f.oauth.Protocol.ClientSecrets, verifier)
	disabled, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	f.oauth.Protocol.OwningClientIntrospection = true
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	access, refresh := issuedConfidentialTokens(t, f, service, client, credential)
	r := oauth.IntrospectRequest{ClientID: client.ID, Token: access, ClientAuthentication: credential}
	if _, err := disabled.Introspect(f.ctx, r); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("configured client implicitly enabled introspection", err)
	}
	for _, denied := range []oauth.IntrospectRequest{
		{ClientID: client.ID, Token: access},
		{ClientID: client.ID, Token: access, ClientAuthentication: confidentialBasic(t, client.ID, strings.Repeat("w", 43))},
		{ClientID: client.ID, Token: access, ClientAuthentication: confidentialBasic(t, other.ID, secretWire)},
		{ClientID: "public-web", Token: access},
	} {
		// Dropping only the OAuth namespace is an actual unavailable lookup
		// boundary: invalid credentials must still fail before any SQL access.
		if _, err := f.pool.Raw().Exec(f.ctx, `ALTER SCHEMA oauth_store RENAME TO oauth_hidden`); err != nil {
			t.Fatal(err)
		}
		got, err := service.Introspect(f.ctx, denied)
		if !errors.Is(err, oauth.ErrInvalidClient) || got.Active {
			t.Fatal("invalid client reached lookup", err)
		}
		configured := client
		if denied.ClientID == "public-web" {
			configured = f.oauth.Protocol.Clients[0]
		}
		got, err = store.Introspect(f.ctx, oauth.IntrospectionCommand{Request: denied, Client: configured})
		if !errors.Is(err, oauth.ErrInvalidClient) || got.Active {
			t.Fatal("direct store bypassed client authentication", err)
		}
		if _, err := f.pool.Raw().Exec(f.ctx, `ALTER SCHEMA oauth_hidden RENAME TO oauth_store`); err != nil {
			t.Fatal(err)
		}
	}
	for _, token := range []string{access, refresh, "not-issued", strings.Repeat("A", 43)} {
		r.Token, r.ClientID, r.ClientAuthentication = token, other.ID, confidentialBasic(t, other.ID, secretWire)
		requireInactiveIntrospection(t, service, f.ctx, r)
	}
	r.Token, r.ClientID, r.ClientAuthentication = access, client.ID, credential
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if got, err := service.Introspect(ctx, r); !errors.Is(err, context.Canceled) || got.Active {
		t.Fatal("canceled introspection exposed metadata", err)
	}
	r.Token = strings.Repeat("A", 2049)
	if got, err := store.Introspect(f.ctx, oauth.IntrospectionCommand{Request: r, Client: client}); !errors.Is(err, oauth.ErrInvalidRequest) || got.Active {
		t.Fatal("direct store widened inspected-token bound", err)
	}
	r.Token = access
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER SCHEMA oauth_store RENAME TO oauth_hidden`); err != nil {
		t.Fatal(err)
	}
	if got, err := service.Introspect(f.ctx, r); !errors.Is(err, oauth.ErrUnavailable) || got.Active || got.Subject != "" {
		t.Fatal("unavailable primary reused positive result", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER SCHEMA oauth_hidden RENAME TO oauth_store`); err != nil {
		t.Fatal(err)
	}
	if got, err := service.Introspect(f.ctx, r); err != nil || !got.Active {
		t.Fatal("read outage changed live token", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER SCHEMA identity RENAME TO identity_hidden`); err != nil {
		t.Fatal(err)
	}
	if got, err := service.Introspect(f.ctx, r); !errors.Is(err, oauth.ErrUnavailable) || got.Active || got.Subject != "" {
		t.Fatal("authority outage reused warm positive observation", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER SCHEMA identity_hidden RENAME TO identity`); err != nil {
		t.Fatal(err)
	}
}

func TestNativeIntrospectionWithdrawsCredentialAndExpiryAuthority(t *testing.T) {
	f := passwordFixtureWithChange(t, true)
	client, _, credential := addConfiguredConfidentialClient(t, &f)
	f.oauth.Protocol.OwningClientIntrospection = true
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	access, refresh := issuedConfidentialTokens(t, f, service, client, credential)
	r := oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: credential, Token: access}
	if got, err := service.Introspect(f.ctx, r); err != nil || !got.Active {
		t.Fatal("pre-withdrawal access inactive", err)
	}
	// OAuth owns these expiry rows; no source-owner SQL or synthetic authority.
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.artifacts SET expires_at=created_at+interval '1 microsecond' WHERE kind=3`); err != nil {
		t.Fatal(err)
	}
	requireInactiveIntrospection(t, service, f.ctx, r)
	r.Token = refresh
	if got, err := service.Introspect(f.ctx, r); err != nil || !got.Active {
		t.Fatal("access expiry withdrew independent refresh", err)
	}
	f.changePassword()
	requireInactiveIntrospection(t, service, f.ctx, r)
	// Repeating an inactive read cannot restore the original credential epoch.
	requireInactiveIntrospection(t, service, f.ctx, r)
}

func TestNativeIntrospectionGrantAndIssuerResourceFences(t *testing.T) {
	for _, changed := range []string{"issuer", "environment", "resource", "grant-expiry", "refresh-revocation"} {
		t.Run(changed, func(t *testing.T) {
			f := passwordFixture(t)
			client, _, credential := addConfiguredConfidentialClient(t, &f)
			f.oauth.Protocol.OwningClientIntrospection = true
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			access, refresh := issuedConfidentialTokens(t, f, service, client, credential)
			switch changed {
			case "issuer":
				f.oauth.Protocol.Issuer, _ = oauth.NewIssuer("https://different-issuer.example")
			case "environment":
				f.oauth.Protocol.Environment = "different-environment"
			case "resource":
				f.oauth.Protocol.Resource = "https://different-resource.example"
				for i := range f.oauth.Protocol.Clients {
					f.oauth.Protocol.Clients[i].Resource = f.oauth.Protocol.Resource
				}
			case "grant-expiry":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.grants SET expires_at=created_at+interval '1 microsecond'`); err != nil {
					t.Fatal(err)
				}
			case "refresh-revocation":
				if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: client.ID, ClientAuthentication: credential, Token: refresh, Network: "192.0.2.1"}); err != nil {
					t.Fatal(err)
				}
			}
			current, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{access, refresh} {
				requireInactiveIntrospection(t, current, f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: credential, Token: token})
			}
		})
	}
}

func TestNativeIntrospectionRejectsEachRetainedOriginalRootMismatch(t *testing.T) {
	f := passwordFixture(t)
	client, _, credential := addConfiguredConfidentialClient(t, &f)
	f.oauth.Protocol.OwningClientIntrospection = true
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	access, _ := issuedConfidentialTokens(t, f, service, client, credential)
	r := oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: credential, Token: access}
	var grant string
	var tenant identity.TenantID
	var user identity.UserID
	var raw []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT grant_id,tenant_id,user_id,source_session FROM oauth_store.grants WHERE state='active'`).Scan(&grant, &tenant, &user, &raw); err != nil {
		t.Fatal(err)
	}
	var fields []identity.FeatureField
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal("retained original fields malformed")
	}
	original, err := sessionpg.OriginalSessionFromFields(tenant, user, fields)
	if err != nil {
		t.Fatal(err)
	}
	for _, dimension := range []string{"global", "tenant", "user", "identifier", "credential", "authorization", "credential-id", "scope", "missing"} {
		t.Run(dimension, func(t *testing.T) {
			spec, err := original.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			vector, err := spec.Authority.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			switch dimension {
			case "global":
				vector.Global.Version++
			case "tenant":
				vector.Tenant.Version++
			case "user":
				vector.User.Version++
			case "identifier":
				vector.Identifier.Version++
			case "credential":
				vector.Credential.Version++
			case "authorization":
				vector.Authorization.Version++
			case "credential-id":
				spec.Authentication.CredentialID = "foreign-credential"
			case "scope":
				vector.Global.ScopeKey = "foreign-authority-scope"
			}
			spec.Authority, err = session.NewAuthoritySnapshot(vector)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := session.NewSession(spec)
			if err != nil {
				t.Fatal(err)
			}
			retained, err := sessionpg.OriginalSessionFields(changed)
			if err != nil {
				t.Fatal(err)
			}
			if dimension == "missing" {
				retained = retained[1:]
			}
			wire, err := json.Marshal(retained)
			if err != nil {
				t.Fatal(err)
			}
			// Fault only OAuth's retained source, never identity/session SQL. The
			// real unchanged primary facts must not be rebased onto altered roots.
			if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.grants SET source_session=$1::jsonb WHERE grant_id=$2`, string(wire), grant); err != nil {
				t.Fatal(err)
			}
			requireInactiveIntrospection(t, service, f.ctx, r)
			if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.grants SET source_session=$1::jsonb WHERE grant_id=$2`, string(raw), grant); err != nil {
				t.Fatal(err)
			}
			if got, err := service.Introspect(f.ctx, r); err != nil || !got.Active {
				t.Fatal("unchanged original primary root was stranded", err)
			}
		})
	}
}

func TestNativeIntrospectionUserBlockDeniesBeforeCascadeWorkers(t *testing.T) {
	f := passwordFixture(t)
	client, _, credential := addConfiguredConfidentialClient(t, &f)
	f.oauth.Protocol.OwningClientIntrospection = true
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	access, refresh := issuedConfidentialTokens(t, f, service, client, credential)
	r := oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: credential, Token: access}
	active, err := service.Introspect(f.ctx, r)
	if err != nil || !active.Active {
		t.Fatal("original token unavailable", err)
	}
	domain, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	status, err := domain.GetStatus(f.ctx, identity.UserStatusQuery{TenantID: f.tenant, UserID: identity.UserID(active.Subject)})
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
	coordinator, err := kernel.NewCoordinator(f.pool, registry, f.oauth.Coordinator)
	if err != nil {
		t.Fatal(err)
	}
	contracts := make(map[string]kernel.StatusConsumerContract)
	for _, id := range (identity.UserStatusCommand{Binding: identity.CommandBinding{OperationID: "identity.user.suspend"}}).RequiredConsumers() {
		contracts[id] = kernel.StatusConsumerContract{Version: 1, Fingerprint: [32]byte{1}}
	}
	owner, err := kernel.NewStatusUnitOfWork(coordinator, domain, kernel.StatusUnitOfWorkConfig{RetentionPolicyVersion: 1, PolicyVersion: 9, Reasons: []string{"security"}, MaximumCascadeDuration: time.Hour, ConsumerContracts: contracts, Policy: identity.StatusPolicy{MaximumSuspension: time.Hour, BanRequiresReason: true, AllowedTransitions: []identity.StatusTransition{{From: identity.StatusActive, To: identity.StatusSuspended}}}})
	if err != nil {
		t.Fatal(err)
	}
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewUserStatusCommand(identity.UserStatusCommand{Binding: identity.CommandBinding{CommandID: commandID, TenantID: f.tenant, UserID: status.User.ID, ActorID: identity.ActorID(status.User.ID), ActorKind: authorization.SubjectUser, OperationID: "identity.user.suspend", SchemaID: "identity-lifecycle", SchemaVersion: 1, PolicyID: "oauth-consumer-block-test", PolicyVersion: 9, CorrelationID: string(commandID)}, ExpectedVersion: status.User.Version, ExpectedAuthorityVersion: status.AuthorityVersion, StatusPolicyVersion: 9, TargetStatus: identity.StatusSuspended, Reason: "security"})
	if err != nil {
		t.Fatal(err)
	}
	// Trusted fixture administration enters the actual public status owner,
	// never direct identity SQL. Cascade workers intentionally do not run: the
	// primary status/epoch itself must already deny the issued OAuth authority.
	blocked, err := owner.Execute(f.ctx, command)
	if err != nil || blocked.Outcome != identity.CommitOutcomeCommitted || blocked.Revocation == nil || blocked.Revocation.Status != identity.RevocationPending {
		t.Fatal("real status owner did not suspend subject", err)
	}
	for _, token := range []string{access, refresh} {
		r.Token = token
		requireInactiveIntrospection(t, service, f.ctx, r)
	}
}

func requireInactiveIntrospection(t *testing.T, service *oauth.Service, ctx context.Context, request oauth.IntrospectRequest) {
	t.Helper()
	got, err := service.Introspect(ctx, request)
	if err != nil || got.Active || got.Subject != "" || got.ClientID != "" || got.Resource != "" || got.Issuer.String() != "" || got.Scopes != nil || !got.ExpiresAt.IsZero() {
		t.Fatal("inactive native introspection failed or disclosed metadata", err)
	}
}

func TestNativeOwningClientIntrospectionCompleteConsumer(t *testing.T) {
	f := passwordFixture(t)
	client, _, credential := addConfiguredConfidentialClient(t, &f)
	f.oauth.Protocol.OwningClientIntrospection = true
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	access, refresh := issuedConfidentialTokens(t, f, service, client, credential)
	r := oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: credential}
	readState := func() [5]int64 {
		var values [5]int64
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.artifacts),(SELECT count(*) FROM oauth_store.effects),(SELECT sum(version)::bigint FROM oauth_store.grants),(SELECT count(*) FROM audit.records),(SELECT count(*) FROM public.outbox_messages)`).Scan(&values[0], &values[1], &values[2], &values[3], &values[4]); err != nil {
			t.Fatal(err)
		}
		return values
	}
	before := readState()
	for _, token := range []string{access, refresh} {
		r.Token, r.Hint = token, oauth.TokenAccess // Wrong hint must still find refresh.
		got, err := service.Introspect(f.ctx, r)
		if err != nil || !got.Active || got.ClientID != client.ID || got.Subject == "" || got.Resource != client.Resource || got.Issuer.String() != f.oauth.Protocol.Issuer.String() || len(got.Scopes) != 1 || got.Scopes[0] != "identity:read" || got.ExpiresAt.IsZero() {
			t.Fatal("genuine issued token was not introspected", err)
		}
	}
	if after := readState(); after != before {
		t.Fatal("introspection consumed or mutated grant/audit/lifecycle state")
	}
	if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: client.ID, ClientAuthentication: credential, Token: access, Network: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	r.Token = access
	requireInactiveIntrospection(t, service, f.ctx, r)
	r.Token = refresh
	if got, err := service.Introspect(f.ctx, r); err != nil || !got.Active {
		t.Fatal("access-only revocation withdrew refresh", err)
	}
	rotated, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: refresh, ClientAuthentication: credential, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("refresh rotation failed", err)
	}
	child, err := rotated.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	requireInactiveIntrospection(t, service, f.ctx, r)
	r.Token = child
	if got, err := service.Introspect(f.ctx, r); err != nil || !got.Active {
		t.Fatal("rotation successor was not active", err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: refresh, ClientAuthentication: credential, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("consumed refresh reuse accepted")
	}
	requireInactiveIntrospection(t, service, f.ctx, r)
	// A different genuinely consented family is not collateral replay damage.
	other, _ := issuedConfidentialTokens(t, f, service, client, credential)
	r.Token = other
	if got, err := service.Introspect(f.ctx, r); err != nil || !got.Active {
		t.Fatal("unrelated family was revoked", err)
	}
	f.signOut()
	if got, err := service.Introspect(f.ctx, r); err != nil || !got.Active {
		t.Fatal("browser logout replaced independent approved grant authority", err)
	}
}
