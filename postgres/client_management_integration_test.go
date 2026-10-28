//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

// This is the selected application's exact platform-management policy. The
// manager is obtained from real signup/verification/signin and native session
// custody; constructor owner metadata alone cannot satisfy this decision.
type clientManagerPolicy struct {
	authorization.Service
	manager authorization.SubjectID
	denied  *atomic.Bool
	inspect func(context.Context) error
}

func (p clientManagerPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	r := c.Request
	if strings.HasPrefix(string(r.Action), "identity.oauth-server.client-") {
		if r.Resource.Type == "oauth.platform" && p.inspect != nil {
			if err := p.inspect(ctx); err != nil {
				return authorization.Decision{}, err
			}
		}
		if err := ctx.Err(); err != nil {
			return authorization.Decision{}, err
		}
		allow := !p.denied.Load() && r.Tenant == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == p.manager && (r.Resource.Type == "oauth.platform" && r.Resource.ID == "deployment" || r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(p.manager) || r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action))
		if allow {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
		return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
	}
	return p.Service.Decide(ctx, c)
}

func TestNativeManagedClientPolicyRunsOutsideProtectedLocksAndEpochFencesLateWithdrawal(t *testing.T) {
	for _, withdraw := range []bool{false, true} {
		t.Run(map[bool]string{false: "positive-unlocked", true: "late-epoch-withdrawal"}[withdraw], func(t *testing.T) {
			f := passwordFixture(t)
			enableClientManagement(t, &f)
			policy := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
			var locked atomic.Bool
			policy.inspect = func(ctx context.Context) error {
				var held bool
				err := f.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_class r ON r.oid=l.relation JOIN pg_namespace n ON n.oid=r.relnamespace JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND l.granted AND l.mode IN('RowShareLock','RowExclusiveLock') AND n.nspname IN('identity','session_store'))`).Scan(&held)
				if held {
					locked.Store(true)
				}
				return err
			}
			barrier := &consentRaceBarrier{owner: policy, action: "identity.oauth-server.client-create", ready: make(chan struct{}), release: make(chan struct{})}
			query := *f.oauth.Coordinator.QueryPolicy
			admission := *f.oauth.Coordinator.AdmissionPolicy
			query.Authorization = barrier
			admission.Authorization = barrier
			f.oauth.Coordinator.QueryPolicy = &query
			f.oauth.Coordinator.AdmissionPolicy = &admission
			f.oauth.RequestKeys.Policy.Authorization = barrier
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			r := clientCreateRequest(t, f, "manager-lock-epoch")
			if !withdraw {
				if _, err := service.ClientCreate(f.ctx, r); err != nil {
					t.Fatal("live management positive control", err)
				}
			} else {
				ctx, cancel := context.WithCancel(context.WithValue(f.ctx, consentRaceKey{}, true))
				defer cancel()
				done := make(chan error, 1)
				go func() { _, err := service.ClientCreate(ctx, r); done <- err }()
				joined := false
				defer func() {
					cancel()
					select {
					case <-barrier.release:
					default:
						close(barrier.release)
					}
					if !joined {
						<-done
					}
				}()
				select {
				case <-barrier.ready:
				case err := <-done:
					joined = true
					t.Fatal("management did not reach original decision gate", err)
				case <-f.ctx.Done():
					t.Fatal("bounded management gate canceled")
				}
				owner, err := authority.NewAuthorityStore(f.pool.Raw(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				scope := authority.AuthorityScope{TenantID: authorization.TenantID(f.tenant), PolicyNamespace: f.oauth.Session.Profile.PolicyNamespace, SubjectID: policy.manager}
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
				close(barrier.release)
				err = <-done
				joined = true
				if err == nil {
					t.Fatal("late owning authorization epoch withdrawal admitted client")
				}
				var rows int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.managed_clients`).Scan(&rows); err != nil || rows != 0 {
					t.Fatal("late denied manager changed client state", err)
				}
			}
			if locked.Load() {
				t.Fatal("caller platform policy ran while protected SQL locks were retained")
			}
		})
	}
}

func enableClientManagement(t *testing.T, f *authenticatedPasswordFixture) *atomic.Bool {
	t.Helper()
	enableConsentManagement(t, f)
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
	source := oauthpostgres.ClientMigrationSource{Base: oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}, Schema: "oauth_store", Version: 7003}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(f.ctx); err != nil {
		t.Fatal("managed client forward install", err)
	}
	token, _ := session.ParseToken(f.browser.Token())
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	observed, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil {
		t.Fatal(err)
	}
	b, err := observed.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	denied := &atomic.Bool{}
	policy := clientManagerPolicy{Service: f.oauth.Coordinator.AdmissionPolicy.Authorization, manager: authorization.SubjectID(b.UserID), denied: denied}
	query := *f.oauth.Coordinator.QueryPolicy
	admission := *f.oauth.Coordinator.AdmissionPolicy
	query.Authorization = policy
	admission.Authorization = policy
	f.oauth.Coordinator.QueryPolicy = &query
	f.oauth.Coordinator.AdmissionPolicy = &admission
	f.oauth.RequestKeys.Policy.Authorization = policy
	f.oauth.Protocol.ManagedClients = &oauth.ManagedClientPolicy{Owner: f.oauth.Protocol.Clients[0].Owner, TenantID: f.tenant, Redirects: []string{"https://managed.example/callback"}, Scopes: f.oauth.Protocol.Scopes}
	f.oauth.Protocol.OwningClientIntrospection = true
	return denied
}
func clientCreateRequest(t *testing.T, f authenticatedPasswordFixture, label string) oauth.ClientManagementRequest {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte(label))
	if err != nil {
		t.Fatal(err)
	}
	return oauth.ClientManagementRequest{Owner: f.oauth.Protocol.ManagedClients.Owner, TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", RequestKey: key, Redirects: []string{"https://managed.example/callback"}, Scopes: []string{"identity:read", "identity:write"}}
}

func TestNativeCurrentClientMutationCannotChangeStaticAuthority(t *testing.T) {
	f := passwordFixture(t)
	enableClientManagement(t, &f)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	client, err := store.CurrentClient(f.ctx, "public-web")
	if err != nil {
		t.Fatal(err)
	}
	client.Redirects[0] = "https://foreign.example/callback"
	client.Scopes[0] = "identity:forged"
	token, _ := session.ParseToken(f.browser.Token())
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	observed, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := oauth.S256Challenge(strings.Repeat("a", 43))
	command := oauth.AuthorizationCommand{Client: client, Browser: f.browser, Session: observed, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: client.ID, RedirectURI: client.Redirects[0], Resource: client.Resource, Scopes: []string{"identity:forged"}, CodeChallenge: challenge}}
	if _, err := store.Authorize(f.ctx, command); err == nil {
		t.Fatal("caller-mutated getter persisted foreign static registration authority")
	}
	var rows int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.grants`).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("rejected getter mutation changed durable authority", err)
	}
	command.Client = f.oauth.Protocol.Clients[0]
	command.Request.RedirectURI = command.Client.Redirects[0]
	command.Request.Scopes = []string{"identity:read"}
	if out, err := store.Authorize(f.ctx, command); err != nil || out.Outcome != oauth.ConsentRequired {
		t.Fatal("original static authority positive control changed", err)
	}
}

func TestNativeManagedClientDiscoveryAndLifecycleFollowBindingContract(t *testing.T) {
	// These topic names come from LIFECYCLE_CASCADES.md lifecycle.events.oauth_server,
	// not the participant implementation or its recovery allowlist.
	for _, introspection := range []bool{false, true} {
		t.Run(map[bool]string{false: "basic-public-static", true: "introspection-public-static"}[introspection], func(t *testing.T) {
			f := passwordFixture(t)
			enableClientManagement(t, &f)
			f.oauth.Protocol.OwningClientIntrospection = introspection
			origin := f.oauth.Protocol.Issuer.String()
			f.oauth.Protocol.Discovery = oauth.DiscoveryConfig{Enabled: true, AuthorizationEndpoint: origin + "/oauth2/authorize", TokenEndpoint: origin + "/oauth2/token", RevocationEndpoint: origin + "/oauth2/revoke"}
			if introspection {
				f.oauth.Protocol.Discovery.IntrospectionEndpoint = origin + "/oauth2/introspect"
			}
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal("coherent managed Basic discovery rejected", err)
			}
			metadata, err := service.DiscoveryOauth(f.ctx, oauth.DiscoveryOauthRequest{})
			if err != nil || !slices.Equal(metadata.Metadata.TokenEndpointAuthMethodsSupported, []string{"client_secret_basic", "none"}) || !slices.Equal(metadata.Metadata.RevocationEndpointAuthMethodsSupported, []string{"client_secret_basic", "none"}) {
				t.Fatal("running registry Basic capability not discoverable", err)
			}
			r := clientCreateRequest(t, f, "discovery-client-create")
			created, err := service.ClientCreate(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			secret, _ := created.Secret.Reveal()
			basic := confidentialBasic(t, created.Client.ID, secret)
			access, _ := issuedConfidentialTokens(t, f, service, created.Client, basic)
			if introspection {
				if out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: created.Client.ID, ClientAuthentication: basic, Token: access}); err != nil || !out.Active {
					t.Fatal("advertised managed owning-client introspection is not usable", err)
				}
			}
			remove := r
			remove.ClientID = created.Client.ID
			remove.Version = 1
			remove.Redirects = nil
			remove.Scopes = nil
			remove.RequestKey, _ = identity.NewIdempotencyKey([]byte("discovery-client-delete"))
			if _, err := service.ClientDelete(f.ctx, remove); err != nil {
				t.Fatal(err)
			}
			var creates, revokes, unexpected int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE topic='oauth_client.created.v1'),count(*) FILTER(WHERE topic='oauth_client.revoked.v1'),count(*) FILTER(WHERE topic IN('client.created.v1','client.deleted.v1')) FROM public.outbox_messages`).Scan(&creates, &revokes, &unexpected); err != nil || creates != 1 || revokes != 1 || unexpected != 0 {
				t.Fatal("actual outbox violates binding OAuth client lifecycle topics", err)
			}
		})
	}
}

func TestNativeManagedHumanDiscoveryComposesWithExistingStaticWorkload(t *testing.T) {
	f := passwordFixture(t)
	enableClientManagement(t, &f)
	// Existing configured workload support needs its own installed forward
	// history even though the managed registration remains strictly human web.
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
	base := oauthpostgres.ClientMigrationSource{Base: oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}, Schema: "oauth_store", Version: 7003}
	runner, err := migrations.NewRunner(oauthpostgres.WorkloadMigrationSource{Base: base, Schema: "oauth_store", Version: 7004}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal(err)
	}
	client, _, _ := addConfiguredConfidentialClient(t, &f)
	client.Workload, err = oauth.NewWorkload(f.tenant, "configured-worker", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.Redirects = nil
	f.oauth.Protocol.Clients = []oauth.Client{client}
	f.oauth.WorkloadAuthority = oauthpostgres.WorkloadAuthorityConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "oauth-workloads"}
	origin := f.oauth.Protocol.Issuer.String()
	f.oauth.Protocol.Discovery = oauth.DiscoveryConfig{Enabled: true, AuthorizationEndpoint: origin + "/oauth2/authorize", TokenEndpoint: origin + "/oauth2/token", RevocationEndpoint: origin + "/oauth2/revoke", IntrospectionEndpoint: origin + "/oauth2/introspect"}
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal("managed human service lost genuine session composition", err)
	}
	metadata, err := service.DiscoveryOauth(f.ctx, oauth.DiscoveryOauthRequest{})
	if err != nil || !slices.Equal(metadata.Metadata.GrantTypesSupported, []string{"authorization_code", "client_credentials", "refresh_token"}) || !slices.Equal(metadata.Metadata.TokenEndpointAuthMethodsSupported, []string{"client_secret_basic"}) {
		t.Fatal("native mixed composition metadata inconsistent", err)
	}
	created, err := service.ClientCreate(f.ctx, clientCreateRequest(t, f, "human-with-static-machine"))
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := created.Secret.Reveal()
	access, _ := issuedConfidentialTokens(t, f, service, created.Client, confidentialBasic(t, created.Client.ID, secret))
	if access == "" {
		t.Fatal("advertised managed human web capability not usable")
	}
}

func TestNativeManagedClientWarmServicesCreateUseDelete(t *testing.T) {
	f := passwordFixture(t)
	denied := enableClientManagement(t, &f)
	first, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal("first warm constructor", err)
	}
	second, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	r := clientCreateRequest(t, f, "original-client-create")
	denied.Store(true)
	if _, err := first.ClientCreate(f.ctx, r); err == nil {
		t.Fatal("owner metadata bypassed exact manager policy")
	}
	denied.Store(false)
	created, err := first.ClientCreate(f.ctx, r)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted || created.Client.Version != 1 || !strings.HasPrefix(created.Client.ID, oauth.ManagedClientPrefix) {
		t.Fatal("genuine manager create", err)
	}
	secret, err := created.Secret.Reveal()
	if err != nil {
		t.Fatal("known committed secret unavailable", err)
	}
	basic := confidentialBasic(t, created.Client.ID, secret)
	retry, err := second.ClientCreate(f.ctx, r)
	if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != created.Completion.CommandID {
		t.Fatal("original retry metadata", err)
	}
	if _, err := retry.Secret.Reveal(); err == nil {
		t.Fatal("retry redelivered secret")
	}
	changed := r
	changed.Scopes = []string{"identity:read"}
	if _, err := second.ClientCreate(f.ctx, changed); !errors.Is(err, oauth.ErrClientConflict) {
		t.Fatal("changed original intent did not conflict", err)
	}
	access, refresh := issuedConfidentialTokens(t, f, second, created.Client, basic)
	verifier, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, resourcePolicy(f, created.Client))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := verifier.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"}); err != nil || p.RequireScope("identity:read") != nil {
		t.Fatal("managed access did not authorize selected resource", err)
	}
	code, proof := confidentialCode(t, f, first, created.Client)
	key, _ := identity.NewIdempotencyKey([]byte("original-client-delete"))
	remove := r
	remove.RequestKey = key
	remove.ClientID = created.Client.ID
	remove.Version = 1
	remove.Redirects = nil
	remove.Scopes = nil
	deleted, err := second.ClientDelete(f.ctx, remove)
	if err != nil || deleted.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("terminal management delete", err)
	}
	for _, service := range []*oauth.Service{first, second} {
		for _, request := range []oauth.TokenRequest{{GrantType: oauth.AuthorizationCodeGrant, ClientID: created.Client.ID, ClientAuthentication: basic, Code: code, CodeVerifier: proof, RedirectURI: created.Client.Redirects[0], Network: "192.0.2.1"}, {GrantType: oauth.RefreshTokenGrant, ClientID: created.Client.ID, ClientAuthentication: basic, RefreshToken: refresh, Network: "192.0.2.1"}} {
			if _, err := service.Token(f.ctx, request); err == nil {
				t.Fatal("warm service accepted deleted descendant")
			}
		}
		if _, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: created.Client.ID, ClientAuthentication: basic, Token: access}); err == nil {
			t.Fatal("deleted client introspection accepted")
		}
	}
	requireInvalidResource(t, verifier, f.ctx, access)
	var version, state string
	var rows int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,state FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&version, &state); err != nil || version != "2" || state != "deleted" {
		t.Fatal("durable tombstone mismatch", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects WHERE client_id=$1`, created.Client.ID).Scan(&rows); err != nil || rows != 2 {
		t.Fatal("client effects were duplicated", err)
	}
}

func TestNativeManagedClientExactManagerCSRFAndImmutablePolicyDenials(t *testing.T) {
	f := passwordFixture(t)
	denied := enableClientManagement(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	r := clientCreateRequest(t, f, "deny-client-create")
	other, otherCSRF := f.anotherUser()
	for _, mode := range []string{"owner", "tenant", "user", "csrf", "origin", "redirect", "scope", "public", "policy"} {
		bad := r
		switch mode {
		case "owner":
			bad.Owner, _ = oauth.NewPlatformOwner("other")
		case "tenant":
			bad.TenantID = "foreign"
		case "user":
			bad.Session, bad.CSRF = other, otherCSRF
		case "csrf":
			bad.CSRF, _ = session.NewCSRFToken()
		case "origin":
			bad.Origin = "https://foreign.example"
		case "redirect":
			bad.Redirects = []string{"https://foreign.example/cb"}
		case "scope":
			bad.Scopes = []string{"administration"}
		case "public":
			bad.Public = true
		case "policy":
			denied.Store(true)
		}
		if out, err := service.ClientCreate(f.ctx, bad); err == nil || out.Client.ID != "" {
			t.Fatal("invalid management admitted", mode)
		}
		denied.Store(false)
	}
	var rows int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.managed_clients`).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("denial created client authority", err)
	}
	created, err := service.ClientCreate(f.ctx, r)
	if err != nil {
		t.Fatal("positive control", err)
	}
	remove := r
	remove.ClientID = created.Client.ID
	remove.Version = 2
	remove.Redirects = nil
	remove.Scopes = nil
	remove.RequestKey, _ = identity.NewIdempotencyKey([]byte("wrong-client-version"))
	if _, err := service.ClientDelete(f.ctx, remove); err == nil {
		t.Fatal("stale version admitted")
	}
	var state string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&state); err != nil || state != "active" {
		t.Fatal("stale delete changed client", err)
	}
	static := f.oauth
	static.Protocol.Clients = append([]oauth.Client(nil), static.Protocol.Clients...)
	static.Protocol.Clients[0].ID = created.Client.ID
	if _, err := oauthpostgres.NewStore(f.pool, static, f.keys); err == nil {
		t.Fatal("static collision entered exclusive registry namespace")
	}
}

func TestNativeManagedClientRequiredEffectsRollbackAndOriginalRecovery(t *testing.T) {
	testNativeManagedClientRequiredEffectsRollbackAndOriginalRecovery(t, false)
}

func testNativeManagedClientRequiredEffectsRollbackAndOriginalRecovery(t *testing.T, public bool) {
	testNativeManagedClientRequiredEffectsProfile(t, public, false)
}

func testNativeManagedClientRequiredEffectsProfile(t *testing.T, public, managedOIDC bool) {
	t.Helper()
	for _, mode := range []string{"audit", "outbox", "unknown", "before"} {
		t.Run(mode, func(t *testing.T) {
			var provisional atomic.Bool
			fault := &oauthCommitFault{before: mode == "before", beforeWrite: func(wire []byte) {
				if bytes.Contains(wire, []byte(`INSERT INTO "oauth_store".managed_clients`)) {
					provisional.Store(true)
				}
			}}
			f := passwordFixture(t, fault)
			var service *oauth.Service
			var signer *oauth.SigningService
			var subjectKey [32]byte
			var err error
			if managedOIDC {
				signer, subjectKey = managedOIDCFixture(t, &f, false)
				f.oauth.Protocol.ManagedClients.PublicOIDC = true
				service, _, _ = managedOIDCServices(t, f, signer, subjectKey)
			} else {
				enableClientManagement(t, &f)
				if public {
					installPublicClients(t, &f)
				}
				service, err = oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "audit" {
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE audit.records ADD CONSTRAINT refuse_client_audit CHECK(action<>'identity.oauth_server.create_client')`)
			}
			if mode == "outbox" {
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_client_event CHECK(topic<>'oauth_client.created.v1') NOT VALID`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown" || mode == "before" {
				fault.armed.Store(true)
			}
			r := clientCreateRequest(t, f, "client-required-effects-"+mode)
			r.Public = public
			if managedOIDC {
				r.Scopes = []string{"openid"}
			}
			out, createErr := service.ClientCreate(f.ctx, r)
			if createErr == nil || !provisional.Load() {
				t.Fatal("required failure reported success")
			}
			if _, err := out.Secret.Reveal(); err == nil {
				t.Fatal("uncertain/failed creation delivered secret")
			}
			store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown" || mode == "before" {
				if !fault.hit.Load() || out.Completion.Outcome != identity.CommitOutcomeUnknown || out.Completion.CommandID == "" {
					t.Fatalf("real COMMIT seam missed: hit=%t provisional=%t outcome_unknown=%t command_present=%t unavailable=%t deadline=%t canceled=%t error_type=%T", fault.hit.Load(), provisional.Load(), out.Completion.Outcome == identity.CommitOutcomeUnknown, out.Completion.CommandID != "", errors.Is(createErr, oauth.ErrUnavailable), errors.Is(createErr, context.DeadlineExceeded), errors.Is(createErr, context.Canceled), createErr)
				}
				rr := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-create", CommandID: out.Completion.CommandID, ClientID: oauth.ManagedClientPrefix + string(out.Completion.CommandID), TenantID: f.tenant, Session: f.browser}
				metadata, err := store.Recover(f.ctx, rr)
				want := identity.CommitOutcomeCommitted
				if mode == "before" {
					want = identity.CommitOutcomeNotCommitted
					if err != nil || metadata.Outcome != identity.CommitOutcomeInProgress {
						t.Fatal("live original lease not observational", err)
					}
				}
				deadline := time.Now().Add(8 * time.Second)
				for metadata.Outcome != want {
					if time.Now().After(deadline) {
						t.Fatal("original recovery did not reconcile", err)
					}
					timer := time.NewTimer(100 * time.Millisecond)
					select {
					case <-timer.C:
					case <-f.ctx.Done():
						timer.Stop()
						t.Fatal("recovery deadline")
					}
					metadata, err = store.Recover(f.ctx, rr)
					if err != nil && !errors.Is(err, oauth.ErrUnavailable) {
						t.Fatal("recovery rejected original custody", err)
					}
				}
				for i := 0; i < 2; i++ {
					again, err := store.Recover(f.ctx, rr)
					if err != nil && !(mode == "before" && errors.Is(err, oauth.ErrUnavailable)) || again.Outcome != want || again.CommandID != rr.CommandID {
						t.Fatal("terminal recovery unstable", err)
					}
				}
			}
			var clients, effects, audits, events int
			for _, q := range []struct {
				sql    string
				target *int
			}{{`SELECT count(*) FROM oauth_store.managed_clients`, &clients}, {`SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-create'`, &effects}, {`SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.create_client' AND outcome=1`, &audits}, {`SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_client.created.v1'`, &events}} {
				if err := f.pool.Raw().QueryRow(f.ctx, q.sql).Scan(q.target); err != nil {
					t.Fatal(err)
				}
			}
			want := 0
			if mode == "unknown" {
				want = 1
			}
			if clients != want || effects != want || audits != want || events != want {
				t.Fatal("atomic client effects violated")
			}
			var restarted *oauth.Service
			if managedOIDC {
				restarted, _, _ = managedOIDCServices(t, f, signer, subjectKey)
			} else {
				restarted, err = oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			}
			if err != nil {
				t.Fatal(err)
			}
			retry, err := restarted.ClientCreate(f.ctx, r)
			if mode == "unknown" && (err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != out.Completion.CommandID) {
				t.Fatal("original unknown retry diverged", err)
			}
			if _, err := retry.Secret.Reveal(); err == nil {
				t.Fatal("retry regenerated client custody")
			}
		})
	}
}

func TestNativeManagedClientDeletionFencesLateApprovalExchangeAndRefresh(t *testing.T) {
	testNativeManagedClientDeletionFences(t, false)
}

func testNativeManagedClientDeletionFences(t *testing.T, managedOIDC bool) {
	t.Helper()
	for _, mode := range []string{"approval", "exchange", "refresh"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			var service *oauth.Service
			var signer *oauth.SigningService
			var subjectKey [32]byte
			var err error
			scopes := []string{"identity:read"}
			if managedOIDC {
				signer, subjectKey = managedOIDCFixture(t, &f, false)
				f.oauth.Protocol.ManagedClients.PublicOIDC = true
				service, _, _ = managedOIDCServices(t, f, signer, subjectKey)
				scopes = []string{"openid"}
			} else {
				enableClientManagement(t, &f)
				service, err = oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			}
			if err != nil {
				t.Fatal(err)
			}
			r := clientCreateRequest(t, f, "race-create")
			if managedOIDC {
				r.Public, r.Scopes = true, scopes
			}
			created, err := service.ClientCreate(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			var basic oauth.ClientAuthentication
			if !managedOIDC {
				secret, _ := created.Secret.Reveal()
				basic = confidentialBasic(t, created.Client.ID, secret)
			}
			var tokenRequest oauth.TokenRequest
			var continuation string
			if mode == "approval" {
				challenge, _ := oauth.S256Challenge(strings.Repeat("a", 43))
				begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: created.Client.ID, RedirectURI: created.Client.Redirects[0], Resource: created.Client.Resource, Scopes: scopes, CodeChallenge: challenge}})
				if err != nil {
					t.Fatal(err)
				}
				continuation, err = begin.Continuation.Reveal()
				if err != nil {
					t.Fatal(err)
				}
			} else {
				code, proof := confidentialCodeScopes(t, f, service, created.Client, scopes)
				tokenRequest = oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: created.Client.ID, ClientAuthentication: basic, Code: code, CodeVerifier: proof, RedirectURI: created.Client.Redirects[0], Network: "192.0.2.1"}
				if mode == "refresh" {
					issued, err := service.Token(f.ctx, tokenRequest)
					if err != nil {
						t.Fatal(err)
					}
					refresh, err := issued.RefreshToken.Reveal()
					if err != nil {
						t.Fatal(err)
					}
					tokenRequest = oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: created.Client.ID, ClientAuthentication: basic, RefreshToken: refresh, Network: "192.0.2.1"}
				}
			}
			var before int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			action := authorization.Action("identity.oauth-server.token")
			if mode == "approval" {
				action = "identity.oauth-server.continue"
			}
			barrier := &consentRaceBarrier{owner: f.oauth.Coordinator.AdmissionPolicy.Authorization, action: action, ready: make(chan struct{}), release: make(chan struct{})}
			admission := *f.oauth.Coordinator.AdmissionPolicy
			admission.Authorization = barrier
			f.oauth.Coordinator.AdmissionPolicy = &admission
			var late *oauth.Service
			if managedOIDC {
				late, _, _ = managedOIDCServices(t, f, signer, subjectKey)
			} else {
				late, err = oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.WithValue(f.ctx, consentRaceKey{}, true))
			defer cancel()
			done := make(chan error, 1)
			joined := false
			defer func() {
				cancel()
				select {
				case <-barrier.release:
				default:
					close(barrier.release)
				}
				if !joined {
					<-done
				}
			}()
			go func() {
				if mode == "approval" {
					out, err := late.Continue(ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", ClientID: created.Client.ID, Continuation: continuation, Approve: true, Scopes: scopes})
					if _, deliveryErr := out.Location(); deliveryErr == nil {
						done <- errors.New("late deleted client received redirect")
						return
					}
					done <- err
				} else {
					out, err := late.Token(ctx, tokenRequest)
					if _, deliveryErr := out.AccessToken.Reveal(); deliveryErr == nil {
						done <- errors.New("late deleted client received access")
						return
					}
					done <- err
				}
			}()
			select {
			case <-barrier.ready:
			case err := <-done:
				joined = true
				t.Fatal("actual protocol target did not reach late native gate", err)
			case <-f.ctx.Done():
				t.Fatal("bounded late protocol gate canceled")
			}
			remove := r
			remove.ClientID = created.Client.ID
			remove.Version = 1
			remove.Public = false
			remove.Redirects = nil
			remove.Scopes = nil
			remove.RequestKey, _ = identity.NewIdempotencyKey([]byte("race-delete"))
			if out, err := service.ClientDelete(f.ctx, remove); err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("concurrent terminal deletion failed", err)
			}
			close(barrier.release)
			err = <-done
			joined = true
			if err == nil {
				t.Fatal("late protocol ignored terminal client deletion")
			}
			var after int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects`).Scan(&after); err != nil || after != before+1 {
				t.Fatal("late issuance changed descendants after deletion", err)
			}
		})
	}
}

func TestNativeManagedClientDeletionFencesLateResourcePrimaryRead(t *testing.T) {
	f := passwordFixture(t)
	enableClientManagement(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	r := clientCreateRequest(t, f, "resource-race-create")
	created, err := service.ClientCreate(f.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := created.Secret.Reveal()
	access, _ := issuedConfidentialTokens(t, f, service, created.Client, confidentialBasic(t, created.Client.ID, secret))
	gate := &resourceReadGate{reached: make(chan struct{}), proceed: make(chan struct{})}
	original := f.pool.Raw().Config().ConnConfig
	pool, err := database.Connect(f.ctx, database.Config{DSN: original.ConnString(), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = original.Database
		c.ConnConfig.RuntimeParams = maps.Clone(original.RuntimeParams)
		c.ConnConfig.Tracer = gate
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if pool.Close(ctx) != nil {
			t.Error("owned resource pool cleanup")
		}
	}()
	verifier, err := oauthpostgres.NewResourceVerifier(pool, f.oauth, f.keys, resourcePolicy(f, created.Client))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"}); err != nil {
		t.Fatal("live resource control", err)
	}
	ctx, cancel := context.WithCancel(context.WithValue(f.ctx, resourceReadKey{}, true))
	defer cancel()
	type result struct {
		p   oauth.ResourcePrincipal
		err error
	}
	done := make(chan result, 1)
	joined := false
	defer func() {
		cancel()
		select {
		case <-gate.proceed:
		default:
			close(gate.proceed)
		}
		if !joined {
			<-done
		}
	}()
	go func() {
		p, err := verifier.Verify(ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"})
		done <- result{p, err}
	}()
	select {
	case <-gate.reached:
	case out := <-done:
		joined = true
		t.Fatal("resource did not reach second actual primary lookup", out.err)
	case <-f.ctx.Done():
		t.Fatal("bounded resource gate canceled")
	}
	remove := r
	remove.ClientID = created.Client.ID
	remove.Version = 1
	remove.Redirects = nil
	remove.Scopes = nil
	remove.RequestKey, _ = identity.NewIdempotencyKey([]byte("resource-race-delete"))
	if _, err := service.ClientDelete(f.ctx, remove); err != nil {
		t.Fatal(err)
	}
	close(gate.proceed)
	out := <-done
	joined = true
	if !errors.Is(out.err, oauth.ErrInvalidResourceToken) || out.p.Subject() != "" || out.p.RequireScope("identity:read") == nil {
		t.Fatal("late deleted client supplied resource authority", out.err)
	}
}

func TestNativeManagedClientDeleteRequiredOutboxAndLostCommitRecovery(t *testing.T) {
	for _, mode := range []string{"outbox", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			var provisional atomic.Bool
			fault := &oauthCommitFault{beforeWrite: func(wire []byte) {
				if bytes.Contains(wire, []byte(`UPDATE "oauth_store".managed_clients SET version=2`)) {
					provisional.Store(true)
				}
			}}
			f := passwordFixture(t, fault)
			enableClientManagement(t, &f)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			r := clientCreateRequest(t, f, "delete-fault-create")
			created, err := service.ClientCreate(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			secret, _ := created.Secret.Reveal()
			basic := confidentialBasic(t, created.Client.ID, secret)
			if mode == "outbox" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_client_deletion CHECK(topic<>'oauth_client.revoked.v1') NOT VALID`); err != nil {
					t.Fatal(err)
				}
			} else {
				fault.armed.Store(true)
			}
			remove := r
			remove.ClientID = created.Client.ID
			remove.Version = 1
			remove.Redirects = nil
			remove.Scopes = nil
			remove.RequestKey, _ = identity.NewIdempotencyKey([]byte("delete-fault-original"))
			out, err := service.ClientDelete(f.ctx, remove)
			if err == nil || !provisional.Load() {
				t.Fatal("uncertain/failed deletion reported success")
			}
			if _, err := out.Secret.Reveal(); err == nil {
				t.Fatal("deletion delivered a secret")
			}
			store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown" {
				if !fault.hit.Load() || out.Completion.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("lost deletion COMMIT was not unknown")
				}
				for i := 0; i < 2; i++ {
					recovered, err := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-delete", CommandID: out.Completion.CommandID, ClientID: created.Client.ID, TenantID: f.tenant, Session: f.browser})
					if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("original deleted client recovery lost commitment", err)
					}
				}
				if err := store.AuthenticateCurrentClient(f.ctx, created.Client, basic); err == nil {
					t.Fatal("lost-ack committed delete accepted old Basic")
				}
			} else {
				if err := store.AuthenticateCurrentClient(f.ctx, created.Client, basic); err != nil {
					t.Fatal("rolled-back deletion withdrew actual client", err)
				}
			}
			var version, state string
			var effects, events, audits int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,state,(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-delete'),(SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_client.revoked.v1'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.delete_client' AND outcome=1) FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&version, &state, &effects, &events, &audits); err != nil {
				t.Fatal(err)
			}
			want := 0
			wantVersion, wantState := "1", "active"
			if mode == "unknown" {
				want = 1
				wantVersion, wantState = "2", "deleted"
			}
			if version != wantVersion || state != wantState || effects != want || events != want || audits != want {
				t.Fatal("deletion atomic effects mismatch")
			}
			if _, err := store.CurrentClient(f.ctx, oauth.ManagedClientPrefix+strings.Repeat("x", 129)); err == nil {
				t.Fatal("unbounded direct registry ID admitted")
			}
		})
	}
}
