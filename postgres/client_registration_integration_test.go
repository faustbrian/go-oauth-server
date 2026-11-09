//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

// This is the consumer's bounded configured-platform admission policy, not an
// initial-token verifier or a replacement for native registration authority.
type registrationConsumerPolicy struct {
	authorization.Service
	platform string
}

func (p registrationConsumerPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	r := c.Request
	if r.Action == "identity.oauth-server.dynamic-register" || r.Action == "identity.oauth-server.dynamic-register.recover" {
		allow := r.Tenant == baselineTenant && r.Subject.Kind == authorization.SubjectServiceAccount && string(r.Subject.ID) == p.platform &&
			(r.Resource.Type == "identity.anonymous-flow" && r.Resource.ID != "" || r.Resource.Type == "identity.request-admission" && r.Resource.ID == "identity.oauth-server.dynamic-register")
		outcome := authorization.Deny
		if allow {
			outcome = authorization.Allow
		}
		return authorization.Decision{Outcome: outcome, Revision: 9}, nil
	}
	return p.Service.Decide(ctx, c)
}

func nativeRegistrationFixture(t *testing.T, faults ...*oauthCommitFault) (authenticatedPasswordFixture, *oauthpostgres.Store, oauth.DynamicRegisterRequest) {
	t.Helper()
	f := passwordFixture(t, faults...)
	enableClientManagement(t, &f)
	installPublicClients(t, &f)
	store, request := enableNativeRegistration(t, &f)
	return f, store, request
}

func enableNativeRegistration(t *testing.T, f *authenticatedPasswordFixture) (*oauthpostgres.Store, oauth.DynamicRegisterRequest) {
	t.Helper()
	p := f.oauth.Protocol.ManagedClients
	p.DynamicRegistration = &oauth.DynamicRegistrationPolicy{Audience: f.oauth.Protocol.Issuer.String() + "/oauth2/register", Version: 1, AllowedScopes: []string{"identity:read"}}
	policy := registrationConsumerPolicy{Service: f.oauth.Coordinator.AdmissionPolicy.Authorization, platform: p.Owner.PlatformID()}
	query, admission := *f.oauth.Coordinator.QueryPolicy, *f.oauth.Coordinator.AdmissionPolicy
	query.Authorization, admission.Authorization = policy, policy
	f.oauth.Coordinator.QueryPolicy, f.oauth.Coordinator.AdmissionPolicy = &query, &admission
	f.oauth.RequestKeys.Policy.Authorization = policy
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
	base := oauthpostgres.ClientPublicMigrationSource{Base: oauthpostgres.ClientMigrationSource{Base: oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}, Schema: "oauth_store", Version: 7003}, Schema: "oauth_store", Version: 7004}
	runner, err := migrations.NewRunner(oauthpostgres.ClientRegistrationMigrationSource{Base: base, Schema: "oauth_store", Version: 7005}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := runner.Up(f.ctx); err != nil || len(result.Records()) != 1 {
		t.Fatal("registration forward migration", err)
	}
	if result, err := runner.Up(f.ctx); err != nil || len(result.Records()) != 0 {
		t.Fatal("registration changed installed history", err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	token, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal("initial custody unavailable")
	}
	if err := store.BootstrapRegistrationToken(f.ctx, wire, time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)); err != nil {
		t.Fatal("configured initial-token bootstrap", err)
	}
	r := oauth.DynamicRegisterRequest{InitialAccessToken: wire, Public: true, RedirectURIs: []string{"https://managed.example/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, AuthenticationMethod: "none", Scopes: []string{"identity:read"}, ClientName: "Native public consumer", Network: "192.0.2.1"}
	return store, r
}

func requireRegistrationCounts(t *testing.T, f authenticatedPasswordFixture, clients, consumed int) {
	t.Helper()
	var gotClients, gotConsumed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.managed_clients),(SELECT count(*) FROM oauth_store.initial_registration_tokens WHERE consumed_command IS NOT NULL)`).Scan(&gotClients, &gotConsumed); err != nil || gotClients != clients || gotConsumed != consumed {
		t.Fatalf("registration atomicity: clients=%d consumed=%d: %v", gotClients, gotConsumed, err)
	}
}

func TestNativeDynamicRegistrationPublicCodeS256DeleteAndOriginalRecovery(t *testing.T) {
	f, store, r := nativeRegistrationFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.DynamicRegister(f.ctx, r)
	if err != nil || created.Completion.Outcome != identity.CommitOutcomeCommitted || !created.Client.Public || created.Client.AuthenticationMethod != "none" || created.Client.Owner != f.oauth.Protocol.ManagedClients.Owner {
		t.Fatal("header-free RFC7591 registration", err)
	}
	if _, err := created.ClientSecret.Reveal(); err == nil {
		t.Fatal("public registration revealed a secret")
	}
	requireRegistrationCounts(t, f, 1, 1)
	var secretAbsent bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT secret_digest IS NULL FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&secretAbsent); err != nil || !secretAbsent {
		t.Fatal("public client stored secret custody", err)
	}
	fresh, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := confidentialCode(t, f, fresh, created.Client)
	request := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: created.Client.ID, Code: code, CodeVerifier: strings.Repeat("z", 43), RedirectURI: created.Client.Redirects[0], Network: r.Network}
	if _, err := fresh.Token(f.ctx, request); err == nil {
		t.Fatal("DCR public code accepted wrong S256 verifier")
	}
	request.CodeVerifier = verifier
	issued, err := fresh.Token(f.ctx, request)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("durable registered public client could not redeem real code/S256", err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal("committed refresh custody absent")
	}
	remove := clientRotationRequest(t, f, created.Client, "dcr-terminal-delete", 0).Management
	if _, err := fresh.ClientDelete(f.ctx, remove); err != nil {
		t.Fatal("ordinary owner management cannot terminally delete DCR client", err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: created.Client.ID, RefreshToken: refresh, Network: r.Network}); err == nil {
		t.Fatal("warm service issued descendant after terminal deletion")
	}
	recovered, err := store.RecoverDynamicRegistration(f.ctx, r)
	if err != nil || recovered.Completion.Outcome != identity.CommitOutcomeCommitted || recovered.Completion.CommandID != created.Completion.CommandID || !recovered.Completion.Replayed {
		t.Fatal("terminal deletion stranded original DCR command recovery", err)
	}
	if _, err := recovered.ClientSecret.Reveal(); err == nil {
		t.Fatal("original registration recovery revealed custody")
	}
	if _, err := fresh.DynamicRegister(f.ctx, r); err == nil {
		t.Fatal("consumed initial token created or resurrected a client")
	}
	requireRegistrationCounts(t, f, 1, 1)
}

func TestNativeDynamicRegistrationWrongMetadataAndPolicyDoNotConsumeToken(t *testing.T) {
	f, store, original := nativeRegistrationFixture(t)
	if _, err := store.RecoverDynamicRegistration(f.ctx, original); err == nil {
		t.Fatal("unconsumed custody substituted for absent command authority")
	}
	for name, change := range map[string]func(*oauth.DynamicRegisterRequest){
		"wrong token": func(r *oauth.DynamicRegisterRequest) {
			token, _ := oauth.NewToken()
			r.InitialAccessToken, _ = token.Reveal()
		},
		"scope expansion":         func(r *oauth.DynamicRegisterRequest) { r.Scopes = []string{"identity:read", "identity:write"} },
		"duplicate scope":         func(r *oauth.DynamicRegisterRequest) { r.Scopes = []string{"identity:read", "identity:read"} },
		"bad redirect":            func(r *oauth.DynamicRegisterRequest) { r.RedirectURIs = []string{"https://foreign.example/cb"} },
		"confidential unselected": func(r *oauth.DynamicRegisterRequest) { r.Public, r.AuthenticationMethod = false, "client_secret_basic" },
	} {
		t.Run(name, func(t *testing.T) {
			r := original
			change(&r)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.DynamicRegister(f.ctx, r); err == nil {
				t.Fatal("invalid registration committed")
			}
			requireRegistrationCounts(t, f, 0, 0)
		})
	}
	for _, change := range []func(*oauth.ManagedClientPolicy){
		func(p *oauth.ManagedClientPolicy) { p.Owner, _ = oauth.NewPlatformOwner("another-platform") },
		func(p *oauth.ManagedClientPolicy) {
			p.DynamicRegistration.Audience = "https://other.example/oauth2/register"
		},
		func(p *oauth.ManagedClientPolicy) { p.DynamicRegistration.Version++ },
	} {
		config := f.oauth
		managed := *config.Protocol.ManagedClients
		profile := *managed.DynamicRegistration
		managed.DynamicRegistration = &profile
		config.Protocol.ManagedClients = &managed
		change(&managed)
		service, err := oauthpostgres.NewService(f.pool, config, f.keys)
		if err == nil {
			if _, err := service.DynamicRegister(f.ctx, original); err == nil {
				t.Fatal("token crossed immutable owner/audience/version")
			}
		}
		requireRegistrationCounts(t, f, 0, 0)
	}
}

func TestNativeDynamicRegistrationCompetingUseCommitsOneClient(t *testing.T) {
	f, _, r := nativeRegistrationFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, name := range []string{"first", "competing"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			<-start
			request := r
			request.ClientName = name
			_, err := service.DynamicRegister(f.ctx, request)
			results <- err
		}(name)
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("one initial token admitted %d registrations", successes)
	}
	requireRegistrationCounts(t, f, 1, 1)
}

func TestNativeDynamicRegistrationExpiredTokenDoesNotCreateClient(t *testing.T) {
	f, store, r := nativeRegistrationFixture(t)
	// Advance only this task-owned token's expiry into the past, not the
	// database clock or a user/service-wide authority clock.
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.initial_registration_tokens SET expires_at=created_at + interval '1 microsecond'`); err != nil {
		t.Fatal(err)
	}
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.DynamicRegister(f.ctx, r); err == nil {
		t.Fatal("expired initial token registered a client")
	}
	if _, err := store.RecoverDynamicRegistration(f.ctx, r); err == nil {
		t.Fatal("absent original command acquired recovery authority")
	}
	requireRegistrationCounts(t, f, 0, 0)
}

func TestNativeDynamicRegistrationUnknownCommitAndRollback(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost-acknowledgement", true: "rollback"}[before], func(t *testing.T) {
			fault := &oauthCommitFault{before: before}
			f, store, r := nativeRegistrationFixture(t, fault)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			fault.armed.Store(true)
			lost, err := service.DynamicRegister(f.ctx, r)
			if err == nil || !fault.hit.Load() || lost.Completion.Outcome != identity.CommitOutcomeUnknown {
				t.Fatal("real protected DCR COMMIT fault missed", err)
			}
			if _, err := lost.ClientSecret.Reveal(); err == nil {
				t.Fatal("unknown registration disclosed secret")
			}
			want, clients := identity.CommitOutcomeCommitted, 1
			if before {
				want, clients = identity.CommitOutcomeNotCommitted, 0
			}
			recovered, err := store.RecoverDynamicRegistration(f.ctx, r)
			if before {
				if err != nil || recovered.Completion.Outcome != identity.CommitOutcomeInProgress {
					t.Fatal("live original lease must remain observational", err)
				}
				deadline := time.Now().Add(8 * time.Second)
				for recovered.Completion.Outcome == identity.CommitOutcomeInProgress && time.Now().Before(deadline) {
					timer := time.NewTimer(100 * time.Millisecond)
					select {
					case <-timer.C:
					case <-f.ctx.Done():
						timer.Stop()
						t.Fatal("bounded original recovery canceled")
					}
					recovered, err = store.RecoverDynamicRegistration(f.ctx, r)
					if err != nil {
						break
					}
				}
			}
			// The existing kernel terminalizes proven rollback as dependency-failure:
			// NotCommitted plus its retained Unavailable error, never success.
			// Unknown/InProgress plus Unavailable cannot satisfy this assertion.
			if before && !errors.Is(err, oauth.ErrUnavailable) || !before && err != nil || recovered.Completion.Outcome != want || recovered.Completion.CommandID != lost.Completion.CommandID || !recovered.Completion.Replayed {
				t.Fatal("original DCR reconciliation lost outcome/identity", err)
			}
			again, againErr := store.RecoverDynamicRegistration(f.ctx, r)
			if before && !errors.Is(againErr, oauth.ErrUnavailable) || !before && againErr != nil || again.Completion.Outcome != want || again.Completion.CommandID != lost.Completion.CommandID || !again.Completion.Replayed {
				t.Fatal("original terminal classification changed on repeated recovery", againErr)
			}
			if recovered.Client.ID != "" || again.Client.ID != "" {
				t.Fatal("historical recovery projected current client authority")
			}
			if before {
				retried, retryErr := service.DynamicRegister(f.ctx, r)
				if !errors.Is(retryErr, oauth.ErrUnavailable) || retried.Completion.Outcome != identity.CommitOutcomeNotCommitted || retried.Completion.CommandID != lost.Completion.CommandID || !retried.Completion.Replayed {
					t.Fatal("terminal original retry restarted registration", retryErr)
				}
			}
			var effects, successes, events int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
			 (SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.dynamic-register'),
			 (SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.create_client' AND outcome=1),
			 (SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_client.created.v1')`).Scan(&effects, &successes, &events); err != nil || effects != clients || successes != clients || events != clients {
				t.Fatal("durable registration effects disagreed with original recovery", err)
			}
			requireRegistrationCounts(t, f, clients, clients)
		})
	}
}
