//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"maps"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

func suspendResourceUser(t *testing.T, f authenticatedPasswordFixture, user identity.UserID) {
	t.Helper()
	domain, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	status, err := domain.GetStatus(f.ctx, identity.UserStatusQuery{TenantID: f.tenant, UserID: user})
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
	id, _ := identity.NewCommandID()
	command, err := identity.NewUserStatusCommand(identity.UserStatusCommand{Binding: identity.CommandBinding{CommandID: id, TenantID: f.tenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.user.suspend", SchemaID: "identity-lifecycle", SchemaVersion: 1, PolicyID: "resource-consumer-block", PolicyVersion: 9, CorrelationID: string(id)}, ExpectedVersion: status.User.Version, ExpectedAuthorityVersion: status.AuthorityVersion, StatusPolicyVersion: 9, TargetStatus: identity.StatusSuspended, Reason: "security"})
	if err != nil {
		t.Fatal(err)
	}
	// The actual public status owner changes its primary epoch. No cascade
	// worker or fabricated identity row establishes the resource denial.
	out, err := owner.Execute(f.ctx, command)
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Revocation == nil || out.Revocation.Status != identity.RevocationPending {
		t.Fatal("actual primary status withdrawal failed", err)
	}
}

func TestNativeResourceVerifyCurrentCredentialAndBlockedUser(t *testing.T) {
	for _, mode := range []string{"credential", "user"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixtureWithChange(t, mode == "credential")
			enableConsentManagement(t, &f)
			client, _, basic := addConfiguredConfidentialClient(t, &f)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			access, _ := issuedConfidentialTokens(t, f, service, client, basic)
			v, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, resourcePolicy(f, client))
			if err != nil {
				t.Fatal(err)
			}
			p, err := v.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"})
			if err != nil {
				t.Fatal("current authority positive control failed", err)
			}
			if mode == "credential" {
				f.changePassword()
			} else {
				suspendResourceUser(t, f, p.Subject())
			}
			requireInvalidResource(t, v, f.ctx, access)
			requireInvalidResource(t, v, f.ctx, access)
		})
	}
}

type resourceReadKey struct{}
type resourceReadGate struct {
	count            atomic.Uint32
	reached, proceed chan struct{}
}

func (g *resourceReadGate) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	// This deliberate pgx scheduling seam passes every real query/result through.
	// Only the second token lookup of the marked verification is paused, after
	// the genuine first token and complete primary-authority pass succeeded.
	if ctx.Value(resourceReadKey{}) == true && strings.Contains(d.SQL, `FROM "oauth_store".artifacts a JOIN`) && g.count.Add(1) == 2 {
		close(g.reached)
		select {
		case <-g.proceed:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (*resourceReadGate) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestNativeResourceVerifyLateWithdrawalExpiryOutageAndCancellation(t *testing.T) {
	for _, mode := range []string{"revoke", "credential", "narrow", "expiry", "outage", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixtureWithChange(t, mode == "credential")
			if mode == "narrow" {
				enableConsentNarrowing(t, &f)
			} else {
				enableConsentManagement(t, &f)
			}
			if mode == "expiry" {
				f.oauth.Protocol.AccessTTL = time.Second
			}
			client, _, basic := addConfiguredConfidentialClient(t, &f)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			var access string
			if mode == "narrow" {
				access = resourceNarrowableAccess(t, f, service, client, basic)
			} else {
				access, _ = issuedConfidentialTokens(t, f, service, client, basic)
			}
			gate := &resourceReadGate{reached: make(chan struct{}), proceed: make(chan struct{})}
			originalConfig := f.pool.Raw().Config().ConnConfig
			pool, err := database.Connect(f.ctx, database.Config{DSN: originalConfig.ConnString(), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
				// pgx ConnString retains the original administrative DSN; the
				// fixture selected its private database through Configure.
				c.ConnConfig.Database = originalConfig.Database
				c.ConnConfig.RuntimeParams = maps.Clone(originalConfig.RuntimeParams)
				c.ConnConfig.Tracer = gate
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if pool.Close(cleanup) != nil {
					t.Error("traced task-owned pool cleanup failed")
				}
			}()
			var actualDatabase string
			if err := pool.Raw().QueryRow(f.ctx, `SELECT current_database()`).Scan(&actualDatabase); err != nil || actualDatabase != originalConfig.Database {
				t.Fatal("traced pool did not select the exact fixture database", err)
			}
			v, err := oauthpostgres.NewResourceVerifier(pool, f.oauth, f.keys, resourcePolicy(f, client))
			if err != nil {
				t.Fatal(err)
			}
			positive, err := v.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"})
			if err != nil {
				t.Fatal("late-change positive control failed", err)
			}
			if mode == "narrow" {
				if _, err := v.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:write"}); !errors.Is(err, oauth.ErrInvalidScope) {
					t.Fatal("generation-race access must already be read-only", err)
				}
			}
			ctx, cancel := context.WithCancel(context.WithValue(f.ctx, resourceReadKey{}, true))
			type result struct {
				p   oauth.ResourcePrincipal
				err error
			}
			finished := make(chan result, 1)
			var once sync.Once
			release := func() { once.Do(func() { close(gate.proceed) }) }
			joined := false
			defer func() {
				cancel()
				release()
				if !joined {
					<-finished
				}
			}()
			go func() {
				p, err := v.Verify(ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"})
				finished <- result{p, err}
			}()
			select {
			case <-gate.reached:
			case premature := <-finished:
				joined = true
				t.Fatal("real verification did not reach late lookup gate", premature.err)
			case <-f.ctx.Done():
				t.Fatal("bounded late lookup gate canceled")
			}
			switch mode {
			case "revoke":
				if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: client.ID, ClientAuthentication: basic, Token: access, Network: "192.0.2.1"}); err != nil {
					t.Fatal(err)
				}
			case "credential":
				f.changePassword()
			case "narrow":
				consent := currentNarrowConsent(t, f, service)
				if len(consent.Scopes()) != 2 {
					t.Fatal("generation race needs genuine broader original consent")
				}
				request := narrowRequest(t, f, consent, "late-resource-narrow", []string{"identity:read"})
				if out, err := service.ConsentUpdate(f.ctx, request); err != nil || !out.Updated {
					t.Fatal("late actual keyed consent narrowing failed", err)
				}
			case "expiry":
				waitAuthenticationBoundary(t, f, positive.ValidUntil())
				if positive.RequireScope("identity:read") == nil {
					t.Fatal("original returned principal renewed expired token")
				}
			case "outage":
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER SCHEMA identity RENAME TO resource_hidden`); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			}
			release()
			out := <-finished
			joined = true
			if mode == "outage" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER SCHEMA resource_hidden RENAME TO identity`); err != nil {
					t.Fatal("owned schema restoration failed", err)
				}
			}
			want := oauth.ErrInvalidResourceToken
			if mode == "outage" {
				want = oauth.ErrUnavailable
			}
			if mode == "cancel" {
				want = context.Canceled
			}
			if !errors.Is(out.err, want) || out.p.Subject() != "" || out.p.RequireScope("identity:read") == nil {
				t.Fatal("late change exposed or cached resource principal", mode, out.err)
			}
		})
	}
}

// Approve broad consent, then rotate its actual refresh into read-only access.
// The late narrowing retains that very same read scope, so only the changed
// consent generation (not an absent demanded scope) can establish denial.
func resourceNarrowableAccess(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service, client oauth.Client, basic oauth.ClientAuthentication) string {
	t.Helper()
	proof := oauth2.GenerateVerifier()
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: client.ID, RedirectURI: client.Redirects[0], Resource: client.Resource, Scopes: []string{"identity:read", "identity:write"}, CodeChallenge: oauth2.S256ChallengeFromVerifier(proof)}})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("late-narrowing original authorization failed", err)
	}
	continuation, _ := begin.Continuation.Reveal()
	approved, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: client.ID, Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true})
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("late-narrowing original broad consent failed", err)
	}
	location, _ := approved.Location()
	callback, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, ClientAuthentication: basic, Code: callback.Query().Get("code"), CodeVerifier: proof, RedirectURI: client.Redirects[0], Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("late-narrowing original code exchange failed", err)
	}
	refresh, _ := issued.RefreshToken.Reveal()
	narrowed, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, ClientAuthentication: basic, RefreshToken: refresh, Scopes: []string{"identity:read"}, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("late-narrowing read-only refresh control failed", err)
	}
	access, err := narrowed.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return access
}
