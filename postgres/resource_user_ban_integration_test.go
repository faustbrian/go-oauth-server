//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// This selected application grants the existing fixture service actor only the
// two literal admin operations on one actual native user. All other decisions
// retain the fixture's existing authorization service and native owners.
type resourceUserBanPolicy struct {
	authorization.Service
	tenant identity.TenantID
	user   identity.UserID
}

func (p resourceUserBanPolicy) Decide(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	r := dc.Request
	if r.Tenant == authorization.TenantID(p.tenant) && r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == baselineActor && r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(p.user) && (r.Action == "identity.admin.user-ban" || r.Action == "identity.admin.user-unban") {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return p.Service.Decide(ctx, dc)
}

func resourceUserBanService(t *testing.T, f authenticatedPasswordFixture, user identity.UserID) (*identity.UserStatusService, *kernel.Repository) {
	t.Helper()
	domain, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
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
	query := *configuration.QueryPolicy
	query.Authorization = resourceUserBanPolicy{Service: query.Authorization, tenant: f.tenant, user: user}
	configuration.QueryPolicy, configuration.AdmissionPolicy = &query, &query
	coordinator, err := kernel.NewCoordinator(f.pool, registry, configuration)
	if err != nil {
		t.Fatal(err)
	}
	policy := identity.StatusPolicy{MaximumSuspension: time.Hour, BanRequiresReason: true, AllowedTransitions: []identity.StatusTransition{{From: identity.StatusActive, To: identity.StatusBanned, ReasonRequired: true}, {From: identity.StatusBanned, To: identity.StatusActive}}}
	contracts := make(map[string]kernel.StatusConsumerContract)
	for _, id := range (identity.UserStatusCommand{Binding: identity.CommandBinding{OperationID: "identity.admin.user-ban"}}).RequiredConsumers() {
		contracts[id] = kernel.StatusConsumerContract{Version: 1, Fingerprint: [32]byte{1}}
	}
	owner, err := kernel.NewStatusUnitOfWork(coordinator, domain, kernel.StatusUnitOfWorkConfig{RetentionPolicyVersion: 1, PolicyVersion: 9, Reasons: []string{"security"}, MaximumCascadeDuration: time.Hour, ConsumerContracts: contracts, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewUserStatusService(domain, owner, query.Authorization, func(ctx context.Context, in identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		return identity.RedactionPolicyDecision{PolicyID: "resource-user-ban", PolicyVersion: 9, Reason: "visible", VisibleFields: in.Fields}, ctx.Err()
	}, identity.UserStatusConfig{Query: identity.UserQueryConfig{Clock: query.Clock, MaximumDuration: time.Second, PolicyID: "resource-user-ban", PolicyVersion: 9, RedactionReasons: []identity.PolicyReason{"visible"}, ValidateCanonicalUserID: func(ctx context.Context, id identity.UserID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := identity.ParseSubjectID(string(id))
		return err
	}}, Policy: policy, PolicyVersion: 9, Reasons: []string{"security"}})
	if err != nil {
		t.Fatal(err)
	}
	return service, domain
}

func TestNativeResourceUserBanUnbanLostInvalidationDoesNotRestoreOldAuthority(t *testing.T) {
	h := nativeHumanExchange(t, false)
	child := humanChild(t, h, h.source)
	pool, counter, _ := resourceCacheObservedPool(t, h.f)
	clock := &resourceCacheTestClock{}
	cached, err := oauthpostgres.NewResourceVerifier(pool, h.f.oauth, h.f.keys, cachedResourcePolicy(h.f, h.client, clock))
	if err != nil {
		t.Fatal(err)
	}
	strict, err := oauthpostgres.NewResourceVerifier(h.f.pool, h.f.oauth, h.f.keys, resourcePolicy(h.f, h.client))
	if err != nil {
		t.Fatal(err)
	}
	tokens := []string{h.source, child}
	original := make([]oauth.ResourcePrincipal, len(tokens))
	for i, token := range tokens {
		original[i], err = cached.Verify(h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: token, Scope: "identity:read"})
		if err != nil || original[i].RequireScope("identity:read") != nil {
			t.Fatal("genuine source/child did not warm current resource authority", err)
		}
	}
	user := original[0].Subject()
	if user == "" || original[1].Subject() != user {
		t.Fatal("native source and exchanged child do not identify the same user")
	}
	coldQueries := counter.queries.Load()
	if coldQueries < 2 {
		t.Fatal("warming did not consult actual primary owners")
	}
	service, domain := resourceUserBanService(t, h.f, user)
	readStatus := func() identity.UserStatusRecord {
		t.Helper()
		state, err := domain.GetStatus(h.f.ctx, identity.UserStatusQuery{TenantID: h.f.tenant, UserID: user})
		if err != nil {
			t.Fatal("actual user status unavailable", err)
		}
		return state
	}
	request := func(operation string, state identity.UserStatusRecord) identity.UserStatusRequest {
		t.Helper()
		command, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return identity.UserStatusRequest{CommandID: command, TenantID: h.f.tenant, UserID: user, ExpectedVersion: state.User.Version, ExpectedAuthorityVersion: state.AuthorityVersion, CorrelationID: string(command), ActorScope: authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: authorization.TenantID(h.f.tenant), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: baselineActor}, Action: authorization.Action(operation), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}}
	}
	counts := func() [3]int64 {
		t.Helper()
		var out [3]int64
		if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT (SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.artifacts),(SELECT count(*) FROM oauth_store.effects)`).Scan(&out[0], &out[1], &out[2]); err != nil {
			t.Fatal(err)
		}
		return out
	}
	denyIssuance := func() {
		t.Helper()
		before := counts()
		requests := []oauth.TokenRequest{humanExchangeRequest(h.client, h.basic, h.source), humanExchangeRequest(h.client, h.basic, child), {GrantType: oauth.RefreshTokenGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, RefreshToken: h.refresh, Network: "192.0.2.1"}}
		for _, req := range requests {
			out, err := h.service.Token(h.f.ctx, req)
			if !errors.Is(err, oauth.ErrInvalidGrant) || out.Outcome == identity.CommitOutcomeCommitted || out.AccessToken != (oauth.Token{}) || out.RefreshToken != (oauth.Token{}) {
				t.Fatal("withdrawn source, child or refresh minted authority", err)
			}
		}
		if counts() != before {
			t.Fatal("denied issuance created an OAuth grant, artifact or effect")
		}
	}

	active := readStatus()
	if active.User.Status != identity.StatusActive {
		t.Fatal("ban positive control requires an active native user")
	}
	ban := request("identity.admin.user-ban", active)
	ban.Reason = "security"
	ban.ExpiresAt = time.Now().UTC().Truncate(time.Microsecond).Add(30 * time.Minute)
	blockedAt := clock.Now()
	result, err := service.AdminUserBan(h.f.ctx, ban)
	if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.User.Status != identity.StatusBanned || result.Revocation.Status != identity.RevocationPending || result.Revocation.AuthorityVersion != active.AuthorityVersion+1 {
		t.Fatal("actual public admin ban did not commit primary withdrawal", err)
	}
	banned := readStatus()
	if banned.User.Status != identity.StatusBanned || banned.User.Version != active.User.Version+1 || banned.AuthorityVersion != active.AuthorityVersion+1 {
		t.Fatal("ban did not advance both native user versions")
	}
	var reason string
	var expiry time.Time
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT status_reason,status_expires_at FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(h.f.tenant), string(user)).Scan(&reason, &expiry); err != nil || reason != ban.Reason || !expiry.Equal(ban.ExpiresAt) {
		t.Fatal("ban did not retain configured reason and absolute expiry", err)
	}
	for _, token := range tokens {
		requireInvalidResource(t, strict, h.f.ctx, token)
	}
	denyIssuance()
	deadline := original[0].ValidUntil()
	for i, token := range tokens {
		if original[i].ValidUntil().After(blockedAt.Add(30 * time.Second)) {
			t.Fatal("original evidence exceeds the SI-05 block visibility bound")
		}
		for range 3 {
			warm, err := cached.Verify(h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: token, Scope: "identity:read"})
			if err != nil || warm.ValidUntil() != original[i].ValidUntil() || warm.RequireScope("identity:read") != nil {
				t.Fatal("lost invalidation renewed or discarded still-current original evidence", err)
			}
		}
		if original[i].ValidUntil().After(deadline) {
			deadline = original[i].ValidUntil()
		}
	}
	if counter.queries.Load() != coldQueries {
		t.Fatal("warm decisions did not demonstrate lost invalidation without primary refresh")
	}
	clock.at(deadline)
	for i, token := range tokens {
		if original[i].RequireScope("identity:read") == nil {
			t.Fatal("copied warm evidence survived its original absolute deadline")
		}
		requireInvalidResource(t, cached, h.f.ctx, token)
	}
	if counter.queries.Load() <= coldQueries {
		t.Fatal("expired cache did not consult actual banned primary authority")
	}

	unban := request("identity.admin.user-unban", banned)
	if unban.CommandID == ban.CommandID {
		t.Fatal("unban reused the ban command instead of fresh dual-version intent")
	}
	result, err = service.AdminUserUnban(h.f.ctx, unban)
	if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.User.Status != identity.StatusActive || result.Revocation.Status != identity.RevocationPending || result.Revocation.AuthorityVersion != banned.AuthorityVersion+1 {
		t.Fatal("actual public admin unban did not restore eligibility", err)
	}
	restored := readStatus()
	if restored.User.Status != identity.StatusActive || restored.User.Version != banned.User.Version+1 || restored.AuthorityVersion != banned.AuthorityVersion+1 {
		t.Fatal("unban did not retain the new native authority epoch")
	}
	for _, token := range tokens {
		requireInvalidResource(t, strict, h.f.ctx, token)
		requireInvalidResource(t, cached, h.f.ctx, token)
	}
	denyIssuance()
}
