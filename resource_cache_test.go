package oauthserver_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

func resourceCacheFixture(now *time.Time) (oauth.ResourceVerificationConfig, oauth.ResourceAccessProjection) {
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	scopes, _ := oauth.NewScopeCatalog([]string{"identity:read", "identity:write"})
	c := oauth.ResourceVerificationConfig{Issuer: issuer, Environment: "test", TenantID: "tenant", ClientID: "client", ClientVersion: 1, Resource: "https://resource.example", Scopes: scopes, Clock: clockFunc(func() time.Time { return *now }), MaximumDuration: time.Second, Cache: oauth.ResourceCachePolicy{Capacity: 2, ClockUncertainty: time.Second, DecisionRaceBudget: time.Second}}
	p := oauth.ResourceAccessProjection{Issuer: issuer, Environment: c.Environment, TenantID: c.TenantID, UserID: "user", ClientID: c.ClientID, ClientVersion: c.ClientVersion, Resource: c.Resource, Kind: oauth.TokenAccess, Scopes: scopes.Scopes(), ReadStartedAt: *now, ValidUntil: now.Add(20 * time.Second), TokenExpiresAt: now.Add(time.Minute)}
	return c, p
}

func TestResourceCacheConservesEveryExpiryAndReadStart(t *testing.T) {
	for _, limit := range []string{"evidence", "token", "credential"} {
		t.Run(limit, func(t *testing.T) {
			now := time.Now().UTC()
			c, projection := resourceCacheFixture(&now)
			projection.ReadStartedAt = now.Add(-5 * time.Second)
			projection.ValidUntil = projection.ReadStartedAt.Add(20 * time.Second)
			deadline := projection.ValidUntil
			if limit == "token" {
				projection.TokenExpiresAt = now.Add(time.Second)
				deadline = projection.TokenExpiresAt
			}
			if limit == "credential" {
				projection.CredentialExpiresAt = now.Add(time.Second)
				deadline = projection.CredentialExpiresAt
			}
			reads := 0
			v, err := oauth.NewResourceVerifier(c, resourceReader(func(context.Context, string) (oauth.ResourceAccessProjection, error) {
				reads++
				if reads > 1 {
					return oauth.ResourceAccessProjection{}, oauth.ErrUnavailable
				}
				return projection, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			request := oauth.ResourceVerifyRequest{AccessToken: "opaque-custody", Scope: "identity:read"}
			first, err := v.Verify(context.Background(), request)
			if err != nil || first.ValidUntil() != deadline {
				t.Fatal("original source expiry changed", err)
			}
			now = deadline.Add(-time.Nanosecond)
			if warm, err := v.Verify(context.Background(), request); err != nil || warm.ValidUntil() != deadline || reads != 1 {
				t.Fatal("warm deadline changed", err)
			}
			now = deadline
			if p, err := v.Verify(context.Background(), request); !errors.Is(err, oauth.ErrUnavailable) || p.Subject() != "" {
				t.Fatal("expiry boundary reused stale evidence", err)
			}
		})
	}
}

func TestResourceCacheDoesNotBroadenScopeTokenOrVerifier(t *testing.T) {
	now := time.Now().UTC()
	c, projection := resourceCacheFixture(&now)
	reads := 0
	reader := resourceReader(func(context.Context, string) (oauth.ResourceAccessProjection, error) {
		reads++
		if reads > 1 {
			return oauth.ResourceAccessProjection{}, oauth.ErrUnavailable
		}
		return projection, nil
	})
	v, err := oauth.NewResourceVerifier(c, reader)
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.ResourceVerifyRequest{AccessToken: "opaque-custody", Scope: "identity:read"}
	if _, err := v.Verify(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	for _, other := range []oauth.ResourceVerifyRequest{{AccessToken: request.AccessToken, Scope: "identity:write"}, {AccessToken: "other-opaque-custody", Scope: request.Scope}} {
		if p, err := v.Verify(context.Background(), other); !errors.Is(err, oauth.ErrUnavailable) || p.Subject() != "" {
			t.Fatal("cache crossed exact credential/scope", err)
		}
	}
	c.ClientVersion++
	other, err := oauth.NewResourceVerifier(c, reader)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := other.Verify(context.Background(), request); !errors.Is(err, oauth.ErrUnavailable) || p.Subject() != "" {
		t.Fatal("verifier inherited another policy's cache", err)
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", v, v), request.AccessToken) {
		t.Fatal("cache formatting disclosed custody")
	}
}

func TestResourceCacheCancellationAndRollbackCannotSpendWarmEvidence(t *testing.T) {
	now := time.Now().UTC()
	c, projection := resourceCacheFixture(&now)
	reads := 0
	v, err := oauth.NewResourceVerifier(c, resourceReader(func(context.Context, string) (oauth.ResourceAccessProjection, error) { reads++; return projection, nil }))
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.ResourceVerifyRequest{AccessToken: "opaque-custody", Scope: "identity:read"}
	if _, err := v.Verify(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, err := v.Verify(ctx, request); !errors.Is(err, context.Canceled) || p.Subject() != "" || reads != 1 {
		t.Fatal("cancelled warm request exposed principal", err)
	}
	now = projection.ReadStartedAt.Add(-time.Nanosecond)
	if p, err := v.Verify(context.Background(), request); err == nil || p.Subject() != "" {
		t.Fatal("rollback spent future evidence")
	}
}

func TestResourceCacheWarmDecisionFencesLateCancellationExpiryAndRollback(t *testing.T) {
	for _, change := range []string{"cancel", "expiry", "rollback"} {
		t.Run(change, func(t *testing.T) {
			now := time.Now().UTC()
			c, projection := resourceCacheFixture(&now)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			warmClockCalls, reads := 0, 0
			warmPhase := false
			c.Clock = clockFunc(func() time.Time {
				if warmPhase {
					warmClockCalls++
				}
				// Inject only after the warm call has already found a hit.
				if warmClockCalls == 2 {
					switch change {
					case "cancel":
						cancel()
					case "expiry":
						now = projection.ValidUntil
					case "rollback":
						now = projection.ReadStartedAt.Add(-time.Nanosecond)
					}
				}
				return now
			})
			v, err := oauth.NewResourceVerifier(c, resourceReader(func(context.Context, string) (oauth.ResourceAccessProjection, error) { reads++; return projection, nil }))
			if err != nil {
				t.Fatal(err)
			}
			request := oauth.ResourceVerifyRequest{AccessToken: "opaque-custody", Scope: "identity:read"}
			if _, err := v.Verify(ctx, request); err != nil {
				t.Fatal(err)
			}
			warmPhase = true
			p, err := v.Verify(ctx, request)
			if err == nil || p.Subject() != "" || reads != 1 {
				t.Fatal("late warm fence failed", change, err, reads)
			}
			if change == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("late cancellation lost", err)
			}
		})
	}
}

func TestResourceCacheObservedExpiryCannotReviveAfterFailedRefreshAndRollback(t *testing.T) {
	now := time.Now().UTC()
	c, projection := resourceCacheFixture(&now)
	reads := 0
	v, err := oauth.NewResourceVerifier(c, resourceReader(func(context.Context, string) (oauth.ResourceAccessProjection, error) {
		reads++
		if reads > 1 {
			return oauth.ResourceAccessProjection{}, oauth.ErrUnavailable
		}
		return projection, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.ResourceVerifyRequest{AccessToken: "opaque-custody", Scope: "identity:read"}
	if _, err := v.Verify(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	now = projection.ValidUntil
	if _, err := v.Verify(context.Background(), request); !errors.Is(err, oauth.ErrUnavailable) {
		t.Fatal("expired refresh did not fail closed", err)
	}
	now = projection.ReadStartedAt.Add(time.Second)
	if p, err := v.Verify(context.Background(), request); !errors.Is(err, oauth.ErrUnavailable) || p.Subject() != "" || reads != 3 {
		t.Fatal("observed-expired snapshot revived after rollback and outage", err, reads)
	}
}

func TestResourceCacheColdReturnRechecksDeadlineAfterStorage(t *testing.T) {
	now := time.Now().UTC()
	c, projection := resourceCacheFixture(&now)
	reads, clockCalls := 0, 0
	c.Clock = clockFunc(func() time.Time {
		clockCalls++
		if clockCalls == 3 {
			now = projection.ValidUntil
		}
		return now
	})
	v, err := oauth.NewResourceVerifier(c, resourceReader(func(context.Context, string) (oauth.ResourceAccessProjection, error) {
		reads++
		if reads > 1 {
			return oauth.ResourceAccessProjection{}, oauth.ErrUnavailable
		}
		return projection, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.ResourceVerifyRequest{AccessToken: "opaque-custody", Scope: "identity:read"}
	if p, err := v.Verify(context.Background(), request); !errors.Is(err, oauth.ErrInvalidResourceToken) || p.Subject() != "" {
		t.Fatal("cold return did not fence deadline after storing", err)
	}
	now = projection.ReadStartedAt.Add(time.Second)
	if p, err := v.Verify(context.Background(), request); !errors.Is(err, oauth.ErrUnavailable) || p.Subject() != "" || reads != 2 {
		t.Fatal("late-expired fill survived a later rollback", err, reads)
	}
}

func TestResourceCacheCapacityEvictsWithoutRetainingCustody(t *testing.T) {
	now := time.Now().UTC()
	c, projection := resourceCacheFixture(&now)
	c.Cache.Capacity = 1
	reads := 0
	v, err := oauth.NewResourceVerifier(c, resourceReader(func(context.Context, string) (oauth.ResourceAccessProjection, error) {
		reads++
		if reads > 2 {
			return oauth.ResourceAccessProjection{}, oauth.ErrUnavailable
		}
		return projection, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"first-custody", "second-custody"} {
		if _, err := v.Verify(context.Background(), oauth.ResourceVerifyRequest{AccessToken: token, Scope: "identity:read"}); err != nil {
			t.Fatal(err)
		}
	}
	if p, err := v.Verify(context.Background(), oauth.ResourceVerifyRequest{AccessToken: "first-custody", Scope: "identity:read"}); !errors.Is(err, oauth.ErrUnavailable) || p.Subject() != "" || reads != 3 {
		t.Fatal("capacity did not bound retained decisions", err, reads)
	}
}

func TestResourceCacheRejectsUnboundedDeploymentPolicy(t *testing.T) {
	now := time.Now().UTC()
	c, projection := resourceCacheFixture(&now)
	for _, policy := range []oauth.ResourceCachePolicy{{Capacity: -1}, {Capacity: 4097}, {Capacity: 1}, {ClockUncertainty: time.Second}, {Capacity: 1, ClockUncertainty: 9 * time.Second, DecisionRaceBudget: time.Second}, {Capacity: 1, ClockUncertainty: time.Second, DecisionRaceBudget: -time.Second}} {
		c.Cache = policy
		if _, err := oauth.NewResourceVerifier(c, resourceReader(func(context.Context, string) (oauth.ResourceAccessProjection, error) { return projection, nil })); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("invalid cache policy admitted", policy, err)
		}
	}
}

func TestResourceCacheCannotSelectOrganizationProfile(t *testing.T) {
	now := time.Now().UTC()
	c, _ := resourceCacheFixture(&now)
	if _, err := (oauth.OrganizationResourceVerificationConfig{Verification: c, OrganizationID: "organization"}).Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("human cache selection claimed organization coverage", err)
	}
	c.Cache = oauth.ResourceCachePolicy{}
	if _, err := (oauth.OrganizationResourceVerificationConfig{Verification: c, OrganizationID: "organization"}).Validated(); err != nil {
		t.Fatal("default organization policy changed", err)
	}
}

func TestResourceCacheNeverStoresInvalidOrFailedProjection(t *testing.T) {
	for _, mode := range []string{"kind", "resource", "client", "scope", "future", "late", "error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			c, original := resourceCacheFixture(&now)
			reads := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			v, err := oauth.NewResourceVerifier(c, resourceReader(func(context.Context, string) (oauth.ResourceAccessProjection, error) {
				reads++
				if reads > 1 {
					return oauth.ResourceAccessProjection{}, oauth.ErrUnavailable
				}
				p := original
				switch mode {
				case "kind":
					p.Kind = oauth.TokenRefresh
				case "resource":
					p.Resource = "https://foreign.example"
				case "client":
					p.ClientID = "foreign"
				case "scope":
					p.Scopes = []string{"identity:write"}
				case "future":
					p.ReadStartedAt = now.Add(time.Second)
				case "late":
					now = p.ValidUntil
				case "error":
					return p, oauth.ErrUnavailable
				case "cancel":
					cancel()
				}
				return p, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			request := oauth.ResourceVerifyRequest{AccessToken: "opaque-custody", Scope: "identity:read"}
			if p, err := v.Verify(ctx, request); err == nil || p.Subject() != "" {
				t.Fatal("invalid source admitted", mode)
			}
			if p, err := v.Verify(context.Background(), request); !errors.Is(err, oauth.ErrUnavailable) || p.Subject() != "" || reads != 2 {
				t.Fatal("failed decision seeded positive cache", err, reads)
			}
		})
	}
}

func TestResourceCacheOlderConcurrentFillCannotReplaceNewerEvidence(t *testing.T) {
	start := time.Now().UTC()
	now := start
	c, original := resourceCacheFixture(&now)
	var nanos atomic.Int64
	nanos.Store(start.UnixNano())
	c.Clock = clockFunc(func() time.Time { return time.Unix(0, nanos.Load()).UTC() })
	var reads atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	v, err := oauth.NewResourceVerifier(c, resourceReader(func(ctx context.Context, _ string) (oauth.ResourceAccessProjection, error) {
		p := original
		switch reads.Add(1) {
		case 1:
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return oauth.ResourceAccessProjection{}, ctx.Err()
			}
		case 2:
			p.ReadStartedAt = start.Add(time.Second)
			p.ValidUntil = start.Add(10 * time.Second)
		default:
			return oauth.ResourceAccessProjection{}, oauth.ErrUnavailable
		}
		return p, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request := oauth.ResourceVerifyRequest{AccessToken: "opaque-custody", Scope: "identity:read"}
	finished := make(chan error, 1)
	go func() { _, err := v.Verify(ctx, request); finished <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	nanos.Store(start.Add(time.Second).UnixNano())
	newer, err := v.Verify(ctx, request)
	close(release)
	olderErr := <-finished
	if err != nil || olderErr != nil {
		t.Fatal("concurrent primary reads failed", err, olderErr)
	}
	warm, err := v.Verify(ctx, request)
	if err != nil || warm.ValidUntil() != newer.ValidUntil() || reads.Load() != 2 {
		t.Fatal("older slow fill replaced newer evidence", err, reads.Load())
	}
}

func TestResourceCacheWarmDecisionNeedsNoReaderAndCannotRenew(t *testing.T) {
	now := time.Now().UTC()
	c, projection := resourceCacheFixture(&now)
	reads := 0
	v, err := oauth.NewResourceVerifier(c, resourceReader(func(context.Context, string) (oauth.ResourceAccessProjection, error) {
		reads++
		if reads > 1 {
			return oauth.ResourceAccessProjection{}, oauth.ErrUnavailable
		}
		return projection, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.ResourceVerifyRequest{AccessToken: "borrowed-opaque-custody", Scope: "identity:read"}
	first, err := v.Verify(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(19 * time.Second)
	warm, err := v.Verify(context.Background(), request)
	if err != nil || reads != 1 || warm.ValidUntil() != first.ValidUntil() || warm.RequireScope(request.Scope) != nil {
		t.Fatal("still-valid original evidence required a primary read or renewed validity", err, reads)
	}
	now = first.ValidUntil()
	if p, err := v.Verify(context.Background(), request); !errors.Is(err, oauth.ErrUnavailable) || p.Subject() != "" || reads != 2 {
		t.Fatal("expired refresh outage admitted stale evidence", err, reads)
	}
	if warm.RequireScope(request.Scope) == nil {
		t.Fatal("warm copy survived original deadline")
	}
}
