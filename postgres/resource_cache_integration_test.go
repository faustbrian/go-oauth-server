//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"maps"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type resourceCacheSQLCounter struct{ queries atomic.Int64 }

func (c *resourceCacheSQLCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.queries.Add(1)
	return ctx
}
func (*resourceCacheSQLCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Only the verifier clock is controlled. All minting, root/parent/credential
// authority and SQL results remain actual primary owners and real database time.
type resourceCacheTestClock struct{ offset atomic.Int64 }

func (c *resourceCacheTestClock) Now() time.Time {
	return time.Now().UTC().Add(time.Duration(c.offset.Load()))
}
func (c *resourceCacheTestClock) at(deadline time.Time) { c.offset.Store(int64(time.Until(deadline))) }

func resourceCacheObservedPool(t *testing.T, f authenticatedPasswordFixture) (*database.Pool, *resourceCacheSQLCounter, func()) {
	t.Helper()
	original := f.pool.Raw().Config().ConnConfig
	counter := &resourceCacheSQLCounter{}
	pool, err := database.Connect(f.ctx, database.Config{DSN: original.ConnString(), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = original.Database
		c.ConnConfig.RuntimeParams = maps.Clone(original.RuntimeParams)
		c.ConnConfig.Tracer = counter
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	closePool := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := pool.Close(ctx); err != nil {
				t.Error("owned observer pool cleanup failed", err)
			}
		})
	}
	t.Cleanup(closePool)
	var actual string
	if err := pool.Raw().QueryRow(f.ctx, `SELECT current_database()`).Scan(&actual); err != nil || actual != original.Database {
		t.Fatal("observer pool did not select exact owned fixture database", err)
	}
	return pool, counter, closePool
}

func cachedResourcePolicy(f authenticatedPasswordFixture, client oauth.Client, clock *resourceCacheTestClock) oauth.ResourceVerificationConfig {
	policy := resourcePolicy(f, client)
	policy.Clock = clock
	policy.Cache = oauth.ResourceCachePolicy{Capacity: 4, ClockUncertainty: time.Second, DecisionRaceBudget: time.Second}
	return policy
}

func TestNativeResourceCacheLostInvalidationRootAndUserWithdrawal(t *testing.T) {
	for _, withdrawal := range []string{"root", "user"} {
		t.Run(withdrawal, func(t *testing.T) {
			h := nativeHumanExchange(t, false)
			child := humanChild(t, h, h.source)
			pool, counter, _ := resourceCacheObservedPool(t, h.f)
			clock := &resourceCacheTestClock{}
			v, err := oauthpostgres.NewResourceVerifier(pool, h.f.oauth, h.f.keys, cachedResourcePolicy(h.f, h.client, clock))
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
				original[i], err = v.Verify(h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: token, Scope: "identity:read"})
				if err != nil {
					t.Fatal("actual minted source/child failed initial verification", err)
				}
			}
			coldQueries := counter.queries.Load()
			if coldQueries < 2 {
				t.Fatal("cold verification did not access actual primary owners")
			}
			if withdrawal == "root" {
				if _, err := h.service.Revoke(h.f.ctx, oauth.RevokeRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: h.source, Network: "192.0.2.1"}); err != nil {
					t.Fatal(err)
				}
			} else {
				suspendResourceUser(t, h.f, original[0].Subject())
			}
			for i, token := range tokens {
				requireInvalidResource(t, strict, h.f.ctx, token)
				warm, err := v.Verify(h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: token, Scope: "identity:read"})
				if err != nil || warm.ValidUntil() != original[i].ValidUntil() || warm.RequireScope("identity:read") != nil {
					t.Fatal("warm original evidence lost or renewed without invalidation", err)
				}
			}
			if counter.queries.Load() != coldQueries {
				t.Fatal("warm verifier consulted a primary authority")
			}
			deadline := original[0].ValidUntil()
			if original[1].ValidUntil().After(deadline) {
				deadline = original[1].ValidUntil()
			}
			clock.at(deadline)
			for i, token := range tokens {
				if original[i].RequireScope("identity:read") == nil {
					t.Fatal("original copied evidence survived its absolute deadline")
				}
				requireInvalidResource(t, v, h.f.ctx, token)
			}
			if counter.queries.Load() <= coldQueries {
				t.Fatal("expired decision did not refresh against actual withdrawal")
			}
		})
	}
}

func TestNativeResourceCacheWarmPrimaryOutageAndExpiredRefreshDenial(t *testing.T) {
	h := nativeHumanExchange(t, false)
	child := humanChild(t, h, h.source)
	pool, counter, closePool := resourceCacheObservedPool(t, h.f)
	clock := &resourceCacheTestClock{}
	v, err := oauthpostgres.NewResourceVerifier(pool, h.f.oauth, h.f.keys, cachedResourcePolicy(h.f, h.client, clock))
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.ResourceVerifyRequest{AccessToken: child, Scope: "identity:read"}
	original, err := v.Verify(h.f.ctx, request)
	if err != nil {
		t.Fatal("actual child did not produce verified original evidence", err)
	}
	queries := counter.queries.Load()
	closePool()
	for range 3 {
		warm, err := v.Verify(h.f.ctx, request)
		if err != nil || warm.ValidUntil() != original.ValidUntil() || warm.RequireScope(request.Scope) != nil {
			t.Fatal("warm decision needed unavailable primary or renewed evidence", err)
		}
	}
	if counter.queries.Load() != queries {
		t.Fatal("warm primary outage attempted authority access")
	}
	ctx, cancel := context.WithCancel(h.f.ctx)
	cancel()
	if p, err := v.Verify(ctx, request); !errors.Is(err, context.Canceled) || p.Subject() != "" {
		t.Fatal("cancelled warm call exposed identity", err)
	}
	clock.at(original.ValidUntil())
	for range 2 {
		if p, err := v.Verify(h.f.ctx, request); !errors.Is(err, oauth.ErrUnavailable) || p.Subject() != "" || p.RequireScope(request.Scope) == nil {
			t.Fatal("expired refresh outage reused cached authority", err)
		}
	}
	if original.RequireScope(request.Scope) == nil {
		t.Fatal("copy survived expired refresh outage")
	}
}
