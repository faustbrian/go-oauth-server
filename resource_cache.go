package oauthserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"sync"
	"time"
)

// ResourceCachePolicy explicitly selects bounded process-local positive reuse.
// Zero disables reuse. Capacity is 1..4096 decisions; no token custody, shared
// cache, invalidation delivery, background work or issuance authority is added.
// ClockUncertainty and DecisionRaceBudget are trusted deployment bounds, each
// positive when enabled. Together with MaximumDuration they must fit the ten
// seconds reserved by SI-05/06 beyond the original twenty-second evidence.
type ResourceCachePolicy struct {
	Capacity                             int
	ClockUncertainty, DecisionRaceBudget time.Duration
}

func (c ResourceCachePolicy) valid(read time.Duration) bool {
	if c.Capacity == 0 {
		return c.ClockUncertainty == 0 && c.DecisionRaceBudget == 0
	}
	return c.Capacity > 0 && c.Capacity <= 4096 && c.ClockUncertainty > 0 && c.ClockUncertainty <= 10*time.Second && c.DecisionRaceBudget > 0 && c.DecisionRaceBudget <= 10*time.Second && read+c.ClockUncertainty+c.DecisionRaceBudget <= 10*time.Second
}

type resourceCacheKey struct {
	digest [sha256.Size]byte
	scope  string
}

type cacheableResourcePrincipal interface {
	RequireScope(string) error
	evidenceWindow() (start, until time.Time)
}

type resourceCacheEntry[P cacheableResourcePrincipal] struct {
	principal P
	expired   bool
}

// resourceDecisionCache owns only validated decisions for one frozen verifier.
// Its mutex never spans reader IO or clock callbacks. FIFO bounds both map and
// key storage without keeping borrowed tokens or a reusable digest namespace.
type resourceDecisionCache[P cacheableResourcePrincipal] struct {
	mu             sync.Mutex
	secret         [32]byte
	entries        map[resourceCacheKey]resourceCacheEntry[P]
	order          []resourceCacheKey
	next, capacity int
}

func newResourceDecisionCache[P cacheableResourcePrincipal](capacity int) (*resourceDecisionCache[P], error) {
	if capacity == 0 {
		return nil, nil
	}
	c := &resourceDecisionCache[P]{capacity: capacity, entries: make(map[resourceCacheKey]resourceCacheEntry[P], capacity), order: make([]resourceCacheKey, 0, capacity)}
	if _, err := rand.Read(c.secret[:]); err != nil {
		return nil, ErrUnavailable
	}
	return c, nil
}

func (c *resourceDecisionCache[P]) key(token, scope string) resourceCacheKey {
	h := hmac.New(sha256.New, c.secret[:])
	_, _ = h.Write([]byte(token))
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return resourceCacheKey{digest: digest, scope: scope}
}

func (c *resourceDecisionCache[P]) load(key resourceCacheKey, now time.Time) (zero P, _ bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || entry.expired {
		return zero, false
	}
	_, until := entry.principal.evidenceWindow()
	if !now.Before(until) {
		// Observed expiry is terminal for this snapshot, even if a failed
		// authority refresh is followed by a backwards clock adjustment.
		entry.expired = true
		c.entries[key] = entry
		return zero, false
	}
	return entry.principal, true
}

func (c *resourceDecisionCache[P]) expire(key resourceCacheKey, principal P) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return
	}
	start, until := principal.evidenceWindow()
	currentStart, currentUntil := entry.principal.evidenceWindow()
	if currentStart.Equal(start) && currentUntil.Equal(until) {
		entry.expired = true
		c.entries[key] = entry
	}
}

func (c *resourceDecisionCache[P]) store(key resourceCacheKey, p P) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Callers detach their typed projection. The key similarly must not retain
	// the backing bytes of a borrowed request field.
	key.scope = strings.Clone(key.scope)
	if entry, ok := c.entries[key]; ok {
		currentStart, currentUntil := entry.principal.evidenceWindow()
		start, until := p.evidenceWindow()
		// An older in-flight read cannot replace newer authoritative evidence;
		// identical starts cannot lengthen an already retained deadline either.
		if start.Before(currentStart) || (start.Equal(currentStart) && (entry.expired || until.After(currentUntil))) {
			return
		}
		c.entries[key] = resourceCacheEntry[P]{principal: p}
		return
	}
	if len(c.order) < c.capacity {
		c.order = append(c.order, key)
	} else {
		delete(c.entries, c.order[c.next])
		c.order[c.next] = key
		c.next = (c.next + 1) % c.capacity
	}
	c.entries[key] = resourceCacheEntry[P]{principal: p}
}

// checkDecision is the final scope/time/cancellation fence for both freshly
// stored and warm decisions. A failed time fence retires that exact window.
func (c *resourceDecisionCache[P]) checkDecision(ctx context.Context, key resourceCacheKey, p P, decisionStart time.Time, clock Clock) error {
	if err := p.RequireScope(key.scope); err != nil {
		c.expire(key, p)
		return err
	}
	_, until := p.evidenceWindow()
	if now := clock.Now(); now.Before(decisionStart) || !now.Before(until) {
		c.expire(key, p)
		return ErrInvalidResourceToken
	}
	return ctx.Err()
}
