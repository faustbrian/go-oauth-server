package oauthserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"time"
)

// PublicSigningKey is the public ES256 JWK projection. Private members are not
// representable. Kid values are unique for the lifetime of an authority.
type PublicSigningKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type signingKey struct {
	private            *ecdsa.PrivateKey
	public             PublicSigningKey
	published, removed bool
	until              time.Time
}

// SigningAuthority owns private key custody and selected ES256 lifecycle. Its
// mutex alone owns key states and the last possible issued expiry. No goroutines
// or external resources are created. Applications must coordinate all serving
// instances through the same authority/lifecycle; independent instances are not
// a distributed key registry. Restart must restore published keys and overlap
// deadlines before activation; a fresh authority is not lifecycle recovery.
type SigningAuthority struct {
	mu         sync.Mutex
	clock      Clock
	maximumTTL time.Duration
	keys       map[string]*signingKey
	active     string
}

// NewSigningAuthority selects explicit ID-token lifetime bounds, 1s..5min.
// Clock is borrowed, fast and concurrency-safe; it must not call this authority.
func NewSigningAuthority(clock Clock, maximumTTL time.Duration) (*SigningAuthority, error) {
	if nilDependency(clock) || maximumTTL < time.Second || maximumTTL > 5*time.Minute {
		return nil, ErrInvalidRequest
	}
	return &SigningAuthority{clock: clock, maximumTTL: maximumTTL, keys: make(map[string]*signingKey)}, nil
}

// AddKey copies a valid P-256 private key. It is initially unselectable until
// PublicKeys has projected it and Activate explicitly selects it. Removed kids
// cannot be reused, avoiding verifier cache ambiguity (OIDC Core 10.1.1).
func (a *SigningAuthority) AddKey(kid string, key *ecdsa.PrivateKey) error {
	if a == nil || !identifier(kid) || key == nil || key.Curve != elliptic.P256() {
		return ErrInvalidRequest
	}
	wire, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return ErrInvalidRequest
	}
	defer clear(wire)
	owned, err := x509.ParseECPrivateKey(wire)
	if err != nil || owned.D.Sign() <= 0 || owned.D.Cmp(elliptic.P256().Params().N) >= 0 {
		return ErrInvalidRequest
	}
	x, y := elliptic.P256().ScalarBaseMult(owned.D.Bytes())
	if x.Cmp(owned.X) != 0 || y.Cmp(owned.Y) != 0 {
		return ErrInvalidRequest
	}
	encode := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32))) }
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.keys[kid]; exists || len(a.keys) >= 64 {
		return ErrInvalidRequest
	}
	a.keys[kid] = &signingKey{private: owned, public: PublicSigningKey{Kty: "EC", Crv: "P-256", Use: "sig", Alg: "ES256", Kid: kid, X: encode(owned.X), Y: encode(owned.Y)}}
	return nil
}

// PublicKeys publishes the current verification projection and marks included
// keys eligible for explicit activation. Serve this projection before activating
// a new key and do not positively cache JWKS across activation. Publication is a
// composition operation, not proof that a particular remote client fetched it.
func (a *SigningAuthority) PublicKeys(ctx context.Context) ([]PublicSigningKey, error) {
	if a == nil || ctx == nil {
		return nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]PublicSigningKey, 0, len(a.keys))
	for _, key := range a.keys {
		if !key.removed {
			key.published = true
			out = append(out, key.public)
		}
	}
	slices.SortFunc(out, func(a, b PublicSigningKey) int {
		if a.Kid < b.Kid {
			return -1
		}
		if a.Kid > b.Kid {
			return 1
		}
		return 0
	})
	return out, nil
}

// Activate selects only previously published, uncompromised private custody.
func (a *SigningAuthority) Activate(kid string) error {
	if a == nil {
		return ErrInvalidRequest
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	k := a.keys[kid]
	if k == nil || !k.published || k.removed {
		return ErrAccessDenied
	}
	a.active = kid
	return nil
}

// Retire removes only inactive keys whose last signed token has expired. Keep
// serving old public keys until then (OIDC Core 10.1.1 key rotation).
func (a *SigningAuthority) Retire(kid string) error {
	if a == nil {
		return ErrInvalidRequest
	}
	now := a.clock.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	k := a.keys[kid]
	if k == nil || k.removed || a.active == kid || now.Before(k.until) {
		return ErrAccessDenied
	}
	k.removed = true
	k.private = nil
	return nil
}

// Compromise immediately disables signing and publication, deliberately
// overriding overlap. Existing offline RP caches require explicit invalidation;
// ID tokens alone are not current resource/session authorization evidence.
func (a *SigningAuthority) Compromise(kid string) error {
	if a == nil {
		return ErrInvalidRequest
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	k := a.keys[kid]
	if k == nil || k.removed {
		return ErrAccessDenied
	}
	k.removed = true
	k.private = nil
	if a.active == kid {
		a.active = ""
	}
	return nil
}

// Sign performs bounded ES256 signing using only the active published key.
// Returned signature is the JWS fixed-width R||S encoding, not ASN.1 DER.
func (a *SigningAuthority) Sign(ctx context.Context, input []byte, expires time.Time) (string, string, error) {
	if a == nil || ctx == nil || len(input) == 0 || len(input) > 16384 {
		return "", "", ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	now := a.clock.Now()
	a.mu.Lock()
	kid, signature, err := a.signLocked(input, expires, now, a.active)
	a.mu.Unlock()
	if cancelled := ctx.Err(); cancelled != nil {
		return "", "", cancelled
	}
	return kid, signature, err
}

func (a *SigningAuthority) signLocked(input []byte, expires, now time.Time, kid string) (string, string, error) {
	k := a.keys[kid]
	if k == nil || k.removed || !k.published {
		return "", "", ErrAccessDenied
	}
	if !now.Before(expires) || expires.After(now.Add(a.maximumTTL)) {
		return "", "", ErrInvalidRequest
	}
	digest := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, k.private, digest[:])
	if err != nil {
		return "", "", ErrUnavailable
	}
	wire := make([]byte, 64)
	r.FillBytes(wire[:32])
	s.FillBytes(wire[32:])
	if expires.After(k.until) {
		k.until = expires
	}
	return kid, base64.RawURLEncoding.EncodeToString(wire), nil
}

// SignCompact is a raw signing capability, not a claim validator or authority.
// Its caller must supply its own closed typed object, never untrusted JSON.
// It binds the current kid and fixed ES256/JWT header in one lock, so rotation
// cannot change the key between header creation and signature. Native grant
// commitment, not possession of signed bytes, authorizes token delivery.
func (a *SigningAuthority) SignCompact(ctx context.Context, claims []byte, expires time.Time) (string, error) {
	return a.signCompact(ctx, claims, expires, "")
}

func (a *SigningAuthority) signCompact(ctx context.Context, claims []byte, expires time.Time, kid string) (string, error) {
	if a == nil || ctx == nil || len(claims) == 0 || len(claims) > 8192 || !json.Valid(claims) || claims[0] != '{' {
		return "", ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	now := a.clock.Now()
	a.mu.Lock()
	if kid == "" {
		kid = a.active
	}
	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}{"ES256", "JWT", kid})
	if err != nil {
		a.mu.Unlock()
		return "", ErrUnavailable
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	_, signature, err := a.signLocked([]byte(input), expires, now, kid)
	a.mu.Unlock()
	if cancelled := ctx.Err(); cancelled != nil {
		return "", cancelled
	}
	if err != nil {
		return "", err
	}
	return input + "." + signature, nil
}

// Format and serialization prohibit implicit private-custody diagnostics.
func (*SigningAuthority) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oauthserver.SigningAuthority(redacted)"))
}
func (*SigningAuthority) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (*SigningAuthority) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// SigningLifecycle is core's durable public-key authority. Implementations must
// compare complete registered public material on repeated registration, make
// publication irreversible, serialize activation, retain the greatest reserved
// expiry across restart, and prohibit retired/compromised kid reuse. Unknown
// mutations deny; callers reconcile against the original immutable key/kid.
// No private material crosses this seam. All methods honor the bounded ctx.
type SigningLifecycle interface {
	RegisterSigningKey(context.Context, PublicSigningKey) error
	PublishSigningKeys(context.Context) ([]PublicSigningKey, error)
	ActivateSigningKey(context.Context, string) error
	ReserveSigningKey(context.Context, string, time.Time) error
	RetireSigningKey(context.Context, string) error
	CompromiseSigningKey(context.Context, string) error
}

// SigningService combines core-owned private custody with native durable public
// lifecycle. This, not an isolated SigningAuthority, is the selected provider
// signing capability. Lifecycle remains borrowed; it owns no private key.
type SigningService struct {
	authority *SigningAuthority
	lifecycle SigningLifecycle
}

func NewSigningService(authority *SigningAuthority, lifecycle SigningLifecycle) (*SigningService, error) {
	if authority == nil || nilDependency(lifecycle) {
		return nil, ErrInvalidRequest
	}
	return &SigningService{authority: authority, lifecycle: lifecycle}, nil
}

// Install copies private custody in core and idempotently registers only its
// exact public identity in the durable owner. A restart must explicitly install
// private custody again; persistence cannot reconstitute or disclose it.
func (s *SigningService) Install(ctx context.Context, kid string, key *ecdsa.PrivateKey) error {
	if s == nil || ctx == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.authority.mu.Lock()
	existing := s.authority.keys[kid]
	if existing != nil {
		valid := !existing.removed && existing.private != nil && key != nil && key.Curve == elliptic.P256() && key.D != nil && key.X != nil && key.Y != nil && existing.private.D.Cmp(key.D) == 0 && existing.private.X.Cmp(key.X) == 0 && existing.private.Y.Cmp(key.Y) == 0
		public := existing.public
		s.authority.mu.Unlock()
		if !valid {
			return ErrInvalidRequest
		}
		return s.lifecycle.RegisterSigningKey(ctx, public)
	}
	s.authority.mu.Unlock()
	if err := s.authority.AddKey(kid, key); err != nil {
		return err
	}
	s.authority.mu.Lock()
	public := s.authority.keys[kid].public
	s.authority.mu.Unlock()
	return s.lifecycle.RegisterSigningKey(ctx, public)
}

func (s *SigningService) PublicKeys(ctx context.Context) ([]PublicSigningKey, error) {
	if s == nil || ctx == nil {
		return nil, ErrInvalidRequest
	}
	return s.lifecycle.PublishSigningKeys(ctx)
}
func (s *SigningService) Activate(ctx context.Context, kid string) error {
	if s == nil || ctx == nil {
		return ErrInvalidRequest
	}
	// Local validation precedes a durable selection, but local marking alone is
	// never sufficient: native activation rejects a not-yet-published key.
	if _, err := s.authority.PublicKeys(ctx); err != nil {
		return err
	}
	s.authority.mu.Lock()
	key := s.authority.keys[kid]
	valid := key != nil && !key.removed
	s.authority.mu.Unlock()
	if !valid {
		return ErrAccessDenied
	}
	if err := s.lifecycle.ActivateSigningKey(ctx, kid); err != nil {
		return err
	}
	return s.authority.Activate(kid)
}
func (s *SigningService) Retire(ctx context.Context, kid string) error {
	if s == nil || ctx == nil {
		return ErrInvalidRequest
	}
	if err := s.lifecycle.RetireSigningKey(ctx, kid); err != nil {
		return err
	}
	// Native time and greatest reserved expiry are authoritative after restart.
	s.authority.mu.Lock()
	if key := s.authority.keys[kid]; key != nil {
		key.removed = true
		key.private = nil
	}
	s.authority.mu.Unlock()
	return nil
}
func (s *SigningService) Compromise(ctx context.Context, kid string) error {
	if s == nil || ctx == nil {
		return ErrInvalidRequest
	}
	if err := s.lifecycle.CompromiseSigningKey(ctx, kid); err != nil {
		return err
	}
	_ = s.authority.Compromise(kid)
	return nil
}

// SignCompact is a raw bounded signing capability: the child must first build
// its own closed typed claims object, never caller JSON. Private signing starts
// only after native authority reserves expiry under the exact active, published
// kid. Reservations are conservative on rollback or lost acknowledgement and
// are never shortened; delivery still belongs to the native token transaction.
func (s *SigningService) SignCompact(ctx context.Context, claims []byte, expires time.Time) (IDToken, string, error) {
	if s == nil || ctx == nil || len(claims) < 1 || len(claims) > 8192 || !json.Valid(claims) || claims[0] != '{' {
		return IDToken{}, "", ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return IDToken{}, "", err
	}
	s.authority.mu.Lock()
	kid := s.authority.active
	key := s.authority.keys[kid]
	available := key != nil && !key.removed && key.published
	s.authority.mu.Unlock()
	if !available {
		return IDToken{}, "", ErrAccessDenied
	}
	if err := s.lifecycle.ReserveSigningKey(ctx, kid, expires); err != nil {
		return IDToken{}, "", err
	}
	// Rotation may select a successor after this exact reservation. The previous
	// published key remains eligible for that reserved window; bind its header
	// and signature together rather than silently switching to the successor.
	wire, err := s.authority.signCompact(ctx, claims, expires, kid)
	if err != nil {
		return IDToken{}, "", err
	}
	token, err := ParseIDToken(wire)
	return token, kid, err
}

func (*SigningService) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oauthserver.SigningService(redacted)"))
}
func (*SigningService) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (*SigningService) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }
