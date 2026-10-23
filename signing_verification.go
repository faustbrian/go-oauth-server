package oauthserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

// SigningVerificationKeys is an optional read-only current key-eligibility owner.
// Unlike publication, this operation must never activate/register keys. Retained
// retired material may verify historical hints; compromised/foreign keys deny.
// Implementations perform a bounded primary read without positive caching.
type SigningVerificationKeys interface {
	VerificationSigningKey(context.Context, string) (PublicSigningKey, error)
}

// VerifiedCompact proves only the exact compact signature, not claim, issuance,
// session or current authorization semantics. Payload returns caller-owned bytes.
// Digest binds the original wire representation for durable issuance lookup.
type VerifiedCompact struct {
	kid         string
	payload     []byte
	digest      [32]byte
	readStarted time.Time
}

func (v VerifiedCompact) KeyID() string    { return v.kid }
func (v VerifiedCompact) Payload() []byte  { return append([]byte(nil), v.payload...) }
func (v VerifiedCompact) Digest() [32]byte { return v.digest }

// ReadStartedAt is the sealed original verification-key read start. It supplies
// no lease or current authorization; native consumers retain this earlier start
// instead of trusting a caller-constructed execution timestamp to renew time.
func (v VerifiedCompact) ReadStartedAt() time.Time { return v.readStarted }
func (VerifiedCompact) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("VerifiedCompact(redacted)"))
}
func (VerifiedCompact) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (VerifiedCompact) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// VerificationConfigured reports the optional read-only owner without IO. It
// does not establish current eligibility or authorize any protocol operation.
func (s *SigningService) VerificationConfigured() bool {
	if s == nil || s.authority == nil {
		return false
	}
	owner, ok := s.lifecycle.(SigningVerificationKeys)
	return ok && !nilDependency(owner)
}

// VerifyCompact validates the core-issued ES256/JWT envelope with bounded strict
// JOSE syntax and current read-only key eligibility. It intentionally does not
// reject exp: RP-Initiated Logout §2 permits historical hints. The consuming
// protocol must still establish exact durable issuance and current source-session
// association before using such a hint. Cancellation never returns partial proof.
func (s *SigningService) VerifyCompact(ctx context.Context, wire string) (VerifiedCompact, error) {
	if s == nil || ctx == nil || s.authority == nil || len(wire) == 0 || len(wire) > 16384 {
		return VerifiedCompact{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return VerifiedCompact{}, err
	}
	started := s.authority.clock.Now().UTC()
	// Go's base64 decoder deliberately ignores CR/LF, including Strict mode.
	// Compact JWS uses only unpadded base64url segments (RFC7515 §3.1), so
	// reject ignored/noncanonical input before consulting the key owner.
	for _, b := range []byte(wire) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.') {
			return VerifiedCompact{}, ErrInvalidRequest
		}
	}
	parts := strings.Split(wire, ".")
	if len(parts) != 3 || len(parts[0]) > 684 || len(parts[1]) > 10923 || len(parts[2]) != 86 {
		return VerifiedCompact{}, ErrInvalidRequest
	}
	decode := func(part string) ([]byte, error) { return base64.RawURLEncoding.Strict().DecodeString(part) }
	header, err := decode(parts[0])
	if err != nil || len(header) > 512 {
		return VerifiedCompact{}, ErrInvalidRequest
	}
	kid, err := verificationHeader(header)
	if err != nil {
		return VerifiedCompact{}, err
	}
	payload, err := decode(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > 8192 || payload[0] != '{' || !json.Valid(payload) {
		return VerifiedCompact{}, ErrInvalidRequest
	}
	signature, err := decode(parts[2])
	if err != nil || len(signature) != 64 {
		return VerifiedCompact{}, ErrInvalidRequest
	}
	owner, ok := s.lifecycle.(SigningVerificationKeys)
	if !ok || nilDependency(owner) {
		return VerifiedCompact{}, ErrAccessDenied
	}
	key, err := owner.VerificationSigningKey(ctx, kid)
	if err != nil {
		return VerifiedCompact{}, err
	}
	if err := ctx.Err(); err != nil {
		return VerifiedCompact{}, err
	}
	// Historical verification needs only retained public material, not retired
	// private custody on a fresh process. If local custody exists, its compromise
	// or material mismatch cannot be undone by a stale/misconfigured key reader.
	s.authority.mu.Lock()
	local := s.authority.keys[kid]
	eligible := local == nil || !local.compromised && local.public == key
	s.authority.mu.Unlock()
	if !eligible || key.Kty != "EC" || key.Crv != "P-256" || key.Alg != "ES256" || key.Use != "sig" || key.Kid != kid {
		return VerifiedCompact{}, ErrAccessDenied
	}
	x, xerr := decode(key.X)
	y, yerr := decode(key.Y)
	if xerr != nil || yerr != nil || len(x) != 32 || len(y) != 32 {
		return VerifiedCompact{}, ErrAccessDenied
	}
	public := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !public.Curve.IsOnCurve(public.X, public.Y) || !ecdsa.Verify(&public, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return VerifiedCompact{}, ErrAccessDenied
	}
	if err := ctx.Err(); err != nil {
		return VerifiedCompact{}, err
	}
	return VerifiedCompact{kid: kid, payload: payload, digest: sha256.Sum256([]byte(wire)), readStarted: started}, nil
}

func verificationHeader(raw []byte) (string, error) {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return "", ErrInvalidRequest
	}
	values := make(map[string]string, 3)
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || (name != "alg" && name != "typ" && name != "kid") {
			return "", ErrInvalidRequest
		}
		if _, duplicate := values[name]; duplicate {
			return "", ErrInvalidRequest
		}
		var value string
		if d.Decode(&value) != nil {
			return "", ErrInvalidRequest
		}
		values[name] = value
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') || len(values) != 3 || values["alg"] != "ES256" || values["typ"] != "JWT" || !identifier(values["kid"]) {
		return "", ErrInvalidRequest
	}
	if _, err := d.Token(); err != io.EOF {
		return "", ErrInvalidRequest
	}
	return values["kid"], nil
}
