package oauthserver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
)

var (
	// ErrAlreadyRevealed denies repeated delivery through any custody copy.
	// It is not replay detection: durable protocol state remains authoritative.
	ErrAlreadyRevealed = errors.New("oauthserver: token already revealed")
	// ErrUnavailable redacts unavailable dependencies without secret diagnostics.
	ErrUnavailable = errors.New("oauthserver: unavailable")
)

// TokenKind is a closed purpose-separated OAuth lookup domain.
type TokenKind uint8

const (
	TokenContinuation TokenKind = iota + 1
	TokenCode
	TokenAccess
	TokenRefresh
)

// Token owns one OAuth 32-byte canonical opaque bearer. Copies share a single
// atomic delivery permission; immutable Digest remains available afterward.
// This is secret custody, not a session, signature, protocol grant, proof of
// authentication, persistence or one-time consumption. Only a fresh known
// committed issuance may deliver it. Unknown and replay results reveal nothing.
// Go does not guarantee erasure of retained string bytes; there are no external
// resources or background goroutines. Formatting/serialization never reveals it.
type Token struct{ state *tokenState }
type tokenState struct {
	wire     string
	revealed atomic.Bool
}

// NewToken uses the standard library's cryptographic entropy to create exactly
// 32 random bytes (RFC6749 section10.10). It issues no grant or permission.
// It must not be called to retry an uncertain durable issuance; reconcile that
// original command before any new grant or material can be generated.
func NewToken() (Token, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Token{}, ErrUnavailable
	}
	return Token{state: &tokenState{wire: base64.RawURLEncoding.EncodeToString(raw[:])}}, nil
}

// ParseToken copies already possessed canonical 32-byte bearer syntax. It
// establishes no validity, purpose, ownership or replay authority. New delivery
// custody from parsed wire cannot undo protocol consumption or reveal an unknown
// secret. Bounds precede allocation; malformed input is always redacted.
func ParseToken(wire string) (Token, error) {
	if !opaque32(wire) {
		return Token{}, ErrInvalidRequest
	}
	return Token{state: &tokenState{wire: strings.Clone(wire)}}, nil
}

// Reveal explicitly returns the original bearer once across all copies. Losing
// the response does not restore this permission. Transport must keep the wire
// value out of logs, telemetry, persistence and implicit serialization.
func (t Token) Reveal() (string, error) {
	if t.state == nil {
		return "", ErrInvalidRequest
	}
	if !t.state.revealed.CompareAndSwap(false, true) {
		return "", ErrAlreadyRevealed
	}
	return t.state.wire, nil
}

// Format redacts all formatting verbs, including Go-syntax diagnostics.
func (Token) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "oauthserver.Token(redacted)") }

// MarshalJSON forbids automatic bearer export. Use explicit Reveal after commit.
func (Token) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }

// MarshalText forbids automatic text and map-key bearer export.
func (Token) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// TokenDigestKey owns an independent nonzero 256-bit lookup key and positive
// rotation version. Source buffers are copied; callers own their erasure. Retain
// old versions while active records/tombstones or recovery need their lookup.
// Versions must never identify different material. This is not an envelope,
// capability-signing, session, command-fingerprint or client-secret key.
type TokenDigestKey struct{ state *tokenDigestKeyState }
type tokenDigestKeyState struct {
	version  uint32
	material [32]byte
}

// NewTokenDigestKey validates/copies dedicated configuration without IO.
func NewTokenDigestKey(version uint32, material []byte) (TokenDigestKey, error) {
	if version == 0 || len(material) != 32 {
		return TokenDigestKey{}, ErrInvalidRequest
	}
	s := &tokenDigestKeyState{version: version}
	copy(s.material[:], material)
	if s.material == ([32]byte{}) {
		return TokenDigestKey{}, ErrInvalidRequest
	}
	return TokenDigestKey{state: s}, nil
}

// Version returns non-secret rotation metadata. Zero means unconfigured.
func (k TokenDigestKey) Version() uint32 {
	if k.state == nil {
		return 0
	}
	return k.state.version
}

// Format prevents automatic key disclosure for every verb.
func (TokenDigestKey) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "oauthserver.TokenDigestKey(redacted)")
}

// MarshalJSON prevents secret-key serialization.
func (TokenDigestKey) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }

// MarshalText prevents secret-key text serialization.
func (TokenDigestKey) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// TokenScope binds a lookup to trusted issuer/environment, exact client and one
// protocol purpose. These are server configuration/registered-client values,
// never authority selected from unverified token claims. The row reached by a
// digest must separately preserve/check its tenant, owner, actor and grant.
type TokenScope struct {
	Issuer                Issuer
	Environment, ClientID string
	Kind                  TokenKind
}

// TokenDigest is a non-bearer keyed lookup commitment. Persist version and sum
// together; neither authenticates a grant without current durable state. Avoid
// exposing stable commitments as correlation identifiers or alternate bearers.
type TokenDigest struct {
	KeyVersion uint32
	Sum        [32]byte
}

// Format suppresses stable correlation values in diagnostics.
func (TokenDigest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "oauthserver.TokenDigest(redacted)")
}

// Digest uses standard HMAC-SHA-256, domain separation and unambiguous length
// framing, not new cryptography. The version, exact issuer/environment/client,
// closed purpose and decoded 32-byte bearer are bound. No raw bearer is retained
// by the result. This pure concurrent-safe operation does not reveal custody,
// check durable use/expiry, authorize the client, or refresh validity evidence.
func (t Token) Digest(key TokenDigestKey, scope TokenScope) (TokenDigest, error) {
	if t.state == nil || key.state == nil || !validOrigin(scope.Issuer.value) || !identifier(scope.Environment) || !identifier(scope.ClientID) || scope.Kind < TokenContinuation || scope.Kind > TokenRefresh {
		return TokenDigest{}, ErrInvalidRequest
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(t.state.wire)
	if err != nil || len(raw) != 32 {
		return TokenDigest{}, ErrInvalidRequest
	}
	defer clear(raw)
	h := hmac.New(sha256.New, key.state.material[:])
	_, _ = h.Write([]byte("golib-oauth-token-digest-v1\x00"))
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], key.state.version)
	_, _ = h.Write(version[:])
	for _, value := range []string{scope.Issuer.value, scope.Environment, scope.ClientID} {
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(value)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(value))
	}
	_, _ = h.Write([]byte{byte(scope.Kind)})
	_, _ = h.Write(raw)
	result := TokenDigest{KeyVersion: key.state.version}
	copy(result.Sum[:], h.Sum(nil))
	return result, nil
}
