package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// SubjectKeyEnvelope carries one independently versioned, dedicated 256-bit
// HMAC key encrypted by secret-envelope/v2. Envelope is the binary persistence
// representation with exact subject-policy AAD, not plaintext key material.
// Constructors borrow/copy its bytes; never mutate concurrently with a call.
type SubjectKeyEnvelope struct {
	Version  uint32
	Envelope []byte
}

func (SubjectKeyEnvelope) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oidc.SubjectKeyEnvelope(redacted)"))
}
func (SubjectKeyEnvelope) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }
func (SubjectKeyEnvelope) MarshalText() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

// SubjectPolicyConfig selects immutable issuer/environment policy identity and
// 1..8 retained derivation-key envelopes. ActiveKeyVersion selects only new
// binding candidates: durable subjects are never rederived on key rotation.
// The native owner must stage/activate the same authenticated key registration
// before it will accept a new binding. Loading a child alone activates nothing.
type SubjectPolicyConfig struct {
	Issuer                oauth.Issuer
	Environment, PolicyID string
	PolicyVersion         uint64
	ActiveKeyVersion      uint32
	Keys                  []SubjectKeyEnvelope
}

func (SubjectPolicyConfig) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oidc.SubjectPolicyConfig(redacted)"))
}
func (SubjectPolicyConfig) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }
func (SubjectPolicyConfig) MarshalText() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

type subjectKey struct {
	derive       func([]string) string
	erase        func()
	registration oauth.OIDCSubjectKeyRegistration
}

// SubjectPolicy owns authenticated in-memory HMAC keys for its lifetime and
// immutable copied envelope custody. It owns no provider/resources/background
// work. Copies of its pointer are safe for concurrent calls. Diagnostics redact.
type SubjectPolicy struct {
	issuer                oauth.Issuer
	environment, policyID string
	version               uint64
	active                uint32
	keys                  map[uint32]subjectKey
}

func (*SubjectPolicy) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oidc.SubjectPolicy(redacted)"))
}
func (*SubjectPolicy) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }
func (*SubjectPolicy) MarshalText() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

// NewSubjectPolicy authenticates every retained envelope using an explicit
// borrowed concurrent-safe envelope service. The call has a five-second ceiling
// and honors an earlier ctx deadline; provider/decryption failure denies rather
// than creating a fallback key. Associated data is profile, issuer, environment,
// policy_id, policy_version and key_version, with decimal version text. Each
// plaintext must be exactly 32 nonzero bytes and is cleared after the owned copy.
// Persist the original key envelopes: generating replacements resets identities
// not yet materialized by native bindings and is not a custody migration.
func NewSubjectPolicy(ctx context.Context, c SubjectPolicyConfig, cipher *envelope.Service) (*SubjectPolicy, error) {
	if ctx == nil || cipher == nil || c.Issuer.String() == "" || !policyIdentifier(c.Environment) || !policyIdentifier(c.PolicyID) || c.PolicyVersion == 0 || c.ActiveKeyVersion == 0 || len(c.Keys) < 1 || len(c.Keys) > 8 {
		return nil, oauth.ErrInvalidRequest
	}
	ctx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p := &SubjectPolicy{issuer: c.Issuer, environment: strings.Clone(c.Environment), policyID: strings.Clone(c.PolicyID), version: c.PolicyVersion, active: c.ActiveKeyVersion, keys: make(map[uint32]subjectKey, len(c.Keys))}
	complete := false
	defer func() {
		if !complete {
			for _, key := range p.keys {
				key.erase()
			}
		}
	}()
	for _, supplied := range c.Keys {
		if _, duplicate := p.keys[supplied.Version]; duplicate || supplied.Version == 0 || len(supplied.Envelope) == 0 || len(supplied.Envelope) > 16384 {
			return nil, oauth.ErrInvalidRequest
		}
		owned := append([]byte(nil), supplied.Envelope...)
		sealed, err := envelope.ParseEnvelope(owned)
		if err != nil {
			return nil, oauth.ErrAccessDenied
		}
		aad, _ := envelope.NewContext(map[string]string{"profile": "golib.oidc.pairwise-key.v1", "issuer": c.Issuer.String(), "environment": c.Environment, "policy_id": c.PolicyID, "policy_version": strconv.FormatUint(c.PolicyVersion, 10), "key_version": strconv.FormatUint(uint64(supplied.Version), 10)})
		plain, err := cipher.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, oauth.ErrAccessDenied
		}
		var material [32]byte
		if len(plain) == len(material) {
			copy(material[:], plain)
		}
		clear(plain)
		if material == ([32]byte{}) {
			return nil, oauth.ErrAccessDenied
		}
		derive, erase := subjectDeriver(material)
		p.keys[supplied.Version] = subjectKey{derive: derive, erase: erase, registration: oauth.OIDCSubjectKeyRegistration{Issuer: c.Issuer, Environment: p.environment, PolicyID: p.policyID, PolicyVersion: c.PolicyVersion, KeyVersion: supplied.Version, Commitment: sha256.Sum256(material[:]), Envelope: owned}}
		clear(material[:])
	}
	if _, exists := p.keys[p.active]; !exists {
		return nil, oauth.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	complete = true
	return p, nil
}

// KeyRegistration returns independently owned encrypted custody and material
// commitment for native durable staging. It reveals no plaintext and does not
// activate a key. Unknown/retired-from-this-policy versions deny.
func (p *SubjectPolicy) KeyRegistration(version uint32) (oauth.OIDCSubjectKeyRegistration, error) {
	if p == nil {
		return oauth.OIDCSubjectKeyRegistration{}, oauth.ErrInvalidRequest
	}
	key, exists := p.keys[version]
	if !exists {
		return oauth.OIDCSubjectKeyRegistration{}, oauth.ErrAccessDenied
	}
	out := key.registration
	out.Envelope = append([]byte(nil), out.Envelope...)
	return out, nil
}

func policyIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i := range len(value) {
		b := value[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '_' || b == '-') {
			return false
		}
	}
	return true
}

func (p *SubjectPolicy) matches(registration *oauth.OIDCSubjectRegistration, environment string) bool {
	return p != nil && registration != nil && registration.PolicyID() == p.policyID && registration.PolicyVersion() == p.version && environment == p.environment
}

func (p *SubjectPolicy) derive(tenant, user, sector string) string {
	key := p.keys[p.active]
	// OIDC Core 1.0 errata 2 section 8.1 requires distinct, non-reversible
	// sector subjects. Client IDs and key versions deliberately do not create
	// identity namespaces; existing identities come from native stored bindings.
	return key.derive([]string{p.issuer.String(), p.environment, tenant, sector, user})
}

func subjectDeriver(key [32]byte) (func([]string) string, func()) {
	return opaqueHMAC(key, "golib.oidc.pairwise-subject.v1\x00")
}

func opaqueHMAC(key [32]byte, domain string) (func([]string) string, func()) {
	// Formatter methods cannot protect values reached through external private
	// wrapper fields: fmt recursively inspects their representation. Only an
	// opaque closure retains plaintext; no struct/map field can be traversed.
	// erase is used only if construction fails, before concurrent publication.
	return func(values []string) string {
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte(domain))
		for _, value := range values {
			var length [4]byte
			binary.BigEndian.PutUint32(length[:], uint32(len(value)))
			_, _ = mac.Write(length[:])
			_, _ = mac.Write([]byte(value))
		}
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}, func() { clear(key[:]) }
}

func (s *Service) claimSubject(in oauth.OIDCClaimsInput) (string, error) {
	registration := in.SubjectRegistration
	if registration == nil {
		if in.BoundSubject != "" || s.publicSubject == nil {
			return "", oauth.ErrAccessDenied
		}
		return s.subject(in), nil
	}
	if !s.config.SubjectPolicy.matches(registration, in.Environment) {
		return "", oauth.ErrAccessDenied
	}
	if registration.SubjectType() == "public" && in.BoundSubject == "" && s.publicSubject != nil {
		return s.subject(in), nil
	}
	if registration.SubjectType() != "pairwise" || len(in.BoundSubject) != 43 {
		return "", oauth.ErrAccessDenied
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(in.BoundSubject)
	if err != nil || len(decoded) != 32 {
		return "", oauth.ErrAccessDenied
	}
	return in.BoundSubject, nil
}
