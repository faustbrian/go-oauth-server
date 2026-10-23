package oauthserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

// This isolates cryptographic admission and the read-only lifecycle seam; real
// native key/issued-hint/source-session custody is proved by PostgreSQL consumers.
type retainedVerificationKey struct {
	oauth.SigningLifecycle
	key    oauth.PublicSigningKey
	denied bool
	reads  int
}

func (l *retainedVerificationKey) VerificationSigningKey(_ context.Context, kid string) (oauth.PublicSigningKey, error) {
	l.reads++
	if l.denied || kid != l.key.Kid {
		return oauth.PublicSigningKey{}, oauth.ErrAccessDenied
	}
	return l.key, nil
}

func TestCompactVerificationRetainsHistoricalKeysWithoutClaimAuthority(t *testing.T) {
	now := time.Date(2026, 10, 23, 2, 0, 0, 0, time.UTC)
	authority, err := oauth.NewSigningAuthority(clockFunc(func() time.Time { return now }), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if authority.AddKey("original", private) != nil {
		t.Fatal("original key setup")
	}
	keys, err := authority.PublicKeys(context.Background())
	if err != nil || authority.Activate("original") != nil {
		t.Fatal("original publication setup", err)
	}
	payload := []byte(`{"iss":"https://issuer.example","exp":1}`)
	wire, err := authority.SignCompact(context.Background(), payload, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := &retainedVerificationKey{key: keys[0]}
	signer, _ := oauth.NewSigningService(authority, lifecycle)
	verified, err := signer.VerifyCompact(context.Background(), wire)
	if err != nil || verified.KeyID() != "original" || string(verified.Payload()) != string(payload) {
		t.Fatal("genuine compact signature denied", err)
	}
	copy := verified.Payload()
	copy[0] = 'x'
	if string(verified.Payload()) != string(payload) {
		t.Fatal("verified payload aliases caller memory")
	}
	// Verification does not enforce OIDC exp: RP-Initiated Logout §2 permits
	// eligible historical hints, but native source-session binding is mandatory.
	now = now.Add(2 * time.Second)
	successor, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = authority.AddKey("successor", successor)
	_, _ = authority.PublicKeys(context.Background())
	_ = authority.Activate("successor")
	if authority.Retire("original") != nil {
		t.Fatal("original retirement setup")
	}
	if _, err := signer.VerifyCompact(context.Background(), wire); err != nil {
		t.Fatal("retained retired signature no longer verifiable", err)
	}
	// Historical public verification must not require restoring a retired
	// private key on a fresh process. The native read-only owner retains only
	// eligible public material; it remains the independent compromise fence.
	freshAuthority, _ := oauth.NewSigningAuthority(clockFunc(func() time.Time { return now }), time.Minute)
	freshSigner, _ := oauth.NewSigningService(freshAuthority, lifecycle)
	if _, err := freshSigner.VerifyCompact(context.Background(), wire); err != nil {
		t.Fatal("fresh verifier required retired private custody", err)
	}
	lifecycle.denied = true
	if _, err := signer.VerifyCompact(context.Background(), wire); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("native compromise/unavailable verification authority ignored", err)
	}
	lifecycle.denied = false
	parts := strings.Split(wire, ".")
	parts[1] = "e30"
	if _, err := signer.VerifyCompact(context.Background(), strings.Join(parts, ".")); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("tampered signed payload verified", err)
	}
	for _, hostile := range []string{"", strings.Repeat("x", 16385), "a.b.c.d", strings.Replace(wire, ".", "\n.", 1), base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"original"}`)) + ".e30." + strings.Repeat("A", 86), base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","alg":"ES256","typ":"JWT","kid":"original"}`)) + ".e30." + strings.Repeat("A", 86)} {
		before := lifecycle.reads
		if _, err := signer.VerifyCompact(context.Background(), hostile); err == nil || lifecycle.reads != before {
			t.Fatal("hostile compact input reached verification owner or succeeded")
		}
	}
}

func TestCompactVerificationRejectsIgnoredBase64LineBreakBeforeOwner(t *testing.T) {
	authority, _ := oauth.NewSigningAuthority(clockFunc(time.Now), time.Minute)
	owner := &retainedVerificationKey{key: oauth.PublicSigningKey{Kid: "original"}}
	signer, _ := oauth.NewSigningService(authority, owner)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT","kid":"original"}`))
	wire := header + "\n.e30." + strings.Repeat("A", 86)
	if _, err := signer.VerifyCompact(context.Background(), wire); err == nil || owner.reads != 0 {
		t.Fatal("base64 CR/LF tolerance reached key authority")
	}
}

// Exercise the new hostile compact boundary, not OIDC issuance or session
// authority. Every accepted proof must retain the exact bounded signed packet.
func FuzzCompactVerification(f *testing.F) {
	now := time.Date(2026, 10, 23, 2, 0, 0, 0, time.UTC)
	authority, _ := oauth.NewSigningAuthority(clockFunc(func() time.Time { return now }), time.Minute)
	// Publicly known, non-authoritative test material gives fuzz subprocesses
	// the same public key, so the coordinator's valid seed remains verifiable.
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult([]byte{1})
	private := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: big.NewInt(1)}
	if authority.AddKey("original", private) != nil {
		f.Fatal("fuzz key setup")
	}
	keys, _ := authority.PublicKeys(context.Background())
	if authority.Activate("original") != nil {
		f.Fatal("fuzz active key setup")
	}
	valid, err := authority.SignCompact(context.Background(), []byte(`{"test":"signature-only"}`), now.Add(time.Second))
	if err != nil {
		f.Fatal(err)
	}
	signer, _ := oauth.NewSigningService(authority, &retainedVerificationKey{key: keys[0]})
	for _, seed := range []string{"", valid, "a.b.c", valid + "\n", strings.Repeat("x", 16385)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		proof, err := signer.VerifyCompact(context.Background(), wire)
		if err != nil {
			return
		}
		parts := strings.Split(wire, ".")
		if len(wire) > 16384 || len(parts) != 3 || proof.KeyID() != "original" || proof.Digest() != sha256.Sum256([]byte(wire)) {
			t.Fatal("accepted proof lost compact identity or bounds")
		}
		payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
		if err != nil || len(payload) == 0 || len(payload) > 8192 || !json.Valid(payload) || string(payload) != string(proof.Payload()) {
			t.Fatal("accepted proof changed bounded JSON payload")
		}
		for _, b := range []byte(wire) {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.') {
				t.Fatal("accepted noncompact alphabet")
			}
		}
	})
}
