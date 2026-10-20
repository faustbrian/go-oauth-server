package oidc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestSubjectPolicyAuthenticatesVersionedEnvelopeAndOwnsCustody(t *testing.T) {
	ctx := context.Background()
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	keys, err := keyring.New(map[string][]byte{"wrapping": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	material := [32]byte{1, 2, 3}
	// The fixture uses the envelope owner's public API directly: changing any
	// subject-policy dimension must fail GCM authentication, not select a key.
	aad, err := envelope.NewContext(map[string]string{"profile": "golib.oidc.pairwise-key.v1", "issuer": issuer.String(), "environment": "test", "policy_id": "subjects", "policy_version": "1", "key_version": "1"})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cipher.Encrypt(ctx, envelope.EncryptRequest{Plaintext: material[:], KeyReference: "wrapping", Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	c := SubjectPolicyConfig{Issuer: issuer, Environment: "test", PolicyID: "subjects", PolicyVersion: 1, ActiveKeyVersion: 1, Keys: []SubjectKeyEnvelope{{Version: 1, Envelope: wire}}}
	policy, err := NewSubjectPolicy(ctx, c, cipher)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := policy.KeyRegistration(1)
	if err != nil || registration.Commitment != sha256.Sum256(material[:]) {
		t.Fatal("authenticated key custody has wrong material commitment", err)
	}
	wire[0] ^= 1
	registration.Envelope[0] ^= 1
	owned, err := policy.KeyRegistration(1)
	if err != nil || owned.Envelope[0] == wire[0] || owned.Envelope[0] == registration.Envelope[0] {
		t.Fatal("caller mutation changed retained envelope custody", err)
	}
	if fmt.Sprintf("%#v", policy) != "oidc.SubjectPolicy(redacted)" {
		t.Fatal("subject policy diagnostics disclose custody")
	}
	c.Keys[0].Envelope = owned.Envelope
	for _, change := range []func(*SubjectPolicyConfig){
		func(c *SubjectPolicyConfig) { c.Environment = "production" },
		func(c *SubjectPolicyConfig) { c.PolicyID = "foreign" },
		func(c *SubjectPolicyConfig) { c.PolicyVersion = 2 },
		func(c *SubjectPolicyConfig) {
			c.Keys = []SubjectKeyEnvelope{{Version: 2, Envelope: owned.Envelope}}
			c.ActiveKeyVersion = 2
		},
		func(c *SubjectPolicyConfig) { c.ActiveKeyVersion = 2 },
	} {
		altered := c
		change(&altered)
		if _, err := NewSubjectPolicy(ctx, altered, cipher); !errors.Is(err, oauth.ErrAccessDenied) && !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("foreign or missing key custody was accepted", err)
		}
	}
}

func TestPairwiseClaimsUseOriginalNativeBindingAndDenyMissingPolicy(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	derive, erase := subjectDeriver([32]byte{9})
	policy := &SubjectPolicy{issuer: issuer, environment: "test", policyID: "subjects", version: 1, active: 2, keys: map[uint32]subjectKey{2: {derive: derive, erase: erase}}}
	s := &Service{config: Config{Issuer: issuer, SubjectKey: [32]byte{1}, SubjectPolicy: policy, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second}}
	// Native bindings, not the newest HMAC key, own subjects after first use.
	original := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"
	in := oauth.OIDCClaimsInput{Issuer: issuer, Environment: "test", TenantID: "tenant", UserID: "user", ClientID: "client", SubjectRegistration: &registration, BoundSubject: original, ExpectedSubject: original, Scopes: []string{"openid"}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), AuthenticatedAt: now.Add(-time.Minute), UserInfo: true}
	out, err := s.Claims(context.Background(), in)
	if err != nil || out.Subject != original {
		t.Fatal("current writer key replaced original native binding", err)
	}
	for _, change := range []func(*oauth.OIDCClaimsInput){
		func(i *oauth.OIDCClaimsInput) { i.BoundSubject = "" },
		func(i *oauth.OIDCClaimsInput) { i.Environment = "foreign" },
		func(i *oauth.OIDCClaimsInput) {
			r, _ := oauth.NewOIDCSubjectRegistration("pairwise", "other.example", "foreign", 1)
			i.SubjectRegistration = &r
		},
		func(i *oauth.OIDCClaimsInput) { i.ExpectedSubject = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI" },
	} {
		altered := in
		change(&altered)
		if out, err := s.Claims(context.Background(), altered); !errors.Is(err, oauth.ErrAccessDenied) || out.Subject != "" {
			t.Fatal("missing or foreign original subject authority projected identity", err)
		}
	}
	s.config.SubjectPolicy = nil
	if _, err := s.Claims(context.Background(), in); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("missing policy silently fell back to public derivation", err)
	}
}

func FuzzSubjectPolicyEnvelopeBounds(f *testing.F) {
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	keys, err := keyring.New(map[string][]byte{"wrapping": make([]byte, 32)})
	if err != nil {
		f.Fatal(err)
	}
	cipher, err := envelope.NewService(keys)
	if err != nil {
		f.Fatal(err)
	}
	aad, _ := envelope.NewContext(map[string]string{"profile": "golib.oidc.pairwise-key.v1", "issuer": issuer.String(), "environment": "test", "policy_id": "subjects", "policy_version": "1", "key_version": "1"})
	material := [32]byte{1, 2, 3}
	sealed, err := cipher.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: material[:], KeyReference: "wrapping", Context: aad})
	if err != nil {
		f.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire, uint32(1), "test")
	f.Add([]byte("SEV1"), uint32(0), "foreign")
	f.Fuzz(func(t *testing.T, wire []byte, version uint32, environment string) {
		policy, err := NewSubjectPolicy(context.Background(), SubjectPolicyConfig{Issuer: issuer, Environment: environment, PolicyID: "subjects", PolicyVersion: 1, ActiveKeyVersion: version, Keys: []SubjectKeyEnvelope{{Version: version, Envelope: wire}}}, cipher)
		if err == nil {
			registration, err := policy.KeyRegistration(version)
			if err != nil || version != 1 || environment != "test" || len(wire) > 16384 || registration.Commitment != sha256.Sum256(material[:]) {
				t.Fatal("hostile/foreign envelope created policy custody")
			}
		} else if policy != nil {
			t.Fatal("failed envelope load returned partial policy")
		}
	})
}
