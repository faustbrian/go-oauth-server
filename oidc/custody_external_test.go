package oidc_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

type custodyClock struct{}

func (custodyClock) Now() time.Time { return time.Now() }

func TestSubjectPolicyNestedDiagnosticsCannotTraversePlaintextCustody(t *testing.T) {
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	keys, err := keyring.New(map[string][]byte{"wrapping": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	material := [32]byte{0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79}
	aad, _ := envelope.NewContext(map[string]string{"profile": "golib.oidc.pairwise-key.v1", "issuer": issuer.String(), "environment": "test", "policy_id": "subjects", "policy_version": "1", "key_version": "1"})
	sealed, err := cipher.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: material[:], KeyReference: "wrapping", Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := op.NewSubjectPolicy(context.Background(), op.SubjectPolicyConfig{Issuer: issuer, Environment: "test", PolicyID: "subjects", PolicyVersion: 1, ActiveKeyVersion: 1, Keys: []op.SubjectKeyEnvelope{{Version: 1, Envelope: wire}}}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	key, err := policy.KeyRegistration(1)
	if err != nil {
		t.Fatal(err)
	}
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	candidate := oauth.OIDCSubjectCandidate{Registration: registration, Subject: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE", KeyVersion: 1, KeyCommitment: key.Commitment}
	// No protocol operation is exercised here: the public constructor retains
	// these borrowed pointers, and the boundary under test is owned key custody.
	service, err := op.NewService(op.Config{Issuer: issuer, JWKSURI: issuer.String() + "/jwks", UserInfoEndpoint: issuer.String() + "/userinfo", SubjectKey: material, SubjectPolicy: policy, Clock: custodyClock{}, MaximumDuration: time.Second, Signing: new(oauth.SigningService)}, new(oauth.Service))
	if err != nil {
		t.Fatal(err)
	}
	// fmt cannot invoke a formatter through an external unexported wrapper
	// field. Dereferenced policies must remain opaque even on that path.
	for _, test := range []struct {
		name  string
		value any
	}{
		{"policy", struct{ policy op.SubjectPolicy }{*policy}},
		{"key-registration", struct {
			registration oauth.OIDCSubjectKeyRegistration
		}{key}},
		{"candidate", struct{ candidate oauth.OIDCSubjectCandidate }{candidate}},
		{"service", struct{ service op.Service }{*service}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, format := range []string{"%v", "%+v", "%#v"} {
				if strings.Contains(fmt.Sprintf(format, test.value), fmt.Sprintf(format, material)) {
					t.Fatal("nested diagnostics traversed synthetic plaintext key custody")
				}
			}
		})
	}
}

func TestConstructedServicePreservesPublicSubjectBytes(t *testing.T) {
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	c := op.Config{Issuer: issuer, JWKSURI: issuer.String() + "/jwks", UserInfoEndpoint: issuer.String() + "/userinfo", SubjectKey: [32]byte{1}, Clock: custodyClock{}, MaximumDuration: time.Second, Signing: new(oauth.SigningService)}
	service, err := op.NewService(c, new(oauth.Service))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// Fixed vector from the original public HMAC domain and length framing,
	// independently calculated rather than obtained from this implementation.
	const original = "jYxisinDX3COWgFeEOiMG7JpcwSy0y8JSXDK3oJyqr0"
	out, err := service.Claims(context.Background(), oauth.OIDCClaimsInput{Issuer: issuer, TenantID: "tenant", UserID: "user", ClientID: "client", ExpectedSubject: original, Scopes: []string{"openid"}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), AuthenticatedAt: now.Add(-time.Minute), UserInfo: true})
	if err != nil || out.Subject != original || c.SubjectKey != ([32]byte{1}) {
		t.Fatal("constructed service changed public subject bytes or caller-owned input", err)
	}
}
