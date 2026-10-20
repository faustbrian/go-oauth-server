package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
)

type clockFunc func() time.Time

func (f clockFunc) Now() time.Time { return f() }

func isolatedClaimsService(c Config) *Service {
	derive, _ := opaqueHMAC(c.SubjectKey, "golib.oidc.public-subject.v1\x00")
	clear(c.SubjectKey[:])
	return &Service{config: c, publicSubject: derive}
}

// The child test isolates NumericDate projection; native lifecycle/commit
// behavior has separate real PostgreSQL consumers.
type acceptingReservation struct{ oauth.SigningLifecycle }

func (acceptingReservation) ReserveSigningKey(context.Context, string, time.Time) error { return nil }

func TestClaimsRequiresFutureRepresentableNumericDate(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 500_000_000, time.UTC)
	clock := clockFunc(func() time.Time { return now })
	authority, err := oauth.NewSigningAuthority(clock, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.AddKey("test", key); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.PublicKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := authority.Activate("test"); err != nil {
		t.Fatal(err)
	}
	signer, err := oauth.NewSigningService(authority, acceptingReservation{})
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	s := isolatedClaimsService(Config{Issuer: issuer, SubjectKey: [32]byte{1}, Signing: signer, Clock: clock, MaximumDuration: time.Second})
	in := oauth.OIDCClaimsInput{Issuer: issuer, TenantID: "tenant", UserID: "user", ClientID: "client", Scopes: []string{"openid"}, IssuedAt: now, ExpiresAt: now.Add(400 * time.Millisecond), AuthenticatedAt: now.Add(-time.Minute)}
	if out, err := s.Claims(context.Background(), in); !errors.Is(err, oauth.ErrAccessDenied) || out.Subject != "" {
		t.Fatal("already-expired encoded exp was signed", err)
	}
	in.ExpiresAt = now.Add(time.Second)
	out, err := s.Claims(context.Background(), in)
	if err != nil {
		t.Fatal("representable expiry denied", err)
	}
	wire, err := out.IDToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	claims, err := base64.RawURLEncoding.DecodeString(strings.Split(wire, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(claims, &decoded) != nil || !now.Before(time.Unix(decoded.Exp, 0)) || time.Unix(decoded.Exp, 0).After(in.ExpiresAt) {
		t.Fatal("encoded expiry is not future and bounded by native ceiling")
	}
}

func TestPublicSubjectAndUserInfoProjectionAreScopeAndIssuerBound(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	s := isolatedClaimsService(Config{Issuer: issuer, SubjectKey: [32]byte{1}, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second})
	if fmt.Sprintf("%#v", s) != "oidc.Service(redacted)" {
		t.Fatal("service diagnostics traversed private subject custody")
	}
	in := oauth.OIDCClaimsInput{Issuer: issuer, TenantID: "tenant", UserID: "user", ClientID: "client", Scopes: []string{"openid"}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), AuthenticatedAt: now.Add(-time.Minute), UserInfo: true}
	in.ExpectedSubject = s.subject(in)
	first, err := s.Claims(context.Background(), in)
	if err != nil || first.Subject == "user" || first.Subject == "" {
		t.Fatal("public subject projection invalid", err)
	}
	otherClient := in
	otherClient.ClientID = "other"
	if s.subject(otherClient) != first.Subject {
		t.Fatal("public subject became pairwise")
	}
	otherTenant := in
	otherTenant.TenantID = "foreign"
	if s.subject(otherTenant) == first.Subject {
		t.Fatal("public subject links tenant identity namespaces")
	}
	for _, alter := range []func(*oauth.OIDCClaimsInput){func(i *oauth.OIDCClaimsInput) { i.ExpectedSubject = "foreign" }, func(i *oauth.OIDCClaimsInput) { i.Scopes = []string{"identity:read"} }, func(i *oauth.OIDCClaimsInput) { i.Scopes = []string{"openid", "email"} }, func(i *oauth.OIDCClaimsInput) { i.Issuer, _ = oauth.NewIssuer("https://foreign.example") }, func(i *oauth.OIDCClaimsInput) { i.ExpiresAt = now }, func(i *oauth.OIDCClaimsInput) { i.AuthenticatedAt = now.Add(time.Second) }} {
		changed := in
		alter(&changed)
		if out, err := s.Claims(context.Background(), changed); !errors.Is(err, oauth.ErrAccessDenied) || out.Subject != "" {
			t.Fatal("invalid UserInfo authority projected claims")
		}
	}
}

func FuzzUserInfoClaimBounds(f *testing.F) {
	f.Add("tenant", "user", "nonce", "openid")
	f.Add("", "user", "", "email")
	f.Fuzz(func(t *testing.T, tenant, user, nonce, scope string) {
		now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
		issuer, _ := oauth.NewIssuer("https://issuer.example")
		s := isolatedClaimsService(Config{Issuer: issuer, SubjectKey: [32]byte{1}, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second})
		in := oauth.OIDCClaimsInput{Issuer: issuer, TenantID: identity.TenantID(tenant), UserID: identity.UserID(user), ClientID: "client", Scopes: []string{scope}, Nonce: nonce, IssuedAt: now, ExpiresAt: now.Add(time.Minute), AuthenticatedAt: now, UserInfo: true}
		if len(tenant) <= 128 && len(user) <= 128 {
			in.ExpectedSubject = s.subject(in)
		}
		out, err := s.Claims(context.Background(), in)
		if err == nil && (out.Subject == "" || scope != "openid" || len(nonce) > 256 || len(tenant) < 1 || len(tenant) > 128 || len(user) < 1 || len(user) > 128) {
			t.Fatal("hostile UserInfo accepted")
		}
	})
}
