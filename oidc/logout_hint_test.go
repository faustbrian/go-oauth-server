package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

type hintVerificationKey struct {
	oauth.SigningLifecycle
	key oauth.PublicSigningKey
}

func (k hintVerificationKey) VerificationSigningKey(_ context.Context, kid string) (oauth.PublicSigningKey, error) {
	if k.key.Kid != kid {
		return oauth.PublicSigningKey{}, oauth.ErrAccessDenied
	}
	return k.key, nil
}

func TestEndSessionHintUsesVerifiedIssuerAudienceAndHistoricalPolicy(t *testing.T) {
	now := time.Date(2026, 10, 23, 3, 0, 0, 0, time.UTC)
	clock := clockFunc(func() time.Time { return now })
	authority, _ := oauth.NewSigningAuthority(clock, time.Minute)
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = authority.AddKey("original", private)
	keys, _ := authority.PublicKeys(context.Background())
	_ = authority.Activate("original")
	signer, _ := oauth.NewSigningService(authority, hintVerificationKey{key: keys[0]})
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	s := &Service{config: Config{Issuer: issuer, Signing: signer, Clock: clock}}
	claims := idClaims{Issuer: issuer.String(), Subject: "opaque-subject", Audience: "client", AuthorizedParty: "client", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Second).Unix(), AuthTime: now.Add(-time.Minute).Unix(), Methods: []string{"pwd"}}
	sign := func(c idClaims) string {
		raw, _ := json.Marshal(c)
		wire, err := authority.SignCompact(context.Background(), raw, now.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	wire := sign(claims)
	got, err := s.endSessionHint(context.Background(), EndSessionParameters{IDTokenHint: wire, ClientID: "client"})
	if err != nil || got.ClientID != "client" || got.Subject != "opaque-subject" || got.Hint.KeyID() != "original" {
		t.Fatal("genuine verified hint denied", err)
	}
	for _, alter := range []func(*idClaims){
		func(c *idClaims) { c.Issuer = "https://foreign.example" },
		func(c *idClaims) { c.AuthorizedParty = "other" },
		func(c *idClaims) { c.Subject = "" },
		func(c *idClaims) { c.AuthTime = c.IssuedAt + 1 },
		func(c *idClaims) { c.IssuedAt++ },
		func(c *idClaims) { c.ExpiresAt = c.IssuedAt },
		func(c *idClaims) { c.Methods = []string{"unselected"} },
	} {
		invalid := claims
		alter(&invalid)
		if _, err := s.endSessionHint(context.Background(), EndSessionParameters{IDTokenHint: sign(invalid)}); err == nil {
			t.Fatal("invalid signed OIDC binding admitted")
		}
	}
	if _, err := s.endSessionHint(context.Background(), EndSessionParameters{IDTokenHint: wire, ClientID: "foreign"}); err == nil {
		t.Fatal("caller replaced verified audience")
	}
	// Expiry is not fresh authority. This selected §2 historical policy keeps
	// the exact cryptographic/issued proof; native current-source admission is
	// still mandatory and tested through the genuine PostgreSQL consumer.
	now = now.Add(2 * time.Second)
	if _, err := s.endSessionHint(context.Background(), EndSessionParameters{IDTokenHint: wire}); err != nil {
		t.Fatal("eligible historical hint rejected merely for exp", err)
	}
}

func TestLogoutEndpointCannotBeSelectedWithoutNativeOwner(t *testing.T) {
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	for _, target := range []string{"https://issuer.example/logout", "https://foreign.example/logout", "https://issuer.example/token?next=evil"} {
		_, err := NewService(Config{Issuer: issuer, JWKSURI: issuer.String() + "/keys", UserInfoEndpoint: issuer.String() + "/userinfo", EndSessionEndpoint: target, Signing: &oauth.SigningService{}, SubjectKey: [32]byte{1}, Clock: clockFunc(time.Now), MaximumDuration: time.Second}, &oauth.Service{})
		if err == nil {
			t.Fatal("logout advertised without actual selected native owner")
		}
	}
}
