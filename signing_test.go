package oauthserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestSigningPublicationOverlapAndCompromise(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	a, err := oauth.NewSigningAuthority(clockFunc(func() time.Time { return now }), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	second, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ctx := context.Background()
	if err := a.AddKey("first", first); err != nil {
		t.Fatal(err)
	}
	if err := a.Activate("first"); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("unpublished key activated")
	}
	keys, err := a.PublicKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].Kid != "first" {
		t.Fatal("public projection missing", err)
	}
	if err := a.Activate("first"); err != nil {
		t.Fatal(err)
	}
	kid, signature, err := a.Sign(ctx, []byte("header.payload"), now.Add(time.Minute))
	raw, _ := base64.RawURLEncoding.DecodeString(signature)
	digest := sha256.Sum256([]byte("header.payload"))
	if err != nil || kid != "first" || len(raw) != 64 || !ecdsa.Verify(&first.PublicKey, digest[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
		t.Fatal("invalid ES256 signature")
	}
	if err := a.AddKey("second", second); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PublicKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Activate("second"); err != nil {
		t.Fatal(err)
	}
	if err := a.Retire("first"); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("retired before token verification window")
	}
	now = now.Add(time.Minute)
	if err := a.Retire("first"); err != nil {
		t.Fatal(err)
	}
	if err := a.Compromise("second"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Sign(ctx, []byte("header.payload"), now.Add(time.Second)); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("compromised signer usable")
	}
	keys, err = a.PublicKeys(ctx)
	if err != nil || len(keys) != 0 {
		t.Fatal("retired/compromised key published")
	}
}
