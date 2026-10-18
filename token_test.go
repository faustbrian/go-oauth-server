package oauthserver_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	oauthserver "github.com/faustbrian/go-oauth-server"
)

func TestOAuthTokenOwnsRevealOnceWithoutLeaking(t *testing.T) {
	token, err := oauthserver.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	copy := token
	wire, err := token.Reveal()
	if err != nil || len(wire) != 43 {
		t.Fatal("fresh owned token not revealed", err)
	}
	if again, err := copy.Reveal(); !errors.Is(err, oauthserver.ErrAlreadyRevealed) || again != "" {
		t.Fatal("copied custody revealed again")
	}
	if bytes.Contains([]byte(fmt.Sprintf("%#v %+v %s", token, token, token)), []byte(wire)) {
		t.Fatal("token disclosed in formatting")
	}
	if _, err := json.Marshal(token); err == nil {
		t.Fatal("token automatically serialized")
	}
	parsed, err := oauthserver.ParseToken(wire)
	if err != nil {
		t.Fatal("possessed wire cannot be explicitly parsed", err)
	}
	var successes atomic.Uint32
	var wait sync.WaitGroup
	for range 8 {
		wait.Go(func() {
			if _, err := parsed.Reveal(); err == nil {
				successes.Add(1)
			}
		})
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatal("concurrent copies do not share one delivery permission")
	}
}

func TestOAuthTokenLookupIsKeyedAndPurposeIssuerClientBound(t *testing.T) {
	key, err := oauthserver.NewTokenDigestKey(3, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := oauthserver.ParseToken(strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := oauthserver.NewIssuer("https://issuer.example")
	scope := oauthserver.TokenScope{Issuer: issuer, Environment: "test", ClientID: "client", Kind: oauthserver.TokenCode}
	original, err := token.Digest(key, scope)
	if err != nil || original.KeyVersion != 3 || original.Sum == ([32]byte{}) {
		t.Fatal("invalid digest", err)
	}
	for _, mutate := range []func(*oauthserver.TokenScope){
		func(s *oauthserver.TokenScope) { s.Kind = oauthserver.TokenAccess },
		func(s *oauthserver.TokenScope) { s.Kind = oauthserver.TokenRefresh },
		func(s *oauthserver.TokenScope) { s.Kind = oauthserver.TokenContinuation },
		func(s *oauthserver.TokenScope) { s.Environment = "production" },
		func(s *oauthserver.TokenScope) { s.ClientID = "another-client" },
		func(s *oauthserver.TokenScope) { s.Issuer, _ = oauthserver.NewIssuer("https://other.example") },
	} {
		changed := scope
		mutate(&changed)
		got, err := token.Digest(key, changed)
		if err != nil || got.Sum == original.Sum {
			t.Fatal("lookup domains or authority scopes conflated")
		}
	}
	for _, wire := range []string{"", strings.Repeat("A", 42), strings.Repeat("A", 44), strings.Repeat("A", 42) + "B", strings.Repeat("A", 42) + "+"} {
		if _, err := oauthserver.ParseToken(wire); !errors.Is(err, oauthserver.ErrInvalidRequest) {
			t.Fatal("noncanonical or unbounded token parsed")
		}
	}
	if _, err := token.Digest(oauthserver.TokenDigestKey{}, scope); err == nil {
		t.Fatal("unkeyed OAuth lookup accepted")
	}
	if _, err := token.Digest(key, oauthserver.TokenScope{}); err == nil {
		t.Fatal("unbound OAuth lookup accepted")
	}
}
