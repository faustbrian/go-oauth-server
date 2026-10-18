package oauthpostgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestConsentCursorBindsExactOwnerAndLimit(t *testing.T) {
	s := &Store{config: Config{IntentKey: [32]byte{1}}}
	const id = "abcdefghijklmnopqrstuw"
	wire := s.encodeConsentCursor(id, "tenant", "user", 2)
	if got, err := s.consentCursor(wire, "tenant", "user", 2); err != nil || got != id {
		t.Fatal("valid cursor rejected", err)
	}
	for _, change := range []struct {
		tenant, user string
		limit        uint16
	}{{"other", "user", 2}, {"tenant", "other", 2}, {"tenant", "user", 1}} {
		if _, err := s.consentCursor(wire, identity.TenantID(change.tenant), identity.UserID(change.user), change.limit); err != oauth.ErrAccessDenied {
			t.Fatal("foreign cursor admitted", err)
		}
	}
}

func FuzzConsentCursor(f *testing.F) {
	s := &Store{config: Config{IntentKey: [32]byte{1}}}
	f.Add("")
	f.Add(s.encodeConsentCursor("abcdefghijklmnopqrstuw", "tenant", "user", 2))
	f.Add("malformed")
	f.Fuzz(func(t *testing.T, wire string) {
		id, err := s.consentCursor(wire, "tenant", "user", 2)
		if err == nil && wire != "" && wire != s.encodeConsentCursor(id, "tenant", "user", 2) {
			t.Fatal("noncanonical cursor accepted")
		}
	})
}
