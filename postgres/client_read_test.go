package oauthpostgres

import (
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
)

func cursorReadFixture() (*Store, oauth.ClientReadExecution, string) {
	owner, _ := oauth.NewPlatformOwner("platform")
	scopes, _ := oauth.NewScopeCatalog([]string{"identity:read"})
	policy := &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: scopes}
	s := &Store{config: Config{Protocol: oauth.Config{ManagedClients: policy}, IntentKey: [32]byte{1}}}
	e := oauth.ClientReadExecution{Request: oauth.ClientReadRequest{Owner: owner, TenantID: "tenant", Limit: 1}}
	return s, e, "managed.abcdefghijklmnopqrstuw"
}

func TestClientReadCursorAuthenticatesEveryScopeAndRejectsMalformedInput(t *testing.T) {
	s, e, id := cursorReadFixture()
	wire := s.encodeClientReadCursor(id, e, "manager")
	e.Request.Cursor, _ = oauth.ParseCursor(wire)
	if got, err := s.clientReadCursor(e, "manager"); err != nil || got != id {
		t.Fatal("cursor positive control", err)
	}
	for _, mode := range []string{"actor", "tenant", "owner", "limit", "policy", "configuration", "key", "forged", "short", "long", "id"} {
		t.Run(mode, func(t *testing.T) {
			s, e, _ := cursorReadFixture()
			e.Request.Cursor, _ = oauth.ParseCursor(wire)
			actor := identity.UserID("manager")
			switch mode {
			case "actor":
				actor = "another"
			case "tenant":
				e.Request.TenantID = "another"
			case "owner":
				e.Request.Owner, _ = oauth.NewPlatformOwner("another")
			case "limit":
				e.Request.Limit = 2
			case "policy":
				s.config.Protocol.ManagedClients.Redirects[0] = "https://changed.example/cb"
			case "configuration":
				s.identity[0]++
			case "key":
				s.config.IntentKey[0]++
			case "forged":
				e.Request.Cursor, _ = oauth.ParseCursor(wire[:len(wire)-1] + "!")
			case "short":
				e.Request.Cursor, _ = oauth.ParseCursor("x")
			case "long":
				e.Request.Cursor, _ = oauth.ParseCursor(strings.Repeat("x", 512))
			case "id":
				e.Request.Cursor, _ = oauth.ParseCursor("foreign." + wire[len("managed."):])
			}
			if id, err := s.clientReadCursor(e, actor); err == nil || id != "" {
				t.Fatal("cursor crossed authenticated scope")
			}
		})
	}
}

func FuzzClientReadCursor(f *testing.F) {
	s, e, id := cursorReadFixture()
	valid := s.encodeClientReadCursor(id, e, "manager")
	for _, seed := range []string{"", "x", valid, valid + "x", strings.Repeat("x", 512)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		cursor, err := oauth.ParseCursor(wire)
		if err != nil {
			return
		}
		copy := e
		copy.Request.Cursor = cursor
		got, err := s.clientReadCursor(copy, "manager")
		if err == nil && (wire != "" && wire != valid || wire == valid && got != id || wire == "" && got != "") {
			t.Fatal("unauthenticated cursor accepted")
		}
		if got, err := s.clientReadCursor(copy, "another"); wire != "" && (err == nil || got != "") {
			t.Fatal("cursor accepted for another actor")
		}
	})
}
