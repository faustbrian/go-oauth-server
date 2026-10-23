package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestEndSessionQueryIsClosedBoundedAndPreservesOpaqueState(t *testing.T) {
	values := url.Values{"id_token_hint": {"header.payload.signature"}, "client_id": {"client"}, "post_logout_redirect_uri": {"https://client.example/out?view=original"}, "state": {"opaque +/%?=&"}}
	parameters, err := ParseEndSessionQuery(values.Encode())
	if err != nil || parameters.IDTokenHint != "header.payload.signature" || parameters.ClientID != "client" || parameters.PostLogoutRedirectURI != values.Get("post_logout_redirect_uri") || parameters.State != values.Get("state") {
		t.Fatal("logout input changed original protocol bytes", err)
	}
	if strings.Contains(fmt.Sprintf("%#v", parameters), "opaque") || strings.Contains(fmt.Sprintf("%#v", parameters), "payload") {
		t.Fatal("logout hint/state leaked through diagnostics")
	}
	for _, mode := range []string{"hint-missing", "hint-empty", "hint-limit", "duplicate-hint", "duplicate-state", "unknown", "empty-uri", "oversize-state", "malformed", "oversize-query"} {
		copy := url.Values{}
		for k, v := range values {
			copy[k] = append([]string(nil), v...)
		}
		switch mode {
		case "hint-missing":
			copy.Del("id_token_hint")
		case "hint-empty":
			copy.Set("id_token_hint", "")
		case "hint-limit":
			copy.Set("id_token_hint", strings.Repeat("x", 16385))
		case "duplicate-hint":
			copy.Add("id_token_hint", "other.payload.signature")
		case "duplicate-state":
			copy.Add("state", "other")
		case "unknown":
			copy.Set("session_id", "caller-chosen")
		case "empty-uri":
			copy.Set("post_logout_redirect_uri", "")
		case "oversize-state":
			copy.Set("state", strings.Repeat("x", 1025))
		}
		query := copy.Encode()
		if mode == "malformed" {
			query += "%GG"
		}
		if mode == "oversize-query" {
			query = strings.Repeat("x", 65537)
		}
		if _, err := ParseEndSessionQuery(query); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("unselected or hostile logout input admitted", mode, err)
		}
	}
	local, err := ParseEndSessionQuery("id_token_hint=header.payload.signature")
	if err != nil || local.ClientID != "" || local.PostLogoutRedirectURI != "" || local.State != "" {
		t.Fatal("absent optional parameters manufactured authority", err)
	}
}

func FuzzEndSessionQuery(f *testing.F) {
	for _, seed := range []string{"", "id_token_hint=header.payload.signature", "id_token_hint=header.payload.signature&state=opaque+%2B%2F%25", "id_token_hint=a.b.c&id_token_hint=d.e.f", "id_token_hint=%GG", "session_id=caller-selected", strings.Repeat("x", 65537)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := ParseEndSessionQuery(raw)
		if err != nil {
			return
		}
		values, err := url.ParseQuery(raw)
		if err != nil || len(raw) > 65536 || len(values) == 0 || len(values) > 4 {
			t.Fatal("malformed/unbounded input admitted")
		}
		for key, entries := range values {
			if len(entries) != 1 {
				t.Fatal("duplicate field admitted")
			}
			switch key {
			case "id_token_hint", "client_id", "post_logout_redirect_uri", "state":
			default:
				t.Fatal("unknown field admitted")
			}
		}
		if got.IDTokenHint != values.Get("id_token_hint") || got.ClientID != values.Get("client_id") || got.PostLogoutRedirectURI != values.Get("post_logout_redirect_uri") || got.State != values.Get("state") || len(got.IDTokenHint) == 0 || len(got.IDTokenHint) > 16384 || len(got.State) > 1024 {
			t.Fatal("accepted logout input changed original bytes or bounds")
		}
	})
}
