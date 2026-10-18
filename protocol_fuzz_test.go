package oauthserver_test

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	oauth "github.com/faustbrian/go-oauth-server"
)

func FuzzAuthorizationQuery(f *testing.F) {
	f.Add("response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&scope=identity%3Aread&state=original&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=https%3A%2F%2Fresource.example")
	for _, seed := range []string{"", "%zz", "scope=a&scope=b", strings.Repeat("x", 16385), "response_type=token&nonce=foreign"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		r, err := oauth.ParseAuthorizationQuery(raw)
		if err != nil {
			if !errors.Is(err, oauth.ErrInvalidRequest) {
				t.Fatal("unexpected parser error")
			}
			return
		}
		if len(raw) > 16384 || len(strings.Join(r.Scopes, " ")) > 1024 {
			t.Fatal("parser widened input budget")
		}
		q := url.Values{"response_type": {"code"}, "client_id": {r.ClientID}, "redirect_uri": {r.RedirectURI}, "scope": {strings.Join(r.Scopes, " ")}, "state": {r.State}, "code_challenge": {r.CodeChallenge}, "code_challenge_method": {"S256"}, "resource": {r.Resource}}
		copy, err := oauth.ParseAuthorizationQuery(q.Encode())
		if err != nil || !reflect.DeepEqual(copy, r) {
			t.Fatal("authorization projection is not stable")
		}
		if _, err := oauth.ParseAuthorizationQuery(raw + "&client_id=foreign"); err == nil {
			t.Fatal("duplicate identity channel accepted")
		}
	})
}

func FuzzTokenForm(f *testing.F) {
	f.Add("grant_type=authorization_code&client_id=public-client&code=ccccccccccccccccccccccccccccccccccccccccccc&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	f.Add("grant_type=refresh_token&client_id=public-client&refresh_token=ccccccccccccccccccccccccccccccccccccccccccc&scope=identity%3Aread")
	for _, seed := range []string{"", "%zz", "grant_type=refresh_token&grant_type=authorization_code", strings.Repeat("x", 16385), "grant_type=password&client_id=public-client"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		r, err := oauth.ParseTokenForm(raw)
		if err != nil {
			if !errors.Is(err, oauth.ErrInvalidRequest) && !errors.Is(err, oauth.ErrUnsupportedGrant) {
				t.Fatal("unexpected parser error")
			}
			return
		}
		if len(raw) > 16384 || r.Network != "" || len(strings.Join(r.Scopes, " ")) > 1024 {
			t.Fatal("parser widened trusted input or size")
		}
		q := url.Values{"grant_type": {string(r.GrantType)}, "client_id": {r.ClientID}}
		if r.Resource != "" {
			q.Set("resource", r.Resource)
		}
		switch r.GrantType {
		case oauth.AuthorizationCodeGrant:
			q.Set("code", r.Code)
			q.Set("redirect_uri", r.RedirectURI)
			q.Set("code_verifier", r.CodeVerifier)
		case oauth.RefreshTokenGrant:
			q.Set("refresh_token", r.RefreshToken)
			if r.Scopes != nil {
				q.Set("scope", strings.Join(r.Scopes, " "))
			}
		default:
			t.Fatal("parser opened an unselected grant")
		}
		copy, err := oauth.ParseTokenForm(q.Encode())
		if err != nil || !reflect.DeepEqual(copy, r) {
			t.Fatal("token projection is not stable")
		}
		if _, err := oauth.ParseTokenForm(raw + "&network=trusted"); err == nil {
			t.Fatal("form supplied trusted network attribution")
		}
	})
}
