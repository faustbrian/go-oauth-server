package oauthserver_test

import (
	"errors"
	"maps"
	"net/url"
	"strings"
	"testing"

	oauthserver "github.com/faustbrian/go-oauth-server"
)

func TestS256MatchesRFC7636AndRejectsDowngrade(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got, err := oauthserver.S256Challenge(verifier); err != nil || got != challenge {
		t.Fatalf("official S256 vector: challenge matches=%v err=%v", got == challenge, err)
	}
	for _, value := range []string{"", strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 42) + "+", strings.Repeat("a", 42) + "\n"} {
		if _, err := oauthserver.S256Challenge(value); !errors.Is(err, oauthserver.ErrInvalidRequest) {
			t.Fatalf("invalid verifier accepted: length=%d", len(value))
		}
	}
}

func TestRedirectPolicyIsExactAndRejectsConfusion(t *testing.T) {
	const registered = "https://client.example/callback?selected=1"
	policy, err := oauthserver.NewRedirectPolicy([]string{registered})
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Allows(registered) {
		t.Fatal("exact registered redirect denied")
	}
	for _, value := range []string{"https://client.example/callback", "https://CLIENT.example/callback?selected=1", registered + "&extra=1", registered + "#fragment", "https://client.example:443/callback?selected=1"} {
		if policy.Allows(value) {
			t.Fatal("redirect normalization or expansion accepted")
		}
	}
	for _, value := range []string{"http://client.example/cb", "https://user@client.example/cb", "https://client.example/cb#fragment", "https://*.example/cb", "https://client.example\\evil/cb", "https://client.example/cb?code=existing"} {
		if _, err := oauthserver.NewRedirectPolicy([]string{value}); !errors.Is(err, oauthserver.ErrInvalidRequest) {
			t.Fatal("unsafe registered redirect accepted")
		}
	}
}

func TestAuthorizationParsingBindsScopeResourceAndS256(t *testing.T) {
	const raw = "response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&scope=identity%3Aread&state=bound-state&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=https%3A%2F%2Fresource.example"
	request, err := oauthserver.ParseAuthorizationQuery(raw)
	if err != nil || request.ClientID != "public-client" || request.Resource != "https://resource.example" || request.State != "bound-state" || len(request.Scopes) != 1 {
		t.Fatalf("valid request projection: %v", err)
	}
	for _, tail := range []string{"&client_id=other", "&scope=identity%3Awrite", "&code_challenge_method=plain", "&nonce=unselected-oidc", "&response_mode=fragment", "&actor=override", "&request_uri=https%3A%2F%2Funtrusted.example"} {
		if _, err := oauthserver.ParseAuthorizationQuery(raw + tail); !errors.Is(err, oauthserver.ErrInvalidRequest) {
			t.Fatalf("duplicate/unselected authorization field accepted: %s", strings.Split(tail, "=")[0])
		}
	}
	if _, err := oauthserver.ParseAuthorizationQuery(strings.Repeat("a", 16385)); !errors.Is(err, oauthserver.ErrInvalidRequest) {
		t.Fatal("unbounded query accepted")
	}
}

func TestTokenParsingDiscriminatesGrantBeforeCredentialUse(t *testing.T) {
	values := url.Values{"grant_type": {"authorization_code"}, "client_id": {"public-client"}, "code": {strings.Repeat("c", 43)}, "redirect_uri": {"https://client.example/cb"}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
	request, err := oauthserver.ParseTokenForm(values.Encode())
	if err != nil || request.GrantType != oauthserver.AuthorizationCodeGrant || request.Code == "" {
		t.Fatalf("code request rejected: %v", err)
	}
	for _, field := range []string{"refresh_token", "scope", "client_secret", "subject_token", "actor_token", "username", "password"} {
		copy := maps.Clone(values)
		copy[field] = []string{"must-not-be-used"}
		if _, err := oauthserver.ParseTokenForm(copy.Encode()); !errors.Is(err, oauthserver.ErrInvalidRequest) {
			t.Fatalf("foreign grant field accepted: %s", field)
		}
	}
	if _, err := oauthserver.ParseTokenForm(values.Encode() + "&code=another"); !errors.Is(err, oauthserver.ErrInvalidRequest) {
		t.Fatal("duplicate code accepted")
	}
	for _, grant := range []string{"implicit", "password", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange", "urn:golib:params:oauth:grant-type:session-jwt"} {
		if _, err := oauthserver.ParseTokenForm(url.Values{"grant_type": {grant}, "client_id": {"public-client"}}.Encode()); !errors.Is(err, oauthserver.ErrUnsupportedGrant) {
			t.Fatal("unselected grant accepted or conflated")
		}
	}
}

func TestTokenRequiredGrantDiscriminatorIsInvalidRequest(t *testing.T) {
	for _, raw := range []string{"client_id=public-client", "client_id=public-client&grant_type="} {
		if _, err := oauthserver.ParseTokenForm(raw); !errors.Is(err, oauthserver.ErrInvalidRequest) {
			t.Fatal("missing required grant_type was not invalid_request")
		}
	}
}
