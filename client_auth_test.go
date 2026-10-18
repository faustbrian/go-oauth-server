package oauthserver_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	oauth "github.com/faustbrian/go-oauth-server"
	password "github.com/faustbrian/go-password/v2"
)

func clientBasicHeader(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
}

func FuzzClientAuthenticationForms(f *testing.F) {
	// Synthetic, non-deployed wire values exercise percent decoding and bounds.
	validHeader := clientBasicHeader("confidential-client", strings.Repeat("A", 43))
	f.Add(validHeader, "grant_type=refresh_token&refresh_token="+strings.Repeat("A", 43))
	f.Add(validHeader, "grant_type=client_credentials&scope=workload%3Aread&resource=https%3A%2F%2Fresource.example")
	f.Add("Basic %zz", "token="+strings.Repeat("A", 43))
	f.Add("Bearer unsupported", "client_id=public-client")
	f.Add(strings.Repeat("x", 1025), strings.Repeat("x", 16385))
	f.Fuzz(func(t *testing.T, header, raw string) {
		credential, err := oauth.ParseClientAuthentication([]string{header})
		if err == nil {
			if len(header) > 1024 || credential.Method() != "client_secret_basic" || credential.ClientID() == "" || len(credential.ClientID()) > 128 {
				t.Fatal("Basic decoder widened selected custody or bounds")
			}
			if _, err := json.Marshal(credential); err == nil {
				t.Fatal("borrowed Basic credential exported implicitly")
			}
		}
		if _, err := oauth.ParseClientAuthentication([]string{header, header}); err == nil {
			t.Fatal("duplicate Authorization fields admitted")
		}
		if request, err := oauth.ParseTokenFormWithClientAuthentication(raw, []string{header}); err == nil {
			if len(raw) > 16384 || request.ClientAuthentication.Method() != "client_secret_basic" || request.ClientID != request.ClientAuthentication.ClientID() || request.Network != "" {
				t.Fatal("token form widened credential or trusted-channel policy")
			}
			if _, err := oauth.ParseTokenFormWithClientAuthentication(raw+"&client_id=foreign", []string{header}); err == nil {
				t.Fatal("multiple client authentication locations admitted")
			}
		}
		if request, err := oauth.ParseRevocationForm(raw, []string{header}); err == nil {
			if len(raw) > 16384 || request.ClientAuthentication.Method() != "client_secret_basic" || request.ClientID != request.ClientAuthentication.ClientID() || request.Network != "" {
				t.Fatal("revocation form widened credential or trusted-channel policy")
			}
			if _, err := oauth.ParseRevocationForm(raw+"&client_secret=foreign", []string{header}); err == nil {
				t.Fatal("body secret channel admitted")
			}
		}
	})
}

func confidentialCoreConfig(t *testing.T) (oauth.Config, string) {
	t.Helper()
	_, _, now, _ := coreSessionFixture(t)
	config := coreConfig(t, now)
	config.Clients[0].Public = false
	config.Clients[0].AuthenticationMethod = "client_secret_basic"
	token, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := password.NewSecret([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oauth.NewClientSecretVerifier(config.Clients[0].ID, config.Clients[0].Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	config.ClientSecrets = []oauth.ClientSecretVerifier{verifier}
	return config, wire
}

func TestConfiguredConfidentialClientUsesActualReviewedBasicVerification(t *testing.T) {
	config, wire := confidentialCoreConfig(t)
	frozen, err := config.Validated()
	if err != nil {
		t.Fatal("configured confidential profile rejected", err)
	}
	credential, err := oauth.ParseClientAuthentication([]string{clientBasicHeader("public-client", wire)})
	if err != nil {
		t.Fatal(err)
	}
	if err := frozen.AuthenticateClient(context.Background(), "public-client", credential); err != nil {
		t.Fatal("actual configured secret was not authenticated", err)
	}
	for _, input := range []struct{ id, secret string }{{"public-client", strings.Repeat("w", 43)}, {"foreign-client", wire}} {
		wrong, err := oauth.ParseClientAuthentication([]string{clientBasicHeader(input.id, input.secret)})
		if err != nil {
			t.Fatal(err)
		}
		if err := frozen.AuthenticateClient(context.Background(), "public-client", wrong); !errors.Is(err, oauth.ErrInvalidClient) {
			t.Fatal("wrong or foreign credential authenticated", err)
		}
	}
	if err := frozen.AuthenticateClient(context.Background(), "public-client", oauth.ClientAuthentication{}); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatal("confidential method downgraded to none")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := frozen.AuthenticateClient(ctx, "public-client", credential); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost before client authentication", err)
	}
	if got := fmt.Sprintf("%s %v %#v %f", credential, credential, credential, credential); strings.Contains(got, wire) {
		t.Fatal("client credential escaped formatting")
	}
	if _, err := json.Marshal(credential); err == nil {
		t.Fatal("client credential implicitly serialized")
	}
}

func TestConfiguredClientSecretsHaveExactStartupVersionAndCustody(t *testing.T) {
	config, wire := confidentialCoreConfig(t)
	for _, secrets := range [][]oauth.ClientSecretVerifier{nil, {{}}, {config.ClientSecrets[0], config.ClientSecrets[0]}} {
		invalid := config
		invalid.ClientSecrets = secrets
		if _, err := invalid.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("missing, empty or duplicate configured verifier admitted", err)
		}
	}
	changed := config
	changed.Clients = append([]oauth.Client(nil), config.Clients...)
	changed.Clients[0].Version++
	if _, err := changed.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("new client version reused old configured verifier", err)
	}
	newSecretToken, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	newWire, err := newSecretToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := password.NewSecret([]byte(newWire))
	if err != nil {
		t.Fatal(err)
	}
	newVerifier, err := oauth.NewClientSecretVerifier(changed.Clients[0].ID, changed.Clients[0].Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	changed.ClientSecrets = []oauth.ClientSecretVerifier{newVerifier}
	current, err := changed.Validated()
	if err != nil {
		t.Fatal(err)
	}
	oldCredential, _ := oauth.ParseClientAuthentication([]string{clientBasicHeader("public-client", wire)})
	newCredential, _ := oauth.ParseClientAuthentication([]string{clientBasicHeader("public-client", newWire)})
	if err := current.AuthenticateClient(context.Background(), "public-client", oldCredential); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatal("replacement snapshot accepted old configured secret", err)
	}
	if err := current.AuthenticateClient(context.Background(), "public-client", newCredential); err != nil {
		t.Fatal("replacement snapshot rejected current secret", err)
	}
	for _, value := range []any{newVerifier, current} {
		if got := fmt.Sprintf("%v %#v", value, value); strings.Contains(got, newWire) || strings.Contains(got, wire) {
			t.Fatal("startup authority exposed configured secret")
		}
	}
	if _, err := json.Marshal(newVerifier); err == nil {
		t.Fatal("verifier implicitly exported")
	}
}

func TestOAuthBasicFormsSelectOneCredentialChannelAndPreservePublicForms(t *testing.T) {
	config, wire := confidentialCoreConfig(t)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {strings.Repeat("w", 43)}}
	encodedID := "%70ublic-client"
	encodedSecret := fmt.Sprintf("%%%02X", wire[0]) + wire[1:]
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(encodedID+":"+encodedSecret))
	request, err := oauth.ParseTokenFormWithClientAuthentication(form.Encode(), []string{header})
	if err != nil || request.ClientID != "public-client" || request.ClientAuthentication.Method() != "client_secret_basic" {
		t.Fatal("RFC6749 component-escaped Basic token request rejected", err)
	}
	if err := config.AuthenticateClient(context.Background(), request.ClientID, request.ClientAuthentication); err != nil {
		t.Fatal("components were not form-unescaped exactly once", err)
	}
	for _, headers := range [][]string{{header, header}, {""}, {"Bearer unrelated"}, {"Basic %%%"}, {"Basic " + base64.StdEncoding.EncodeToString([]byte("public-client:"))}, {strings.Repeat("x", 1025)}} {
		if _, err := oauth.ParseTokenFormWithClientAuthentication(form.Encode(), headers); err == nil {
			t.Fatal("ambiguous or malformed auth accepted")
		}
	}
	for _, extra := range []string{"&client_id=public-client", "&client_secret=body", "&client_assertion=body", "&grant_type=refresh_token"} {
		if _, err := oauth.ParseTokenFormWithClientAuthentication(form.Encode()+extra, []string{header}); err == nil {
			t.Fatal("duplicate or multiple-location credential accepted")
		}
	}
	public := form.Encode() + "&client_id=public-client"
	if request, err := oauth.ParseTokenForm(public); err != nil || request.ClientAuthentication.Method() != "none" {
		t.Fatal("existing public form changed", err)
	}
	if request, err := oauth.ParseTokenFormWithClientAuthentication(public, nil); err != nil || request.ClientAuthentication.Method() != "none" {
		t.Fatal("public none fallback changed", err)
	}
	revoke, err := oauth.ParseRevocationForm(url.Values{"token": {strings.Repeat("w", 43)}, "token_type_hint": {"refresh_token"}}.Encode(), []string{header})
	if err != nil || revoke.ClientID != "public-client" || revoke.Hint != oauth.TokenRefresh || revoke.ClientAuthentication.Method() != "client_secret_basic" {
		t.Fatal("confidential revocation form rejected", err)
	}
	if _, err := oauth.ParseRevocationForm("token="+strings.Repeat("w", 43)+"&client_secret=body", []string{header}); err == nil {
		t.Fatal("revocation accepted body secret alongside Basic")
	}
}

type clientBoundaryStore struct {
	oauth.Store
	calls int
}

func (s *clientBoundaryStore) Token(context.Context, oauth.TokenCommand) (oauth.TokenResult, error) {
	s.calls++
	return oauth.TokenResult{}, nil
}
func (s *clientBoundaryStore) Revoke(context.Context, oauth.RevocationCommand) (oauth.RevokeResult, error) {
	s.calls++
	return oauth.RevokeResult{}, nil
}

func TestTokenAndRevocationRejectClientAuthenticationBeforeAdapter(t *testing.T) {
	config, wire := confidentialCoreConfig(t)
	sessions, _, _, _ := coreSessionFixture(t)
	store := &clientBoundaryStore{}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	wrongWire := "A" + wire[1:]
	if wrongWire == wire {
		wrongWire = "B" + wire[1:]
	}
	wrong, err := oauth.ParseClientAuthentication([]string{clientBasicHeader("public-client", wrongWire)})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := oauth.ParseClientAuthentication([]string{clientBasicHeader("foreign-client", wire)})
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []oauth.ClientAuthentication{{}, wrong, foreign} {
		if _, err := service.Token(context.Background(), oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-client", RefreshToken: strings.Repeat("w", 43), Network: "192.0.2.1", ClientAuthentication: credential}); !errors.Is(err, oauth.ErrInvalidClient) {
			t.Fatal("invalid token client reached adapter", err)
		}
		if _, err := service.Revoke(context.Background(), oauth.RevokeRequest{ClientID: "public-client", Token: strings.Repeat("w", 43), Network: "192.0.2.1", ClientAuthentication: credential}); !errors.Is(err, oauth.ErrInvalidClient) {
			t.Fatal("invalid revocation client reached adapter", err)
		}
	}
	if store.calls != 0 {
		t.Fatal("rejected client produced adapter effects")
	}
	correct, err := oauth.ParseClientAuthentication([]string{clientBasicHeader("public-client", wire)})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = service.Token(context.Background(), oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-client", RefreshToken: strings.Repeat("w", 43), Network: "192.0.2.1", ClientAuthentication: correct})
	if store.calls != 1 {
		t.Fatal("actual authenticated client never reached grant owner")
	}
	config.Clients[0].Public = true
	config.Clients[0].AuthenticationMethod = "none"
	config.ClientSecrets = nil
	public, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := public.Token(context.Background(), oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-client", RefreshToken: strings.Repeat("w", 43), Network: "192.0.2.1", ClientAuthentication: correct}); !errors.Is(err, oauth.ErrInvalidClient) || store.calls != 1 {
		t.Fatal("public client accepted Basic downgrade/secret channel", err)
	}
}
