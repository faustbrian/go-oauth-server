package oauthserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	auth "github.com/faustbrian/go-authentication/v2"
	authhttp "github.com/faustbrian/go-authentication/v2/adapters/http"
	"github.com/faustbrian/go-authentication/v2/basic"
	password "github.com/faustbrian/go-password/v2"
)

// ErrInvalidClient denies missing, wrong, foreign or downgraded client
// authentication without disclosing credential/configuration details.
var ErrInvalidClient = errors.New("oauthserver: invalid client")

// ClientSecretVerifier is immutable startup-only confidential-client authority.
// The reviewed Basic primitive retains keyed digests, never the plaintext input.
// It is not a durable secret store, hot-rotation policy or tenant/user authority.
// Retire old service instances and advance Client.Version on configuration or
// secret changes. Copies share this immutable verifier and support concurrency.
type ClientSecretVerifier struct{ state *clientSecretState }
type clientSecretState struct {
	clientID string
	version  uint64
	verifier *basic.Static
}

// NewClientSecretVerifier binds one fixed configured 32-byte canonical opaque
// secret to an exact client ID/version. Generate that secret independently with
// cryptographic entropy. This constructor borrows Secret only during Use; the
// caller still owns Destroy. It generates only the Basic primitive's local
// digest key, performs no network/storage IO and does not issue/reveal a secret.
// Encoded passwords and arbitrary human passwords are not this selected profile.
func NewClientSecretVerifier(clientID string, version uint64, secret password.Secret) (ClientSecretVerifier, error) {
	if !identifier(clientID) || version == 0 || secret.Len() != 43 {
		return ClientSecretVerifier{}, ErrInvalidRequest
	}
	var verifier *basic.Static
	err := secret.Use(func(value []byte) error {
		if !opaque32(string(value)) {
			return ErrInvalidRequest
		}
		var err error
		verifier, err = basic.NewStaticWithOptions([]basic.Entry{{Username: clientID, Password: string(value), Principal: auth.PrincipalSpec{Subject: clientID, Method: "basic"}}}, basic.WithMaxUsernameBytes(128), basic.WithMaxPasswordBytes(43))
		return err
	})
	if err != nil || verifier == nil {
		return ClientSecretVerifier{}, ErrInvalidRequest
	}
	return ClientSecretVerifier{state: &clientSecretState{clientID: clientID, version: version, verifier: verifier}}, nil
}

// Format redacts configured credential authority for every formatting verb.
func (ClientSecretVerifier) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "oauthserver.ClientSecretVerifier(redacted)")
}

// MarshalJSON denies implicit configured-credential export.
func (ClientSecretVerifier) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }

// MarshalText denies implicit configured-credential export.
func (ClientSecretVerifier) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ClientAuthentication borrows exactly one parsed Basic credential; zero selects
// public-client none. Parsing grants no client, user or tenant authority. Keep
// this credential only until the bounded operation returns, never in durable
// commands or logs. Strings cannot provide guaranteed runtime-wide erasure.
type ClientAuthentication struct{ credential *auth.BasicCredential }

// Method returns only the selected protocol method, not successful verification.
func (a ClientAuthentication) Method() string {
	if a.credential == nil {
		return "none"
	}
	return "client_secret_basic"
}

// ClientID returns parsed non-secret metadata, not authenticated client identity.
func (a ClientAuthentication) ClientID() string {
	if a.credential == nil {
		return ""
	}
	return a.credential.Username()
}

// Format redacts borrowed credentials for every formatting verb.
func (ClientAuthentication) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "oauthserver.ClientAuthentication(redacted)")
}

// MarshalJSON denies implicit borrowed-credential export.
func (ClientAuthentication) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }

// MarshalText denies implicit borrowed-credential export.
func (ClientAuthentication) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ParseClientAuthentication admits absent or exactly one bounded Authorization
// field. It delegates strict padded Basic decoding to the existing HTTP
// extractor, then form-unescapes each component once (RFC6749 section2.3.1).
// A present unsupported/malformed field never falls back to none. The 1KiB
// ceiling accommodates this profile's 128-byte client ID and 43-byte secret,
// including component percent-encoding and Base64, before decoding allocations.
// Applications still bound whole requests and reject credentials in URI/body
// locations; use the OAuth form parsers for the supported exclusive channels.
func ParseClientAuthentication(authorization []string) (ClientAuthentication, error) {
	if len(authorization) == 0 {
		return ClientAuthentication{}, nil
	}
	if len(authorization) != 1 || len(authorization[0]) == 0 || len(authorization[0]) > 1024 {
		return ClientAuthentication{}, ErrInvalidClient
	}
	extractor, err := authhttp.NewExtractor(authhttp.BasicAuthorization())
	if err != nil {
		return ClientAuthentication{}, ErrUnavailable
	}
	credential, err := extractor.Extract(&http.Request{Header: http.Header{"Authorization": authorization}})
	if err != nil {
		return ClientAuthentication{}, ErrInvalidClient
	}
	value, ok := credential.(auth.BasicCredential)
	if !ok {
		return ClientAuthentication{}, ErrInvalidClient
	}
	username, e1 := url.QueryUnescape(value.Username())
	secret, e2 := url.QueryUnescape(value.Password())
	if e1 != nil || e2 != nil || !identifier(username) || !opaque32(secret) {
		return ClientAuthentication{}, ErrInvalidClient
	}
	decoded := auth.NewBasicCredential(username, secret)
	return ClientAuthentication{credential: &decoded}, nil
}

func (v ClientSecretVerifier) matches(client Client) bool {
	return v.state != nil && v.state.verifier != nil && !client.Public && client.AuthenticationMethod == "client_secret_basic" && v.state.clientID == client.ID && v.state.version == client.Version
}

func validateClientSecrets(clients []Client, secrets []ClientSecretVerifier) error {
	if len(secrets) > len(clients) {
		return ErrInvalidRequest
	}
	matched := 0
	for _, client := range clients {
		count := 0
		for _, secret := range secrets {
			if secret.matches(client) {
				count++
			}
		}
		if client.Public && count != 0 || !client.Public && count != 1 {
			return ErrInvalidRequest
		}
		matched += count
	}
	if matched != len(secrets) {
		return ErrInvalidRequest
	}
	return nil
}

// AuthenticateClient enforces this validated configuration's exact registered
// none/Basic matrix using the reviewed primitive, before durable effects.
// Startup configuration is the authority: it cannot claim hot/fleet-wide secret
// revocation. It never authenticates a human or chooses tenant authority.
// Native adapters repeat this same check rather than trusting a parsed DTO.
func (c Config) AuthenticateClient(ctx context.Context, clientID string, input ClientAuthentication) error {
	if ctx == nil {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(c.Clients) < 1 || len(c.Clients) > 64 || len(c.ClientSecrets) > 64 {
		return ErrInvalidClient
	}
	var client Client
	count := 0
	for _, candidate := range c.Clients {
		if candidate.ID == clientID {
			client = candidate
			count++
		}
	}
	if count != 1 {
		return ErrInvalidClient
	}
	if client.Public {
		if client.AuthenticationMethod != "none" || input.credential != nil {
			return ErrInvalidClient
		}
		return nil
	}
	if input.credential == nil || input.ClientID() != client.ID || !identifier(input.ClientID()) || !opaque32(input.credential.Password()) {
		return ErrInvalidClient
	}
	var verifier *basic.Static
	count = 0
	for _, secret := range c.ClientSecrets {
		if secret.matches(client) {
			verifier = secret.state.verifier
			count++
		}
	}
	if count != 1 {
		return ErrInvalidClient
	}
	_, err := verifier.Authenticate(ctx, *input.credential)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return ErrInvalidClient
	}
	return nil
}
