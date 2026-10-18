// Package oauthserver owns the explicitly selected OAuth authorization-server
// protocol. Protocol parsing does not authenticate a client or subject, authorize
// consent, consume a code, or issue a token. Durable adapters own those effects.
package oauthserver

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
)

var (
	// ErrInvalidRequest rejects malformed, conflicting or out-of-profile input.
	// Errors deliberately contain no submitted values or credential material.
	ErrInvalidRequest = errors.New("oauthserver: invalid request")
	// ErrUnsupportedGrant denies every grant not selected by this profile.
	ErrUnsupportedGrant = errors.New("oauthserver: unsupported grant type")
)

// GrantType is the exact protocol discriminator. No grant is implicit.
type GrantType string

const (
	AuthorizationCodeGrant GrantType = "authorization_code"
	RefreshTokenGrant      GrantType = "refresh_token"
)

// AuthorizationRequest contains a bounded code/S256 OAuth-only request. It
// conveys no validated redirect, client, subject or consent authority. Scopes
// are sorted unique; state is retained byte-for-byte. The selected profile does
// not accept OIDC, implicit, request-object or caller-selected response modes.
type AuthorizationRequest struct {
	ClientID, RedirectURI, State, CodeChallenge, Resource string
	Scopes                                                []string
}

// Format prevents correlated request/state data from appearing in diagnostics.
func (AuthorizationRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "oauthserver.AuthorizationRequest(redacted)")
}

// TokenRequest contains exactly one grant variant for the public-client
// profile. Code, refresh token and verifier remain secret caller custody;
// transport must never log or serialize this request. Parsing does not validate
// client status, code ownership, PKCE, replay, current authority or expiry.
type TokenRequest struct {
	GrantType                                 GrantType
	ClientID, Code, RedirectURI, CodeVerifier string
	RefreshToken, Resource                    string
	Scopes                                    []string
	// Network is trusted transport attribution supplied after parsing. It is
	// never accepted from the OAuth form and grants no network trust by itself.
	Network string
}

// Format redacts every credential channel for all formatting verbs.
func (TokenRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "oauthserver.TokenRequest(redacted)")
}

// MarshalJSON prevents implicit export of bearer-equivalent values.
func (TokenRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }

// MarshalText prevents implicit export of bearer-equivalent values.
func (TokenRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// RedirectPolicy freezes 1..16 exact registered HTTPS callback URIs. Zero
// denies all redirects. This initial web-client profile does not select RFC8252
// native loopback/custom-scheme exceptions; it never normalizes URI strings.
type RedirectPolicy struct{ targets []string }

// NewRedirectPolicy validates/copies a nonempty unique redirect set without IO.
// Fragments, userinfo, wildcard hosts, backslashes and reserved OAuth response
// query members are rejected. Output query members must not be shadowed by a
// registered callback's own parameters (RFC6749 sections3.1.2/4.1.2).
func NewRedirectPolicy(targets []string) (RedirectPolicy, error) {
	if len(targets) < 1 || len(targets) > 16 {
		return RedirectPolicy{}, ErrInvalidRequest
	}
	owned := slices.Clone(targets)
	slices.Sort(owned)
	for i, target := range owned {
		if !validRedirect(target) || i > 0 && target == owned[i-1] {
			return RedirectPolicy{}, ErrInvalidRequest
		}
	}
	return RedirectPolicy{targets: owned}, nil
}

// Allows performs byte-for-byte matching only, with no URI normalization,
// prefix matching, query removal or implicit default-port equivalence.
func (p RedirectPolicy) Allows(target string) bool {
	_, exists := slices.BinarySearch(p.targets, target)
	return exists
}

func validRedirect(value string) bool {
	if !visible(value, 2048) || strings.ContainsAny(value, "\\*") {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" || strings.Contains(value, "#") || u.Opaque != "" || u.String() != value || strings.ContainsAny(u.Path, "\\") {
		return false
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false
	}
	for _, reserved := range []string{"code", "state", "iss", "error", "error_description", "error_uri"} {
		if _, exists := q[reserved]; exists {
			return false
		}
	}
	return true
}

// S256Challenge implements RFC7636 sections4.1/4.2 using standard SHA-256.
// Verifiers are 43..128 ASCII unreserved characters; plain PKCE is not offered.
// The returned challenge alone proves neither verifier possession nor entropy.
func S256Challenge(verifier string) (string, error) {
	if len(verifier) < 43 || len(verifier) > 128 {
		return "", ErrInvalidRequest
	}
	for i := range len(verifier) {
		b := verifier[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~", rune(b))) {
			return "", ErrInvalidRequest
		}
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ParseAuthorizationQuery parses at most16KiB before allocation-heavy work.
// Every field is unique and belongs to this selected code/S256 profile. URI
// syntax is validated but redirect authority remains the registered client
// policy's responsibility; a parsed RedirectURI must never itself enable a
// redirect error. Unknown parameters fail rather than silently change profiles.
func ParseAuthorizationQuery(raw string) (AuthorizationRequest, error) {
	values, err := parseFields(raw, []string{"response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "resource"})
	if err != nil || values.Get("response_type") != "code" || values.Get("code_challenge_method") != "S256" {
		return AuthorizationRequest{}, ErrInvalidRequest
	}
	r := AuthorizationRequest{ClientID: values.Get("client_id"), RedirectURI: values.Get("redirect_uri"), State: values.Get("state"), CodeChallenge: values.Get("code_challenge"), Resource: values.Get("resource")}
	r.Scopes, err = parseScopes(values.Get("scope"))
	if err != nil || !visible(r.ClientID, 128) || !validRedirect(r.RedirectURI) || !optionalVisible(r.State, 1024) || !opaque32(r.CodeChallenge) || !validOrigin(r.Resource) {
		return AuthorizationRequest{}, ErrInvalidRequest
	}
	return r, nil
}

// ParseTokenForm discriminates a bounded form before credential use. This
// profile selects public clients only: secret/assertion credential channels,
// client credentials, standard exchange and private session exchange are not
// advertised or accepted. Scope omission on refresh preserves grant authority;
// code requests must not supply scope (selected TRANSACTION/API contract).
func ParseTokenForm(raw string) (TokenRequest, error) {
	values, err := parseFields(raw, []string{"grant_type", "client_id", "code", "redirect_uri", "code_verifier", "refresh_token", "scope", "resource"})
	if err != nil {
		return TokenRequest{}, ErrInvalidRequest
	}
	r := TokenRequest{GrantType: GrantType(values.Get("grant_type")), ClientID: values.Get("client_id"), Resource: values.Get("resource")}
	if !visible(r.ClientID, 128) || !visible(string(r.GrantType), 128) || r.Resource != "" && !validOrigin(r.Resource) {
		return TokenRequest{}, ErrInvalidRequest
	}
	switch r.GrantType {
	case AuthorizationCodeGrant:
		if hasField(values, "refresh_token") || hasField(values, "scope") {
			return TokenRequest{}, ErrInvalidRequest
		}
		r.Code, r.RedirectURI, r.CodeVerifier = values.Get("code"), values.Get("redirect_uri"), values.Get("code_verifier")
		if !opaque32(r.Code) || !validRedirect(r.RedirectURI) {
			return TokenRequest{}, ErrInvalidRequest
		}
		if _, err := S256Challenge(r.CodeVerifier); err != nil {
			return TokenRequest{}, ErrInvalidRequest
		}
	case RefreshTokenGrant:
		if hasField(values, "code") || hasField(values, "redirect_uri") || hasField(values, "code_verifier") {
			return TokenRequest{}, ErrInvalidRequest
		}
		r.RefreshToken = values.Get("refresh_token")
		if !opaque32(r.RefreshToken) {
			return TokenRequest{}, ErrInvalidRequest
		}
		if hasField(values, "scope") {
			r.Scopes, err = parseScopes(values.Get("scope"))
			if err != nil {
				return TokenRequest{}, ErrInvalidRequest
			}
		}
	default:
		return TokenRequest{}, ErrUnsupportedGrant
	}
	return r, nil
}

func parseFields(raw string, allowed []string) (url.Values, error) {
	if len(raw) == 0 || len(raw) > 16384 || strings.Count(raw, "&") >= len(allowed) {
		return nil, ErrInvalidRequest
	}
	values, err := url.ParseQuery(raw)
	if err != nil || len(values) == 0 || len(values) > len(allowed) {
		return nil, ErrInvalidRequest
	}
	for name, entries := range values {
		if !slices.Contains(allowed, name) || len(entries) != 1 || len(entries[0]) > 2048 {
			return nil, ErrInvalidRequest
		}
	}
	return values, nil
}

func hasField(values url.Values, name string) bool { _, present := values[name]; return present }

func parseScopes(raw string) ([]string, error) {
	if !visible(raw, 1024) {
		return nil, ErrInvalidRequest
	}
	scopes := strings.Split(raw, " ")
	if len(scopes) > 16 {
		return nil, ErrInvalidRequest
	}
	for _, scope := range scopes {
		if len(scope) == 0 || len(scope) > 128 {
			return nil, ErrInvalidRequest
		}
		for i := range len(scope) {
			b := scope[i]
			if b < 0x21 || b > 0x7e || b == '"' || b == '\\' {
				return nil, ErrInvalidRequest
			}
		}
	}
	slices.Sort(scopes)
	for i := 1; i < len(scopes); i++ {
		if scopes[i] == scopes[i-1] {
			return nil, ErrInvalidRequest
		}
	}
	return scopes, nil
}

func visible(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func optionalVisible(value string, limit int) bool { return value == "" || visible(value, limit) }

func opaque32(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == 32
}

func validOrigin(value string) bool {
	if !visible(value, 2048) || strings.ContainsAny(value, "\\*#") {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && u.String() == value
}
