// Package device owns the optional RFC8628 device authorization protocol.
// It composes the actual OAuth Service and native execution owner; it owns no
// replacement authentication, consent, grant, token or transaction engine.
package device

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"slices"
	"strings"

	oauth "github.com/faustbrian/go-oauth-server"
)

// GrantType is RFC8628 section3.4's exact extension-grant discriminator.
const GrantType = "urn:ietf:params:oauth:grant-type:device_code"
const userAlphabet = "BCDFGHJKLMNPQRSTVWXZ23456789"

// Error is a stable redacted protocol condition, suitable for errors.Is and
// explicit OAuth transport mapping. It contains no submitted diagnostic values.
type Error string

func (e Error) Error() string { return "device: " + string(e) }

const (
	ErrInvalidRequest       Error = "invalid_request"
	ErrAuthorizationPending Error = "authorization_pending"
	ErrSlowDown             Error = "slow_down"
	ErrAccessDenied         Error = "access_denied"
	ErrExpiredToken         Error = "expired_token"
	ErrUnavailable          Error = "temporarily_unavailable"
)

// DeviceCode retains the root owner's canonical32byte reveal-once secret
// custody. Parsing or copying one never creates durable grant authority.
type DeviceCode = oauth.Token

// UserCode is the fixed reference nonconfusable8-character code, displayed4-4.
// It is not an authenticated actor, an OAuth bearer or an approval instruction.
type UserCode string

// ParseUserCode accepts only8ASCII alphabet characters with optional middle
// hyphen. ASCII case folding is explicit; whitespace/Unicode/confusables deny.
// Missing, malformed, expired and foreign codes share the same public denial.
func ParseUserCode(wire string) (UserCode, error) {
	if len(wire) != 8 && len(wire) != 9 {
		return "", ErrAccessDenied
	}
	var out [9]byte
	out[4] = '-'
	index := 0
	for i := range len(wire) {
		if len(wire) == 9 && i == 4 {
			if wire[i] != '-' {
				return "", ErrAccessDenied
			}
			continue
		}
		b := wire[i]
		if b >= 'a' && b <= 'z' {
			b -= 32
		}
		if !strings.ContainsRune(userAlphabet, rune(b)) {
			return "", ErrAccessDenied
		}
		if index == 4 {
			index++
		}
		out[index] = b
		index++
	}
	return UserCode(string(out[:])), nil
}
func newUserCode() (string, error) {
	var out [9]byte
	out[4] = '-'
	// Rejection sampling avoids modulo bias; the alphabet is fixed by the
	// selected reference profile, not caller-controlled generator policy.
	for i := range len(out) {
		if i == 4 {
			continue
		}
		var b [1]byte
		accepted := false
		for range 128 {
			if _, err := rand.Read(b[:]); err != nil {
				return "", ErrUnavailable
			}
			if int(b[0]) < 256-256%len(userAlphabet) {
				out[i] = userAlphabet[int(b[0])%len(userAlphabet)]
				accepted = true
				break
			}
		}
		if !accepted {
			return "", ErrUnavailable
		}
	}
	return string(out[:]), nil
}

func canonicalDevice(wire string) bool {
	if len(wire) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(wire)
	defer clear(raw)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == wire
}
func boundedText(wire string, max int) bool {
	if len(wire) == 0 || len(wire) > max {
		return false
	}
	for i := range len(wire) {
		if wire[i] < 0x21 || wire[i] > 0x7e {
			return false
		}
	}
	return true
}
func parseFields(raw string) (url.Values, error) {
	if len(raw) == 0 || len(raw) > 16384 {
		return nil, ErrInvalidRequest
	}
	q, err := url.ParseQuery(raw)
	if err != nil || len(q) > 32 {
		return nil, ErrInvalidRequest
	}
	for name, values := range q {
		if !boundedText(name, 128) || len(values) != 1 || len(values[0]) > 4096 {
			return nil, ErrInvalidRequest
		}
	}
	for _, forbidden := range []string{"client_secret", "client_assertion", "client_assertion_type", "subject", "tenant_id", "user_id", "redirect_uri", "code", "code_verifier", "refresh_token"} {
		if _, ok := q[forbidden]; ok {
			return nil, ErrInvalidRequest
		}
	}
	return q, nil
}
func clientCredential(q url.Values, headers []string) (string, oauth.ClientAuthentication, error) {
	if len(headers) == 0 {
		if !boundedText(q.Get("client_id"), 128) {
			return "", oauth.ClientAuthentication{}, ErrInvalidRequest
		}
		return q.Get("client_id"), oauth.ClientAuthentication{}, nil
	}
	if _, ok := q["client_id"]; ok {
		return "", oauth.ClientAuthentication{}, ErrInvalidRequest
	}
	a, err := oauth.ParseClientAuthentication(headers)
	if err != nil {
		return "", oauth.ClientAuthentication{}, err
	}
	return a.ClientID(), a, nil
}
func requestScopes(wire string) ([]string, error) {
	if wire == "" {
		return nil, nil
	}
	if len(wire) > 4096 {
		return nil, ErrInvalidRequest
	}
	values := strings.Split(wire, " ")
	if len(values) > 16 {
		return nil, ErrInvalidRequest
	}
	for _, scope := range values {
		if !boundedText(scope, 128) || strings.ContainsAny(scope, "\"\\") {
			return nil, ErrInvalidRequest
		}
	}
	slices.Sort(values)
	for i := 1; i < len(values); i++ {
		if values[i] == values[i-1] {
			return nil, ErrInvalidRequest
		}
	}
	return values, nil
}

// ParseDeviceRequest parses bounded RFC8628 section3.1 public-none or exclusive
// confidential-Basic custody. Unknown parameters are ignored; duplicates and
// conflicting credential channels deny. Trusted Network is never form input.
func ParseDeviceRequest(raw string, authorization []string) (DeviceRequest, error) {
	q, err := parseFields(raw)
	if err != nil {
		return DeviceRequest{}, err
	}
	if _, ok := q["grant_type"]; ok {
		return DeviceRequest{}, ErrInvalidRequest
	}
	if _, ok := q["device_code"]; ok {
		return DeviceRequest{}, ErrInvalidRequest
	}
	id, a, err := clientCredential(q, authorization)
	if err != nil {
		return DeviceRequest{}, err
	}
	scopes, err := requestScopes(q.Get("scope"))
	if err != nil {
		return DeviceRequest{}, err
	}
	return DeviceRequest{ClientID: id, Resource: q.Get("resource"), Scopes: scopes, ClientAuthentication: a}, nil
}

// ParseTokenExchange admits only the exact device grant and canonical bearer.
// Scope is not an allowed polling override. Parsing grants no client/device
// authority; the native owner independently fences both on every request.
func ParseTokenExchange(raw string, authorization []string) (TokenExchange, error) {
	q, err := parseFields(raw)
	if err != nil {
		return TokenExchange{}, err
	}
	if q.Get("grant_type") != GrantType || !canonicalDevice(q.Get("device_code")) {
		return TokenExchange{}, ErrInvalidRequest
	}
	for _, name := range []string{"scope", "resource"} {
		if _, ok := q[name]; ok {
			return TokenExchange{}, ErrInvalidRequest
		}
	}
	id, a, err := clientCredential(q, authorization)
	if err != nil {
		return TokenExchange{}, err
	}
	return TokenExchange{ClientID: id, DeviceCode: q.Get("device_code"), ClientAuthentication: a}, nil
}

func redacted(f fmt.State, _ rune) { _, _ = f.Write([]byte("device credential request(redacted)")) }
