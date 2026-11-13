package oauthserver

import (
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

// WorkloadExchangePolicy explicitly selects the finite issuer-owned opaque
// workload-access RFC8693 profile. It enables no human, API-key, organization,
// actor-token or private session exchange. Original and delegated tokens remain
// usable only by their owning Basic client at its one configured resource.
// MaximumDepth zero means four; explicit values may only lower that ceiling.
// ClockUncertainty is a trusted deployment upper bound, not a measured clock
// correction; with MaximumDuration it must fit the profile's ten-second budget.
// The native adapter always reads primary owners and never serves stale evidence.
type WorkloadExchangePolicy struct {
	MaximumDepth     uint8
	ClockUncertainty time.Duration
}

// HumanCodeExchangePolicy explicitly selects owning-client delegation of opaque
// access issued through the existing password-session/S256 authorization-code
// profile. Clients must independently opt in with Client.HumanCodeExchange.
// It grants no workload, refresh-bearer, device, API-key, organization, JWT or
// private-session exchange authority. Zero MaximumDepth means four exchanges;
// an explicit value may only lower that ceiling. ClockUncertainty and the
// configured MaximumDuration share the profile's ten-second uncertainty budget.
// The native adapter requires its real consent owner and forward lineage history.
type HumanCodeExchangePolicy struct {
	MaximumDepth     uint8
	ClockUncertainty time.Duration
	// AllowRefreshIssuedAccess additionally admits opaque human access from
	// native refresh rotation with bounded original S256 issuance provenance.
	// False preserves code-issued access only. Refresh tokens are never sources.
	AllowRefreshIssuedAccess bool `json:",omitempty"`
}

// APIKeyExchangePolicy selects USER-key delegation for explicitly opted-in
// configured Basic clients. A key authenticates its integration actor, never its
// human owner or the Basic caller. The native adapter must supply the real key
// verifier, separate primary observations and final Work fences; this policy
// alone grants no key, tenant or owner authority. Organization, JWT,
// refresh-bearer, actor-token and private-session inputs remain unselected.
// Zero MaximumDepth means four; explicit values can only lower that ceiling.
// ClockUncertainty and MaximumDuration must fit the ten-second race budget.
type APIKeyExchangePolicy struct {
	MaximumDepth     uint8
	ClockUncertainty time.Duration
	// LegacySHA256 selects the existing bare SHA-256 source instead of modern
	// key syntax. The native source must use the exact verify-only configuration;
	// token text never selects or falls back between algorithms. False preserves
	// modern behavior and its serialized configuration fingerprints.
	LegacySHA256 bool `json:",omitempty"`
}

// APIKeyExchangeUnknownError retains only nonsecret correlation for the actual
// source verification attempt and OAuth command. It grants no principal or
// retry authority. Native recovery authenticates the owning Basic client and
// reconciles these exact existing journals without a key, debit or new attempt.
// A zero Verification means no usable source correlation was disclosed; the
// caller must not guess a replacement attempt. Never log or serialize this
// object; preserve it only in the original operation's bounded recovery custody.
type APIKeyExchangeUnknownError struct {
	CommandID    identity.CommandID
	Verification apikey.VerificationReconcileQuery
}

func (APIKeyExchangeUnknownError) Error() string {
	return "oauthserver: API-key exchange outcome unknown"
}
func (APIKeyExchangeUnknownError) Unwrap() error { return ErrUnavailable }
func (APIKeyExchangeUnknownError) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthserver.APIKeyExchangeUnknownError(redacted)"))
}
func (APIKeyExchangeUnknownError) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (APIKeyExchangeUnknownError) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

func (p APIKeyExchangePolicy) validated(c Config) (APIKeyExchangePolicy, error) {
	if p.MaximumDepth == 0 {
		p.MaximumDepth = 4
	}
	if p.MaximumDepth > 4 || p.ClockUncertainty < 0 || p.ClockUncertainty > 10*time.Second-c.MaximumDuration {
		return APIKeyExchangePolicy{}, ErrInvalidRequest
	}
	for _, client := range c.Clients {
		if client.APIKeyExchange {
			return p, nil
		}
	}
	return APIKeyExchangePolicy{}, ErrInvalidRequest
}

func (p HumanCodeExchangePolicy) validated(c Config) (HumanCodeExchangePolicy, error) {
	if p.MaximumDepth == 0 {
		p.MaximumDepth = 4
	}
	if p.MaximumDepth > 4 || p.ClockUncertainty < 0 || p.ClockUncertainty > 10*time.Second-c.MaximumDuration {
		return HumanCodeExchangePolicy{}, ErrInvalidRequest
	}
	for _, client := range c.Clients {
		if client.HumanCodeExchange {
			return p, nil
		}
	}
	return HumanCodeExchangePolicy{}, ErrInvalidRequest
}

func (p WorkloadExchangePolicy) validated(c Config) (WorkloadExchangePolicy, error) {
	if p.MaximumDepth == 0 {
		p.MaximumDepth = 4
	}
	if p.MaximumDepth > 4 || p.ClockUncertainty < 0 || p.ClockUncertainty > 10*time.Second-c.MaximumDuration {
		return WorkloadExchangePolicy{}, ErrInvalidRequest
	}
	selected := false
	for _, client := range c.Clients {
		selected = selected || client.Workload != nil
	}
	if !selected {
		return WorkloadExchangePolicy{}, ErrInvalidRequest
	}
	return p, nil
}

func validExchangeRequest(r TokenRequest, client Client, apiKeyPolicy *APIKeyExchangePolicy) bool {
	if r.CommandID != "" {
		if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
			return false
		}
	}
	clientSelected := !client.Public && (client.Workload != nil || client.HumanCodeExchange || client.APIKeyExchange)
	if !clientSelected || r.GrantType != TokenExchangeGrant {
		return false
	}
	sourceTypeAllowed := r.SubjectTokenType == AccessTokenType || client.APIKeyExchange && r.SubjectTokenType == APIKeyTokenType
	if !sourceTypeAllowed || !validExchangeSubjectSyntaxForPolicy(r.SubjectToken, r.SubjectTokenType, apiKeyPolicy) {
		return false
	}
	requestedTypeAllowed := r.RequestedTokenType == "" || r.RequestedTokenType == AccessTokenType
	exactTarget := (r.Resource == "") != (r.Audience == "") && (r.Resource == client.Resource || r.Audience == client.Resource)
	otherGrantsAbsent := r.Code == "" && r.CodeVerifier == "" && r.RedirectURI == "" && r.RefreshToken == ""
	return requestedTypeAllowed && exactTarget && otherGrantsAbsent
}

func validExchangeSubjectSyntaxForPolicy(wire, tokenType string, policy *APIKeyExchangePolicy) bool {
	if tokenType == APIKeyTokenType && policy != nil && policy.LegacySHA256 {
		_, err := apikey.ParseLegacySecret(wire)
		return err == nil
	}
	return validExchangeSubjectSyntax(wire, tokenType)
}

// The credential owner defines modern key syntax. Neither branch proves bearer
// validity; selected native owners must authenticate the exact input separately.
func validExchangeSubjectSyntax(wire, tokenType string) bool {
	switch tokenType {
	case AccessTokenType:
		return opaque32(wire)
	case APIKeyTokenType:
		_, err := apikey.ParseSecret(wire)
		return err == nil
	default:
		return false
	}
}

func exchangeFieldsPresent(r TokenRequest) bool {
	return r.SubjectToken != "" || r.SubjectTokenType != "" || r.RequestedTokenType != "" || r.Audience != "" || r.CommandID != ""
}
