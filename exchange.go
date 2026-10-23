package oauthserver

import (
	"time"

	identity "github.com/faustbrian/go-identity"
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
// It grants no workload, refresh-source, device, API-key, organization, JWT or
// private-session exchange authority. Zero MaximumDepth means four exchanges;
// an explicit value may only lower that ceiling. ClockUncertainty and the
// configured MaximumDuration share the profile's ten-second uncertainty budget.
// The native adapter requires its real consent owner and forward lineage history.
type HumanCodeExchangePolicy struct {
	MaximumDepth     uint8
	ClockUncertainty time.Duration
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

func validExchangeRequest(r TokenRequest, client Client) bool {
	if r.CommandID != "" {
		if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
			return false
		}
	}
	return (client.Workload != nil || client.HumanCodeExchange) && !client.Public && r.GrantType == TokenExchangeGrant && opaque32(r.SubjectToken) && r.SubjectTokenType == AccessTokenType && (r.RequestedTokenType == "" || r.RequestedTokenType == AccessTokenType) && (r.Resource == "") != (r.Audience == "") && (r.Resource == client.Resource || r.Audience == client.Resource) && r.Code == "" && r.CodeVerifier == "" && r.RedirectURI == "" && r.RefreshToken == ""
}

func exchangeFieldsPresent(r TokenRequest) bool {
	return r.SubjectToken != "" || r.SubjectTokenType != "" || r.RequestedTokenType != "" || r.Audience != "" || r.CommandID != ""
}
