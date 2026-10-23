package oauthpostgres

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-identity/risk"
	oauth "github.com/faustbrian/go-oauth-server"
	rate "github.com/faustbrian/go-rate-limit/v2"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

// DeviceConfig explicitly selects optional storage and independent versioned
// device lookup keys. Retain old versions while any live/terminal recovery row
// uses them. Keys are borrowed immutable opaque values; input slices are copied.
// Install DeviceMigrationSource and the existing rate-limit owner's migration
// before enabling. No constructor performs IO, migration or background work.
type DeviceConfig struct {
	Policy                 oauth.DevicePolicy
	LookupKeys             []oauth.TokenDigestKey
	ActiveLookupKeyVersion uint32
}

func (DeviceConfig) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte("DeviceConfig(redacted)")) }
func (DeviceConfig) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }
func (DeviceConfig) MarshalText() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

// DeviceStore is an optional immutable factory product over the actual core
// native owner. It owns no transaction coordinator, domain engine or pool; every
// mutation uses the same native phase/coordinator/audit/lifecycle composition.
type DeviceStore struct {
	core                     *Store
	config                   DeviceConfig
	active                   oauth.TokenDigestKey
	rates                    *rate.Service
	lookupPolicy, pollPolicy rate.Policy
}

var _ oauth.DeviceStore = (*DeviceStore)(nil)

func (*DeviceStore) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oauthpostgres.DeviceStore(redacted)"))
}
func (*DeviceStore) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }
func (*DeviceStore) MarshalText() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

func deviceURI(wire, issuer string) bool {
	if len(wire) == 0 || len(wire) > 2048 || strings.ContainsAny(wire, "?#\\\r\n\x00") {
		return false
	}
	u, e := url.Parse(wire)
	base, b := url.Parse(issuer)
	return e == nil && b == nil && u.Scheme == "https" && u.Host == base.Host && u.User == nil && u.Opaque == "" && u.Path != "" && !strings.Contains(u.Host, "*")
}
func validDevicePolicy(p oauth.DevicePolicy, issuer string) bool {
	// The fixed canonical user code uses only RFC3986 section2.3 unreserved
	// characters; reject a complete-URI policy that can never fit before IO.
	if len(p.VerificationURI)+len("?user_code=BCDF-GHJK") > int(p.VerificationURICompleteBytes) {
		return false
	}
	return p.Enabled && boundedText(string(p.TenantID), 128) && deviceURI(p.VerificationURI, issuer) && deviceURI(p.TokenEndpoint, issuer) && deviceURI(p.AuthorizationEndpoint, issuer) && p.VerificationURI != p.TokenEndpoint && p.VerificationURI != p.AuthorizationEndpoint && p.TokenEndpoint != p.AuthorizationEndpoint && p.TTL >= time.Minute && p.TTL <= 15*time.Minute && p.TTL%time.Second == 0 && p.PollInterval >= 5*time.Second && p.PollInterval <= 60*time.Second && p.PollInterval%time.Second == 0 && p.VerificationURICompleteBytes >= 128 && p.VerificationURICompleteBytes <= 2048 && p.LookupLimit >= 1 && p.LookupLimit <= 100
}

// DeviceStore selects the unbound, OAuth-only recent-password-human device
// profile. Ordinary NewStore/NewService remain device-free. Core consent
// management is required; workload/OIDC device variants are explicitly denied,
// never implemented by fake redirect/code exchanges or downgraded MFA sessions.
func (s *Store) DeviceStore(c DeviceConfig) (*DeviceStore, error) {
	if s == nil || !s.config.ConsentManagement || len(s.config.Protocol.OIDCScopes.Scopes()) != 0 || workloadSelected(s.config.Protocol.Clients) || !validDevicePolicy(c.Policy, s.config.Protocol.Issuer.String()) || len(c.LookupKeys) < 1 || len(c.LookupKeys) > 4 {
		return nil, oauth.ErrInvalidRequest
	}
	if p := s.config.Protocol.ManagedClients; p != nil && p.TenantID != c.Policy.TenantID {
		return nil, oauth.ErrInvalidRequest
	}
	c.LookupKeys = slices.Clone(c.LookupKeys)
	d := &DeviceStore{config: c}
	for i, key := range c.LookupKeys {
		if key.Version() == 0 {
			return nil, oauth.ErrInvalidRequest
		}
		if key.Version() == c.ActiveLookupKeyVersion {
			d.active = key
		}
		for _, old := range c.LookupKeys[:i] {
			if key.Version() == old.Version() {
				return nil, oauth.ErrInvalidRequest
			}
		}
	}
	if d.active.Version() == 0 {
		return nil, oauth.ErrInvalidRequest
	}
	for _, op := range deviceOperations() {
		a, err := s.config.Counters.CommandCounters.Policy.Admit(risk.Action(op.OperationID))
		if err != nil || a.PolicyVersion != s.config.Counters.PolicyVersion || a.Preflight != "" || a.Profile.Class != risk.Privileged || !slices.Equal(a.Profile.RequiredSignals, []string{"velocity"}) {
			return nil, oauth.ErrInvalidRequest
		}
	}
	owned := *s
	var err error
	if owned.policy == nil {
		owned.policy, err = authority.NewAuthorityStore(s.pool.Raw(), s.config.Protocol.MaximumDuration)
		if err != nil {
			return nil, oauth.ErrInvalidRequest
		}
	}
	d.core = &owned
	backend, err := ratepg.New(s.pool.Raw(), ratepg.Options{Timeout: s.config.Protocol.MaximumDuration, LockTimeout: s.config.Protocol.MaximumDuration, Clock: ratepg.ServerClock})
	if err != nil {
		return nil, oauth.ErrInvalidRequest
	}
	d.rates, err = rate.NewService(backend)
	if err != nil {
		return nil, oauth.ErrInvalidRequest
	}
	// Count all canonical lookup attempts, including successful ones. This is
	// deliberately stricter than32 failed guesses and avoids success-dependent
	// rate-store timing. Its stable per-IP key never includes a guessed code.
	d.lookupPolicy, err = rate.NewPolicy(rate.PolicySpec{ID: "oauth-device-user-code", Revision: "1", Algorithm: rate.SlidingWindow, Capacity: uint64(c.Policy.LookupLimit), Period: time.Hour, MaxCost: 1, FailureMode: rate.FailClosed, Consistency: rate.ConsistencyStrong})
	if err != nil {
		return nil, oauth.ErrInvalidRequest
	}
	d.pollPolicy, err = rate.NewPolicy(rate.PolicySpec{ID: "oauth-device-poll-ip", Revision: "1", Algorithm: rate.SlidingWindow, Capacity: 120, Period: time.Hour, MaxCost: 1, FailureMode: rate.FailClosed, Consistency: rate.ConsistencyStrong})
	if err != nil {
		return nil, oauth.ErrInvalidRequest
	}
	return d, nil
}

// DevicePolicy returns a safe copied policy projection with no keys or handles.
func (d *DeviceStore) DevicePolicy() oauth.DevicePolicy {
	if d == nil {
		return oauth.DevicePolicy{}
	}
	return d.config.Policy
}
