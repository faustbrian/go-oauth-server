package oauthserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// DevicePolicy is the optional child's immutable storage-neutral policy
// projection. The child owns RFC8628 validation and protocol semantics. Tenant
// and all endpoint locations are trusted configuration, never device input.
// Zero Enabled exposes no device capability. Native construction installs no
// schema, launches no work and must reject a different projection at execution.
type DevicePolicy struct {
	Enabled                                               bool
	TenantID                                              identity.TenantID
	VerificationURI, TokenEndpoint, AuthorizationEndpoint string
	TTL, PollInterval                                     time.Duration
	VerificationURICompleteBytes                          uint16
	LookupLimit                                           uint16
}

// DeviceConfigurationProjection is core-owned trusted composition policy.
// Clock is borrowed, fast, local and concurrent-safe; no state is transferred.
type DeviceConfigurationProjection struct {
	Issuer                                 Issuer
	Environment, Resource                  string
	Clock                                  Clock
	MaximumDuration, AccessTTL, RefreshTTL time.Duration
}

// DeviceConfiguration returns copied public configuration for the optional
// child without authenticating a client, advertising a feature or doing IO.
func (s *Service) DeviceConfiguration() (DeviceConfigurationProjection, error) {
	if s == nil {
		return DeviceConfigurationProjection{}, ErrInvalidRequest
	}
	c := s.config
	return DeviceConfigurationProjection{Issuer: c.Issuer, Environment: c.Environment, Resource: c.Resource, Clock: c.Clock, MaximumDuration: c.MaximumDuration, AccessTTL: c.AccessTTL, RefreshTTL: c.RefreshTTL}, nil
}

// DeviceAction is a closed native execution discriminator, not a protocol grant.
type DeviceAction uint8

const (
	DeviceIssue DeviceAction = iota + 1
	DeviceApprove
	DeviceDeny
	DevicePoll
	DeviceCancel
)

// DeviceCondition is a native protocol-state projection. Only the device child
// maps it to RFC8628 errors; zero has no successful protocol meaning.
type DeviceCondition string

const (
	DevicePending   DeviceCondition = "authorization_pending"
	DeviceSlowDown  DeviceCondition = "slow_down"
	DeviceDenied    DeviceCondition = "access_denied"
	DeviceExpired   DeviceCondition = "expired_token"
	DeviceSucceeded DeviceCondition = "success"
)

// DeviceExecution borrows original credentials until the bounded native call
// returns. Client and Session are projections, never permission assertions;
// native execution must independently authenticate them and compare all original
// versions inside its sole coordinator. Generated codes are accepted only for
// Issue and may be disclosed only after fresh known commitment.
type DeviceExecution struct {
	Action                                DeviceAction
	Policy                                DevicePolicy
	Client                                DeviceClientProjection
	ClientAuthentication                  ClientAuthentication
	Session                               DeviceSessionProjection
	CSRF                                  session.CSRFToken
	Origin, Network, DeviceCode, UserCode string
	GeneratedDeviceCode                   Token
	GeneratedUserCode                     string
}

func (DeviceExecution) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("DeviceExecution(redacted)"))
}
func (DeviceExecution) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (DeviceExecution) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// DeviceResult contains fresh material only for a fresh known-committed Issue
// or token winner. Replays, cancellation, error and unknown commitment retain
// only Completion and closed nonsecret protocol state, never credentials.
type DeviceResult struct {
	Completion Completion
	Condition  DeviceCondition
	DeviceCode Token
	UserCode   string
	ExpiresAt  time.Time
	Interval   time.Duration
	Tokens     TokenResult
}

func (DeviceResult) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte("DeviceResult(redacted)")) }
func (DeviceResult) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (DeviceResult) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// DeviceInspection borrows an actual recent session and a bounded canonical
// user code. Native inspection rate-limits before lookup and emits no domain
// audit or lifecycle; rate-store writes are abuse admission, not authorization.
type DeviceInspection struct {
	Policy            DevicePolicy
	Session           DeviceSessionProjection
	UserCode, Network string
}

func (DeviceInspection) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("DeviceInspection(redacted)"))
}
func (DeviceInspection) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (DeviceInspection) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// DevicePrompt contains only safe current bounded display metadata and the
// canonical code the user must explicitly compare. It grants no approval.
type DevicePrompt struct {
	ClientID, ClientDisplay, UserCode, Resource string
	Scopes                                      []string
	ExpiresAt                                   time.Time
}

func (DevicePrompt) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("DevicePrompt(redacted)")) }

// DeviceRecovery asks the existing coordinator about the original command.
// Client custody is required for Issue/Poll; human approval/denial requires a
// current real same-actor session. No recovery generates or redelivers secrets.
type DeviceRecovery struct {
	Policy               DevicePolicy
	OperationID          string
	CommandID            identity.CommandID
	Client               DeviceClientProjection
	ClientAuthentication ClientAuthentication
	Session              DeviceSessionProjection
	DeviceCode, UserCode string
}

func (DeviceRecovery) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte("DeviceRecovery(redacted)")) }
func (DeviceRecovery) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (DeviceRecovery) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// DeviceStore is the optional native execution owner consumed by the device
// child. Base OAuth Store and bootstrap do not require this interface, a child
// import or its migrations. Implementations own permanent winning state and
// atomic core grant/consent/token, audit/lifecycle and reconciliation effects;
// applications do not supply missing protocol or domain-store orchestration.
type DeviceStore interface {
	DevicePolicy() DevicePolicy
	ExecuteDevice(context.Context, DeviceExecution) (DeviceResult, error)
	InspectDevice(context.Context, DeviceInspection) (DevicePrompt, error)
	RecoverDevice(context.Context, DeviceRecovery) (Completion, error)
}

// DeviceDigestScope fixes the native digest-at-rest namespace. UserCode lookup
// requires empty ClientID so inspection can find the original registration;
// device-code lookup requires it. All other fields are trusted configuration.
type DeviceDigestScope struct {
	Issuer                                   Issuer
	Environment                              string
	TenantID                                 identity.TenantID
	VerificationURI, TokenEndpoint, ClientID string
	UserCode                                 bool
}

// DeviceLookupDigest applies versioned standard HMAC-SHA256 with a device-only
// domain and length framing. It validates canonical lookup syntax before crypto,
// retains no wire input and authenticates no state. Keys must be dedicated and
// retained while rows or original-command recovery can reference their version.
func DeviceLookupDigest(key TokenDigestKey, scope DeviceDigestScope, wire string) (TokenDigest, error) {
	if key.state == nil || !validOrigin(scope.Issuer.String()) || !identifier(scope.Environment) || !identifier(string(scope.TenantID)) || !deviceDigestURI(scope.VerificationURI) || !deviceDigestURI(scope.TokenEndpoint) {
		return TokenDigest{}, ErrInvalidRequest
	}
	var raw []byte
	if scope.UserCode {
		if scope.ClientID != "" || len(wire) != 9 || wire[4] != '-' {
			return TokenDigest{}, ErrInvalidRequest
		}
		for i := range len(wire) {
			if i != 4 && !strings.ContainsRune("BCDFGHJKLMNPQRSTVWXZ23456789", rune(wire[i])) {
				return TokenDigest{}, ErrInvalidRequest
			}
		}
		raw = []byte(wire)
	} else {
		if !identifier(scope.ClientID) || !opaque32(wire) {
			return TokenDigest{}, ErrInvalidRequest
		}
		var err error
		raw, err = base64.RawURLEncoding.Strict().DecodeString(wire)
		if err != nil || len(raw) != 32 {
			return TokenDigest{}, ErrInvalidRequest
		}
	}
	defer clear(raw)
	h := hmac.New(sha256.New, key.state.material[:])
	_, _ = h.Write([]byte("golib-oauth-device-lookup-v1\x00"))
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], key.Version())
	_, _ = h.Write(version[:])
	for _, value := range []string{scope.Issuer.String(), scope.Environment, string(scope.TenantID), scope.VerificationURI, scope.TokenEndpoint, scope.ClientID} {
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(value)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(value))
	}
	if scope.UserCode {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{2})
	}
	_, _ = h.Write(raw)
	out := TokenDigest{KeyVersion: key.Version()}
	copy(out.Sum[:], h.Sum(nil))
	return out, nil
}
func deviceDigestURI(wire string) bool {
	if len(wire) == 0 || len(wire) > 2048 || strings.ContainsAny(wire, "?#\\\r\n\x00") {
		return false
	}
	u, err := url.Parse(wire)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Opaque == "" && u.Hostname() != "" && !strings.Contains(u.Host, "*")
}
