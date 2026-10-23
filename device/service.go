package device

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

// Config is the child's immutable policy projection shared with its native
// owner. Enabled=false permits dependency-free disabled construction. Enabled
// policy requires trusted tenant and same-issuer exact HTTPS endpoint locations,
// TTL1..15minutes, initial interval5..60seconds, complete-URI bound128..2048 and
// lookup limit1..100/hour. No request/proxy header may replace these values.
type Config = oauth.DevicePolicy

// Store is the actual native execution interface. Base OAuth does not require
// it. Applications compose the owned native factory, not private domain stores.
type Store = oauth.DeviceStore

// PollPolicy describes server-owned polling policy. SlowDown is fixed by
// RFC8628 section3.5, not configuration; every early poll adds exactly5seconds.
type PollPolicy struct{ Initial, SlowDown, Maximum time.Duration }

// DeviceRequest supplies no subject/tenant/consent selectors. Nil Scopes selects
// the current registered OAuth-only ceiling; client credentials remain borrowed.
type DeviceRequest struct {
	ClientID, Resource, Network string
	Scopes                      []string
	ClientAuthentication        oauth.ClientAuthentication
}

func (DeviceRequest) Format(f fmt.State, v rune)   { redacted(f, v) }
func (DeviceRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (DeviceRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// Verification borrows a genuine recent browser session and submitted user
// code. Tenant is fixed at construction. Network is trusted transport attribution.
type Verification struct {
	Session           auth.BearerCredential
	UserCode, Network string
}

func (Verification) Format(f fmt.State, v rune)   { redacted(f, v) }
func (Verification) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (Verification) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// Approval requires an explicit user action comparing the displayed canonical
// code. A complete verification URI never supplies this confirmation or CSRF.
type Approval struct {
	Verification
	CSRF                      session.CSRFToken
	Origin, ConfirmedUserCode string
}

func (Approval) Format(f fmt.State, v rune)   { redacted(f, v) }
func (Approval) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (Approval) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// Denial requires the same genuine fresh session/origin/CSRF admission. Repeated
// denial is idempotent without disclosing a previous reviewing subject.
type Denial struct {
	Verification
	CSRF   session.CSRFToken
	Origin string
}

func (Denial) Format(f fmt.State, v rune)   { redacted(f, v) }
func (Denial) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (Denial) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// TokenExchange borrows exact client and device-code custody. It permits no
// subject/scope/resource override. Cancel uses this same authenticated custody
// to permanently withdraw the device request; context cancellation is distinct.
type TokenExchange struct {
	ClientID, DeviceCode, Network string
	ClientAuthentication          oauth.ClientAuthentication
}

func (TokenExchange) Format(f fmt.State, v rune)   { redacted(f, v) }
func (TokenExchange) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (TokenExchange) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// Authorization contains fresh known-committed reveal-once device custody and
// bounded UI data. Completion alone never establishes response delivery.
type Authorization struct {
	Completion                                         oauth.Completion
	DeviceCode                                         DeviceCode
	UserCode, VerificationURI, VerificationURIComplete string
	ExpiresAt                                          time.Time
	Interval                                           time.Duration
}

func (Authorization) Format(f fmt.State, v rune)   { redacted(f, v) }
func (Authorization) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (Authorization) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// PollResult preserves committed polling interval/durability even for pending
// and slow_down errors. Tokens exist only for the sole fresh atomic winner.
type PollResult struct {
	Completion oauth.Completion
	Interval   time.Duration
	Tokens     oauth.TokenResult
}

func (PollResult) Format(f fmt.State, v rune)   { redacted(f, v) }
func (PollResult) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (PollResult) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// Metadata advertises only a completely selected optional device profile.
// It is not base OAuth discovery or HTTP route registration.
type Metadata struct{ DeviceAuthorizationEndpoint, TokenEndpoint, GrantType string }

// Service is immutable, concurrent-safe and borrows all owner dependencies. It
// owns no pool, goroutine, background recovery loop or resource to Close.
type Service struct {
	core    *oauth.Service
	config  Config
	store   Store
	profile oauth.DeviceConfigurationProjection
}

func (*Service) Format(f fmt.State, v rune) { redacted(f, v) }

// NewService freezes exact optional composition without IO or generation.
// Disabled construction exposes no capability or metadata and needs no owners.
// The selected profile supports unbound issuance and recent verified password
// humans only; pre-binding, OIDC claims, workload/device UI are not approximated.
func NewService(core *oauth.Service, c Config, store Store) (*Service, error) {
	if !c.Enabled {
		return &Service{config: c}, nil
	}
	if core == nil || nilValue(store) {
		return nil, ErrInvalidRequest
	}
	p, err := core.DeviceConfiguration()
	if err != nil || !validConfig(c, p.Issuer.String()) || store.DevicePolicy() != c {
		return nil, ErrInvalidRequest
	}
	return &Service{core: core, config: c, store: store, profile: p}, nil
}
func nilValue(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return r.IsNil()
	}
	return false
}
func validURI(wire, issuer string) bool {
	if len(wire) == 0 || len(wire) > 2048 || strings.ContainsAny(wire, "?#\\\r\n\x00") {
		return false
	}
	u, err := url.Parse(wire)
	base, e := url.Parse(issuer)
	return err == nil && e == nil && u.Scheme == "https" && u.Host == base.Host && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Opaque == "" && u.Path != "" && !strings.Contains(u.Host, "*")
}
func validConfig(c Config, issuer string) bool {
	// The selected fixed user alphabet is URI-unreserved (RFC3986 section2.3),
	// so its canonical nine-byte code has one exact complete-URI overhead.
	if len(c.VerificationURI)+len("?user_code=BCDF-GHJK") > int(c.VerificationURICompleteBytes) {
		return false
	}
	return c.Enabled && boundedText(string(c.TenantID), 128) && validURI(c.VerificationURI, issuer) && validURI(c.TokenEndpoint, issuer) && validURI(c.AuthorizationEndpoint, issuer) && c.VerificationURI != c.TokenEndpoint && c.TokenEndpoint != c.AuthorizationEndpoint && c.VerificationURI != c.AuthorizationEndpoint && c.TTL >= time.Minute && c.TTL <= 15*time.Minute && c.TTL%time.Second == 0 && c.PollInterval >= 5*time.Second && c.PollInterval <= 60*time.Second && c.PollInterval%time.Second == 0 && c.VerificationURICompleteBytes >= 128 && c.VerificationURICompleteBytes <= 2048 && c.LookupLimit >= 1 && c.LookupLimit <= 100
}

// Enabled reports complete selected composition, not deployment/readiness.
func (s *Service) Enabled() bool {
	return s != nil && s.config.Enabled && s.core != nil && !nilValue(s.store)
}

// Metadata returns no endpoints/grant when disabled.
func (s *Service) Metadata() Metadata {
	if !s.Enabled() {
		return Metadata{}
	}
	return Metadata{s.config.AuthorizationEndpoint, s.config.TokenEndpoint, GrantType}
}

// PollPolicy returns the selected bounds, not a mutable current device interval.
func (s *Service) PollPolicy() PollPolicy {
	if !s.Enabled() {
		return PollPolicy{}
	}
	return PollPolicy{s.config.PollInterval, 5 * time.Second, 60 * time.Second}
}
func (s *Service) bounded(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if s == nil || ctx == nil {
		return nil, nil, ErrInvalidRequest
	}
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	if !s.Enabled() {
		return nil, nil, ErrAccessDenied
	}
	bounded, stop := context.WithTimeout(ctx, s.profile.MaximumDuration)
	return bounded, stop, nil
}
func safeError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return nil
	}
	for _, e := range []error{ErrInvalidRequest, ErrAuthorizationPending, ErrSlowDown, ErrAccessDenied, ErrExpiredToken, ErrUnavailable, oauth.ErrInvalidClient, oauth.ErrInvalidScope} {
		if errors.Is(err, e) {
			return e
		}
	}
	if errors.Is(err, oauth.ErrAccessDenied) || errors.Is(err, oauth.ErrInvalidGrant) {
		return ErrAccessDenied
	}
	if errors.Is(err, oauth.ErrInvalidRequest) {
		return ErrInvalidRequest
	}
	return ErrUnavailable
}
func completionOnly(r oauth.DeviceResult) oauth.DeviceResult {
	return oauth.DeviceResult{Completion: r.Completion, Condition: r.Condition, Interval: r.Interval}
}
func (s *Service) execute(ctx context.Context, e oauth.DeviceExecution) (out oauth.DeviceResult, err error) {
	defer func() {
		if recover() != nil {
			out = completionOnly(out)
			out.Completion.Outcome = identity.CommitOutcomeUnknown
			err = ErrUnavailable
		}
	}()
	out, err = s.store.ExecuteDevice(ctx, e)
	if err != nil || ctx.Err() != nil {
		return completionOnly(out), safeError(ctx, err)
	}
	if out.Completion.Outcome != identity.CommitOutcomeCommitted {
		return completionOnly(out), ErrUnavailable
	}
	if out.Completion.Replayed {
		if e.Action != oauth.DeviceIssue && e.Action != oauth.DeviceApprove && out.Condition != oauth.DeviceSucceeded {
			return completionOnly(out), nil
		}
		return completionOnly(out), ErrUnavailable
	}
	return out, nil
}

// Authorize authenticates an explicitly permitted current registration before
// native issuance. Core/native retain current policy/transaction authority; the
// device cannot select a subject. Codes are delivered only on known commitment.
func (s *Service) Authorize(ctx context.Context, r DeviceRequest) (out Authorization, err error) {
	defer func() {
		if recover() != nil {
			out = Authorization{Completion: out.Completion}
			out.Completion.Outcome = identity.CommitOutcomeUnknown
			err = ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if !boundedText(r.Network, 128) {
		return out, ErrInvalidRequest
	}
	c, err := s.core.DeviceClientSource(ctx, oauth.DeviceClientSourceRequest{ClientID: r.ClientID, Resource: r.Resource, Scopes: r.Scopes, ClientAuthentication: r.ClientAuthentication})
	if err != nil {
		return out, safeError(ctx, err)
	}
	user, err := newUserCode()
	if err != nil {
		return out, err
	}
	code, err := oauth.NewToken()
	if err != nil {
		return out, ErrUnavailable
	}
	complete := s.config.VerificationURI + "?user_code=" + url.QueryEscape(user)
	if len(complete) > int(s.config.VerificationURICompleteBytes) {
		return out, ErrInvalidRequest
	}
	result, err := s.execute(ctx, oauth.DeviceExecution{Action: oauth.DeviceIssue, Policy: s.config, Client: c, ClientAuthentication: r.ClientAuthentication, Network: r.Network, GeneratedDeviceCode: code, GeneratedUserCode: user})
	out.Completion = result.Completion
	if err != nil {
		return out, err
	}
	if result.UserCode != user || !s.profile.Clock.Now().Before(result.ExpiresAt) || result.Interval != s.config.PollInterval {
		return out, ErrUnavailable
	}
	return Authorization{Completion: result.Completion, DeviceCode: result.DeviceCode, UserCode: result.UserCode, VerificationURI: s.config.VerificationURI, VerificationURIComplete: complete, ExpiresAt: result.ExpiresAt, Interval: result.Interval}, nil
}
func (s *Service) review(ctx context.Context, r Verification) (oauth.DeviceSessionProjection, string, error) {
	if !boundedText(r.Network, 128) {
		return oauth.DeviceSessionProjection{}, "", ErrInvalidRequest
	}
	code, err := ParseUserCode(r.UserCode)
	if err != nil {
		return oauth.DeviceSessionProjection{}, "", err
	}
	p, err := s.core.DeviceSessionSource(ctx, oauth.DeviceSessionSourceRequest{TenantID: s.config.TenantID, Session: r.Session})
	return p, string(code), safeError(ctx, err)
}

// Inspect returns only a current safe prompt. It never approves, creates a
// command or emits a domain audit/lifecycle; native rate admission precedes lookup.
func (s *Service) Inspect(ctx context.Context, r Verification) (out oauth.DevicePrompt, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.DevicePrompt{}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	p, code, err := s.review(ctx, r)
	if err != nil {
		return out, err
	}
	out, err = s.store.InspectDevice(ctx, oauth.DeviceInspection{Policy: s.config, Session: p, UserCode: code, Network: r.Network})
	if err != nil || ctx.Err() != nil {
		return oauth.DevicePrompt{}, safeError(ctx, err)
	}
	if p.ValidateAt(s.profile.Clock.Now()) != nil || out.UserCode != code || !boundedText(out.ClientID, 128) || !boundedText(out.ClientDisplay, 128) || out.Resource != s.profile.Resource || len(out.Scopes) == 0 || len(out.Scopes) > 16 || !s.profile.Clock.Now().Before(out.ExpiresAt) {
		return oauth.DevicePrompt{}, ErrAccessDenied
	}
	out.Scopes = slices.Clone(out.Scopes)
	return out, nil
}

// Approve binds actual reviewing subject/current consent atomically only after
// explicit canonical-code comparison and native current session/origin/CSRF fences.
func (s *Service) Approve(ctx context.Context, r Approval) (oauth.Completion, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return oauth.Completion{}, err
	}
	defer stop()
	p, code, err := s.review(ctx, r.Verification)
	if err != nil {
		return oauth.Completion{}, err
	}
	confirmed, err := ParseUserCode(r.ConfirmedUserCode)
	if err != nil || string(confirmed) != code || r.Origin != s.profile.Issuer.String() || r.CSRF == (session.CSRFToken{}) {
		return oauth.Completion{}, ErrAccessDenied
	}
	out, err := s.execute(ctx, oauth.DeviceExecution{Action: oauth.DeviceApprove, Policy: s.config, Session: p, UserCode: code, Origin: r.Origin, CSRF: r.CSRF, Network: r.Network})
	return out.Completion, err
}

// Deny permanently wins over later approval/exchange and remains idempotent.
func (s *Service) Deny(ctx context.Context, r Denial) (oauth.Completion, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return oauth.Completion{}, err
	}
	defer stop()
	p, code, err := s.review(ctx, r.Verification)
	if err != nil {
		return oauth.Completion{}, err
	}
	if r.Origin != s.profile.Issuer.String() || r.CSRF == (session.CSRFToken{}) {
		return oauth.Completion{}, ErrAccessDenied
	}
	out, err := s.execute(ctx, oauth.DeviceExecution{Action: oauth.DeviceDeny, Policy: s.config, Session: p, UserCode: code, Origin: r.Origin, CSRF: r.CSRF, Network: r.Network})
	return out.Completion, err
}

func (s *Service) poll(ctx context.Context, r TokenExchange, action oauth.DeviceAction) (out PollResult, err error) {
	defer func() {
		if recover() != nil {
			out = PollResult{Completion: out.Completion}
			out.Completion.Outcome = identity.CommitOutcomeUnknown
			err = ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if !canonicalDevice(r.DeviceCode) || !boundedText(r.Network, 128) {
		return out, ErrInvalidRequest
	}
	c, err := s.core.DeviceClientSource(ctx, oauth.DeviceClientSourceRequest{ClientID: r.ClientID, ClientAuthentication: r.ClientAuthentication})
	if err != nil {
		return out, safeError(ctx, err)
	}
	result, err := s.execute(ctx, oauth.DeviceExecution{Action: action, Policy: s.config, Client: c, ClientAuthentication: r.ClientAuthentication, DeviceCode: r.DeviceCode, Network: r.Network})
	out = PollResult{Completion: result.Completion, Interval: result.Interval}
	if err != nil {
		return out, err
	}
	switch result.Condition {
	case oauth.DevicePending:
		return out, ErrAuthorizationPending
	case oauth.DeviceSlowDown:
		return out, ErrSlowDown
	case oauth.DeviceDenied:
		if action == oauth.DeviceCancel {
			return out, nil
		}
		return out, ErrAccessDenied
	case oauth.DeviceExpired:
		return out, ErrExpiredToken
	case oauth.DeviceSucceeded:
		t := result.Tokens
		if t.Outcome != identity.CommitOutcomeCommitted || t.Replayed || t.CommandID == "" || t.Resource != c.Resource || len(t.Scopes) == 0 || !s.profile.Clock.Now().Before(t.ExpiresAt) || t.ExpiresAt.After(s.profile.Clock.Now().Add(s.profile.AccessTTL)) {
			return out, ErrUnavailable
		}
		for _, scope := range t.Scopes {
			if !slices.Contains(c.Scopes, scope) {
				return out, ErrUnavailable
			}
		}
		out.Tokens = t
		return out, nil
	default:
		return out, ErrUnavailable
	}
}

// Poll implements RFC8628 pending/slow_down/denied/expired and one token winner.
func (s *Service) Poll(ctx context.Context, r TokenExchange) (PollResult, error) {
	return s.poll(ctx, r, oauth.DevicePoll)
}

// Cancel is an authenticated explicit client extension. It permanently withdraws
// this request; cancelling a Go context alone does not imply durable withdrawal.
func (s *Service) Cancel(ctx context.Context, r TokenExchange) (oauth.Completion, error) {
	out, err := s.poll(ctx, r, oauth.DeviceCancel)
	return out.Completion, err
}

// Recovery carries only original-command correlation plus the appropriate
// current client or human custody. No user/tenant/subject override is accepted.
type Recovery struct {
	OperationID                    string
	CommandID                      identity.CommandID
	ClientID, DeviceCode, UserCode string
	ClientAuthentication           oauth.ClientAuthentication
	Session                        auth.BearerCredential
}

func (Recovery) Format(f fmt.State, v rune)   { redacted(f, v) }
func (Recovery) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (Recovery) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// Recover delegates metadata-only reconciliation to the sole native coordinator.
func (s *Service) Recover(ctx context.Context, r Recovery) (oauth.Completion, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return oauth.Completion{}, err
	}
	defer stop()
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return oauth.Completion{}, ErrInvalidRequest
	}
	e := oauth.DeviceRecovery{Policy: s.config, OperationID: r.OperationID, CommandID: r.CommandID, ClientAuthentication: r.ClientAuthentication, DeviceCode: r.DeviceCode, UserCode: r.UserCode}
	switch r.OperationID {
	case "identity.oauth-server.device-authorize", "identity.oauth-server.device-token":
		e.Client, err = s.core.DeviceClientSource(ctx, oauth.DeviceClientSourceRequest{ClientID: r.ClientID, ClientAuthentication: r.ClientAuthentication})
	case "identity.oauth-server.device-approve", "identity.oauth-server.device-deny":
		e.Session, err = s.core.DeviceSessionSource(ctx, oauth.DeviceSessionSourceRequest{TenantID: s.config.TenantID, Session: r.Session})
	default:
		return oauth.Completion{}, ErrInvalidRequest
	}
	if err != nil {
		return oauth.Completion{}, safeError(ctx, err)
	}
	out, err := s.store.RecoverDevice(ctx, e)
	return out, safeError(ctx, err)
}
