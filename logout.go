package oauthserver

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// EndSessionOutcome is the closed native RP logout result taxonomy. Provider
// variants are reserved protocol outcomes, not implemented provider orchestration.
type EndSessionOutcome string

const (
	EndSessionRedirect              EndSessionOutcome = "redirect"
	EndSessionLocalOnly             EndSessionOutcome = "local-only"
	EndSessionProviderComplete      EndSessionOutcome = "provider-complete"
	EndSessionProviderError         EndSessionOutcome = "provider-error"
	EndSessionTimeout               EndSessionOutcome = "timeout"
	EndSessionUnknownReconciliation EndSessionOutcome = "unknown-reconciliation"
)

// EndSessionInput borrows initiating browser and verified compact custody. The
// OIDC consumer validates protocol claims; the native owner must independently
// bind the exact issued digest to its original tenant/client/subject/session.
// Subject and client are checked preconditions, never target selectors. Expiry
// is historical hint metadata, not an authorization deadline. No refresh, global
// session termination, hintless UI or arbitrary recent-session policy is implied.
type EndSessionInput struct {
	TenantID                     identity.TenantID
	Session                      auth.BearerCredential
	CSRF                         session.CSRFToken
	Origin, Network              string
	Hint                         VerifiedCompact
	ClientID, Subject            string
	IssuedAt, ExpiresAt          time.Time
	PostLogoutRedirectURI, State string
}

func (EndSessionInput) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("EndSessionInput(redacted)"))
}
func (EndSessionInput) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (EndSessionInput) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// EndSessionExecution captures immutable current client policy and the original
// core call start. The native primary observation must retain the earlier of
// this start+20s and every original contributing authority/session deadline.
type EndSessionExecution struct {
	Input     EndSessionInput
	Client    Client
	StartedAt time.Time
}

func (EndSessionExecution) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("EndSessionExecution(redacted)"))
}
func (EndSessionExecution) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (EndSessionExecution) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// EndSessionStore is an optional native composition, not another mandatory Store
// method. Fresh execution authenticates the real current initiating session.
// Matching historical repeat/result access must instead prove original retained
// custody without requiring that self-revoked session to authenticate again.
// Required invalidation/audit/lifecycle effects share the existing sole Work.
type EndSessionStore interface {
	EndSessionSelected() bool
	EndSession(context.Context, EndSessionExecution) (EndSessionResult, error)
}

// EndSessionResult exposes redirect/state only for fresh known committed logout.
// Unknown and historical outcomes contain durability metadata, never renewed
// authority, successful redirect or permission to clear a browser credential.
// ValidUntil is the original exclusive delivery deadline, not a renewable lease.
type EndSessionResult struct {
	Outcome     EndSessionOutcome `json:"outcome"`
	RedirectURI string            `json:"redirect_uri,omitempty"`
	State       string            `json:"state,omitempty"`
	Completion  Completion        `json:"completion"`
	ValidUntil  time.Time         `json:"-"`
}

func (EndSessionResult) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("EndSessionResult(redacted)"))
}

// Validate rejects impossible/mixed payloads; it supplies no revocation proof.
func (r EndSessionResult) Validate() error {
	if _, err := identity.ParseCommandID(string(r.Completion.CommandID)); err != nil {
		return ErrInvalidRequest
	}
	if r.Outcome != EndSessionRedirect && (r.RedirectURI != "" || r.State != "") {
		return ErrInvalidRequest
	}
	if (r.Completion.Replayed || r.Outcome == EndSessionUnknownReconciliation) && !r.ValidUntil.IsZero() {
		return ErrInvalidRequest
	}
	switch r.Outcome {
	case EndSessionRedirect:
		if r.Completion.Outcome != identity.CommitOutcomeCommitted || r.Completion.Replayed || r.ValidUntil.IsZero() || r.RedirectURI == "" || !optionalVisible(r.State, 1024) {
			return ErrInvalidRequest
		}
		if _, err := NewRedirectPolicy([]string{r.RedirectURI}); err != nil {
			return ErrInvalidRequest
		}
	case EndSessionLocalOnly:
		if r.Completion.Outcome != identity.CommitOutcomeCommitted || !r.Completion.Replayed && r.ValidUntil.IsZero() {
			return ErrInvalidRequest
		}
	case EndSessionUnknownReconciliation:
		if r.Completion.Outcome != identity.CommitOutcomeUnknown && r.Completion.Outcome != identity.CommitOutcomeInProgress {
			return ErrInvalidRequest
		}
	default:
		// The selected native lane does not manufacture provider or timeout
		// success variants merely because the full catalog names them.
		return ErrInvalidRequest
	}
	return nil
}

func (r EndSessionResult) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	type wire EndSessionResult
	return json.Marshal(wire(r))
}

// EndSessionConfigured reports trusted native selection only, with no IO or
// capability activation. An ordinary/custom Store remains unselected by default.
func (s *Service) EndSessionConfigured() (selected bool) {
	defer func() {
		if recover() != nil {
			selected = false
		}
	}()
	if s == nil || !s.config.OIDCScopes.Contains("openid") {
		return false
	}
	owner, ok := s.deps.Store.(EndSessionStore)
	return ok && !nilDependency(owner) && owner.EndSessionSelected()
}

// EndSession delivers only the exact native committed policy-bound outcome.
// It deliberately delegates original-vs-current browser admission to the native
// session composition so historical access never authenticates a revoked cookie
// as a fresh current session. Unknown acknowledgement never yields a redirect.
func (s *Service) EndSession(ctx context.Context, in EndSessionInput) (out EndSessionResult, err error) {
	defer func() {
		if recover() != nil {
			out = EndSessionResult{}
			err = ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	started := s.config.Clock.Now().UTC()
	// The verified packet seals the original key-read start; neither a slow
	// client lookup nor a later source observation may renew its 20s budget.
	if in.Hint.readStarted.IsZero() || in.Hint.readStarted.After(started) {
		return out, ErrAccessDenied
	}
	if in.Hint.readStarted.Before(started) {
		started = in.Hint.readStarted
	}
	if !s.EndSessionConfigured() {
		return out, ErrAccessDenied
	}
	if !identifier(string(in.TenantID)) || in.Origin != s.config.Issuer.String() || !visible(in.Network, 128) || in.CSRF == (session.CSRFToken{}) || in.Hint.kid == "" || in.Hint.digest == ([32]byte{}) || !identifier(in.ClientID) || !visible(in.Subject, 128) || in.IssuedAt.IsZero() || !in.ExpiresAt.After(in.IssuedAt) || in.ExpiresAt.After(in.IssuedAt.Add(5*time.Minute)) || !optionalVisible(in.State, 1024) {
		return out, ErrInvalidRequest
	}
	if _, err := session.ParseToken(in.Session.Token()); err != nil {
		return out, ErrInvalidRequest
	}
	client, err := s.currentClient(ctx, in.ClientID)
	if err != nil || client.Workload != nil {
		return out, ErrAccessDenied
	}
	if in.PostLogoutRedirectURI != "" && !PostLogoutRedirectAllowed(client, in.PostLogoutRedirectURI) {
		return out, ErrAccessDenied
	}
	if in.IssuedAt.After(started) {
		return out, ErrAccessDenied
	}
	out, err = s.deps.Store.(EndSessionStore).EndSession(ctx, EndSessionExecution{Input: in, Client: client, StartedAt: started})
	if ctx.Err() != nil {
		return endSessionErrorMetadata(out), ctx.Err()
	}
	if err != nil {
		return endSessionErrorMetadata(out), operationError(ctx, err)
	}
	if out.Validate() != nil {
		return EndSessionResult{Completion: out.Completion}, ErrAccessDenied
	}
	if out.Outcome == EndSessionUnknownReconciliation || out.Completion.Replayed {
		return out, nil
	}
	now := s.config.Clock.Now()
	if now.Before(started) || !now.Before(out.ValidUntil) || out.ValidUntil.After(started.Add(20*time.Second)) {
		return EndSessionResult{Completion: out.Completion}, ErrAccessDenied
	}
	current, err := s.currentClient(ctx, in.ClientID)
	if err != nil || !sameClientPolicy(current, client) || out.Outcome == EndSessionRedirect && (out.RedirectURI != in.PostLogoutRedirectURI || out.State != in.State) || out.Outcome == EndSessionLocalOnly && in.PostLogoutRedirectURI != "" {
		return EndSessionResult{Completion: out.Completion}, ErrAccessDenied
	}
	if ctx.Err() != nil {
		return EndSessionResult{Completion: out.Completion}, ctx.Err()
	}
	return out, nil
}

func endSessionErrorMetadata(out EndSessionResult) EndSessionResult {
	// A lost acknowledgement may accompany an error. Preserve its closed
	// original reconciliation locator, never delivery authority or a redirect.
	if out.Outcome == EndSessionUnknownReconciliation && out.Validate() == nil {
		return out
	}
	return EndSessionResult{Completion: out.Completion}
}

func sameClientPolicy(a, b Client) bool {
	return reflect.DeepEqual(a, b)
}
