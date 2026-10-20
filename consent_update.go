package oauthserver

import (
	"context"
	"errors"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ErrConsentConflict means the original request key is already bound to a
// different narrowing intent. No command identity or authority is disclosed.
var ErrConsentConflict = errors.New("oauthserver: consent request conflict")

// ConsentUpdateRequest selects only strict scope narrowing of an existing own
// consent. Client/version/resource are exact immutable preconditions, not edits.
// RequestKey is required native retry correlation, never authentication. Session
// and CSRF in Consent remain borrowed; Scopes are copied before delegation.
type ConsentUpdateRequest struct {
	Consent       ConsentCommand
	ClientID      string
	ClientVersion uint64
	Resource      string
	Scopes        []string
	RequestKey    identity.IdempotencyKey
}

func (ConsentUpdateRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ConsentUpdateRequest(redacted)"))
}
func (ConsentUpdateRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ConsentUpdateRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// Validated returns an owned scope copy after bounded structural checks only.
// The native owner must prove current identity, strict subset and original key.
func (r ConsentUpdateRequest) Validated() (ConsentUpdateRequest, error) {
	if _, err := NewConsentCommand(r.Consent.Input()); err != nil || r.Consent.Input().Operation != ConsentNarrow || !identifier(r.ClientID) || r.ClientVersion == 0 || r.ClientVersion == ^uint64(0) || !validOrigin(r.Resource) || r.RequestKey == (identity.IdempotencyKey{}) {
		return ConsentUpdateRequest{}, ErrInvalidRequest
	}
	scopes, err := validatedScopes(r.Scopes)
	if err != nil {
		return ConsentUpdateRequest{}, ErrInvalidRequest
	}
	r.Scopes = scopes
	return r, nil
}

// ConsentUpdateExecution carries genuine original session custody and the
// current configured client. These projections alone are not live authority.
type ConsentUpdateExecution struct {
	Request ConsentUpdateRequest
	Session session.GetResult
	Client  Client
}

func (ConsentUpdateExecution) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ConsentUpdateExecution(redacted)"))
}
func (ConsentUpdateExecution) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ConsentUpdateExecution) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ConsentUpdateResult contains metadata only. Updated means a known committed
// narrowing; historical completion never redelivers tokens or renews authority.
type ConsentUpdateResult struct {
	Updated    bool
	Completion Completion
}

// ConsentUpdater is an additive optional capability. ConsentManager and legacy
// Store implementations retain their existing method set unchanged.
type ConsentUpdater interface {
	ConsentUpdate(context.Context, ConsentUpdateExecution) (ConsentUpdateResult, error)
}

// ConsentUpdate narrows only an authenticated own consent under fresh original
// password-session, origin, exact CSRF and native request-key fences.
func (s *Service) ConsentUpdate(ctx context.Context, r ConsentUpdateRequest) (out ConsentUpdateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = ConsentUpdateResult{Completion: Completion{Outcome: identity.CommitOutcomeUnknown}}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	r, err = r.Validated()
	if err != nil {
		return out, err
	}
	owner, ok := s.deps.Store.(ConsentUpdater)
	if !ok || nilDependency(owner) {
		return out, ErrAccessDenied
	}
	client, err := s.client(r.ClientID)
	if err != nil || client.Workload != nil || client.Version != r.ClientVersion || client.Resource != r.Resource || !scopeSubset(r.Scopes, client.Scopes) {
		return out, ErrAccessDenied
	}
	_, observed, err := s.consentSource(ctx, r.Consent, ConsentNarrow)
	if err != nil {
		return out, err
	}
	out, err = owner.ConsentUpdate(ctx, ConsentUpdateExecution{Request: r, Session: observed, Client: client})
	if ctx.Err() == nil && err != nil && out.Completion.Outcome == identity.CommitOutcomeConflict {
		return ConsentUpdateResult{Completion: out.Completion}, ErrConsentConflict
	}
	if err != nil || ctx.Err() != nil {
		return ConsentUpdateResult{Completion: out.Completion}, operationError(ctx, err)
	}
	if out.Updated != (out.Completion.Outcome == identity.CommitOutcomeCommitted) {
		return ConsentUpdateResult{Completion: out.Completion}, ErrUnavailable
	}
	return out, nil
}
