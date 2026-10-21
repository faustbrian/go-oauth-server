package oauthserver

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ClientSecretRotationRequest borrows the exact management custody and selects
// an overlap in [0,24h] at microsecond precision. No registration edits, caller
// secret or caller expiry are accepted. Rotation advances the client authority
// version: all earlier grants/consents are invalid, including during overlap.
// A predecessor authenticates only new current-version authorizations, until its
// original exclusive expiry. A second rotation retires any older predecessor.
type ClientSecretRotationRequest struct {
	Management ClientManagementRequest
	Overlap    time.Duration
}

func (ClientSecretRotationRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ClientSecretRotationRequest(redacted)"))
}
func (ClientSecretRotationRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ClientSecretRotationRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ClientSecretRotationExecution retains the original sealed human observation;
// it is not management authorization. The native owner repeats actual current
// actor/platform policy/CSRF and original freshness fences inside sole Work.
type ClientSecretRotationExecution struct {
	Request ClientSecretRotationRequest
	Session session.GetResult
}

func (ClientSecretRotationExecution) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ClientSecretRotationExecution(redacted)"))
}
func (ClientSecretRotationExecution) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ClientSecretRotationExecution) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ValidateAt preserves the original session/proof deadline; it cannot renew it.
func (e ClientSecretRotationExecution) ValidateAt(now time.Time) error {
	return (ClientManagementExecution{Request: e.Request.Management, Session: e.Session, Delete: true}).ValidateAt(now)
}

// ClientSecretRotationResult exposes the successor once, only on a fresh known
// commitment. Replays/recovery never redeliver it. PredecessorExpiresAt is zero
// for zero overlap, otherwise the immutable exclusive predecessor deadline.
type ClientSecretRotationResult struct {
	Client               Client
	Secret               Token
	PredecessorExpiresAt time.Time
	Completion           Completion
}

func (ClientSecretRotationResult) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ClientSecretRotationResult(redacted)"))
}
func (ClientSecretRotationResult) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ClientSecretRotationResult) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ClientSecretRotator is additive; existing ClientManager/Store implementations
// do not acquire a mandatory method. Selection alone never authorizes a manager.
type ClientSecretRotator interface {
	RotateClientSecret(context.Context, ClientSecretRotationExecution) (ClientSecretRotationResult, error)
}

// ValidateClientSecretRotationRequest checks finite policy/preconditions, not
// authorization. PostgreSQL's microsecond timestamp precision must not round an
// exclusive expiry into a longer overlap than explicitly requested.
func ValidateClientSecretRotationRequest(r ClientSecretRotationRequest, p ManagedClientPolicy, issuer Issuer) (ClientSecretRotationRequest, error) {
	if r.Overlap < 0 || r.Overlap > 24*time.Hour || r.Overlap%time.Microsecond != 0 {
		return ClientSecretRotationRequest{}, ErrInvalidRequest
	}
	var err error
	r.Management, err = ValidateClientManagementRequest(r.Management, true, p, issuer)
	if err != nil {
		return ClientSecretRotationRequest{}, err
	}
	return r, nil
}

// ClientRotateSecret rotates one exact managed confidential client/version using
// current fresh human password authority, exact platform policy and CSRF.
func (s *Service) ClientRotateSecret(ctx context.Context, r ClientSecretRotationRequest) (out ClientSecretRotationResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = ClientSecretRotationResult{Completion: Completion{Outcome: identity.CommitOutcomeUnknown}}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if s.config.ManagedClients == nil {
		return out, ErrAccessDenied
	}
	r, err = ValidateClientSecretRotationRequest(r, *s.config.ManagedClients, s.config.Issuer)
	if err != nil {
		return out, err
	}
	owner, ok := s.deps.Store.(ClientSecretRotator)
	if !ok || nilDependency(owner) {
		return out, ErrAccessDenied
	}
	observed, err := s.source(ctx, r.Management.TenantID, r.Management.Session)
	if err != nil {
		return out, err
	}
	e := ClientSecretRotationExecution{Request: r, Session: observed}
	if e.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrAccessDenied
	}
	out, err = owner.RotateClientSecret(ctx, e)
	if ctx.Err() != nil {
		return ClientSecretRotationResult{Completion: out.Completion}, ctx.Err()
	}
	if err != nil {
		if out.Completion.Outcome == identity.CommitOutcomeConflict {
			return ClientSecretRotationResult{Completion: out.Completion}, ErrClientConflict
		}
		return ClientSecretRotationResult{Completion: out.Completion}, operationError(ctx, err)
	}
	if e.ValidateAt(s.config.Clock.Now()) != nil {
		return ClientSecretRotationResult{Completion: out.Completion}, ErrAccessDenied
	}
	if out.Completion.Replayed || out.Completion.Outcome != identity.CommitOutcomeCommitted {
		out.Secret = Token{}
	}
	return out, nil
}
