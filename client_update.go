package oauthserver

import (
	"context"
	"fmt"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ClientUpdateRequest borrows existing sensitive management custody for an exact
// current managed confidential-human client/version. Redirects and Scopes are
// complete replacements within immutable configured ceilings, not merge patches.
// ID, owner, resource, authentication method and secret generations cannot change.
// Every committed replacement advances authority and invalidates old consent and
// grants; unchanged Basic custody requires new explicit authorization afterward.
type ClientUpdateRequest struct {
	Management ClientManagementRequest
	Redirects  []string
	Scopes     []string
}

func (ClientUpdateRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ClientUpdateRequest(redacted)"))
}
func (ClientUpdateRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ClientUpdateRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ClientUpdateExecution retains original sealed session custody, not permission.
// The native owner independently authenticates borrowed Management.Session and
// repeats current platform policy, CSRF, actor/version and original expiry fences.
type ClientUpdateExecution struct {
	Request ClientUpdateRequest
	Session session.GetResult
}

func (ClientUpdateExecution) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ClientUpdateExecution(redacted)"))
}
func (ClientUpdateExecution) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ClientUpdateExecution) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ValidateAt checks the original nonrenewing sensitive management observation.
func (e ClientUpdateExecution) ValidateAt(now time.Time) error {
	return (ClientManagementExecution{Request: e.Request.Management, Session: e.Session, Delete: true}).ValidateAt(now)
}

// ClientUpdateResult contains safe historical committed metadata and completion
// only. No secret is generated or revealed by update, retry or recovery.
type ClientUpdateResult struct {
	Client     Client
	Completion Completion
}

// ClientUpdater is optional and additive; Store and ClientManager do not acquire
// a mandatory method. Native activation requires compatible forward history.
type ClientUpdater interface {
	UpdateClient(context.Context, ClientUpdateExecution) (ClientUpdateResult, error)
}

// ValidateClientUpdateRequest copies a complete bounded replacement. Embedded
// Management registration edits are forbidden; neither validation nor configured
// owner selection authenticates a manager.
func ValidateClientUpdateRequest(r ClientUpdateRequest, p ManagedClientPolicy, issuer Issuer) (ClientUpdateRequest, error) {
	var err error
	r.Management, err = ValidateClientManagementRequest(r.Management, true, p, issuer)
	if err != nil {
		return ClientUpdateRequest{}, err
	}
	if _, err := identity.ParseSubjectID(r.Management.ClientID[len(ManagedClientPrefix):]); err != nil {
		return ClientUpdateRequest{}, ErrInvalidRequest
	}
	replacement := r.Management
	replacement.ClientID, replacement.Version = "", 0
	replacement.Redirects, replacement.Scopes = r.Redirects, r.Scopes
	replacement, err = ValidateClientManagementRequest(replacement, false, p, issuer)
	if err != nil {
		return ClientUpdateRequest{}, err
	}
	r.Redirects, r.Scopes = replacement.Redirects, replacement.Scopes
	return r, nil
}

// ClientUpdate atomically replaces only redirects/scopes of one exact managed
// registration. Existing fresh-session, origin/CSRF and keyed native management
// authority remain mandatory. Static/public/workload/OIDC variants are unselected.
func (s *Service) ClientUpdate(ctx context.Context, r ClientUpdateRequest) (out ClientUpdateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = ClientUpdateResult{Completion: Completion{Outcome: identity.CommitOutcomeUnknown}}, ErrUnavailable
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
	r, err = ValidateClientUpdateRequest(r, *s.config.ManagedClients, s.config.Issuer)
	if err != nil {
		return out, err
	}
	owner, ok := s.deps.Store.(ClientUpdater)
	if !ok || nilDependency(owner) {
		return out, ErrAccessDenied
	}
	observed, err := s.source(ctx, r.Management.TenantID, r.Management.Session)
	if err != nil {
		return out, err
	}
	e := ClientUpdateExecution{Request: r, Session: observed}
	if e.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrAccessDenied
	}
	out, err = owner.UpdateClient(ctx, e)
	if ctx.Err() != nil {
		return ClientUpdateResult{Completion: out.Completion}, ctx.Err()
	}
	if err != nil {
		if out.Completion.Outcome == identity.CommitOutcomeConflict {
			return ClientUpdateResult{Completion: out.Completion}, ErrClientConflict
		}
		return ClientUpdateResult{Completion: out.Completion}, operationError(ctx, err)
	}
	if e.ValidateAt(s.config.Clock.Now()) != nil {
		return ClientUpdateResult{Completion: out.Completion}, ErrAccessDenied
	}
	if out.Completion.Outcome != identity.CommitOutcomeCommitted {
		return ClientUpdateResult{Completion: out.Completion}, nil
	}
	client, err := s.selectedClientReadProjection(out.Client)
	if err != nil || client.ID != r.Management.ClientID || client.Version != r.Management.Version+1 || !slices.Equal(client.Redirects, r.Redirects) || !slices.Equal(client.Scopes, r.Scopes) {
		return ClientUpdateResult{Completion: out.Completion}, ErrAccessDenied
	}
	out.Client = client
	return out, nil
}
