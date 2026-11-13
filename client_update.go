package oauthserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ClientUpdateRequest borrows existing sensitive management custody for an exact
// current managed browser client/version. Management.Public is the expected
// immutable class: false selects confidential Basic, true requires PublicClients
// and selects public none. It never requests a class conversion. Redirects and
// Scopes are complete replacements within immutable ceilings, not merge patches.
// ID, owner, resource, authentication method and secret generations cannot change.
// Every committed replacement advances authority and invalidates old consent and
// grants; unchanged Basic custody requires new explicit authorization afterward.
type ClientUpdateRequest struct {
	Management          ClientManagementRequest
	Redirects           []string
	PostLogoutRedirects []string
	Scopes              []string
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
	if r.Management.Public && !p.PublicClients {
		return ClientUpdateRequest{}, ErrAccessDenied
	}
	// Delete-shaped custody validates ID/version and forbids embedded edits.
	// Public is an update-only class precondition, not a deletion registration edit.
	public := r.Management.Public
	management := r.Management
	management.Public = false
	var err error
	r.Management, err = ValidateClientManagementRequest(management, true, p, issuer)
	if err != nil {
		return ClientUpdateRequest{}, err
	}
	r.Management.Public = public
	// Creation does not select OIDC replacement. This explicit finite profile
	// preserves openid-only semantics; current source metadata is fenced later.
	if hasExtensionScope(r.Scopes) && (!p.PublicOIDCUpdates || !p.PublicOIDC || !r.Management.Public || !minimalManagedBrowserOIDC(false, r.Scopes)) {
		return ClientUpdateRequest{}, ErrInvalidScope
	}
	if _, err := identity.ParseSubjectID(r.Management.ClientID[len(ManagedClientPrefix):]); err != nil {
		return ClientUpdateRequest{}, ErrInvalidRequest
	}
	replacement := r.Management
	replacement.ClientID, replacement.Version = "", 0
	replacement.Redirects, replacement.Scopes = r.Redirects, r.Scopes
	replacement.PostLogoutRedirects = r.PostLogoutRedirects
	replacement, err = ValidateClientManagementRequest(replacement, false, p, issuer)
	if err != nil {
		return ClientUpdateRequest{}, err
	}
	r.Redirects, r.Scopes = replacement.Redirects, replacement.Scopes
	r.PostLogoutRedirects = replacement.PostLogoutRedirects
	return r, nil
}

// AllowsMetadataReplacement checks only immutable source/target profile shape,
// never manager authority or registration existence. OAuth replacements retain
// their original ceiling, including stored device capability. Explicit public
// OIDC replacement preserves the existing minimal browser class: default subject,
// none authentication and openid only, with no conversion from another class.
// Native owners must repeat this against protected original metadata.
func (p ManagedClientPolicy) AllowsMetadataReplacement(current Client, scopes []string) bool {
	if current.Workload != nil {
		return false
	}
	if !hasExtensionScope(current.Scopes) && !hasExtensionScope(scopes) {
		return scopeSubset(current.Scopes, p.Scopes.values) && scopeSubset(scopes, p.Scopes.values)
	}
	defaultPublicOIDC := current.Public && current.AuthenticationMethod == "none" && current.SubjectRegistration == nil && minimalManagedBrowserOIDC(current.DeviceAuthorization, current.Scopes)
	return p.PublicOIDCUpdates && defaultPublicOIDC && minimalManagedBrowserOIDC(current.DeviceAuthorization, scopes) && p.AllowsRegistration(current.Public, current.DeviceAuthorization, current.Scopes, nil)
}

// ClientUpdate atomically replaces only redirects/scopes of one exact managed
// registration. Existing fresh-session, origin/CSRF and keyed native management
// authority remain mandatory. Public clients retain none authentication and no
// secret custody. Public/default-subject/openid-only browser registrations need
// the explicit PublicOIDCUpdates selection and composed OIDC owner. Other OIDC,
// static and workload variants remain unselected.
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
	if hasExtensionScope(r.Scopes) && nilDependency(s.deps.OIDC) {
		return out, ErrAccessDenied
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
	if s.config.ManagedClients.ConfidentialOIDC || s.config.ManagedClients.PublicOIDCUpdates {
		// Fence the original class before invoking even an older updater. The
		// native owner must repeat this against protected current state for races.
		current, err := s.currentClient(ctx, r.Management.ClientID)
		if err != nil && !errors.Is(err, ErrInvalidClient) {
			return out, operationError(ctx, err)
		}
		// Missing/tombstoned current metadata cannot invalidate original keyed
		// history. Only its existing updater may recover that result or deny a
		// fresh request; this classified absence grants no mutation permission.
		if err == nil && !s.config.ManagedClients.AllowsMetadataReplacement(current, r.Scopes) || e.ValidateAt(s.config.Clock.Now()) != nil {
			return out, ErrAccessDenied
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
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
	if err != nil || client.ID != r.Management.ClientID || client.Version != r.Management.Version+1 || client.Public != r.Management.Public || !slices.Equal(client.Redirects, r.Redirects) || !slices.Equal(client.PostLogoutRedirects, r.PostLogoutRedirects) || !slices.Equal(client.Scopes, r.Scopes) {
		return ClientUpdateResult{Completion: out.Completion}, ErrAccessDenied
	}
	if hasExtensionScope(r.Scopes) && !s.config.ManagedClients.AllowsMetadataReplacement(client, r.Scopes) {
		return ClientUpdateResult{Completion: out.Completion}, ErrAccessDenied
	}
	out.Client = client
	return out, nil
}
