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
	// Creation does not select OIDC replacement. Extra public claims require
	// their separate operation selection, not just a creation scope ceiling.
	oidcUpdateSelected := p.ConfidentialOIDC && p.ConfidentialOIDCUpdates
	allowedOIDCScopes := minimalManagedBrowserOIDC(false, r.Scopes)
	if r.Management.Public {
		oidcUpdateSelected = p.PublicOIDC && p.PublicOIDCUpdates
		if p.PublicOIDCClaimsUpdates {
			allowedOIDCScopes = managedPublicClaimScopes(false, r.Scopes)
		}
	}
	if hasExtensionScope(r.Scopes) && (!oidcUpdateSelected || !allowedOIDCScopes) {
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
// their original ceiling, including stored device capability. Explicit OIDC
// replacement preserves the registered subject policy and original none/Basic
// authentication. Pairwise and public account claims require separate operation
// selections within their existing trusted registration/scope ceilings.
// Native owners must repeat this against protected original metadata.
func (p ManagedClientPolicy) AllowsMetadataReplacement(current Client, scopes []string) bool {
	if current.Workload != nil {
		return false
	}
	if !hasExtensionScope(current.Scopes) && !hasExtensionScope(scopes) {
		return scopeSubset(current.Scopes, p.Scopes.values) && scopeSubset(scopes, p.Scopes.values)
	}
	if !hasExtensionScope(current.Scopes) || !hasExtensionScope(scopes) {
		return false
	}
	if current.Public {
		if !p.PublicOIDCUpdates || current.AuthenticationMethod != "none" || current.SubjectRegistration != nil {
			return false
		}
		if p.PublicOIDCClaimsUpdates {
			return p.AllowsRegistration(true, current.DeviceAuthorization, current.Scopes, nil) && p.AllowsRegistration(true, current.DeviceAuthorization, scopes, nil)
		}
		return minimalManagedBrowserOIDC(current.DeviceAuthorization, current.Scopes) && minimalManagedBrowserOIDC(current.DeviceAuthorization, scopes) && p.AllowsRegistration(true, current.DeviceAuthorization, current.Scopes, nil)
	}
	if !p.ConfidentialOIDCUpdates || current.AuthenticationMethod != "client_secret_basic" || !minimalManagedBrowserOIDC(current.DeviceAuthorization, current.Scopes) || !minimalManagedBrowserOIDC(current.DeviceAuthorization, scopes) {
		return false
	}
	if current.SubjectRegistration != nil && !p.ConfidentialPairwiseUpdates {
		return false
	}
	return p.AllowsRegistration(false, current.DeviceAuthorization, current.Scopes, current.SubjectRegistration)
}

func sameSubjectRegistration(a, b *OIDCSubjectRegistration) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// ClientUpdate atomically replaces only redirects/scopes of one exact managed
// registration. Existing fresh-session, origin/CSRF and keyed native management
// authority remain mandatory. Public clients retain none authentication and no
// secret custody. Default-subject/openid-only browser registrations need their
// explicit PublicOIDCUpdates or ConfidentialOIDCUpdates selection and composed
// OIDC owner. Confidential pairwise and public account-claim replacements require
// their additional operation selectors; other OIDC/static/workload variants deny.
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
	var original *Client
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
		if err == nil {
			// A request cannot change the immutable class or attach another
			// registered sector, even if both are trusted creation selections.
			if current.Public != r.Management.Public || !s.config.ManagedClients.AllowsMetadataReplacement(current, r.Scopes) || !validSubjectRegistration(Client{SubjectRegistration: current.SubjectRegistration, Redirects: r.Redirects}) {
				return out, ErrAccessDenied
			}
			original = &current
		}
		if e.ValidateAt(s.config.Clock.Now()) != nil {
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
	if original != nil && !sameSubjectRegistration(original.SubjectRegistration, client.SubjectRegistration) {
		return ClientUpdateResult{Completion: out.Completion}, ErrAccessDenied
	}
	out.Client = client
	return out, nil
}
