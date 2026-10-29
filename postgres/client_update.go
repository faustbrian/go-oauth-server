package oauthpostgres

import (
	"context"
	"errors"
	"slices"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

type clientReplacement struct {
	Redirects, Scopes   []string
	PostLogoutRedirects []string `json:",omitempty"`
}

// Original encrypted v1 preparation omitted SecretVersion because registration
// and digest generation were coupled. Its original client version remains the
// only valid interpretation. New update-aware preparation captures the actual
// digest generation before any authority-version change (never a current read).
func (p *phase) managementSecretVersion() uint64 {
	if p.input.ClientChange.SecretVersion != 0 {
		return p.input.ClientChange.SecretVersion
	}
	return p.client.Version
}

func (s *Store) updatedClient(c oauth.Client, r *clientReplacement) (oauth.Client, error) {
	if r == nil || c.Version == ^uint64(0) {
		return oauth.Client{}, oauth.ErrInvalidRequest
	}
	// Metadata replacement remains the OAuth-only profile. Check the original
	// scopes before overwriting them, including at the protected mutation call,
	// so selecting OIDC creation cannot also convert an existing OIDC client.
	policy := s.config.Protocol.ManagedClients
	if policy == nil || !scopeSubset(c.Scopes, policy.Scopes.Scopes()) {
		return oauth.Client{}, oauth.ErrAccessDenied
	}
	c.Version++
	c.Redirects, c.Scopes = slices.Clone(r.Redirects), slices.Clone(r.Scopes)
	c.PostLogoutRedirects = slices.Clone(r.PostLogoutRedirects)
	c, err := oauth.ValidateClient(c)
	if err != nil || !s.managedMetadata(c) {
		return oauth.Client{}, oauth.ErrInvalidRequest
	}
	return c, nil
}

var _ oauth.ClientUpdater = (*Store)(nil)

// UpdateClient uses original native request-key/encrypted preparation and sole
// Work. Only registration authority advances; both digest slots/generations and
// the predecessor's original exclusive expiry remain unchanged. Existing grants
// and consent are fenced by that advanced registration authority.
func (s *Store) UpdateClient(ctx context.Context, e oauth.ClientUpdateExecution) (out oauth.ClientUpdateResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.ClientUpdateResult{Completion: oauth.Completion{Outcome: identity.CommitOutcomeUnknown}}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if !s.config.ClientMetadataUpdates || s.config.Protocol.ManagedClients == nil {
		return out, oauth.ErrAccessDenied
	}
	r, err := oauth.ValidateClientUpdateRequest(e.Request, *s.config.Protocol.ManagedClients, s.config.Protocol.Issuer)
	if err != nil {
		return out, err
	}
	const action = "identity.oauth-server.client-update"
	c, err := s.managementObservation(ctx, oauth.ClientManagementExecution{Request: r.Management, Session: e.Session, Delete: true}, action)
	if err != nil {
		return out, err
	}
	p, err := s.clientManagementPhase(ctx, c, action)
	if err != nil {
		return out, err
	}
	p.input.Transition = updateManagedClient
	p.input.ClientChange.Replacement = &clientReplacement{Redirects: r.Redirects, Scopes: r.Scopes, PostLogoutRedirects: r.PostLogoutRedirects}
	if _, err := s.updatedClient(p.client, p.input.ClientChange.Replacement); err != nil {
		return out, err
	}
	if err = s.coordinator(p); err != nil {
		return out, err
	}
	intent, err := p.clientIntent(r.Management)
	if err != nil {
		return out, err
	}
	b, _ := c.Session.Session.Bindings()
	scope := kernel.RequestKeyScope{TenantID: b.TenantID, ActorID: identity.ActorID(b.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: action}
	caller := p.caller()
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(action)}
	k, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.Management.RequestKey, intent, caller, p.registration(), p)
	if err != nil {
		var conflict identity.ConflictError
		var unknown identity.UnknownCommitError
		if errors.As(err, &conflict) {
			out.Completion.Outcome = identity.CommitOutcomeConflict
		}
		if errors.As(err, &unknown) {
			out.Completion.Outcome, out.Completion.CommandID = identity.CommitOutcomeUnknown, unknown.CommandID
		}
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	defer clear(wire)
	out.Completion = oauth.Completion{CommandID: k.Admission.CommandID, Outcome: identity.CommitOutcomeUnknown}
	if err = p.restoreClientKey(ctx, k, wire); err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	result, err := p.execute(ctx)
	out.Completion.Outcome, out.Completion.Replayed = result.Outcome, !p.applied
	if err != nil || ctx.Err() != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if _, err := s.managementObservation(ctx, c, action); err != nil {
		return out, err
	}
	// The external policy callback may withdraw its owning actor epoch. The
	// final public session-owner read must follow it, without renewing original
	// invocation or encrypted-preparation custody.
	current, err := s.recoverySession(ctx, RecoveryRequest{TenantID: r.Management.TenantID, Session: r.Management.Session})
	if err != nil {
		return out, err
	}
	originalFields, err := sessionpg.OriginalSessionFields(c.Session.Session)
	if err != nil {
		return out, oauth.ErrAccessDenied
	}
	currentFields, err := sessionpg.OriginalSessionFields(current.Session)
	if err != nil || !sameJSON(originalFields, currentFields) {
		return out, oauth.ErrAccessDenied
	}
	db, err := s.introspectionTime(ctx)
	if err != nil {
		return out, err
	}
	now := s.now()
	if c.ValidateAt(now) != nil || c.ValidateAt(db) != nil || now.Before(p.input.CreatedAt) || db.Before(p.input.CreatedAt) || !now.Before(p.input.ObservationUntil) || !db.Before(p.input.ObservationUntil) {
		return out, oauth.ErrAccessDenied
	}
	if result.Outcome == identity.CommitOutcomeCommitted {
		// This is the original committed result, never today's aggregate projected
		// onto an older command after later update/rotation/deletion.
		out.Client, err = s.updatedClient(p.client, p.input.ClientChange.Replacement)
	}
	return out, err
}
