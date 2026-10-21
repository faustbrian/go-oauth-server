package oauthpostgres

import (
	"context"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

var _ oauth.ClientSecretRotator = (*Store)(nil)

func (p *phase) rotationOverlap() *time.Duration {
	if p.input.Transition != rotateManagedSecret || p.input.ClientChange == nil {
		return nil
	}
	d := p.input.ClientChange.Overlap
	return &d
}

// RotateClientSecret uses the existing immutable encrypted request preparation,
// manager authority and sole coordinator Work. Secret changes advance the same
// oauth_client dimension as revocation (LIFECYCLE_CASCADES.md), so no old grant
// or consent survives merely because its Basic secret has bounded overlap.
func (s *Store) RotateClientSecret(ctx context.Context, e oauth.ClientSecretRotationExecution) (out oauth.ClientSecretRotationResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.ClientSecretRotationResult{Completion: oauth.Completion{Outcome: identity.CommitOutcomeUnknown}}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if !s.config.ClientSecretRotation || s.config.Protocol.ManagedClients == nil {
		return out, oauth.ErrAccessDenied
	}
	r, err := oauth.ValidateClientSecretRotationRequest(e.Request, *s.config.Protocol.ManagedClients, s.config.Protocol.Issuer)
	if err != nil {
		return out, err
	}
	const action = "identity.oauth-server.client-rotate-secret"
	c, err := s.managementObservation(ctx, oauth.ClientManagementExecution{Request: r.Management, Session: e.Session, Delete: true}, action)
	if err != nil {
		return out, err
	}
	p, err := s.clientManagementPhase(ctx, c, action)
	if err != nil {
		return out, err
	}
	p.input.Transition = rotateManagedSecret
	p.input.ClientChange.Overlap = r.Overlap
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
			out.Completion.Outcome = identity.CommitOutcomeUnknown
			out.Completion.CommandID = unknown.CommandID
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
	now := s.now()
	if c.ValidateAt(now) != nil || now.Before(p.input.CreatedAt) || !now.Before(p.input.ObservationUntil) {
		return out, oauth.ErrAccessDenied
	}
	out.Client = p.client
	out.Client.Version++
	if p.input.ClientChange.Overlap > 0 {
		out.PredecessorExpiresAt = p.input.CreatedAt.Add(p.input.ClientChange.Overlap)
	}
	if p.applied && result.Outcome == identity.CommitOutcomeCommitted {
		out.Secret, err = oauth.ParseToken(p.output.ClientSecret)
	}
	return out, err
}
