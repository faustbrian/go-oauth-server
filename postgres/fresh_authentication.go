package oauthpostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

type authenticationSelection struct {
	Requirement oauth.OIDCAuthenticationRequirement
	Until       time.Time
}

var _ kernel.OAuthContinuationPreparationContributor = (*phase)(nil)

// OAuthContinuationHandoff declares only a candidate's exact immutable
// predecessor. It cannot establish the journal outcome or advance native state.
func (p *phase) OAuthContinuationHandoff(command identity.Command) (identity.CommandID, bool, error) {
	if p == nil || command != p.command {
		return "", false, identity.ForbiddenError{}
	}
	previous := p.input.ContinuationPrevious
	if previous == "" {
		return "", false, nil
	}
	if p.input.Transition != approveInteraction || p.input.Binding.OperationID != "identity.oauth-server.continue" || previous == p.input.Binding.CommandID || p.input.PreviousSource == nil || p.input.Authentication == nil || p.input.Authentication.Requirement != oauth.OIDCAuthenticationCurrent || !authenticationRequested(p.input.Request) {
		return "", false, identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(previous)); err != nil {
		return "", false, identity.ForbiddenError{}
	}
	return previous, true, nil
}

// AdvanceOAuthContinuation is writable only in the coordinator's checked
// preparation-start handoff. The existing artifact is a current-attempt pointer,
// not an outcome journal; its token, original scope and expiry never change.
func (p *phase) AdvanceOAuthContinuation(ctx context.Context, work kernel.Work, command identity.Command, previous identity.CommandID) error {
	if err := work.RequireOAuthContinuationHandoff(ctx, p, command, previous); err != nil {
		return err
	}
	selected, requested, err := p.OAuthContinuationHandoff(command)
	if err != nil || !requested || selected != previous {
		return identity.ForbiddenError{}
	}
	if err := p.check(ctx, work, false); err != nil {
		return err
	}
	if err := p.checkArtifactExpiry(ctx, work); err != nil {
		return err
	}
	i := p.input
	n, err := work.Exec(ctx, `UPDATE `+p.store.schema+`.artifacts SET transition_command=$1 WHERE digest_version=$2 AND digest=$3 AND artifact_id=$4 AND grant_id=$5 AND client_id=$6 AND kind=$7 AND state='active' AND transition_command=$8 AND expires_at=$9`, string(i.Binding.CommandID), i.Target.KeyVersion, i.Target.Sum[:], i.TargetID, i.Grant.ID, i.Grant.ClientID, int16(oauth.TokenContinuation), string(previous), i.TargetExpires)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *phase) checkContinuationAttempt(ctx context.Context, work kernel.Work) error {
	i := p.input
	if i.Transition != approveInteraction || i.Authentication == nil {
		return nil
	}
	rows, err := work.Query(ctx, `SELECT transition_command FROM `+p.store.schema+`.artifacts WHERE digest_version=$1 AND digest=$2 AND artifact_id=$3 AND grant_id=$4 AND client_id=$5 AND kind=$6 AND state='active' FOR UPDATE`, i.Target.KeyVersion, i.Target.Sum[:], i.TargetID, i.Grant.ID, i.Grant.ClientID, int16(oauth.TokenContinuation))
	if err != nil {
		return err
	}
	defer rows.Close()
	var actual string
	if !rows.Next() {
		if rows.Err() != nil {
			return rows.Err()
		}
		return identity.ForbiddenError{}
	}
	if err := rows.Scan(&actual); err != nil {
		return err
	}
	if rows.Next() || rows.Err() != nil || actual != string(i.Binding.CommandID) {
		return identity.ForbiddenError{}
	}
	return nil
}

func authenticationRequested(request oauth.AuthorizationRequest) bool {
	return request.Prompt != "" || request.MaxAge != nil
}

func copyAuthorizationRequest(request oauth.AuthorizationRequest) oauth.AuthorizationRequest {
	request.Scopes = append([]string(nil), request.Scopes...)
	if request.MaxAge != nil {
		owned := *request.MaxAge
		request.MaxAge = &owned
	}
	return request
}

func (s *Store) authenticationPolicy(ctx context.Context, policy func(context.Context, oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error), client oauth.Client, request oauth.AuthorizationRequest, observed session.GetResult, original *oauth.OIDCReauthenticationInput) (*authenticationSelection, error) {
	if !authenticationRequested(request) {
		return nil, nil
	}
	if policy == nil {
		return nil, oauth.ErrAccessDenied
	}
	// ValidateClient returns an owned snapshot, matching core's callback
	// boundary: borrowed extension code cannot mutate retained native policy.
	ownedClient, err := oauth.ValidateClient(client)
	if err != nil {
		return nil, oauth.ErrAccessDenied
	}
	projection, err := policy(ctx, oauth.OIDCAuthorizationInput{Issuer: s.config.Protocol.Issuer, Environment: s.config.Protocol.Environment, Client: ownedClient, Request: copyAuthorizationRequest(request), Session: observed, Reauthentication: original})
	if err != nil {
		return nil, err
	}
	if !projection.Accepted || projection.Authentication != oauth.OIDCAuthenticationCurrent && projection.Authentication != oauth.OIDCAuthenticationFresh || projection.Authentication == oauth.OIDCAuthenticationFresh && !projection.AuthenticationUntil.IsZero() {
		return nil, oauth.ErrAccessDenied
	}
	return &authenticationSelection{Requirement: projection.Authentication, Until: projection.AuthenticationUntil}, nil
}

// The new authentication is trusted only through its actual Get custody,
// bearer/CSRF and live primary record checks in Work. These comparisons conserve
// the original flow's same-account scope; a timestamp alone proves nothing.
func validateFreshSource(original session.Session, observed session.GetResult, requestedAt time.Time) error {
	before, err := original.Bindings()
	if err != nil {
		return oauth.ErrAccessDenied
	}
	after, err := observed.Session.Bindings()
	if err != nil || before.TenantID != after.TenantID || before.UserID != after.UserID || before.SessionID == after.SessionID || before.Authentication.Proof.ID == after.Authentication.Proof.ID || !after.Authentication.Proof.IssuedAt.After(requestedAt) {
		return oauth.ErrAccessDenied
	}
	return nil
}

func (p *phase) checkPreviousSource(ctx context.Context, w kernel.Work) error {
	if p.input.PreviousSource == nil {
		return nil
	}
	if p.input.Transition != approveInteraction || p.input.Authentication == nil || p.input.Authentication.Requirement != oauth.OIDCAuthenticationCurrent {
		return identity.ForbiddenError{}
	}
	old, err := sessionpg.OriginalSessionFromFields(p.input.Grant.Tenant, p.input.Grant.User, p.input.PreviousSource)
	if err != nil || validateFreshSource(old, p.observation, p.input.Grant.CreatedAt) != nil {
		return identity.ForbiddenError{}
	}
	directory, credential, authorization, err := sessionpg.OriginalSessionAdmission(p.store.config.Session.Profile, old, p.input.Binding)
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveActorCredential(ctx, p, credential); err != nil {
		return err
	}
	if err := w.RequireActiveActorAuthorization(ctx, p, authorization); err != nil {
		return err
	}
	return sessionpg.RequireSession(ctx, w, p.store.config.Session.Repository, old)
}
