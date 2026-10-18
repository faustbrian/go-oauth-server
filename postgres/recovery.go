package oauthpostgres

import (
	"context"
	"fmt"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

// RecoveryRequest identifies one original command, never a new execution.
// OperationID is one of the four selected canonical OAuth operation IDs.
// Authorize requires the original current browser and tenant, with Token empty;
// continue additionally requires its original continuation. Token/revoke require
// the original client-bound protocol bearer, with Session/TenantID empty.
// No user, actor, scope, timestamp, redirect or command override is accepted.
// Session and Token are borrowed secret custody; never log or serialize them.
type RecoveryRequest struct {
	OperationID string
	CommandID   identity.CommandID
	ClientID    string
	TenantID    identity.TenantID
	Session     auth.BearerCredential
	Token       string
}

// Format redacts original bearer custody and correlated command scope.
func (RecoveryRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.RecoveryRequest(redacted)"))
}

// MarshalJSON denies implicit credential export.
func (RecoveryRequest) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

// MarshalText denies implicit credential export.
func (RecoveryRequest) MarshalText() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

// RecoveryResult contains only historical durability and bounded retry metadata.
// It contains no redirect, code, token, source identity or renewed permission.
// Unknown and live pending never prove rollback. Even committed recovery cannot
// redeliver an original credential or authorize another issuance.
type RecoveryResult struct {
	Outcome    identity.CommitOutcome
	CommandID  identity.CommandID
	RetryAfter time.Duration
}

// Format redacts correlated historical command metadata.
func (RecoveryResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.RecoveryResult(redacted)"))
}

// Recover authenticates original browser/grant custody and delegates solely to
// the existing coordinator's current-policy metadata reconciliation. It does
// not reserve, execute, generate, refresh admission or reveal retained output.
// Initial authorization authenticates its original encrypted preparation before
// disclosure because a random command ID alone does not prove client/session
// binding. Retain original keys/configuration and preparation history until
// recovery is retired. Missing/foreign custody denies; outages fail closed.
// Concurrent calls use independent native participants; earlier deadlines win.
func (s *Store) Recover(ctx context.Context, request RecoveryRequest) (out RecoveryResult, err error) {
	defer func() {
		if recover() != nil {
			out = RecoveryResult{Outcome: identity.CommitOutcomeUnknown, CommandID: request.CommandID}
			err = oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if _, err := identity.ParseCommandID(string(request.CommandID)); err != nil || len(request.ClientID) == 0 || len(request.ClientID) > 128 {
		return out, oauth.ErrInvalidRequest
	}
	var client oauth.Client
	for _, candidate := range s.config.Protocol.Clients {
		if candidate.ID == request.ClientID {
			client = candidate
			break
		}
	}
	if client.ID == "" {
		return out, oauth.ErrAccessDenied
	}
	var p *phase
	var observed session.GetResult
	switch request.OperationID {
	case "identity.oauth-server.authorize", "identity.oauth-server.continue":
		observed, err = s.recoverySession(ctx, request)
		if err != nil {
			return out, err
		}
		bindings, err := observed.Session.Bindings()
		if err != nil {
			return out, oauth.ErrAccessDenied
		}
		source, err := sessionpg.OriginalSessionFields(observed.Session)
		if err != nil {
			return out, oauth.ErrAccessDenied
		}
		if request.OperationID == "identity.oauth-server.authorize" {
			if request.Token != "" {
				return out, oauth.ErrInvalidRequest
			}
			p = &phase{store: s, client: client}
			p.input = phaseInput{Schema: 1, Configuration: s.identity, Transition: createInteraction, Grant: grantRecord{ID: string(request.CommandID), Tenant: bindings.TenantID, User: bindings.UserID, Source: source}, Intent: s.intent("authorize", string(request.CommandID))}
			p.bind(request.CommandID, request.OperationID, string(request.CommandID))
		} else {
			target, err := s.lookup(ctx, request.Token, client, []oauth.TokenKind{oauth.TokenContinuation})
			if err != nil {
				return out, publicError(ctx, err, oauth.ErrAccessDenied)
			}
			if request.CommandID != target.Transition || target.Grant.Tenant != bindings.TenantID || target.Grant.User != bindings.UserID || !sameJSON(source, target.Grant.Source) {
				return out, oauth.ErrAccessDenied
			}
			p = s.targetPhase(target, client, approveInteraction, request.OperationID, request.CommandID, s.intent("recover"), "")
		}
	case "identity.oauth-server.token", "identity.oauth-server.revoke":
		if request.TenantID != "" || request.Session.Token() != "" {
			return out, oauth.ErrInvalidRequest
		}
		kinds := []oauth.TokenKind{oauth.TokenCode, oauth.TokenRefresh}
		if request.OperationID == "identity.oauth-server.revoke" {
			kinds = []oauth.TokenKind{oauth.TokenAccess, oauth.TokenRefresh}
		}
		target, err := s.lookup(ctx, request.Token, client, kinds)
		if err != nil {
			return out, publicError(ctx, err, oauth.ErrAccessDenied)
		}
		transition := exchangeCode
		if request.OperationID == "identity.oauth-server.revoke" {
			if request.CommandID != target.Replay {
				return out, oauth.ErrAccessDenied
			}
			transition = revokeFamily
			if target.Kind == oauth.TokenAccess {
				transition = revokeAccess
			}
		} else if request.CommandID == target.Replay {
			transition = rejectReplay
		} else if request.CommandID != target.Transition {
			return out, oauth.ErrAccessDenied
		}
		p = s.targetPhase(target, client, transition, request.OperationID, request.CommandID, s.intent("recover"), "")
	default:
		return out, oauth.ErrInvalidRequest
	}
	if err := s.coordinator(p); err != nil {
		return out, err
	}
	if request.OperationID == "identity.oauth-server.authorize" {
		wire, generation, err := p.coordinator.QueryFeaturePreparation(ctx, p.query(), p.caller(), p.registration(), p)
		if err != nil {
			return out, publicError(ctx, err, oauth.ErrAccessDenied)
		}
		defer clear(wire)
		if err := p.restore(ctx, generation, wire, true); err != nil {
			return out, publicError(ctx, err, oauth.ErrAccessDenied)
		}
		// Authentication of retained context is not a credential delivery path.
		p.output = preparedOutput{}
	}
	if request.Session.Token() != "" && observed.ValidateAt(s.now()) != nil {
		return out, oauth.ErrAccessDenied
	}
	result, err := p.coordinator.RecoverFeatureCommand(ctx, p.query(), p.caller())
	out = RecoveryResult{Outcome: result.Outcome, CommandID: request.CommandID, RetryAfter: result.RetryAfter}
	return out, publicError(ctx, err, oauth.ErrAccessDenied)
}

func (s *Store) recoverySession(ctx context.Context, request RecoveryRequest) (session.GetResult, error) {
	if len(request.TenantID) == 0 || len(request.TenantID) > 128 {
		return session.GetResult{}, oauth.ErrInvalidRequest
	}
	token, err := session.ParseToken(request.Session.Token())
	if err != nil {
		return session.GetResult{}, oauth.ErrAccessDenied
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return session.GetResult{}, oauth.ErrAccessDenied
	}
	reader, err := sessionpg.NewSessionService(s.pool, s.config.Session)
	if err != nil {
		return session.GetResult{}, oauth.ErrUnavailable
	}
	observed, err := reader.Get(ctx, session.GetRequest{TenantID: request.TenantID, Credential: credential})
	if err != nil {
		return session.GetResult{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if !observed.Authenticated || observed.ValidateAt(s.now()) != nil {
		return session.GetResult{}, oauth.ErrAccessDenied
	}
	return observed, nil
}
