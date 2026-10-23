package oauthserver

import (
	"context"
	"fmt"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// DeviceClientSourceRequest borrows actual registered-client custody. Resource
// omission selects the sole registered resource; nil scopes select its complete
// OAuth-only scope ceiling. It conveys no subject or consent authority.
type DeviceClientSourceRequest struct {
	ClientID, Resource   string
	Scopes               []string
	ClientAuthentication ClientAuthentication
}

func (DeviceClientSourceRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("DeviceClientSourceRequest(redacted)"))
}
func (DeviceClientSourceRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (DeviceClientSourceRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// DeviceClientProjection is copied, configured core policy after current
// client authentication, not a reusable authentication proof. The device child
// consumes it directly; native mutation must reauthenticate and fence the same
// registration/version inside its existing transaction before issuing tokens.
// This first profile excludes workload clients and OIDC scope/subject policy.
type DeviceClientProjection struct {
	Issuer                                 Issuer
	Environment, Resource                  string
	Client                                 Client
	Scopes                                 []string
	AccessTTL, RefreshTTL, MaximumDuration time.Duration
}

func (DeviceClientProjection) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("DeviceClientProjection(redacted)"))
}

// DeviceClientSource admits only an explicitly permitted current registration
// through core's existing public/Basic authentication owner. It has no storage,
// device-code generation or side effects and advertises no endpoint.
func (s *Service) DeviceClientSource(ctx context.Context, r DeviceClientSourceRequest) (out DeviceClientProjection, err error) {
	defer func() {
		if recover() != nil {
			out, err = DeviceClientProjection{}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if !identifier(r.ClientID) || r.Resource != "" && !validOrigin(r.Resource) {
		return out, ErrInvalidRequest
	}
	c, err := s.currentClient(ctx, r.ClientID)
	if err != nil {
		return out, operationError(ctx, err)
	}
	if !c.DeviceAuthorization || c.Workload != nil || c.SubjectRegistration != nil || r.Resource != "" && r.Resource != c.Resource {
		return out, ErrAccessDenied
	}
	if r.Scopes == nil {
		r.Scopes = slices.Clone(c.Scopes)
	}
	scopes, err := validatedScopes(r.Scopes)
	if err != nil || !scopeSubset(scopes, c.Scopes) || hasExtensionScope(scopes) {
		return out, ErrInvalidScope
	}
	if err := s.authenticateClient(ctx, c, r.ClientAuthentication); err != nil {
		return out, operationError(ctx, err)
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return DeviceClientProjection{Issuer: s.config.Issuer, Environment: s.config.Environment, Resource: c.Resource, Client: c.snapshot(), Scopes: scopes, AccessTTL: s.config.AccessTTL, RefreshTTL: s.config.RefreshTTL, MaximumDuration: s.config.MaximumDuration}, nil
}

// DeviceSessionSourceRequest selects a tenant lookup and borrows a genuine
// browser credential. It never accepts a device-selected subject identifier.
type DeviceSessionSourceRequest struct {
	TenantID identity.TenantID
	Session  auth.BearerCredential
}

func (DeviceSessionSourceRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("DeviceSessionSourceRequest(redacted)"))
}
func (DeviceSessionSourceRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (DeviceSessionSourceRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// DeviceSessionProjection conserves existing session-owner sealed custody and
// the original nonrenewing read deadline. Native inspection/mutation must
// independently authenticate/fence this same source and current primary owners;
// approval/denial additionally require the session owner's actual synchronizer.
type DeviceSessionProjection struct {
	Request DeviceSessionSourceRequest
	Session session.GetResult
}

func (DeviceSessionProjection) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("DeviceSessionProjection(redacted)"))
}
func (DeviceSessionProjection) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (DeviceSessionProjection) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ValidateAt enforces the existing sensitive password-session freshness policy,
// including original <=20s observation and exclusive15-minute proof age. It
// grants no current authority and cannot replace native transactional fences.
func (p DeviceSessionProjection) ValidateAt(now time.Time) error {
	return (ClientManagementExecution{Request: ClientManagementRequest{TenantID: p.Request.TenantID}, Session: p.Session}).ValidateAt(now)
}

// DeviceSessionSource requires a current recently authenticated password human
// through the actual configured SessionService; it creates no replacement
// session engine, consent, device state or audit effect.
func (s *Service) DeviceSessionSource(ctx context.Context, r DeviceSessionSourceRequest) (out DeviceSessionProjection, err error) {
	defer func() {
		if recover() != nil {
			out, err = DeviceSessionProjection{}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if s.deps.Sessions == nil {
		return out, ErrAccessDenied
	}
	observed, err := s.source(ctx, r.TenantID, r.Session)
	if err != nil {
		return out, operationError(ctx, err)
	}
	p := DeviceSessionProjection{Request: r, Session: observed}
	if p.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrAccessDenied
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return p, nil
}
