package oauthserver

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ClientReadRequest borrows current browser custody for private managed-client
// metadata. Get requires only ClientID; list requires Limit in 1..100 and accepts
// Cursor, but no ClientID. Owner/tenant are exact configured preconditions, never
// management authorization. Safe reads require neither CSRF nor sensitive-change
// freshness. Credentials must remain alive until the bounded call returns.
type ClientReadRequest struct {
	Owner    Owner
	TenantID identity.TenantID
	Session  auth.BearerCredential
	ClientID string
	Limit    uint16
	Cursor   Cursor
}

func (ClientReadRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ClientReadRequest(redacted)"))
}
func (ClientReadRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ClientReadRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ClientReadExecution carries borrowed browser custody and the original session
// observation. This exported struct is not sealed authentication evidence or a
// permission assertion. Native readers independently authenticate Request.Session
// and compare exact original session/actor/tenant, then repeat current platform
// policy and client status/version fences without renewing original <=20s
// validity. This profile selects verified password humans only.
type ClientReadExecution struct {
	Request ClientReadRequest
	Session session.GetResult
}

func (ClientReadExecution) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ClientReadExecution(redacted)"))
}
func (ClientReadExecution) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ClientReadExecution) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ValidateAt checks original current-read custody only. Unlike client mutations,
// private safe reads do not require Lifetime.Fresh or a 15-minute password age.
// Current native authorization and owner/status comparison remain mandatory.
func (e ClientReadExecution) ValidateAt(now time.Time) error {
	if e.Session.ValidateAt(now) != nil {
		return ErrAccessDenied
	}
	b, err := e.Session.Session.Bindings()
	if err != nil || b.TenantID != e.Request.TenantID || b.Authentication.Kind != session.AuthenticationVerified || b.Authentication.Proof.Method != "password" || b.Authentication.Proof.Assurance != auth.AssuranceSingleFactor {
		return ErrAccessDenied
	}
	a, err := b.Authority.Bindings()
	if err != nil || a.Organization.Present || a.Factor.Present || a.Passkey.Present {
		return ErrAccessDenied
	}
	return nil
}

// ClientReader is an additive optional authenticated private-read owner. The
// protocol's trusted CurrentClientRegistry is not this management API. Readers
// return no secret/digest/ciphertext or credentials, create no durable effects,
// and return zero results on denial, cancellation or unavailable authority.
type ClientReader interface {
	ClientGet(context.Context, ClientReadExecution) (ClientGetResult, error)
	ClientList(context.Context, ClientReadExecution) (ClientListResult, error)
}

// ClientGetResult contains one safe current registration, not authentication or
// an authorization lease. Mutations must independently admit its exact version.
type ClientGetResult struct{ Client Client }

// ClientListResult contains a bounded independently owned page and scoped cursor.
// Pages are keyset reads, not an enduring multi-request snapshot or permission.
type ClientListResult struct {
	Page       ClientListPage
	NextCursor Cursor
}

// ClientListPage owns up to 100 safe managed human-web registrations in
// ascending ID order. Zero is invalid; an explicitly constructed empty page is
// valid. Items returns independent copies, including nested collections.
type ClientListPage struct {
	items []Client
	valid bool
}

// NewClientListPage checks the finite metadata class and deep-copies its items.
// Static/workload clients, unselected OIDC classes and unsorted/duplicate IDs
// are invalid. Minimal public openid metadata still requires service selection.
func NewClientListPage(items []Client) (ClientListPage, error) {
	if len(items) > 100 {
		return ClientListPage{}, ErrInvalidRequest
	}
	owned := make([]Client, len(items))
	for i, c := range items {
		var err error
		owned[i], err = clientReadProjection(c)
		if err != nil || i > 0 && items[i-1].ID >= c.ID {
			return ClientListPage{}, ErrInvalidRequest
		}
	}
	return ClientListPage{items: owned, valid: true}, nil
}

// Items returns owned mutable projections; changing them cannot alter the page
// or native registration authority. The safe managed class has no nested secret,
// workload or subject-registration policy.
func (p ClientListPage) Items() []Client {
	items := make([]Client, len(p.items))
	for i, c := range p.items {
		items[i], _ = ValidateClient(c)
	}
	return items
}

func clientReadProjection(c Client) (Client, error) {
	if !strings.HasPrefix(c.ID, ManagedClientPrefix) || c.Workload != nil || c.SubjectRegistration != nil || hasExtensionScope(c.Scopes) && !minimalManagedPublicOIDC(c.Public, c.DeviceAuthorization, c.Scopes) {
		return Client{}, ErrInvalidRequest
	}
	if _, err := identity.ParseSubjectID(strings.TrimPrefix(c.ID, ManagedClientPrefix)); err != nil {
		return Client{}, ErrInvalidRequest
	}
	return ValidateClient(c)
}

// ValidateClientReadRequest validates the closed get/list variants and exact
// immutable policy, never session authentication, cursor ownership or permission.
func ValidateClientReadRequest(r ClientReadRequest, list bool, p ManagedClientPolicy) (ClientReadRequest, error) {
	if r.Owner != p.Owner || r.TenantID != p.TenantID {
		return ClientReadRequest{}, ErrAccessDenied
	}
	if _, err := session.ParseToken(r.Session.Token()); err != nil {
		return ClientReadRequest{}, ErrInvalidRequest
	}
	if list {
		if r.ClientID != "" || r.Limit < 1 || r.Limit > 100 {
			return ClientReadRequest{}, ErrInvalidRequest
		}
		if _, err := ParseCursor(r.Cursor.String()); err != nil {
			return ClientReadRequest{}, err
		}
	} else {
		if !strings.HasPrefix(r.ClientID, ManagedClientPrefix) || r.Limit != 0 || r.Cursor.String() != "" {
			return ClientReadRequest{}, ErrInvalidRequest
		}
		if _, err := identity.ParseSubjectID(strings.TrimPrefix(r.ClientID, ManagedClientPrefix)); err != nil {
			return ClientReadRequest{}, ErrInvalidRequest
		}
	}
	return r, nil
}

func (s *Service) clientReadAdmission(ctx context.Context, r ClientReadRequest, list bool) (ClientReadExecution, ClientReader, error) {
	if s.config.ManagedClients == nil {
		return ClientReadExecution{}, nil, ErrAccessDenied
	}
	r, err := ValidateClientReadRequest(r, list, *s.config.ManagedClients)
	if err != nil {
		return ClientReadExecution{}, nil, err
	}
	reader, ok := s.deps.Store.(ClientReader)
	if !ok || nilDependency(reader) {
		return ClientReadExecution{}, nil, ErrAccessDenied
	}
	observed, err := s.source(ctx, r.TenantID, r.Session)
	if err != nil {
		return ClientReadExecution{}, nil, err
	}
	e := ClientReadExecution{Request: r, Session: observed}
	if e.ValidateAt(s.config.Clock.Now()) != nil {
		return ClientReadExecution{}, nil, ErrAccessDenied
	}
	return e, reader, nil
}

func (s *Service) selectedClientReadProjection(c Client) (Client, error) {
	c, err := clientReadProjection(c)
	if err != nil || c.Owner != s.config.ManagedClients.Owner || c.Resource != s.config.Resource || !s.config.ManagedClients.AllowsRegistrationScopes(c.Public, c.DeviceAuthorization, c.Scopes) || hasExtensionScope(c.Scopes) && nilDependency(s.deps.OIDC) {
		return Client{}, ErrAccessDenied
	}
	for _, redirect := range c.Redirects {
		if !slices.Contains(s.config.ManagedClients.Redirects, redirect) {
			return Client{}, ErrAccessDenied
		}
	}
	for _, redirect := range c.PostLogoutRedirects {
		if !slices.Contains(s.config.ManagedClients.PostLogoutRedirects, redirect) {
			return Client{}, ErrAccessDenied
		}
	}
	return c, nil
}

// ClientGet authenticates current platform-management permission for one safe
// registration. It never accepts an ID as authority or exposes secret custody.
func (s *Service) ClientGet(ctx context.Context, r ClientReadRequest) (out ClientGetResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = ClientGetResult{}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	e, reader, err := s.clientReadAdmission(ctx, r, false)
	if err != nil {
		return out, err
	}
	out, err = reader.ClientGet(ctx, e)
	if ctx.Err() != nil {
		return ClientGetResult{}, ctx.Err()
	}
	if err != nil {
		return ClientGetResult{}, operationError(ctx, err)
	}
	if e.ValidateAt(s.config.Clock.Now()) != nil {
		return ClientGetResult{}, ErrAccessDenied
	}
	out.Client, err = s.selectedClientReadProjection(out.Client)
	if err != nil || out.Client.ID != r.ClientID {
		return ClientGetResult{}, ErrAccessDenied
	}
	return out, nil
}

// ClientList authenticates current platform-management permission for a bounded
// safe metadata page. Cursors are native scoped metadata, not authorization.
func (s *Service) ClientList(ctx context.Context, r ClientReadRequest) (out ClientListResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = ClientListResult{}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	e, reader, err := s.clientReadAdmission(ctx, r, true)
	if err != nil {
		return out, err
	}
	out, err = reader.ClientList(ctx, e)
	if ctx.Err() != nil {
		return ClientListResult{}, ctx.Err()
	}
	if err != nil {
		return ClientListResult{}, operationError(ctx, err)
	}
	if e.ValidateAt(s.config.Clock.Now()) != nil {
		return ClientListResult{}, ErrAccessDenied
	}
	if !out.Page.valid || len(out.Page.items) > int(r.Limit) || len(out.Page.items) == 0 && out.NextCursor.String() != "" {
		return ClientListResult{}, ErrUnavailable
	}
	items := out.Page.Items()
	for i, c := range items {
		items[i], err = s.selectedClientReadProjection(c)
		if err != nil {
			return ClientListResult{}, err
		}
	}
	out.Page, err = NewClientListPage(items)
	if err != nil {
		return ClientListResult{}, ErrUnavailable
	}
	return out, nil
}
