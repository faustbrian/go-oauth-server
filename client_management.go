package oauthserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ManagedClientPrefix reserves one server-owned namespace. Selected registries
// never fall back to static configuration for any ID in this namespace.
const ManagedClientPrefix = "managed."

// ErrClientConflict means a request key already names another management intent.
var ErrClientConflict = errors.New("oauthserver: client request conflict")

// ManagedClientPolicy fixes the only supported immutable platform owner,
// management tenant and exact redirect/OAuth-scope ceilings. It selects no
// administrator: each call must authorize the genuine current human separately.
type ManagedClientPolicy struct {
	Owner     Owner
	TenantID  identity.TenantID
	Redirects []string
	// PostLogoutRedirects is an independent exact ceiling, never inferred from Redirects.
	PostLogoutRedirects []string
	Scopes              ScopeCatalog
}

func (p ManagedClientPolicy) validated(c Config) (ManagedClientPolicy, error) {
	redirects, err := NewRedirectPolicy(p.Redirects)
	if err != nil || !identifier(p.Owner.PlatformID()) || !identifier(string(p.TenantID)) || len(p.Scopes.values) == 0 || hasExtensionScope(p.Scopes.values) || !scopeSubset(p.Scopes.values, c.Scopes.values) {
		return ManagedClientPolicy{}, ErrInvalidRequest
	}
	p.Redirects = slices.Clone(redirects.targets)
	if len(p.PostLogoutRedirects) != 0 {
		logout, err := NewRedirectPolicy(p.PostLogoutRedirects)
		if err != nil {
			return ManagedClientPolicy{}, ErrInvalidRequest
		}
		p.PostLogoutRedirects = slices.Clone(logout.targets)
	}
	for _, client := range c.Clients {
		if strings.HasPrefix(client.ID, ManagedClientPrefix) {
			return ManagedClientPolicy{}, ErrInvalidRequest
		}
	}
	return p, nil
}

// CurrentClientRegistry is a trusted optional native current-client owner, not
// caller-provided authentication. Each read/authentication must fence actual
// status/version/owner and never cache positives or fall back on tombstones.
// Static clients remain owned by Config; only ManagedClientPrefix is delegated.
type CurrentClientRegistry interface {
	CurrentClient(context.Context, string) (Client, error)
	AuthenticateCurrentClient(context.Context, Client, ClientAuthentication) error
}

// ClientManagementRequest borrows genuine browser/CSRF custody. Create accepts
// no ID/version; the native owner allocates both once. Public=false explicitly
// selects the supported Basic confidential class. Delete accepts only ID/version
// and no registration edits. Owner/tenant are exact preconditions, not overrides.
// RequestKey is correlation only and never authenticates a manager.
type ClientManagementRequest struct {
	Owner               Owner
	TenantID            identity.TenantID
	Session             auth.BearerCredential
	CSRF                session.CSRFToken
	Origin, Network     string
	RequestKey          identity.IdempotencyKey
	ClientID            string
	Version             uint64
	Public              bool
	Redirects, Scopes   []string
	PostLogoutRedirects []string
}

func (ClientManagementRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ClientManagementRequest(redacted)"))
}
func (ClientManagementRequest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ClientManagementRequest) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ClientManagementExecution carries original sealed custody, not a permission
// assertion. Native owners repeat real current actor, exact platform-owner
// authorization, session/CSRF and original sensitive-proof fences inside Work.
type ClientManagementExecution struct {
	Request ClientManagementRequest
	Session session.GetResult
	Delete  bool
}

func (ClientManagementExecution) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ClientManagementExecution(redacted)"))
}
func (ClientManagementExecution) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ClientManagementExecution) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ValidateAt checks only original sealed admission and the sensitive 15-minute
// password age; current native authority, authorization and CSRF remain required.
func (e ClientManagementExecution) ValidateAt(now time.Time) error {
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
	life, err := e.Session.Session.Lifetime(now)
	completed := b.Authentication.Proof.IssuedAt
	if err != nil || !life.Fresh || completed.After(now) || !now.Before(completed.Add(15*time.Minute)) {
		return ErrAccessDenied
	}
	return nil
}

// ClientManagementResult returns metadata only except a fresh known committed
// creation's reveal-once Secret. Retry/recovery/unknown never redelivers secret.
type ClientManagementResult struct {
	Client     Client
	Secret     Token
	Completion Completion
}

func (ClientManagementResult) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ClientManagementResult(redacted)"))
}
func (ClientManagementResult) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ClientManagementResult) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ClientManager is additive; existing Store implementations remain unchanged.
type ClientManager interface {
	ManageClient(context.Context, ClientManagementExecution) (ClientManagementResult, error)
}

// ClientCreate selects confidential creation under current platform-owner policy.
func (s *Service) ClientCreate(ctx context.Context, r ClientManagementRequest) (ClientManagementResult, error) {
	return s.manageClient(ctx, r, false)
}

// ClientDelete terminally withdraws one exact managed client/version.
func (s *Service) ClientDelete(ctx context.Context, r ClientManagementRequest) (ClientManagementResult, error) {
	return s.manageClient(ctx, r, true)
}
func (s *Service) manageClient(ctx context.Context, r ClientManagementRequest, remove bool) (out ClientManagementResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = ClientManagementResult{Completion: Completion{Outcome: identity.CommitOutcomeUnknown}}, ErrUnavailable
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
	p := s.config.ManagedClients
	r, err = ValidateClientManagementRequest(r, remove, *p, s.config.Issuer)
	if err != nil {
		return out, err
	}
	manager, ok := s.deps.Store.(ClientManager)
	if !ok || nilDependency(manager) {
		return out, ErrAccessDenied
	}
	observed, err := s.source(ctx, r.TenantID, r.Session)
	if err != nil {
		return out, err
	}
	e := ClientManagementExecution{Request: r, Session: observed, Delete: remove}
	if e.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrAccessDenied
	}
	out, err = manager.ManageClient(ctx, e)
	if err != nil || ctx.Err() != nil {
		if ctx.Err() != nil {
			return ClientManagementResult{Completion: out.Completion}, ctx.Err()
		}
		if out.Completion.Outcome == identity.CommitOutcomeConflict {
			return ClientManagementResult{Completion: out.Completion}, ErrClientConflict
		}
		return ClientManagementResult{Completion: out.Completion}, operationError(ctx, err)
	}
	if e.ValidateAt(s.config.Clock.Now()) != nil {
		return ClientManagementResult{Completion: out.Completion}, ErrAccessDenied
	}
	if remove || out.Completion.Replayed || out.Completion.Outcome != identity.CommitOutcomeCommitted {
		out.Secret = Token{}
	}
	return out, nil
}

// ValidateClientManagementRequest copies the finite registration variant and
// checks immutable policy preconditions, never authentication or authorization.
func ValidateClientManagementRequest(r ClientManagementRequest, remove bool, p ManagedClientPolicy, issuer Issuer) (ClientManagementRequest, error) {
	if r.Owner != p.Owner || r.TenantID != p.TenantID || r.Origin != issuer.String() || r.CSRF == (session.CSRFToken{}) || !visible(r.Network, 128) || r.RequestKey == (identity.IdempotencyKey{}) || r.Public {
		return ClientManagementRequest{}, ErrAccessDenied
	}
	if _, err := session.ParseToken(r.Session.Token()); err != nil {
		return ClientManagementRequest{}, ErrInvalidRequest
	}
	if remove {
		if !strings.HasPrefix(r.ClientID, ManagedClientPrefix) || !identifier(r.ClientID) || r.Version == 0 || r.Version == ^uint64(0) || len(r.Redirects) != 0 || len(r.Scopes) != 0 || len(r.PostLogoutRedirects) != 0 {
			return ClientManagementRequest{}, ErrInvalidRequest
		}
		return r, nil
	}
	if r.ClientID != "" || r.Version != 0 {
		return ClientManagementRequest{}, ErrInvalidRequest
	}
	redirects, err := NewRedirectPolicy(r.Redirects)
	if err != nil {
		return ClientManagementRequest{}, ErrInvalidRequest
	}
	for _, target := range redirects.targets {
		if !slices.Contains(p.Redirects, target) {
			return ClientManagementRequest{}, ErrAccessDenied
		}
	}
	if len(r.PostLogoutRedirects) != 0 {
		logout, err := NewRedirectPolicy(r.PostLogoutRedirects)
		if err != nil {
			return ClientManagementRequest{}, ErrInvalidRequest
		}
		for _, target := range logout.targets {
			if !slices.Contains(p.PostLogoutRedirects, target) {
				return ClientManagementRequest{}, ErrAccessDenied
			}
		}
		r.PostLogoutRedirects = slices.Clone(logout.targets)
	}
	scopes, err := validatedScopes(r.Scopes)
	if err != nil || !scopeSubset(scopes, p.Scopes.values) {
		return ClientManagementRequest{}, ErrInvalidScope
	}
	r.Redirects = slices.Clone(redirects.targets)
	r.Scopes = scopes
	return r, nil
}

func (s *Service) currentClient(ctx context.Context, id string) (Client, error) {
	if s.config.ManagedClients == nil || !strings.HasPrefix(id, ManagedClientPrefix) {
		return s.client(id)
	}
	c, err := s.deps.Clients.CurrentClient(ctx, id)
	if err != nil {
		return Client{}, err
	}
	c, err = ValidateClient(c)
	if err != nil || c.ID != id || c.Owner != s.config.ManagedClients.Owner || c.Public || c.Workload != nil || c.SubjectRegistration != nil || c.Resource != s.config.Resource || !scopeSubset(c.Scopes, s.config.ManagedClients.Scopes.values) {
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
func (s *Service) authenticateClient(ctx context.Context, c Client, a ClientAuthentication) error {
	if s.config.ManagedClients != nil && strings.HasPrefix(c.ID, ManagedClientPrefix) {
		return s.deps.Clients.AuthenticateCurrentClient(ctx, c, a)
	}
	return s.config.AuthenticateClient(ctx, c.ID, a)
}

// ClientSecretDigest is digest-only durable verification for a random 32-byte
// client secret. It is not suitable for human passwords or bearer disclosure.
type ClientSecretDigest [32]byte

func (ClientSecretDigest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ClientSecretDigest(redacted)"))
}
func (ClientSecretDigest) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ClientSecretDigest) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// DigestClientSecret binds canonical high-entropy custody to client/secret
// generation. This is not Client.Version after metadata replacement; native
// digest-slot custody owns the generation independently of registration authority.
// Native generation uses independent crypto/rand; no user password is accepted.
func DigestClientSecret(id string, version uint64, wire string) (ClientSecretDigest, error) {
	if !identifier(id) || version == 0 || !opaque32(wire) {
		return ClientSecretDigest{}, ErrInvalidRequest
	}
	h := sha256.New()
	h.Write([]byte("golib-managed-client-secret-v1\x00"))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(id)))
	h.Write(n[:])
	h.Write([]byte(id))
	binary.BigEndian.PutUint64(n[:], version)
	h.Write(n[:])
	h.Write([]byte(wire))
	var d ClientSecretDigest
	copy(d[:], h.Sum(nil))
	return d, nil
}

// VerifySecretDigest authenticates only the exact Basic client/secret-generation digest.
// Digest possession grants no actor, tenant or management authority.
func (a ClientAuthentication) VerifySecretDigest(id string, version uint64, digest ClientSecretDigest) error {
	if a.credential == nil || a.ClientID() != id || digest == (ClientSecretDigest{}) {
		return ErrInvalidClient
	}
	got, err := DigestClientSecret(id, version, a.credential.Password())
	if err != nil || subtle.ConstantTimeCompare(got[:], digest[:]) != 1 {
		return ErrInvalidClient
	}
	return nil
}
