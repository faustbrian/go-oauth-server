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
	// PublicClients permits managed none-authenticated human-web registrations.
	// Zero retains confidential-only management; native storage needs its
	// separately installed forward history before selecting this capability.
	PublicClients bool `json:",omitempty"`
	// PublicOIDC separately permits openid-only managed public browser clients
	// with the existing default public subject. It requires PublicClients and
	// configured OIDCScopes containing openid. Creation, private reads,
	// authorization and token issuance require the composed OIDC extension;
	// the actual child still reads trusted UserInfoSource through its original
	// core. OAuth Scopes and retained policy stay unchanged.
	PublicOIDC bool `json:",omitempty"`
	// ConfidentialOIDC independently permits openid-only managed confidential
	// browser clients using their existing Basic secret custody and default public
	// subject. It requires configured OIDCScopes containing openid, not PublicClients.
	// Creation, private reads, authorization and issuance require OIDC composition.
	ConfidentialOIDC bool `json:",omitempty"`
	// PairwiseRegistrations is an explicit trusted ceiling for confidential,
	// openid-only single-host registrations. It requires ConfidentialOIDC and
	// selects no key material or subject derivation. Nil retains default subjects.
	PairwiseRegistrations []OIDCSubjectRegistration `json:",omitempty"`
	// DeviceAuthorization is an explicit ceiling for newly managed device
	// registrations; false preserves the existing browser-only namespace.
	DeviceAuthorization bool
}

func (p ManagedClientPolicy) validated(c Config) (ManagedClientPolicy, error) {
	redirects, err := NewRedirectPolicy(p.Redirects)
	if err != nil || !identifier(p.Owner.PlatformID()) || !identifier(string(p.TenantID)) || len(p.Scopes.values) == 0 || hasExtensionScope(p.Scopes.values) || !scopeSubset(p.Scopes.values, c.Scopes.values) {
		return ManagedClientPolicy{}, ErrInvalidRequest
	}
	if p.PublicOIDC && (!p.PublicClients || !c.OIDCScopes.Contains("openid")) {
		return ManagedClientPolicy{}, ErrInvalidRequest
	}
	if p.ConfidentialOIDC && !c.OIDCScopes.Contains("openid") {
		return ManagedClientPolicy{}, ErrInvalidRequest
	}
	// Match Config's bounded startup client catalog: each exact registration is
	// a trusted selection, not an unbounded request-controlled policy search.
	if len(p.PairwiseRegistrations) > 64 || len(p.PairwiseRegistrations) != 0 && !p.ConfidentialOIDC {
		return ManagedClientPolicy{}, ErrInvalidRequest
	}
	for i, registration := range p.PairwiseRegistrations {
		if !singleHostManagedPairwise(&registration) || slices.Contains(p.PairwiseRegistrations[:i], registration) {
			return ManagedClientPolicy{}, ErrInvalidRequest
		}
	}
	p.PairwiseRegistrations = slices.Clone(p.PairwiseRegistrations)
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

// AllowsRegistrationScopes checks immutable scope/class ceilings only, never
// registration existence, authentication or management authority. OAuth-only
// registrations retain Scopes; PublicOIDC and ConfidentialOIDC independently
// select exactly openid for their browser class, not device/additional claims.
// Native registries use this same admission rule on every restored projection.
func (p ManagedClientPolicy) AllowsRegistrationScopes(public, device bool, scopes []string) bool {
	values, err := validatedScopes(scopes)
	if err != nil || public && !p.PublicClients || device && !p.DeviceAuthorization {
		return false
	}
	if hasExtensionScope(values) {
		return (public && p.PublicOIDC || !public && p.ConfidentialOIDC) && minimalManagedBrowserOIDC(device, values)
	}
	return scopeSubset(values, p.Scopes.values)
}

func minimalManagedBrowserOIDC(device bool, scopes []string) bool {
	return !device && len(scopes) == 1 && scopes[0] == "openid"
}

// AllowsRegistration checks exact immutable class/scope/subject ceilings. It
// does not establish manager authority, key custody or durable registration.
// Nil subject registration retains the original default-subject selection.
func (p ManagedClientPolicy) AllowsRegistration(public, device bool, scopes []string, registration *OIDCSubjectRegistration) bool {
	if !p.AllowsRegistrationScopes(public, device, scopes) {
		return false
	}
	if registration == nil {
		return true
	}
	return !public && p.ConfidentialOIDC && minimalManagedBrowserOIDC(device, scopes) && singleHostManagedPairwise(registration) && slices.Contains(p.PairwiseRegistrations, *registration)
}

func singleHostManagedPairwise(registration *OIDCSubjectRegistration) bool {
	return registration != nil && registration.valid() && registration.kind == "pairwise" && registration.uri == ""
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
// no ID/version; the native owner allocates both once. Public=true selects none
// without a secret; Public=false selects Basic confidential custody. Delete accepts only ID/version
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
	DeviceAuthorization bool
	Redirects, Scopes   []string
	PostLogoutRedirects []string
	// SubjectRegistration selects only an exact trusted PairwiseRegistrations
	// member. Nil preserves default subjects. Delete accepts no registration edits.
	SubjectRegistration *OIDCSubjectRegistration
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
// confidential creation's reveal-once Secret. Public creation and
// retry/recovery/unknown never deliver a secret.
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

// ClientCreate selects public or confidential creation under current platform-owner policy.
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
	if !remove && r.SubjectRegistration != nil {
		r, err = ValidatePairwiseClientManagementRequest(r, *p, s.config.Issuer)
	} else {
		r, err = ValidateClientManagementRequest(r, remove, *p, s.config.Issuer)
	}
	if err != nil {
		return out, err
	}
	if hasExtensionScope(r.Scopes) && nilDependency(s.deps.OIDC) {
		return out, ErrAccessDenied
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
	if r.Public || remove || out.Completion.Replayed || out.Completion.Outcome != identity.CommitOutcomeCommitted {
		out.Secret = Token{}
	}
	return out, nil
}

// ValidateClientManagementRequest copies the original default-subject variants
// and checks immutable preconditions, never authentication or authorization.
// It rejects subject registrations so existing native writers cannot accept a
// new field they would discard before persistence.
func ValidateClientManagementRequest(r ClientManagementRequest, remove bool, p ManagedClientPolicy, issuer Issuer) (ClientManagementRequest, error) {
	if r.SubjectRegistration != nil {
		return ClientManagementRequest{}, ErrInvalidRequest
	}
	return validateClientManagementRequest(r, remove, p, issuer)
}

// ValidatePairwiseClientManagementRequest is the explicit create-only adapter
// opt-in for exact trusted confidential single-host pairwise registration. New
// native owners must preserve this registration in their existing preparation
// and persistence. It grants no manager authority or key/binding custody.
func ValidatePairwiseClientManagementRequest(r ClientManagementRequest, p ManagedClientPolicy, issuer Issuer) (ClientManagementRequest, error) {
	if r.SubjectRegistration == nil {
		return ClientManagementRequest{}, ErrInvalidRequest
	}
	return validateClientManagementRequest(r, false, p, issuer)
}

func validateClientManagementRequest(r ClientManagementRequest, remove bool, p ManagedClientPolicy, issuer Issuer) (ClientManagementRequest, error) {
	if r.Owner != p.Owner || r.TenantID != p.TenantID || r.Origin != issuer.String() || r.CSRF == (session.CSRFToken{}) || !visible(r.Network, 128) || r.RequestKey == (identity.IdempotencyKey{}) {
		return ClientManagementRequest{}, ErrAccessDenied
	}
	if _, err := session.ParseToken(r.Session.Token()); err != nil {
		return ClientManagementRequest{}, ErrInvalidRequest
	}
	if remove {
		if r.Public {
			return ClientManagementRequest{}, ErrAccessDenied
		}
		if !strings.HasPrefix(r.ClientID, ManagedClientPrefix) || !identifier(r.ClientID) || r.Version == 0 || r.Version == ^uint64(0) || len(r.Redirects) != 0 || len(r.Scopes) != 0 || len(r.PostLogoutRedirects) != 0 || r.DeviceAuthorization || r.SubjectRegistration != nil {
			return ClientManagementRequest{}, ErrInvalidRequest
		}
		return r, nil
	}
	if r.ClientID != "" || r.Version != 0 {
		return ClientManagementRequest{}, ErrInvalidRequest
	}
	if r.Public && !p.PublicClients {
		return ClientManagementRequest{}, ErrAccessDenied
	}
	if r.DeviceAuthorization && !p.DeviceAuthorization {
		return ClientManagementRequest{}, ErrAccessDenied
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
	if err != nil || !p.AllowsRegistrationScopes(r.Public, r.DeviceAuthorization, scopes) {
		return ClientManagementRequest{}, ErrInvalidScope
	}
	if !p.AllowsRegistration(r.Public, r.DeviceAuthorization, scopes, r.SubjectRegistration) || !validSubjectRegistration(Client{SubjectRegistration: r.SubjectRegistration, Redirects: redirects.targets}) {
		return ClientManagementRequest{}, ErrAccessDenied
	}
	if r.SubjectRegistration != nil {
		registration := *r.SubjectRegistration
		r.SubjectRegistration = &registration
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
	if err != nil || c.ID != id || c.Owner != s.config.ManagedClients.Owner || c.Workload != nil || c.Resource != s.config.Resource || !s.config.ManagedClients.AllowsRegistration(c.Public, c.DeviceAuthorization, c.Scopes, c.SubjectRegistration) {
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
