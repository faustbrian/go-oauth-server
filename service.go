package oauthserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

var (
	// ErrInvalidGrant denies absent, expired, withdrawn, foreign or reused grant
	// custody without disclosing which property failed.
	ErrInvalidGrant = errors.New("oauthserver: invalid grant")
	// ErrAccessDenied denies current subject, browser, consent or owner admission.
	ErrAccessDenied = errors.New("oauthserver: access denied")
	// ErrInvalidScope denies malformed or expanding requested scope authority.
	ErrInvalidScope = errors.New("oauthserver: invalid scope")
)

// Clock is trusted, fast, local and concurrent-safe. Callers cannot supply time
// in protocol input. Native transactions additionally use authoritative DB time.
type Clock interface{ Now() time.Time }

// Config selects OAuth-only public or configured Basic-client web profiles. Every duration is
// explicit: code/continuation/access are 1s..5min; refresh is AccessTTL..30days;
// MaximumDuration is 1ms..5s. Resources and issuer are exact HTTPS origins.
// Sessions and configuration remain borrowed, with no package-owned goroutines.
type Config struct {
	Issuer                Issuer
	Environment, Resource string
	Scopes                ScopeCatalog
	// OIDCScopes declares the optional child's reserved scope catalog to native
	// persistence. It grants no semantics until WithOIDC composes the child.
	OIDCScopes ScopeCatalog
	Clients    []Client
	// ClientSecrets contains exactly one verifier per confidential client ID and
	// version, none for public clients. See NewClientSecretVerifier's startup policy.
	ClientSecrets []ClientSecretVerifier
	// OwningClientIntrospection explicitly enables RFC7662 for authenticated
	// confidential clients inspecting only their own issued opaque tokens.
	// Merely configuring a confidential client never enables this capability.
	OwningClientIntrospection bool
	// Discovery explicitly selects OAuth authorization-server metadata using
	// trusted endpoint locations. Zero preserves the unadvertised legacy profile.
	Discovery                                                        DiscoveryConfig
	Clock                                                            Clock
	MaximumDuration, CodeTTL, ContinuationTTL, AccessTTL, RefreshTTL time.Duration
}

// Validated freezes owned configuration projections without IO, callbacks,
// randomness, migration or dependency health checks. Confidential clients require
// exactly one matching startup verifier; missing/foreign/duplicate verifiers deny.
func (c Config) Validated() (Config, error) {
	if !validOrigin(c.Issuer.value) || !identifier(c.Environment) || !validOrigin(c.Resource) || nilDependency(c.Clock) || len(c.Scopes.values) == 0 || len(c.Clients) < 1 || len(c.Clients) > 64 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second || c.RefreshTTL < c.AccessTTL || c.RefreshTTL > 30*24*time.Hour {
		return Config{}, ErrInvalidRequest
	}
	for _, duration := range []time.Duration{c.CodeTTL, c.ContinuationTTL, c.AccessTTL} {
		if duration < time.Second || duration > 5*time.Minute || duration%time.Microsecond != 0 {
			return Config{}, ErrInvalidRequest
		}
	}
	if c.RefreshTTL%time.Microsecond != 0 {
		return Config{}, ErrInvalidRequest
	}
	// Catalog constructors return the same immutable value type, so admission
	// must enforce ownership even when callers cross-assign the two fields.
	if hasExtensionScope(c.Scopes.values) {
		return Config{}, ErrInvalidRequest
	}
	for _, scope := range c.OIDCScopes.values {
		if !isOIDCScope(scope) || c.Scopes.Contains(scope) {
			return Config{}, ErrInvalidRequest
		}
	}
	c.Clients = slices.Clone(c.Clients)
	slices.SortFunc(c.Clients, func(a, b Client) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	for i, client := range c.Clients {
		owned, err := ValidateClient(client)
		if err != nil || owned.Resource != c.Resource || i > 0 && c.Clients[i-1].ID == owned.ID || !scopeSubset(owned.Scopes, append(slices.Clone(c.Scopes.values), c.OIDCScopes.values...)) || owned.Workload != nil && (owned.Workload.AccessTTL() > c.AccessTTL || hasExtensionScope(owned.Scopes)) {
			return Config{}, ErrInvalidRequest
		}
		c.Clients[i] = owned
	}
	if err := validateClientSecrets(c.Clients, c.ClientSecrets); err != nil {
		return Config{}, err
	}
	c.ClientSecrets = slices.Clone(c.ClientSecrets)
	c.Scopes.values = slices.Clone(c.Scopes.values)
	c.OIDCScopes.values = slices.Clone(c.OIDCScopes.values)
	if err := validateDiscovery(c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Dependencies uses the existing session owner for credential admission and an
// owned adapter for complete OAuth effects. Store implementations must honor
// context, recheck current authority, own no replacement authentication engine,
// and provide atomic mutation/audit/lifecycle/reconciliation. The PostgreSQL
// adapter supplies that implementation; applications need no domain-store glue.
type Dependencies struct {
	Sessions *session.SessionService
	Store    Store
	OIDC     OIDCExtension
}

// Store is the consumer-owned storage-neutral OAuth execution seam. Commands
// contain original custody, not permission to omit current owner checks. Native
// implementations must not expose concrete transaction handles to core, retain
// caller inputs after completion, or reveal material on replay/unknown outcomes.
type Store interface {
	Authorize(context.Context, AuthorizationCommand) (AuthorizeResult, error)
	Continue(context.Context, ContinuationCommand) (AuthorizeResult, error)
	Token(context.Context, TokenCommand) (TokenResult, error)
	Revoke(context.Context, RevocationCommand) (RevokeResult, error)
}

// Service freezes selected protocol and adapter composition. It issues no local
// session and owns no pool, transaction, listener or background work. Immutable
// concurrent calls require borrowed dependencies to remain alive/concurrent-safe.
type Service struct {
	config Config
	deps   Dependencies
}

// Format prevents recursive diagnostics from traversing borrowed secret-bearing
// extension/store configuration. Public metadata has explicit read operations.
func (*Service) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("oauthserver.Service(redacted)")) }

// NewService validates/copies selected composition without IO or generation.
func NewService(config Config, dependencies Dependencies) (*Service, error) {
	c, err := config.Validated()
	if err != nil || nilDependency(dependencies.Store) {
		return nil, ErrInvalidRequest
	}
	for _, client := range c.Clients {
		if client.Workload == nil && (dependencies.Sessions == nil || !dependencies.Sessions.Configured()) {
			return nil, ErrInvalidRequest
		}
	}
	if c.OwningClientIntrospection {
		if reader, ok := dependencies.Store.(Introspector); !ok || nilDependency(reader) {
			return nil, ErrInvalidRequest
		}
	}
	if !nilDependency(dependencies.OIDC) && !slices.Equal(dependencies.OIDC.Scopes().Scopes(), c.OIDCScopes.Scopes()) {
		return nil, ErrInvalidRequest
	}
	return &Service{config: c, deps: dependencies}, nil
}

// AuthorizeRequest supplies borrowed browser bearer custody and a typed parsed
// request. Tenant selects lookup scope, never a user/actor override. Network is
// trusted transport attribution for native risk, not an authorization assertion.
type AuthorizeRequest struct {
	TenantID identity.TenantID
	Session  auth.BearerCredential
	Request  AuthorizationRequest
	Network  string
}

// ContinueRequest consumes one original browser-bound interaction. The selected
// issuer-origin synchronizer profile is mandatory. Nil Scopes accepts the exact
// originally requested set; a supplied set may only narrow it. Deny ignores no
// authority checks: the native owner still validates/consumes the continuation.
type ContinueRequest struct {
	TenantID                                identity.TenantID
	Session                                 auth.BearerCredential
	CSRF                                    session.CSRFToken
	ClientID, Continuation, Origin, Network string
	Approve                                 bool
	Scopes                                  []string
}

// AuthorizeOutcome distinguishes interaction, known redirect and metadata-only
// durability states. Zero is invalid; unknown/historical carry no credentials.
type AuthorizeOutcome uint8

const (
	LoginRequired AuthorizeOutcome = iota + 1
	ConsentRequired
	AuthorizationRedirect
	AuthorizationDenied
	AuthorizationUnknown
	AuthorizationHistorical
)

// AuthorizeResult is a closed interaction/redirect/durability result. Core fills
// redirect/issuer/state only after checking exact current client registration.
// Tokens are explicit reveal custody and cannot be implicitly serialized.
// Historical and unknown outcomes contain no fresh material or redirect.
type AuthorizeResult struct {
	Outcome            AuthorizeOutcome
	CommandID          identity.CommandID
	Continuation, Code Token
	ExpiresAt          time.Time
	RedirectURI, State string
	Issuer             Issuer
	Request            AuthorizationRequest
}

// Location explicitly encodes a known committed success/denial for transport.
// Success consumes Code's sole reveal permission. This representation helper is
// not proof of issuance or redirect authority; use only a Service result.
func (r AuthorizeResult) Location() (string, error) {
	if (r.Outcome != AuthorizationRedirect && r.Outcome != AuthorizationDenied) || !validRedirect(r.RedirectURI) || !validOrigin(r.Issuer.value) || !optionalVisible(r.State, 1024) {
		return "", ErrInvalidRequest
	}
	u, err := url.Parse(r.RedirectURI)
	if err != nil {
		return "", ErrInvalidRequest
	}
	q := u.Query()
	q.Set("iss", r.Issuer.value)
	if r.State != "" {
		q.Set("state", r.State)
	}
	if r.Outcome == AuthorizationRedirect {
		code, err := r.Code.Reveal()
		if err != nil {
			return "", err
		}
		q.Set("code", code)
	} else {
		q.Set("error", "access_denied")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// AuthorizationCommand carries a validated request and genuine sealed session
// observation to persistence. Browser remains borrowed secret custody, not a
// caller-selected identity; adapters must repeat current native owner checks.
type AuthorizationCommand struct {
	Request AuthorizationRequest
	Client  Client
	Session session.GetResult
	Browser auth.BearerCredential
	Network string
}

// ContinuationCommand preserves the current original-browser observation for
// one consent transition. The adapter must authenticate the original interaction
// and synchronizer, not infer authority from this projection's identifiers.
type ContinuationCommand struct {
	Request ContinueRequest
	Client  Client
	Session session.GetResult
}

// TokenCommand borrows exactly one code/S256 or refresh credential until the
// bounded call returns. Client is configured policy, not client authentication.
type TokenCommand struct {
	Request TokenRequest
	Client  Client
	// OIDC is a trusted composition callback, invoked only for a genuine native
	// human grant in encrypted preparation. Adapters must never invoke it during
	// metadata-only replay/recovery or deliver it before known commitment.
	OIDC func(context.Context, OIDCClaimsInput) (OIDCClaimsProjection, error)
}

// TokenResult distinguishes fresh known commitment from metadata-only replay
// and uncertain durability. Child expiry is bounded by the native parent/grant
// and Config.AccessTTL; core rejects/scrubs an adapter's invalid output.
type TokenResult struct {
	Outcome                   identity.CommitOutcome
	CommandID                 identity.CommandID
	Replayed                  bool
	AccessToken, RefreshToken Token
	IDToken                   IDToken
	ExpiresAt                 time.Time
	Resource                  string
	Scopes                    []string
}

// RevokeRequest borrows a protocol token for client-bound RFC7009 revocation.
// Hint is advisory; Network is trusted transport attribution, never form input.
type RevokeRequest struct {
	ClientID, Token      string
	Hint                 TokenKind
	Network              string
	ClientAuthentication ClientAuthentication
}

// RevocationCommand binds borrowed token possession to configured client policy;
// unknown/foreign tokens must remain indistinguishable successful no-ops.
type RevocationCommand struct {
	Request RevokeRequest
	Client  Client
}
type RevokeResult struct {
	Outcome   identity.CommitOutcome
	CommandID identity.CommandID
}

// IntrospectRequest borrows an inspected token separately from the caller's
// Basic credential. Hint is advisory and cannot restrict supported-type lookup.
type IntrospectRequest struct {
	ClientID, Token      string
	Hint                 TokenKind
	ClientAuthentication ClientAuthentication
}

// Introspector is an optional adapter-neutral read seam. Implementations must
// separately authenticate the owning confidential client and read current
// primary token/grant and original subject/credential authority. No writes,
// caching, freshness renewal or credential disclosure are permitted.
type Introspector interface {
	Introspect(context.Context, IntrospectionCommand) (IntrospectResult, error)
}
type IntrospectionCommand struct {
	Request IntrospectRequest
	Client  Client
}

// IntrospectResult is normal successful inactive metadata or current active
// disclosure. Every metadata member must be absent for Active=false. This is
// not resource-server authorization or renewable source validity evidence.
type IntrospectResult struct {
	Active                      bool
	ClientID, Subject, Resource string
	Scopes                      []string
	ExpiresAt                   time.Time
	Issuer                      Issuer
}

func (s *Service) client(id string) (Client, error) {
	if s == nil || !identifier(id) {
		return Client{}, ErrInvalidRequest
	}
	for _, c := range s.config.Clients {
		if c.ID == id {
			return c.snapshot(), nil
		}
	}
	return Client{}, ErrInvalidRequest
}

func (s *Service) validateAuthorization(r AuthorizationRequest) (AuthorizationRequest, Client, error) {
	c, err := s.client(r.ClientID)
	if err != nil || !slices.Contains(c.Redirects, r.RedirectURI) || !opaque32(r.CodeChallenge) || r.Resource != c.Resource || !optionalVisible(r.State, 1024) || !optionalVisible(r.Nonce, 256) {
		return AuthorizationRequest{}, Client{}, ErrInvalidRequest
	}
	scopes, err := validatedScopes(r.Scopes)
	if err != nil || !scopeSubset(scopes, c.Scopes) {
		return AuthorizationRequest{}, Client{}, ErrInvalidScope
	}
	r.Scopes = scopes
	if (hasExtensionScope(scopes) || r.Nonce != "") && nilDependency(s.deps.OIDC) {
		return AuthorizationRequest{}, Client{}, ErrInvalidScope
	}
	return r, c, nil
}

func (s *Service) source(ctx context.Context, tenant identity.TenantID, browser auth.BearerCredential) (session.GetResult, error) {
	if !identifier(string(tenant)) {
		return session.GetResult{}, ErrInvalidRequest
	}
	token, err := session.ParseToken(browser.Token())
	if err != nil {
		return session.GetResult{}, nil
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return session.GetResult{}, ErrInvalidRequest
	}
	observed, err := s.deps.Sessions.Get(ctx, session.GetRequest{TenantID: tenant, Credential: credential})
	if ctx.Err() != nil {
		return session.GetResult{}, ctx.Err()
	}
	if err != nil {
		return session.GetResult{}, ErrUnavailable
	}
	if !observed.Authenticated {
		return session.GetResult{}, nil
	}
	now := s.config.Clock.Now()
	if observed.ValidateAt(now) != nil {
		return session.GetResult{}, ErrAccessDenied
	}
	spec, err := observed.Session.Bindings()
	if err != nil || spec.TenantID != tenant || spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "password" || spec.Authentication.Proof.Assurance != auth.AssuranceSingleFactor {
		return session.GetResult{}, ErrAccessDenied
	}
	authority, err := spec.Authority.Bindings()
	if err != nil || authority.Organization.Present || authority.Factor.Present || authority.Passkey.Present {
		return session.GetResult{}, ErrAccessDenied
	}
	return observed, nil
}

// Authorize validates exact registered request policy before native state work,
// then delegates genuine session custody without selecting another subject.
// Missing/inactive sessions yield LoginRequired; operational failures deny.
func (s *Service) Authorize(ctx context.Context, request AuthorizeRequest) (out AuthorizeResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AuthorizeResult{Outcome: AuthorizationUnknown}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	input, client, err := s.validateAuthorization(request.Request)
	if err != nil || !visible(request.Network, 128) {
		return out, ErrInvalidRequest
	}
	source, err := s.source(ctx, request.TenantID, request.Session)
	if err != nil {
		return out, err
	}
	if !source.Authenticated {
		return AuthorizeResult{Outcome: LoginRequired}, nil
	}
	if hasExtensionScope(input.Scopes) || input.Nonce != "" {
		projection, e := s.deps.OIDC.ValidateAuthorization(ctx, OIDCAuthorizationInput{Request: input, Session: source})
		if e != nil || !projection.Accepted {
			if e != nil {
				return out, e
			}
			return out, ErrAccessDenied
		}
	}
	out, err = s.deps.Store.Authorize(ctx, AuthorizationCommand{Request: input, Client: client.snapshot(), Session: source, Browser: request.Session, Network: request.Network})
	if err != nil || ctx.Err() != nil {
		return AuthorizeResult{Outcome: out.Outcome, CommandID: out.CommandID}, operationError(ctx, err)
	}
	return s.authorizeResult(out, input, client)
}

// Continue requires a current genuine source session plus exact issuer origin
// and a submitted synchronizer. Native storage enforces original interaction,
// current CSRF/session/authority, one-time consumption and atomic consent/code.
func (s *Service) Continue(ctx context.Context, request ContinueRequest) (out AuthorizeResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AuthorizeResult{Outcome: AuthorizationUnknown}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	client, err := s.client(request.ClientID)
	if err != nil || client.Workload != nil || !opaque32(request.Continuation) || request.Origin != s.config.Issuer.value || request.CSRF == (session.CSRFToken{}) || !visible(request.Network, 128) {
		return out, ErrInvalidRequest
	}
	if request.Scopes != nil {
		request.Scopes, err = validatedScopes(request.Scopes)
		if err != nil || !scopeSubset(request.Scopes, client.Scopes) {
			return out, ErrInvalidScope
		}
	}
	source, err := s.source(ctx, request.TenantID, request.Session)
	if err != nil {
		return out, err
	}
	if !source.Authenticated {
		return out, ErrAccessDenied
	}
	out, err = s.deps.Store.Continue(ctx, ContinuationCommand{Request: request, Client: client.snapshot(), Session: source})
	if err != nil || ctx.Err() != nil {
		return AuthorizeResult{Outcome: out.Outcome, CommandID: out.CommandID}, operationError(ctx, err)
	}
	input, current, err := s.validateAuthorization(out.Request)
	if err != nil || current.ID != client.ID {
		return AuthorizeResult{}, ErrUnavailable
	}
	return s.authorizeResult(out, input, current)
}

func (s *Service) authorizeResult(out AuthorizeResult, input AuthorizationRequest, client Client) (AuthorizeResult, error) {
	now := s.config.Clock.Now()
	switch out.Outcome {
	case ConsentRequired:
		if out.Continuation.state == nil || out.Code.state != nil || !now.Before(out.ExpiresAt) || out.ExpiresAt.After(now.Add(s.config.ContinuationTTL)) {
			return AuthorizeResult{}, ErrUnavailable
		}
		out.RedirectURI, out.State, out.Issuer = "", "", Issuer{}
	case AuthorizationRedirect:
		if out.Code.state == nil || out.Continuation.state != nil || !now.Before(out.ExpiresAt) || out.ExpiresAt.After(now.Add(s.config.CodeTTL)) {
			return AuthorizeResult{}, ErrUnavailable
		}
		out.RedirectURI, out.State, out.Issuer = input.RedirectURI, input.State, s.config.Issuer
	case AuthorizationDenied:
		if out.Code.state != nil || out.Continuation.state != nil {
			return AuthorizeResult{}, ErrUnavailable
		}
		out.RedirectURI, out.State, out.Issuer = input.RedirectURI, input.State, s.config.Issuer
	case AuthorizationUnknown, AuthorizationHistorical:
		return AuthorizeResult{Outcome: out.Outcome, CommandID: out.CommandID}, nil
	default:
		return AuthorizeResult{}, ErrUnavailable
	}
	out.Request = input
	return out, nil
}

// Token admits the exact selected grant/client shape and delegates atomic
// possession/PKCE/current-authority/one-use effects. No browser session, arbitrary
// tenant selector, actor override or private exchange is inferred. A workload
// grant requires explicit immutable startup policy and confidential Basic custody.
func (s *Service) Token(ctx context.Context, request TokenRequest) (out TokenResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = TokenResult{Outcome: identity.CommitOutcomeUnknown}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	client, err := s.client(request.ClientID)
	if err != nil && request.ClientAuthentication.Method() != "none" {
		return out, ErrInvalidClient
	}
	if err != nil || !visible(request.Network, 128) {
		return out, ErrInvalidRequest
	}
	if request.Resource != "" && request.Resource != client.Resource {
		return out, ErrInvalidRequest
	}
	if client.Workload != nil && request.GrantType != ClientCredentialsGrant || client.Workload == nil && request.GrantType == ClientCredentialsGrant {
		return out, ErrUnsupportedGrant
	}
	switch request.GrantType {
	case AuthorizationCodeGrant:
		if !opaque32(request.Code) || !slices.Contains(client.Redirects, request.RedirectURI) || request.RefreshToken != "" || request.Scopes != nil {
			return out, ErrInvalidRequest
		}
		if _, err := S256Challenge(request.CodeVerifier); err != nil {
			return out, err
		}
	case RefreshTokenGrant:
		if !opaque32(request.RefreshToken) || request.Code != "" || request.RedirectURI != "" || request.CodeVerifier != "" {
			return out, ErrInvalidRequest
		}
		if request.Scopes != nil {
			request.Scopes, err = validatedScopes(request.Scopes)
			if err != nil || !scopeSubset(request.Scopes, client.Scopes) {
				return out, ErrInvalidScope
			}
		}
		if hasExtensionScope(request.Scopes) && nilDependency(s.deps.OIDC) {
			return out, ErrAccessDenied
		}
	case ClientCredentialsGrant:
		if client.Public || request.Code != "" || request.RedirectURI != "" || request.CodeVerifier != "" || request.RefreshToken != "" {
			return out, ErrInvalidRequest
		}
		if request.Scopes == nil {
			request.Scopes = slices.Clone(client.Scopes)
		} else {
			request.Scopes, err = validatedScopes(request.Scopes)
			if err != nil || !scopeSubset(request.Scopes, client.Scopes) {
				return out, ErrInvalidScope
			}
		}
		request.Resource = client.Resource
	default:
		return out, ErrUnsupportedGrant
	}
	if err := s.config.AuthenticateClient(ctx, client.ID, request.ClientAuthentication); err != nil {
		return out, err
	}
	var issuer func(context.Context, OIDCClaimsInput) (OIDCClaimsProjection, error)
	if !nilDependency(s.deps.OIDC) {
		issuer = s.deps.OIDC.Claims
	}
	out, err = s.deps.Store.Token(ctx, TokenCommand{Request: request, Client: client.snapshot(), OIDC: issuer})
	if err != nil || ctx.Err() != nil {
		return TokenResult{Outcome: out.Outcome, CommandID: out.CommandID}, operationError(ctx, err)
	}
	if out.Outcome != identity.CommitOutcomeCommitted || out.Replayed {
		if out.AccessToken.state != nil || out.RefreshToken.state != nil || out.IDToken.state != nil {
			return TokenResult{Outcome: out.Outcome, CommandID: out.CommandID, Replayed: out.Replayed}, ErrUnavailable
		}
		return TokenResult{Outcome: out.Outcome, CommandID: out.CommandID, Replayed: out.Replayed}, nil
	}
	now := s.config.Clock.Now()
	accessTTL := s.config.AccessTTL
	if client.Workload != nil {
		accessTTL = client.Workload.AccessTTL()
		if out.RefreshToken.state != nil {
			return TokenResult{Outcome: identity.CommitOutcomeCommitted, CommandID: out.CommandID}, ErrUnavailable
		}
	}
	scopes, e := validatedScopes(out.Scopes)
	if e != nil || !scopeSubset(scopes, client.Scopes) || request.Scopes != nil && !scopeSubset(scopes, request.Scopes) || hasExtensionScope(scopes) && nilDependency(s.deps.OIDC) || out.AccessToken.state == nil || out.Resource != client.Resource || !now.Before(out.ExpiresAt) || out.ExpiresAt.After(now.Add(accessTTL)) {
		return TokenResult{Outcome: identity.CommitOutcomeCommitted, CommandID: out.CommandID}, ErrUnavailable
	}
	out.Scopes = scopes
	if out.IDToken.state != nil && (request.GrantType != AuthorizationCodeGrant || !hasExtensionScope(scopes) || nilDependency(s.deps.OIDC)) {
		return TokenResult{Outcome: identity.CommitOutcomeCommitted, CommandID: out.CommandID}, ErrUnavailable
	}
	if request.GrantType == AuthorizationCodeGrant && hasExtensionScope(scopes) && out.IDToken.state == nil {
		return TokenResult{Outcome: identity.CommitOutcomeCommitted, CommandID: out.CommandID}, ErrUnavailable
	}
	return out, nil
}

// Revoke delegates a possessed owning-client access/refresh token. Unknown
// tokens are non-enumerating native success; hints cannot select foreign kinds.
func (s *Service) Revoke(ctx context.Context, request RevokeRequest) (out RevokeResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = RevokeResult{Outcome: identity.CommitOutcomeUnknown}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	client, err := s.client(request.ClientID)
	if err != nil && request.ClientAuthentication.Method() != "none" {
		return out, ErrInvalidClient
	}
	if err != nil || !opaque32(request.Token) || request.Hint != 0 && request.Hint != TokenAccess && request.Hint != TokenRefresh || !visible(request.Network, 128) {
		return out, ErrInvalidRequest
	}
	if err := s.config.AuthenticateClient(ctx, client.ID, request.ClientAuthentication); err != nil {
		return out, err
	}
	out, err = s.deps.Store.Revoke(ctx, RevocationCommand{Request: request, Client: client.snapshot()})
	return out, operationError(ctx, err)
}

// Introspect selects only explicitly enabled owning-confidential-client RFC7662
// disclosure. Separate Basic authentication precedes lookup; public clients and
// disabled profiles deny. Unknown, inactive or foreign tokens return only false.
// The result is a current uncached observation, not renewable validity evidence
// or resource-server authorization. Transport must enforce TLS and rate limits.
func (s *Service) Introspect(ctx context.Context, request IntrospectRequest) (out IntrospectResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = IntrospectResult{}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if !s.config.OwningClientIntrospection {
		return out, ErrAccessDenied
	}
	client, err := s.client(request.ClientID)
	if err != nil || client.Public || request.ClientAuthentication.Method() != "client_secret_basic" {
		return out, ErrInvalidClient
	}
	if err := s.config.AuthenticateClient(ctx, client.ID, request.ClientAuthentication); err != nil {
		return out, err
	}
	if !visible(request.Token, 2048) || request.Hint != 0 && request.Hint != TokenAccess && request.Hint != TokenRefresh {
		return out, ErrInvalidRequest
	}
	reader, ok := s.deps.Store.(Introspector)
	if !ok || nilDependency(reader) {
		return out, ErrUnavailable
	}
	out, err = reader.Introspect(ctx, IntrospectionCommand{Request: request, Client: client.snapshot()})
	if err != nil || ctx.Err() != nil {
		return IntrospectResult{}, operationError(ctx, err)
	}
	if !out.Active {
		return IntrospectResult{}, nil
	}
	scopes, err := validatedScopes(out.Scopes)
	now := s.config.Clock.Now()
	if err != nil || !scopeSubset(scopes, client.Scopes) || out.ClientID != client.ID || !identifier(out.Subject) || out.Resource != client.Resource || out.Issuer != s.config.Issuer || !now.Before(out.ExpiresAt) || out.ExpiresAt.After(now.Add(s.config.RefreshTTL)) || out.ExpiresAt.Year() > 9999 {
		return IntrospectResult{}, ErrUnavailable
	}
	out.Scopes = scopes
	return out, nil
}

func (s *Service) bounded(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if s == nil || ctx == nil {
		return nil, nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	bounded, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	return bounded, stop, nil
}
func operationError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return nil
	}
	for _, known := range []error{ErrInvalidRequest, ErrInvalidClient, ErrInvalidGrant, ErrAccessDenied, ErrInvalidScope, ErrUnsupportedGrant} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrUnavailable
}
func validatedScopes(input []string) ([]string, error) {
	if len(input) < 1 || len(input) > 16 {
		return nil, ErrInvalidScope
	}
	// Typed callers have the same scope-field budget as ParseAuthorizationQuery
	// and ParseTokenForm; bypassing form decoding must not widen the profile.
	size := len(input) - 1
	for _, value := range input {
		if len(value) > 128 || size > 1024-len(value) {
			return nil, ErrInvalidScope
		}
		size += len(value)
	}
	owned := slices.Clone(input)
	slices.Sort(owned)
	for i, value := range owned {
		parsed, err := parseScopes(value)
		if err != nil || len(parsed) != 1 || i > 0 && value == owned[i-1] {
			return nil, ErrInvalidScope
		}
	}
	return owned, nil
}
func scopeSubset(child, parent []string) bool {
	if len(child) == 0 {
		return false
	}
	for _, value := range child {
		if !slices.Contains(parent, value) {
			return false
		}
	}
	return true
}
func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Chan, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func redacted(s fmt.State, name string)                   { _, _ = io.WriteString(s, "oauthserver."+name+"(redacted)") }
func (AuthorizeRequest) Format(s fmt.State, _ rune)       { redacted(s, "AuthorizeRequest") }
func (ContinueRequest) Format(s fmt.State, _ rune)        { redacted(s, "ContinueRequest") }
func (AuthorizeResult) Format(s fmt.State, _ rune)        { redacted(s, "AuthorizeResult") }
func (AuthorizationCommand) Format(s fmt.State, _ rune)   { redacted(s, "AuthorizationCommand") }
func (ContinuationCommand) Format(s fmt.State, _ rune)    { redacted(s, "ContinuationCommand") }
func (TokenCommand) Format(s fmt.State, _ rune)           { redacted(s, "TokenCommand") }
func (TokenResult) Format(s fmt.State, _ rune)            { redacted(s, "TokenResult") }
func (RevokeRequest) Format(s fmt.State, _ rune)          { redacted(s, "RevokeRequest") }
func (RevocationCommand) Format(s fmt.State, _ rune)      { redacted(s, "RevocationCommand") }
func (IntrospectRequest) Format(s fmt.State, _ rune)      { redacted(s, "IntrospectRequest") }
func (IntrospectionCommand) Format(s fmt.State, _ rune)   { redacted(s, "IntrospectionCommand") }
func (AuthorizeRequest) MarshalJSON() ([]byte, error)     { return nil, ErrInvalidRequest }
func (ContinueRequest) MarshalJSON() ([]byte, error)      { return nil, ErrInvalidRequest }
func (AuthorizeResult) MarshalJSON() ([]byte, error)      { return nil, ErrInvalidRequest }
func (AuthorizationCommand) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ContinuationCommand) MarshalJSON() ([]byte, error)  { return nil, ErrInvalidRequest }
func (TokenCommand) MarshalJSON() ([]byte, error)         { return nil, ErrInvalidRequest }
func (TokenResult) MarshalJSON() ([]byte, error)          { return nil, ErrInvalidRequest }
func (RevokeRequest) MarshalJSON() ([]byte, error)        { return nil, ErrInvalidRequest }
func (RevocationCommand) MarshalJSON() ([]byte, error)    { return nil, ErrInvalidRequest }
func (IntrospectRequest) MarshalJSON() ([]byte, error)    { return nil, ErrInvalidRequest }
func (IntrospectionCommand) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
