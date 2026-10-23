package oauthpostgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/jackc/pgx/v5"
)

type transition uint8

const (
	createInteraction transition = iota + 1
	approveInteraction
	denyInteraction
	exchangeCode
	rotateRefresh
	rejectReplay
	revokeAccess
	revokeFamily
	createWorkload
	deleteConsent
	narrowConsent
	createManagedClient
	deleteManagedClient
	rotateManagedSecret
	updateManagedClient
)

type grantRecord struct {
	ID                   string
	Tenant               identity.TenantID
	User                 identity.UserID
	ClientID             string
	ClientVersion        uint64
	Version              uint64
	ClientFingerprint    [32]byte
	Source               []identity.FeatureField
	Scopes               []string
	Resource             string
	CreatedAt, ExpiresAt time.Time
	Workload             *workloadSource `json:",omitempty"`
	ConsentID            string          `json:",omitempty"`
	ConsentGeneration    uint64          `json:",omitempty"`
	Subject              *subjectBinding `json:",omitempty"`
}
type artifactPayload struct {
	Schema       uint32
	Request      oauth.AuthorizationRequest
	Scopes       []string
	Subject      string `json:",omitempty"`
	SigningKeyID string `json:",omitempty"`
}
type artifactRecord struct {
	ID                   string
	Digest               oauth.TokenDigest
	Kind                 oauth.TokenKind
	Grant                grantRecord
	CreatedAt, ExpiresAt time.Time
	State                string
	GrantState           string
	Transition, Replay   identity.CommandID
	Payload              artifactPayload
}
type phaseInput struct {
	Schema                      uint32
	Configuration               [32]byte
	Binding                     identity.CommandBinding
	Transition                  transition
	Grant                       grantRecord
	Target                      oauth.TokenDigest
	TargetID                    string
	TargetKind                  oauth.TokenKind
	TargetPayload               artifactPayload
	TargetExpires               time.Time
	Request                     oauth.AuthorizationRequest
	Scopes                      []string
	CreatedAt, ObservationUntil time.Time
	Intent                      [32]byte
	Network                     string
	Consent                     consentMutation
	Deletion                    *consentDeletion              `json:",omitempty"`
	Narrowing                   *consentDeletion              `json:",omitempty"`
	ClientChange                *clientMutation               `json:",omitempty"`
	ClientAuthentication        *clientAuthenticationSnapshot `json:",omitempty"`
	SubjectCandidate            *oauth.OIDCSubjectCandidate   `json:",omitempty"`
	Authentication              *authenticationSelection      `json:",omitempty"`
	PreviousSource              []identity.FeatureField       `json:",omitempty"`
	ContinuationPrevious        identity.CommandID            `json:",omitempty"`
	SilentConsent               *silentConsent                `json:",omitempty"`
}

type consentMutation struct {
	ID                          string
	BeforeVersion, AfterVersion uint64
	Created                     bool
	Generation                  uint64     `json:",omitempty"`
	State                       string     `json:",omitempty"`
	ExpiresAt                   *time.Time `json:",omitempty"`
}

func (s *Store) prepareConsent(ctx context.Context, g grantRecord) (consentMutation, error) {
	if s.config.ConsentManagement {
		return s.prepareManagedConsent(ctx, g)
	}
	var id, rawVersion string
	err := s.pool.Raw().QueryRow(ctx, `SELECT consent_id,version::text FROM `+s.schema+`.consents WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3`, string(g.Tenant), string(g.User), g.ClientID).Scan(&id, &rawVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		id, err := identity.NewSubjectID()
		if err != nil {
			return consentMutation{}, oauth.ErrUnavailable
		}
		return consentMutation{ID: string(id), AfterVersion: 1, Created: true}, nil
	}
	if err != nil {
		return consentMutation{}, oauth.ErrUnavailable
	}
	version, err := strconv.ParseUint(rawVersion, 10, 64)
	if _, idErr := identity.ParseSubjectID(id); err != nil || idErr != nil || version == 0 || version == math.MaxUint64 {
		return consentMutation{}, oauth.ErrAccessDenied
	}
	return consentMutation{ID: id, BeforeVersion: version, AfterVersion: version + 1}, nil
}

// These are private durable nonsecret projections, not credentials or policy
// assertions. Diagnostic formatting is still forbidden correlation disclosure.
func (phaseInput) Format(s fmt.State, _ rune)     { _, _ = s.Write([]byte("oauth phase input(redacted)")) }
func (grantRecord) Format(s fmt.State, _ rune)    { _, _ = s.Write([]byte("oauth grant(redacted)")) }
func (artifactRecord) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("oauth artifact(redacted)")) }

func (s *Store) bounded(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil || s == nil {
		return nil, nil, oauth.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	bounded, stop := context.WithTimeout(ctx, s.config.Protocol.MaximumDuration)
	return bounded, stop, nil
}
func (s *Store) client(c oauth.Client) (oauth.Client, error) {
	validated, err := oauth.ValidateClient(c)
	if err != nil {
		return oauth.Client{}, oauth.ErrInvalidRequest
	}
	for _, registered := range s.config.Protocol.Clients {
		if registered.ID == c.ID && clientFingerprint(registered) == clientFingerprint(validated) {
			return registered, nil
		}
	}
	return oauth.Client{}, oauth.ErrAccessDenied
}
func (s *Store) now() time.Time {
	return s.config.Protocol.Clock.Now().UTC().Truncate(time.Microsecond)
}
func (s *Store) intent(values ...string) [32]byte {
	h := hmac.New(sha256.New, s.config.IntentKey[:])
	h.Write([]byte("oauth-caller-intent-v1\x00"))
	for _, value := range values {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		h.Write(size[:])
		h.Write([]byte(value))
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
func scopeSubset(request, allowed []string) bool {
	for _, scope := range request {
		if !slices.Contains(allowed, scope) {
			return false
		}
	}
	return len(request) > 0
}

// Native Store is public as well as Service's adapter. Bound typed projections
// before encoding, hashing or cloning, preserving the protocol field ceilings.
func boundedText(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}
func selectedScopes(values []string) ([]string, error) {
	if len(values) < 1 || len(values) > 16 {
		return nil, oauth.ErrInvalidScope
	}
	size := len(values) - 1
	for _, value := range values {
		if len(value) > 128 || size > 1024-len(value) || !boundedText(value, 128) || strings.ContainsAny(value, " \"\\") {
			return nil, oauth.ErrInvalidScope
		}
		size += len(value)
	}
	owned := slices.Clone(values)
	slices.Sort(owned)
	for i := 1; i < len(owned); i++ {
		if owned[i] == owned[i-1] {
			return nil, oauth.ErrInvalidScope
		}
	}
	return owned, nil
}

// Authorize creates a browser-bound consent interaction, or a selected silent
// code after independently checking original bounded explicit approval. It authenticates
// sealed GetResult custody again and rechecks every current owner inside native
// preparation/apply/final commit. It never issues or replaces a local session.
func (s *Store) Authorize(ctx context.Context, c oauth.AuthorizationCommand) (oauth.AuthorizeResult, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return oauth.AuthorizeResult{}, err
	}
	defer stop()
	if !boundedText(c.Network, 128) || !boundedText(c.Request.ClientID, 128) || !boundedText(c.Request.RedirectURI, 2048) || !boundedText(c.Request.CodeChallenge, 43) || !boundedText(c.Request.Resource, 2048) || c.Request.State != "" && !boundedText(c.Request.State, 1024) || c.Request.Nonce != "" && !boundedText(c.Request.Nonce, 256) || c.Request.Prompt != "" && c.Request.Prompt != "login" && c.Request.Prompt != "none" && c.Request.Prompt != "consent" {
		return oauth.AuthorizeResult{}, oauth.ErrInvalidRequest
	}
	if c.Request.Scopes, err = selectedScopes(c.Request.Scopes); err != nil {
		return oauth.AuthorizeResult{}, err
	}
	client, err := s.checkedClient(ctx, c.Client)
	if err != nil {
		return oauth.AuthorizeResult{}, err
	}
	q := url.Values{"response_type": {"code"}, "client_id": {c.Request.ClientID}, "redirect_uri": {c.Request.RedirectURI}, "code_challenge_method": {"S256"}, "code_challenge": {c.Request.CodeChallenge}, "resource": {c.Request.Resource}, "scope": {strings.Join(c.Request.Scopes, " ")}}
	if c.Request.State != "" {
		q.Set("state", c.Request.State)
	}
	if c.Request.Nonce != "" {
		q.Set("nonce", c.Request.Nonce)
	}
	if c.Request.Prompt != "" {
		q.Set("prompt", c.Request.Prompt)
	}
	if c.Request.MaxAge != nil {
		q.Set("max_age", strconv.FormatUint(uint64(*c.Request.MaxAge), 10))
	}
	parser := oauth.ParseAuthorizationQuery
	if len(s.config.Protocol.OIDCScopes.Scopes()) > 0 {
		parser = oauth.ParseAuthorizationQueryWithOIDC
	}
	request, err := parser(q.Encode())
	if err != nil || request.ClientID != client.ID || !slices.Contains(client.Redirects, request.RedirectURI) || request.Resource != client.Resource || !scopeSubset(request.Scopes, client.Scopes) || c.Session.ValidateAt(s.now()) != nil {
		return oauth.AuthorizeResult{}, oauth.ErrAccessDenied
	}
	authentication, err := s.authenticationPolicy(ctx, c.OIDC, client, request, c.Session, nil)
	if err != nil {
		return oauth.AuthorizeResult{}, err
	}
	var subjectCandidate *oauth.OIDCSubjectCandidate
	if pairwiseClient(client) && slices.Contains(request.Scopes, "openid") {
		if !validSubjectProposal(client, c.SubjectCandidate) {
			return oauth.AuthorizeResult{}, oauth.ErrAccessDenied
		}
		owned := *c.SubjectCandidate
		subjectCandidate = &owned
	} else if c.SubjectCandidate != nil {
		return oauth.AuthorizeResult{}, oauth.ErrAccessDenied
	}
	bindings, err := c.Session.Session.Bindings()
	if err != nil {
		return oauth.AuthorizeResult{}, oauth.ErrAccessDenied
	}
	if s.managedID(client.ID) && bindings.TenantID != s.config.Protocol.ManagedClients.TenantID {
		return oauth.AuthorizeResult{}, oauth.ErrAccessDenied
	}
	source, err := sessionpg.OriginalSessionFields(c.Session.Session)
	if err != nil {
		return oauth.AuthorizeResult{}, oauth.ErrAccessDenied
	}
	command, err := identity.NewCommandID()
	if err != nil {
		return oauth.AuthorizeResult{}, oauth.ErrUnavailable
	}
	now := s.now()
	// Initial record correlation must survive a lost final COMMIT response.
	// Both names are one server-generated opaque ID, never caller identity or
	// bearer authority; existing native recovery still authenticates its scope.
	grant := grantRecord{ID: string(command), Tenant: bindings.TenantID, User: bindings.UserID, ClientID: client.ID, ClientVersion: client.Version, ClientFingerprint: clientFingerprint(client), Source: source, Scopes: slices.Clone(request.Scopes), Resource: request.Resource, CreatedAt: now, ExpiresAt: now.Add(s.config.Protocol.RefreshTTL)}
	p := &phase{store: s, client: client, browser: c.Browser, observation: c.Session}
	p.input = phaseInput{Schema: 1, Configuration: s.identity, Transition: createInteraction, Grant: grant, Request: copyAuthorizationRequest(request), Scopes: slices.Clone(request.Scopes), CreatedAt: now, ObservationUntil: c.Session.ValidUntil(), Intent: s.intent("authorize", string(command)), Network: c.Network, SubjectCandidate: subjectCandidate, Authentication: authentication}
	if request.Prompt == "none" {
		if authentication == nil || authentication.Requirement != oauth.OIDCAuthenticationSilent {
			return oauth.AuthorizeResult{}, oauth.ErrAccessDenied
		}
		approved, err := s.readSilentConsent(ctx, client, grant)
		if err != nil {
			return oauth.AuthorizeResult{}, err
		}
		p.input.SilentConsent = approved
		p.input.Grant.ConsentID, p.input.Grant.ConsentGeneration = approved.ID, approved.Generation
		p.input.Grant.ExpiresAt = minTime(p.input.Grant.ExpiresAt, approved.ExpiresAt)
	}
	p.bind(command, "identity.oauth-server.authorize", string(command))
	result, err := p.execute(ctx)
	if err != nil {
		return oauth.AuthorizeResult{CommandID: command, Outcome: authorizeOutcome(result)}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if p.input.SilentConsent != nil {
		if err := p.finishSilentAuthorization(ctx); err != nil {
			return oauth.AuthorizeResult{CommandID: command, Outcome: oauth.AuthorizationHistorical}, err
		}
	}
	return p.authorizationResult(result), nil
}

// Continue consumes only the originally issued interaction with its current
// browser/session and synchronizer. Selected OIDC freshness may adopt a genuine
// newly authenticated same-user session while fencing the original source too.
// Explicit denial remains a protected one-use transition; earlier consent never
// silently approves a new request.
func (s *Store) Continue(ctx context.Context, c oauth.ContinuationCommand) (oauth.AuthorizeResult, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return oauth.AuthorizeResult{}, err
	}
	defer stop()
	if !boundedText(c.Request.Network, 128) {
		return oauth.AuthorizeResult{}, oauth.ErrInvalidRequest
	}
	if c.Request.Scopes != nil {
		if c.Request.Scopes, err = selectedScopes(c.Request.Scopes); err != nil {
			return oauth.AuthorizeResult{}, err
		}
	}
	client, err := s.checkedClient(ctx, c.Client)
	if err != nil {
		return oauth.AuthorizeResult{}, err
	}
	if c.Request.ClientID != client.ID || c.Request.Origin != s.config.Protocol.Issuer.String() || c.Session.ValidateAt(s.now()) != nil {
		return oauth.AuthorizeResult{}, oauth.ErrAccessDenied
	}
	target, err := s.lookup(ctx, c.Request.Continuation, client, []oauth.TokenKind{oauth.TokenContinuation})
	if err != nil {
		return oauth.AuthorizeResult{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	// A spent interaction is historical custody, never a new authentication
	// request. Reject it before evaluating freshness against its adopted source.
	if target.State != "active" {
		return oauth.AuthorizeResult{}, oauth.ErrAccessDenied
	}
	current, err := sessionpg.OriginalSessionFields(c.Session.Session)
	if err != nil || c.Request.TenantID != target.Grant.Tenant {
		return oauth.AuthorizeResult{}, oauth.ErrAccessDenied
	}
	var authentication *authenticationSelection
	var previous []identity.FeatureField
	if c.Request.Approve && authenticationRequested(target.Payload.Request) {
		original, err := sessionpg.OriginalSessionFromFields(target.Grant.Tenant, target.Grant.User, target.Grant.Source)
		if err != nil {
			return oauth.AuthorizeResult{}, oauth.ErrAccessDenied
		}
		authentication, err = s.authenticationPolicy(ctx, c.OIDC, client, target.Payload.Request, c.Session, &oauth.OIDCReauthenticationInput{OriginalSession: original, RequestedAt: target.Grant.CreatedAt})
		if err != nil {
			return oauth.AuthorizeResult{}, err
		}
		if authentication.Requirement == oauth.OIDCAuthenticationFresh {
			return oauth.AuthorizeResult{}, oauth.ErrLoginRequired
		}
		if !sameJSON(current, target.Grant.Source) {
			if err := validateFreshSource(original, c.Session, target.Grant.CreatedAt); err != nil {
				return oauth.AuthorizeResult{}, err
			}
			previous = target.Grant.Source
			target.Grant.Source = current
		}
	} else if !sameJSON(current, target.Grant.Source) {
		return oauth.AuthorizeResult{}, oauth.ErrAccessDenied
	}
	selected := c.Request.Scopes
	if selected == nil {
		selected = slices.Clone(target.Payload.Scopes)
	}
	if !scopeSubset(selected, target.Payload.Scopes) {
		return oauth.AuthorizeResult{}, oauth.ErrInvalidScope
	}
	p := s.targetPhase(target, client, approveInteraction, "identity.oauth-server.continue", target.Transition, s.intent("continue", c.Request.Continuation, fmt.Sprint(c.Request.Approve), strings.Join(selected, " "), c.Request.Network), c.Request.Network)
	if !c.Request.Approve {
		p.input.Transition = denyInteraction
	} else {
		p.input.Consent, err = s.prepareConsent(ctx, target.Grant)
		if err != nil {
			return oauth.AuthorizeResult{}, err
		}
		if s.config.ConsentReuseTTL != 0 {
			expiry := p.input.CreatedAt.Add(s.config.ConsentReuseTTL)
			p.input.Consent.ExpiresAt = &expiry
		}
	}
	p.input.Scopes = slices.Clone(selected)
	p.input.Authentication, p.input.PreviousSource = authentication, previous
	p.input.ObservationUntil = c.Session.ValidUntil()
	p.browser = c.Request.Session
	p.csrf = c.Request.CSRF
	p.observation = c.Session
	result, err := p.execute(ctx)
	if err != nil {
		return oauth.AuthorizeResult{CommandID: p.input.Binding.CommandID, Outcome: authorizeOutcome(result)}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	return p.authorizationResult(result), nil
}

// Token verifies the configured none/Basic client method before admitting a
// client-bound code/S256 or refresh bearer. Subject, tenant and
// root credential/policy epochs are loaded only from the original native grant;
// no browser cookie, request actor or token claim can replace them. A correct
// proof replay revokes only its related grant/family and returns invalid_grant.
func (s *Store) Token(ctx context.Context, c oauth.TokenCommand) (out oauth.TokenResult, err error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return oauth.TokenResult{}, err
	}
	defer stop()
	if !boundedText(c.Request.Network, 128) {
		return oauth.TokenResult{}, oauth.ErrInvalidRequest
	}
	if c.Request.Scopes != nil {
		if c.Request.Scopes, err = selectedScopes(c.Request.Scopes); err != nil {
			return oauth.TokenResult{}, err
		}
	}
	client, err := s.checkedClient(ctx, c.Client)
	if err != nil {
		return oauth.TokenResult{}, err
	}
	r := c.Request
	proof, err := s.authenticateClientSnapshot(ctx, client, r.ClientAuthentication)
	if err != nil {
		return oauth.TokenResult{}, err
	}
	var executing *phase
	defer func() {
		if err == nil {
			var retained *clientAuthenticationSnapshot
			if executing != nil {
				retained = executing.input.ClientAuthentication
			}
			if fence := s.finishClientAuthentication(ctx, client, proof, retained); fence != nil {
				out = oauth.TokenResult{Outcome: out.Outcome, CommandID: out.CommandID, Replayed: out.Replayed}
				err = fence
			}
		}
	}()
	if r.ClientID != client.ID || r.Resource != "" && r.Resource != client.Resource {
		return oauth.TokenResult{}, oauth.ErrInvalidRequest
	}
	if client.Workload != nil {
		return s.issueWorkload(ctx, client, r)
	}
	kind, operation, wire := oauth.TokenCode, exchangeCode, r.Code
	switch r.GrantType {
	case oauth.AuthorizationCodeGrant:
		if r.RefreshToken != "" || r.Scopes != nil || !slices.Contains(client.Redirects, r.RedirectURI) {
			return oauth.TokenResult{}, oauth.ErrInvalidRequest
		}
		if _, err := oauth.S256Challenge(r.CodeVerifier); err != nil {
			return oauth.TokenResult{}, oauth.ErrInvalidRequest
		}
	case oauth.RefreshTokenGrant:
		kind, operation, wire = oauth.TokenRefresh, rotateRefresh, r.RefreshToken
		if r.Code != "" || r.RedirectURI != "" || r.CodeVerifier != "" {
			return oauth.TokenResult{}, oauth.ErrInvalidRequest
		}
	default:
		return oauth.TokenResult{}, oauth.ErrUnsupportedGrant
	}
	target, err := s.lookup(ctx, wire, client, []oauth.TokenKind{kind})
	if err != nil {
		return oauth.TokenResult{}, publicError(ctx, err, oauth.ErrInvalidGrant)
	}
	if target.GrantState != "active" {
		return oauth.TokenResult{}, oauth.ErrInvalidGrant
	}
	if kind == oauth.TokenCode {
		challenge, _ := oauth.S256Challenge(r.CodeVerifier)
		if r.RedirectURI != target.Payload.Request.RedirectURI || subtle.ConstantTimeCompare([]byte(challenge), []byte(target.Payload.Request.CodeChallenge)) != 1 {
			return oauth.TokenResult{}, oauth.ErrInvalidGrant
		}
	}
	selected := r.Scopes
	if selected == nil {
		selected = slices.Clone(target.Payload.Scopes)
	}
	if !scopeSubset(selected, target.Payload.Scopes) || !scopeSubset(selected, client.Scopes) {
		return oauth.TokenResult{}, oauth.ErrInvalidScope
	}
	// Omitted refresh scopes inherit original authority. Admission therefore
	// belongs after native lookup but before any consumption/replay effects.
	for _, scope := range selected {
		if s.config.Protocol.OIDCScopes.Contains(scope) && c.OIDC == nil {
			return oauth.TokenResult{}, oauth.ErrAccessDenied
		}
	}
	id := target.Transition
	if target.State == "consumed" {
		operation, id = rejectReplay, target.Replay
	} else if target.State != "active" {
		return oauth.TokenResult{}, oauth.ErrInvalidGrant
	}
	p := s.targetPhase(target, client, operation, "identity.oauth-server.token", id, s.intent("token", string(r.GrantType), wire, r.RedirectURI, r.CodeVerifier, strings.Join(selected, " "), r.Resource, r.Network), r.Network)
	executing = p
	p.input.Scopes = slices.Clone(selected)
	p.input.ClientAuthentication = proof
	if r.GrantType == oauth.AuthorizationCodeGrant {
		p.oidc = c.OIDC
	}
	result, err := p.execute(ctx)
	out = oauth.TokenResult{Outcome: result.Outcome, CommandID: id, Replayed: !p.applied}
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrInvalidGrant)
	}
	if result.Outcome == identity.CommitOutcomeCommitted && !p.applied && operation != rejectReplay {
		// This is another protocol credential use, not Recover's read-only
		// observation. Two callers can both read active before the winner commits;
		// recovering its terminal issuance must still detect the now-spent parent
		// and revoke its actual descendants (RFC9700 section4.14.2).
		current, err := s.lookup(ctx, wire, client, []oauth.TokenKind{kind})
		if err != nil {
			return out, publicError(ctx, err, oauth.ErrInvalidGrant)
		}
		if current.ID != target.ID || current.Grant.ID != target.Grant.ID || current.State != "consumed" || current.GrantState != "active" {
			return out, oauth.ErrInvalidGrant
		}
		replay := s.targetPhase(current, client, rejectReplay, "identity.oauth-server.token", current.Replay, s.intent("token", string(r.GrantType), wire, r.RedirectURI, r.CodeVerifier, strings.Join(selected, " "), r.Resource, r.Network), r.Network)
		replay.input.Scopes = slices.Clone(selected)
		replay.input.ClientAuthentication = proof
		revoked, err := replay.execute(ctx)
		out = oauth.TokenResult{Outcome: revoked.Outcome, CommandID: current.Replay, Replayed: !replay.applied}
		if err != nil {
			return out, publicError(ctx, err, oauth.ErrInvalidGrant)
		}
		return out, oauth.ErrInvalidGrant
	}
	if operation == rejectReplay {
		return out, oauth.ErrInvalidGrant
	}
	if result.Outcome == identity.CommitOutcomeCommitted && p.applied {
		out.AccessToken, out.RefreshToken, out.ExpiresAt = p.generatedToken(oauth.TokenAccess), p.generatedToken(oauth.TokenRefresh), p.generatedExpiry(oauth.TokenAccess)
		out.Resource, out.Scopes = target.Grant.Resource, slices.Clone(selected)
		if p.output.IDToken != "" {
			out.IDToken, err = oauth.ParseIDToken(p.output.IDToken)
			if err != nil {
				return oauth.TokenResult{Outcome: out.Outcome, CommandID: out.CommandID}, oauth.ErrUnavailable
			}
		}
	}
	return out, nil
}

// Revoke authenticates the registered none/Basic method before token-bound
// revocation (RFC7009 sections2.1/5), including unknown-token no-ops.
// Unknown and foreign tokens are indistinguishable successful no-ops. Access
// revocation affects only that access record; refresh revokes its related grant,
// never another client/root family. The token hint is advisory, not authority.
func (s *Store) Revoke(ctx context.Context, c oauth.RevocationCommand) (out oauth.RevokeResult, err error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return oauth.RevokeResult{}, err
	}
	defer stop()
	if !boundedText(c.Request.Network, 128) {
		return oauth.RevokeResult{}, oauth.ErrInvalidRequest
	}
	client, err := s.checkedClient(ctx, c.Client)
	if err != nil {
		return oauth.RevokeResult{}, err
	}
	proof, err := s.authenticateClientSnapshot(ctx, client, c.Request.ClientAuthentication)
	if err != nil {
		return oauth.RevokeResult{}, err
	}
	var executing *phase
	defer func() {
		if err == nil {
			var retained *clientAuthenticationSnapshot
			if executing != nil {
				retained = executing.input.ClientAuthentication
			}
			if fence := s.finishClientAuthentication(ctx, client, proof, retained); fence != nil {
				out = oauth.RevokeResult{Outcome: out.Outcome, CommandID: out.CommandID}
				err = fence
			}
		}
	}()
	if c.Request.ClientID != client.ID || c.Request.Hint != 0 && c.Request.Hint != oauth.TokenAccess && c.Request.Hint != oauth.TokenRefresh {
		return oauth.RevokeResult{}, oauth.ErrInvalidRequest
	}
	target, err := s.lookup(ctx, c.Request.Token, client, []oauth.TokenKind{oauth.TokenAccess, oauth.TokenRefresh})
	if errors.Is(err, oauth.ErrInvalidGrant) {
		return oauth.RevokeResult{Outcome: identity.CommitOutcomeCommitted}, nil
	}
	if err != nil {
		return oauth.RevokeResult{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if target.GrantState != "active" || target.State == "revoked" {
		return oauth.RevokeResult{Outcome: identity.CommitOutcomeCommitted}, nil
	}
	operation := revokeAccess
	if target.Kind == oauth.TokenRefresh {
		operation = revokeFamily
	}
	p := s.targetPhase(target, client, operation, "identity.oauth-server.revoke", target.Replay, s.intent("revoke", c.Request.Token, c.Request.Network), c.Request.Network)
	executing = p
	p.input.ClientAuthentication = proof
	result, err := p.execute(ctx)
	var conflict identity.ConflictError
	if errors.As(err, &conflict) && result.Outcome == identity.CommitOutcomeConflict && ctx.Err() == nil {
		// Two authenticated callers can race the same preallocated claim while
		// its winner has not completed revocation. RFC7009 section2.2.1 permits
		// unavailable/retry semantics here, not a fabricated completed no-op.
		// Preserve the actual conflict and never query, retry or reconcile it
		// as a side effect of this call. Unknown COMMIT and cancellation differ.
		return oauth.RevokeResult{Outcome: result.Outcome, CommandID: target.Replay}, oauth.ErrUnavailable
	}
	return oauth.RevokeResult{Outcome: result.Outcome, CommandID: target.Replay}, publicError(ctx, err, oauth.ErrAccessDenied)
}

func (s *Store) targetPhase(target artifactRecord, client oauth.Client, t transition, operation string, id identity.CommandID, intent [32]byte, network string) *phase {
	p := &phase{store: s, client: client}
	p.input = phaseInput{Schema: 1, Configuration: s.identity, Transition: t, Grant: target.Grant, Target: target.Digest, TargetID: target.ID, TargetKind: target.Kind, TargetPayload: target.Payload, TargetExpires: target.ExpiresAt, Request: target.Payload.Request, Scopes: slices.Clone(target.Payload.Scopes), CreatedAt: s.now(), Intent: intent, Network: network}
	p.bind(id, operation, target.Grant.ID)
	if t == revokeAccess {
		p.input.Binding.RecordID = target.ID
	}
	return p
}
func (p *phase) bind(id identity.CommandID, operation, record string) {
	g := p.input.Grant
	p.input.Binding = identity.CommandBinding{CommandID: id, TenantID: g.Tenant, UserID: g.User, ActorID: identity.ActorID(g.User), ActorKind: authorization.SubjectUser, OperationID: operation, SchemaID: operation + ".public-password-v1", SchemaVersion: 1, PolicyID: p.store.config.PolicyID, PolicyVersion: p.store.config.Coordinator.AdmissionPolicy.PolicyVersion, RecordID: record, CorrelationID: string(id)}
	if g.Workload != nil {
		p.input.Binding.AnonymousFlowID = g.ID
		p.input.Binding.UserID = ""
		p.input.Binding.ActorID = identity.ActorID(g.Workload.ID)
		p.input.Binding.ActorKind = authorization.SubjectServiceAccount
		p.input.Binding.SchemaID = operation + ".configured-workload-v1"
	}
}
func (p *phase) query() identity.RecoveryQuery {
	b := p.input.Binding
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
}
func (p *phase) caller() authorization.DecisionContext {
	b := p.input.Binding
	if p.input.Grant.Workload != nil {
		// Coordinator admission/recovery authorizes the exact server-owned flow,
		// not a second workload resource alias (kernel CommandQueryPolicy).
		return authorization.DecisionContext{PolicyRevision: authorization.Revision(b.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}}}
	}
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(b.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.UserID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
}

func (s *Store) lookup(ctx context.Context, wire string, client oauth.Client, kinds []oauth.TokenKind) (artifactRecord, error) {
	if _, err := s.checkedClient(ctx, client); err != nil {
		return artifactRecord{}, err
	}
	token, err := oauth.ParseToken(wire)
	if err != nil {
		return artifactRecord{}, oauth.ErrInvalidGrant
	}
	var found *artifactRecord
	for _, kind := range kinds {
		for _, key := range s.config.TokenKeys {
			digest, err := token.Digest(key, oauth.TokenScope{Issuer: s.config.Protocol.Issuer, Environment: s.config.Protocol.Environment, ClientID: client.ID, Kind: kind})
			if err != nil {
				return artifactRecord{}, oauth.ErrInvalidGrant
			}
			var artifact artifactRecord
			var source, scopes, payload, fingerprint, workload []byte
			var clientVersion, grantVersion string
			workloadColumn := "NULL::jsonb"
			if workloadSelected(s.config.Protocol.Clients) {
				workloadColumn = "g.workload_source"
			}
			err = s.pool.Raw().QueryRow(ctx, `SELECT a.artifact_id,a.kind,a.created_at,a.expires_at,a.state,a.transition_command,a.replay_command,a.payload,g.grant_id,g.tenant_id,COALESCE(g.user_id,''),g.client_id,g.client_version::text,g.client_fingerprint,g.source_session,g.scopes,g.resource,g.created_at,g.expires_at,g.version::text,g.state,`+workloadColumn+` FROM `+s.schema+`.artifacts a JOIN `+s.schema+`.grants g USING(grant_id) WHERE a.digest_version=$1 AND a.digest=$2 AND a.kind=$3 AND a.client_id=$4`, digest.KeyVersion, digest.Sum[:], kind, client.ID).Scan(&artifact.ID, &artifact.Kind, &artifact.CreatedAt, &artifact.ExpiresAt, &artifact.State, &artifact.Transition, &artifact.Replay, &payload, &artifact.Grant.ID, &artifact.Grant.Tenant, &artifact.Grant.User, &artifact.Grant.ClientID, &clientVersion, &fingerprint, &source, &scopes, &artifact.Grant.Resource, &artifact.Grant.CreatedAt, &artifact.Grant.ExpiresAt, &grantVersion, &artifact.GrantState, &workload)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return artifactRecord{}, publicError(ctx, err, oauth.ErrInvalidGrant)
			}
			artifact.Digest = digest
			if decodeJSON(source, &artifact.Grant.Source) != nil || decodeJSON(scopes, &artifact.Grant.Scopes) != nil || decodeJSON(payload, &artifact.Payload) != nil || len(fingerprint) != 32 {
				return artifactRecord{}, oauth.ErrUnavailable
			}
			copy(artifact.Grant.ClientFingerprint[:], fingerprint)
			if s.managedID(client.ID) && artifact.Grant.Tenant != s.config.Protocol.ManagedClients.TenantID {
				return artifactRecord{}, oauth.ErrInvalidGrant
			}
			if len(workload) > 0 {
				var original workloadSource
				if decodeJSON(workload, &original) != nil {
					return artifactRecord{}, oauth.ErrUnavailable
				}
				artifact.Grant.Workload = &original
			}
			if client.Workload != nil && (!s.validWorkload(artifact.Grant, client) || artifact.Kind != oauth.TokenAccess) || client.Workload == nil && artifact.Grant.Workload != nil {
				return artifactRecord{}, oauth.ErrInvalidGrant
			}
			if _, err := fmt.Sscan(grantVersion, &artifact.Grant.Version); err != nil || artifact.Grant.Version == 0 || artifact.Grant.Version == ^uint64(0) {
				return artifactRecord{}, oauth.ErrUnavailable
			}
			ceiling := artifact.Grant.Scopes
			if artifact.Kind == oauth.TokenContinuation {
				// A spent consent interaction retains the original requested set,
				// not the subsequently narrowed grant. It can authenticate historical
				// recovery, never bypass active one-use/consent issuance checks.
				ceiling = client.Scopes
				if !slices.Equal(artifact.Payload.Scopes, artifact.Payload.Request.Scopes) {
					return artifactRecord{}, oauth.ErrInvalidGrant
				}
			}
			if _, err := fmt.Sscan(clientVersion, &artifact.Grant.ClientVersion); err != nil || artifact.Grant.ClientID != client.ID || artifact.Grant.ClientVersion != client.Version || artifact.Grant.ClientFingerprint != clientFingerprint(client) || artifact.Grant.Resource != client.Resource || artifact.Payload.Schema != 1 || !scopeSubset(artifact.Payload.Scopes, ceiling) {
				return artifactRecord{}, oauth.ErrInvalidGrant
			}
			if pairwiseClient(client) && slices.Contains(artifact.Payload.Request.Scopes, "openid") {
				if err := s.loadSubjectBinding(ctx, &artifact.Grant); err != nil {
					return artifactRecord{}, err
				}
				if !bindingMatchesClient(artifact.Grant.Subject, client) {
					return artifactRecord{}, oauth.ErrAccessDenied
				}
			}
			if found != nil {
				return artifactRecord{}, oauth.ErrUnavailable
			}
			found = &artifact
		}
	}
	if found == nil {
		return artifactRecord{}, oauth.ErrInvalidGrant
	}
	if s.config.ConsentManagement && found.Grant.Workload == nil {
		active, err := s.consentLookupState(ctx, &found.Grant)
		if err != nil {
			return artifactRecord{}, err
		}
		if found.Kind != oauth.TokenContinuation && !active {
			found.GrantState = "revoked"
		}
	}
	if _, err := s.checkedClient(ctx, client); err != nil {
		return artifactRecord{}, err
	}
	return *found, nil
}

func sameJSON(a, b any) bool {
	x, xe := json.Marshal(a)
	y, ye := json.Marshal(b)
	defer clear(x)
	defer clear(y)
	return xe == nil && ye == nil && bytes.Equal(x, y)
}
func decodeJSON(wire []byte, target any) error {
	if len(wire) < 1 || len(wire) > 262144 {
		return oauth.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(wire))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return oauth.ErrUnavailable
	}
	return nil
}
func publicError(ctx context.Context, err, denied error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, oauth.ErrLoginRequired) {
		return oauth.ErrLoginRequired
	}
	if errors.Is(err, oauth.ErrConsentRequired) {
		return oauth.ErrConsentRequired
	}
	var reauthentication kernel.OAuthReauthenticationRequiredError
	if errors.As(err, &reauthentication) {
		return oauth.ErrLoginRequired
	}
	var forbidden identity.ForbiddenError
	var conflict identity.ConflictError
	if errors.As(err, &forbidden) || errors.As(err, &conflict) || errors.Is(err, oauth.ErrInvalidGrant) || errors.Is(err, oauth.ErrAccessDenied) {
		return denied
	}
	var unknown identity.UnknownCommitError
	if errors.As(err, &unknown) {
		return unknown
	}
	return oauth.ErrUnavailable
}
func authorizeOutcome(r identity.CommandResult) oauth.AuthorizeOutcome {
	if r.Outcome == identity.CommitOutcomeUnknown {
		return oauth.AuthorizationUnknown
	}
	return oauth.AuthorizationHistorical
}

// Keep command IDs canonical at the SQL journal boundary; they are not bearer
// credentials. This projection never supplies an identity or permission.
func commandBytes(id identity.CommandID) []byte {
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(string(id))
	return raw
}
