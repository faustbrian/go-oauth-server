package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

// EndSessionParameters is the closed RP-Initiated Logout query profile. The
// hint is untrusted signed input, not verification, issuance or session authority.
// ClientID is optional; a supplied value must match the verified hint's client.
// An absent URI selects local-only termination, never an authorization callback.
// Parse/validation do not revoke sessions or authorize a redirect.
type EndSessionParameters struct {
	IDTokenHint, ClientID, PostLogoutRedirectURI, State string
}

func (EndSessionParameters) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oidc.EndSessionParameters(redacted)"))
}
func (EndSessionParameters) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }
func (EndSessionParameters) MarshalText() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

// ParseEndSessionQuery bounds input before decoding and accepts only the four
// selected RP-Initiated Logout §2 fields, each at most once. This native profile
// requires a hint and current matching source session; hintless confirmation UI,
// logout_hint and ui_locales are not selected. Returned hint/state retain their
// exact decoded bytes and must not be logged or implicitly serialized.
func ParseEndSessionQuery(raw string) (EndSessionParameters, error) {
	if len(raw) == 0 || len(raw) > 65536 {
		return EndSessionParameters{}, oauth.ErrInvalidRequest
	}
	values, err := url.ParseQuery(raw)
	if err != nil || len(values) > 4 {
		return EndSessionParameters{}, oauth.ErrInvalidRequest
	}
	for name, entries := range values {
		if len(entries) != 1 {
			return EndSessionParameters{}, oauth.ErrInvalidRequest
		}
		switch name {
		case "id_token_hint", "client_id", "post_logout_redirect_uri", "state":
		default:
			return EndSessionParameters{}, oauth.ErrInvalidRequest
		}
		if name != "state" && entries[0] == "" {
			return EndSessionParameters{}, oauth.ErrInvalidRequest
		}
	}
	parameters := EndSessionParameters{values.Get("id_token_hint"), values.Get("client_id"), values.Get("post_logout_redirect_uri"), values.Get("state")}
	if err := validateEndSessionParameters(parameters); err != nil {
		return EndSessionParameters{}, err
	}
	return parameters, nil
}

func validateEndSessionParameters(p EndSessionParameters) error {
	if _, err := oauth.ParseIDToken(p.IDTokenHint); err != nil || !endSessionText(p.State, 1024) || !endSessionText(p.ClientID, 128) {
		return oauth.ErrInvalidRequest
	}
	for _, r := range p.ClientID {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.", r)) {
			return oauth.ErrInvalidRequest
		}
	}
	if p.PostLogoutRedirectURI != "" {
		if _, err := oauth.NewRedirectPolicy([]string{p.PostLogoutRedirectURI}); err != nil {
			return oauth.ErrInvalidRequest
		}
	}
	return nil
}

func endSessionText(value string, maximum int) bool {
	if len(value) > maximum {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

// EndSessionRequest borrows the genuine initiating browser/CSRF from trusted
// transport and untrusted RP parameters. Tenant is an exact precondition, not
// permission to choose another hint's/session's owner. No raw fields may be logged.
type EndSessionRequest struct {
	TenantID        identity.TenantID
	Session         auth.BearerCredential
	CSRF            session.CSRFToken
	Origin, Network string
	Parameters      EndSessionParameters
}

func (EndSessionRequest) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oidc.EndSessionRequest(redacted)"))
}
func (EndSessionRequest) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }
func (EndSessionRequest) MarshalText() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

// EndSessionResult adds only the existing session owner's credential-free cookie
// deletion to core's closed outcome. Historical/unknown/error results never carry
// deletion or a successful redirect. This package writes no HTTP response.
type EndSessionResult struct {
	oauth.EndSessionResult
	DeleteCookie *http.Cookie `json:"-"`
}

func (EndSessionResult) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oidc.EndSessionResult(redacted)"))
}

// EndSession verifies the actual signed hint, delegates exact source-session
// admission/atomic invalidation to native core composition, and conserves original
// policy/deadline at delivery. RP-Initiated Logout §2 historical exp acceptance is
// selected ONLY with durable issued-hint/current original-source association;
// signature or subject equality alone never authorizes termination.
func (s *Service) EndSession(ctx context.Context, r EndSessionRequest) (out EndSessionResult, err error) {
	defer func() {
		if recover() != nil {
			out = EndSessionResult{}
			err = oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if s.config.EndSessionEndpoint == "" || s.core == nil || !s.core.EndSessionConfigured() {
		return out, oauth.ErrAccessDenied
	}
	in, err := s.endSessionHint(ctx, r.Parameters)
	if err != nil {
		return out, err
	}
	in.TenantID, in.Session, in.CSRF = r.TenantID, r.Session, r.CSRF
	in.Origin, in.Network = r.Origin, r.Network
	in.PostLogoutRedirectURI, in.State = r.Parameters.PostLogoutRedirectURI, r.Parameters.State
	result, err := s.core.EndSession(ctx, in)
	out.EndSessionResult = result
	if err != nil {
		return out, err
	}
	if result.Outcome == oauth.EndSessionUnknownReconciliation || result.Completion.Replayed {
		return out, nil
	}
	// A compromise/withdrawal may follow the first read or protected SQL wait.
	// Reverification cannot replace the first proof or renew ValidUntil.
	if _, err := s.config.Signing.VerifyCompact(ctx, r.Parameters.IDTokenHint); err != nil {
		return EndSessionResult{EndSessionResult: oauth.EndSessionResult{Completion: result.Completion}}, err
	}
	if ctx.Err() != nil {
		return EndSessionResult{EndSessionResult: oauth.EndSessionResult{Completion: result.Completion}}, ctx.Err()
	}
	if !s.config.Clock.Now().Before(result.ValidUntil) {
		return EndSessionResult{EndSessionResult: oauth.EndSessionResult{Completion: result.Completion}}, oauth.ErrAccessDenied
	}
	deletion, err := s.config.SessionCookie.DeletionAttributes()
	if err != nil {
		return EndSessionResult{EndSessionResult: oauth.EndSessionResult{Completion: result.Completion}}, oauth.ErrUnavailable
	}
	out.DeleteCookie = &deletion
	return out, nil
}

func (s *Service) endSessionHint(ctx context.Context, p EndSessionParameters) (oauth.EndSessionInput, error) {
	if validateEndSessionParameters(p) != nil {
		return oauth.EndSessionInput{}, oauth.ErrInvalidRequest
	}
	verified, err := s.config.Signing.VerifyCompact(ctx, p.IDTokenHint)
	if err != nil {
		return oauth.EndSessionInput{}, err
	}
	payload := verified.Payload()
	// The selected issuing child emits this closed minimized object. Duplicate
	// top-level names cannot silently change OIDC binding under JSON last-wins.
	d := json.NewDecoder(strings.NewReader(string(payload)))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return oauth.EndSessionInput{}, oauth.ErrAccessDenied
	}
	seen := make(map[string]bool, 9)
	for d.More() {
		name, err := d.Token()
		key, ok := name.(string)
		if err != nil || !ok || seen[key] {
			return oauth.EndSessionInput{}, oauth.ErrAccessDenied
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return oauth.EndSessionInput{}, oauth.ErrAccessDenied
		}
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') {
		return oauth.EndSessionInput{}, oauth.ErrAccessDenied
	}
	if _, err := d.Token(); err != io.EOF {
		return oauth.EndSessionInput{}, oauth.ErrAccessDenied
	}
	var claims idClaims
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&claims) != nil || claims.Issuer != s.config.Issuer.String() || claims.Subject == "" || !endSessionText(claims.Subject, 128) || claims.Audience == "" || claims.AuthorizedParty != claims.Audience || p.ClientID != "" && p.ClientID != claims.Audience || claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > 300 || claims.AuthTime <= 0 || claims.AuthTime > claims.IssuedAt || len(claims.Methods) != 1 || claims.Methods[0] != "pwd" || s.config.Clock.Now().Before(time.Unix(claims.IssuedAt, 0)) {
		return oauth.EndSessionInput{}, oauth.ErrAccessDenied
	}
	return oauth.EndSessionInput{Hint: verified, ClientID: claims.Audience, Subject: claims.Subject, IssuedAt: time.Unix(claims.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC()}, nil
}
