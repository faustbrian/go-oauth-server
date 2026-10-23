// Package oidc supplies selected public and registered pairwise
// subjects for the ES256 authorization-code extension. Native OAuth, consent,
// session and transaction authority remain in their existing owners. This is not
// a complete OIDC provider profile.
package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

// Config explicitly selects one origin-only issuer, native durable signer and
// stable dedicated nonzero 256-bit public-subject derivation key. Keep that key
// unchanged for this profile's lifetime: replacing it changes all RP subjects.
// It is not a session, token-digest or private signing key. Clock and Signing are
// borrowed concurrent-safe dependencies. No network or migration runs at startup.
type Config struct {
	Issuer                    oauth.Issuer
	JWKSURI, UserInfoEndpoint string
	Signing                   *oauth.SigningService
	SubjectKey                [32]byte
	Clock                     oauth.Clock
	MaximumDuration           time.Duration
	// SubjectPolicy optionally selects authenticated pairwise key custody.
	// Native durable activation/binding remains independently required.
	SubjectPolicy *SubjectPolicy
	// EmailUserInfo explicitly enables consented email/email_verified UserInfo
	// projection from native primary identifier custody. It never expands ID tokens.
	EmailUserInfo bool
	// PhoneUserInfo explicitly enables verified, consented phone UserInfo claims
	// from native primary custody. Pending/revoked numbers are omitted; ID tokens
	// retain their subject/authentication-only projection.
	PhoneUserInfo bool
	// EndSessionEndpoint explicitly selects native RP-initiated logout only
	// when core supplies its actual optional session-owner composition and the
	// signer supplies read-only verification. Empty leaves logout unavailable.
	EndSessionEndpoint string
	// SessionCookie is the initiating transport's existing owner policy. Only
	// fresh known committed logout may project its credential-free deletion.
	SessionCookie session.CookiePolicy
}

func (Config) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte("oidc.Config(redacted)")) }
func (Config) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }
func (Config) MarshalText() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

// Service implements core's exactly four-method extension and selected public
// read operations. The core is its existing public concrete Service, not a
// replacement opaque authority. Construction is staged: create core/native store
// with OIDCScopes declared, create child, then use core.WithOIDC(child) for OAuth
// authorization/token operations. The original core never admits OIDC issuance.
type Service struct {
	config        Config
	core          *oauth.Service
	scopes        oauth.ScopeCatalog
	publicSubject func([]string) string
}

// Format prevents recursive diagnostics from traversing subject-key custody.
func (*Service) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte("oidc.Service(redacted)")) }
func (*Service) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }
func (*Service) MarshalText() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

var _ oauth.OIDCExtension = (*Service)(nil)

func NewService(c Config, core *oauth.Service) (*Service, error) {
	if core == nil || c.Issuer.String() == "" || c.Signing == nil || c.SubjectKey == ([32]byte{}) || nilClock(c.Clock) || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second || !endpoint(c.Issuer, c.JWKSURI) || !endpoint(c.Issuer, c.UserInfoEndpoint) || c.JWKSURI == c.UserInfoEndpoint {
		return nil, oauth.ErrInvalidRequest
	}
	if c.EndSessionEndpoint != "" {
		_, cookieErr := c.SessionCookie.DeletionAttributes()
		if !endpoint(c.Issuer, c.EndSessionEndpoint) || c.EndSessionEndpoint == c.JWKSURI || c.EndSessionEndpoint == c.UserInfoEndpoint || cookieErr != nil || !c.Signing.VerificationConfigured() || !core.EndSessionConfigured() {
			return nil, oauth.ErrInvalidRequest
		}
	}
	if c.SubjectPolicy != nil {
		if _, present := c.SubjectPolicy.keys[c.SubjectPolicy.active]; !present || c.SubjectPolicy.issuer != c.Issuer {
			return nil, oauth.ErrInvalidRequest
		}
	}
	names := []string{"openid"}
	if c.EmailUserInfo {
		names = append(names, "email")
	}
	if c.PhoneUserInfo {
		names = append(names, "phone")
	}
	scopes, _ := oauth.NewOIDCScopeCatalog(names)
	publicSubject, _ := opaqueHMAC(c.SubjectKey, "golib.oidc.public-subject.v1\x00")
	clear(c.SubjectKey[:])
	return &Service{config: c, core: core, scopes: scopes, publicSubject: publicSubject}, nil
}

func nilClock(clock oauth.Clock) bool {
	if clock == nil {
		return true
	}
	v := reflect.ValueOf(clock)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func endpoint(issuer oauth.Issuer, value string) bool {
	if len(value) > 2048 || strings.ContainsAny(value, "\\#?%*") || value == issuer.String()+"/.well-known/openid-configuration" || value == issuer.String()+"/.well-known/oauth-authorization-server" {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && u.Scheme+"://"+u.Host == issuer.String() && u.User == nil && u.Opaque == "" && u.Path != "" && u.Path != "/" && path.Clean(u.Path) == u.Path && u.String() == value
}
func (s *Service) bounded(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if s == nil || ctx == nil {
		return nil, nil, oauth.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	c, stop := context.WithTimeout(ctx, s.config.MaximumDuration)
	return c, stop, nil
}

// Scopes returns only implemented scope ownership. Profile/address
// claims and offline_access remain unselected. Front/back-channel logout is
// unavailable; native RP logout requires its separate explicit composition.
func (s *Service) Scopes() oauth.ScopeCatalog {
	if s == nil {
		return oauth.ScopeCatalog{}
	}
	return s.scopes
}

func (s *Service) selected(scopes []string) bool {
	if len(scopes) < 1 || len(scopes) > 16 || !slices.Contains(scopes, "openid") {
		return false
	}
	for _, scope := range scopes {
		switch scope {
		case "email":
			if !s.config.EmailUserInfo {
				return false
			}
		case "phone":
			if !s.config.PhoneUserInfo {
				return false
			}
		case "profile", "address", "offline_access":
			return false
		}
	}
	return true
}

// ValidateAuthorization admits only the code/S256 request already selected by
// core and genuine session custody. It projects selected login/none/consent and
// max_age policy, but never creates authentication, consent or a continuation.
// Unselected prompt variants and identity-claim scopes are unavailable.
func (s *Service) ValidateAuthorization(ctx context.Context, in oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return oauth.OIDCAuthorizationProjection{}, err
	}
	defer stop()
	if !s.selected(in.Request.Scopes) || len(in.Request.Nonce) > 256 {
		return oauth.OIDCAuthorizationProjection{}, oauth.ErrAccessDenied
	}
	if in.Request.Prompt == "none" && in.Reauthentication != nil {
		return oauth.OIDCAuthorizationProjection{}, oauth.ErrInvalidRequest
	}
	if in.Session.ValidateAt(s.config.Clock.Now()) != nil {
		if in.Request.Prompt == "none" {
			return oauth.OIDCAuthorizationProjection{}, oauth.ErrLoginRequired
		}
		return oauth.OIDCAuthorizationProjection{}, oauth.ErrAccessDenied
	}
	if err := ctx.Err(); err != nil {
		return oauth.OIDCAuthorizationProjection{}, err
	}
	out := oauth.OIDCAuthorizationProjection{Accepted: true}
	if in.Request.Prompt != "" || in.Request.MaxAge != nil {
		if in.Request.Prompt != "" && in.Request.Prompt != "login" && in.Request.Prompt != "none" && in.Request.Prompt != "consent" {
			return oauth.OIDCAuthorizationProjection{}, oauth.ErrInvalidRequest
		}
		bindings, err := in.Session.Session.Bindings()
		if err != nil || bindings.Authentication.Proof.IssuedAt.After(s.config.Clock.Now()) {
			return oauth.OIDCAuthorizationProjection{}, oauth.ErrAccessDenied
		}
		out.Authentication = oauth.OIDCAuthenticationCurrent
		// Core3.1.2.1: max_age=0 is equivalent to prompt=login. A new
		// issuance/refresh of the same authentication is not reauthentication.
		if in.Request.Prompt == "login" || in.Request.MaxAge != nil && *in.Request.MaxAge == 0 {
			fresh := false
			if original := in.Reauthentication; original != nil {
				before, err := original.OriginalSession.Bindings()
				fresh = err == nil && before.UserID == bindings.UserID && before.TenantID == bindings.TenantID && before.SessionID != bindings.SessionID && before.Authentication.Proof.ID != bindings.Authentication.Proof.ID && !original.RequestedAt.IsZero() && bindings.Authentication.Proof.IssuedAt.After(original.RequestedAt)
			}
			if !fresh {
				out.Authentication = oauth.OIDCAuthenticationFresh
			}
		}
		if in.Request.MaxAge != nil && *in.Request.MaxAge > 0 {
			until := bindings.Authentication.Proof.IssuedAt.Add(time.Duration(*in.Request.MaxAge) * time.Second)
			if !s.config.Clock.Now().Before(until) {
				out.Authentication = oauth.OIDCAuthenticationFresh
			} else if out.Authentication == oauth.OIDCAuthenticationCurrent {
				out.AuthenticationUntil = until
			}
		}
		if in.Request.Prompt == "none" {
			// OIDC Core1.0 errata2 §§3.1.2.1/3.1.2.3 forbids interactive
			// reauthentication for none, including unmet max_age. Native OAuth
			// still independently admits exact pre-existing bounded consent.
			if out.Authentication == oauth.OIDCAuthenticationFresh {
				return oauth.OIDCAuthorizationProjection{}, oauth.ErrLoginRequired
			}
			out.Authentication = oauth.OIDCAuthenticationSilent
		}
	}
	if in.Client.SubjectRegistration != nil {
		client, err := oauth.ValidateClient(in.Client)
		registration := in.Client.SubjectRegistration
		if err != nil || client.ID != in.Request.ClientID || in.Issuer != s.config.Issuer || !s.config.SubjectPolicy.matches(registration, in.Environment) {
			return oauth.OIDCAuthorizationProjection{}, oauth.ErrAccessDenied
		}
		if registration.SubjectType() == "pairwise" {
			bindings, err := in.Session.Session.Bindings()
			if err != nil {
				return oauth.OIDCAuthorizationProjection{}, oauth.ErrAccessDenied
			}
			policy := s.config.SubjectPolicy
			key := policy.keys[policy.active]
			sub := policy.derive(string(bindings.TenantID), string(bindings.UserID), registration.SectorHost())
			out.SubjectCandidate = &oauth.OIDCSubjectCandidate{Registration: *registration, Subject: sub, KeyVersion: policy.active, KeyCommitment: key.registration.Commitment}
		}
	}
	return out, nil
}

func (s *Service) subject(in oauth.OIDCClaimsInput) string {
	if s.publicSubject == nil {
		return ""
	}
	return s.publicSubject([]string{in.Issuer.String(), string(in.TenantID), string(in.UserID)})
}

type idClaims struct {
	Issuer          string   `json:"iss"`
	Subject         string   `json:"sub"`
	Audience        string   `json:"aud"`
	AuthorizedParty string   `json:"azp"`
	IssuedAt        int64    `json:"iat"`
	ExpiresAt       int64    `json:"exp"`
	Nonce           string   `json:"nonce,omitempty"`
	AuthTime        int64    `json:"auth_time"`
	Methods         []string `json:"amr"`
}

// Claims consumes only core's typed authenticated native grant result. It does
// not parse token forms, select grants, authenticate clients or issue sessions.
// The closed ID-token object contains no unrequested user attributes. Code flow
// returns ID tokens only at the token endpoint, so at_hash/c_hash are not required
// by OIDC Core 3.1.3.6; implicit/hybrid are not implemented or advertised.
func (s *Service) Claims(ctx context.Context, in oauth.OIDCClaimsInput) (oauth.OIDCClaimsProjection, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return oauth.OIDCClaimsProjection{}, err
	}
	defer stop()
	now := s.config.Clock.Now()
	if in.Issuer != s.config.Issuer || len(in.TenantID) < 1 || len(in.TenantID) > 128 || len(in.UserID) < 1 || len(in.UserID) > 128 || len(in.ClientID) < 1 || len(in.ClientID) > 128 || len(in.ExpectedSubject) > 128 || !s.selected(in.Scopes) || len(in.Nonce) > 256 || in.AuthenticatedAt.IsZero() || in.AuthenticatedAt.After(in.IssuedAt) || in.IssuedAt.After(now) || !now.Before(in.ExpiresAt) || in.ExpiresAt.After(in.IssuedAt.Add(5*time.Minute)) {
		return oauth.OIDCClaimsProjection{}, oauth.ErrAccessDenied
	}
	if in.UserInfo && !in.AuthorityExpiresAt.IsZero() && !now.Before(in.AuthorityExpiresAt) {
		return oauth.OIDCClaimsProjection{}, oauth.ErrAccessDenied
	}
	sub, err := s.claimSubject(in)
	if err != nil {
		return oauth.OIDCClaimsProjection{}, err
	}
	if in.UserInfo {
		if subtle.ConstantTimeCompare([]byte(sub), []byte(in.ExpectedSubject)) != 1 {
			return oauth.OIDCClaimsProjection{}, oauth.ErrAccessDenied
		}
		return oauth.OIDCClaimsProjection{Subject: sub}, nil
	}
	if in.ExpectedSubject != "" {
		return oauth.OIDCClaimsProjection{}, oauth.ErrAccessDenied
	}
	// This profile emits whole-second NumericDates (OIDC Core 2). Flooring a
	// short remaining native lifetime must not deliver an already expired JWT;
	// rounding up would instead exceed the authoritative grant ceiling.
	if !now.Before(time.Unix(in.ExpiresAt.Unix(), 0)) {
		return oauth.OIDCClaimsProjection{}, oauth.ErrAccessDenied
	}
	payload, err := json.Marshal(idClaims{Issuer: in.Issuer.String(), Subject: sub, Audience: in.ClientID, AuthorizedParty: in.ClientID, IssuedAt: in.IssuedAt.Unix(), ExpiresAt: in.ExpiresAt.Unix(), Nonce: in.Nonce, AuthTime: in.AuthenticatedAt.Unix(), Methods: []string{"pwd"}})
	if err != nil {
		return oauth.OIDCClaimsProjection{}, oauth.ErrUnavailable
	}
	token, kid, err := s.config.Signing.SignCompact(ctx, payload, in.ExpiresAt)
	if err != nil {
		return oauth.OIDCClaimsProjection{}, err
	}
	return oauth.OIDCClaimsProjection{Subject: sub, SigningKeyID: kid, IDToken: token}, nil
}

// OIDCDiscovery contributes only actually implemented selected metadata; issuer,
// OAuth endpoint/PKCE/client capabilities remain sourced from the same core.
func (s *Service) OIDCDiscovery(ctx context.Context) (oauth.OIDCDiscoveryProjection, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return oauth.OIDCDiscoveryProjection{}, err
	}
	defer stop()
	core, err := s.core.DiscoveryOauth(ctx, oauth.DiscoveryOauthRequest{})
	if err != nil || core.Metadata.Issuer != s.config.Issuer.String() || !slices.Contains(core.Metadata.ResponseTypesSupported, "code") {
		return oauth.OIDCDiscoveryProjection{}, oauth.ErrAccessDenied
	}
	for _, url := range []string{core.Metadata.AuthorizationEndpoint, core.Metadata.TokenEndpoint, core.Metadata.RevocationEndpoint, core.Metadata.IntrospectionEndpoint} {
		if url == s.config.JWKSURI || url == s.config.UserInfoEndpoint || s.config.EndSessionEndpoint != "" && url == s.config.EndSessionEndpoint {
			return oauth.OIDCDiscoveryProjection{}, oauth.ErrInvalidRequest
		}
	}
	subjectTypes := []string{"public"}
	if s.config.SubjectPolicy != nil {
		subjectTypes = append(subjectTypes, "pairwise")
	}
	claims := []string{"iss", "sub", "aud", "azp", "iat", "exp", "nonce", "auth_time", "amr"}
	if s.config.EmailUserInfo {
		claims = append(claims, "email", "email_verified")
	}
	if s.config.PhoneUserInfo {
		claims = append(claims, "phone_number", "phone_number_verified")
	}
	return oauth.OIDCDiscoveryProjection{JWKSURI: s.config.JWKSURI, UserInfoEndpoint: s.config.UserInfoEndpoint, EndSessionEndpoint: s.config.EndSessionEndpoint, SubjectTypesSupported: subjectTypes, IDTokenSigningAlgValuesSupported: []string{"ES256"}, ClaimsSupported: claims}, nil
}

type Discovery struct {
	oauth.DiscoveryOauthMetadata
	oauth.OIDCDiscoveryProjection
}

func (s *Service) Discovery(ctx context.Context) (Discovery, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return Discovery{}, err
	}
	defer stop()
	projection, err := s.OIDCDiscovery(ctx)
	if err != nil {
		return Discovery{}, err
	}
	core, err := s.core.DiscoveryOauth(ctx, oauth.DiscoveryOauthRequest{})
	if err != nil {
		return Discovery{}, err
	}
	for _, scope := range s.Scopes().Scopes() {
		if !slices.Contains(core.Metadata.ScopesSupported, scope) {
			core.Metadata.ScopesSupported = append(core.Metadata.ScopesSupported, scope)
		}
	}
	slices.Sort(core.Metadata.ScopesSupported)
	return Discovery{core.Metadata, projection}, nil
}

type JWKS struct {
	Keys []oauth.PublicSigningKey `json:"keys"`
}

func (s *Service) JWKS(ctx context.Context) (JWKS, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return JWKS{}, err
	}
	defer stop()
	keys, err := s.config.Signing.PublicKeys(ctx)
	if err != nil {
		return JWKS{}, err
	}
	return JWKS{Keys: keys}, nil
}

// UserInfo contains the grant subject and only explicitly selected consented
// claims. EmailVerified is nil when email is omitted and non-nil for actual
// pending(false)/verified(true) custody. JSON is intentional RP disclosure;
// diagnostics redact. No field is an authentication credential or identity key.
// PhoneNumberVerified is present and true only with a native verified canonical
// number; this conservative profile omits pending/revoked phone contacts.
type UserInfo struct {
	Subject             string `json:"sub"`
	Email               string `json:"email,omitempty"`
	EmailVerified       *bool  `json:"email_verified,omitempty"`
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool  `json:"phone_number_verified,omitempty"`
}

func (UserInfo) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("oidc.UserInfo(redacted)")) }

func (s *Service) UserInfo(ctx context.Context, request oauth.UserInfoRequest) (UserInfo, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return UserInfo{}, err
	}
	defer stop()
	source, err := s.core.UserInfoSource(ctx, request)
	if err != nil {
		return UserInfo{}, err
	}
	claims, err := s.Claims(ctx, source)
	if err != nil {
		return UserInfo{}, err
	}
	info := UserInfo{Subject: claims.Subject}
	if slices.Contains(source.Scopes, "email") {
		info, err = s.emailClaims(ctx, source)
		if err != nil {
			return UserInfo{}, err
		}
		info.Subject = claims.Subject
	}
	if slices.Contains(source.Scopes, "phone") {
		phone, err := s.phoneClaims(ctx, source)
		if err != nil {
			return UserInfo{}, err
		}
		info.PhoneNumber, info.PhoneNumberVerified = phone.PhoneNumber, phone.PhoneNumberVerified
	}
	if err := ctx.Err(); err != nil {
		return UserInfo{}, err
	}
	if !s.config.Clock.Now().Before(source.ExpiresAt) || !source.AuthorityExpiresAt.IsZero() && !s.config.Clock.Now().Before(source.AuthorityExpiresAt) {
		return UserInfo{}, oauth.ErrAccessDenied
	}
	return info, nil
}
