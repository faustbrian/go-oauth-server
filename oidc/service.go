// Package oidc supplies the selected public-subject, ES256 authorization-code
// provider extension. Native OAuth, consent, session and transaction authority
// remain in their existing owners. This is not a complete OIDC provider profile.
package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"reflect"
	"slices"
	"strings"
	"time"

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
	config Config
	core   *oauth.Service
	scopes oauth.ScopeCatalog
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
	scopes, _ := oauth.NewOIDCScopeCatalog([]string{"openid"})
	return &Service{config: c, core: core, scopes: scopes}, nil
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

// Scopes returns only implemented scope ownership. Profile/email/address/phone
// claims, offline_access, pairwise subjects and every logout profile remain
// unselected, unadvertised and unavailable rather than approximated.
func (s *Service) Scopes() oauth.ScopeCatalog {
	if s == nil {
		return oauth.ScopeCatalog{}
	}
	return s.scopes
}

func selected(scopes []string) bool {
	if len(scopes) < 1 || len(scopes) > 16 || !slices.Contains(scopes, "openid") {
		return false
	}
	for _, scope := range scopes {
		switch scope {
		case "profile", "email", "address", "phone", "offline_access":
			return false
		}
	}
	return true
}

// ValidateAuthorization admits only the code/S256 request already selected by
// core and genuine session custody. It never creates a login or consent and
// does not reinterpret supplied unsupported prompt/max_age/claims parameters.
func (s *Service) ValidateAuthorization(ctx context.Context, in oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return oauth.OIDCAuthorizationProjection{}, err
	}
	defer stop()
	if !selected(in.Request.Scopes) || len(in.Request.Nonce) > 256 || in.Session.ValidateAt(s.config.Clock.Now()) != nil {
		return oauth.OIDCAuthorizationProjection{}, oauth.ErrAccessDenied
	}
	if err := ctx.Err(); err != nil {
		return oauth.OIDCAuthorizationProjection{}, err
	}
	return oauth.OIDCAuthorizationProjection{Accepted: true}, nil
}

func (s *Service) subject(in oauth.OIDCClaimsInput) string {
	mac := hmac.New(sha256.New, s.config.SubjectKey[:])
	_, _ = mac.Write([]byte("golib.oidc.public-subject.v1\x00"))
	for _, value := range []string{in.Issuer.String(), string(in.TenantID), string(in.UserID)} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = mac.Write(length[:])
		_, _ = mac.Write([]byte(value))
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
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
	if in.Issuer != s.config.Issuer || len(in.TenantID) < 1 || len(in.TenantID) > 128 || len(in.UserID) < 1 || len(in.UserID) > 128 || len(in.ClientID) < 1 || len(in.ClientID) > 128 || len(in.ExpectedSubject) > 128 || !selected(in.Scopes) || len(in.Nonce) > 256 || in.AuthenticatedAt.IsZero() || in.AuthenticatedAt.After(in.IssuedAt) || in.IssuedAt.After(now) || !now.Before(in.ExpiresAt) || in.ExpiresAt.After(in.IssuedAt.Add(5*time.Minute)) {
		return oauth.OIDCClaimsProjection{}, oauth.ErrAccessDenied
	}
	sub := s.subject(in)
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
		if url == s.config.JWKSURI || url == s.config.UserInfoEndpoint {
			return oauth.OIDCDiscoveryProjection{}, oauth.ErrInvalidRequest
		}
	}
	return oauth.OIDCDiscoveryProjection{JWKSURI: s.config.JWKSURI, UserInfoEndpoint: s.config.UserInfoEndpoint, SubjectTypesSupported: []string{"public"}, IDTokenSigningAlgValuesSupported: []string{"ES256"}, ClaimsSupported: []string{"iss", "sub", "aud", "azp", "iat", "exp", "nonce", "auth_time", "amr"}}, nil
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

// UserInfo is a minimized subject-only response. Expected subject equality is
// rechecked against the same grant/client artifact, never a caller ID token.
type UserInfo struct {
	Subject string `json:"sub"`
}

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
	return UserInfo{Subject: claims.Subject}, nil
}
