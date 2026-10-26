package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

func profileInput(now time.Time) oauth.OIDCClaimsInput {
	in := emailInput(now)
	in.Scopes = []string{"openid", "profile"}
	in.Identifiers = nil
	in.Profile = &identity.ProfileRecord{User: identity.User{ID: in.UserID, TenantID: in.TenantID, Status: identity.StatusActive, Version: 2}, Profile: identity.UserProfile{ID: in.UserID, TenantID: in.TenantID, Name: "Current display name", Version: 2}}
	return in
}

func TestProfileUserInfoSelectsOnlyCurrentName(t *testing.T) {
	now := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	in := profileInput(now)
	s := isolatedClaimsService(Config{Issuer: in.Issuer, SubjectKey: [32]byte{1}, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second, ProfileUserInfo: true})
	in.ExpectedSubject = s.subject(in)
	if out, err := s.Claims(context.Background(), in); err != nil || out.Subject != in.ExpectedSubject {
		t.Fatal("consented profile scope changed or denied native subject", err)
	}
	for _, name := range []string{"Current display name", "Updated display name", ""} {
		in.Profile.Profile.Name = name
		out, err := s.profileClaims(context.Background(), in)
		if err != nil || out.Name != name || out.Email != "" || out.PhoneNumber != "" {
			t.Fatal("profile did not preserve current optional name", err)
		}
		wire, err := json.Marshal(out)
		var claims map[string]json.RawMessage
		if err != nil || json.Unmarshal(wire, &claims) != nil || len(claims) != 1+boolInt(name != "") {
			t.Fatal("profile wire leaked unselected attributes")
		}
	}
	disabled := isolatedClaimsService(Config{Issuer: in.Issuer, SubjectKey: [32]byte{1}, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second})
	if disabled.selected(in.Scopes) {
		t.Fatal("default profile exposed a disabled scope")
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestProfileUserInfoRejectsMissingMixedOrStaleCustody(t *testing.T) {
	now := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	in := profileInput(now)
	s := isolatedClaimsService(Config{Issuer: in.Issuer, SubjectKey: [32]byte{1}, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second, ProfileUserInfo: true})
	for _, mode := range []string{"missing", "tenant", "user", "version", "zero-version", "inactive", "oversize", "utf8", "image", "custom", "expired", "missing-deadline", "unrequested", "no-scope"} {
		t.Run(mode, func(t *testing.T) {
			input := profileInput(now)
			switch mode {
			case "missing":
				input.Profile = nil
			case "tenant":
				input.Profile.Profile.TenantID = "foreign"
			case "user":
				input.Profile.Profile.ID = "foreign"
			case "version":
				input.Profile.Profile.Version++
			case "zero-version":
				input.Profile.User.Version, input.Profile.Profile.Version = 0, 0
			case "inactive":
				input.Profile.User.Status = identity.Status("disabled")
			case "oversize":
				input.Profile.Profile.Name = strings.Repeat("n", 257)
			case "utf8":
				input.Profile.Profile.Name = string([]byte{255})
			case "image":
				input.Profile.Profile.Image = "https://images.example/private.png"
			case "custom":
				input.Profile.Profile.AdditionalFields = []identity.AttributeUpdate{{Name: "private"}}
			case "expired":
				input.AuthorityExpiresAt = now
			case "missing-deadline":
				input.AuthorityExpiresAt = time.Time{}
			case "unrequested":
				input.UserInfo = false
			case "no-scope":
				input.Scopes = []string{"openid"}
			}
			out, err := s.profileClaims(context.Background(), input)
			if !errors.Is(err, oauth.ErrAccessDenied) || out != (UserInfo{}) {
				t.Fatal("invalid profile custody exposed partial claims", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := s.profileClaims(ctx, in); !errors.Is(err, context.Canceled) || out != (UserInfo{}) {
		t.Fatal("canceled profile returned claims", err)
	}
}

func TestProfileSelectionKeepsIDTokensMinimized(t *testing.T) {
	now := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	in := profileInput(now)
	clock := clockFunc(func() time.Time { return now })
	authority, err := oauth.NewSigningAuthority(clock, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = authority.AddKey("test", key); err != nil {
		t.Fatal(err)
	}
	if _, err = authority.PublicKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = authority.Activate("test"); err != nil {
		t.Fatal(err)
	}
	signer, err := oauth.NewSigningService(authority, acceptingReservation{})
	if err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		s, err := NewService(Config{Issuer: in.Issuer, JWKSURI: in.Issuer.String() + "/jwks", UserInfoEndpoint: in.Issuer.String() + "/userinfo", Signing: signer, SubjectKey: [32]byte{1}, Clock: clock, MaximumDuration: time.Second, ProfileUserInfo: enabled}, new(oauth.Service))
		if err != nil {
			t.Fatal(err)
		}
		if s.selected(in.Scopes) != enabled || s.Scopes().Contains("profile") != enabled || !s.selected([]string{"openid"}) || s.selected([]string{"openid", "address"}) {
			t.Fatal("profile selection changed unavailable variants")
		}
		if !enabled {
			continue
		}
		in.UserInfo = false
		out, err := s.Claims(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := out.IDToken.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		payload, err := base64.RawURLEncoding.DecodeString(strings.Split(wire, ".")[1])
		var claims map[string]json.RawMessage
		if err != nil || json.Unmarshal(payload, &claims) != nil {
			t.Fatal("invalid signed payload")
		}
		for name := range claims {
			if !slices.Contains([]string{"iss", "sub", "aud", "azp", "iat", "exp", "auth_time", "amr"}, name) {
				t.Fatal("profile expanded ID-token claims", name)
			}
		}
	}
}

// The core's explicit UserInfo storage port is the unit boundary here. Native
// account/session/consent authority is separately exercised by the PG consumer;
// this test detects public child composition losing or partially returning data.
type profileCompositionStore struct {
	oauth.Store
	input oauth.OIDCClaimsInput
}

func (s *profileCompositionStore) UserInfo(context.Context, oauth.UserInfoCommand) (oauth.OIDCClaimsInput, error) {
	return s.input, nil
}

func TestPublicUserInfoComposesSelectedClaimsAndDiscardsPartialFailure(t *testing.T) {
	now := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	in := profileInput(now)
	in.Scopes = []string{"openid", "profile", "email", "phone"}
	in.Identifiers = emailInput(now).Identifiers
	in.Identifiers.User = in.Profile.User
	phone := phoneInput(now)
	in.Identifiers.Identifiers = append(in.Identifiers.Identifiers, phone.Identifiers.Identifiers[1])
	in.Identifiers.Verifications = append(in.Identifiers.Verifications, phone.Identifiers.Verifications[1])
	clock := clockFunc(func() time.Time { return now })
	selected := Config{Issuer: in.Issuer, JWKSURI: in.Issuer.String() + "/jwks", UserInfoEndpoint: in.Issuer.String() + "/userinfo", SubjectKey: [32]byte{1}, Signing: new(oauth.SigningService), Clock: clock, MaximumDuration: time.Second, ProfileUserInfo: true, EmailUserInfo: true, PhoneUserInfo: true}
	in.ExpectedSubject = isolatedClaimsService(selected).subject(in)
	store := &profileCompositionStore{input: in}
	resource, _ := oauth.NewScopeCatalog([]string{"resource:read"})
	identityScopes, _ := oauth.NewOIDCScopeCatalog(in.Scopes)
	owner, _ := oauth.NewPlatformOwner("deployment")
	lookup, _ := session.NewDigestKey(1, make([]byte, 32))
	// UserInfo authenticates its access token via the selected Store, not a
	// browser session. This configured existing reader is never invoked here.
	sessions, err := session.NewSessionService(silentSessionReader{}, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity-service", Clock: clock, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}})
	if err != nil {
		t.Fatal(err)
	}
	core, err := oauth.NewService(oauth.Config{Issuer: in.Issuer, Environment: "test", Resource: "https://resource.example", Scopes: resource, OIDCScopes: identityScopes, Clients: []oauth.Client{{ID: in.ClientID, Owner: owner, Version: 1, Public: true, AuthenticationMethod: "none", Redirects: []string{"https://client.example/callback"}, Scopes: in.Scopes, Resource: "https://resource.example"}}, Clock: clock, MaximumDuration: time.Second, CodeTTL: time.Minute, ContinuationTTL: time.Minute, AccessTTL: time.Minute, RefreshTTL: time.Hour}, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewService(selected, core)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := oauth.NewToken()
	wire, _ := token.Reveal()
	request := oauth.UserInfoRequest{ClientID: in.ClientID, AccessToken: wire}
	out, err := s.UserInfo(context.Background(), request)
	if err != nil || out.Subject != in.ExpectedSubject || out.Name != in.Profile.Profile.Name || out.Email != "verified@example.test" || out.EmailVerified == nil || !*out.EmailVerified || out.PhoneNumber != "+358401234567" || out.PhoneNumberVerified == nil || !*out.PhoneNumberVerified {
		t.Fatal("public UserInfo lost selected claims during composition", err)
	}
	encoded, err := json.Marshal(out)
	var raw map[string]json.RawMessage
	if err != nil || json.Unmarshal(encoded, &raw) != nil || len(raw) != 6 {
		t.Fatal("public composed UserInfo wire claims differ")
	}
	store.input.Identifiers.Identifiers[2].CanonicalValue = "+0"
	if earlier, err := s.emailClaims(context.Background(), store.input); err != nil || earlier.Email == "" {
		t.Fatal("late-failure fixture invalidated an earlier projection", err)
	}
	if out, err := s.UserInfo(context.Background(), request); !errors.Is(err, oauth.ErrAccessDenied) || out != (UserInfo{}) {
		t.Fatal("later claim failure exposed partial subject/name/email", err)
	}
}
