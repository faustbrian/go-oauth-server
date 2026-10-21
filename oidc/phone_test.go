package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
)

func phoneInput(now time.Time) oauth.OIDCClaimsInput {
	in := emailInput(now)
	in.Scopes = []string{"openid", "phone"}
	in.Identifiers.Identifiers = []identity.Identifier{
		{ID: "phone-a", UserID: "user", Kind: identity.IdentifierPhone, CanonicalValue: "+12025550123", Version: 1},
		{ID: "phone-b", UserID: "user", Kind: identity.IdentifierPhone, CanonicalValue: "+358401234567", Verified: true, Version: 1},
	}
	in.Identifiers.Verifications = []identity.Verification{
		{IdentifierID: "phone-a", State: identity.VerificationPending, Version: 1},
		{IdentifierID: "phone-b", State: identity.VerificationVerified, VerifiedAt: now.Add(-time.Minute), Version: 1},
	}
	return in
}

func TestPhoneUserInfoSelectedClaims(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	in := phoneInput(now)
	s := isolatedClaimsService(Config{Issuer: in.Issuer, SubjectKey: [32]byte{1}, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second, PhoneUserInfo: true})
	in.ExpectedSubject = s.subject(in)
	if projection, err := s.Claims(context.Background(), in); err != nil || projection.Subject != in.ExpectedSubject {
		t.Fatal("explicit phone scope did not preserve native UserInfo subject", err)
	}
	for _, mode := range []string{"verified", "primary", "later-primary", "stable", "pending", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			input := phoneInput(now)
			want := "+358401234567"
			if mode == "primary" || mode == "later-primary" || mode == "stable" {
				input.Identifiers.Identifiers[0].Verified = true
				input.Identifiers.Identifiers[0].Primary = mode == "primary"
				input.Identifiers.Verifications[0].State = identity.VerificationVerified
				input.Identifiers.Verifications[0].VerifiedAt = now.Add(-time.Minute)
				want = "+12025550123"
				if mode == "later-primary" {
					input.Identifiers.Identifiers[1].Primary = true
					want = "+358401234567"
				}
			} else if mode == "pending" || mode == "revoked" {
				input.Identifiers.Identifiers[1].Verified = false
				input.Identifiers.Verifications[1].State = identity.VerificationRevoked
				if mode == "revoked" {
					input.Identifiers.Verifications[0].State = identity.VerificationRevoked
				}
				want = ""
			}
			info, err := s.phoneClaims(context.Background(), input)
			if err != nil || info.PhoneNumber != want || want != "" && (info.PhoneNumberVerified == nil || !*info.PhoneNumberVerified) || want == "" && info.PhoneNumberVerified != nil {
				t.Fatal("phone selection did not preserve verified owner custody", err)
			}
			wire, err := json.Marshal(info)
			var raw map[string]json.RawMessage
			if err != nil || json.Unmarshal(wire, &raw) != nil || want != "" && string(raw["phone_number_verified"]) != "true" || want == "" && len(raw) != 1 {
				t.Fatal("phone Boolean/omission wire contract changed")
			}
		})
	}
}

func TestPhoneUserInfoRejectsInvalidAuthorityWithoutPartialClaims(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	in := phoneInput(now)
	s := isolatedClaimsService(Config{Issuer: in.Issuer, Clock: clockFunc(func() time.Time { return now }), PhoneUserInfo: true})
	for _, mode := range []string{"missing", "tenant", "subject", "disabled-user", "verification", "order", "syntax", "duplicate", "duplicate-primary", "pending-primary", "expired", "zero-deadline", "id-token", "email-only", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			input := phoneInput(now)
			selected := *s
			switch mode {
			case "missing":
				input.Identifiers = nil
			case "tenant":
				input.Identifiers.User.TenantID = "foreign"
			case "subject":
				input.Identifiers.User.ID = "foreign"
			case "disabled-user":
				input.Identifiers.User.Status = identity.Status("disabled")
			case "verification":
				input.Identifiers.Verifications[1].State = identity.VerificationPending
			case "order":
				input.Identifiers.Identifiers[1].ID = "phone-a"
			case "syntax":
				input.Identifiers.Identifiers[1].CanonicalValue = "+358 401234567"
			case "duplicate":
				input.Identifiers.Identifiers[0].CanonicalValue = input.Identifiers.Identifiers[1].CanonicalValue
			case "duplicate-primary":
				input.Identifiers.Identifiers[0].Verified = true
				input.Identifiers.Identifiers[0].Primary = true
				input.Identifiers.Verifications[0].State = identity.VerificationVerified
				input.Identifiers.Verifications[0].VerifiedAt = now.Add(-time.Minute)
				input.Identifiers.Identifiers[1].Primary = true
			case "pending-primary":
				input.Identifiers.Identifiers[0].Verified = true
				input.Identifiers.Verifications[0].State = identity.VerificationVerified
				input.Identifiers.Verifications[0].VerifiedAt = now.Add(-time.Minute)
				// The owner forbids Primary on an unverified contact. Reject the
				// whole inconsistent snapshot, not a partial earlier selection.
				input.Identifiers.Identifiers[1].Primary = true
				input.Identifiers.Identifiers[1].Verified = false
				input.Identifiers.Verifications[1].State = identity.VerificationPending
				input.Identifiers.Verifications[1].VerifiedAt = time.Time{}
			case "expired":
				input.AuthorityExpiresAt = now
			case "zero-deadline":
				input.AuthorityExpiresAt = time.Time{}
			case "id-token":
				input.UserInfo = false
			case "email-only":
				input.Scopes = []string{"openid", "email"}
			case "disabled":
				selected.config.PhoneUserInfo = false
			}
			if out, err := selected.phoneClaims(context.Background(), input); !errors.Is(err, oauth.ErrAccessDenied) || out.PhoneNumber != "" || out.PhoneNumberVerified != nil {
				t.Fatal("invalid phone authority returned partial claims", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := s.phoneClaims(ctx, in); !errors.Is(err, context.Canceled) || out.PhoneNumber != "" {
		t.Fatal("canceled phone projection returned claims", err)
	}
	reads := 0
	s.config.Clock = clockFunc(func() time.Time {
		reads++
		if reads == 1 {
			return now
		}
		return in.AuthorityExpiresAt
	})
	if out, err := s.phoneClaims(context.Background(), in); !errors.Is(err, oauth.ErrAccessDenied) || out.PhoneNumber != "" {
		t.Fatal("late projection renewed original exclusive authority deadline", err)
	}
}

func TestPhoneScopeIsExplicitlySelectedWithoutChangingOtherProfiles(t *testing.T) {
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	for _, enabled := range []bool{false, true} {
		s, err := NewService(Config{Issuer: issuer, JWKSURI: issuer.String() + "/jwks", UserInfoEndpoint: issuer.String() + "/userinfo", SubjectKey: [32]byte{1}, Clock: clockFunc(time.Now), MaximumDuration: time.Second, Signing: new(oauth.SigningService), PhoneUserInfo: enabled}, new(oauth.Service))
		if err != nil {
			t.Fatal(err)
		}
		if s.selected([]string{"openid", "phone"}) != enabled || !s.selected([]string{"openid"}) || s.selected([]string{"openid", "email"}) {
			t.Fatal("phone opt-in changed another profile's scope authority")
		}
	}
}
