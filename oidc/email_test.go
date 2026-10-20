package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
)

func emailInput(now time.Time) oauth.OIDCClaimsInput {
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	state := identity.IdentifierState{User: identity.User{ID: "user", TenantID: "tenant", Status: identity.StatusActive, Version: 1}, AuthorityVersion: 1,
		Identifiers:   []identity.Identifier{{ID: "email-a", UserID: "user", Kind: identity.IdentifierEmail, CanonicalValue: "pending@example.test", Version: 1}, {ID: "email-b", UserID: "user", Kind: identity.IdentifierEmail, CanonicalValue: "verified@example.test", Verified: true, Version: 1}},
		Verifications: []identity.Verification{{IdentifierID: "email-a", State: identity.VerificationPending, Version: 1}, {IdentifierID: "email-b", State: identity.VerificationVerified, VerifiedAt: now.Add(-time.Minute), Version: 1}}}
	return oauth.OIDCClaimsInput{Issuer: issuer, TenantID: "tenant", UserID: "user", ClientID: "client", Scopes: []string{"openid", "email"}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), AuthenticatedAt: now.Add(-time.Minute), UserInfo: true, Identifiers: &state, AuthorityExpiresAt: now.Add(20 * time.Second)}
}

func TestEmailUserInfoSelectedClaimsPreserveSubjectAndActualVerification(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	in := emailInput(now)
	s := isolatedClaimsService(Config{Issuer: in.Issuer, SubjectKey: [32]byte{1}, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second, EmailUserInfo: true})
	in.ExpectedSubject = s.subject(in)
	projection, err := s.Claims(context.Background(), in)
	if err != nil || projection.Subject != in.ExpectedSubject {
		t.Fatal("explicit consented email scope did not preserve UserInfo subject", err)
	}
	if fmt.Sprintf("%#v", UserInfo{Email: "private@example.test"}) != "oidc.UserInfo(redacted)" {
		t.Fatal("email UserInfo diagnostics exposed private claims")
	}
	expired := in
	expired.AuthorityExpiresAt = now
	if out, err := s.Claims(context.Background(), expired); !errors.Is(err, oauth.ErrAccessDenied) || out.Subject != "" {
		t.Fatal("copied native claims renewed original authority deadline", err)
	}
	// Selection is independent of slice iteration luck: verified email outranks
	// an earlier pending record, and primary outranks other verified records.
	for _, mode := range []string{"verified", "primary", "pending", "absent"} {
		t.Run(mode, func(t *testing.T) {
			input := emailInput(now)
			want, verified := "verified@example.test", true
			if mode == "primary" {
				input.Identifiers.Identifiers[0].Verified, input.Identifiers.Identifiers[0].Primary = true, true
				input.Identifiers.Verifications[0].State, input.Identifiers.Verifications[0].VerifiedAt = identity.VerificationVerified, now.Add(-time.Minute)
				want = "pending@example.test"
			} else if mode == "pending" || mode == "absent" {
				input.Identifiers.Identifiers[1].Verified = false
				input.Identifiers.Verifications[1].State = identity.VerificationRevoked
				want, verified = "pending@example.test", false
				if mode == "absent" {
					input.Identifiers.Verifications[0].State = identity.VerificationRevoked
					want = ""
				}
			}
			claims, err := s.emailClaims(context.Background(), input)
			if err != nil || claims.Email != want || want != "" && (claims.EmailVerified == nil || *claims.EmailVerified != verified) || want == "" && claims.EmailVerified != nil {
				t.Fatal("email did not reflect authoritative selected identifier", err)
			}
			wire, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			var response map[string]json.RawMessage
			if json.Unmarshal(wire, &response) != nil || mode == "pending" && string(response["email_verified"]) != "false" || mode == "absent" && len(response) != 1 {
				t.Fatal("omission or false verification wire semantics changed")
			}
		})
	}
}

func TestEmailUserInfoRejectsUnboundStaleOrInconsistentCustody(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	in := emailInput(now)
	s := isolatedClaimsService(Config{Issuer: in.Issuer, SubjectKey: [32]byte{1}, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second, EmailUserInfo: true})
	for _, mode := range []string{"missing", "tenant", "user", "inactive", "verification", "duplicate-primary", "order", "email-syntax", "expired", "missing-deadline", "unrequested", "no-scope"} {
		t.Run(mode, func(t *testing.T) {
			input := emailInput(now)
			switch mode {
			case "missing":
				input.Identifiers = nil
			case "tenant":
				input.Identifiers.User.TenantID = "foreign"
			case "user":
				input.Identifiers.User.ID = "foreign"
			case "inactive":
				input.Identifiers.User.Status = identity.Status("disabled")
			case "verification":
				input.Identifiers.Verifications[1].State = identity.VerificationPending
			case "duplicate-primary":
				input.Identifiers.Identifiers[0].Primary, input.Identifiers.Identifiers[0].Verified = true, true
				input.Identifiers.Verifications[0].State, input.Identifiers.Verifications[0].VerifiedAt = identity.VerificationVerified, now.Add(-time.Minute)
				input.Identifiers.Identifiers[1].Primary = true
			case "order":
				input.Identifiers.Identifiers[1].ID = "email-a"
			case "email-syntax":
				input.Identifiers.Identifiers[1].CanonicalValue = "Name <verified@example.test>"
			case "expired":
				input.AuthorityExpiresAt = now
			case "missing-deadline":
				input.AuthorityExpiresAt = time.Time{}
			case "unrequested":
				input.UserInfo = false
			case "no-scope":
				input.Scopes = []string{"openid"}
			}
			out, err := s.emailClaims(context.Background(), input)
			if !errors.Is(err, oauth.ErrAccessDenied) || out.Email != "" || out.EmailVerified != nil {
				t.Fatal("invalid email custody returned partial claims", err)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := s.emailClaims(canceled, in); !errors.Is(err, context.Canceled) || out.Email != "" {
		t.Fatal("canceled email read returned claims", err)
	}
}
