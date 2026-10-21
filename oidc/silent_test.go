package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

type silentSessionReader struct{ observation session.SessionObservation }

func (r silentSessionReader) ObserveSession(context.Context, session.SessionLookup) (session.SessionObservation, error) {
	return r.observation, nil
}

// This isolates the child policy seam using actual sealed Get custody. Genuine
// native sign-in, consent and no-interaction issuance are separate PG consumers.
func silentSession(t *testing.T, now time.Time) session.GetResult {
	t.Helper()
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	token, _ := session.NewToken(32)
	digest, _ := token.Digest(key, "tenant")
	remember, _ := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	bindings := session.AuthoritySnapshotSpec{Global: session.AuthorityBinding{ScopeKey: "global", Version: 1}, Tenant: session.AuthorityBinding{ScopeKey: "tenant", Version: 1}, User: session.AuthorityBinding{ScopeKey: "user", Version: 1}, Identifier: session.AuthorityBinding{ScopeKey: "identifier", Version: 1}, Credential: session.AuthorityBinding{ScopeKey: "credential", Version: 1}, SessionFamily: session.AuthorityBinding{ScopeKey: "family", Version: 1}, Session: session.AuthorityBinding{ScopeKey: "session", Version: 1}, Authorization: session.AuthorityBinding{ScopeKey: "authorization", Version: 1}}
	authority, err := session.NewAuthoritySnapshot(bindings)
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(session.SessionSpec{SessionID: "session", FamilyID: "family", TenantID: "tenant", UserID: "user", Audience: "identity-service", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, IssuedAt: now, LastActivityAt: now, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant", Subject: "user", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity-service", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	reader := silentSessionReader{session.SessionObservation{Session: record, Current: authority, Active: true, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second)}}
	service, err := session.NewSessionService(reader, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity-service", Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	out, err := service.Get(context.Background(), session.GetRequest{TenantID: "tenant", Credential: credential})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSilentPolicyRequiresCurrentAuthenticationWithoutInteraction(t *testing.T) {
	now := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	s := isolatedClaimsService(Config{Issuer: issuer, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second})
	for _, mode := range []string{"current", "live-age", "zero-age", "expired-age", "missing-session", "not-openid", "combination", "duplicate", "continuation"} {
		t.Run(mode, func(t *testing.T) {
			in := oauth.OIDCAuthorizationInput{Issuer: issuer, Request: oauth.AuthorizationRequest{Prompt: "none", Scopes: []string{"openid"}}, Session: silentSession(t, now)}
			switch mode {
			case "live-age", "expired-age", "zero-age":
				value := uint32(0)
				if mode == "live-age" {
					value = 120
				} else if mode == "expired-age" {
					value = 60
				}
				in.Request.MaxAge = &value
			case "missing-session":
				in.Session = session.GetResult{}
			case "not-openid":
				in.Request.Scopes = []string{"identity:read"}
			case "combination":
				in.Request.Prompt = "none login"
			case "duplicate":
				in.Request.Prompt = "none none"
			case "continuation":
				in.Reauthentication = &oauth.OIDCReauthenticationInput{OriginalSession: in.Session.Session, RequestedAt: now}
			}
			out, err := s.ValidateAuthorization(context.Background(), in)
			if mode == "current" || mode == "live-age" {
				if err != nil || !out.Accepted || out.Authentication != oauth.OIDCAuthenticationSilent || mode == "live-age" && !out.AuthenticationUntil.Equal(now.Add(time.Minute)) {
					t.Fatal("current authentication did not select silent bounded policy", err)
				}
			} else if mode == "zero-age" || mode == "expired-age" || mode == "missing-session" {
				if !errors.Is(err, oauth.ErrLoginRequired) || out.Accepted {
					t.Fatal("silent authentication requirement became interactive or admitted", err)
				}
			} else if err == nil || out.Accepted {
				t.Fatal("invalid silent context admitted")
			}
		})
	}
}
