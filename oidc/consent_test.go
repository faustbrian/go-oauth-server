package oidc

import (
	"context"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestConsentPromptPreservesAuthenticationAgeInsteadOfForcingLogin(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	s := isolatedClaimsService(Config{Issuer: issuer, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second})
	for _, mode := range []string{"current", "live-age", "zero-age", "expired-age"} {
		t.Run(mode, func(t *testing.T) {
			in := oauth.OIDCAuthorizationInput{Issuer: issuer, Request: oauth.AuthorizationRequest{Prompt: "consent", Scopes: []string{"openid"}}, Session: silentSession(t, now)}
			want := oauth.OIDCAuthenticationCurrent
			if mode != "current" {
				age := uint32(120)
				if mode == "zero-age" {
					age = 0
					want = oauth.OIDCAuthenticationFresh
				}
				if mode == "expired-age" {
					age = 60
					want = oauth.OIDCAuthenticationFresh
				}
				in.Request.MaxAge = &age
			}
			out, err := s.ValidateAuthorization(context.Background(), in)
			if err != nil || !out.Accepted || out.Authentication != want || mode == "live-age" && !out.AuthenticationUntil.Equal(now.Add(time.Minute)) {
				t.Fatal("consent changed original authentication requirement/deadline", err)
			}
		})
	}
}
