package oauthserver_test

import (
	"context"
	"errors"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

// This trusted projection seam proves core custody/error handling only; genuine
// native consumers separately prove token and current primary authority reads.
type resourceReader func(context.Context, string) (oauth.ResourceAccessProjection, error)

func (f resourceReader) ReadResourceAccess(ctx context.Context, token string) (oauth.ResourceAccessProjection, error) {
	return f(ctx, token)
}

func TestResourceVerifierReturnsOnlyScopeBoundUnrenewablePrincipal(t *testing.T) {
	now := time.Now().UTC()
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	scopes, _ := oauth.NewScopeCatalog([]string{"identity:read", "identity:write"})
	c := oauth.ResourceVerificationConfig{Issuer: issuer, Environment: "test", TenantID: "tenant", ClientID: "client", ClientVersion: 1, Resource: "https://resource.example", Scopes: scopes, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second}
	projection := oauth.ResourceAccessProjection{Issuer: issuer, Environment: "test", TenantID: "tenant", UserID: "user", ClientID: "client", ClientVersion: 1, Resource: c.Resource, Kind: oauth.TokenAccess, Scopes: scopes.Scopes(), ReadStartedAt: now, ValidUntil: now.Add(3 * time.Second), TokenExpiresAt: now.Add(time.Minute)}
	v, err := oauth.NewResourceVerifier(c, resourceReader(func(context.Context, string) (oauth.ResourceAccessProjection, error) { return projection, nil }))
	if err != nil {
		t.Fatal(err)
	}
	p, err := v.Verify(context.Background(), oauth.ResourceVerifyRequest{AccessToken: "borrowed-token", Scope: "identity:read"})
	if err != nil || p.Subject() != "user" || p.TenantID() != "tenant" || p.Resource() != c.Resource || p.ValidUntil() != projection.ValidUntil || p.RequireScope("identity:read") != nil {
		t.Fatal("valid access did not produce bounded selected read authority", err)
	}
	if p.RequireScope("identity:write") == nil {
		t.Fatal("principal expanded beyond demanded scope")
	}
	copy := p
	now = projection.ReadStartedAt.Add(-time.Millisecond)
	if !errors.Is(copy.RequireScope("identity:read"), oauth.ErrInvalidResourceToken) {
		t.Fatal("captured clock moved before original evidence start")
	}
	now = projection.ValidUntil
	if !errors.Is(copy.RequireScope("identity:read"), oauth.ErrInvalidResourceToken) {
		t.Fatal("copied principal renewed original validity")
	}
	if (oauth.ResourcePrincipal{}).RequireScope("identity:read") == nil {
		t.Fatal("zero principal admitted")
	}
}

func TestResourceVerifierDeniesForeignProjectionFailureAndNeverCaches(t *testing.T) {
	now := time.Now().UTC()
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	scopes, _ := oauth.NewScopeCatalog([]string{"identity:read", "identity:write"})
	c := oauth.ResourceVerificationConfig{Issuer: issuer, Environment: "test", TenantID: "tenant", ClientID: "client", ClientVersion: 1, Resource: "https://resource.example", Scopes: scopes, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second}
	original := oauth.ResourceAccessProjection{Issuer: issuer, Environment: "test", TenantID: "tenant", UserID: "user", ClientID: "client", ClientVersion: 1, Resource: c.Resource, Kind: oauth.TokenAccess, Scopes: []string{"identity:read"}, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second), TokenExpiresAt: now.Add(10 * time.Second), CredentialExpiresAt: now.Add(3 * time.Second)}
	projection, failure := original, error(nil)
	v, err := oauth.NewResourceVerifier(c, resourceReader(func(context.Context, string) (oauth.ResourceAccessProjection, error) { return projection, failure }))
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.ResourceVerifyRequest{AccessToken: "borrowed-token", Scope: "identity:read"}
	p, err := v.Verify(context.Background(), request)
	if err != nil || p.ValidUntil() != original.CredentialExpiresAt {
		t.Fatal("earliest original expiry was not conserved", err)
	}
	for _, mode := range []string{"refresh", "tenant", "client", "version", "resource", "issuer", "environment", "future-read", "renewed-deadline", "missing-scope", "failure"} {
		projection, failure = original, nil
		switch mode {
		case "refresh":
			projection.Kind = oauth.TokenRefresh
		case "tenant":
			projection.TenantID = "foreign"
		case "client":
			projection.ClientID = "foreign"
		case "version":
			projection.ClientVersion++
		case "resource":
			projection.Resource = "https://foreign.example"
		case "issuer":
			projection.Issuer, _ = oauth.NewIssuer("https://foreign.example")
		case "environment":
			projection.Environment = "foreign"
		case "future-read":
			projection.ReadStartedAt = now.Add(time.Second)
		case "renewed-deadline":
			projection.ValidUntil = now.Add(21 * time.Second)
		case "missing-scope":
			projection.Scopes = []string{"identity:write"}
		case "failure":
			failure = errors.New("reader failure")
		}
		if bad, err := v.Verify(context.Background(), request); err == nil || bad.Subject() != "" || bad.RequireScope("identity:read") == nil {
			t.Fatal("invalid or failed read exposed principal", mode)
		}
	}
	projection, failure = original, oauth.ErrUnavailable
	now = original.CredentialExpiresAt
	if bad, err := v.Verify(context.Background(), request); !errors.Is(err, oauth.ErrUnavailable) || bad.Subject() != "" {
		t.Fatal("failed fresh read fell back to cached authority", err)
	}
	if p.RequireScope("identity:read") == nil {
		t.Fatal("failed refresh renewed existing principal")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if bad, err := v.Verify(ctx, request); !errors.Is(err, context.Canceled) || bad.Subject() != "" {
		t.Fatal("cancellation returned principal", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	late, err := oauth.NewResourceVerifier(c, resourceReader(func(context.Context, string) (oauth.ResourceAccessProjection, error) { cancel(); return original, nil }))
	if err != nil {
		t.Fatal(err)
	}
	if bad, err := late.Verify(ctx, request); !errors.Is(err, context.Canceled) || bad.Subject() != "" {
		t.Fatal("late cancellation exposed otherwise positive projection", err)
	}
}
