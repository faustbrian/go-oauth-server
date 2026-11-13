package oauthserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
	oauth "github.com/faustbrian/go-oauth-server"
)

// This trusted-reader seam tests opaque principal custody only. Actual token,
// organization/key/client authority and lineage come from the native consumer.
type organizationResourceReader func(context.Context, string) (oauth.OrganizationResourceAccessProjection, error)

func (f organizationResourceReader) ReadOrganizationResourceAccess(ctx context.Context, wire string) (oauth.OrganizationResourceAccessProjection, error) {
	return f(ctx, wire)
}

func TestOrganizationResourceVerifierRetainsTypedOwnerActorAndOriginalScope(t *testing.T) {
	now := time.Now().UTC()
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	scopes, _ := oauth.NewScopeCatalog([]string{"identity:read", "identity:write"})
	base := oauth.ResourceVerificationConfig{Issuer: issuer, Environment: "test", TenantID: "tenant", ClientID: "basic-client", ClientVersion: 1, Resource: "https://resource.example", Scopes: scopes, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second}
	config := oauth.OrganizationResourceVerificationConfig{Verification: base, OrganizationID: "organization"}
	owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: base.TenantID, Kind: apikey.OwnerOrganization, OrganizationID: config.OrganizationID, Version: 2})
	lineage := oauth.OrganizationResourceLineage{RootID: "org-key", RootVersion: 3, ParentID: "parent-access", ParentTokenType: oauth.AccessTokenType, ParentVersion: 1, TokenID: "current-access", Depth: 2}
	projection := oauth.OrganizationResourceAccessProjection{Issuer: issuer, Environment: base.Environment, Owner: owner, APIKeyActor: "org-key", TenantID: base.TenantID, ClientID: base.ClientID, ClientVersion: base.ClientVersion, Resource: base.Resource, Scopes: scopes.Scopes(), Kind: oauth.TokenAccess, Lineage: lineage, ReadStartedAt: now, ValidUntil: now.Add(3 * time.Second), TokenExpiresAt: now.Add(time.Minute), CredentialExpiresAt: now.Add(time.Hour)}
	calls := 0
	var failure error
	verifier, err := oauth.NewOrganizationResourceVerifier(config, organizationResourceReader(func(context.Context, string) (oauth.OrganizationResourceAccessProjection, error) {
		calls++
		return projection, failure
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.ResourceVerifyRequest{AccessToken: "borrowed-opaque-token", Scope: "identity:read"}
	principal, err := verifier.Verify(context.Background(), request)
	if err != nil || principal.Owner() != owner || principal.APIKeyActor() != "org-key" || principal.TenantID() != base.TenantID || principal.ClientID() != base.ClientID || principal.ClientVersion() != base.ClientVersion || principal.Resource() != base.Resource || principal.Lineage() != lineage || principal.ReadStartedAt() != projection.ReadStartedAt || principal.ValidUntil() != projection.ValidUntil || principal.RequireScope("identity:read") != nil {
		t.Fatal("organization verification lost separate typed owner/key/caller/lineage", err)
	}
	if principal.RequireScope("identity:write") == nil {
		t.Fatal("organization principal expanded beyond the verified scope")
	}
	copy := principal
	now = projection.ReadStartedAt.Add(-time.Millisecond)
	if !errors.Is(copy.RequireScope("identity:read"), oauth.ErrInvalidResourceToken) {
		t.Fatal("copied org principal admitted a clock before original read start")
	}
	now = projection.ValidUntil
	if !errors.Is(copy.RequireScope("identity:read"), oauth.ErrInvalidResourceToken) {
		t.Fatal("copied organization principal renewed original freshness")
	}
	failure = oauth.ErrUnavailable
	if out, err := verifier.Verify(context.Background(), request); !errors.Is(err, oauth.ErrUnavailable) || out.Owner() != (apikey.Owner{}) || out.RequireScope("identity:read") == nil || calls != 2 {
		t.Fatal("organization resource failure fell back to an old principal", err)
	}
	if (oauth.OrganizationResourcePrincipal{}).RequireScope("identity:read") == nil {
		t.Fatal("zero organization principal acquired resource authority")
	}
	if wire, err := json.Marshal(principal); err == nil || len(wire) != 0 {
		t.Fatal("organization principal became an exported bearer/authority assertion")
	}
}

func TestOrganizationResourceVerifierDeniesForeignOrRenewedAuthority(t *testing.T) {
	now := time.Now().UTC()
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	scopes, _ := oauth.NewScopeCatalog([]string{"identity:read"})
	base := oauth.ResourceVerificationConfig{Issuer: issuer, Environment: "test", TenantID: "tenant", ClientID: "basic-client", ClientVersion: 1, Resource: "https://resource.example", Scopes: scopes, Clock: clockFunc(func() time.Time { return now }), MaximumDuration: time.Second}
	config := oauth.OrganizationResourceVerificationConfig{Verification: base, OrganizationID: "organization"}
	owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: base.TenantID, Kind: apikey.OwnerOrganization, OrganizationID: config.OrganizationID, Version: 2})
	initial := oauth.OrganizationResourceAccessProjection{Issuer: issuer, Environment: base.Environment, Owner: owner, APIKeyActor: "org-key", TenantID: base.TenantID, ClientID: base.ClientID, ClientVersion: base.ClientVersion, Resource: base.Resource, Scopes: scopes.Scopes(), Kind: oauth.TokenAccess, Lineage: oauth.OrganizationResourceLineage{RootID: "org-key", RootVersion: 3, ParentID: "org-key", ParentTokenType: oauth.APIKeyTokenType, ParentVersion: 3, TokenID: "current-access", Depth: 1}, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second), TokenExpiresAt: now.Add(10 * time.Second), CredentialExpiresAt: now.Add(3 * time.Second)}
	projection := initial
	verifier, err := oauth.NewOrganizationResourceVerifier(config, organizationResourceReader(func(context.Context, string) (oauth.OrganizationResourceAccessProjection, error) {
		return projection, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.ResourceVerifyRequest{AccessToken: "borrowed-opaque-token", Scope: "identity:read"}
	principal, err := verifier.Verify(context.Background(), request)
	if err != nil || principal.ValidUntil() != initial.CredentialExpiresAt {
		t.Fatal("organization resource verification ignored earliest original expiry", err)
	}
	for _, mode := range []string{"USER-owner", "foreign-org", "foreign-tenant", "foreign-client", "foreign-version", "foreign-resource", "foreign-issuer", "foreign-environment", "non-key-actor", "missing-root", "missing-root-version", "missing-parent-version", "cycle", "wrong-parent-kind", "excess-depth", "refresh", "future-read", "renewed-deadline", "missing-scope"} {
		t.Run(mode, func(t *testing.T) {
			projection = initial
			switch mode {
			case "USER-owner":
				projection.Owner, _ = apikey.NewOwner(apikey.OwnerSpec{TenantID: base.TenantID, Kind: apikey.OwnerUser, UserID: "creator", Version: 2})
			case "foreign-org":
				projection.Owner, _ = apikey.NewOwner(apikey.OwnerSpec{TenantID: base.TenantID, Kind: apikey.OwnerOrganization, OrganizationID: "another-organization", Version: 2})
			case "foreign-tenant":
				projection.TenantID = "another-tenant"
			case "foreign-client":
				projection.ClientID = "another-client"
			case "foreign-version":
				projection.ClientVersion++
			case "foreign-resource":
				projection.Resource = "https://another-resource.example"
			case "foreign-issuer":
				projection.Issuer, _ = oauth.NewIssuer("https://another-issuer.example")
			case "foreign-environment":
				projection.Environment = "another-environment"
			case "non-key-actor":
				projection.APIKeyActor = "basic-client"
			case "missing-root":
				projection.Lineage.RootID = ""
			case "missing-root-version":
				projection.Lineage.RootVersion = 0
			case "missing-parent-version":
				projection.Lineage.ParentVersion = 0
			case "cycle":
				projection.Lineage.ParentID = projection.Lineage.TokenID
			case "wrong-parent-kind":
				projection.Lineage.ParentTokenType = oauth.AccessTokenType
			case "excess-depth":
				projection.Lineage.Depth = 5
			case "refresh":
				projection.Kind = oauth.TokenRefresh
			case "future-read":
				projection.ReadStartedAt = now.Add(time.Second)
			case "renewed-deadline":
				projection.ValidUntil = now.Add(21 * time.Second)
			case "missing-scope":
				projection.Scopes = []string{"identity:write"}
			}
			if out, err := verifier.Verify(context.Background(), request); err == nil || out.Owner() != (apikey.Owner{}) || out.RequireScope("identity:read") == nil {
				t.Fatal("foreign, non-key or renewed organization authority exposed a principal", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := verifier.Verify(ctx, request); !errors.Is(err, context.Canceled) || out.Owner() != (apikey.Owner{}) {
		t.Fatal("canceled organization read exposed principal", err)
	}
}
