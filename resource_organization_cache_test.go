package oauthserver_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestOrganizationResourceCacheRetainsTypedDecisionAndOriginalDeadline(t *testing.T) {
	t.Parallel()
	started := time.Date(2026, time.November, 26, 12, 0, 0, 0, time.UTC)
	now := started
	base, _ := resourceCacheFixture(&now)
	base.Scopes, _ = oauth.NewScopeCatalog([]string{"identity:read", "identity:write"})
	config := oauth.OrganizationResourceVerificationConfig{Verification: base, OrganizationID: "organization"}
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: base.TenantID, Kind: apikey.OwnerOrganization, OrganizationID: config.OrganizationID, Version: 2})
	if err != nil {
		t.Fatal(err)
	}
	lineage := oauth.OrganizationResourceLineage{RootID: "org-key", RootVersion: 3, ParentID: "parent-access", ParentTokenType: oauth.AccessTokenType, ParentVersion: 1, TokenID: "current-access", Depth: 2}
	projection := oauth.OrganizationResourceAccessProjection{
		Issuer: base.Issuer, Environment: base.Environment, Owner: owner, APIKeyActor: "org-key",
		TenantID: base.TenantID, ClientID: base.ClientID, ClientVersion: base.ClientVersion,
		Resource: base.Resource, Scopes: base.Scopes.Scopes(), Kind: oauth.TokenAccess, Lineage: lineage,
		ReadStartedAt: started, ValidUntil: started.Add(18 * time.Second), TokenExpiresAt: started.Add(time.Minute),
		CredentialExpiresAt: started.Add(12 * time.Second),
	}
	reads := 0
	verifier, err := oauth.NewOrganizationResourceVerifier(config, organizationResourceReader(func(context.Context, string) (oauth.OrganizationResourceAccessProjection, error) {
		reads++
		if reads != 1 {
			return oauth.OrganizationResourceAccessProjection{}, oauth.ErrUnavailable
		}
		return projection, nil
	}))
	if err != nil {
		t.Fatal("valid explicit organization cache was not selected", err)
	}
	request := oauth.ResourceVerifyRequest{AccessToken: "borrowed-organization-access", Scope: "identity:read"}
	cold, err := verifier.Verify(t.Context(), request)
	if err != nil || cold.ValidUntil() != projection.CredentialExpiresAt || cold.RequireScope(request.Scope) != nil {
		t.Fatal("cold decision lost the earliest owner credential deadline", err)
	}
	now = started.Add(time.Second)
	warm, err := verifier.Verify(t.Context(), request)
	if err != nil || reads != 1 || warm.RequireScope(request.Scope) != nil || warm.Owner() != owner ||
		warm.APIKeyActor() != projection.APIKeyActor || warm.TenantID() != base.TenantID || warm.ClientID() != base.ClientID ||
		warm.ClientVersion() != base.ClientVersion || warm.Resource() != base.Resource || warm.Lineage() != lineage ||
		warm.ReadStartedAt() != cold.ReadStartedAt() || warm.ValidUntil() != cold.ValidUntil() {
		t.Fatal("warm decision changed original typed authority, deadline or accessed the reader", err, reads)
	}
	for _, other := range []oauth.ResourceVerifyRequest{
		{AccessToken: request.AccessToken, Scope: "identity:write"},
		{AccessToken: "unrelated-organization-access", Scope: request.Scope},
	} {
		if p, err := verifier.Verify(t.Context(), other); !errors.Is(err, oauth.ErrUnavailable) || p.Owner() != (apikey.Owner{}) {
			t.Fatal("cached decision crossed token or scope", err)
		}
	}
	now = cold.ValidUntil()
	if cold.RequireScope(request.Scope) == nil || warm.RequireScope(request.Scope) == nil {
		t.Fatal("a copied decision extended the original lifetime")
	}
	if p, err := verifier.Verify(t.Context(), request); !errors.Is(err, oauth.ErrUnavailable) || p.Owner() != (apikey.Owner{}) || reads != 4 {
		t.Fatal("expired decision failed to refresh and deny on outage", err, reads)
	}
	now = started.Add(2 * time.Second)
	if p, err := verifier.Verify(t.Context(), request); !errors.Is(err, oauth.ErrUnavailable) || p.Owner() != (apikey.Owner{}) || reads != 5 {
		t.Fatal("observed expiry was reversed after clock rollback", err, reads)
	}
}
