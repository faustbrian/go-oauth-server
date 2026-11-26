//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

func requireInvalidOrganizationResource(t *testing.T, verifier *oauth.OrganizationResourceVerifier, ctx context.Context, token string) {
	t.Helper()
	principal, err := verifier.Verify(ctx, oauth.ResourceVerifyRequest{AccessToken: token, Scope: "identity:read"})
	if !errors.Is(err, oauth.ErrInvalidResourceToken) || principal.Owner() != (apikey.Owner{}) || principal.APIKeyActor() != "" || principal.ClientID() != "" || principal.RequireScope("identity:read") == nil {
		t.Fatal("withdrawn organization token retained resource authority", err)
	}
}

func TestNativeOrganizationResourceCacheLostInvalidationParentAndRootRevocation(t *testing.T) {
	for _, withdrawal := range []string{"parent", "root"} {
		t.Run(withdrawal, func(t *testing.T) {
			f := organizationAPIKeyExchangeFixture(t)
			key, source := createOrganizationExchangeSource(t, f, "m33-organization-cache-"+withdrawal)
			request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: f.h.client.ID, ClientAuthentication: f.h.basic, SubjectToken: source, SubjectTokenType: oauth.APIKeyTokenType, Resource: f.h.client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.10"}
			parent, err := f.h.service.Token(f.h.f.ctx, request)
			request.SubjectToken, source = "", ""
			if err != nil || parent.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("actual organization key did not issue access parent", err)
			}
			parentWire, err := parent.AccessToken.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			request.SubjectToken, request.SubjectTokenType = parentWire, oauth.AccessTokenType
			child, err := f.h.service.Token(f.h.f.ctx, request)
			request.SubjectToken = ""
			if err != nil || child.Outcome != identity.CommitOutcomeCommitted || child.ExpiresAt.After(parent.ExpiresAt) {
				t.Fatal("actual organization access parent did not issue bounded child", err)
			}
			childWire, err := child.AccessToken.Reveal()
			if err != nil {
				t.Fatal(err)
			}

			pool, counter, _ := resourceCacheObservedPool(t, f.h.f)
			clock := &resourceCacheTestClock{}
			policy := oauth.OrganizationResourceVerificationConfig{Verification: cachedResourcePolicy(f.h.f, f.h.client, clock), OrganizationID: f.profile.OrganizationID}
			cached, err := oauthpostgres.NewOrganizationResourceVerifier(pool, f.h.f.oauth, f.h.f.keys, f.profile, policy)
			if err != nil {
				t.Fatal(err)
			}
			tokens := []string{parentWire, childWire}
			expires := []time.Time{parent.ExpiresAt, child.ExpiresAt}
			original := make([]oauth.OrganizationResourcePrincipal, len(tokens))
			for i, token := range tokens {
				original[i], err = cached.Verify(f.h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: token, Scope: "identity:read"})
				if err != nil || original[i].RequireScope("identity:read") != nil || original[i].Owner() != key.Owner || original[i].APIKeyActor() != key.ID {
					t.Fatal("actual organization parent/child did not produce typed cached authority", err)
				}
				if original[i].ReadStartedAt().IsZero() || !original[i].ValidUntil().After(original[i].ReadStartedAt()) || original[i].ValidUntil().After(original[i].ReadStartedAt().Add(20*time.Second)) || original[i].ValidUntil().After(expires[i]) || original[i].ValidUntil().After(key.ExpiresAt) {
					t.Fatal("cold organization authority exceeded original native or credential window")
				}
			}
			if original[0].Lineage().RootID != key.RootID || original[1].Lineage().RootID != key.RootID || original[1].Lineage().ParentID != original[0].Lineage().TokenID {
				t.Fatal("cached organization child lost its actual key/parent lineage")
			}
			coldQueries := counter.queries.Load()
			if coldQueries < 2 {
				t.Fatal("cold organization verification did not consult primary authority")
			}

			if withdrawal == "parent" {
				result, err := f.h.service.Revoke(f.h.f.ctx, oauth.RevokeRequest{ClientID: f.h.client.ID, ClientAuthentication: f.h.basic, Token: parentWire, Hint: oauth.TokenAccess, Network: "192.0.2.10"})
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("actual organization access parent could not be revoked", err)
				}
			} else {
				idempotency, err := identity.NewIdempotencyKey([]byte("m33-organization-cache-root-revoke"))
				if err != nil {
					t.Fatal(err)
				}
				result, err := f.h.keys.Revoke(f.h.f.ctx, apikey.Revocation{Authentication: f.manager, IdempotencyKey: idempotency, KeyID: key.ID, ExpectedVersion: key.Version, Network: "192.0.2.11"})
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("actual organization key root could not be revoked", err)
				}
			}

			for i, token := range tokens {
				requireInvalidOrganizationResource(t, f.resource, f.h.f.ctx, token)
				for range 3 {
					warm, err := cached.Verify(f.h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: token, Scope: "identity:read"})
					cold := original[i]
					if err != nil || warm.RequireScope("identity:read") != nil || warm.RequireScope("identity:write") == nil {
						t.Fatal("warm organization cache lost its original scoped authority", err)
					}
					if warm.Owner() != cold.Owner() || warm.APIKeyActor() != cold.APIKeyActor() || warm.TenantID() != cold.TenantID() ||
						warm.ClientID() != cold.ClientID() || warm.ClientVersion() != cold.ClientVersion() || warm.Resource() != cold.Resource() || warm.Lineage() != cold.Lineage() {
						t.Fatal("warm organization cache changed typed owner, key, caller or lineage")
					}
					if warm.ReadStartedAt() != cold.ReadStartedAt() || warm.ValidUntil() != cold.ValidUntil() {
						t.Fatal("warm organization cache renewed original evidence")
					}
				}
			}
			if counter.queries.Load() != coldQueries {
				t.Fatal("warm organization verifier queried a primary authority")
			}

			deadline := original[0].ValidUntil()
			if original[1].ValidUntil().After(deadline) {
				deadline = original[1].ValidUntil()
			}
			clock.at(deadline)
			for i, token := range tokens {
				if original[i].RequireScope("identity:read") == nil {
					t.Fatal("copied organization authority survived its absolute deadline")
				}
				beforeRefresh := counter.queries.Load()
				requireInvalidOrganizationResource(t, cached, f.h.f.ctx, token)
				if counter.queries.Load() <= beforeRefresh {
					t.Fatal("expired organization decision did not refresh actual revoked authority")
				}
			}
		})
	}
}
