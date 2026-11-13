//go:build integration && oauthflow

package oauthpostgres_test

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	organization "github.com/faustbrian/go-organization"
)

func TestNativeOrganizationAPIKeyFixedOwnerAndResourceBindings(t *testing.T) {
	f := organizationAPIKeyExchangeFixture(t)
	_, wire := createOrganizationExchangeSource(t, f, "m33-org-exact-server-selector")
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: f.h.client.ID, ClientAuthentication: f.h.basic, SubjectToken: wire, SubjectTokenType: oauth.APIKeyTokenType, Resource: f.h.client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.10"}
	issued, err := f.h.service.Token(f.h.f.ctx, request)
	if err != nil {
		t.Fatal("actual source must be accepted by its exact selected profile first", err)
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	foreign := f.profile
	foreign.OrganizationID = apikey.OrganizationID(otherID)
	store, err := oauthpostgres.NewOrganizationAPIKeyExchangeStore(f.h.f.pool, f.h.f.oauth, f.h.f.keys, foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapAPIKeyExchangeClient(f.h.f.ctx, oauth.IntrospectRequest{ClientID: f.h.client.ID, ClientAuthentication: f.h.basic}); err != nil {
		t.Fatal("independent fixed-owner client must be bootstrapped before selector denial", err)
	}
	service, err := oauthpostgres.NewOrganizationAPIKeyExchangeService(f.h.f.pool, f.h.f.oauth, f.h.f.keys, foreign)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := service.Token(f.h.f.ctx, request); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("genuine key for one organization entered another fixed server owner")
	}
	request.SubjectToken, wire = "", ""
	base := oauth.OrganizationResourceVerificationConfig{Verification: oauth.ResourceVerificationConfig{Issuer: f.h.f.oauth.Protocol.Issuer, Environment: f.h.f.oauth.Protocol.Environment, TenantID: f.h.f.tenant, ClientID: f.h.client.ID, ClientVersion: f.h.client.Version, Resource: f.h.client.Resource, Scopes: f.h.f.oauth.Protocol.Scopes, Clock: clock.System{}, MaximumDuration: 4 * time.Second}, OrganizationID: f.profile.OrganizationID}
	for _, name := range []string{"organization", "client", "tenant", "resource", "client-version", "issuer", "environment"} {
		t.Run(name, func(t *testing.T) {
			selected, policy := f.profile, base
			switch name {
			case "organization":
				selected, policy.OrganizationID = foreign, foreign.OrganizationID
			case "client":
				policy.Verification.ClientID = f.other.ID
			case "tenant":
				policy.Verification.TenantID = "foreign-resource-tenant"
			case "resource":
				policy.Verification.Resource = "https://foreign.example.test/resource"
			case "client-version":
				policy.Verification.ClientVersion++
			case "issuer":
				policy.Verification.Issuer, _ = oauth.NewIssuer("https://foreign.example.test")
			case "environment":
				policy.Verification.Environment = "foreign-resource-environment"
			}
			verifier, err := oauthpostgres.NewOrganizationResourceVerifier(f.h.f.pool, f.h.f.oauth, f.h.f.keys, selected, policy)
			if err != nil {
				if name == "organization" || name == "client" {
					t.Fatal("valid foreign policy must reach actual token custody/owner read", err)
				}
				return
			}
			if principal, err := verifier.Verify(f.h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"}); err == nil || principal.Owner() != (apikey.Owner{}) || principal.RequireScope("identity:read") == nil {
				t.Fatal("foreign server binding admitted actual organization resource token")
			}
		})
	}
	if principal, err := f.resource.Verify(f.h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"}); err != nil || principal.RequireScope("identity:read") != nil {
		t.Fatal("foreign-profile probes mutated original organization authority", err)
	}
}

func createOrganizationExchangeSource(t *testing.T, f organizationKeyExchangeFixture, name string) (apikey.Record, string) {
	t.Helper()
	id, err := identity.NewIdempotencyKey([]byte(name))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.h.keys.CreateOrganization(f.h.f.ctx, apikey.OrganizationCreateRequest{CreateRequest: apikey.CreateRequest{Authentication: f.h.manager, IdempotencyKey: id, Name: name, Permissions: []string{"identity:read", "identity:write"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.10"}, OrganizationID: apikey.OrganizationID(f.id)})
	if err != nil {
		t.Fatal("genuine organization-owned modern key", err)
	}
	record, ok := issued.Record()
	if !ok || record.Owner.Spec().Kind != apikey.OwnerOrganization || record.Owner.Spec().UserID != "" || record.Owner.Spec().OrganizationID != apikey.OrganizationID(f.id) {
		t.Fatal("organization key fabricated a creator owner")
	}
	wire, err := issued.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return record, wire
}

func checkOrganizationKeyLineage(t *testing.T, f organizationKeyExchangeFixture, issued oauth.TokenResult, key apikey.Record, depth uint8, parent string) string {
	t.Helper()
	var artifact, storedParent, user, client string
	var payload, source []byte
	if err := f.h.f.pool.Raw().QueryRow(f.h.f.ctx, `SELECT a.artifact_id,COALESCE(a.parent_artifact_id,''),COALESCE(g.user_id,''),g.client_id,a.payload,g.api_key_source FROM oauth_store.artifacts a JOIN oauth_store.grants g USING(grant_id) WHERE a.issued_by=$1 AND a.kind=$2`, string(issued.CommandID), int16(oauth.TokenAccess)).Scan(&artifact, &storedParent, &user, &client, &payload, &source); err != nil {
		t.Fatal(err)
	}
	var provenance struct {
		Owner                         apikey.OwnerSpec
		KeyID, RootID                 apikey.KeyID
		AuthorityVersion, RootVersion uint64
	}
	var lineage struct {
		APIKeyExchange *struct {
			RootID, ParentID, ParentTokenType string
			RootVersion                       uint64
			Depth                             uint8
		}
	}
	if json.Unmarshal(source, &provenance) != nil || json.Unmarshal(payload, &lineage) != nil || lineage.APIKeyExchange == nil || provenance.Owner != key.Owner.Spec() || provenance.KeyID != key.ID || provenance.RootID != key.RootID || provenance.AuthorityVersion != key.AuthorityVersion || provenance.RootVersion != key.RootVersion || user != "" || client != f.h.client.ID || lineage.APIKeyExchange.RootID != string(key.RootID) || lineage.APIKeyExchange.RootVersion != key.RootVersion || lineage.APIKeyExchange.Depth != depth || lineage.APIKeyExchange.ParentID != parent {
		t.Fatal("durable organization/key/caller/root lineage aliased a USER or lost authority")
	}
	if depth == 1 && (storedParent != "" || lineage.APIKeyExchange.ParentTokenType != oauth.APIKeyTokenType) || depth > 1 && (storedParent != parent || lineage.APIKeyExchange.ParentTokenType != oauth.AccessTokenType) {
		t.Fatal("organization source fabricated OAuth/code/session parent ancestry")
	}
	return artifact
}

func TestNativeOrganizationAPIKeyExchangeRetainsOwnerAfterCreatorRemoval(t *testing.T) {
	f := organizationAPIKeyExchangeFixture(t)
	key, source := createOrganizationExchangeSource(t, f, "m33-organization-original")
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: f.h.client.ID, ClientAuthentication: f.h.basic, SubjectToken: source, SubjectTokenType: oauth.APIKeyTokenType, Resource: f.h.client.Resource, Scopes: []string{"identity:read", "identity:write"}, Network: "192.0.2.10"}
	started := time.Now()
	first, err := f.h.service.Token(f.h.f.ctx, request)
	request.SubjectToken, source = "", ""
	if err != nil || first.Outcome != identity.CommitOutcomeCommitted || first.IssuedTokenType != oauth.AccessTokenType || first.RefreshToken != (oauth.Token{}) || first.IDToken != (oauth.IDToken{}) || first.ExpiresAt.After(started.Add(5*time.Minute)) || first.ExpiresAt.After(key.ExpiresAt) {
		t.Fatal("actual org key failed restricted access-only exchange", err)
	}
	firstID := checkOrganizationKeyLineage(t, f, first, key, 1, string(key.ID))
	firstWire, err := first.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	principal, err := f.resource.Verify(f.h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: firstWire, Scope: "identity:read"})
	if err != nil || principal.RequireScope("identity:read") != nil || principal.Owner() != key.Owner || principal.APIKeyActor() != key.ID || principal.TenantID() != key.Owner.Spec().TenantID || principal.ClientID() != f.h.client.ID || principal.Resource() != f.h.client.Resource || principal.Lineage().RootID != key.RootID || principal.Lineage().RootVersion != key.RootVersion || principal.Lineage().TokenID != firstID || principal.Lineage().ParentID != string(key.ID) {
		t.Fatal("public org resource path lost owner/key/caller/root separation", err)
	}
	remove, err := f.owner.PrepareRemoveMember(f.h.f.ctx, organization.MemberRequest{Authentication: organization.Authentication{TenantID: f.manager.TenantID, Bearer: f.manager.Bearer}, CommandID: organizationExchangeCommand(t), OrganizationID: f.id, UserID: f.h.user, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "m33-remove-key-creator"}, "192.0.2.11")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := f.owner.Execute(f.h.f.ctx, remove); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual creator membership removal", err)
	}
	updateID, _ := identity.NewIdempotencyKey([]byte("removed-org-creator-denied"))
	if _, err := f.h.keys.Update(f.h.f.ctx, apikey.UpdateRequest{Authentication: f.h.manager, IdempotencyKey: updateID, KeyID: key.ID, ExpectedVersion: key.Version, Name: "removed creator", Permissions: slices.Clone(key.Grant), Network: "192.0.2.11"}); err == nil {
		t.Fatal("removed human retained management authority")
	}
	request.SubjectToken, request.SubjectTokenType, request.Scopes = firstWire, oauth.AccessTokenType, []string{"identity:read"}
	child, err := f.h.service.Token(f.h.f.ctx, request)
	if err != nil || child.Outcome != identity.CommitOutcomeCommitted || child.ExpiresAt.After(first.ExpiresAt) || !slices.Equal(child.Scopes, []string{"identity:read"}) {
		t.Fatal("creator removal revoked independent org authority or child widened it", err)
	}
	childID := checkOrganizationKeyLineage(t, f, child, key, 2, firstID)
	childWire, err := child.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	childPrincipal, err := f.resource.Verify(f.h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: childWire, Scope: "identity:read"})
	if err != nil || childPrincipal.RequireScope("identity:read") != nil || childPrincipal.RequireScope("identity:write") == nil || childPrincipal.Owner() != key.Owner || childPrincipal.APIKeyActor() != key.ID || childPrincipal.Lineage().ParentID != firstID || childPrincipal.Lineage().Depth != 2 {
		t.Fatal("actual public resource read lost org authority after creator removal", err)
	}
	request.SubjectToken, request.Scopes = childWire, []string{"identity:write"}
	if out, err := f.h.service.Token(f.h.f.ctx, request); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("organization child recovered permission removed by parent")
	}
	for _, wire := range []string{firstWire, childWire} {
		out, err := f.h.service.Introspect(f.h.f.ctx, oauth.IntrospectRequest{ClientID: f.h.client.ID, ClientAuthentication: f.h.basic, Token: wire})
		if err != nil || !out.Active || out.Subject != "" || out.ClientID != f.h.client.ID || out.Resource != f.h.client.Resource {
			t.Fatal("org integration fabricated a USER subject or lost caller/resource", err)
		}
	}
	request.SubjectToken, request.Scopes = childWire, []string{"identity:read"}
	grandchild, err := f.h.service.Token(f.h.f.ctx, request)
	if err != nil || grandchild.ExpiresAt.After(child.ExpiresAt) {
		t.Fatal("organization grandchild lost parent expiry ceiling", err)
	}
	checkOrganizationKeyLineage(t, f, grandchild, key, 3, childID)
	grandchildWire, err := grandchild.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if principal, err := f.resource.Verify(f.h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: grandchildWire, Scope: "identity:read"}); err != nil || principal.RequireScope("identity:read") != nil {
		t.Fatal("genuine organization grandchild unavailable before parent revoke", err)
	}
	if out, err := f.h.service.Revoke(f.h.f.ctx, oauth.RevokeRequest{ClientID: f.h.client.ID, ClientAuthentication: f.h.basic, Token: childWire, Hint: oauth.TokenAccess, Network: "192.0.2.10"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("owning Basic could not revoke actual org OAuth parent", err)
	}
	if out, err := f.h.service.Introspect(f.h.f.ctx, oauth.IntrospectRequest{ClientID: f.h.client.ID, ClientAuthentication: f.h.basic, Token: grandchildWire}); err != nil || out.Active {
		t.Fatal("revoked OAuth parent left organization grandchild active", err)
	}
	if principal, err := f.resource.Verify(f.h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: grandchildWire, Scope: "identity:read"}); err == nil || principal.RequireScope("identity:read") == nil {
		t.Fatal("revoked OAuth parent retained public organization resource authority")
	}
	if principal, err := f.resource.Verify(f.h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: firstWire, Scope: "identity:read"}); err != nil || principal.RequireScope("identity:read") != nil {
		t.Fatal("child revocation incorrectly revoked the independent org key/root", err)
	}
	request.SubjectToken = grandchildWire
	if out, err := f.h.service.Token(f.h.f.ctx, request); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("revoked OAuth parent admitted a new organization descendant")
	}
	revokeID, _ := identity.NewIdempotencyKey([]byte("actual-owner-revokes-m33-org-root"))
	if out, err := f.h.keys.Revoke(f.h.f.ctx, apikey.Revocation{Authentication: f.manager, IdempotencyKey: revokeID, KeyID: key.ID, ExpectedVersion: key.Version, Network: "192.0.2.11"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual remaining org owner could not revoke root", err)
	}
	for _, wire := range []string{firstWire, childWire, grandchildWire} {
		out, err := f.h.service.Introspect(f.h.f.ctx, oauth.IntrospectRequest{ClientID: f.h.client.ID, ClientAuthentication: f.h.basic, Token: wire})
		if err != nil || out.Active || out.Subject != "" || out.ClientID != "" || out.Resource != "" || out.Scopes != nil || !out.ExpiresAt.IsZero() {
			t.Fatal("revoked organization root retained descendants or inactive metadata", err)
		}
		if out, err := f.resource.Verify(f.h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: wire, Scope: "identity:read"}); err == nil || out.Owner() != (apikey.Owner{}) || out.RequireScope("identity:read") == nil {
			t.Fatal("revoked organization root retained public resource authority", err)
		}
	}
	request.SubjectToken, request.Scopes = firstWire, []string{"identity:read"}
	if out, err := f.h.service.Token(f.h.f.ctx, request); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("revoked organization root admitted a new descendant")
	}
}

func TestNativeOrganizationAPIKeyUnknownExchangeRetainsOriginalMetadata(t *testing.T) {
	fault := &oauthCommitFault{}
	f := organizationAPIKeyExchangeFixture(t, fault)
	_, source := createOrganizationExchangeSource(t, f, "m33-org-unknown-original")
	command := organizationExchangeCommand(t)
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: f.h.client.ID, ClientAuthentication: f.h.basic, CommandID: command, SubjectToken: source, SubjectTokenType: oauth.APIKeyTokenType, Resource: f.h.client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.10"}
	knownRequest := request
	knownRequest.CommandID = ""
	known, err := f.h.service.Token(f.h.f.ctx, knownRequest)
	knownRequest.SubjectToken = ""
	if err != nil {
		t.Fatal("known organization token before acknowledgement loss", err)
	}
	knownWire, err := known.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	fault.armed.Store(true)
	lost, err := f.h.service.Token(f.h.f.ctx, request)
	request.SubjectToken, source = "", ""
	var unknown oauth.APIKeyExchangeUnknownError
	if !fault.hit.Load() || !errors.As(err, &unknown) || lost.Outcome != identity.CommitOutcomeUnknown || lost.CommandID != command || lost.AccessToken != (oauth.Token{}) || unknown.Verification.Validate() != nil || unknown.Verification.Original.UserID != "" || unknown.Verification.Original.AnonymousFlowID != string(unknown.Verification.AttemptID) {
		t.Fatal("actual org-key lost acknowledgement fabricated a human or lost original custody", err)
	}
	var before string
	if err := f.h.f.pool.Raw().QueryRow(f.h.f.ctx, `SELECT api_key_source::text FROM oauth_store.grants WHERE grant_id=$1`, string(command)).Scan(&before); err != nil {
		t.Fatal(err)
	}
	recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: command, ClientID: f.h.client.ID, ClientAuthentication: f.h.basic, APIKeyVerification: &unknown.Verification}
	for _, withdrawn := range []bool{false, true} {
		if withdrawn {
			// Actual primary failure injection through the owned epoch trigger,
			// not a claim of executing a new public archive/MFA workflow.
			if _, err := f.h.f.pool.Raw().Exec(f.h.f.ctx, `UPDATE organization.organizations SET state='archived',version=version+1 WHERE tenant_id=$1 AND organization_id=$2`, baselineTenant, string(f.id)); err != nil {
				t.Fatal(err)
			}
		}
		out, err := f.h.store.Recover(f.h.f.ctx, recovery)
		if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.CommandID != command {
			t.Fatal("exact original org exchange could not recover metadata without renewed authority", withdrawn, err)
		}
		if withdrawn {
			if principal, err := f.resource.Verify(f.h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: knownWire, Scope: "identity:read"}); err == nil || principal.Owner() != (apikey.Owner{}) || principal.RequireScope("identity:read") == nil {
				t.Fatal("withdrawn organization still authorized the public resource", err)
			}
		}
	}
	var after string
	var grants, artifacts, effects int
	if err := f.h.f.pool.Raw().QueryRow(f.h.f.ctx, `SELECT api_key_source::text,(SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.artifacts),(SELECT count(*) FROM oauth_store.effects WHERE command_id=$1) FROM oauth_store.grants WHERE grant_id=$1`, string(command)).Scan(&after, &grants, &artifacts, &effects); err != nil || before != after || grants != 2 || artifacts != 2 || effects != 1 {
		t.Fatal("org recovery renewed source timestamps or repeated issuance", err)
	}
	wrong := recovery
	wrong.ClientID, wrong.ClientAuthentication = f.other.ID, f.otherBasic
	if _, err := f.h.store.Recover(f.h.f.ctx, wrong); err == nil {
		t.Fatal("different genuinely authenticated Basic client acquired org exchange custody")
	}
	wrong = recovery
	wrong.CommandID = organizationExchangeCommand(t)
	if _, err := f.h.store.Recover(f.h.f.ctx, wrong); err == nil {
		t.Fatal("another command acquired original org exchange custody")
	}
	changed := unknown.Verification
	changed.Fingerprint[0]++
	wrong = recovery
	wrong.APIKeyVerification = &changed
	if _, err := f.h.store.Recover(f.h.f.ctx, wrong); err == nil {
		t.Fatal("changed org verification handle acquired original custody")
	}
}
