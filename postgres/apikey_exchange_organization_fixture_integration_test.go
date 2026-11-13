//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5/stdlib"
)

type organizationKeyExchangeFixture struct {
	h          apiKeyNativeExchange
	owner      *organizationpg.Service
	id         organization.ID
	manager    apikey.Authentication
	managerID  identity.UserID
	profile    oauthpostgres.OrganizationAPIKeyExchangeConfig
	resource   *oauth.OrganizationResourceVerifier
	other      oauth.Client
	otherBasic oauth.ClientAuthentication
}

func addOrganizationExchangeCaller(t *testing.T, h *apiKeyNativeExchange) (oauth.Client, oauth.ClientAuthentication) {
	t.Helper()
	other := h.client
	other.ID = "m33-organization-other-basic"
	token, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := primitive.NewSecret([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oauth.NewClientSecretVerifier(other.ID, other.Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	basic := confidentialBasic(t, other.ID, wire)
	h.f.oauth.Protocol.Clients = append(h.f.oauth.Protocol.Clients, other)
	h.f.oauth.Protocol.ClientSecrets = append(h.f.oauth.Protocol.ClientSecrets, verifier)
	return other, basic
}

func organizationExchangeCommand(t *testing.T) identity.CommandID {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Consumer policy is supplied; actual sessions, owner/member authority, native
// key verification and original OAuth coordination remain their real owners.
type organizationKeyExchangePolicy struct {
	base authorization.Service
	id   organization.ID
}

func (p organizationKeyExchangePolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	r := c.Request
	allow := false
	if string(r.Tenant) == baselineTenant && r.Subject.ID != "" {
		if r.Action == "identity.oauth-server.token" || r.Action == "identity.oauth-server.revoke" {
			allow = r.Subject.Kind == authorization.SubjectAPIKey && r.Resource.Type == "identity.anonymous-flow" && r.Resource.ID != ""
			outcome := authorization.Deny
			if allow {
				outcome = authorization.Allow
			}
			return authorization.Decision{Outcome: outcome, Revision: c.PolicyRevision}, nil
		}
		if r.Subject.Kind == authorization.SubjectUser {
			own := r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(r.Subject.ID)
			target := r.Resource.Type == "organization" && r.Resource.ID == authorization.ResourceID(p.id)
			configuration := r.Resource.Type == "api-key" && r.Resource.ID == "m33-modern-organization"
			admission := r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action)
			if own || configuration || admission {
				switch r.Action {
				case "identity.apikey.create", "identity.apikey.delete", "identity.apikey.update", "identity.apikey.get":
					allow = true
				}
			}
			if own || target {
				switch r.Action {
				case authorization.Action(organization.Create), authorization.Action(organization.AddMember), authorization.Action(organization.RemoveMember), authorization.Action(organization.Get):
					allow = true
				}
			}
		}
		orgKey := r.Resource.Type == "organization-api-key" && r.Resource.ID == authorization.ResourceID(p.id)
		if orgKey && (r.Subject.Kind == authorization.SubjectUser || r.Subject.Kind == authorization.SubjectAPIKey) {
			switch r.Action {
			case "identity.apikey.create", "identity.apikey.delete", "identity.apikey.update", "identity.apikey.get", "identity:read", "identity:write":
				allow = true
			}
		}
		if r.Action == "identity.apikey.verify" && r.Subject.Kind == authorization.SubjectAPIKey && r.Resource.Type == "identity.anonymous-flow" {
			allow = true
		}
		if r.Action == "identity.command.query" && r.Resource.Type == "identity.command" && (r.Subject.Kind == authorization.SubjectAPIKey || r.Subject.Kind == authorization.SubjectUser) {
			allow = true
		}
	}
	if allow {
		return authorization.Decision{Outcome: authorization.Allow, Revision: c.PolicyRevision}, nil
	}
	return p.base.Decide(ctx, c)
}

func applyOrganizationExchangeHistory(t *testing.T, ctx context.Context, db *sql.DB, namespace string, source migrations.Source) {
	t.Helper()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace(namespace)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("actual organization exchange history", err)
	}
}

func organizationAPIKeyExchangeFixture(t *testing.T, faults ...*oauthCommitFault) organizationKeyExchangeFixture {
	return organizationAPIKeyExchangeFixtureObserved(t, nil, faults...)
}

func organizationAPIKeyExchangeFixtureObserved(t *testing.T, trace *apiKeySQLTrace, faults ...*oauthCommitFault) organizationKeyExchangeFixture {
	t.Helper()
	h := apiKeyExchangeFixtureObserved(t, trace, faults...)
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	policy := organizationKeyExchangePolicy{base: h.sourceConfig.Authorization, id: organization.ID(id)}
	query, admission := *h.f.oauth.Coordinator.QueryPolicy, *h.f.oauth.Coordinator.AdmissionPolicy
	query.Authorization, admission.Authorization = policy, policy
	h.f.oauth.Coordinator.QueryPolicy, h.f.oauth.Coordinator.AdmissionPolicy = &query, &admission
	db := stdlib.OpenDB(*h.f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	var ownerSteps []migrations.Migration
	for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 1}, organizationpg.CredentialAuthorityMigrationSource{Version: 2}, apikeypg.OrganizationMigrationSource{Version: 3}} {
		steps, err := source.Load(h.f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		ownerSteps = append(ownerSteps, steps...)
	}
	applyOrganizationExchangeHistory(t, h.f.ctx, db, "m33_organization_key_owners", fixtureHistory(ownerSteps))
	history := oauthpostgres.OrganizationAPIKeyExchangeMigrationSource{Base: oauthpostgres.APIKeyExchangeMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7200}, Schema: "oauth_store", Version: 7400}
	applyOrganizationExchangeHistory(t, h.f.ctx, db, "oauth_server", history)
	repository, err := organizationpg.NewRepository(h.f.pool, organizationpg.Config{MaximumDuration: 4 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	sourceConfig := h.sourceConfig
	sourceConfig.Authorization, sourceConfig.Coordinator = policy, h.f.oauth.Coordinator
	var requestKey [32]byte
	if _, err := rand.Read(requestKey[:]); err != nil {
		t.Fatal(err)
	}
	sourceConfig.RequestKeys, err = kernel.NewRequestKeyConfig("m33-organization-source", requestKey, query)
	clear(requestKey[:])
	if err != nil {
		t.Fatal(err)
	}
	spec := h.configuration.Spec()
	spec.ID = "m33-modern-organization"
	sourceConfig.Configuration, err = apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	participant, err := organizationpg.NewContributor(repository, organizationpg.ContributorConfig{Session: sourceConfig.Session, Profile: sourceConfig.Profile, LookupKeys: sourceConfig.LookupKeys, PolicyID: "m33-organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := kernel.NewRepository(h.f.pool, kernel.Config{MaximumDuration: 4 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{directory, audits, outbox, sourceConfig.Counters, participant})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := kernel.NewCoordinator(h.f.pool, registry, h.f.oauth.Coordinator)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := organizationpg.NewService(participant, organizationpg.ServiceConfig{Core: organization.Config{Clock: clock.System{}, MaximumDuration: 4 * time.Second, PolicyID: "m33-organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, ValidateCanonicalID: func(ctx context.Context, id organization.ID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := identity.ParseSubjectID(string(id))
		return err
	}}, Sessions: h.f.sessions, Authorization: policy, Risk: sourceConfig.Counters, Coordinator: coordinator, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	create, err := owner.PrepareCreate(h.f.ctx, organization.CreateRequest{Authentication: organization.Authentication{TenantID: h.manager.TenantID, Bearer: h.manager.Bearer}, CommandID: organizationExchangeCommand(t), ID: organization.ID(id), Slug: "m33-integration", Name: "M33 integration", CorrelationID: "m33-organization-create"}, "192.0.2.10")
	if err != nil {
		t.Fatal("prepare genuine organization", err)
	}
	if result, err := owner.Execute(h.f.ctx, create); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("create genuine organization", err)
	}
	var manager apikey.Authentication
	var managerID identity.UserID
	h.f.anotherUserWithCredentials(func(address string, password []byte) {
		input := *h.f.phoneInput
		input.identifier, input.password = address, password
		second := h.f
		second.phoneInput = &input
		manager, managerID = genuineAPIKeyManagerBearerWithRisk(t, second, h.managerRisk)
	})
	add, err := owner.PrepareAddMember(h.f.ctx, organization.MemberRequest{Authentication: organization.Authentication{TenantID: h.manager.TenantID, Bearer: h.manager.Bearer}, CommandID: organizationExchangeCommand(t), OrganizationID: organization.ID(id), UserID: managerID, Role: organization.RoleOwner, OrganizationVersion: 1, CorrelationID: "m33-organization-second-owner"}, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := owner.Execute(h.f.ctx, add); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("admit genuine second owner", err)
	}
	h.keys, err = apikeypg.NewOrganizationService(h.f.pool, sourceConfig, repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.keys.InitializeConfiguration(h.f.ctx, h.f.tenant); err != nil {
		t.Fatal(err)
	}
	h.configuration, h.sourceConfig = sourceConfig.Configuration, sourceConfig
	selected := *h.f.oauth.APIKeyExchange
	selected.Configuration, selected.Source, selected.ClientPolicyNamespace = h.configuration, h.keys, "m33-organization-api-key-clients"
	profile := oauthpostgres.OrganizationAPIKeyExchangeConfig{Source: selected, OrganizationID: apikey.OrganizationID(id)}
	h.f.oauth.APIKeyExchange = nil
	other, otherBasic := addOrganizationExchangeCaller(t, &h)
	h.store, err = oauthpostgres.NewOrganizationAPIKeyExchangeStore(h.f.pool, h.f.oauth, h.f.keys, profile)
	if err != nil {
		t.Fatal("actual selected organization key store", err)
	}
	if err := h.store.BootstrapAPIKeyExchangeClient(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.BootstrapAPIKeyExchangeClient(h.f.ctx, oauth.IntrospectRequest{ClientID: other.ID, ClientAuthentication: otherBasic}); err != nil {
		t.Fatal(err)
	}
	h.service, err = oauthpostgres.NewOrganizationAPIKeyExchangeService(h.f.pool, h.f.oauth, h.f.keys, profile)
	if err != nil {
		t.Fatal(err)
	}
	resourcePolicy := oauth.OrganizationResourceVerificationConfig{Verification: oauth.ResourceVerificationConfig{Issuer: h.f.oauth.Protocol.Issuer, Environment: h.f.oauth.Protocol.Environment, TenantID: h.f.tenant, ClientID: h.client.ID, ClientVersion: h.client.Version, Resource: h.client.Resource, Scopes: h.f.oauth.Protocol.Scopes, Clock: clock.System{}, MaximumDuration: 4 * time.Second}, OrganizationID: apikey.OrganizationID(id)}
	resource, err := oauthpostgres.NewOrganizationResourceVerifier(h.f.pool, h.f.oauth, h.f.keys, profile, resourcePolicy)
	if err != nil {
		t.Fatal("actual organization resource verifier", err)
	}
	return organizationKeyExchangeFixture{h: h, owner: owner, id: organization.ID(id), manager: manager, managerID: managerID, profile: profile, resource: resource, other: other, otherBasic: otherBasic}
}
