//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"slices"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	"github.com/jackc/pgx/v5/stdlib"
)

type apiKeyNativeExchange struct {
	f             authenticatedPasswordFixture
	client        oauth.Client
	basic         oauth.ClientAuthentication
	service       *oauth.Service
	store         *oauthpostgres.Store
	keys          *apikeypg.Service
	configuration apikey.Configuration
	manager       apikey.Authentication
	user          identity.UserID
}

// This is application policy, not authentication. OAuth issuance is allowed
// only for an API-key actor and its USER resource, never the manager's human
// session or the separately authenticated Basic client as a subject substitute.
type apiKeyExchangeFixturePolicy struct {
	base   authorization.Service
	user   identity.UserID
	legacy bool
}

func (p apiKeyExchangeFixturePolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	r := c.Request
	if r.Action == "identity.oauth-server.token" || r.Action == "identity.oauth-server.revoke" {
		outcome := authorization.Deny
		if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectAPIKey && r.Subject.ID != "" && r.Resource.Type == "identity.user" && string(r.Resource.ID) == string(p.user) {
			outcome = authorization.Allow
		}
		return authorization.Decision{Outcome: outcome, Revision: c.PolicyRevision}, nil
	}
	if string(r.Tenant) == baselineTenant && r.Subject.ID != "" {
		allowed := false
		if r.Subject.Kind == authorization.SubjectUser && string(r.Subject.ID) == string(p.user) {
			configuration := r.Resource.Type == "api-key" && (r.Resource.ID == "m33-modern-user" || p.legacy && r.Resource.ID == "m33-legacy-user")
			ownUser := r.Resource.Type == "identity.user" && string(r.Resource.ID) == string(p.user)
			admission := r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action)
			switch r.Action {
			case "identity.apikey.create", "identity.apikey.delete", "identity.apikey.get":
				allowed = configuration || ownUser || admission
			case "identity.apikey.import":
				legacyConfiguration := r.Resource.Type == "api-key" && r.Resource.ID == "m33-legacy-user"
				importSource := r.Resource.Type == "api-key-import-source" && r.Resource.ID == "m33-authenticated-import"
				allowed = p.legacy && (legacyConfiguration || ownUser || admission || importSource)
			case "identity:read", "identity:write":
				allowed = configuration
			}
		}
		if r.Action == "identity.apikey.verify" {
			keySubject := r.Subject.Kind == authorization.SubjectAPIKey && r.Resource.Type == "identity.user" && string(r.Resource.ID) == string(p.user)
			unmatchedSource := r.Subject.Kind == authorization.SubjectServiceAccount && (r.Subject.ID == "m33-modern-user" || p.legacy && r.Subject.ID == "m33-legacy-user") && r.Resource.Type == "identity.anonymous-flow"
			allowed = keySubject || unmatchedSource
		}
		if r.Action == "identity.command.query" && r.Resource.Type == "identity.command" && (r.Subject.Kind == authorization.SubjectAPIKey || r.Subject.Kind == authorization.SubjectUser && string(r.Subject.ID) == string(p.user)) {
			allowed = true
		}
		if allowed {
			return authorization.Decision{Outcome: authorization.Allow, Revision: c.PolicyRevision}, nil
		}
	}
	return p.base.Decide(ctx, c)
}

func genuineAPIKeyManagerBearer(t *testing.T, f authenticatedPasswordFixture) (apikey.Authentication, identity.UserID) {
	t.Helper()
	input := f.phoneInput
	c := input.signin
	c.Transport, c.CSRFKey, c.Issuance.Cookie = password.BearerSignin, session.CSRFKey{}, session.CookiePolicy{}
	// Reuse the existing real counted-authentication fixture, not phone state,
	// a risk double or a cookie token reclassified as a bearer session.
	c.Risk = phoneAuthenticationRisk(t, f)
	signin, err := passwordpg.NewSigninService(f.pool, c)
	if err != nil {
		t.Fatal("actual bearer signin owner configuration", err)
	}
	executor, err := sessionpg.NewPreAuthIssueExecutor(f.pool, sessionpg.PreAuthIssueExecutorConfig{Repository: c.Session, Coordinator: c.Coordinator, Authorization: c.Coordinator.QueryPolicy.Authorization, Clock: clock.System{}, ActorID: baselineActor, Action: "identity.password.signin", Origin: c.Origins[0], CallbackURL: c.CallbackURLs[0], PolicyID: c.PolicyID, PolicyVersion: 9, AuditRetentionVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{ActorID: baselineActor, Action: "identity.password.signin", Origin: c.Origins[0], CallbackURL: c.CallbackURLs[0], PolicyID: c.PolicyID, PolicyVersion: 9, Clock: clock.System{}, MaximumDuration: 2 * time.Second, FlowTTL: 5 * time.Minute, LookupKey: c.FlowKeys[0], TokenSize: 32, Cookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.RememberDefault, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := issuer.Prepare(session.PreAuthPrepareInput{CommandID: id, TenantID: f.tenant, CorrelationID: string(id), Remember: remember})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.Issue(f.ctx, prepared)
	if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual original bearer-signin preauth", err)
	}
	flow, err := issued.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	flowWire, err := issued.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := primitive.NewSecret(input.password)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	inputIdentifier, err := identifier.NewInput(input.identifier)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: baselineActor}, Tenant: authorization.TenantID(f.tenant), Action: "identity.password.signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.signin"}}}
	result, err := signin.Signin(f.ctx, password.SigninRequest{TenantID: f.tenant, PreAuthID: flow.Binding.ID, Cookie: auth.NewBearerCredential(flowWire), Identifier: inputIdentifier, Password: secret, Remember: remember, Caller: caller, Origin: c.Origins[0], CallbackURL: c.CallbackURLs[0], Network: "192.0.2.10", Device: "m33-api-key-manager"})
	if err != nil || result.State != auth.SignInStateAuthenticated || result.Transport != password.BearerSignin || result.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || result.Issuance.Session.CSRFState() != (session.CSRFState{}) {
		t.Fatal("actual registered bearer signin for key management", err)
	}
	bindings, err := result.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := result.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return apikey.Authentication{TenantID: f.tenant, Bearer: auth.NewBearerCredential(wire)}, bindings.UserID
}

func apiKeyExchangeFixture(t *testing.T, faults ...*oauthCommitFault) apiKeyNativeExchange {
	return apiKeyExchangeFixtureObserved(t, nil, faults...)
}

func apiKeyExchangeFixtureObserved(t *testing.T, trace *apiKeySQLTrace, faults ...*oauthCommitFault) apiKeyNativeExchange {
	return configuredAPIKeyExchangeFixture(t, trace, false, faults...)
}

func legacyAPIKeyExchangeFixture(t *testing.T, faults ...*oauthCommitFault) apiKeyNativeExchange {
	return configuredAPIKeyExchangeFixture(t, nil, true, faults...)
}

func configuredAPIKeyExchangeFixture(t *testing.T, trace *apiKeySQLTrace, legacy bool, faults ...*oauthCommitFault) apiKeyNativeExchange {
	t.Helper()
	f := passwordFixture(t, faults...)
	manager, user := genuineAPIKeyManagerBearer(t, f)
	if trace != nil {
		f.pool = observedAPIKeyPool(t, f, trace)
	}
	client, _, basic := addConfiguredConfidentialClient(t, &f)
	client.APIKeyExchange = true
	for i := range f.oauth.Protocol.Clients {
		if f.oauth.Protocol.Clients[i].ID == client.ID {
			f.oauth.Protocol.Clients[i] = client
		}
	}
	policy := apiKeyExchangeFixturePolicy{base: f.oauth.Coordinator.QueryPolicy.Authorization, user: user, legacy: legacy}
	query, admission := *f.oauth.Coordinator.QueryPolicy, *f.oauth.Coordinator.AdmissionPolicy
	query.Authorization, admission.Authorization = policy, policy
	f.oauth.Coordinator.QueryPolicy, f.oauth.Coordinator.AdmissionPolicy = &query, &admission
	var requestKey, pepperBytes, envelopeBytes [32]byte
	for _, key := range [][]byte{requestKey[:], pepperBytes[:], envelopeBytes[:]} {
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		defer clear(key)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("m33-api-key-source", requestKey, query)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := apikey.NewConfiguration(apikey.ConfigurationSpec{ID: "m33-modern-user", Revision: 1, State: apikey.ConfigurationActive, Issuer: f.oauth.Protocol.Issuer.String(), Environment: f.oauth.Protocol.Environment, Audience: client.Resource, PermissionReduction: apikey.PermissionReductionNarrow, MaximumLifetime: 90 * 24 * time.Hour, MaximumRead: 4 * time.Second, ClockUncertainty: time.Millisecond, DecisionRaceBudget: time.Millisecond, Quota: apikey.QuotaUnlimited, Cache: apikey.CacheDisabled})
	if err != nil {
		t.Fatal(err)
	}
	selectedConfiguration := configuration
	var legacyConfiguration apikey.Configuration
	var canonicalKeyID func(context.Context, apikey.KeyID) error
	keyHistory := migrations.Source(apikeypg.MigrationSource{Version: 7100})
	if legacy {
		spec := configuration.Spec()
		spec.ID, spec.Algorithm, spec.State = "m33-legacy-user", apikey.AlgorithmLegacySHA256V1, apikey.ConfigurationVerifyOnly
		spec.AllowLegacyNoExpiry = true
		legacyConfiguration, err = apikey.NewConfiguration(spec)
		if err != nil {
			t.Fatal(err)
		}
		selectedConfiguration = legacyConfiguration
		canonicalKeyID = func(ctx context.Context, id apikey.KeyID) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if id != "01ARZ3NDEKTSV4RRFFQ69G5FAV" && id != "01ARZ3NDEKTSV4RRFFQ69G5FAT" {
				return apikey.ErrInvalid
			}
			return nil
		}
		keyHistory = apikeypg.LegacyMigrationSource{Base: keyHistory, Version: 7101}
	}
	pepper, err := apikey.NewPepper(1, pepperBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	counters, err := riskpg.NewRepository(f.oauth.Counters)
	if err != nil {
		t.Fatal(err)
	}
	counterPolicy := f.oauth.Counters.CommandCounters.Policy
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: counterPolicy, Clock: time.Now, Timeout: time.Second, Sources: []risk.Source{{Name: "velocity", Version: "native-counter-deferred-v1", Timeout: time.Second, Read: func(context.Context, risk.Context) (risk.Signal, error) {
		return risk.Signal{}, risk.ErrUnsupportedIssuance
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	for _, install := range []struct {
		namespace string
		source    migrations.Source
	}{
		{"identity_api_keys", keyHistory},
		{"oauth_server", oauthpostgres.APIKeyExchangeMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7200}},
	} {
		backend, err := migrationdb.New(db)
		if err != nil {
			t.Fatal(err)
		}
		backend, err = backend.ForNamespace(install.namespace)
		if err != nil {
			t.Fatal(err)
		}
		runner, err := migrations.NewRunner(install.source, backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("actual selected source/OAuth history", err)
		}
	}
	keyOwner, err := apikeypg.NewService(f.pool, apikeypg.ServiceConfig{Configuration: configuration, LegacyConfiguration: legacyConfiguration, ValidateCanonicalKeyID: canonicalKeyID, Clock: clock.System{}, MaximumDuration: 4 * time.Second, Sessions: f.sessions, Session: f.oauth.Session.Repository, Profile: f.oauth.Session.Profile, LookupKeys: map[uint32]session.DigestKey{11: f.phoneInput.signin.Issuance.LookupKey}, Authorization: policy, PolicyID: "m33-api-key-source", PolicyVersion: 9, Pepper: pepper, Counters: counters, Risk: risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "m33-api-key-provider", Keys: slices.Clone(f.oauth.Counters.EvidenceKeys)}, CounterPolicy: counterPolicy, Coordinator: f.oauth.Coordinator, RequestKeys: requestKeys, ActiveEnvelopeKeyID: "m33-api-key-envelope", RetainedEnvelopeKeys: map[string][]byte{"m33-api-key-envelope": envelopeBytes[:]}})
	if err != nil {
		t.Fatal("actual API-key source owner", err)
	}
	if err := keyOwner.InitializeConfiguration(f.ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	if legacy {
		if err := keyOwner.InitializeLegacyConfiguration(f.ctx, f.tenant); err != nil {
			t.Fatal(err)
		}
	}
	f.oauth.Protocol.APIKeyExchange = &oauth.APIKeyExchangePolicy{MaximumDepth: 4, ClockUncertainty: time.Millisecond, LegacySHA256: legacy}
	f.oauth.Protocol.OwningClientIntrospection = true
	f.oauth.APIKeyExchange = &oauthpostgres.APIKeyExchangeConfig{TenantID: f.tenant, Configuration: selectedConfiguration, Source: keyOwner, ClientPolicyNamespace: "m33-api-key-clients"}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal("actual selected API-key exchange store", err)
	}
	if err := store.BootstrapAPIKeyExchangeClient(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: basic}); err != nil {
		t.Fatal("explicit API-key exchange client authority bootstrap", err)
	}
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	return apiKeyNativeExchange{f: f, client: client, basic: basic, service: service, store: store, keys: keyOwner, configuration: selectedConfiguration, manager: manager, user: user}
}
