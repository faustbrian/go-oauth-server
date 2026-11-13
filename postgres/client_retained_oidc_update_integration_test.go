//go:build integration && oauthflow

package oauthpostgres_test

import (
	"errors"
	"net/url"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/oauth2"
)

func appendRetainedClientUpdates(t *testing.T, f *authenticatedPasswordFixture, pairwise bool) {
	t.Helper()
	var source migrations.Source = oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}
	source = oauthpostgres.ClientMigrationSource{Base: source, Schema: "oauth_store", Version: 7003}
	source = oauthpostgres.ClientRotationMigrationSource{Base: source, Schema: "oauth_store", Version: 7004}
	if pairwise {
		source = oauthpostgres.SigningMigrationSource{Base: source, Schema: "oauth_store", Version: 7005}
		source = oauthpostgres.PairwiseMigrationSource{Base: source, Schema: "oauth_store", Version: 7006}
	} else {
		source = oauthpostgres.ClientPublicMigrationSource{Base: source, Schema: "oauth_store", Version: 7005}
		source = oauthpostgres.SigningMigrationSource{Base: source, Schema: "oauth_store", Version: 7006}
	}
	source = oauthpostgres.ClientUpdateMigrationSource{Base: source, Schema: "oauth_store", Version: 7007}
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("oauth_server")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := runner.Up(f.ctx); err != nil || len(result.Records()) != 1 {
		t.Fatal("existing update migration did not append to populated OIDC history", err)
	}
	if result, err := runner.Up(f.ctx); err != nil || len(result.Records()) != 0 {
		t.Fatal("populated OIDC history prefix changed on replay", err)
	}
	f.oauth.ClientMetadataUpdates = true
}

func retainedOIDCUpdateCode(t *testing.T, f authenticatedPasswordFixture, core *oauth.Service, client oauth.Client, nonce string) (string, string) {
	t.Helper()
	proof := oauth2.GenerateVerifier()
	request := oauth.AuthorizationRequest{ClientID: client.ID, RedirectURI: client.Redirects[0], Resource: client.Resource, Scopes: slices.Clone(client.Scopes), CodeChallenge: oauth2.S256ChallengeFromVerifier(proof), State: nonce, Nonce: nonce}
	begin, err := core.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: request})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("retained OIDC class did not require real explicit consent", err)
	}
	continuation, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	approved, err := core.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, Origin: f.oauth.Protocol.Issuer.String(), ClientID: client.ID, Continuation: continuation, Network: "192.0.2.1", Approve: true})
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("retained OIDC explicit consent failed", err)
	}
	location, err := approved.Location()
	if err != nil {
		t.Fatal(err)
	}
	callback, err := url.Parse(location)
	if err != nil || callback.Scheme+"://"+callback.Host+callback.Path != client.Redirects[0] || callback.Query().Get("iss") != f.oauth.Protocol.Issuer.String() || callback.Query().Get("state") != nonce || callback.Query().Get("code") == "" {
		t.Fatal("retained OIDC callback lost exact redirect/issuer/state")
	}
	return callback.Query().Get("code"), proof
}

func retainedOIDCReplacement(t *testing.T, f authenticatedPasswordFixture, client oauth.Client, key string) oauth.ClientUpdateRequest {
	t.Helper()
	request := publicClientUpdateRequest(t, f, client, key)
	request.Scopes = slices.Clone(client.Scopes)
	request.PostLogoutRedirects = []string{"https://managed.example/signed-out"}
	return request
}

func requireRetainedOldGrantsDenied(t *testing.T, f authenticatedPasswordFixture, core *oauth.Service, client oauth.Client, authentication oauth.ClientAuthentication, code, proof, refresh string) {
	t.Helper()
	for _, request := range []oauth.TokenRequest{
		{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, ClientAuthentication: authentication, Code: code, CodeVerifier: proof, RedirectURI: client.Redirects[0], Network: "192.0.2.1"},
		{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, ClientAuthentication: authentication, RefreshToken: refresh, Network: "192.0.2.1"},
	} {
		if out, err := core.Token(f.ctx, request); err == nil || out.AccessToken != (oauth.Token{}) {
			t.Fatal("earlier retained-class code/refresh authority survived replacement")
		}
	}
}

func retainedOriginalConsent(t *testing.T, f authenticatedPasswordFixture, core *oauth.Service) string {
	t.Helper()
	consents, err := core.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
	if err != nil || len(consents.Page.Items()) != 1 {
		t.Fatal("retained-class original consent unavailable", err)
	}
	return consents.Page.Items()[0].ID()
}

func requireRetainedConsentDenied(t *testing.T, f authenticatedPasswordFixture, core *oauth.Service, id string) {
	t.Helper()
	if out, err := core.ConsentGet(f.ctx, oauth.ConsentGetRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRead, id, 0)}); err == nil || out.Consent.ID() != "" {
		t.Fatal("earlier retained-class consent survived replacement")
	}
}

func TestNativeRetainedOIDCClientUpdatePairwiseConsumer(t *testing.T) {
	f := passwordFixture(t)
	signer, defaultKey := managedPairwiseFixture(t, &f)
	p := f.oauth.Protocol.ManagedClients
	p.Redirects = []string{"https://managed.example/callback", "https://managed.example/new", "https://foreign.example/callback"}
	p.PostLogoutRedirects = []string{"https://managed.example/logout", "https://managed.example/signed-out"}
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "managed.example", "subjects", 1)
	p.PairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
	subjectPolicy := randomPairwisePolicy(t, f, 1)
	core, child, store := managedPairwiseServices(t, f, signer, defaultKey, subjectPolicy)
	key, err := subjectPolicy.KeyRegistration(1)
	if err != nil || store.InstallSubjectKey(f.ctx, key) != nil || store.ActivateSubjectKey(f.ctx, "subjects", 1, 1) != nil {
		t.Fatal("existing pairwise subject custody failed", err)
	}
	create := clientCreateRequest(t, f, "retained-pairwise-create")
	create.Scopes, create.SubjectRegistration, create.PostLogoutRedirects = []string{"openid"}, &registration, []string{"https://managed.example/logout"}
	created, err := core.ClientCreate(f.ctx, create)
	if err != nil {
		t.Fatal("genuine retained pairwise client creation failed", err)
	}
	secret, err := created.Secret.Reveal()
	if err != nil {
		t.Fatal("pairwise creation omitted its known fresh Basic secret")
	}
	token, verified := consumeManagedPairwise(t, f, core, child, created.Client, secret, "pairwise-before-replacement")
	code, proof := retainedOIDCUpdateCode(t, f, core, created.Client, "pairwise-pending-old-code")
	consentID := retainedOriginalConsent(t, f, core)
	before := readConfidentialUpdateState(t, confidentialUpdateFixture{f: f, client: created.Client})
	var bindingsBefore int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.subject_bindings`).Scan(&bindingsBefore); err != nil {
		t.Fatal(err)
	}
	appendRetainedClientUpdates(t, &f, true)
	p.ConfidentialOIDCUpdates, p.ConfidentialPairwiseUpdates = true, true
	fresh, freshChild, _ := managedPairwiseServices(t, f, signer, defaultKey, subjectPolicy)
	read, err := fresh.ClientGet(f.ctx, oauth.ClientReadRequest{Owner: created.Client.Owner, TenantID: f.tenant, Session: f.browser, ClientID: created.Client.ID})
	if err != nil || read.Client.SubjectRegistration == nil || *read.Client.SubjectRegistration != registration {
		t.Fatal("private read lost original pairwise metadata", err)
	}
	request := retainedOIDCReplacement(t, f, read.Client, "retained-pairwise-original")
	updated, err := fresh.ClientUpdate(f.ctx, request)
	if err != nil || updated.Completion.Outcome != identity.CommitOutcomeCommitted || updated.Completion.Replayed || updated.Client.Version != 2 || updated.Client.Public || updated.Client.AuthenticationMethod != "client_secret_basic" || updated.Client.SubjectRegistration == nil || *updated.Client.SubjectRegistration != registration || updated.Client.Owner != created.Client.Owner || updated.Client.Resource != created.Client.Resource {
		t.Fatal("existing pairwise class could not replace metadata without subject/auth conversion", err)
	}
	if _, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: created.Client.ID, AccessToken: token.AccessToken}); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("old pairwise access retained UserInfo", err)
	}
	requireRetainedConsentDenied(t, f, core, consentID)
	requireRetainedOldGrantsDenied(t, f, core, created.Client, confidentialBasic(t, created.Client.ID, secret), code, proof, token.RefreshToken)
	_, current := consumeManagedPairwise(t, f, fresh, freshChild, updated.Client, secret, "pairwise-after-replacement")
	if current.Subject != verified.Subject {
		t.Fatal("redirect replacement reassigned the retained pairwise subject")
	}
	var bindingsAfter int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.subject_bindings`).Scan(&bindingsAfter); err != nil || bindingsAfter != bindingsBefore {
		t.Fatal("metadata replacement minted a second pairwise subject binding", err)
	}
	replayed, err := fresh.ClientUpdate(f.ctx, request)
	if err != nil || !replayed.Completion.Replayed || replayed.Completion.CommandID != updated.Completion.CommandID || replayed.Client.SubjectRegistration == nil || *replayed.Client.SubjectRegistration != registration {
		t.Fatal("original pairwise replacement recovery changed subject policy", err)
	}
	requireConfidentialUpdateState(t, confidentialUpdateFixture{f: f, client: created.Client}, before, "2", 1)
}

func TestNativeRetainedOIDCClientUpdatePublicClaimsConsumer(t *testing.T) {
	f := profilePasswordFixture(t, false)
	profile := mutateNativeProfile(t, f, "Retained claims user")
	phone := pendingNativePhone(t, f)
	phone.verify(t, f, false)
	f.browser, f.csrf = f.signInAgain()
	signer, subjectKey := managedClaimsFixture(t, &f, true)
	selectManagedClaims(&f)
	p := f.oauth.Protocol.ManagedClients
	p.Redirects = []string{"https://managed.example/callback", "https://managed.example/new"}
	p.PostLogoutRedirects = []string{"https://managed.example/logout", "https://managed.example/signed-out"}
	email := managedClaimsEmail(t, f, profile.ID)
	core, child, _ := managedClaimsServices(t, f, signer, subjectKey)
	client := createManagedClaimsClient(t, f, core, "retained-claims-create")
	consumer := newManagedClaimsRP(t, f, core, child, client)
	token, verified := consumer.issue(t, client.Scopes, "claims-before-replacement")
	code, proof := retainedOIDCUpdateCode(t, f, core, client, "claims-pending-old-code")
	consentID := retainedOriginalConsent(t, f, core)
	consumer.userInfo(t, token, verified.Subject, client.Scopes, profile.Name, email, "+12025550123")
	appendRetainedClientUpdates(t, &f, false)
	p.PublicOIDCUpdates, p.PublicOIDCClaimsUpdates = true, true
	fresh, freshChild, _ := managedClaimsServices(t, f, signer, subjectKey)
	read, err := fresh.ClientGet(f.ctx, oauth.ClientReadRequest{Owner: client.Owner, TenantID: f.tenant, Session: f.browser, ClientID: client.ID})
	if err != nil || !slices.Equal(read.Client.Scopes, client.Scopes) {
		t.Fatal("private read lost selected public claims scopes", err)
	}
	request := retainedOIDCReplacement(t, f, read.Client, "retained-claims-original")
	request.Scopes = []string{"email", "openid", "profile"}
	updated, err := fresh.ClientUpdate(f.ctx, request)
	if err != nil || updated.Completion.Outcome != identity.CommitOutcomeCommitted || updated.Completion.Replayed || updated.Client.Version != 2 || !updated.Client.Public || updated.Client.AuthenticationMethod != "none" || updated.Client.SubjectRegistration != nil || updated.Client.Owner != client.Owner || updated.Client.Resource != client.Resource || !slices.Equal(updated.Client.Scopes, request.Scopes) {
		t.Fatal("existing public claims class could not replace bounded metadata", err)
	}
	if _, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: client.ID, AccessToken: token.AccessToken}); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("old public account-claims access retained UserInfo", err)
	}
	requireRetainedConsentDenied(t, f, core, consentID)
	requireRetainedOldGrantsDenied(t, f, core, client, oauth.ClientAuthentication{}, code, proof, token.RefreshToken)
	currentConsumer := newManagedClaimsRP(t, f, fresh, freshChild, updated.Client)
	currentToken, current := currentConsumer.issue(t, updated.Client.Scopes, "claims-after-replacement")
	if current.Subject != verified.Subject {
		t.Fatal("public claims replacement changed stable default subject")
	}
	currentConsumer.userInfo(t, currentToken, current.Subject, updated.Client.Scopes, profile.Name, email, "")
	replayed, err := fresh.ClientUpdate(f.ctx, request)
	if err != nil || !replayed.Completion.Replayed || replayed.Completion.CommandID != updated.Completion.CommandID || !slices.Equal(replayed.Client.Scopes, request.Scopes) {
		t.Fatal("public claims metadata replay changed historical result", err)
	}
	requirePublicUpdateState(t, f, client, "2", "active", 1)
}

type retainedMutationFixture struct {
	f      authenticatedPasswordFixture
	core   *oauth.Service
	child  *op.Service
	store  *oauthpostgres.Store
	client oauth.Client
}

func newRetainedMutationFixture(t *testing.T, kind string, fault *oauthCommitFault) retainedMutationFixture {
	t.Helper()
	var f authenticatedPasswordFixture
	if kind == "pairwise" {
		f = passwordFixture(t, fault)
		signer, key := managedPairwiseFixture(t, &f)
		p := f.oauth.Protocol.ManagedClients
		p.Redirects = []string{"https://managed.example/callback", "https://managed.example/new", "https://foreign.example/new"}
		p.PostLogoutRedirects = []string{"https://managed.example/signed-out"}
		registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "managed.example", "subjects", 1)
		p.PairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
		appendRetainedClientUpdates(t, &f, true)
		p.ConfidentialOIDCUpdates, p.ConfidentialPairwiseUpdates = true, true
		policy := randomPairwisePolicy(t, f, 1)
		core, child, store := managedPairwiseServices(t, f, signer, key, policy)
		registered, err := policy.KeyRegistration(1)
		if err != nil || store.InstallSubjectKey(f.ctx, registered) != nil || store.ActivateSubjectKey(f.ctx, "subjects", 1, 1) != nil {
			t.Fatal("retained pairwise fixture key custody failed", err)
		}
		request := clientCreateRequest(t, f, "retained-outcome-create")
		request.Scopes, request.SubjectRegistration = []string{"openid"}, &registration
		created, err := core.ClientCreate(f.ctx, request)
		if err != nil {
			t.Fatal("retained pairwise fixture creation failed", err)
		}
		return retainedMutationFixture{f, core, child, store, created.Client}
	}
	schema := nativeProfileSchema()
	f = passwordFixtureWithProfileSchema(t, false, &schema, fault)
	signer, key := managedClaimsFixture(t, &f, true)
	selectManagedClaims(&f)
	p := f.oauth.Protocol.ManagedClients
	p.Redirects = []string{"https://managed.example/callback", "https://managed.example/new"}
	p.PostLogoutRedirects = []string{"https://managed.example/signed-out"}
	appendRetainedClientUpdates(t, &f, false)
	p.PublicOIDCUpdates, p.PublicOIDCClaimsUpdates = true, true
	core, child, store := managedClaimsServices(t, f, signer, key)
	client := createManagedClaimsClient(t, f, core, "retained-outcome-create")
	return retainedMutationFixture{f, core, child, store, client}
}

func requireRetainedMutationState(t *testing.T, x retainedMutationFixture, original confidentialUpdateState, version string, effects int) {
	t.Helper()
	if x.client.Public {
		requirePublicUpdateState(t, x.f, x.client, version, "active", effects)
		return
	}
	requireConfidentialUpdateState(t, confidentialUpdateFixture{f: x.f, client: x.client}, original, version, effects)
}

func TestNativeRetainedOIDCClientUpdateCurrentAuthorityAndRecovery(t *testing.T) {
	for _, kind := range []string{"pairwise", "claims"} {
		for _, outcome := range []string{"denials", "outbox", "unknown"} {
			t.Run(kind+"/"+outcome, func(t *testing.T) {
				fault := &oauthCommitFault{}
				x := newRetainedMutationFixture(t, kind, fault)
				before := readConfidentialUpdateState(t, confidentialUpdateFixture{f: x.f, client: x.client})
				request := retainedOIDCReplacement(t, x.f, x.client, "retained-original-"+outcome)
				policy := x.f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
				if outcome == "denials" {
					for _, variant := range []string{"owner", "csrf", "stale", "withdrawn", "subject", "sector", "unselected"} {
						denied := request
						denied.Management.RequestKey, _ = identity.NewIdempotencyKey([]byte("retained-denied-" + variant))
						core, store := x.core, x.store
						switch variant {
						case "owner":
							denied.Management.Owner, _ = oauth.NewPlatformOwner("foreign")
						case "csrf":
							denied.Management.CSRF, _ = session.NewCSRFToken()
						case "stale":
							denied.Management.Version++
						case "withdrawn":
							policy.denied.Store(true)
						case "subject":
							registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "managed.example", "other-key", 1)
							denied.Management.SubjectRegistration = &registration
						case "sector":
							denied.Redirects = []string{"https://foreign.example/new"}
						case "unselected":
							config := x.f.oauth
							selection := *config.Protocol.ManagedClients
							selection.ConfidentialPairwiseUpdates, selection.PublicOIDCClaimsUpdates = false, false
							config.Protocol.ManagedClients = &selection
							var err error
							core, err = oauthpostgres.NewService(x.f.pool, config, x.f.keys)
							if err != nil {
								t.Fatal(err)
							}
							core, err = core.WithOIDC(x.child)
							if err != nil {
								t.Fatal(err)
							}
							store, err = oauthpostgres.NewStore(x.f.pool, config, x.f.keys)
							if err != nil {
								t.Fatal(err)
							}
						}
						out, err := core.ClientUpdate(x.f.ctx, denied)
						policy.denied.Store(false)
						if err == nil || out.Client.ID != "" {
							t.Fatal("retained-class update bypassed current authority or immutable registration", variant, err)
						}
						if variant == "unselected" {
							out, err = store.UpdateClient(x.f.ctx, oauth.ClientUpdateExecution{Request: denied, Session: originalClientRead(t, x.f).Session})
							if err == nil || out.Client.ID != "" {
								t.Fatal("direct native owner ignored explicit operation selection", err)
							}
						}
						requireRetainedMutationState(t, x, before, "1", 0)
					}
				} else if outcome == "outbox" {
					if _, err := x.f.pool.Raw().Exec(x.f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_retained_update CHECK(topic<>'oauth_client.configuration_changed.v1') NOT VALID`); err != nil {
						t.Fatal(err)
					}
				} else {
					fault.armed.Store(true)
				}
				out, err := x.core.ClientUpdate(x.f.ctx, request)
				if outcome == "denials" {
					if err != nil || out.Client.Version != 2 {
						t.Fatal("denials stranded genuine retained-class update", err)
					}
					requireRetainedMutationState(t, x, before, "2", 1)
					return
				}
				if err == nil || out.Client.ID != "" {
					t.Fatal("required failure/unknown completion disclosed retained metadata", err)
				}
				if outcome == "outbox" {
					requireRetainedMutationState(t, x, before, "1", 0)
					return
				}
				if !fault.hit.Load() || out.Completion.Outcome != identity.CommitOutcomeUnknown || out.Completion.CommandID == "" {
					t.Fatal("actual retained update lost-COMMIT boundary missed")
				}
				recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-update", CommandID: out.Completion.CommandID, ClientID: x.client.ID, TenantID: x.f.tenant, Session: x.f.browser}
				deadline := time.Now().Add(8 * time.Second)
				for {
					known, err := x.store.Recover(x.f.ctx, recovery)
					if err == nil && known.Outcome == identity.CommitOutcomeCommitted {
						break
					}
					if err != nil && !errors.Is(err, oauth.ErrUnavailable) || time.Now().After(deadline) {
						t.Fatal("retained update original command could not reconcile", err)
					}
					select {
					case <-time.After(100 * time.Millisecond):
					case <-x.f.ctx.Done():
						t.Fatal("retained update recovery canceled")
					}
				}
				policy.denied.Store(true)
				denied, deniedErr := x.core.ClientUpdate(x.f.ctx, request)
				policy.denied.Store(false)
				if deniedErr == nil || denied.Client.ID != "" {
					t.Fatal("original retained update bypassed current withdrawal")
				}
				for i := 0; i < 2; i++ {
					known, err := x.core.ClientUpdate(x.f.ctx, request)
					if err != nil || !known.Completion.Replayed || known.Completion.CommandID != recovery.CommandID || known.Client.Version != 2 || !sameRegistration(known.Client.SubjectRegistration, x.client.SubjectRegistration) {
						t.Fatal("retained original replay changed subject policy or outcome", err)
					}
				}
				requireRetainedMutationState(t, x, before, "2", 1)
			})
		}
	}
}

func sameRegistration(a, b *oauth.OIDCSubjectRegistration) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
