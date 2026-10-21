//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/hibp"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	oauth "github.com/faustbrian/go-oauth-server"
	primitive "github.com/faustbrian/go-password/v2"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

func phoneLifecycleMigrations(t *testing.T, f authenticatedPasswordFixture) {
	t.Helper()
	base := kernel.IdentifierRemovalCascadeMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 1751}
	removal := kernel.PhoneRemovalCascadeMigrationSource{Base: base, Version: 1752}
	proof := passwordpg.PhoneReauthenticationMigrationSource{Base: passwordpg.ActionReauthenticationMigrationSource{Base: passwordpg.EmailReauthenticationMigrationSource{}, Version: 1770}, Version: 1771}
	for _, source := range []migrations.Source{
		base, removal, kernel.PhoneChangeCascadeMigrationSource{Base: removal, Version: 1753},
		passwordpg.PhoneRemovalReauthenticationMigrationSource{Base: proof, Version: 1772},
		passwordpg.PhoneChangeReauthenticationMigrationSource{Base: passwordpg.PhoneRemovalReauthenticationMigrationSource{Base: proof, Version: 1772}, Version: 1773},
	} {
		history, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
			t.Fatal("native phone lifecycle populated migration", err)
		}
	}
}

func phoneProtectedRisk(t *testing.T, f authenticatedPasswordFixture, p *nativePhoneFixture) (riskpg.Config, risk.ProtectedProviderAdmissionCustodyConfig) {
	t.Helper()
	history, err := (riskpg.LockoutMigrationSource{Base: riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "oidc_phone_mutations", Version: 1}, Version: 2}, Version: 3}, Version: 4}, Version: 5}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	policy, err := baselineRiskPolicy(9, false, false)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{170}, 32))
	if err != nil {
		t.Fatal(err)
	}
	// The selected policy requires only velocity, whose authoritative mutation
	// remains in the native command counter participant, not an invented signal.
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: time.Now, Timeout: time.Second, Sources: []risk.Source{{Name: "velocity", Version: "native-command-counter-v1", Timeout: time.Second, Read: func(context.Context, risk.Context) (risk.Signal, error) {
		return risk.Signal{}, errors.New("velocity is owned by native command counters")
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	counters := riskpg.Config{Schema: "oidc_phone_mutations", PolicyVersion: 9, EvidenceKeys: p.signin.Risk.Keys, EnvelopeKeys: map[string][]byte{"wrap": bytes.Repeat([]byte{171}, 32)}, CurrentEnvelopeKey: "wrap", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{digest}}, EnforceLockouts: true}
	return counters, risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "oidc-phone-mutations-v1", Keys: p.signin.Risk.Keys}
}

func phoneResetOwner(t *testing.T, f authenticatedPasswordFixture, p *nativePhoneFixture) *passwordpg.ResetService {
	t.Helper()
	c := f.phoneInput.signup
	signer, err := capability.NewHMACSHA256Signer("oidc-phone-reset", bytes.Repeat([]byte{164}, 32))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{164}, 32))
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: p.signin.Issuer, ID: "oidc-phone-reset", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(f.phoneInput.keys)
	if err != nil {
		t.Fatal(err)
	}
	deliveryConfig := p.delivery
	deliveryConfig.Deployment = "oidc-phone-reset"
	deliveryConfig.ProviderProfiles = map[uint64]deliverypg.ProviderProfile{3: {Provider: "oidc-reset-email", PolicyVersion: 1}}
	owner, err := deliverypg.NewContributor(deliveryConfig, crypto)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "oidc-phone-reset", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "Reset: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{p.signin.Issuer}, MaxRenderedBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("oidc-phone-reset", [32]byte{165}, *p.signin.Coordinator.QueryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	screeningPolicy, err := baselineRiskPolicy(3, true, true)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := hibp.NewSignalProvider(f.phoneInput.hibp, screeningPolicy)
	if err != nil {
		t.Fatal(err)
	}
	screening := c.Screening
	screening.Policy = screeningPolicy
	screening.Collect = func(ctx context.Context, scope risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		command, err := identity.ParseCommandID(scope.Attempt)
		if err != nil {
			return nil, err
		}
		signal, err := provider.Assess(ctx, hibp.CheckRequest{OperationID: "identity.password.reset-complete", TenantID: identity.TenantID(scope.Tenant), Action: scope.Operation, Purpose: "identity.password.reset-complete", SubjectScope: "password-screening", PolicyVersion: "oidc-phone-reset-v1", ReplayID: command, Candidate: candidate})
		return []risk.Signal{signal}, err
	}
	callback := p.signin.Issuer + "/reset"
	deliveryProfile := c.Delivery
	deliveryProfile.Owner, deliveryProfile.Renderer, deliveryProfile.Resolver = owner, renderer, resolver
	deliveryProfile.Endpoint, deliveryProfile.TemplateID, deliveryProfile.TemplateVersion, deliveryProfile.ProviderVersion = callback, "oidc-phone-reset", 1, 3
	config := passwordpg.ResetConfig{Repository: c.Repository, ConfigurationID: "oidc-phone-reset-v1", PolicyID: "oidc-phone-reset", Profile: password.ResetProfileConfig{Issuer: p.signin.Issuer, Audience: "oidc-phone-reset", MaximumLifetime: 2 * time.Minute, Callbacks: []string{callback}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {166}}}, Issuer: issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: p.signin.Issuer, Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "oidc-phone-reset", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {167}}, PreparationTimeout: time.Second}, Screening: screening, Risk: p.signin.Risk, Coordinator: p.signin.Coordinator, Session: p.signin.Session, GlobalAuthorityID: p.signin.Profile.GlobalAuthorityID, AuthorizationNamespace: p.signin.Profile.PolicyNamespace, Origins: c.Origins, ActiveEnvelopeKeyID: c.ActiveEnvelopeKeyID, IdentifierKey: [32]byte{168}, Request: &passwordpg.ResetRequestConfig{Address: c.Address, RequestKeys: requestKeys, Lifetime: time.Minute, IssuanceCustody: issuerpg.IssuancePreparationConfig{Deployment: "oidc-phone-reset", ActiveEnvelopeKey: "oidc-phone-reset", EnvelopeKeys: map[string][]byte{"oidc-phone-reset": bytes.Repeat([]byte{169}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "oidc-phone-reset", HMAC: bytes.Repeat([]byte{164}, 32)}}, Clock: time.Now}, Delivery: deliveryProfile}}
	reset, err := passwordpg.NewResetService(f.pool, config, f.phoneInput.keys)
	if err != nil {
		t.Fatal("native compatible independent reset owner", err)
	}
	return reset
}

func phoneAction(t *testing.T, f authenticatedPasswordFixture, p *nativePhoneFixture, action string) (*passwordpg.ActionPrimarySource, auth.ReauthenticationProof) {
	t.Helper()
	c := p.proof
	target := passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: action, Audience: "oidc-phone-lifecycle"}
	c.Targets = append(c.Targets, target)
	owner, err := passwordpg.NewReauthenticationService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := primitive.NewSecret(f.phoneInput.password)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	caller := p.caller.Clone()
	caller.Request.Action = authorization.Action(target.Action)
	proof, err := owner.Verify(f.ctx, passwordpg.ReauthenticationRequest{TenantID: f.tenant, Session: f.browser, Password: secret, Target: target, Caller: caller, Network: "192.0.2.10", Device: "oidc-phone-browser"})
	if err != nil || proof.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native phone action reauthentication", err)
	}
	primary, err := passwordpg.NewActionPrimarySource(owner, passwordpg.ActionPrimaryConfig{Action: action, Audience: target.Audience, MaximumAge: 2 * time.Minute, Transport: session.CredentialCookie, CSRFKeys: []session.CSRFKey{p.signin.CSRFKey}})
	if err != nil {
		t.Fatal(err)
	}
	return primary, proof.Proof
}

// These fingerprints identify the declared test-consumer contracts only. They
// are not adapter acknowledgements: the actual native mutation records pending
// cascade rows, and these tests make no claim that downstream cleanup completed.
func phoneCascade(change bool) kernel.IdentifierRemovalCascadeConfig {
	c := kernel.IdentifierRemovalCascadeConfig{PolicyVersion: 101, Reasons: []string{"user-requested"}, MaximumDuration: time.Hour, ConsumerContracts: map[string]kernel.StatusConsumerContract{}}
	consumers := identity.IdentifierRemovalConsumers()
	if change {
		consumers = identity.IdentifierChangeConsumers()
	}
	for _, id := range consumers {
		c.ConsumerContracts[id] = kernel.StatusConsumerContract{Version: 1, Fingerprint: sha256.Sum256([]byte("oidc-phone-test-consumer-contract-v1:" + id))}
	}
	return c
}

func (p *nativePhoneFixture) remove(t *testing.T, f authenticatedPasswordFixture) identity.CommandResult {
	t.Helper()
	primary, proof := phoneAction(t, f, p, "identity.phone.remove")
	signin, err := passwordpg.NewSigninService(f.pool, p.signin)
	if err != nil {
		t.Fatal(err)
	}
	reset := phoneResetOwner(t, f, p)
	counters, risk := phoneProtectedRisk(t, f, p)
	requestKeys, err := kernel.NewRequestKeyConfig("oidc-phone-remove", [32]byte{172}, *p.signin.Coordinator.QueryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	notice := passwordpg.PhoneRemovalNoticeConfig{Delivery: p.delivery, Templates: []delivery.Template{{ID: "phone-removed", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Your phone number was removed.", ContentType: "text/plain", MaxRenderedBytes: 128}}, TemplateID: "phone-removed", TemplateVersion: 1, ProviderVersion: 2, LocaleChain: []string{"en"}, TTL: time.Hour}
	service, err := passwordpg.NewPhoneRemovalService(primary, signin, reset, p.numbers, passwordpg.PhoneRemovalConfig{PolicyID: "oidc-phone-remove", ConfigurationID: "oidc-phone-remove-v1", MaximumDuration: 5 * time.Second, Domain: kernel.PhoneRemovalDomainConfig{Directory: p.config.Domain, Cascade: phoneCascade(false)}, RequestKeys: requestKeys, IntentKey: [32]byte{173}, Risk: risk, Counters: counters, ActiveEnvelopeKeyID: "delivery-envelope", Notice: notice}, f.phoneInput.keys)
	if err != nil {
		t.Fatal("native phone removal composition", err)
	}
	identifier, verification := p.current(t, f)
	number, err := p.numbers.Canonicalize(f.ctx, identifier.CanonicalValue)
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("oidc-native-phone-remove"))
	if err != nil {
		t.Fatal(err)
	}
	caller := p.caller.Clone()
	caller.Request.Action = "identity.phone.remove"
	request, err := phone.NewRemoveRequest(phone.RemoveRequestSpec{TenantID: f.tenant, UserID: p.user, Number: number, IdentifierID: identifier.ID, ExpectedIdentifierVersion: identifier.Version, ExpectedVerificationVersion: verification.Version, Reason: "user-requested", Session: f.browser, Proof: proof, CSRFToken: f.csrf, IdempotencyKey: key, Caller: caller, Network: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Remove(f.ctx, request)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual native phone Remove", err)
	}
	return result
}

func (p *nativePhoneFixture) current(t *testing.T, f authenticatedPasswordFixture) (identity.Identifier, identity.Verification) {
	t.Helper()
	owner, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	state, err := owner.GetIdentifierState(f.ctx, identity.IdentifierQuery{TenantID: f.tenant, UserID: p.user, MaximumIdentifiers: 128})
	if err != nil {
		t.Fatal(err)
	}
	for j, identifier := range state.Identifiers {
		if identifier.ID == p.send.IdentifierID {
			return identifier, state.Verifications[j]
		}
	}
	t.Fatal("native phone target absent")
	return identity.Identifier{}, identity.Verification{}
}

func TestNativeOIDCPhoneRemovalWithdrawsOriginalGrant(t *testing.T) {
	f := passwordFixture(t)
	p := pendingNativePhone(t, f)
	p.verify(t, f, false)
	f.browser, f.csrf = f.signInAgain()
	service, child, _, _, _ := phoneFixture(t, &f)
	code, verifier := oidcCode(t, f, service, "phone-removal")
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}
	before, err := child.UserInfo(f.ctx, request)
	if err != nil || before.PhoneNumber != "+12025550123" {
		t.Fatal("native phone missing before removal", err)
	}
	phoneLifecycleMigrations(t, f)
	removed := p.remove(t, f)
	if removed.Cascade == nil || removed.Cascade.Status != identity.RevocationPending {
		t.Fatal("native removal did not retain pending cascade")
	}
	if out, err := child.UserInfo(f.ctx, request); err == nil || out.Subject != "" || out.PhoneNumber != "" {
		t.Fatal("native removal did not withdraw original phone grant", err)
	}
	f.browser, f.csrf = f.signInAgain()
	code, verifier = oidcCode(t, f, service, "phone-after-removal")
	fresh, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	next, err := fresh.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	after, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: next})
	if err != nil || after.Subject != before.Subject || after.PhoneNumber != "" || after.PhoneNumberVerified != nil {
		t.Fatal("fresh grant did not omit removed number with same subject", err)
	}
}

func (p *nativePhoneFixture) replace(t *testing.T, f authenticatedPasswordFixture) identity.CommandResult {
	t.Helper()
	sendPrimary, sendProof := phoneAction(t, f, p, "identity.phone.send-verification")
	updatePrimary, updateProof := phoneAction(t, f, p, "identity.phone.update")
	signin, err := passwordpg.NewSigninService(f.pool, p.signin)
	if err != nil {
		t.Fatal(err)
	}
	reset := phoneResetOwner(t, f, p)
	issuer, err := otppg.NewPhoneChangeIssuer(p.sms)
	if err != nil {
		t.Fatal(err)
	}
	counters, protected := phoneProtectedRisk(t, f, p)
	requestKeys, err := kernel.NewRequestKeyConfig("oidc-phone-change", [32]byte{174}, *p.signin.Coordinator.QueryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	notice := passwordpg.PhoneRemovalNoticeConfig{Delivery: p.delivery, Templates: []delivery.Template{{ID: "phone-changed", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Your phone number was changed.", ContentType: "text/plain", MaxRenderedBytes: 128}}, TemplateID: "phone-changed", TemplateVersion: 1, ProviderVersion: 2, LocaleChain: []string{"en"}, TTL: time.Hour}
	service, err := passwordpg.NewPhoneChangeService(sendPrimary, updatePrimary, signin, reset, p.numbers, passwordpg.PhoneChangeConfig{PolicyID: "oidc-phone-change", ConfigurationID: "oidc-phone-change-v1", Reason: "user-requested", MaximumDuration: 5 * time.Second, Domain: kernel.PhoneChangeDomainConfig{Directory: p.config.Domain, Cascade: phoneCascade(true)}, RequestKeys: requestKeys, IntentKey: [32]byte{175}, IdentifierKey: [32]byte{176}, AuthenticationRisk: p.signin.Risk, UpdateRisk: protected, Counters: counters, ActiveEnvelopeKeyID: "delivery-envelope", Issuer: issuer, CurrentAttemptKeyVersion: 1, Notice: notice}, f.phoneInput.keys)
	if err != nil {
		t.Fatal("actual native phone replacement composition", err)
	}
	if err := service.Initialize(f.ctx); err != nil {
		t.Fatal(err)
	}
	identifier, verification := p.current(t, f)
	old, err := p.numbers.Canonicalize(f.ctx, identifier.CanonicalValue)
	if err != nil {
		t.Fatal(err)
	}
	next, err := p.numbers.Canonicalize(f.ctx, "+358401234567")
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("oidc-native-phone-change-send"))
	if err != nil {
		t.Fatal(err)
	}
	caller := p.caller.Clone()
	caller.Request.Action = "identity.phone.send-verification"
	request, err := phone.NewChangeRequest(phone.ChangeRequestSpec{Enrollment: phone.EnrollmentRequestSpec{TenantID: f.tenant, UserID: p.user, Number: next, Session: f.browser, Proof: sendProof, Caller: caller, CSRFToken: f.csrf, IdempotencyKey: key, Network: "192.0.2.10", Device: "oidc-phone-browser"}, PreviousNumber: old, IdentifierID: identifier.ID, ExpectedIdentifierVersion: identifier.Version, ExpectedVerificationVersion: verification.Version})
	if err != nil {
		t.Fatal(err)
	}
	sent, err := service.SendChange(f.ctx, request)
	if err != nil || sent.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual native phone SendChange", err)
	}
	crypto, err := envelope.NewService(f.phoneInput.keys)
	if err != nil {
		t.Fatal(err)
	}
	workerPolicy := delivery.DefaultConfig()
	workerPolicy.Production, workerPolicy.DedupeTTL = true, 25*time.Hour
	queue, err := deliverypg.NewEnqueueService(f.ctx, f.pool, deliverypg.EnqueueConfig{Custody: p.delivery, Coordinator: p.signin.Coordinator, PolicyID: "oidc-phone-worker", PolicyVersion: 9, AuditRetentionVersion: 1, Timeout: 3 * time.Second, NamespaceKey: [32]byte{138}, Policies: map[uint64]delivery.Config{1: workerPolicy}, StateTracking: true}, crypto, p.signin.Coordinator.QueryPolicy.Authorization, p.templates)
	if err != nil {
		t.Fatal(err)
	}
	var captured string
	worker, err := queue.NewWorker(deliverypg.WorkerConfig{Scope: authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "phone-replacement-worker", Request: authorization.Request{Tenant: baselineTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "baseline-worker"}, Action: "identity.delivery.process", Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "baseline-worker"}}}, ProviderConfigVersion: 2}, phoneSender(func(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
		if a.Recipient != "+358401234567" || !strings.HasPrefix(a.Body, "Code: ") {
			t.Error("replacement SMS recipient/template changed")
		}
		captured = strings.TrimPrefix(a.Body, "Code: ")
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, ctx.Err()
	}))
	if err != nil {
		t.Fatal(err)
	}
	processed, err := worker.ProcessOne(f.ctx)
	if err != nil || !processed.Claimed || len(captured) != 6 {
		t.Fatal("actual native replacement SMS delivery", err)
	}
	token, err := session.ParseToken(f.browser.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("current native replacement session", err)
	}
	bindings, err := current.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	flow, err := otp.NewSessionSendFlow(bindings.SessionID, f.browser)
	if err != nil {
		t.Fatal(err)
	}
	code, err := auth.NewOneTimeCode(captured)
	captured = ""
	if err != nil {
		t.Fatal(err)
	}
	key, err = identity.NewIdempotencyKey([]byte("oidc-native-phone-change-update"))
	if err != nil {
		t.Fatal(err)
	}
	caller.Request.Action = "identity.phone.update"
	completion, err := phone.NewUpdateRequest(phone.UpdateRequestSpec{TenantID: f.tenant, UserID: p.user, Caller: caller, Flow: flow, SendCommandID: sent.Binding.CommandID, Code: code, Proof: updateProof, CSRFToken: f.csrf, Reason: "user-requested", IdempotencyKey: key})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Update(f.ctx, completion)
	if err != nil || result.Result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual native phone Update", err)
	}
	return result.Result
}

func TestNativeOIDCPhoneReplacementWithdrawsOriginalGrant(t *testing.T) {
	f := passwordFixture(t)
	p := pendingNativePhone(t, f)
	p.verify(t, f, false)
	f.browser, f.csrf = f.signInAgain()
	service, child, _, _, _ := phoneFixture(t, &f)
	code, verifier := oidcCode(t, f, service, "phone-replacement")
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}
	before, err := child.UserInfo(f.ctx, request)
	if err != nil || before.PhoneNumber != "+12025550123" {
		t.Fatal("native phone missing before replacement", err)
	}
	phoneLifecycleMigrations(t, f)
	changed := p.replace(t, f)
	if changed.Cascade == nil || changed.Cascade.Status != identity.RevocationPending {
		t.Fatal("replacement did not retain pending cascade")
	}
	if out, err := child.UserInfo(f.ctx, request); err == nil || out.Subject != "" || out.PhoneNumber != "" {
		t.Fatal("native replacement silently changed old grant's contact", err)
	}
	f.browser, f.csrf = f.signInAgain()
	code, verifier = oidcCode(t, f, service, "phone-after-replacement")
	fresh, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	next, err := fresh.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	after, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: next})
	if err != nil || after.Subject != before.Subject || after.PhoneNumber != "+358401234567" || after.PhoneNumberVerified == nil || !*after.PhoneNumberVerified {
		t.Fatal("fresh grant did not reflect genuinely verified replacement with same subject", err)
	}
}
