//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/hibp"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	primitive "github.com/faustbrian/go-password/v2"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

type nativePhoneInput struct {
	signin               passwordpg.SigninConfig
	signup               passwordpg.SignupConfig
	hibp                 *hibp.Client
	keys                 *keyring.Provider
	password, sessionKey []byte
}

// Only application policy is selected here. The actual native services prove
// password, session, actor, tenant, action proof and purpose-bound OTP custody.
type nativePhonePolicy struct{ base authorization.Service }

func (p nativePhonePolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	r := c.Request
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" &&
		(r.Resource.Type == "identity.user" && string(r.Resource.ID) == string(r.Subject.ID) || r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action)) {
		switch r.Action {
		case "identity.password.verify", "identity.password.verify.recover", "identity.phone.send-verification", "identity.phone.send-verification.recover", "identity.phone.verify", "identity.phone.verify.recover", "identity.phone.remove", "identity.phone.remove.recover", "identity.phone.update", "identity.phone.update.recover":
			return authorization.Decision{Outcome: authorization.Allow, Revision: c.PolicyRevision}, ctx.Err()
		}
	}
	return p.base.Decide(ctx, c)
}

type nativePhoneFixture struct {
	service   *passwordpg.PhoneVerificationService
	send      phone.EnrollmentResultSpec
	flow      otp.SendFlow
	caller    authorization.DecisionContext
	code      string
	user      identity.UserID
	csrf      session.CSRFToken
	config    passwordpg.PhoneVerificationConfig
	signin    passwordpg.SigninConfig
	proof     passwordpg.ReauthenticationConfig
	numbers   *phone.NumberPolicy
	sms       otppg.PhoneEnrollmentIssuerConfig
	delivery  deliverypg.ContributorConfig
	templates []delivery.Template
}

func phoneAuthenticationRisk(t *testing.T, f authenticatedPasswordFixture) risk.AuthenticationAdmissionCustodyConfig {
	t.Helper()
	history, err := (riskpg.DurableCounterMigrationSource{Schema: "oidc_phone_counters", Version: 1}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
			t.Fatal("phone counted risk migration", err)
		}
	}
	policy, err := baselineRiskPolicy(9, false, false)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{121}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: f.pool, Schema: "oidc_phone_counters", Namespace: "oidc-phone", Policy: policy, Keys: []risk.CounterDigestKey{digest}, ReplayKey: bytes.Repeat([]byte{122}, 32), Tenants: []string{baselineTenant}, MaximumRecords: 1000, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: []risk.CounterDigestKey{digest}, Store: store, Clock: time.Now, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	sink, err := auditpg.New(f.pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	policyID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Counters: &counters, Clock: time.Now, Timeout: 2 * time.Second,
		DecisionAudit: &risk.DecisionAuditConfig{PolicyID: string(policyID), Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: func(ctx context.Context, lost risk.DecisionDelivery) error {
			_, err := sink.Append(ctx, lost.Record())
			return err
		}}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{123}, 32), bytes.Repeat([]byte{124}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "oidc-phone-risk-v1", Keys: []risk.EvidenceKey{key}}
}

type phoneSender func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error)

func (f phoneSender) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	return f(ctx, a)
}

// This is the published native phone composition, not fabricated verified SQL
// or an OTP double. Only its external SMS provider is replaced by a mailbox.
func pendingNativePhone(t *testing.T, f authenticatedPasswordFixture) *nativePhoneFixture {
	t.Helper()
	input := f.phoneInput
	c := input.signin
	c.Risk = phoneAuthenticationRisk(t, f)
	query := *c.Coordinator.QueryPolicy
	query.Authorization = nativePhonePolicy{base: query.Authorization}
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &query
	for _, source := range []migrations.Source{
		kernel.IdentifierNormalizationMigrationSource{Base: kernel.MigrationSource{}, Version: 1750},
		passwordpg.ActionReauthenticationMigrationSource{Base: passwordpg.EmailReauthenticationMigrationSource{}, Version: 1770},
		passwordpg.PhoneReauthenticationMigrationSource{Base: passwordpg.ActionReauthenticationMigrationSource{Base: passwordpg.EmailReauthenticationMigrationSource{}, Version: 1770}, Version: 1771},
	} {
		history, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Raw().Exec(f.ctx, history[len(history)-1].UpSQL()); err != nil {
			t.Fatal("phone native populated migration", err)
		}
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{127}, 32))
	signing, err := passwordpg.NewReauthenticationSigningKey("oidc-phone-reauth", private)
	if err != nil {
		t.Fatal(err)
	}
	target := passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.phone.send-verification", Audience: "oidc-phone-enrollment"}
	proofConfig := passwordpg.ReauthenticationConfig{Repository: c.Repository, Verifier: c.Verifier, Session: c.Session, Profile: c.Profile, LookupKeys: []session.DigestKey{c.Issuance.LookupKey}, Risk: c.Risk, Coordinator: c.Coordinator, SigningKey: signing, VerificationKeys: map[string]ed25519.PublicKey{"oidc-phone-reauth": private.Public().(ed25519.PublicKey)}, Issuer: c.Issuer, Environment: c.Environment, Targets: []passwordpg.ReauthenticationTarget{target}, TTL: time.Minute, IdentifierKey: bytes.Repeat([]byte{128}, 32)}
	proofOwner, err := passwordpg.NewReauthenticationService(f.pool, proofConfig)
	if err != nil {
		t.Fatal("phone native password proof owner", err)
	}
	secret, err := primitive.NewSecret(input.password)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	token, err := session.ParseToken(f.browser.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	original, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil || !original.Authenticated {
		t.Fatal("phone current genuine session", err)
	}
	bindings, err := original.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: authorization.TenantID(f.tenant), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(bindings.UserID)}, Action: "identity.phone.send-verification", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(bindings.UserID)}}}
	proof, err := proofOwner.Verify(f.ctx, passwordpg.ReauthenticationRequest{TenantID: f.tenant, Session: f.browser, Password: secret, Target: target, Caller: caller, Network: "192.0.2.10", Device: "oidc-phone-browser"})
	if err != nil || proof.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("phone genuine recent authentication", err)
	}
	primary, err := passwordpg.NewActionPrimarySource(proofOwner, passwordpg.ActionPrimaryConfig{Action: target.Action, Audience: target.Audience, MaximumAge: 2 * time.Minute, Transport: session.CredentialCookie, CSRFKeys: []session.CSRFKey{c.CSRFKey}})
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []migrations.Source{
		otppg.MigrationSource{Schema: "oidc_phone_codes", Version: 100}, otppg.LockoutMigrationSource{Schema: "oidc_phone_codes", Version: 101},
		otppg.ConsumingMigrationSource{Schema: "oidc_phone_codes", Version: 102}, otppg.SendFamilyMigrationSource{Schema: "oidc_phone_codes", Version: 103},
		otppg.IssuanceMigrationSource{Schema: "oidc_phone_codes", Version: 104}, otppg.PhonePurposeMigrationSource{Schema: "oidc_phone_codes", Version: 105},
	} {
		history, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history {
			if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
				t.Fatal("phone native OTP migration", err)
			}
		}
	}
	codec, err := otppg.NewAttemptCodec(otppg.AttemptCodecConfig{WrappingKeys: map[string][]byte{"phone-wrap": bytes.Repeat([]byte{129}, 32)}, CurrentWrappingKey: "phone-wrap", AttemptKeys: map[uint32][32]byte{1: {130}}, CodeKeys: map[uint32][32]byte{1: {131}}, CurrentCodeKeyVersion: 1, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(input.keys)
	if err != nil {
		t.Fatal(err)
	}
	templates := []delivery.Template{{ID: "oidc-phone-code", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Code: {{.code}}", ContentType: "text/plain", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128}}
	deliveryConfig := deliverypg.ContributorConfig{Deployment: "oidc-phone", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {132}}, ActiveEnvelopeKeyID: "delivery-envelope", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{2: {Provider: "oidc-sms", PolicyVersion: 1}}}
	deliveryOwner, err := deliverypg.NewContributor(deliveryConfig, crypto)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposePhoneVerification, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 5, Attempts: 5, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	sms := otppg.PhoneEnrollmentIssuerConfig{Store: otppg.ContributorConfig{Schema: "oidc_phone_codes", GlobalAuthorityID: c.Profile.GlobalAuthorityID, UserPolicyNamespace: c.Profile.PolicyNamespace, Codec: codec, LockoutKey: [32]byte{133}}, Session: otppg.SessionAdmissionConfig{Store: c.Session, Profile: c.Profile, RetainedTokenKeys: map[uint32][]byte{11: input.sessionKey}, FreshnessLimit: 10 * time.Minute}, Delivery: deliveryOwner, Policy: policy, TemplateID: "oidc-phone-code", TemplateVersion: 1, ProviderVersion: 2, LocaleChain: []string{"en"}, Templates: templates}
	issuer, err := otppg.NewPhoneEnrollmentIssuer(sms)
	if err != nil || issuer.Initialize(f.ctx, f.pool) != nil {
		t.Fatal("phone genuine OTP issuer", err)
	}
	numbers, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("oidc-phone", [32]byte{134}, query)
	if err != nil {
		t.Fatal(err)
	}
	config := passwordpg.PhoneVerificationConfig{PolicyID: "oidc-phone", ConfigurationID: "oidc-phone-v1", MaximumDuration: 5 * time.Second, Domain: kernel.PhoneEnrollmentDomainConfig{NormalizationProfile: numbers.Profile().ID, NormalizationVersion: numbers.Profile().Version, CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {135}}, ReuseCooldown: 30 * 24 * time.Hour}, RequestKeys: requestKeys, IntentKey: [32]byte{136}, IdentifierKey: [32]byte{137}, Risk: c.Risk, ActiveEnvelopeKeyID: "delivery-envelope", Issuer: issuer, CurrentAttemptKeyVersion: 1}
	service, err := passwordpg.NewPhoneVerificationService(primary, numbers, config, input.keys)
	if err != nil {
		t.Fatal("phone native composition", err)
	}
	if err := service.Initialize(f.ctx); err != nil {
		t.Fatal("phone native retained key initialization", err)
	}
	number, err := numbers.Canonicalize(f.ctx, "+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	idempotency, err := identity.NewIdempotencyKey([]byte("oidc-phone-native-enrollment"))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := phone.NewEnrollmentRequest(phone.EnrollmentRequestSpec{TenantID: f.tenant, UserID: bindings.UserID, Number: number, Session: f.browser, Proof: proof.Proof, Caller: caller, CSRFToken: f.csrf, IdempotencyKey: idempotency, Network: "192.0.2.10", Device: "oidc-phone-browser"})
	if err != nil {
		t.Fatal(err)
	}
	sent, err := service.SendVerification(f.ctx, enrollment)
	if err != nil {
		t.Fatal("phone native SendVerification", err)
	}
	send, err := sent.Bindings()
	if err != nil || send.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("phone native pending enrollment", err)
	}
	workerPolicy := delivery.DefaultConfig()
	workerPolicy.Production, workerPolicy.DedupeTTL = true, 25*time.Hour
	queue, err := deliverypg.NewEnqueueService(f.ctx, f.pool, deliverypg.EnqueueConfig{Custody: deliveryConfig, Coordinator: c.Coordinator, PolicyID: "oidc-phone-worker", PolicyVersion: 9, AuditRetentionVersion: 1, Timeout: 3 * time.Second, NamespaceKey: [32]byte{138}, Policies: map[uint64]delivery.Config{1: workerPolicy}, StateTracking: true}, crypto, query.Authorization, templates)
	if err != nil {
		t.Fatal("native phone delivery worker configuration", err)
	}
	var code string
	worker, err := queue.NewWorker(deliverypg.WorkerConfig{Scope: authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "phone-worker", Request: authorization.Request{Tenant: baselineTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "baseline-worker"}, Action: "identity.delivery.process", Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "baseline-worker"}}}, ProviderConfigVersion: 2}, phoneSender(func(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
		if a.Recipient != "+12025550123" || !strings.HasPrefix(a.Body, "Code: ") {
			t.Error("phone provider received a changed canonical recipient or template")
		}
		code = strings.TrimPrefix(a.Body, "Code: ")
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, ctx.Err()
	}))
	if err != nil {
		t.Fatal(err)
	}
	processed, err := worker.ProcessOne(f.ctx)
	if err != nil || !processed.Claimed || len(code) != 6 {
		t.Fatal("phone actual encrypted SMS delivery", err)
	}
	flow, err := otp.NewSessionSendFlow(bindings.SessionID, f.browser)
	if err != nil {
		t.Fatal(err)
	}
	caller.Request.Action = "identity.phone.verify"
	return &nativePhoneFixture{service: service, send: send, flow: flow, caller: caller, code: code, user: bindings.UserID, csrf: f.csrf, config: config, signin: c, proof: proofConfig, numbers: numbers, sms: sms, delivery: deliveryConfig, templates: templates}
}

func (p *nativePhoneFixture) verify(t *testing.T, f authenticatedPasswordFixture, wrong bool) {
	t.Helper()
	code := []byte(p.code)
	if wrong {
		code[0] = '0' + (code[0]-'0'+1)%10
	}
	credential, err := auth.NewOneTimeCode(string(code))
	clear(code)
	if err != nil {
		t.Fatal(err)
	}
	request, err := phone.NewVerificationRequest(phone.VerificationRequestSpec{TenantID: f.tenant, UserID: p.user, Caller: p.caller, Flow: p.flow, SendCommandID: p.send.Binding.CommandID, Code: credential, CSRFToken: p.csrf})
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.service.Verify(f.ctx, request)
	if wrong {
		if err == nil {
			t.Fatal("genuine wrong OTP verified a phone")
		}
		return
	}
	if err != nil {
		t.Fatal("phone actual native Verify", err)
	}
	bound, err := result.Bindings()
	if err != nil || bound.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("phone verification did not commit", err)
	}
	p.code = ""
}
