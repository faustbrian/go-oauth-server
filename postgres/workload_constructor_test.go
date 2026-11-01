package oauthpostgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	password "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/jackc/pgx/v5"
)

func TestConfiguredWorkloadConstructorsValidateCoordinatorWithoutIO(t *testing.T) {
	pool, err := database.Connect(t.Context(), database.Config{
		DSN: "postgres://constructor@127.0.0.1:1/unused?sslmode=disable", StartupPolicy: database.StartupLazy,
		Configure: func(c *database.PoolConfig) error {
			c.BeforeConnect = func(context.Context, *pgx.ConnConfig) error {
				t.Error("native construction attempted database IO")
				return errors.New("constructor database IO forbidden")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	for _, tc := range []struct {
		name   string
		mutate func(*oauthpostgres.Config)
	}{
		{"zero lease", func(c *oauthpostgres.Config) { c.Coordinator.LeaseDuration = 0 }},
		{"missing fingerprint keys", func(c *oauthpostgres.Config) { c.Coordinator.RetainedFingerprintKeys = nil }},
		{"zero fingerprint material", func(c *oauthpostgres.Config) { c.Coordinator.RetainedFingerprintKeys[1] = [32]byte{} }},
		{"zero fingerprint version", func(c *oauthpostgres.Config) { c.Coordinator.CurrentFingerprintKeyVersion = 0 }},
		{"unretained fingerprint version", func(c *oauthpostgres.Config) { c.Coordinator.CurrentFingerprintKeyVersion = 2 }},
		{"missing request keys", func(c *oauthpostgres.Config) { c.RequestKeys = kernel.RequestKeyConfig{} }},
		{"malformed request namespace", func(c *oauthpostgres.Config) { c.RequestKeys.Namespace = "" }},
		{"valid without schema", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, keys := workloadConstructorConfig(t)
			if tc.mutate != nil {
				tc.mutate(&config)
			}
			store, storeErr := oauthpostgres.NewStore(pool, config, keys)
			service, serviceErr := oauthpostgres.NewService(pool, config, keys)
			if tc.mutate == nil {
				if storeErr != nil || serviceErr != nil || store == nil || service == nil {
					t.Fatal("valid configured workload required database installation", storeErr, serviceErr)
				}
				return
			}
			if !errors.Is(storeErr, oauth.ErrInvalidRequest) || store != nil {
				t.Error("NewStore accepted unusable workload coordinator", storeErr)
			}
			if !errors.Is(serviceErr, oauth.ErrInvalidRequest) || service != nil {
				t.Error("NewService accepted unusable workload coordinator", serviceErr)
			}
		})
	}
}

type constructorAuthorization struct{ t *testing.T }

func (a constructorAuthorization) Decide(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
	a.t.Error("native construction invoked authorization")
	return authorization.Decision{Outcome: authorization.Deny}, nil
}

func workloadConstructorConfig(t *testing.T) (oauthpostgres.Config, *keyring.Provider) {
	t.Helper()
	material := func(label byte) []byte {
		value := make([]byte, 32)
		value[0] = label
		return value
	}
	issuer, err := oauth.NewIssuer("https://issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := oauth.NewPlatformOwner("deployment")
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := oauth.NewScopeCatalog([]string{"workload:read"})
	if err != nil {
		t.Fatal(err)
	}
	workload, err := oauth.NewWorkload("tenant", "worker", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := oauth.Client{ID: "machine-client", Owner: owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: "https://resource.example", Scopes: scopes.Scopes(), Workload: workload}
	secret, err := password.NewSecret([]byte(base64.RawURLEncoding.EncodeToString(material(1))))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	verifier, err := oauth.NewClientSecretVerifier(client.ID, client.Version, secret)
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Clock: clock.System{}, Authorization: constructorAuthorization{t}, PolicyVersion: 9}
	requestKeys, err := kernel.NewRequestKeyConfig("oauth-workload", [32]byte{2}, query)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 9, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Minute, Limit: 10, ThresholdAction: risk.Deny, EvidenceTTL: time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	digestKey, err := risk.NewCounterDigestKey(1, material(3))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := risk.NewEvidenceKey(1, material(4), material(5))
	if err != nil {
		t.Fatal(err)
	}
	tokenKey, err := oauth.NewTokenDigestKey(1, material(6))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.New(map[string][]byte{"oauth-envelope": material(7)})
	if err != nil {
		t.Fatal(err)
	}
	return oauthpostgres.Config{
		Schema: "oauth_store", Protocol: oauth.Config{Issuer: issuer, Environment: "constructor-test", Resource: client.Resource, Scopes: scopes, Clients: []oauth.Client{client}, ClientSecrets: []oauth.ClientSecretVerifier{verifier}, Clock: clock.System{}, MaximumDuration: 4 * time.Second, CodeTTL: time.Minute, ContinuationTTL: time.Minute, AccessTTL: time.Minute, RefreshTTL: time.Hour},
		WorkloadAuthority: oauthpostgres.WorkloadAuthorityConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "oauth-workloads"},
		TokenKeys:         []oauth.TokenDigestKey{tokenKey}, ActiveTokenKeyVersion: 1, IntentKey: [32]byte{8}, ActiveEnvelopeKeyID: "oauth-envelope", PolicyID: "oauth-native",
		Coordinator: kernel.CoordinatorConfig{MaximumDuration: 4 * time.Second, LeaseDuration: 5 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {9}}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys,
		Counters: riskpg.Config{Schema: "risk_store", PolicyVersion: 9, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": material(10)}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{digestKey}}, EnforceLockouts: true},
	}, keys
}
