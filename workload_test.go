package oauthserver_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	password "github.com/faustbrian/go-password/v2"
)

func workloadCoreConfig(t *testing.T) (oauth.Config, oauth.ClientAuthentication) {
	t.Helper()
	config := coreConfig(t, time.Now().UTC())
	client := &config.Clients[0]
	client.Public, client.AuthenticationMethod, client.Redirects = false, "client_secret_basic", nil
	var err error
	client.Workload, err = oauth.NewWorkload("machine-tenant", "worker-a", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := password.NewSecret([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oauth.NewClientSecretVerifier(client.ID, client.Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	config.ClientSecrets = []oauth.ClientSecretVerifier{verifier}
	credential, err := oauth.ParseClientAuthentication([]string{clientBasicHeader(client.ID, wire)})
	if err != nil {
		t.Fatal(err)
	}
	return config, credential
}

// This seam observes root admission/output rules only, never native issuance.
type workloadBoundaryStore struct {
	oauth.Store
	call func(context.Context, oauth.TokenCommand) (oauth.TokenResult, error)
}

func (s workloadBoundaryStore) Token(ctx context.Context, c oauth.TokenCommand) (oauth.TokenResult, error) {
	return s.call(ctx, c)
}

func TestConfiguredWorkloadTokenHasNoHumanSessionOrRefresh(t *testing.T) {
	config, credential := workloadCoreConfig(t)
	calls := 0
	store := workloadBoundaryStore{call: func(ctx context.Context, c oauth.TokenCommand) (oauth.TokenResult, error) {
		calls++
		if c.Client.Workload == nil || c.Client.Workload.TenantID() != "machine-tenant" || c.Client.Workload.ID() != "worker-a" || c.Request.GrantType != oauth.ClientCredentialsGrant || c.Request.Resource != config.Resource {
			t.Fatal("workload lost configured tenant/actor/resource binding")
		}
		access, err := oauth.NewToken()
		return oauth.TokenResult{Outcome: identity.CommitOutcomeCommitted, AccessToken: access, Resource: config.Resource, Scopes: c.Request.Scopes, ExpiresAt: config.Clock.Now().Add(30 * time.Second)}, err
	}}
	service, err := oauth.NewService(config, oauth.Dependencies{Store: store})
	if err != nil {
		t.Fatal("workload-only composition required a manufactured session", err)
	}
	request := oauth.TokenRequest{GrantType: oauth.ClientCredentialsGrant, ClientID: config.Clients[0].ID, ClientAuthentication: credential, Network: "192.0.2.1"}
	issued, err := service.Token(context.Background(), request)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted || calls != 1 {
		t.Fatal("configured workload could not obtain access", err)
	}
	if _, err := issued.RefreshToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("machine grant manufactured refresh authority")
	}
	for _, mutate := range []func(*oauth.TokenRequest){
		func(r *oauth.TokenRequest) { r.ClientAuthentication = oauth.ClientAuthentication{} },
		func(r *oauth.TokenRequest) { r.Scopes = []string{"identity:write"} },
		func(r *oauth.TokenRequest) { r.Resource = "https://other.example" },
		func(r *oauth.TokenRequest) { r.Code = strings.Repeat("A", 43) },
		func(r *oauth.TokenRequest) {
			r.GrantType = oauth.RefreshTokenGrant
			r.RefreshToken = strings.Repeat("A", 43)
		},
	} {
		rejected := request
		mutate(&rejected)
		if _, err := service.Token(context.Background(), rejected); err == nil {
			t.Fatal("workload accepted foreign credential/authority/variant")
		}
	}
	if calls != 1 {
		t.Fatal("rejected workload request reached persistence")
	}
}

func TestClientCredentialsFormIsClosedBeforeCredentialWork(t *testing.T) {
	_, credential := workloadCoreConfig(t)
	// A syntactic Basic header is sufficient here: parsing grants no authority.
	header := clientBasicHeader(credential.ClientID(), strings.Repeat("A", 43))
	raw := url.Values{"grant_type": {"client_credentials"}, "resource": {"https://resource.example"}, "scope": {"identity:read"}}.Encode()
	request, err := oauth.ParseTokenFormWithClientAuthentication(raw, []string{header})
	if err != nil || request.GrantType != oauth.ClientCredentialsGrant || request.ClientAuthentication.Method() != "client_secret_basic" {
		t.Fatal("closed machine form rejected", err)
	}
	for _, extra := range []string{"&tenant_id=foreign", "&subject=human", "&actor=human", "&code=" + strings.Repeat("A", 43), "&refresh_token=" + strings.Repeat("A", 43), "&code_verifier=unused", "&redirect_uri=https%3A%2F%2Fclient.example%2Fcb", "&audience=https%3A%2F%2Fother.example", "&client_id=foreign", "&scope=identity%3Awrite"} {
		if _, err := oauth.ParseTokenFormWithClientAuthentication(raw+extra, []string{header}); err == nil {
			t.Fatal("machine parser accepted a conflicting/foreign channel")
		}
	}
	if _, err := oauth.ParseTokenForm(raw + "&client_id=public-client"); err == nil {
		t.Fatal("machine form silently downgraded to public none")
	}
}

func TestWorkloadRegistrationRequiresExactMachinePolicy(t *testing.T) {
	for _, input := range []struct {
		tenant, id string
		lifetime   time.Duration
	}{
		{"", "worker", time.Second}, {"tenant", "", time.Second}, {"tenant", "worker", 0},
		{"tenant", "worker", 5*time.Minute + time.Microsecond}, {"tenant", "worker", time.Second + time.Nanosecond},
	} {
		if _, err := oauth.NewWorkload(identity.TenantID(input.tenant), input.id, input.lifetime); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("invalid configured workload admitted", err)
		}
	}
	for _, mutate := range []func(*oauth.Client){
		func(c *oauth.Client) { c.Public = true; c.AuthenticationMethod = "none" },
		func(c *oauth.Client) { c.Redirects = []string{"https://client.example/callback"} },
		func(c *oauth.Client) { c.Workload = &oauth.Workload{} },
	} {
		config, _ := workloadCoreConfig(t)
		mutate(&config.Clients[0])
		if _, err := config.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("workload registration accepted human/public/zero policy", err)
		}
	}
	config, _ := workloadCoreConfig(t)
	config.AccessTTL = time.Second
	if _, err := config.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("workload lifetime exceeded issuer ceiling", err)
	}
}

func TestConfiguredWorkloadOwnsCallerPolicyAfterConstruction(t *testing.T) {
	for _, replacement := range []struct {
		tenant, id string
		ttl        time.Duration
	}{
		{"foreign-tenant", "worker-a", 30 * time.Second},
		{"machine-tenant", "foreign-worker", 30 * time.Second},
		{"machine-tenant", "worker-a", time.Minute},
	} {
		t.Run(replacement.tenant+"/"+replacement.id+"/"+replacement.ttl.String(), func(t *testing.T) {
			config, credential := workloadCoreConfig(t)
			callerPolicy := config.Clients[0].Workload
			store := workloadBoundaryStore{call: func(_ context.Context, c oauth.TokenCommand) (oauth.TokenResult, error) {
				if c.Client.Workload.TenantID() != "machine-tenant" || c.Client.Workload.ID() != "worker-a" || c.Client.Workload.AccessTTL() != 30*time.Second {
					t.Fatal("caller whole-value assignment changed constructed service policy")
				}
				access, err := oauth.NewToken()
				return oauth.TokenResult{Outcome: identity.CommitOutcomeCommitted, AccessToken: access, Resource: c.Client.Resource, Scopes: c.Request.Scopes, ExpiresAt: config.Clock.Now().Add(30 * time.Second)}, err
			}}
			service, err := oauth.NewService(config, oauth.Dependencies{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			next, err := oauth.NewWorkload(identity.TenantID(replacement.tenant), replacement.id, replacement.ttl)
			if err != nil {
				t.Fatal(err)
			}
			*callerPolicy = *next
			if out, err := service.Token(context.Background(), oauth.TokenRequest{GrantType: oauth.ClientCredentialsGrant, ClientID: config.Clients[0].ID, ClientAuthentication: credential, Network: "192.0.2.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("caller replacement changed original authorized workload request", err)
			}
		})
	}
}

func TestConfiguredWorkloadDoesNotSharePolicyWithAdapterCommand(t *testing.T) {
	config, credential := workloadCoreConfig(t)
	next, err := oauth.NewWorkload("machine-tenant", "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	var retained *oauth.Workload
	store := workloadBoundaryStore{call: func(_ context.Context, c oauth.TokenCommand) (oauth.TokenResult, error) {
		calls++
		if c.Client.Workload.AccessTTL() != 30*time.Second {
			t.Fatal("adapter's earlier whole-value assignment changed subsequent service policy")
		}
		retained = c.Client.Workload
		if calls == 1 {
			*retained = *next
		}
		access, err := oauth.NewToken()
		ttl := 30 * time.Second
		if calls == 1 {
			ttl = time.Minute
		}
		return oauth.TokenResult{Outcome: identity.CommitOutcomeCommitted, AccessToken: access, Resource: c.Client.Resource, Scopes: c.Request.Scopes, ExpiresAt: config.Clock.Now().Add(ttl)}, err
	}}
	service, err := oauth.NewService(config, oauth.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	r := oauth.TokenRequest{GrantType: oauth.ClientCredentialsGrant, ClientID: config.Clients[0].ID, ClientAuthentication: credential, Network: "192.0.2.1"}
	if out, err := service.Token(context.Background(), r); !errors.Is(err, oauth.ErrUnavailable) || out.AccessToken != (oauth.Token{}) {
		t.Fatal("adapter mutated the local policy used to admit an overlong access result", err)
	}
	*retained = *next
	if out, err := service.Token(context.Background(), r); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("adapter mutation changed later original-policy request", err)
	}
}
