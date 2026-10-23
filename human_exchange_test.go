package oauthserver_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestHumanCodeExchangeRequiresSeparateExplicitProfile(t *testing.T) {
	sessions, _, _, _ := coreSessionFixture(t)
	config, credential := workloadCoreConfig(t)
	client := &config.Clients[0]
	client.Workload = nil
	client.Redirects = []string{"https://client.example/cb"}
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: client.ID, ClientAuthentication: credential, SubjectToken: strings.Repeat("A", 43), SubjectTokenType: oauth.AccessTokenType, Resource: client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.1"}
	calls := 0
	store := workloadBoundaryStore{call: func(_ context.Context, command oauth.TokenCommand) (oauth.TokenResult, error) {
		calls++
		if command.Client.Workload != nil || !command.Client.HumanCodeExchange {
			t.Fatal("human exchange was relabelled as machine authority")
		}
		token, err := oauth.NewToken()
		return oauth.TokenResult{Outcome: identity.CommitOutcomeCommitted, AccessToken: token, Resource: command.Client.Resource, Scopes: command.Request.Scopes, ExpiresAt: config.Clock.Now().Add(time.Minute), IssuedTokenType: oauth.AccessTokenType}, err
	}}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Token(context.Background(), request); !errors.Is(err, oauth.ErrUnsupportedGrant) || calls != 0 {
		t.Fatal("ordinary confidential web client implicitly selected exchange", err)
	}
	client.HumanCodeExchange = true
	config.HumanCodeExchange = &oauth.HumanCodeExchangePolicy{MaximumDepth: 4, ClockUncertainty: time.Second}
	service, err = oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Token(context.Background(), request)
	if err != nil || calls != 1 || issued.IssuedTokenType != oauth.AccessTokenType {
		t.Fatal("explicit human code-access profile did not admit owning Basic client", err)
	}
	for _, mutate := range []func(*oauth.TokenRequest){
		func(r *oauth.TokenRequest) { r.ClientAuthentication = oauth.ClientAuthentication{} },
		func(r *oauth.TokenRequest) { r.SubjectTokenType = "urn:golib:params:oauth:token-type:api-key" },
		func(r *oauth.TokenRequest) { r.RefreshToken = strings.Repeat("A", 43) },
		func(r *oauth.TokenRequest) { r.Audience = r.Resource },
		func(r *oauth.TokenRequest) { r.Resource = "https://foreign.example" },
		func(r *oauth.TokenRequest) { r.Scopes = []string{"foreign:write"} },
	} {
		bad := request
		mutate(&bad)
		if _, err := service.Token(context.Background(), bad); err == nil {
			t.Fatal("human exchange accepted an unsupported authority channel")
		}
	}
	if calls != 1 {
		t.Fatal("rejected human exchange reached persistence")
	}
}

func TestHumanCodeExchangeSelectionCannotRelabelPublicOrWorkloadClients(t *testing.T) {
	config, _ := workloadCoreConfig(t)
	config.HumanCodeExchange = &oauth.HumanCodeExchangePolicy{}
	config.Clients[0].HumanCodeExchange = true
	if _, err := config.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("human profile selected a workload client", err)
	}
	config.Clients[0].Workload = nil
	config.Clients[0].Redirects = []string{"https://client.example/cb"}
	config.Clients[0].Public, config.Clients[0].AuthenticationMethod = true, "none"
	config.ClientSecrets = nil
	if _, err := config.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("human exchange selected a public client", err)
	}
}

func TestHumanCodeExchangePolicyIsBoundedAndFrozen(t *testing.T) {
	config, _ := workloadCoreConfig(t)
	config.Clients[0].Workload = nil
	config.Clients[0].Redirects = []string{"https://client.example/cb"}
	config.Clients[0].HumanCodeExchange = true
	policy := &oauth.HumanCodeExchangePolicy{}
	config.HumanCodeExchange = policy
	validated, err := config.Validated()
	if err != nil || validated.HumanCodeExchange.MaximumDepth != 4 {
		t.Fatal("human delegation default bound missing", err)
	}
	policy.MaximumDepth = 1
	if validated.HumanCodeExchange.MaximumDepth != 4 {
		t.Fatal("caller mutation changed frozen human exchange authority")
	}
	for _, rejected := range []oauth.HumanCodeExchangePolicy{{MaximumDepth: 5}, {ClockUncertainty: -time.Nanosecond}, {ClockUncertainty: 10 * time.Second}} {
		config.HumanCodeExchange = &rejected
		if _, err := config.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("human exchange accepted invalid depth or clock budget", err)
		}
	}
}
