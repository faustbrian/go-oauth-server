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
)

func TestRestrictedWorkloadExchangeRequiresOptInAndAuthenticatesOwningClient(t *testing.T) {
	config, credential := workloadCoreConfig(t)
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: config.Clients[0].ID, ClientAuthentication: credential, SubjectToken: strings.Repeat("A", 43), SubjectTokenType: oauth.AccessTokenType, Resource: config.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.1"}
	calls := 0
	store := workloadBoundaryStore{call: func(ctx context.Context, c oauth.TokenCommand) (oauth.TokenResult, error) {
		calls++
		access, err := oauth.NewToken()
		return oauth.TokenResult{Outcome: identity.CommitOutcomeCommitted, AccessToken: access, Resource: c.Client.Resource, Scopes: c.Request.Scopes, ExpiresAt: config.Clock.Now().Add(10 * time.Second), IssuedTokenType: oauth.AccessTokenType}, err
	}}
	service, err := oauth.NewService(config, oauth.Dependencies{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Token(context.Background(), request); !errors.Is(err, oauth.ErrUnsupportedGrant) || calls != 0 {
		t.Fatal("unselected standard exchange reached persistence", err)
	}
	config.WorkloadExchange = &oauth.WorkloadExchangePolicy{MaximumDepth: 4, ClockUncertainty: time.Second}
	service, err = oauth.NewService(config, oauth.Dependencies{Store: store})
	if err != nil {
		t.Fatal("selected workload exchange construction failed", err)
	}
	out, err := service.Token(context.Background(), request)
	if err != nil || out.IssuedTokenType != oauth.AccessTokenType || calls != 1 {
		t.Fatal("explicit owning Basic workload exchange rejected", err)
	}
	for _, change := range []func(*oauth.TokenRequest){
		func(r *oauth.TokenRequest) { r.ClientAuthentication = oauth.ClientAuthentication{} },
		func(r *oauth.TokenRequest) { r.SubjectTokenType = "urn:golib:params:oauth:token-type:api-key" },
		func(r *oauth.TokenRequest) { r.RequestedTokenType = "urn:ietf:params:oauth:token-type:id_token" },
		func(r *oauth.TokenRequest) { r.Audience = r.Resource },
		func(r *oauth.TokenRequest) { r.Resource = "https://foreign.example" },
		func(r *oauth.TokenRequest) { r.Code = strings.Repeat("A", 43) },
		func(r *oauth.TokenRequest) { r.Scopes = []string{"unregistered:write"} },
		func(r *oauth.TokenRequest) { r.CommandID = identity.CommandID("invalid-command") },
	} {
		bad := request
		change(&bad)
		if _, err := service.Token(context.Background(), bad); err == nil {
			t.Fatal("invalid exchange reached persistence")
		}
	}
	if calls != 1 {
		t.Fatal("denied exchange reached adapter")
	}
	request.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Token(context.Background(), request); err != nil || calls != 2 {
		t.Fatal("trusted original exchange command denied", err)
	}
	request.GrantType = oauth.ClientCredentialsGrant
	request.SubjectToken, request.SubjectTokenType, request.Resource = "", "", ""
	if _, err := service.Token(context.Background(), request); err == nil || calls != 2 {
		t.Fatal("exchange-only trusted command changed existing grant semantics")
	}
}

func TestRestrictedExchangeFormIsExplicitAndClosed(t *testing.T) {
	fields := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {strings.Repeat("A", 43)}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {"https://resource.example"}, "scope": {"identity:read"}}
	header := []string{clientBasicHeader("machine-client", strings.Repeat("A", 43))}
	raw := fields.Encode()
	r, err := oauth.ParseTokenFormWithClientAuthentication(raw, header)
	if err != nil || string(r.GrantType) != fields.Get("grant_type") {
		t.Fatal("standard restricted access exchange rejected", err)
	}
	for _, extra := range []string{"&subject_token=x", "&actor_token=x", "&actor_token_type=x", "&subject=human", "&tenant_id=foreign", "&command_id=untrusted", "&audience=https%3A%2F%2Fresource.example", "&code=x", "&refresh_token=x", "&client_id=machine-client", "&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token"} {
		if _, err := oauth.ParseTokenFormWithClientAuthentication(raw+extra, header); err == nil {
			t.Fatal("exchange accepted duplicate/conflicting/unsupported channel")
		}
	}
	fields.Set("subject_token_type", "urn:golib:params:oauth:token-type:api-key")
	if _, err := oauth.ParseTokenFormWithClientAuthentication(fields.Encode(), header); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("workload-only exchange accepted API key input", err)
	}
	if _, err := oauth.ParseTokenForm(raw + "&client_id=machine-client"); err == nil {
		t.Fatal("standard exchange downgraded to unauthenticated public client")
	}
}

func FuzzRestrictedExchangeForm(f *testing.F) {
	f.Add("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=" + strings.Repeat("A", 43) + "&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&resource=https%3A%2F%2Fresource.example")
	f.Add("grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=x&subject_token=x")
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = oauth.ParseTokenFormWithClientAuthentication(raw, []string{clientBasicHeader("machine-client", strings.Repeat("A", 43))})
	})
}

func TestRestrictedExchangePolicyIsBoundedAndCopied(t *testing.T) {
	for _, policy := range []oauth.WorkloadExchangePolicy{
		{MaximumDepth: 5},
		{ClockUncertainty: -time.Nanosecond},
		{ClockUncertainty: 10 * time.Second},
	} {
		config, _ := workloadCoreConfig(t)
		config.WorkloadExchange = &policy
		if _, err := config.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("invalid delegation depth/clock budget admitted", err)
		}
	}
	config, _ := workloadCoreConfig(t)
	policy := &oauth.WorkloadExchangePolicy{}
	config.WorkloadExchange = policy
	validated, err := config.Validated()
	if err != nil || validated.WorkloadExchange.MaximumDepth != 4 {
		t.Fatal("default exchange ceiling missing", err)
	}
	policy.MaximumDepth = 1
	if validated.WorkloadExchange.MaximumDepth != 4 {
		t.Fatal("caller mutation changed frozen exchange policy")
	}
	if _, err := oauth.ParseTokenFormWithClientAuthentication("grant_type=client_credentials&subject_token=", []string{clientBasicHeader("machine-client", strings.Repeat("A", 43))}); err == nil {
		t.Fatal("cross-grant empty-present exchange field accepted")
	}
}
