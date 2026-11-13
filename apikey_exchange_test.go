package oauthserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestAPIKeyExchangeRequiresSeparateExplicitBasicClientProfile(t *testing.T) {
	sessions, _, _, _ := coreSessionFixture(t)
	config, basic := workloadCoreConfig(t)
	client := &config.Clients[0]
	client.Workload = nil
	client.Redirects = []string{"https://client.example/cb"}
	client.APIKeyExchange = true
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: client.ID, ClientAuthentication: basic, SubjectToken: "idk_" + strings.Repeat("A", 43), SubjectTokenType: oauth.APIKeyTokenType, Resource: client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.1"}
	storeCalls := 0
	store := workloadBoundaryStore{call: func(_ context.Context, command oauth.TokenCommand) (oauth.TokenResult, error) {
		storeCalls++
		if command.Client.Workload != nil || command.Client.HumanCodeExchange || !command.Client.APIKeyExchange || command.Request.SubjectTokenType != oauth.APIKeyTokenType {
			t.Fatal("API-key source was converted into human or workload authority")
		}
		token, err := oauth.NewToken()
		return oauth.TokenResult{Outcome: identity.CommitOutcomeCommitted, AccessToken: token, Resource: command.Client.Resource, Scopes: command.Request.Scopes, ExpiresAt: config.Clock.Now().Add(time.Minute), IssuedTokenType: oauth.AccessTokenType}, err
	}}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Token(context.Background(), request); !errors.Is(err, oauth.ErrUnsupportedGrant) || storeCalls != 0 {
		t.Fatal("API-key token exchange was enabled without its global profile", err)
	}
	config.APIKeyExchange = &oauth.APIKeyExchangePolicy{MaximumDepth: 4, ClockUncertainty: time.Second}
	service, err = oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Token(context.Background(), request)
	if err != nil || issued.IssuedTokenType != oauth.AccessTokenType || storeCalls != 1 {
		t.Fatal("explicit private API-key exchange did not reach its owning Basic adapter", err)
	}
	for _, mutate := range []func(*oauth.TokenRequest){
		func(r *oauth.TokenRequest) { r.ClientAuthentication = oauth.ClientAuthentication{} },
		func(r *oauth.TokenRequest) { r.SubjectTokenType = oauth.AccessTokenType },
		func(r *oauth.TokenRequest) { r.SubjectToken = strings.Repeat("A", 43) },
		func(r *oauth.TokenRequest) { r.RequestedTokenType = "urn:ietf:params:oauth:token-type:id_token" },
		func(r *oauth.TokenRequest) { r.RefreshToken = strings.Repeat("A", 43) },
		func(r *oauth.TokenRequest) { r.Audience = r.Resource },
		func(r *oauth.TokenRequest) { r.Resource = "https://foreign.example" },
		func(r *oauth.TokenRequest) { r.Scopes = []string{"foreign:write"} },
	} {
		bad := request
		mutate(&bad)
		if _, err := service.Token(context.Background(), bad); err == nil {
			t.Fatal("API-key exchange accepted an unselected credential/caller/target channel")
		}
	}
	if storeCalls != 1 {
		t.Fatal("rejected API-key exchange reached native persistence")
	}
}

func TestAPIKeyExchangeUnknownRetainsOnlyOriginalRecoveryCorrelation(t *testing.T) {
	sessions, _, _, _ := coreSessionFixture(t)
	config, basic := workloadCoreConfig(t)
	config.Clients[0].Workload = nil
	config.Clients[0].Redirects = []string{"https://client.example/cb"}
	config.Clients[0].APIKeyExchange = true
	config.APIKeyExchange = &oauth.APIKeyExchangePolicy{}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	expected := oauth.APIKeyExchangeUnknownError{CommandID: command, Verification: apikey.VerificationReconcileQuery{AttemptID: apikey.VerificationAttemptID(attempt), TenantID: "retained-tenant", Fingerprint: [32]byte{1}}}
	store := workloadBoundaryStore{call: func(context.Context, oauth.TokenCommand) (oauth.TokenResult, error) {
		return oauth.TokenResult{Outcome: identity.CommitOutcomeUnknown, CommandID: command}, expected
	}}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.Token(context.Background(), oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: config.Clients[0].ID, ClientAuthentication: basic, SubjectToken: "idk_" + strings.Repeat("A", 43), SubjectTokenType: oauth.APIKeyTokenType, Resource: config.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.1"})
	var retained oauth.APIKeyExchangeUnknownError
	if !errors.As(err, &retained) || retained != expected || !errors.Is(err, oauth.ErrUnavailable) || out.Outcome != identity.CommitOutcomeUnknown || out.CommandID != command || out.AccessToken != (oauth.Token{}) || out.RefreshToken != (oauth.Token{}) || out.IDToken != (oauth.IDToken{}) {
		t.Fatal("unknown source/OAuth outcome lost exact recovery correlation or exposed credentials")
	}
	if wire, err := json.Marshal(retained); err == nil || len(wire) != 0 {
		t.Fatal("unknown correlation exported through JSON")
	}
	if strings.Contains(fmt.Sprintf("%+v", retained), string(command)) || strings.Contains(retained.Error(), "retained-tenant") {
		t.Fatal("unknown correlation leaked through diagnostics")
	}
}

func TestAPIKeyExchangeCancellationRetainsDisclosedUnknownCorrelation(t *testing.T) {
	sessions, _, _, _ := coreSessionFixture(t)
	config, basic := workloadCoreConfig(t)
	config.Clients[0].Workload = nil
	config.Clients[0].Redirects = []string{"https://client.example/cb"}
	config.Clients[0].APIKeyExchange = true
	config.APIKeyExchange = &oauth.APIKeyExchangePolicy{}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	expected := oauth.APIKeyExchangeUnknownError{CommandID: command, Verification: apikey.VerificationReconcileQuery{AttemptID: apikey.VerificationAttemptID(attempt), TenantID: "retained-tenant", Fingerprint: [32]byte{1}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := workloadBoundaryStore{call: func(context.Context, oauth.TokenCommand) (oauth.TokenResult, error) {
		cancel()
		return oauth.TokenResult{Outcome: identity.CommitOutcomeUnknown, CommandID: command}, expected
	}}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.Token(ctx, oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: config.Clients[0].ID, ClientAuthentication: basic, SubjectToken: "idk_" + strings.Repeat("A", 43), SubjectTokenType: oauth.APIKeyTokenType, Resource: config.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.1"})
	var retained oauth.APIKeyExchangeUnknownError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &retained) || retained != expected || out.Outcome != identity.CommitOutcomeUnknown || out.CommandID != command || out.AccessToken != (oauth.Token{}) {
		t.Fatal("cancellation discarded disclosed exact source recovery custody or fabricated rollback")
	}
}

func TestAPIKeyExchangeParsingKeepsPrivateSourceTypeAndClosedFields(t *testing.T) {
	fields := url.Values{"grant_type": {string(oauth.TokenExchangeGrant)}, "subject_token": {"idk_" + strings.Repeat("A", 43)}, "subject_token_type": {oauth.APIKeyTokenType}, "resource": {"https://resource.example"}, "scope": {"identity:read"}}
	headers := []string{clientBasicHeader("machine-client", strings.Repeat("A", 43))}
	request, err := oauth.ParseTokenFormWithClientAuthentication(fields.Encode(), headers)
	if err != nil || request.SubjectTokenType != oauth.APIKeyTokenType || request.GrantType != oauth.TokenExchangeGrant {
		t.Fatal("explicit private API-key input was mislabeled or rejected", err)
	}
	for _, extra := range []string{"&subject_token=x", "&actor_token=x", "&actor_token_type=x", "&subject=human", "&tenant_id=foreign", "&command_id=untrusted", "&audience=https%3A%2F%2Fresource.example", "&code=x", "&refresh_token=x"} {
		if _, err := oauth.ParseTokenFormWithClientAuthentication(fields.Encode()+extra, headers); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("API-key parser accepted conflicting or free-form authority", err)
		}
	}
	fields.Set("subject_token_type", oauth.AccessTokenType)
	if _, err := oauth.ParseTokenFormWithClientAuthentication(fields.Encode(), headers); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("raw API key was presented as a standard OAuth access token", err)
	}
}

func TestAPIKeyExchangePolicyCannotRelabelPublicHumanOrWorkloadClients(t *testing.T) {
	config, _ := workloadCoreConfig(t)
	config.APIKeyExchange = &oauth.APIKeyExchangePolicy{}
	config.Clients[0].APIKeyExchange = true
	if _, err := config.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("API-key source policy relabeled a workload", err)
	}
	config.Clients[0].Workload = nil
	config.Clients[0].Redirects = []string{"https://client.example/cb"}
	config.Clients[0].HumanCodeExchange = true
	if _, err := config.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("API-key profile implicitly shared human exchange authority", err)
	}
	config.Clients[0].HumanCodeExchange = false
	config.Clients[0].Public, config.Clients[0].AuthenticationMethod = true, "none"
	config.ClientSecrets = nil
	if _, err := config.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("API-key exchange admitted a public client", err)
	}
}

func TestAPIKeyExchangePolicyKeepsFrozenDepthAndClockBounds(t *testing.T) {
	config, _ := workloadCoreConfig(t)
	config.Clients[0].Workload = nil
	config.Clients[0].Redirects = []string{"https://client.example/cb"}
	config.Clients[0].APIKeyExchange = true
	policy := &oauth.APIKeyExchangePolicy{}
	config.APIKeyExchange = policy
	validated, err := config.Validated()
	if err != nil || validated.APIKeyExchange.MaximumDepth != 4 {
		t.Fatal("API-key delegation did not retain the default four-hop ceiling", err)
	}
	policy.MaximumDepth = 1
	if validated.APIKeyExchange.MaximumDepth != 4 {
		t.Fatal("caller mutation changed a retained API-key exchange policy")
	}
	for _, rejected := range []oauth.APIKeyExchangePolicy{{MaximumDepth: 5}, {ClockUncertainty: -time.Nanosecond}, {ClockUncertainty: 10 * time.Second}} {
		config.APIKeyExchange = &rejected
		if _, err := config.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("API-key exchange admitted an excessive depth or clock budget", err)
		}
	}
}
