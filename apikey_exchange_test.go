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

func TestLegacyAPIKeyExchangeFormRequiresExplicitProfileAndPreservesBareBytes(t *testing.T) {
	policy := oauth.APIKeyExchangePolicy{LegacySHA256: true}
	headers := []string{clientBasicHeader("machine-client", strings.Repeat("A", 43))}
	fields := url.Values{"grant_type": {string(oauth.TokenExchangeGrant)}, "subject_token_type": {oauth.APIKeyTokenType}, "resource": {"https://resource.example"}, "scope": {"identity:read"}}
	for _, bare := range []string{"x", "bare+token/%\x00", "idk_" + strings.Repeat("A", 43), strings.Repeat("B", 4096)} {
		fields.Set("subject_token", bare)
		request, err := oauth.ParseAPIKeyExchangeForm(fields.Encode(), headers, policy)
		if err != nil || request.SubjectToken != bare || request.SubjectTokenType != oauth.APIKeyTokenType || request.ClientID != "machine-client" || request.GrantType != oauth.TokenExchangeGrant {
			t.Fatal("explicit legacy parser changed bounded historical bytes or caller channel", len(bare), err)
		}
	}
	fields.Set("subject_token", "unchanged-existing-bare")
	for _, parse := range []func(string, []string) (oauth.TokenRequest, error){
		oauth.ParseTokenFormWithClientAuthentication,
		func(raw string, headers []string) (oauth.TokenRequest, error) {
			return oauth.ParseAPIKeyExchangeForm(raw, headers, oauth.APIKeyExchangePolicy{})
		},
	} {
		if _, err := parse(fields.Encode(), headers); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("default modern parser implicitly enabled bare legacy keys", err)
		}
	}
	for _, extra := range []string{"&subject_token=x", "&actor_token=x", "&actor_token_type=x", "&subject=human", "&tenant_id=foreign", "&client_id=body-client", "&audience=https%3A%2F%2Fresource.example", "&code=x", "&refresh_token=x"} {
		if _, err := oauth.ParseAPIKeyExchangeForm(fields.Encode()+extra, headers, policy); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("selected legacy parser opened conflicting or free-form authority", err)
		}
	}
	for _, headers := range [][]string{nil, {headers[0], headers[0]}} {
		if _, err := oauth.ParseAPIKeyExchangeForm(fields.Encode(), headers, policy); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("legacy parser accepted missing or ambiguous Basic credentials", err)
		}
	}
	for _, invalid := range []string{"", strings.Repeat("B", 4097)} {
		fields.Set("subject_token", invalid)
		if _, err := oauth.ParseAPIKeyExchangeForm(fields.Encode(), headers, policy); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("selected historical input exceeded its owning 1..4096-byte limit", err)
		}
	}
	fields.Set("subject_token", "unchanged-existing-bare")
	fields.Set("subject_token_type", oauth.AccessTokenType)
	if _, err := oauth.ParseAPIKeyExchangeForm(fields.Encode(), headers, policy); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("legacy bytes were relabeled as standard OAuth access", err)
	}
	fields.Set("subject_token", strings.Repeat("A", 43))
	if _, err := oauth.ParseAPIKeyExchangeForm(fields.Encode(), headers, policy); err != nil {
		t.Fatal("explicit legacy root profile prevented an opaque access descendant", err)
	}
	fields.Set("subject_token_type", oauth.APIKeyTokenType)
	fields.Set("subject_token", "idk_"+strings.Repeat("A", 43))
	if _, err := oauth.ParseAPIKeyExchangeForm(fields.Encode(), headers, oauth.APIKeyExchangePolicy{}); err != nil {
		t.Fatal("additive parser changed the default modern source profile", err)
	}
	fields.Set("resource", "https://"+strings.Repeat("r", 2049))
	if _, err := oauth.ParseAPIKeyExchangeForm(fields.Encode(), headers, policy); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("legacy subject bound weakened another field's existing bound", err)
	}
	wire, err := json.Marshal(oauth.APIKeyExchangePolicy{})
	if err != nil || strings.Contains(string(wire), "LegacySHA256") {
		t.Fatal("default modern policy changed its historical serialized fingerprint")
	}
}

func TestLegacyAPIKeyExchangeServiceUsesSelectedProfileNotTokenPrefix(t *testing.T) {
	sessions, _, _, _ := coreSessionFixture(t)
	config, basic := workloadCoreConfig(t)
	config.Clients[0].Workload = nil
	config.Clients[0].Redirects = []string{"https://client.example/cb"}
	config.Clients[0].APIKeyExchange = true
	config.APIKeyExchange = &oauth.APIKeyExchangePolicy{}
	calls := 0
	store := workloadBoundaryStore{call: func(_ context.Context, command oauth.TokenCommand) (oauth.TokenResult, error) {
		calls++
		if command.Client.Workload != nil || command.Client.HumanCodeExchange || command.Request.SubjectTokenType != oauth.APIKeyTokenType {
			t.Fatal("legacy source became workload/human/standard-access authority")
		}
		return oauth.TokenResult{}, oauth.ErrInvalidGrant
	}}
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: config.Clients[0].ID, ClientAuthentication: basic, SubjectToken: "unchanged-existing-bare", SubjectTokenType: oauth.APIKeyTokenType, Resource: config.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.1"}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Token(context.Background(), request); !errors.Is(err, oauth.ErrInvalidRequest) || calls != 0 {
		t.Fatal("modern default selected bare SHA256 verification implicitly", err)
	}
	config.APIKeyExchange.LegacySHA256 = true
	service, err = oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range []string{"unchanged-existing-bare", "idk_" + strings.Repeat("A", 43), strings.Repeat("B", 4096)} {
		request.SubjectToken = wire
		if _, err := service.Token(context.Background(), request); !errors.Is(err, oauth.ErrInvalidGrant) {
			t.Fatal("explicit profile did not hand unchanged bounded input to its native owner", err)
		}
	}
	if calls != 3 {
		t.Fatal("credential text selected a different profile or skipped its owner")
	}
}

func FuzzLegacyAPIKeyExchangeFormPreservesOnlyBoundedSelectedBytes(f *testing.F) {
	for _, bare := range []string{"x", "bare+token/%\x00", "idk_" + strings.Repeat("A", 43), strings.Repeat("B", 4096), strings.Repeat("B", 4097), string([]byte{0xff, 0, '+'})} {
		f.Add(bare, false)
		f.Add(bare, true)
	}
	headers := []string{clientBasicHeader("machine-client", strings.Repeat("A", 43))}
	f.Fuzz(func(t *testing.T, bare string, duplicate bool) {
		if len(bare) > 8192 {
			return
		}
		fields := url.Values{"grant_type": {string(oauth.TokenExchangeGrant)}, "subject_token": {bare}, "subject_token_type": {oauth.APIKeyTokenType}, "resource": {"https://resource.example"}}
		raw := fields.Encode()
		if duplicate {
			raw += "&subject_token=x"
		}
		out, err := oauth.ParseAPIKeyExchangeForm(raw, headers, oauth.APIKeyExchangePolicy{LegacySHA256: true})
		valid := !duplicate && len(bare) >= 1 && len(bare) <= 4096
		if valid && (err != nil || out.SubjectToken != bare || out.SubjectTokenType != oauth.APIKeyTokenType || out.ClientID != "machine-client") {
			t.Fatal("bounded selected historical bytes did not round-trip unchanged")
		}
		if !valid && (!errors.Is(err, oauth.ErrInvalidRequest) || out.SubjectToken != "") {
			t.Fatal("duplicate or out-of-bound historical input produced a request")
		}
	})
}
