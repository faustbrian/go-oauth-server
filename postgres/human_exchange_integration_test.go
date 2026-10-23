//go:build integration && oauthflow

package oauthpostgres_test

import (
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	password "github.com/faustbrian/go-password/v2"
	"github.com/jackc/pgx/v5/stdlib"
)

func enableHumanCodeExchange(t *testing.T, f *authenticatedPasswordFixture, client *oauth.Client) {
	t.Helper()
	base := oauthpostgres.ConsentMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7002}
	installHumanCodeHistory(t, f, base, 7003)
	selectHumanCodeExchange(f, client)
}

func installHumanCodeHistory(t *testing.T, f *authenticatedPasswordFixture, base migrations.Source, version migrations.Version) {
	t.Helper()
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
	runner, err := migrations.NewRunner(oauthpostgres.HumanCodeExchangeMigrationSource{Base: base, Schema: "oauth_store", Version: version}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("human forward history failed", err)
	}
	if out, err := runner.Up(f.ctx); err != nil || len(out.Records()) != 0 {
		t.Fatal("human history replay changed installed bytes", err)
	}
}

func selectHumanCodeExchange(f *authenticatedPasswordFixture, client *oauth.Client) {
	client.HumanCodeExchange = true
	for i := range f.oauth.Protocol.Clients {
		if f.oauth.Protocol.Clients[i].ID == client.ID {
			f.oauth.Protocol.Clients[i] = *client
		}
	}
	f.oauth.Protocol.HumanCodeExchange = &oauth.HumanCodeExchangePolicy{MaximumDepth: 4, ClockUncertainty: time.Second}
	f.oauth.HumanCodeExchangeClientNamespace = "oauth-human-code-clients"
	f.oauth.Protocol.OwningClientIntrospection = true
}

func proveHumanExchangeAfterMixedHistory(t *testing.T, f *authenticatedPasswordFixture, base migrations.Source, old *oauth.Service, machine oauth.Client, basic oauth.ClientAuthentication, rootWire, withdrawnWire string) {
	t.Helper()
	if _, err := old.Revoke(f.ctx, oauth.RevokeRequest{ClientID: machine.ID, ClientAuthentication: basic, Token: withdrawnWire, Network: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	client, _, humanBasic := addConfiguredConfidentialClient(t, f)
	original, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := issuedConfidentialTokens(t, *f, original, client, humanBasic)
	const snapshot = `SELECT jsonb_build_object('consents',(SELECT jsonb_agg(to_jsonb(c) ORDER BY consent_id) FROM oauth_store.consents c),'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY grant_id) FROM oauth_store.grants g),'artifacts',(SELECT jsonb_agg(to_jsonb(a)-'human_code_exchange'-'metadata_version' ORDER BY artifact_id) FROM oauth_store.artifacts a))::text`
	var before, after string
	if err := f.pool.Raw().QueryRow(f.ctx, snapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	installHumanCodeHistory(t, f, base, 7006)
	if err := f.pool.Raw().QueryRow(f.ctx, snapshot).Scan(&after); err != nil || after != before {
		t.Fatal("human suffix rewrote populated ordinary/silent/workload/tombstone history", err)
	}
	selectHumanCodeExchange(f, &client)
	aliased := f.oauth
	aliased.HumanCodeExchangeClientNamespace = aliased.WorkloadAuthority.PolicyNamespace
	if _, err := oauthpostgres.NewStore(f.pool, aliased, f.keys); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("human bootstrap namespace may alias configured workload authority", err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := selected.Token(f.ctx, humanExchangeRequest(client, humanBasic, source)); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("existing workload authority substituted for explicit human bootstrap")
	}
	if err := store.BootstrapHumanCodeExchangeClient(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: humanBasic, Token: source}); err != nil {
		t.Fatal(err)
	}
	h := humanNativeExchange{f: *f, client: client, basic: humanBasic, service: selected, store: store, source: source}
	child := humanChild(t, h, source)
	if out, err := selected.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: humanBasic, Token: child}); err != nil || !out.Active {
		t.Fatal("mixed history human child unusable", err)
	}
	for _, wire := range []string{rootWire, withdrawnWire} {
		out, err := selected.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: machine.ID, ClientAuthentication: basic, Token: wire})
		if err != nil || out.Active != (wire == rootWire) {
			t.Fatal("human suffix changed workload root/tombstone authority", err)
		}
	}
	// Both profiles use the real public owner, but withdrawal must retain the
	// other profile's independently bootstrapped authority and usable children.
	advanceHumanAuthority(t, h, authority.AuthorityScope{TenantID: authorization.TenantID(f.tenant), PolicyNamespace: f.oauth.WorkloadAuthority.PolicyNamespace, SubjectID: authorization.SubjectID(machine.Workload.ID())})
	if out, err := selected.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: machine.ID, ClientAuthentication: basic, Token: rootWire}); err != nil || out.Active {
		t.Fatal("workload withdrawal did not fence its original root", err)
	}
	if out, err := selected.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: humanBasic, Token: child}); err != nil || !out.Active {
		t.Fatal("workload withdrawal also withdrew independent human child", err)
	}
	_ = humanChild(t, h, source)
	// The existing workload profile may observe its new principal epoch for a
	// genuinely new root; it does not reactivate any original workload root.
	fresh, err := selected.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.ClientCredentialsGrant, ClientID: machine.ID, ClientAuthentication: basic, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("independent workload owner could not issue at its current epoch", err)
	}
	freshWire, err := fresh.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	advanceHumanAuthority(t, h, humanClientEpoch(t, h))
	if out, err := selected.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: humanBasic, Token: child}); err != nil || out.Active {
		t.Fatal("human client withdrawal did not withdraw its own child", err)
	}
	if _, err := selected.Token(f.ctx, humanExchangeRequest(client, humanBasic, source)); err == nil {
		t.Fatal("human client withdrawal retained new human issuance")
	}
	if out, err := selected.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: machine.ID, ClientAuthentication: basic, Token: freshWire}); err != nil || !out.Active {
		t.Fatal("human client withdrawal also withdrew independent workload root", err)
	}
	if out, err := selected.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: machine.ID, ClientAuthentication: basic, SubjectToken: freshWire, SubjectTokenType: oauth.AccessTokenType, Resource: machine.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("human client withdrawal denied independent workload delegation", err)
	}
}

func humanExchangeRequest(client oauth.Client, basic oauth.ClientAuthentication, source string) oauth.TokenRequest {
	return oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: client.ID, ClientAuthentication: basic, SubjectToken: source, SubjectTokenType: oauth.AccessTokenType, Resource: client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.1"}
}

func TestNativeHumanCodeExchangePreservesConsumedIssuanceAncestryAndOwner(t *testing.T) {
	f := passwordFixture(t)
	enableConsentManagement(t, &f)
	client, secretWire, basic := addConfiguredConfidentialClient(t, &f)
	// Registration revision and the new lifecycle epoch are independent. A
	// genuine preactivation root at version7 must bootstrap at authority epoch1.
	client.Version = 7
	for i := range f.oauth.Protocol.Clients {
		if f.oauth.Protocol.Clients[i].ID == client.ID {
			f.oauth.Protocol.Clients[i] = client
		}
	}
	secret, err := password.NewSecret([]byte(secretWire))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oauth.NewClientSecretVerifier(client.ID, client.Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	f.oauth.Protocol.ClientSecrets = []oauth.ClientSecretVerifier{verifier}
	f.oauth.Protocol.OwningClientIntrospection = true
	original, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	source, refresh := issuedConfidentialTokens(t, f, original, client, basic)
	enableHumanCodeExchange(t, &f, &client)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: basic, Token: source}
	if out, err := service.Token(f.ctx, humanExchangeRequest(client, basic, source)); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("exchange implicitly initialized missing client authority")
	}
	if err := store.BootstrapHumanCodeExchangeClient(f.ctx, bootstrap); err != nil {
		t.Fatal("actual selected registration bootstrap", err)
	}
	if err := store.BootstrapHumanCodeExchangeClient(f.ctx, bootstrap); err != nil {
		t.Fatal("bootstrap was not idempotent", err)
	}
	request := humanExchangeRequest(client, basic, source)
	first, err := service.Token(f.ctx, request)
	if err != nil || first.Outcome != identity.CommitOutcomeCommitted || first.RefreshToken != (oauth.Token{}) || first.IssuedTokenType != oauth.AccessTokenType {
		t.Fatal("genuine consumed-code access source could not delegate", err)
	}
	child, err := first.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	request.SubjectToken = child
	second, err := service.Token(f.ctx, request)
	if err != nil || second.ExpiresAt.After(first.ExpiresAt) {
		t.Fatal("human descendant expanded original access lifetime", err)
	}
	grandchild, err := second.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range []string{source, child, grandchild} {
		out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: basic, Token: wire})
		if err != nil || !out.Active || out.Subject == "" || out.ClientID != client.ID || out.Resource != client.Resource {
			t.Fatal("human owner/client/resource disappeared during delegation", err)
		}
	}
	var consumedCode, exactSource int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts a JOIN oauth_store.artifacts code ON code.artifact_id=a.parent_artifact_id WHERE a.kind=3 AND NOT a.human_code_exchange AND code.kind=2 AND code.state='consumed'`).Scan(&consumedCode); err != nil || consumedCode != 1 {
		t.Fatal("human delegation rewrote genuine consumed code ancestry", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts a JOIN oauth_store.grants g USING(grant_id) WHERE a.human_code_exchange AND g.user_id IS NOT NULL AND g.consent_id IS NOT NULL AND jsonb_array_length(g.source_session)>0`).Scan(&exactSource); err != nil || exactSource != 2 {
		t.Fatal("delegation manufactured a substitute human/session/consent grant", err)
	}
	rotated, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, ClientAuthentication: basic, RefreshToken: refresh, Scopes: []string{"identity:read"}, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("human exchange broke supported original refresh rotation", err)
	}
	for _, wire := range []string{source, child, grandchild} {
		out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: basic, Token: wire})
		if err != nil || !out.Active {
			t.Fatal("changing grant revision invalidated unchanged human access authority", err)
		}
	}
	refreshAccess, err := rotated.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	request.SubjectToken = refreshAccess
	if _, err := service.Token(f.ctx, request); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("refresh-issued access silently broadened the selected code-source profile", err)
	}
	f.signOut()
	request.SubjectToken = source
	if _, err := service.Token(f.ctx, request); err != nil {
		t.Fatal("ordinary browser logout changed approved OAuth grant semantics", err)
	}
	request.SubjectToken = refresh
	if _, err := service.Token(f.ctx, request); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("refresh source substituted for code-issued access", err)
	}
	if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: client.ID, ClientAuthentication: basic, Token: child, Hint: oauth.TokenAccess, Network: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	for _, wire := range []string{child, grandchild} {
		out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: basic, Token: wire})
		if err != nil || out.Active {
			t.Fatal("explicit parent withdrawal retained human descendants", err)
		}
	}
}
