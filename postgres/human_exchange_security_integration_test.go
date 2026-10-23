//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	password "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
)

type humanNativeExchange struct {
	f               authenticatedPasswordFixture
	client          oauth.Client
	basic           oauth.ClientAuthentication
	service         *oauth.Service
	store           *oauthpostgres.Store
	source, refresh string
}

func nativeHumanExchange(t *testing.T, change bool, faults ...*oauthCommitFault) humanNativeExchange {
	t.Helper()
	f := passwordFixtureWithChange(t, change, faults...)
	enableConsentManagement(t, &f)
	c, _, basic := addConfiguredConfidentialClient(t, &f)
	original, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	source, refresh := issuedConfidentialTokens(t, f, original, c, basic)
	enableHumanCodeExchange(t, &f, &c)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapHumanCodeExchangeClient(f.ctx, oauth.IntrospectRequest{ClientID: c.ID, ClientAuthentication: basic, Token: source}); err != nil {
		t.Fatal(err)
	}
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	return humanNativeExchange{f, c, basic, service, store, source, refresh}
}

func humanChild(t *testing.T, h humanNativeExchange, source string) string {
	t.Helper()
	out, err := h.service.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, source))
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("human child issuance", err)
	}
	wire, err := out.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func humanClientEpoch(t *testing.T, h humanNativeExchange) authority.AuthorityScope {
	t.Helper()
	current, err := h.store.HumanCodeExchangeClientAuthority(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: h.source})
	if err != nil || current.Version != 1 {
		t.Fatal("actual selected client epoch unavailable", err)
	}
	return current.Scope
}

func advanceHumanAuthority(t *testing.T, h humanNativeExchange, scope authority.AuthorityScope) {
	t.Helper()
	tx, err := h.f.pool.Raw().Begin(h.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(h.f.ctx)
	if _, err := authority.AdvanceAuthority(h.f.ctx, tx, scope, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(h.f.ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNativeHumanCodeExchangePersistsActualSourceTokenSubject(t *testing.T) {
	h := nativeHumanExchange(t, false)
	var sourceID, grantID string
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT artifact_id,grant_id FROM oauth_store.artifacts WHERE kind=3 AND NOT human_code_exchange`).Scan(&sourceID, &grantID); err != nil || sourceID == grantID {
		t.Fatal("actual source artifact must differ from its grant", err)
	}
	out, err := h.service.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, h.source))
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal(err)
	}
	var effectID, auditType, auditID, lifecycleType, lifecycleID string
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT e.record_id,a.subject_type,a.subject_id,convert_from(o.payload,'UTF8')::jsonb->>'subject_type',convert_from(o.payload,'UTF8')::jsonb->>'subject_id' FROM oauth_store.effects e JOIN audit.records a ON a.correlation_id=e.command_id AND a.outcome=1 JOIN public.outbox_messages o ON convert_from(o.payload,'UTF8')::jsonb->>'command_id'=e.command_id AND o.topic='oauth_access.exchanged.v1' WHERE e.command_id=$1`, string(out.CommandID)).Scan(&effectID, &auditType, &auditID, &lifecycleType, &lifecycleID); err != nil {
		t.Fatal("actual required exchange records unavailable", err)
	}
	if effectID != sourceID || auditType != "oauth_token" || auditID != sourceID || lifecycleType != "oauth_token" || lifecycleID != sourceID {
		t.Fatal("persisted token effect/audit/lifecycle identifies grant instead of source artifact")
	}
}

func TestNativeHumanCodeExchangeNarrowsAfterConsumedCodeExpiry(t *testing.T) {
	f := passwordFixture(t)
	enableConsentManagement(t, &f)
	f.oauth.Protocol.CodeTTL = 5 * time.Second
	client, _, basic := addConfiguredConfidentialClient(t, &f)
	enableHumanCodeExchange(t, &f, &client)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := confidentialCodeScopes(t, f, service, client, []string{"identity:read", "identity:write"})
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, ClientAuthentication: basic, Code: code, CodeVerifier: verifier, RedirectURI: client.Redirects[0], Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	source, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	// Observe the actual consumed code's exclusive primary-time expiry, not an
	// edited timestamp or a guess that its longer-lived access has expired too.
	wait, stop := context.WithTimeout(f.ctx, 8*time.Second)
	defer stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		var expired bool
		if err := f.pool.Raw().QueryRow(wait, `SELECT code.state='consumed' AND code.expires_at<=clock_timestamp() AND access.expires_at>clock_timestamp() FROM oauth_store.artifacts access JOIN oauth_store.artifacts code ON code.artifact_id=access.parent_artifact_id WHERE access.kind=3 AND NOT access.human_code_exchange`).Scan(&expired); err != nil {
			t.Fatal("consumed-code expiry unavailable", err)
		}
		if expired {
			break
		}
		select {
		case <-wait.Done():
			t.Fatal("consumed code did not expire while genuine access remained live")
		case <-tick.C:
		}
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapHumanCodeExchangeClient(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: basic, Token: source}); err != nil {
		t.Fatal("expired consumed code incorrectly withdrew live access issuance proof", err)
	}
	h := humanNativeExchange{f: f, client: client, basic: basic, service: service, store: store, source: source}
	child := humanChild(t, h, source)
	for _, wire := range []string{source, child} {
		out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: basic, Token: wire})
		if err != nil || !out.Active || len(out.Scopes) == 0 || out.Scopes[0] != "identity:read" {
			t.Fatal("live code source or narrowed child lost current introspection", err)
		}
		if wire == source && (len(out.Scopes) != 2 || out.Scopes[1] != "identity:write") || wire == child && len(out.Scopes) != 1 {
			t.Fatal("child introspection did not exactly narrow the genuine two-scope source")
		}
	}
	expansion := humanExchangeRequest(client, basic, child)
	expansion.Scopes = []string{"identity:read", "identity:write"}
	if out, err := service.Token(f.ctx, expansion); !errors.Is(err, oauth.ErrInvalidScope) || out.AccessToken != (oauth.Token{}) {
		t.Fatal("descendant restored scope removed by its actual parent", err)
	}
}

func TestNativeHumanCodeExchangeScopeDepthDisabledAndCorruptLineageDeny(t *testing.T) {
	h := nativeHumanExchange(t, false)
	request := humanExchangeRequest(h.client, h.basic, h.source)
	for _, mutate := range []func(*oauth.TokenRequest){
		func(r *oauth.TokenRequest) { r.Scopes = []string{"identity:write"} },
		func(r *oauth.TokenRequest) { r.Resource = "https://foreign.example" },
		func(r *oauth.TokenRequest) {
			r.ClientID = "public-web"
			r.ClientAuthentication = oauth.ClientAuthentication{}
		},
		func(r *oauth.TokenRequest) { r.SubjectToken = h.refresh },
	} {
		bad := request
		mutate(&bad)
		if out, err := h.service.Token(h.f.ctx, bad); err == nil || out.AccessToken != (oauth.Token{}) {
			t.Fatal("unsupported source/authority was delegated", err)
		}
	}
	var deepest string
	current := h.source
	for range 4 {
		current = humanChild(t, h, current)
		deepest = current
	}
	if _, err := h.service.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, deepest)); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("human depth ceiling exceeded", err)
	}
	v, err := oauthpostgres.NewResourceVerifier(h.f.pool, h.f.oauth, h.f.keys, resourcePolicy(h.f, h.client))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: deepest, Scope: "identity:read"}); err != nil {
		t.Fatal("delegated resource consumer denied", err)
	}
	for _, selection := range []string{"global", "client"} {
		disabled := h.f.oauth
		var foreignClient oauth.Client
		var foreignBasic oauth.ClientAuthentication
		if selection == "global" {
			disabled.Protocol.HumanCodeExchange = nil
			disabled.HumanCodeExchangeClientNamespace = ""
		} else {
			disabled.Protocol.Clients = append([]oauth.Client(nil), disabled.Protocol.Clients...)
			for i := range disabled.Protocol.Clients {
				if disabled.Protocol.Clients[i].ID == h.client.ID {
					disabled.Protocol.Clients[i].HumanCodeExchange = false
				}
			}
			other := h.client
			other.ID = "other-selected-human"
			foreignClient = other
			disabled.Protocol.Clients = append(disabled.Protocol.Clients, other)
			token, _ := oauth.NewToken()
			wire, _ := token.Reveal()
			foreignBasic = confidentialBasic(t, other.ID, wire)
			secret, _ := password.NewSecret([]byte(wire))
			verifier, err := oauth.NewClientSecretVerifier(other.ID, other.Version, secret)
			secret.Destroy()
			if err != nil {
				t.Fatal(err)
			}
			disabled.Protocol.ClientSecrets = append(append([]oauth.ClientSecretVerifier(nil), disabled.Protocol.ClientSecrets...), verifier)
		}
		service, err := oauthpostgres.NewService(h.f.pool, disabled, h.f.keys)
		if err != nil {
			t.Fatal(err)
		}
		if selection == "client" {
			if out, err := service.Token(h.f.ctx, humanExchangeRequest(foreignClient, foreignBasic, h.source)); !errors.Is(err, oauth.ErrInvalidGrant) || out.AccessToken != (oauth.Token{}) {
				t.Fatal("separately authenticated foreign client delegated source", err)
			}
			if out, err := service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: foreignClient.ID, ClientAuthentication: foreignBasic, Token: deepest}); err != nil || out.Active {
				t.Fatal("foreign client observed human child", err)
			}
		}
		for _, wire := range []string{h.source, deepest} {
			out, err := service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: wire})
			if err != nil || out.Active != (wire == h.source) {
				t.Fatal("disabled selection changed ordinary root or retained child authority", selection, err)
			}
		}
		if _, err := service.Token(h.f.ctx, request); !errors.Is(err, oauth.ErrUnsupportedGrant) {
			t.Fatal("disabled human selection still issued", selection, err)
		}
		store, err := oauthpostgres.NewStore(h.f.pool, disabled, h.f.keys)
		if err != nil {
			t.Fatal(err)
		}
		if out, err := store.Token(h.f.ctx, oauth.TokenCommand{Client: h.client, Request: request}); err == nil || out.AccessToken != (oauth.Token{}) {
			t.Fatal("direct native projection bypassed disabled human selection", selection)
		}
	}
	var retained string
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT jsonb_agg(jsonb_build_object('id',artifact_id,'payload',payload,'parent',parent_artifact_id,'expires',expires_at))::text FROM oauth_store.artifacts WHERE human_code_exchange`).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	missing, _ := identity.NewSubjectID()
	for _, statement := range []string{
		`UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{HumanExchange,Environment}','"foreign"') WHERE human_code_exchange`,
		`UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{HumanExchange,RootVersion}','2') WHERE human_code_exchange`,
		`UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{HumanExchange,HumanActor}','"foreign"') WHERE human_code_exchange`,
		`UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{HumanExchange,ClientAuthorityVersion}','2') WHERE human_code_exchange`,
		`UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{HumanExchange,Depth}','5') WHERE human_code_exchange`,
		`UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{HumanExchange,RootID}',to_jsonb('` + string(missing) + `'::text)) WHERE human_code_exchange`,
		`WITH leaf AS (SELECT artifact_id FROM oauth_store.artifacts WHERE (payload->'HumanExchange'->>'Depth')::integer=4) UPDATE oauth_store.artifacts SET parent_artifact_id=leaf.artifact_id,payload=jsonb_set(payload,'{HumanExchange,ParentID}',to_jsonb(leaf.artifact_id)) FROM leaf WHERE (payload->'HumanExchange'->>'Depth')::integer=1`,
		`UPDATE oauth_store.artifacts SET expires_at=expires_at+interval '1 second' WHERE (payload->'HumanExchange'->>'Depth')::integer=4`,
		`UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{Scopes}','["identity:read","identity:write"]') WHERE human_code_exchange`,
	} {
		if _, err := h.f.pool.Raw().Exec(h.f.ctx, statement); err != nil {
			t.Fatal(err)
		}
		requireInvalidResource(t, v, h.f.ctx, deepest)
		if _, err := h.service.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, deepest)); err == nil {
			t.Fatal("corrupt human lineage issued")
		}
		if _, err := h.f.pool.Raw().Exec(h.f.ctx, `UPDATE oauth_store.artifacts a SET payload=s.payload,parent_artifact_id=s.parent,expires_at=s.expires FROM jsonb_to_recordset($1::jsonb) AS s(id text,payload jsonb,parent text,expires timestamptz) WHERE a.artifact_id=s.id`, retained); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: deepest, Scope: "identity:read"}); err != nil {
			t.Fatal("restored independent corruption fixture is not a positive control", err)
		}
	}
}

func TestNativeHumanCodeExchangeWithdrawalUsesCurrentRealOwners(t *testing.T) {
	for _, mode := range []string{"client", "credential", "user", "authorization", "consent", "root"} {
		t.Run(mode, func(t *testing.T) {
			h := nativeHumanExchange(t, mode == "credential")
			child := humanChild(t, h, h.source)
			metadata, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: child})
			if err != nil || !metadata.Active {
				t.Fatal(err)
			}
			switch mode {
			case "client":
				advanceHumanAuthority(t, h, humanClientEpoch(t, h))
			case "credential":
				h.f.changePassword()
			case "user":
				suspendResourceUser(t, h.f, identity.UserID(metadata.Subject))
			case "authorization":
				advanceHumanAuthority(t, h, authority.AuthorityScope{TenantID: authorization.TenantID(h.f.tenant), PolicyNamespace: h.f.oauth.Session.Profile.PolicyNamespace, SubjectID: authorization.SubjectID(metadata.Subject)})
			case "consent":
				consent := currentNarrowConsent(t, h.f, h.service)
				if out, err := h.service.ConsentDelete(h.f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, h.f, oauth.ConsentRemove, consent.ID(), consent.Version())}); err != nil || !out.Deleted {
					t.Fatal(err)
				}
			case "root":
				if _, err := h.service.Revoke(h.f.ctx, oauth.RevokeRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: h.source, Network: "192.0.2.1"}); err != nil {
					t.Fatal(err)
				}
			}
			out, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: child})
			if err != nil || out.Active {
				t.Fatal("withdrawn real owner retained human child", err)
			}
			if out, err := h.service.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, child)); err == nil || out.AccessToken != (oauth.Token{}) {
				t.Fatal("withdrawn real owner renewed delegation", err)
			}
			if mode == "client" {
				if err := h.store.BootstrapHumanCodeExchangeClient(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: h.source}); err == nil {
					t.Fatal("bootstrap reset an advanced registration epoch")
				}
				root, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: h.source})
				if err != nil || !root.Active {
					t.Fatal("exchange withdrawal changed ordinary source OAuth authority", err)
				}
			}
		})
	}
}

func TestNativeHumanCodeExchangeConsentNarrowingWithdrawsOriginalGeneration(t *testing.T) {
	f := passwordFixture(t)
	enableConsentNarrowing(t, &f)
	client, _, basic := addConfiguredConfidentialClient(t, &f)
	enableHumanCodeExchange(t, &f, &client)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	code, proof := confidentialCodeScopes(t, f, service, client, []string{"identity:read", "identity:write"})
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, ClientAuthentication: basic, Code: code, CodeVerifier: proof, RedirectURI: client.Redirects[0], Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	source, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapHumanCodeExchangeClient(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: basic, Token: source}); err != nil {
		t.Fatal(err)
	}
	h := humanNativeExchange{f: f, client: client, basic: basic, service: service, store: store, source: source}
	child := humanChild(t, h, source)
	consent := currentNarrowConsent(t, f, service)
	key, err := identity.NewIdempotencyKey([]byte("human-source-consent-narrow"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.ConsentUpdate(f.ctx, oauth.ConsentUpdateRequest{Consent: ownConsentCommand(t, f, oauth.ConsentNarrow, consent.ID(), consent.Version()), ClientID: client.ID, ClientVersion: client.Version, Resource: client.Resource, Scopes: []string{"identity:read"}, RequestKey: key})
	if err != nil || !out.Updated {
		t.Fatal("real current consent narrowing failed", err)
	}
	for _, wire := range []string{source, child} {
		if active, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: basic, Token: wire}); err != nil || active.Active {
			t.Fatal("old consent generation retained human authority", err)
		}
		if out, err := service.Token(f.ctx, humanExchangeRequest(client, basic, wire)); err == nil || out.AccessToken != (oauth.Token{}) {
			t.Fatal("narrowed current consent renewed old grant")
		}
	}
}

func TestNativeHumanCodeExchangeLateClientAndRootWithdrawalAreProtected(t *testing.T) {
	for _, mode := range []string{"client", "root", "credential", "user", "authorization", "consent", "unchanged"} {
		t.Run(mode, func(t *testing.T) {
			h := nativeHumanExchange(t, mode == "credential")
			child := humanChild(t, h, h.source)
			owner, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: child})
			if err != nil || !owner.Active {
				t.Fatal(err)
			}
			var rootID string
			if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT artifact_id FROM oauth_store.artifacts WHERE kind=3 AND NOT human_code_exchange`).Scan(&rootID); err != nil {
				t.Fatal(err)
			}
			trace := &exchangeFenceTrace{rootID: rootID}
			trace.late = func() {
				if mode == "client" {
					advanceHumanAuthority(t, h, humanClientEpoch(t, h))
				}
				if mode == "root" {
					if _, err := h.service.Revoke(h.f.ctx, oauth.RevokeRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: h.source, Network: "192.0.2.1"}); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "credential" {
					h.f.changePassword()
				}
				if mode == "user" {
					suspendResourceUser(t, h.f, identity.UserID(owner.Subject))
				}
				if mode == "authorization" {
					advanceHumanAuthority(t, h, authority.AuthorityScope{TenantID: authorization.TenantID(h.f.tenant), PolicyNamespace: h.f.oauth.Session.Profile.PolicyNamespace, SubjectID: authorization.SubjectID(owner.Subject)})
				}
				if mode == "consent" {
					consent := currentNarrowConsent(t, h.f, h.service)
					if _, err := h.service.ConsentDelete(h.f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, h.f, oauth.ConsentRemove, consent.ID(), consent.Version())}); err != nil {
						t.Fatal(err)
					}
				}
			}
			pool, err := database.Connect(h.f.ctx, database.Config{DSN: os.Getenv("OAUTH_POSTGRES_TEST_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = h.f.pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.Tracer = trace
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := pool.Close(ctx); err != nil {
					t.Error(err)
				}
			}()
			traced, err := oauthpostgres.NewService(pool, h.f.oauth, h.f.keys)
			if err != nil {
				t.Fatal(err)
			}
			out, err := traced.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, child))
			if !trace.completed.Load() {
				t.Fatal("real post-preflight withdrawal barrier was not exercised")
			}
			if mode == "unchanged" {
				if err != nil || out.AccessToken == (oauth.Token{}) {
					t.Fatal("unchanged preflight positive control", err)
				}
			} else if err == nil || out.AccessToken != (oauth.Token{}) {
				t.Fatal("late real owner withdrawal bypassed protected admission", err)
			}
		})
	}
}

func TestNativeHumanCodeExchangeReusableSourceConcurrentRetryAndRecovery(t *testing.T) {
	h := nativeHumanExchange(t, false)
	r := humanExchangeRequest(h.client, h.basic, h.source)
	r.CommandID, _ = identity.NewCommandID()
	var outcomes [2]oauth.TokenResult
	var failures [2]error
	var wg sync.WaitGroup
	for i := range outcomes {
		wg.Add(1)
		go func(i int) { defer wg.Done(); outcomes[i], failures[i] = h.service.Token(h.f.ctx, r) }(i)
	}
	wg.Wait()
	usable := 0
	for i, out := range outcomes {
		if failures[i] == nil && out.AccessToken != (oauth.Token{}) {
			usable++
		}
	}
	if usable != 1 {
		t.Fatal("same trusted human command issued multiple/no usable child", usable, failures)
	}
	replayed, err := h.service.Token(h.f.ctx, r)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || !replayed.Replayed || replayed.AccessToken != (oauth.Token{}) {
		t.Fatal("exact intent retry redelivered/duplicated", err)
	}
	changed := r
	changed.Audience, changed.Resource = r.Resource, ""
	if out, err := h.service.Token(h.f.ctx, changed); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("changed target selector reused committed intent", err)
	}
	metadata, err := h.store.Recover(h.f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: r.CommandID, ClientID: h.client.ID, ClientAuthentication: h.basic, Token: h.source})
	if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original human command metadata recovery", err)
	}
	humanChild(t, h, h.source)
	var children int
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE human_code_exchange`).Scan(&children); err != nil || children != 2 {
		t.Fatal("source reuse or intent retry semantics lost", err, children)
	}
}

func TestNativeHumanCodeExchangeActualCommitAmbiguityAndRollback(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(map[bool]string{false: "after", true: "before"}[before], func(t *testing.T) {
			fault := &oauthCommitFault{before: before}
			h := nativeHumanExchange(t, false, fault)
			r := humanExchangeRequest(h.client, h.basic, h.source)
			r.CommandID, _ = identity.NewCommandID()
			fault.armed.Store(true)
			out, err := h.service.Token(h.f.ctx, r)
			if !fault.hit.Load() || out.Outcome != identity.CommitOutcomeUnknown || !errors.Is(err, oauth.ErrUnavailable) || out.AccessToken != (oauth.Token{}) {
				t.Fatal("actual human COMMIT uncertainty was concealed", err, out.Outcome)
			}
			want := identity.CommitOutcomeCommitted
			if before {
				want = identity.CommitOutcomeNotCommitted
				// Let the original nonrenewable admission expire while the genuine
				// source remains valid. Retry may reconcile, never restart issuance.
				timer := time.NewTimer(21 * time.Second)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-h.f.ctx.Done():
					t.Fatal("original preparation expiry wait cancelled")
				}
				retried, _ := h.service.Token(h.f.ctx, r)
				if retried.AccessToken != (oauth.Token{}) || retried.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("retry renewed original human admission", retried.Outcome)
				}
			}
			metadata, err := h.store.Recover(h.f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: r.CommandID, ClientID: h.client.ID, ClientAuthentication: h.basic, Token: h.source})
			if err != nil && !(before && errors.Is(err, oauth.ErrUnavailable)) || metadata.Outcome != want {
				t.Fatal("human commit metadata did not reflect actual durability", err, metadata.Outcome)
			}
			var children int
			if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE human_code_exchange`).Scan(&children); err != nil || children != map[bool]int{false: 1, true: 0}[before] {
				t.Fatal("recovery duplicated or invented delegation", err, children)
			}
		})
	}
	// Required outbox failure is a real transaction rollback, not a fake Store.
	h := nativeHumanExchange(t, false)
	if _, err := h.f.pool.Raw().Exec(h.f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT human_exchange_outbox_failure CHECK(topic<>'oauth_access.exchanged.v1')`); err != nil {
		t.Fatal(err)
	}
	if out, err := h.service.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, h.source)); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("required lifecycle failure issued human bearer")
	}
	var children int
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE human_code_exchange`).Scan(&children); err != nil || children != 0 {
		t.Fatal("required effect failure left usable child", err)
	}
}

func TestNativeHumanCodeExchangeFreshReadDoesNotRenewOriginAndOutageDenies(t *testing.T) {
	h := nativeHumanExchange(t, false)
	child := humanChild(t, h, h.source)
	var started, until time.Time
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT (payload->'HumanExchange'->>'SourceReadStartedAt')::timestamptz,(payload->'HumanExchange'->>'SourceValidUntil')::timestamptz FROM oauth_store.artifacts WHERE human_code_exchange`).Scan(&started, &until); err != nil {
		t.Fatal(err)
	}
	if until.After(started.Add(20 * time.Second)) {
		t.Fatal("human original observation exceeds freshness bound")
	}
	timer := time.NewTimer(time.Until(until) + 100*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-h.f.ctx.Done():
		t.Fatal("original observation expiry wait cancelled")
	}
	metadata, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: child})
	if err != nil || !metadata.Active {
		t.Fatal("new genuine primary reads could not use remaining credential validity", err)
	}
	grandchild := humanChild(t, h, child)
	var starts, deadlines int
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT count(DISTINCT payload->'HumanExchange'->>'SourceReadStartedAt'),count(DISTINCT payload->'HumanExchange'->>'SourceValidUntil') FROM oauth_store.artifacts WHERE human_code_exchange`).Scan(&starts, &deadlines); err != nil || starts != 1 || deadlines != 1 {
		t.Fatal("descendant renewed original observation provenance", err)
	}
	if _, err := h.f.pool.Raw().Exec(h.f.ctx, `ALTER TABLE public.authorization_subject_authorities RENAME TO unavailable_human_authority`); err != nil {
		t.Fatal(err)
	}
	if out, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: grandchild}); !errors.Is(err, oauth.ErrUnavailable) || out.Active {
		t.Fatal("old positive survived required authority outage", err)
	}
	if out, err := h.service.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, grandchild)); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("authority outage issued human child", err)
	}
}
