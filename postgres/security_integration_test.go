//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

type tokenCallIndex struct{}

// This scheduling seam delegates every decision to the real configured owner.
// It only pauses each token invocation after its active artifact lookup and
// before its first command observation, making the stale-lookup race exact.
type tokenAdmissionBarrier struct {
	owner   authorization.Service
	ready   chan int
	release [2]chan struct{}
	once    [2]sync.Once
}

func (b *tokenAdmissionBarrier) Decide(ctx context.Context, input authorization.DecisionContext) (authorization.Decision, error) {
	decision, err := b.owner.Decide(ctx, input)
	index, ok := ctx.Value(tokenCallIndex{}).(int)
	if err == nil && ok && index >= 0 && index < 2 && input.Request.Action == "identity.oauth-server.token" {
		b.once[index].Do(func() {
			select {
			case b.ready <- index:
			case <-ctx.Done():
				return
			}
			select {
			case <-b.release[index]:
			case <-ctx.Done():
			}
		})
	}
	if ctx.Err() != nil {
		return authorization.Decision{}, ctx.Err()
	}
	return decision, err
}

func freshRefresh(t *testing.T, f authenticatedPasswordFixture, service *oauth.Service) string {
	t.Helper()
	code, verifier := consentedCode(t, f, service)
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestNativeContendedRefreshTerminalObservationStillRevokesWinnerFamily(t *testing.T) {
	f := passwordFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	refresh := freshRefresh(t, f, service)
	other := freshRefresh(t, f, service)
	barrier := &tokenAdmissionBarrier{owner: f.oauth.Coordinator.AdmissionPolicy.Authorization, ready: make(chan int, 2), release: [2]chan struct{}{make(chan struct{}), make(chan struct{})}}
	policy := *f.oauth.Coordinator.AdmissionPolicy
	policy.Authorization = barrier
	f.oauth.Coordinator.AdmissionPolicy = &policy
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err = oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		output oauth.TokenResult
		err    error
	}
	done := [2]chan result{make(chan result, 1), make(chan result, 1)}
	for i := range done {
		go func(index int) {
			out, err := service.Token(context.WithValue(f.ctx, tokenCallIndex{}, index), oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: []string{"192.0.2.1", "192.0.2.2"}[index]})
			done[index] <- result{out, err}
		}(i)
	}
	for range 2 {
		select {
		case <-barrier.ready:
		case <-f.ctx.Done():
			t.Fatal("both original active lookups did not reach real admission")
		}
	}
	close(barrier.release[0])
	winner := <-done[0]
	if winner.err != nil || winner.output.Outcome != identity.CommitOutcomeCommitted || winner.output.Replayed {
		t.Fatal("scheduled winner did not commit", winner.err)
	}
	metadata, err := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: winner.output.CommandID, ClientID: "public-web", Token: refresh})
	if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original recovery failed", err)
	}
	var active int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE state='active' AND kind=4`).Scan(&active); err != nil || active != 2 {
		t.Fatal("metadata-only recovery changed a family", err)
	}
	close(barrier.release[1])
	loser := <-done[1]
	if !errors.Is(loser.err, oauth.ErrInvalidGrant) {
		t.Fatal("contended duplicate escaped replay denial", loser.err)
	}
	if _, err := loser.output.AccessToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("loser redelivered access")
	}
	if _, err := loser.output.RefreshToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("loser redelivered refresh")
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE state='active' AND kind=4`).Scan(&active); err != nil || active != 1 {
		t.Fatal("contended reuse retained winner descendants or revoked another family", err)
	}
	winnerRefresh, err := winner.output.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: winnerRefresh, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("winning descendant survived detected reuse")
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: other, Network: "192.0.2.1"}); err != nil {
		t.Fatal("unrelated family was revoked", err)
	}
}

func TestNativeRevokeConsumedRefreshRevokesOnlyOriginalFamily(t *testing.T) {
	f := passwordFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	refresh := freshRefresh(t, f, service)
	other := freshRefresh(t, f, service)
	child, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	childRefresh, err := child.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: "other-public-web", Token: refresh, Network: "192.0.2.1"}); err != nil {
		t.Fatal("foreign revocation was enumerable", err)
	}
	result, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: "public-web", Token: refresh, Network: "192.0.2.1"})
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("old consumed refresh could not revoke original family", err)
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: childRefresh, Network: "192.0.2.1"}); !errors.Is(err, oauth.ErrInvalidGrant) {
		t.Fatal("revoked original descendant survived")
	}
	if _, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: other, Network: "192.0.2.1"}); err != nil {
		t.Fatal("old-token revocation affected unrelated family", err)
	}
}

func TestNativeLifecycleBindsIndependentVersionedConsent(t *testing.T) {
	f := passwordFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = consentedCode(t, f, service)
	var created int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM public.outbox_messages WHERE topic='consent.created.v1'`).Scan(&created); err != nil || created != 1 {
		t.Fatal("actual first consent lacks canonical secondary lifecycle", err)
	}
	var consentID, version, grantID string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT consent_id,version::text FROM oauth_store.consents`).Scan(&consentID, &version); err != nil || version != "1" {
		t.Fatal("first consent lacks independent persisted identity/version", err)
	}
	if _, err := identity.ParseSubjectID(consentID); err != nil {
		t.Fatal("consent identity is not server-owned canonical identity")
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT grant_id FROM oauth_store.grants`).Scan(&grantID); err != nil || consentID == grantID {
		t.Fatal("consent incorrectly aliases grant identity", err)
	}
	var bound int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM public.outbox_messages WHERE topic='consent.created.v1' AND convert_from(payload,'UTF8')::jsonb->>'subject_type'='oauth_consent' AND convert_from(payload,'UTF8')::jsonb->>'subject_id'=$1 AND convert_from(payload,'UTF8')::jsonb->>'before_version'='0' AND convert_from(payload,'UTF8')::jsonb->>'after_version'='1'`, consentID).Scan(&bound); err != nil || bound != 1 {
		t.Fatal("secondary consent notification is not actual mutation identity/version", err)
	}
	code, verifier := consentedCode(t, f, service)
	var sameID string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT consent_id,version::text FROM oauth_store.consents`).Scan(&sameID, &version); err != nil || sameID != consentID || version != "2" {
		t.Fatal("repeat approval replaced consent identity or failed to advance actual version", err)
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM public.outbox_messages WHERE topic='consent.reconfirmed.v1' AND convert_from(payload,'UTF8')::jsonb->>'subject_id'=$1 AND convert_from(payload,'UTF8')::jsonb->>'before_version'='1' AND convert_from(payload,'UTF8')::jsonb->>'after_version'='2'`, consentID).Scan(&bound); err != nil || bound != 1 {
		t.Fatal("repeat consent did not commit actual reconfirmation lifecycle", err)
	}
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: "public-web", Token: access, Network: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	for event, want := range map[string]int{"grant.created.v1": 2, "grant.authorized.v1": 2, "consent.created.v1": 1, "consent.reconfirmed.v1": 1, "grant.code_exchanged.v1": 1, "oauth_access.revoked.v1": 1, "grant.scope_changed.v1": 0} {
		var count int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM public.outbox_messages WHERE topic=$1`, event).Scan(&count); err != nil || count != want {
			t.Fatal("transition was misclassified or secondary notification omitted", event, err)
		}
	}
}

func TestNativeSecondaryConsentOutboxFailureRollsBackActualMutation(t *testing.T) {
	f := passwordFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := oauth.S256Challenge(strings.Repeat("a", 43))
	if err != nil {
		t.Fatal(err)
	}
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", CodeChallenge: challenge, Resource: "https://resource.example", Scopes: []string{"identity:read"}}})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("actual pending interaction missing", err)
	}
	wire, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	// The first grant event can persist provisionally; only the actual second
	// outbox insert fails. No SQL/authority owner or command result is replaced.
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT oauth_test_secondary_failure CHECK(topic NOT IN('consent.created.v1','consent.reconfirmed.v1')) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	failed, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: wire, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true, Scopes: []string{"identity:read"}})
	if err == nil || failed.Outcome == oauth.AuthorizationRedirect {
		t.Fatal("secondary outbox failure reported successful consent")
	}
	if _, err := failed.Code.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("rolled-back consent exposed generated code")
	}
	var grants, continuations, codes, consents, effects, notifications, audits int
	// A separate failed-attempt audit is intentionally durable. Only successful
	// consent audit/effects must roll back with the failed secondary insert.
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.grants WHERE grant_id=$1 AND state='active' AND version=1),(SELECT count(*) FROM oauth_store.artifacts WHERE grant_id=$1 AND kind=1 AND state='active'),(SELECT count(*) FROM oauth_store.artifacts WHERE grant_id=$1 AND kind=2),(SELECT count(*) FROM oauth_store.consents),(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.continue'),(SELECT count(*) FROM public.outbox_messages WHERE topic IN('grant.authorized.v1','grant.scope_changed.v1','consent.created.v1','consent.reconfirmed.v1')),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.grant_consent' AND outcome=1)`, string(begin.CommandID)).Scan(&grants, &continuations, &codes, &consents, &effects, &notifications, &audits); err != nil || grants != 1 || continuations != 1 || codes != 0 || consents != 0 || effects != 0 || notifications != 0 || audits != 0 {
		t.Fatal("failed secondary notification retained provisional native effects", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages DROP CONSTRAINT oauth_test_secondary_failure`); err != nil {
		t.Fatal(err)
	}
	_, _ = consentedCode(t, f, service)
	var committed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM public.outbox_messages WHERE topic='consent.created.v1'`).Scan(&committed); err != nil || committed != 1 {
		t.Fatal("later independent authorized interaction did not commit real consent", err)
	}
}

func TestNativeRetainedKeysRotateWithoutStrandingUnknownOriginalCommit(t *testing.T) {
	fault := &oauthCommitFault{}
	f := passwordFixture(t, fault)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := consentedCode(t, f, service)
	known, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := known.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := oauth.S256Challenge(verifier)
	if err != nil {
		t.Fatal(err)
	}
	fault.armed.Store(true)
	lost, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", CodeChallenge: challenge, Resource: "https://resource.example", Scopes: []string{"identity:read"}}})
	if !fault.hit.Load() || !errors.Is(err, oauth.ErrUnavailable) || lost.Outcome != oauth.AuthorizationUnknown {
		t.Fatal("rotation setup did not lose real original COMMIT acknowledgement")
	}
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		t.Fatal(err)
	}
	next, err := oauth.NewTokenDigestKey(2, material[:])
	clear(material[:])
	if err != nil {
		t.Fatal(err)
	}
	f.oauth.TokenKeys = append(f.oauth.TokenKeys, next)
	f.oauth.ActiveTokenKeyVersion = 2
	f.oauth.ActiveEnvelopeKeyID = "oauth-envelope-next"
	rotated, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := rotated.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.authorize", CommandID: lost.CommandID, ClientID: "public-web", TenantID: f.tenant, Session: f.browser})
	if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("active writer-key rotation stranded retained original unknown commit", err)
	}
	newService, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: rotated})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := newService.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"})
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("retained original digest key could not rotate refresh", err)
	}
	var children int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE digest_version=2 AND kind IN(3,4)`).Scan(&children); err != nil || children != 2 {
		t.Fatal("rotated issuance did not select new digest version", err)
	}
}

func TestNativePublicStoreRejectsDuplicateScopeSelectionBeforeConsumption(t *testing.T) {
	f := passwordFixture(t)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	code, verifier := consentedCode(t, f, service)
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := issued.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1", Scopes: []string{"identity:read", "identity:read"}}
	result, err := store.Token(f.ctx, oauth.TokenCommand{Request: request, Client: f.oauth.Protocol.Clients[0]})
	if !errors.Is(err, oauth.ErrInvalidScope) || result.CommandID != "" {
		t.Fatal("direct public store admitted duplicate scope authority")
	}
	request.Scopes = nil
	request.Network = strings.Repeat("n", 129)
	result, err = store.Token(f.ctx, oauth.TokenCommand{Request: request, Client: f.oauth.Protocol.Clients[0]})
	if !errors.Is(err, oauth.ErrInvalidRequest) || result.CommandID != "" {
		t.Fatal("direct public store journaled unbounded attribution")
	}
	request.Network = "192.0.2.1"
	if result, err := service.Token(f.ctx, request); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("rejected typed input consumed original refresh", err)
	}
}

func TestNativeConsentRequiresExactOriginalBrowserCSRFClientOriginAndScope(t *testing.T) {
	f := passwordFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := oauth.S256Challenge(strings.Repeat("a", 43))
	if err != nil {
		t.Fatal(err)
	}
	begin, err := service.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", State: "denied-state", CodeChallenge: challenge, Resource: "https://resource.example", Scopes: []string{"identity:read"}}})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal(err)
	}
	wire, err := begin.Continuation.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	base := oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: wire, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true, Scopes: []string{"identity:read"}}
	badCSRF, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	otherBrowser, otherCSRF := f.signInAgain()
	for _, mutate := range []func(*oauth.ContinueRequest){
		func(r *oauth.ContinueRequest) { r.CSRF = badCSRF },
		func(r *oauth.ContinueRequest) { r.Origin = "https://foreign.example" },
		func(r *oauth.ContinueRequest) { r.ClientID = "other-public-web" },
		func(r *oauth.ContinueRequest) { r.Scopes = []string{"identity:write"} },
		func(r *oauth.ContinueRequest) { r.Session = otherBrowser; r.CSRF = otherCSRF },
	} {
		request := base
		mutate(&request)
		out, err := service.Continue(f.ctx, request)
		if err == nil || out.Outcome == oauth.AuthorizationRedirect {
			t.Fatal("mismatched original consent custody authorized")
		}
		if _, err := out.Code.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("denied consent exposed code")
		}
	}
	base.Approve = false
	denied, err := service.Continue(f.ctx, base)
	if err != nil || denied.Outcome != oauth.AuthorizationDenied {
		t.Fatal("earlier denials consumed legitimate original consent", err)
	}
	location, err := denied.Location()
	if err != nil {
		t.Fatal(err)
	}
	callback, err := url.Parse(location)
	if err != nil || callback.Query().Get("error") != "access_denied" || callback.Query().Get("state") != "denied-state" || callback.Query().Get("code") != "" {
		t.Fatal("explicit denial did not preserve exact credential-free redirect")
	}
	base.Approve = true
	if _, err := service.Continue(f.ctx, base); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("denied one-use interaction was revived")
	}
}

func TestNativeCodeAndRefreshContentionCannotDuplicateIssuance(t *testing.T) {
	for _, grantType := range []oauth.GrantType{oauth.AuthorizationCodeGrant, oauth.RefreshTokenGrant} {
		t.Run(string(grantType), func(t *testing.T) {
			f := passwordFixture(t)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			code, verifier := consentedCode(t, f, service)
			request := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"}
			want := 2
			if grantType == oauth.RefreshTokenGrant {
				known, err := service.Token(f.ctx, request)
				if err != nil {
					t.Fatal(err)
				}
				refresh, err := known.RefreshToken.Reveal()
				if err != nil {
					t.Fatal(err)
				}
				request = oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"}
				want = 4
			}
			start := make(chan struct{})
			var group sync.WaitGroup
			var outputs [2]oauth.TokenResult
			var failures [2]error
			for i := range outputs {
				group.Add(1)
				go func(index int) {
					defer group.Done()
					<-start
					outputs[index], failures[index] = service.Token(f.ctx, request)
				}(i)
			}
			close(start)
			group.Wait()
			fresh := 0
			for i, result := range outputs {
				if failures[i] == nil && result.Outcome == identity.CommitOutcomeCommitted && !result.Replayed {
					fresh++
					continue
				}
				if failures[i] != nil && !errors.Is(failures[i], oauth.ErrInvalidGrant) && !(errors.Is(failures[i], oauth.ErrUnavailable) && result.Outcome == identity.CommitOutcomeUnknown) {
					t.Fatal("contention escaped classified denial/historical pending", failures[i])
				}
				if _, err := result.AccessToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
					t.Fatal("contention loser exposed access token")
				}
				if _, err := result.RefreshToken.Reveal(); !errors.Is(err, oauth.ErrInvalidRequest) {
					t.Fatal("contention loser exposed refresh token")
				}
			}
			if fresh != 1 {
				t.Fatal("contention did not have exactly one fresh issuer")
			}
			var artifacts int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE kind IN(3,4)`).Scan(&artifacts); err != nil || artifacts != want {
				t.Fatal("one-use contention duplicated durable issuance", err)
			}
		})
	}
}

func TestNativeExpiredCodeAndRefreshCannotRenewOriginalLifetime(t *testing.T) {
	for _, grantType := range []oauth.GrantType{oauth.AuthorizationCodeGrant, oauth.RefreshTokenGrant} {
		t.Run(string(grantType), func(t *testing.T) {
			f := passwordFixture(t)
			f.oauth.Protocol.CodeTTL = time.Second
			f.oauth.Protocol.AccessTTL = time.Second
			f.oauth.Protocol.RefreshTTL = 5 * time.Second
			if grantType == oauth.RefreshTokenGrant {
				f.oauth.Protocol.RefreshTTL = time.Second
			}
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			code, verifier := consentedCode(t, f, service)
			request := oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"}
			kind := int16(oauth.TokenCode)
			if grantType == oauth.RefreshTokenGrant {
				known, err := service.Token(f.ctx, request)
				if err != nil {
					t.Fatal(err)
				}
				refresh, err := known.RefreshToken.Reveal()
				if err != nil {
					t.Fatal(err)
				}
				request = oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"}
				kind = int16(oauth.TokenRefresh)
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				var expired bool
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT clock_timestamp()>=expires_at FROM oauth_store.artifacts WHERE kind=$1`, kind).Scan(&expired); err != nil {
					t.Fatal(err)
				}
				if expired {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("bounded real expiry was not observed")
				}
				timer := time.NewTimer(20 * time.Millisecond)
				select {
				case <-timer.C:
				case <-f.ctx.Done():
					timer.Stop()
					t.Fatal("expiry wait cancelled")
				}
			}
			if _, err := service.Token(f.ctx, request); !errors.Is(err, oauth.ErrInvalidGrant) {
				t.Fatal("expired native source artifact issued fresh material")
			}
		})
	}
}
