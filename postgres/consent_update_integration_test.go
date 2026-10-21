//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"golang.org/x/oauth2"
)

// Only the selected application's explicit permission is added; genuine
// identity/session/CSRF, current authority, risk and storage remain native.
type narrowConsentPolicy struct{ authorization.Service }

func (p narrowConsentPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	r := c.Request
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && (r.Action == "identity.oauth-server.consent-update" || r.Action == "identity.oauth-server.consent-update.recover") && (r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(r.Subject.ID) || r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action)) {
		if err := ctx.Err(); err != nil {
			return authorization.Decision{}, err
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return p.Service.Decide(ctx, c)
}

func currentNarrowConsent(t *testing.T, f authenticatedPasswordFixture, s *oauth.Service) oauth.Consent {
	t.Helper()
	listed, err := s.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
	if err != nil || len(listed.Page.Items()) != 1 {
		t.Fatal("own consent missing", err)
	}
	return listed.Page.Items()[0]
}

func TestNativeConsentNarrowingDeniesExpansionScopeAndForeignAuthority(t *testing.T) {
	f := passwordFixture(t)
	enableConsentNarrowing(t, &f)
	s, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = broadConsentCode(t, f, s, []string{"identity:read", "identity:write"})
	consent := currentNarrowConsent(t, f, s)
	for _, mode := range []string{"same", "empty", "expanded", "foreign-scope", "client", "client-version", "resource", "consent-version", "tenant", "csrf", "other-user", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			r := narrowRequest(t, f, consent, "denied-"+mode, []string{"identity:read"})
			input := r.Consent.Input()
			ctx := f.ctx
			switch mode {
			case "same":
				r.Scopes = consent.Scopes()
			case "empty":
				r.Scopes = nil
			case "expanded":
				r.Scopes = []string{"identity:read", "identity:write", "foreign"}
			case "foreign-scope":
				r.Scopes = []string{"foreign"}
			case "client":
				r.ClientID = "other-public-web"
			case "client-version":
				r.ClientVersion++
			case "resource":
				r.Resource = "https://foreign.example"
			case "consent-version":
				input.Version++
			case "tenant":
				input.TenantID = "foreign"
			case "csrf":
				input.CSRF, _ = session.NewCSRFToken()
			case "other-user":
				input.Session, input.CSRF = f.anotherUser()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			r.Consent, err = oauth.NewConsentCommand(input)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := s.ConsentUpdate(ctx, r); err == nil || got.Updated {
				t.Fatal("invalid consent narrowing admitted", mode)
			}
		})
	}
	current := currentNarrowConsent(t, f, s)
	if current.Version() != consent.Version() || !slices.Equal(current.Scopes(), consent.Scopes()) {
		t.Fatal("denials mutated consent")
	}
	f.signOut()
	if got, err := s.ConsentUpdate(f.ctx, narrowRequest(t, f, consent, "withdrawn-session", []string{"identity:read"})); err == nil || got.Updated {
		t.Fatal("revoked session narrowed consent")
	}
}

func TestNativeConsentNarrowingOutboxRollbackAndLostCommitOnce(t *testing.T) {
	for _, mode := range []string{"outbox", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			var provisional atomic.Bool
			fault := &oauthCommitFault{beforeWrite: func(wire []byte) {
				if bytes.Contains(wire, []byte(`UPDATE "oauth_store".consents SET scopes=`)) {
					provisional.Store(true)
				}
			}}
			f := passwordFixture(t, fault)
			enableConsentNarrowing(t, &f)
			s, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = broadConsentCode(t, f, s, []string{"identity:read", "identity:write"})
			consent := currentNarrowConsent(t, f, s)
			if mode == "outbox" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT reject_consent_narrowing CHECK(topic<>'consent.scope_changed.v1') NOT VALID`); err != nil {
					t.Fatal(err)
				}
			} else {
				fault.armed.Store(true)
			}
			r := narrowRequest(t, f, consent, "original-"+mode, []string{"identity:read"})
			out, err := s.ConsentUpdate(f.ctx, r)
			if !provisional.Load() || err == nil || out.Updated {
				t.Fatal("fault did not reach provisional native narrowing", err)
			}
			if mode == "unknown" && (!fault.hit.Load() || out.Completion.Outcome != identity.CommitOutcomeUnknown) {
				t.Fatal("lost actual COMMIT was not unknown", err)
			}
			store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.consent-update", CommandID: out.Completion.CommandID, ClientID: "public-web", TenantID: f.tenant, Session: f.browser, ConsentID: consent.ID()})
			want := identity.CommitOutcomeCommitted
			if mode == "outbox" {
				want = identity.CommitOutcomeNotCommitted
			}
			if recovered.Outcome != want || mode == "unknown" && err != nil {
				t.Fatal("original recovery lost actual outcome", err)
			}
			var version, generation string
			var effects, events, audits int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT c.version::text,c.generation::text,(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.consent-update'),(SELECT count(*) FROM public.outbox_messages WHERE topic='consent.scope_changed.v1'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.revoke_consent' AND outcome=1) FROM oauth_store.consents c WHERE consent_id=$1`, consent.ID()).Scan(&version, &generation, &effects, &events, &audits); err != nil {
				t.Fatal(err)
			}
			if mode == "outbox" {
				if version != "1" || generation != "1" || effects != 0 || events != 0 || audits != 0 {
					t.Fatal("failed required outbox leaked provisional effects")
				}
			} else if version != "2" || generation != "2" || effects != 1 || events != 1 || audits != 1 {
				t.Fatal("unknown commit duplicated or lost effects")
			}
			restart, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			replay, err := restart.ConsentUpdate(f.ctx, r)
			if replay.Completion.CommandID != out.Completion.CommandID || !replay.Completion.Replayed || replay.Updated != (mode == "unknown") || mode == "unknown" && err != nil {
				t.Fatal("retry reexecuted original mutation", err)
			}
			var afterEffects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.consent-update'`).Scan(&afterEffects); err != nil || afterEffects != effects {
				t.Fatal("retry repeated generation effects", err)
			}
		})
	}
}

func TestNativeConsentNarrowingRejectsWithdrawnCredentialDespiteOriginalSealedSession(t *testing.T) {
	f := passwordFixtureWithChange(t, true)
	enableConsentNarrowing(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = broadConsentCode(t, f, service, []string{"identity:read", "identity:write"})
	consent := currentNarrowConsent(t, f, service)
	token, _ := session.ParseToken(f.browser.Token())
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	observed, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil || !observed.Authenticated {
		t.Fatal("real original session missing", err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	request := narrowRequest(t, f, consent, "withdrawn-credential", []string{"identity:read"})
	f.changePassword()
	if out, err := store.ConsentUpdate(f.ctx, oauth.ConsentUpdateExecution{Request: request, Session: observed, Client: f.oauth.Protocol.Clients[0]}); !errors.Is(err, oauth.ErrAccessDenied) || out.Updated || out.Completion.CommandID != "" {
		t.Fatal("old sealed observation bypassed current credential withdrawal", err)
	}
	var version, generation string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,generation::text FROM oauth_store.consents WHERE consent_id=$1`, consent.ID()).Scan(&version, &generation); err != nil || version != "1" || generation != "1" {
		t.Fatal("withdrawn credential advanced consent", err)
	}
}

func TestNativeConsentNarrowingSerializesWithRefreshAndApproval(t *testing.T) {
	for _, operation := range []string{"refresh", "approval"} {
		for _, narrowFirst := range []bool{true, false} {
			t.Run(operation+map[bool]string{true: "-narrow-wins", false: "-other-wins"}[narrowFirst], func(t *testing.T) {
				f := passwordFixture(t)
				enableConsentNarrowing(t, &f)
				s, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				code, proof := broadConsentCode(t, f, s, []string{"identity:read", "identity:write"})
				issued, err := s.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: proof, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
				if err != nil {
					t.Fatal(err)
				}
				refresh, _ := issued.RefreshToken.Reveal()
				var continuation string
				if operation == "approval" {
					begin, err := s.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", Resource: f.oauth.Protocol.Resource, Scopes: []string{"identity:read", "identity:write"}, CodeChallenge: oauth2.S256ChallengeFromVerifier(oauth2.GenerateVerifier())}})
					if err != nil {
						t.Fatal(err)
					}
					continuation, _ = begin.Continuation.Reveal()
				}
				consent := currentNarrowConsent(t, f, s)
				request := narrowRequest(t, f, consent, "contended-narrow", []string{"identity:read"})
				action := authorization.Action("identity.oauth-server.token")
				if operation == "approval" {
					action = "identity.oauth-server.continue"
				}
				if !narrowFirst {
					action = "identity.oauth-server.consent-update"
				}
				barrier := &consentRaceBarrier{owner: f.oauth.Coordinator.AdmissionPolicy.Authorization, action: action, ready: make(chan struct{}), release: make(chan struct{})}
				admission := *f.oauth.Coordinator.AdmissionPolicy
				admission.Authorization = barrier
				f.oauth.Coordinator.AdmissionPolicy = &admission
				s, err = oauthpostgres.NewService(f.pool, f.oauth, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(f.ctx, 8*time.Second)
				defer cancel()
				var once sync.Once
				release := func() { once.Do(func() { close(barrier.release) }) }
				defer release()
				type result struct {
					ok      bool
					err     error
					refresh oauth.Token
				}
				other := make(chan result, 1)
				narrow := make(chan result, 1)
				otherCall := func(ctx context.Context) {
					if operation == "refresh" {
						out, err := s.Token(ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"})
						other <- result{ok: err == nil && out.Outcome == identity.CommitOutcomeCommitted, err: err, refresh: out.RefreshToken}
					} else {
						out, err := s.Continue(ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true})
						other <- result{ok: err == nil && out.Outcome == oauth.AuthorizationRedirect, err: err}
					}
				}
				narrowCall := func(ctx context.Context) {
					out, err := s.ConsentUpdate(ctx, request)
					narrow <- result{ok: out.Updated, err: err}
				}
				var wg sync.WaitGroup
				wg.Add(1)
				if narrowFirst {
					go func() { defer wg.Done(); otherCall(context.WithValue(ctx, consentRaceKey{}, true)) }()
				} else {
					go func() { defer wg.Done(); narrowCall(context.WithValue(ctx, consentRaceKey{}, true)) }()
				}
				defer func() { release(); cancel(); wg.Wait() }()
				select {
				case <-barrier.ready:
				case <-ctx.Done():
					t.Fatal("native admission boundary not reached")
				}
				if narrowFirst {
					narrowCall(ctx)
				} else {
					otherCall(ctx)
				}
				release()
				var a, b result
				select {
				case a = <-narrow:
				case <-ctx.Done():
					t.Fatal("narrowing did not terminate")
				}
				select {
				case b = <-other:
				case <-ctx.Done():
					t.Fatal("other native command did not terminate")
				}
				if narrowFirst {
					if !a.ok || a.err != nil || b.ok {
						t.Fatal("losing broader operation crossed narrowing", a.err, b.err)
					}
				} else if operation == "approval" {
					if a.ok || !b.ok {
						t.Fatal("stale narrowing crossed approved version", a.err, b.err)
					}
				} else {
					if !a.ok || !b.ok {
						t.Fatal("serialized refresh then narrowing failed", a.err, b.err)
					}
					child, _ := b.refresh.Reveal()
					if out, err := s.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: child, Network: "192.0.2.1"}); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
						t.Fatal("new broader child survived later narrowing")
					}
				}
			})
		}
	}
}

func enableConsentNarrowing(t *testing.T, f *authenticatedPasswordFixture) {
	t.Helper()
	enableConsentManagement(t, f)
	query, admission := *f.oauth.Coordinator.QueryPolicy, *f.oauth.Coordinator.AdmissionPolicy
	query.Authorization = narrowConsentPolicy{query.Authorization}
	admission.Authorization = narrowConsentPolicy{admission.Authorization}
	f.oauth.Coordinator.QueryPolicy, f.oauth.Coordinator.AdmissionPolicy = &query, &admission
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	var err error
	f.oauth.RequestKeys, err = kernel.NewRequestKeyConfig("consent-narrow-test", key, query)
	if err != nil {
		t.Fatal(err)
	}
	f.oauth.ConsentNarrowing = true
}

func broadConsentCode(t *testing.T, f authenticatedPasswordFixture, s *oauth.Service, scopes []string) (string, string) {
	t.Helper()
	verifier := oauth2.GenerateVerifier()
	begin, err := s.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", Resource: "https://resource.example", Scopes: scopes, CodeChallenge: oauth2.S256ChallengeFromVerifier(verifier)}})
	if err != nil || begin.Outcome != oauth.ConsentRequired {
		t.Fatal("real consent interaction failed", err)
	}
	wire, _ := begin.Continuation.Reveal()
	approved, err := s.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, ClientID: "public-web", Continuation: wire, Origin: f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true})
	if err != nil || approved.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("real approval failed", err)
	}
	location, _ := approved.Location()
	callback, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	return callback.Query().Get("code"), verifier
}

func narrowRequest(t *testing.T, f authenticatedPasswordFixture, consent oauth.Consent, key string, scopes []string) oauth.ConsentUpdateRequest {
	t.Helper()
	requestKey, err := identity.NewIdempotencyKey([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	return oauth.ConsentUpdateRequest{Consent: ownConsentCommand(t, f, oauth.ConsentNarrow, consent.ID(), consent.Version()), ClientID: consent.ClientID(), ClientVersion: 1, Resource: f.oauth.Protocol.Resource, Scopes: scopes, RequestKey: requestKey}
}

func TestNativeConsentNarrowingKeyedGenerationAndRecovery(t *testing.T) {
	f := passwordFixture(t)
	enableConsentNarrowing(t, &f)
	service, child, _, _, _ := emailFixture(t, &f)
	code, proof := broadConsentCode(t, f, service, []string{"identity:read", "identity:write", "openid", "email"})
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: proof, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	access, _ := issued.AccessToken.Reveal()
	refresh, _ := issued.RefreshToken.Reveal()
	if info, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}); err != nil || info.Subject == "" || info.Email == "" {
		t.Fatal("original consented access/UserInfo unavailable", err)
	}
	oldCode, oldProof := broadConsentCode(t, f, service, []string{"identity:read", "identity:write", "openid", "email"})
	listed, err := service.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
	if err != nil || len(listed.Page.Items()) != 1 {
		t.Fatal("own consent missing", err)
	}
	consent := listed.Page.Items()[0]
	request := narrowRequest(t, f, consent, "original-narrow-key", []string{"identity:read"})
	out, err := service.ConsentUpdate(f.ctx, request)
	if err != nil || !out.Updated || out.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("keyed strict narrowing failed", err)
	}
	current, err := service.ConsentGet(f.ctx, oauth.ConsentGetRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRead, consent.ID(), 0)})
	if err != nil || current.Consent.Version() != consent.Version()+1 || !slices.Equal(current.Consent.Scopes(), []string{"identity:read"}) {
		t.Fatal("durable consent was not narrowed exactly once", err)
	}
	if got, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: oldCode, CodeVerifier: oldProof, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"}); err == nil || got.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("old-generation code survived")
	}
	if got, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: "public-web", RefreshToken: refresh, Network: "192.0.2.1"}); err == nil || got.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("old-generation refresh survived")
	}
	if info, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}); err == nil || info.Subject != "" || info.Email != "" {
		t.Fatal("old-generation access/UserInfo survived")
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restarted.ConsentUpdate(f.ctx, request)
	if err != nil || !replay.Updated || !replay.Completion.Replayed || replay.Completion.CommandID != out.Completion.CommandID {
		t.Fatal("new instance did not recover original keyed completion", err)
	}
	changed := request
	changed.Scopes = []string{"identity:write"}
	conflict, err := restarted.ConsentUpdate(f.ctx, changed)
	if !errors.Is(err, oauth.ErrConsentConflict) || conflict.Completion.Outcome != identity.CommitOutcomeConflict {
		t.Fatal("same key changed intent was not a conflict", err)
	}
	history, err := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.consent-update", CommandID: out.Completion.CommandID, ClientID: "public-web", TenantID: f.tenant, Session: f.browser, ConsentID: consent.ID()})
	if err != nil || history.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("authenticated original recovery failed", err)
	}
	code, proof = broadConsentCode(t, f, restarted, []string{"identity:read"})
	if got, err := restarted.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: proof, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"}); err != nil || got.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("new explicitly approved narrowed grant failed", err)
	}
}
