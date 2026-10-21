//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"maps"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type clientReadKey struct{}
type clientReadGate struct {
	count            atomic.Uint32
	reached, proceed chan struct{}
}

func (g *clientReadGate) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if ctx.Value(clientReadKey{}) == true && strings.HasPrefix(q.SQL, `SELECT registration,version::text,client_id FROM `) && g.count.Add(1) == 2 {
		close(g.reached)
		select {
		case <-g.proceed:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (*clientReadGate) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func originalClientRead(t *testing.T, f authenticatedPasswordFixture) oauth.ClientReadExecution {
	t.Helper()
	reader, err := sessionpg.NewSessionService(f.pool, f.oauth.Session)
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(f.browser.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := reader.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil || !observed.Authenticated {
		t.Fatal("actual original private-read session", err)
	}
	return oauth.ClientReadExecution{Request: clientReadRequest(f, 1), Session: observed}
}

func TestNativeClientReadDirectExecutionCannotSubstituteActualSessionCustody(t *testing.T) {
	f := passwordFixture(t)
	enableClientRotation(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"direct-read-a", "direct-read-b"} {
		if _, err := service.ClientCreate(f.ctx, clientCreateRequest(t, f, key)); err != nil {
			t.Fatal(err)
		}
	}
	s, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	e := originalClientRead(t, f)
	positive, err := s.ClientList(f.ctx, e)
	if err != nil || len(positive.Page.Items()) != 1 || positive.NextCursor.String() == "" {
		t.Fatal("direct read positive control", err)
	}
	forged := e
	forged.Session = session.GetResult{Authenticated: true, Session: e.Session.Session}
	if out, err := s.ClientList(f.ctx, forged); err == nil || len(out.Page.Items()) != 0 || out.NextCursor.String() != "" {
		t.Fatal("public GetResult fields impersonated native custody")
	}
	otherBrowser, _ := f.anotherUser()
	substituted := e
	substituted.Request.Session = otherBrowser
	if out, err := s.ClientList(f.ctx, substituted); err == nil || len(out.Page.Items()) != 0 {
		t.Fatal("different actual session accepted original manager snapshot")
	}
	other := f
	other.browser = otherBrowser
	otherExecution := originalClientRead(t, other)
	b, _ := otherExecution.Session.Session.Bindings()
	policy := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
	policy.manager = authorization.SubjectID(b.UserID)
	config := f.oauth
	admission := *config.Coordinator.AdmissionPolicy
	query := *config.Coordinator.QueryPolicy
	admission.Authorization, query.Authorization = policy, policy
	config.Coordinator.AdmissionPolicy, config.Coordinator.QueryPolicy = &admission, &query
	otherService, err := oauthpostgres.NewService(f.pool, config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := otherService.ClientList(f.ctx, otherExecution.Request); err != nil || len(out.Page.Items()) != 1 {
		t.Fatal("second genuinely authorized actor positive control", err)
	}
	otherExecution.Request.Cursor = positive.NextCursor
	if out, err := otherService.ClientList(f.ctx, otherExecution.Request); err == nil || len(out.Page.Items()) != 0 || out.NextCursor.String() != "" {
		t.Fatal("genuinely authorized second actor reused original actor cursor")
	}
}

func TestNativeClientReadOriginalDeadlineCannotRenewAcrossLatePrimaryRead(t *testing.T) {
	f := passwordFixture(t)
	enableClientRotation(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.ClientCreate(f.ctx, clientCreateRequest(t, f, "read-original-deadline"))
	if err != nil {
		t.Fatal(err)
	}
	gate := &clientReadGate{reached: make(chan struct{}), proceed: make(chan struct{})}
	original := f.pool.Raw().Config().ConnConfig
	pool, err := database.Connect(f.ctx, database.Config{DSN: original.ConnString(), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = original.Database
		c.ConnConfig.RuntimeParams = maps.Clone(original.RuntimeParams)
		c.ConnConfig.Tracer = gate
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if pool.Close(cleanup) != nil {
			t.Error("deadline reader pool cleanup")
		}
	}()
	s, err := oauthpostgres.NewStore(pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	e := originalClientRead(t, f)
	e.Request.Limit, e.Request.ClientID = 0, created.Client.ID
	if out, err := s.ClientGet(f.ctx, e); err != nil || out.Client.ID != created.Client.ID {
		t.Fatal("original snapshot live positive control", err)
	}
	// Age the genuine sealed owner observation outside the bounded call. No
	// timestamp, credential proof, database authority or clock is fabricated.
	timer := time.NewTimer(time.Until(e.Session.ValidUntil().Add(-time.Second)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal("original observation aging canceled")
	}
	ctx, cancel := context.WithCancel(context.WithValue(f.ctx, clientReadKey{}, true))
	defer cancel()
	type answer struct {
		out oauth.ClientGetResult
		err error
	}
	done := make(chan answer, 1)
	joined := false
	defer func() {
		cancel()
		select {
		case <-gate.proceed:
		default:
			close(gate.proceed)
		}
		if !joined {
			<-done
		}
	}()
	go func() {
		out, err := s.ClientGet(ctx, e)
		done <- answer{out, err}
	}()
	select {
	case <-gate.reached:
	case out := <-done:
		joined = true
		t.Fatal("original observation did not reach late primary read", out.err)
	case <-f.ctx.Done():
		t.Fatal("original deadline gate canceled")
	}
	until := time.NewTimer(time.Until(e.Session.ValidUntil().Add(time.Millisecond)))
	defer until.Stop()
	select {
	case <-until.C:
	case <-ctx.Done():
		t.Fatal("exclusive deadline wait canceled")
	}
	close(gate.proceed)
	out := <-done
	joined = true
	if out.err == nil || out.out.Client.ID != "" || e.Session.ValidateAt(time.Now().UTC()) == nil {
		t.Fatal("late re-observation renewed original private-read lifetime")
	}
	if out, err := s.ClientGet(f.ctx, e); err == nil || out.Client.ID != "" {
		t.Fatal("failed original observation renewed on retry")
	}
	if out, err := service.ClientGet(f.ctx, e.Request); err != nil || out.Client.ID != created.Client.ID {
		t.Fatal("fresh independently authenticated retry positive control", err)
	}
}

func TestNativeClientReadRejectsLateClientAndCurrentManagerChangesWithoutPartialPages(t *testing.T) {
	for _, mode := range []string{"rotate-get", "rotate-list", "delete-get", "delete-list", "policy-get", "epoch-list", "outage-get", "cancel-list"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			denied := enableClientRotation(t, &f)
			controller, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := controller.ClientCreate(f.ctx, clientCreateRequest(t, f, "late-read-create")); err != nil {
				t.Fatal(err)
			}
			positive, err := controller.ClientList(f.ctx, clientReadRequest(f, 1))
			if err != nil || len(positive.Page.Items()) != 1 {
				t.Fatal("late read positive control", err)
			}
			client := positive.Page.Items()[0]
			gate := &clientReadGate{reached: make(chan struct{}), proceed: make(chan struct{})}
			original := f.pool.Raw().Config().ConnConfig
			pool, err := database.Connect(f.ctx, database.Config{DSN: original.ConnString(), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = original.Database
				c.ConnConfig.RuntimeParams = maps.Clone(original.RuntimeParams)
				c.ConnConfig.Tracer = gate
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if pool.Close(cleanup) != nil {
					t.Error("private-read pool cleanup")
				}
			}()
			late, err := oauthpostgres.NewService(pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.WithValue(f.ctx, clientReadKey{}, true))
			defer cancel()
			type answer struct {
				err    error
				id     string
				items  int
				cursor string
			}
			done := make(chan answer, 1)
			joined := false
			defer func() {
				cancel()
				select {
				case <-gate.proceed:
				default:
					close(gate.proceed)
				}
				if !joined {
					<-done
				}
			}()
			go func() {
				r := clientReadRequest(f, 1)
				if strings.HasSuffix(mode, "-get") {
					r.Limit = 0
					r.ClientID = client.ID
					out, err := late.ClientGet(ctx, r)
					done <- answer{err: err, id: out.Client.ID}
				} else {
					out, err := late.ClientList(ctx, r)
					done <- answer{err: err, items: len(out.Page.Items()), cursor: out.NextCursor.String()}
				}
			}()
			select {
			case <-gate.reached:
			case out := <-done:
				joined = true
				t.Fatal("private read did not reach actual final metadata query", out.err)
			case <-f.ctx.Done():
				t.Fatal("bounded private read gate canceled")
			}
			switch {
			case strings.HasPrefix(mode, "rotate-"):
				if _, err := controller.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, client, "late-read-rotation", 0)); err != nil {
					t.Fatal(err)
				}
			case strings.HasPrefix(mode, "delete-"):
				if _, err := controller.ClientDelete(f.ctx, clientRotationRequest(t, f, client, "late-read-delete", 0).Management); err != nil {
					t.Fatal(err)
				}
			case mode == "policy-get":
				denied.Store(true)
			case mode == "epoch-list":
				owner, err := authority.NewAuthorityStore(f.pool.Raw(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				manager := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy).manager
				scope := authority.AuthorityScope{TenantID: authorization.TenantID(f.tenant), PolicyNamespace: f.oauth.Session.Profile.PolicyNamespace, SubjectID: manager}
				current, err := owner.Get(f.ctx, scope)
				if err != nil {
					t.Fatal(err)
				}
				tx, err := f.pool.Raw().Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := authority.AdvanceAuthority(f.ctx, tx, scope, current.Version, time.Second); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
			case mode == "outage-get":
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE oauth_store.managed_clients RENAME TO unavailable_clients`); err != nil {
					t.Fatal(err)
				}
			case mode == "cancel-list":
				cancel()
			}
			close(gate.proceed)
			out := <-done
			joined = true
			if out.err == nil || out.id != "" || out.items != 0 || out.cursor != "" {
				t.Fatal("late current-authority failure disclosed private metadata")
			}
			if mode == "cancel-list" && !errors.Is(out.err, context.Canceled) {
				t.Fatal("private read cancellation lost", out.err)
			}
			if mode == "outage-get" {
				if _, err := f.pool.Raw().Exec(f.ctx, `ALTER TABLE oauth_store.unavailable_clients RENAME TO managed_clients`); err != nil {
					t.Fatal(err)
				}
				r := clientReadRequest(f, 0)
				r.ClientID = client.ID
				if current, err := late.ClientGet(f.ctx, r); err != nil || current.Client.ID != client.ID {
					t.Fatal("bounded retry failed to reread restored current authority", err)
				}
			}
		})
	}
}
