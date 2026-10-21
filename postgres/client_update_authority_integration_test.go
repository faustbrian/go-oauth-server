//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

type clientUpdateApplyGate struct {
	armed            atomic.Bool
	queries          atomic.Uint32
	provisional      atomic.Bool
	reached, release chan struct{}
	done             <-chan struct{}
}

func (g *clientUpdateApplyGate) observe(wire []byte) {
	if bytes.Contains(wire, []byte(`UPDATE "oauth_store".managed_clients SET version=version+1,registration=$2::jsonb`)) {
		g.provisional.Store(true)
	}
	if g.armed.Load() && bytes.Contains(wire, []byte(`FROM "oauth_store".managed_clients WHERE client_id=$1 FOR UPDATE`)) && g.queries.Add(1) == 2 {
		close(g.reached)
		select {
		case <-g.release:
		case <-g.done:
		}
	}
}

func TestNativeClientUpdateOriginalAdmissionExpiresAcrossActualClientLockWait(t *testing.T) {
	gate := &clientUpdateApplyGate{reached: make(chan struct{}), release: make(chan struct{})}
	f := passwordFixture(t, &oauthCommitFault{beforeWrite: gate.observe})
	gate.done = f.ctx.Done()
	enableClientUpdates(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.ClientCreate(f.ctx, clientCreateRequest(t, f, "deadline-update-create"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	original := originalClientRead(t, f).Session
	// Genuine original owner custody ages outside the bounded call. Only its
	// final three seconds occur in Work; no clock or source proof is fabricated.
	waitAuthenticationBoundary(t, f, original.ValidUntil().Add(-3*time.Second))
	blocker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	var blockerID uint32
	if err := blocker.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&blockerID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	r := clientUpdateRequest(t, f, created.Client, "original-deadline-update")
	type answer struct {
		out oauth.ClientUpdateResult
		err error
	}
	done := make(chan answer, 1)
	joined := false
	defer func() {
		cancel()
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
		_ = blocker.Rollback(context.Background())
		if !joined {
			<-done
		}
	}()
	gate.armed.Store(true)
	go func() {
		out, err := store.UpdateClient(ctx, oauth.ClientUpdateExecution{Request: r, Session: original})
		done <- answer{out, err}
	}()
	select {
	case <-gate.reached:
	case out := <-done:
		joined = true
		t.Fatal("original update did not reach live Apply client fence", out.err)
	case <-f.ctx.Done():
		t.Fatal("original Apply gate canceled")
	}
	if original.ValidateAt(time.Now()) != nil {
		t.Fatal("original update not live at Apply positive control")
	}
	if _, err := blocker.Exec(f.ctx, `SELECT client_id FROM oauth_store.managed_clients WHERE client_id=$1 FOR UPDATE`, created.Client.ID); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	for {
		var waiting int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, blockerID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if !time.Now().Before(original.ValidUntil()) {
			t.Fatal("update did not actually wait on client root while live")
		}
		waitAuthenticationBoundary(t, f, time.Now().Add(10*time.Millisecond))
	}
	waitAuthenticationBoundary(t, f, original.ValidUntil().Add(time.Millisecond))
	if err := blocker.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	out := <-done
	joined = true
	if out.err == nil || out.out.Client.ID != "" || gate.provisional.Load() {
		t.Fatal("expired original update crossed SQL wait into mutation", out.err)
	}
	var version, generation string
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,secret_version::text,(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-update') FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&version, &generation, &effects); err != nil || version != "1" || generation != "1" || effects != 0 {
		t.Fatal("expired update changed durable authority", err)
	}
	if out, err := service.ClientUpdate(f.ctx, clientUpdateRequest(t, f, created.Client, "fresh-update-positive")); err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("fresh independently read update positive control", err)
	}
}

func TestNativeClientUpdateOriginalCommittedPreparationCannotRenewOnFreshRetry(t *testing.T) {
	f := passwordFixture(t)
	enableClientUpdates(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.ClientCreate(f.ctx, clientCreateRequest(t, f, "retry-deadline-create"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	original := originalClientRead(t, f).Session
	r := clientUpdateRequest(t, f, created.Client, "retry-deadline-original")
	committed, err := store.UpdateClient(f.ctx, oauth.ClientUpdateExecution{Request: r, Session: original})
	if err != nil || committed.Client.Version != 2 {
		t.Fatal("original committed preparation control", err)
	}
	if live, err := service.ClientUpdate(f.ctx, r); err != nil || !live.Completion.Replayed || live.Completion.CommandID != committed.Completion.CommandID || live.Client.Version != 2 {
		t.Fatal("fresh invocation preserves live original preparation", err)
	}
	// A new service call obtains genuine fresh B, but restored preparation A
	// retains this actual owner's original exclusive deadline, including retry.
	waitAuthenticationBoundary(t, f, original.ValidUntil().Add(time.Millisecond))
	late, err := service.ClientUpdate(f.ctx, r)
	if err == nil || late.Client.ID != "" || late.Completion.CommandID != committed.Completion.CommandID || late.Completion.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("fresh retry renewed original committed preparation", err)
	}
	var version string
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,(SELECT count(*) FROM oauth_store.effects WHERE command_id=$2) FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID, string(committed.Completion.CommandID)).Scan(&version, &effects); err != nil || version != "2" || effects != 1 {
		t.Fatal("expired retry repeated authority/effects", err)
	}
	get := clientReadRequest(f, 0)
	get.ClientID = created.Client.ID
	if current, err := service.ClientGet(f.ctx, get); err != nil || current.Client.Version != 2 {
		t.Fatal("independent current authority remains readable", err)
	}
}

func TestNativeClientUpdateExactManagerCSRFAndVersionDenials(t *testing.T) {
	f := passwordFixture(t)
	enableClientUpdates(t, &f)
	policy := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
	policy.inspect = func(ctx context.Context) error {
		var locked bool
		if err := f.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_class r ON r.oid=l.relation JOIN pg_namespace n ON n.oid=r.relnamespace JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND l.granted AND l.mode IN('RowShareLock','RowExclusiveLock') AND n.nspname IN('identity','session_store','oauth_store'))`).Scan(&locked); err != nil {
			return err
		}
		if locked {
			return errors.New("platform decision invoked under protected lock")
		}
		return nil
	}
	admission := *f.oauth.Coordinator.AdmissionPolicy
	admission.Authorization = policy
	f.oauth.Coordinator.AdmissionPolicy = &admission
	s, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.ClientCreate(f.ctx, clientCreateRequest(t, f, "denial-update-create"))
	if err != nil {
		t.Fatal(err)
	}
	other, csrf := f.anotherUser()
	for _, mode := range []string{"owner", "tenant", "manager", "csrf", "origin", "public", "static", "version", "zero-version", "embedded-edit", "redirect", "scope", "empty", "policy", "disabled"} {
		bad := clientUpdateRequest(t, f, created.Client, "denial-update-"+mode)
		selected := s
		switch mode {
		case "owner":
			bad.Management.Owner, _ = oauth.NewPlatformOwner("foreign")
		case "tenant":
			bad.Management.TenantID = "foreign"
		case "manager":
			bad.Management.Session, bad.Management.CSRF = other, csrf
		case "csrf":
			bad.Management.CSRF, _ = session.NewCSRFToken()
		case "origin":
			bad.Management.Origin = "https://foreign.example"
		case "public":
			bad.Management.Public = true
		case "static":
			bad.Management.ClientID = "public-web"
		case "version":
			bad.Management.Version = 2
		case "zero-version":
			bad.Management.Version = 0
		case "embedded-edit":
			bad.Management.Scopes = []string{"identity:read"}
		case "redirect":
			bad.Redirects = []string{"https://foreign.example/cb"}
		case "scope":
			bad.Scopes = []string{"openid"}
		case "empty":
			bad.Scopes = nil
		case "policy":
			policy.denied.Store(true)
		case "disabled":
			config := f.oauth
			config.ClientMetadataUpdates = false
			selected, err = oauthpostgres.NewService(f.pool, config, f.keys)
			if err != nil {
				t.Fatal(err)
			}
		}
		out, err := selected.ClientUpdate(f.ctx, bad)
		if err == nil || out.Client.ID != "" {
			t.Fatal("invalid current-manager replacement admitted", mode)
		}
		policy.denied.Store(false)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	r := clientUpdateRequest(t, f, created.Client, "native-original-update")
	if out, err := store.UpdateClient(f.ctx, oauth.ClientUpdateExecution{Request: r, Session: session.GetResult{Authenticated: true}}); err == nil || out.Client.ID != "" {
		t.Fatal("forged update session observation admitted")
	}
	original := originalClientRead(t, f).Session
	stale := f.oauth
	stale.Protocol.Clock = emailClock(func() time.Time { return original.ValidUntil() })
	staleStore, err := oauthpostgres.NewStore(f.pool, stale, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := staleStore.UpdateClient(f.ctx, oauth.ClientUpdateExecution{Request: r, Session: original}); err == nil || out.Client.ID != "" {
		t.Fatal("expired original management custody renewed")
	}
	var version, generation string
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,secret_version::text,(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-update') FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&version, &generation, &effects); err != nil || version != "1" || generation != "1" || effects != 0 {
		t.Fatal("denial changed registration authority/effects", err)
	}
	if out, err := s.ClientUpdate(f.ctx, r); err != nil || out.Client.Version != 2 {
		t.Fatal("exact current manager unlocked-policy positive control", err)
	}
}

func updateBarrierService(t *testing.T, f authenticatedPasswordFixture, action string) (*oauth.Service, *consentRaceBarrier) {
	t.Helper()
	barrier := &consentRaceBarrier{owner: f.oauth.Coordinator.AdmissionPolicy.Authorization, action: authorization.Action(action), ready: make(chan struct{}), release: make(chan struct{})}
	config := f.oauth
	admission := *config.Coordinator.AdmissionPolicy
	admission.Authorization = barrier
	config.Coordinator.AdmissionPolicy = &admission
	s, err := oauthpostgres.NewService(f.pool, config, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	return s, barrier
}

func TestNativeClientUpdateSerializesWithUpdateRotationAndDelete(t *testing.T) {
	for _, mode := range []string{"update-wins-update", "rotation-wins-update", "delete-wins-update", "update-wins-rotation", "update-wins-delete"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			enableClientUpdates(t, &f)
			winner, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			created, err := winner.ClientCreate(f.ctx, clientCreateRequest(t, f, "contention-update-create"))
			if err != nil {
				t.Fatal(err)
			}
			lateKind := strings.TrimPrefix(mode, strings.Split(mode, "-wins-")[0]+"-wins-")
			action := "identity.oauth-server.client-update"
			if lateKind == "rotation" {
				action = "identity.oauth-server.client-rotate-secret"
			}
			if lateKind == "delete" {
				action = "identity.oauth-server.client-delete"
			}
			late, gate := updateBarrierService(t, f, action)
			ctx, cancel := context.WithCancel(context.WithValue(f.ctx, consentRaceKey{}, true))
			defer cancel()
			type answer struct {
				update   oauth.ClientUpdateResult
				rotation oauth.ClientSecretRotationResult
				deletion oauth.ClientManagementResult
				err      error
			}
			done := make(chan answer, 1)
			joined := false
			defer func() {
				cancel()
				select {
				case <-gate.release:
				default:
					close(gate.release)
				}
				if !joined {
					<-done
				}
			}()
			lateUpdate := clientUpdateRequest(t, f, created.Client, "contention-update-late")
			lateMutation := clientRotationRequest(t, f, created.Client, "contention-other-late", time.Minute)
			go func() {
				if lateKind == "rotation" {
					out, err := late.ClientRotateSecret(ctx, lateMutation)
					done <- answer{rotation: out, err: err}
				} else if lateKind == "delete" {
					out, err := late.ClientDelete(ctx, lateMutation.Management)
					done <- answer{deletion: out, err: err}
				} else {
					out, err := late.ClientUpdate(ctx, lateUpdate)
					done <- answer{update: out, err: err}
				}
			}()
			select {
			case <-gate.ready:
			case out := <-done:
				joined = true
				t.Fatal("native original management not suspended before winning mutation", out.err)
			case <-f.ctx.Done():
				t.Fatal("management contention canceled")
			}
			state, generation := "active", "1"
			if strings.HasPrefix(mode, "rotation-") {
				if _, err := winner.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, created.Client, "contention-rotation-winner", 0)); err != nil {
					t.Fatal(err)
				}
				generation = "2"
			} else if strings.HasPrefix(mode, "delete-") {
				if _, err := winner.ClientDelete(f.ctx, clientRotationRequest(t, f, created.Client, "contention-delete-winner", 0).Management); err != nil {
					t.Fatal(err)
				}
				state = "deleted"
			} else if _, err := winner.ClientUpdate(f.ctx, clientUpdateRequest(t, f, created.Client, "contention-update-winner")); err != nil {
				t.Fatal(err)
			}
			close(gate.release)
			out := <-done
			joined = true
			if !errors.Is(out.err, oauth.ErrAccessDenied) {
				t.Fatal("stale contending operation did not return access denial", out.err)
			}
			if !reflect.DeepEqual(out.update.Client, oauth.Client{}) || !reflect.DeepEqual(out.rotation.Client, oauth.Client{}) || !reflect.DeepEqual(out.deletion.Client, oauth.Client{}) || out.rotation.Secret != (oauth.Token{}) || out.deletion.Secret != (oauth.Token{}) || !out.rotation.PredecessorExpiresAt.IsZero() {
				t.Fatal("denied contending operation disclosed client metadata or secret custody")
			}
			var v, g, st string
			var effects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,secret_version::text,state,(SELECT count(*) FROM oauth_store.effects WHERE client_id=$1) FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&v, &g, &st, &effects); err != nil || v != "2" || g != generation || st != state || effects != 2 {
				t.Fatal("contended operation repeated generation/effects", err)
			}
		})
	}
}

func TestNativeClientUpdateLateCurrentManagerWithdrawalDenies(t *testing.T) {
	for _, mode := range []string{"epoch", "logout"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			enableClientUpdates(t, &f)
			controller, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			created, err := controller.ClientCreate(f.ctx, clientCreateRequest(t, f, "withdraw-update-create"))
			if err != nil {
				t.Fatal(err)
			}
			late, gate := updateBarrierService(t, f, "identity.oauth-server.client-update")
			ctx, cancel := context.WithCancel(context.WithValue(f.ctx, consentRaceKey{}, true))
			defer cancel()
			r := clientUpdateRequest(t, f, created.Client, "withdraw-update-original")
			type answer struct {
				out oauth.ClientUpdateResult
				err error
			}
			done := make(chan answer, 1)
			joined := false
			defer func() {
				cancel()
				select {
				case <-gate.release:
				default:
					close(gate.release)
				}
				if !joined {
					<-done
				}
			}()
			go func() {
				out, err := late.ClientUpdate(ctx, r)
				done <- answer{out, err}
			}()
			select {
			case <-gate.ready:
			case out := <-done:
				joined = true
				t.Fatal("current manager gate missed", out.err)
			case <-f.ctx.Done():
				t.Fatal("withdrawal canceled")
			}
			if mode == "logout" {
				f.signOut()
			} else {
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
			}
			close(gate.release)
			out := <-done
			joined = true
			if !errors.Is(out.err, oauth.ErrAccessDenied) {
				t.Fatal("late current manager withdrawal did not return access denial", out.err)
			}
			if !reflect.DeepEqual(out.out.Client, oauth.Client{}) {
				t.Fatal("withdrawn manager received client metadata")
			}
			var version string
			var effects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-update') FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&version, &effects); err != nil || version != "1" || effects != 0 {
				t.Fatal("withdrawn manager changed client", err)
			}
		})
	}
}
