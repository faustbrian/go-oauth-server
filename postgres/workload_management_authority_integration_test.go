//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"maps"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type managedWorkloadReadKey struct{}
type managedWorkloadReadGate struct {
	count            atomic.Uint32
	keyVersion       uint32
	reached, proceed chan struct{}
}

func (g *managedWorkloadReadGate) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	// Introspection also probes refresh digests and retained keys. Pause only
	// the second real access lookup under its actual active key, after the first
	// complete authority pass; a refresh miss is not a second authority read.
	if ctx.Value(managedWorkloadReadKey{}) == true && strings.HasPrefix(q.SQL, `SELECT a.artifact_id,a.kind,`) && len(q.Args) > 2 && q.Args[0] == g.keyVersion && q.Args[2] == oauth.TokenAccess && g.count.Add(1) == 2 {
		close(g.reached)
		select {
		case <-g.proceed:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (*managedWorkloadReadGate) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestNativeManagedWorkloadOriginalSecretDeadlineFencesFinalWorkWithoutRotation(t *testing.T) {
	var armed, mutated atomic.Bool
	var shift atomic.Int64
	fault := &oauthCommitFault{beforeWrite: func(wire []byte) {
		if armed.Load() && bytes.Contains(wire, []byte(`INSERT INTO "oauth_store".artifacts`)) {
			mutated.Store(true)
			shift.Store(int64(20 * time.Second))
		}
	}}
	f := passwordFixture(t, fault)
	enableClientManagement(t, &f)
	w := installManagedWorkloadProfile(t, &f)
	f.oauth.Protocol.Clock = emailClock(func() time.Time { return time.Now().Add(time.Duration(shift.Load())) })
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.ClientCreate(f.ctx, managedWorkloadCreateRequest(t, f, w, "machine-original-secret-deadline"))
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := created.Secret.Reveal()
	basic := confidentialBasic(t, created.Client.ID, secret)
	armed.Store(true)
	out, err := service.Token(f.ctx, managedWorkloadTokenRequest(created.Client, basic))
	if !mutated.Load() {
		t.Fatal("original matched-secret deadline did not reach final protected Work")
	}
	if err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("expired original matched-secret evidence issued access")
	}
	var grants, artifacts int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.grants WHERE client_id=$1),(SELECT count(*) FROM oauth_store.artifacts WHERE client_id=$1)`, created.Client.ID).Scan(&grants, &artifacts); err != nil || grants != 0 || artifacts != 0 {
		t.Fatal("late secret deadline only withheld delivery after committing issuance", err)
	}
	armed.Store(false)
	shift.Store(0)
	if current, err := service.Token(f.ctx, managedWorkloadTokenRequest(created.Client, basic)); err != nil || current.AccessToken == (oauth.Token{}) {
		t.Fatal("independent fresh authentication could not issue after rollback", err)
	}
}

func TestNativeManagedWorkloadDeletionFencesPendingIssueAndLateIntrospection(t *testing.T) {
	for _, mode := range []string{"issue", "introspect"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			enableClientManagement(t, &f)
			w := installManagedWorkloadProfile(t, &f)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			r := managedWorkloadCreateRequest(t, f, w, "delete-race-managed-machine")
			created, err := service.ClientCreate(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			secret, _ := created.Secret.Reveal()
			basic := confidentialBasic(t, created.Client.ID, secret)
			var ready, release chan struct{}
			var late *oauth.Service
			var marked context.Context
			access := ""
			if mode == "issue" {
				barrier := &consentRaceBarrier{owner: f.oauth.Coordinator.AdmissionPolicy.Authorization, action: "identity.oauth-server.token", ready: make(chan struct{}), release: make(chan struct{})}
				admission := *f.oauth.Coordinator.AdmissionPolicy
				admission.Authorization = barrier
				f.oauth.Coordinator.AdmissionPolicy = &admission
				ready, release = barrier.ready, barrier.release
				marked = context.WithValue(f.ctx, consentRaceKey{}, true)
				late, err = oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			} else {
				issued, issueErr := service.Token(f.ctx, managedWorkloadTokenRequest(created.Client, basic))
				if issueErr != nil {
					t.Fatal(issueErr)
				}
				access, _ = issued.AccessToken.Reveal()
				gate := &managedWorkloadReadGate{keyVersion: f.oauth.ActiveTokenKeyVersion, reached: make(chan struct{}), proceed: make(chan struct{})}
				original := f.pool.Raw().Config().ConnConfig
				pool, poolErr := database.Connect(f.ctx, database.Config{DSN: original.ConnString(), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = original.Database
					c.ConnConfig.RuntimeParams = maps.Clone(original.RuntimeParams)
					c.ConnConfig.Tracer = gate
					return nil
				}})
				if poolErr != nil {
					t.Fatal(poolErr)
				}
				defer func() {
					ctx, stop := context.WithTimeout(context.Background(), time.Second)
					defer stop()
					if pool.Close(ctx) != nil {
						t.Error("owned introspection pool cleanup failed")
					}
				}()
				ready, release = gate.reached, gate.proceed
				marked = context.WithValue(f.ctx, managedWorkloadReadKey{}, true)
				late, err = oauthpostgres.NewService(pool, f.oauth, f.keys)
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(marked)
			type answer struct {
				token    oauth.TokenResult
				metadata oauth.IntrospectResult
				err      error
			}
			done := make(chan answer, 1)
			joined := false
			defer func() {
				cancel()
				select {
				case <-release:
				default:
					close(release)
				}
				if !joined {
					<-done
				}
			}()
			go func() {
				if mode == "issue" {
					out, err := late.Token(ctx, managedWorkloadTokenRequest(created.Client, basic))
					done <- answer{token: out, err: err}
					return
				}
				out, err := late.Introspect(ctx, oauth.IntrospectRequest{ClientID: created.Client.ID, ClientAuthentication: basic, Token: access})
				done <- answer{metadata: out, err: err}
			}()
			select {
			case <-ready:
			case out := <-done:
				joined = true
				t.Fatal("actual machine operation did not reach original late gate", out.err)
			case <-f.ctx.Done():
				t.Fatal("machine race gate canceled")
			}
			remove := r
			remove.ClientID, remove.Version, remove.Scopes, remove.Workload = created.Client.ID, created.Client.Version, nil, nil
			remove.RequestKey, _ = identity.NewIdempotencyKey([]byte("machine-race-terminal-delete"))
			if out, err := service.ClientDelete(f.ctx, remove); err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("concurrent machine deletion failed", err)
			}
			close(release)
			out := <-done
			joined = true
			if mode == "issue" && (out.err == nil || out.token.AccessToken != (oauth.Token{})) {
				t.Fatal("pending issuance ignored terminal deletion", out.err)
			}
			if mode == "introspect" && (out.metadata.Active || out.metadata.ClientID != "" || out.metadata.Subject != "") {
				t.Fatal("late introspection disclosed deleted machine authority", out.err)
			}
		})
	}
}
