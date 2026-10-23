//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type exchangeFenceTraceKey struct{}

// Only the timing of real PostgreSQL calls is controlled. The final unlocked
// ancestor read has returned its original active row when QueryEnd runs; the
// separate actual owner commits withdrawal before protected admission resumes.
type exchangeFenceTrace struct {
	rootID             string
	late               func()
	started, completed atomic.Bool
}

func (t *exchangeFenceTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	selected := len(data.Args) > 0 && data.Args[0] == t.rootID && strings.HasPrefix(data.SQL, "SELECT artifact_id,COALESCE(parent_artifact_id,'')") && !strings.HasSuffix(data.SQL, " FOR SHARE")
	return context.WithValue(ctx, exchangeFenceTraceKey{}, selected)
}

func (t *exchangeFenceTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if data.Err != nil {
		return
	}
	selected, _ := ctx.Value(exchangeFenceTraceKey{}).(bool)
	if selected && t.started.CompareAndSwap(false, true) {
		t.late()
		t.completed.Store(true)
	}
}

func TestNativeRestrictedExchangeWithdrawalAfterPreflightIsProtected(t *testing.T) {
	for _, mode := range []string{"ancestor", "client", "unchanged"} {
		t.Run(mode, func(t *testing.T) {
			f := exchangeFixture(t)
			service, err := oauthpostgres.NewService(f.pool, f.config, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			root, err := service.Token(f.ctx, workloadRequest(f))
			if err != nil {
				t.Fatal(err)
			}
			rootWire, err := root.AccessToken.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			source, err := service.Token(f.ctx, exchangeRequest(f, rootWire, []string{"workload:read"}))
			if err != nil {
				t.Fatal(err)
			}
			sourceWire, err := source.AccessToken.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			current, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: sourceWire})
			if err != nil || !current.Active {
				t.Fatal("delegated source was not genuinely usable before preflight", err)
			}
			var rootID string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT artifact_id FROM oauth_store.artifacts WHERE grant_id=$1 AND workload_only AND parent_artifact_id IS NULL`, string(root.CommandID)).Scan(&rootID); err != nil {
				t.Fatal(err)
			}
			var withdrawalErr error
			trace := &exchangeFenceTrace{rootID: rootID}
			trace.late = func() {
				switch mode {
				case "ancestor":
					out, err := service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: rootWire, Network: "192.0.2.1"})
					withdrawalErr = err
					if err == nil && out.Outcome != identity.CommitOutcomeCommitted {
						withdrawalErr = errors.New("actual ancestor revocation did not commit")
					}
				case "client":
					tx, err := f.pool.Raw().Begin(f.ctx)
					if err != nil {
						withdrawalErr = err
						return
					}
					defer tx.Rollback(f.ctx)
					_, err = authority.AdvanceAuthority(f.ctx, tx, authority.AuthorityScope{TenantID: authorization.TenantID(f.client.Workload.TenantID()), PolicyNamespace: f.config.WorkloadExchangeClientNamespace, SubjectID: authorization.SubjectID(f.client.ID)}, f.client.Version, time.Second)
					if err != nil {
						withdrawalErr = err
						return
					}
					withdrawalErr = tx.Commit(f.ctx)
				}
			}
			pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("OAUTH_POSTGRES_TEST_DSN"), MaxConns: 2, Configure: func(config *database.PoolConfig) error {
				config.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
				config.ConnConfig.Tracer = trace
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := pool.Close(cleanup); err != nil {
					t.Error("traced exchange pool cleanup failed")
				}
			}()
			traced, err := oauthpostgres.NewService(pool, f.config, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			request := exchangeRequest(f, sourceWire, nil)
			request.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			out, exchangeErr := traced.Token(f.ctx, request)
			if withdrawalErr != nil || !trace.completed.Load() {
				t.Fatal("actual owner withdrawal did not complete at the preflight barrier", withdrawalErr)
			}
			wantChildren, wantEffects := 1, 0
			if mode == "unchanged" {
				wantChildren, wantEffects = 2, 1
				wire, revealErr := out.AccessToken.Reveal()
				if exchangeErr != nil || revealErr != nil || out.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("unchanged current authority did not issue through protected admission", exchangeErr)
				}
				if current, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: f.client.ID, ClientAuthentication: f.credential, Token: wire}); err != nil || !current.Active {
					t.Fatal("positive-control delegated child was not usable", err)
				}
			} else if exchangeErr == nil || out.Outcome == identity.CommitOutcomeCommitted || out.AccessToken != (oauth.Token{}) {
				t.Error("withdrawal committed after preflight still authorized exchange")
			}
			var children, effects, lifecycle int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.artifacts WHERE workload_exchange),(SELECT count(*) FROM oauth_store.effects WHERE command_id=$1),(SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_access.exchanged.v1')`, string(request.CommandID)).Scan(&children, &effects, &lifecycle); err != nil || children != wantChildren || effects != wantEffects || lifecycle != wantChildren {
				t.Error("protected admission produced incorrect child or committed exchange effects", err)
			}
		})
	}
}
