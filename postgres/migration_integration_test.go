//go:build integration

package oauthpostgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

type terminalMigrationSnapshot struct {
	rows   int
	digest []byte
	checks map[string]string
}

func terminalMigrationState(t *testing.T, ctx context.Context, pool *database.Pool) terminalMigrationSnapshot {
	t.Helper()
	state := terminalMigrationSnapshot{checks: make(map[string]string)}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*),sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(c) ORDER BY command_id)::text,'[]'),'UTF8')) FROM identity.commands c WHERE state IN ('committed','aborted')`).Scan(&state.rows, &state.digest); err != nil || state.rows == 0 {
		t.Fatal("populated real terminal history unavailable for forward migration", err)
	}
	rows, err := pool.Raw().Query(ctx, `SELECT conname,pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='identity.commands'::regclass AND contype='c'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, definition string
		if err := rows.Scan(&name, &definition); err != nil {
			t.Fatal(err)
		}
		state.checks[name] = definition
	}
	if rows.Err() != nil || state.checks["identity_command_terminal_shape"] == "" {
		t.Fatal("installed terminal shape unavailable", rows.Err())
	}
	return state
}

func requireTerminalMigrationPreserved(t *testing.T, ctx context.Context, pool *database.Pool, before terminalMigrationSnapshot) {
	t.Helper()
	after := terminalMigrationState(t, ctx, pool)
	if before.rows != after.rows || !bytes.Equal(before.digest, after.digest) || len(before.checks) != len(after.checks) {
		t.Fatal("forward OAuth classification migration changed populated terminal history or old CHECK inventory")
	}
	for name, definition := range before.checks {
		actual := after.checks[name]
		if name == "identity_command_terminal_shape" {
			const addition = ", 'reauthentication-required'::text"
			if strings.Contains(definition, "reauthentication-required") || strings.Count(actual, addition) != 1 {
				t.Fatal("forward migration did not add only the closed OAuth terminal classification")
			}
			actual = strings.Replace(actual, addition, "", 1)
		}
		if actual != definition {
			t.Fatal("forward migration changed an existing CHECK invariant")
		}
	}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	probe, err := tx.Begin(ctx) // A real savepoint; no malformed history survives.
	if err != nil {
		t.Fatal(err)
	}
	_, err = probe.Exec(ctx, `UPDATE identity.commands SET result_version=NULL WHERE command_id=(SELECT command_id FROM identity.commands WHERE state='committed' ORDER BY command_id LIMIT 1)`)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23514" || constraint.ConstraintName != "identity_command_terminal_shape" {
		t.Fatal("forward migration weakened populated committed terminal-shape rejection")
	}
	if err := probe.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	unchanged := terminalMigrationState(t, ctx, pool)
	if unchanged.rows != after.rows || !bytes.Equal(unchanged.digest, after.digest) {
		t.Fatal("rolled-back malformed-row probe changed terminal history")
	}
}

// The caller must explicitly provide a task-owned disposable
// loopback cluster. Every test creates and drops its own separate database.
// Existing databases and cluster configuration must never be changed.
func isolatedPostgres(t *testing.T, referenceRoles bool, faults ...*oauthCommitFault) (context.Context, *database.Pool, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("OAUTH_POSTGRES_TEST_DSN")
	expectedDirectory := os.Getenv("OAUTH_POSTGRES_TEST_DATA_DIRECTORY")
	c, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || c.Host != "127.0.0.1" || c.Port == 0 || c.Database == "" || len(expectedDirectory) > 4096 || !filepath.IsAbs(expectedDirectory) || filepath.Clean(expectedDirectory) != expectedDirectory {
		t.Fatal("explicit task-owned loopback PG18 DSN and exact expected data directory required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		t.Fatal("disposable PostgreSQL unavailable")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if admin.Close(cleanup) != nil {
			t.Error("administrative connection cleanup failed")
		}
	})
	var directory string
	if err := admin.QueryRow(ctx, "SHOW data_directory").Scan(&directory); err != nil || directory != expectedDirectory {
		t.Fatal("administrative connection is not the exact borrowed task-owned cluster")
	}
	var serverVersion int
	if err := admin.QueryRow(ctx, "SELECT current_setting('server_version_num')::integer").Scan(&serverVersion); err != nil || serverVersion < 180000 || serverVersion >= 190000 {
		t.Fatal("explicit PostgreSQL18 fixture required")
	}
	if referenceRoles {
		// The public reference audit migration creates cluster-global roles. A
		// private database alone therefore does not isolate this fixture. Only
		// roles proven absent before installation may be removed after DB drop.
		var existing int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname IN ('audit_writer','audit_reader','audit_retention')`).Scan(&existing); err != nil || existing != 0 {
			t.Fatal("reference fixture requires absent audit roles; pre-existing roles are not task-owned")
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			var dependencies int
			if err := admin.QueryRow(cleanup, `SELECT
			(SELECT count(*) FROM pg_shdepend d JOIN pg_roles r ON d.refclassid='pg_authid'::regclass AND d.refobjid=r.oid WHERE r.rolname IN ('audit_writer','audit_reader','audit_retention')) +
			(SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON m.roleid=r.oid OR m.member=r.oid WHERE r.rolname IN ('audit_writer','audit_reader','audit_retention'))`).Scan(&dependencies); err != nil || dependencies != 0 {
				t.Error("owned audit-role cleanup refused: roles are still in use")
				return
			}
			if _, err := admin.Exec(cleanup, "DROP ROLE IF EXISTS audit_writer,audit_reader,audit_retention"); err != nil {
				t.Error("owned audit-role cleanup failed")
			}
		})
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal("database-name entropy unavailable")
	}
	name := "oauth_code_worker_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal("owned database creation failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("owned database cleanup failed")
		}
	})
	c.Database = name
	c.RuntimeParams["search_path"] = "public"
	db := stdlib.OpenDB(*c)
	t.Cleanup(func() {
		if db.Close() != nil {
			t.Error("SQL pool cleanup failed")
		}
	})
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(native *database.PoolConfig) error {
		native.ConnConfig.Database = name
		native.ConnConfig.RuntimeParams["search_path"] = "public"
		if len(faults) == 1 {
			native.ConnConfig.DialFunc = faults[0].dial
		}
		return nil
	}})
	if err != nil {
		t.Fatal("owned primary pool unavailable")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if pool.Close(cleanup) != nil {
			t.Error("owned primary pool cleanup failed")
		}
	})
	var actualDatabase string
	if err := pool.Raw().QueryRow(ctx, "SELECT current_database()").Scan(&actualDatabase); err != nil || actualDatabase != name {
		t.Fatal("primary pool did not select the exact task-owned database")
	}
	if err := db.QueryRowContext(ctx, "SELECT current_database()").Scan(&actualDatabase); err != nil || actualDatabase != name {
		t.Fatal("migration connection did not select the exact task-owned database")
	}
	return ctx, pool, db
}

func TestOAuthMigrationRejectsInvalidStateAndOwnsNoIdentityForeignKeys(t *testing.T) {
	ctx, pool, db := isolatedPostgres(t, false)
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("oauth_server")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, backend)
	if err != nil {
		t.Fatal(err)
	}
	first, err := runner.Up(ctx)
	if err != nil || len(first.Records()) != 1 {
		t.Fatal("fresh OAuth install failed", err)
	}
	second, err := runner.Up(ctx)
	if err != nil || len(second.Records()) != 0 {
		t.Fatal("migration replay changed installed history", err)
	}
	// This is a schema-contract test, not a fabricated authenticated flow. No
	// identity/session data exists; the adapter must not acquire their ownership.
	var foreignKeys int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='oauth_store' AND c.contype='f' AND c.confrelid IN (SELECT cl.oid FROM pg_class cl JOIN pg_namespace ns ON ns.oid=cl.relnamespace WHERE ns.nspname IN ('identity','session_store'))`).Scan(&foreignKeys); err != nil || foreignKeys != 0 {
		t.Fatal("OAuth adapter acquired identity/session foreign-key ownership", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	const insertGrant = `INSERT INTO oauth_store.grants(grant_id,tenant_id,user_id,client_id,client_version,client_fingerprint,source_session,scopes,resource,state,created_at,expires_at,version) VALUES('QWJjZGVmZ2hpamtsbW5vcA','tenant','user','client',1,$1,'[{}]'::jsonb,'["identity:read"]'::jsonb,'https://resource.example',$2,$3,$4,1)`
	if _, err := pool.Raw().Exec(ctx, insertGrant, make([]byte, 32), "active", now, now.Add(time.Hour)); err != nil {
		t.Fatal("positive schema fixture was invalid", err)
	}
	if _, err := pool.Raw().Exec(ctx, `DELETE FROM oauth_store.grants WHERE grant_id='QWJjZGVmZ2hpamtsbW5vcA'`); err != nil {
		t.Fatal("owned schema fixture cleanup failed", err)
	}
	for _, state := range []string{"unknown", "", "restored"} {
		_, err := pool.Raw().Exec(ctx, insertGrant, make([]byte, 32), state, now, now.Add(time.Hour))
		if err == nil {
			t.Fatal("unrecognized grant lifecycle became durable")
		}
	}
	if _, err := pool.Raw().Exec(ctx, insertGrant, make([]byte, 32), "active", now, now); err == nil {
		t.Fatal("zero-lifetime grant became durable")
	}
}
