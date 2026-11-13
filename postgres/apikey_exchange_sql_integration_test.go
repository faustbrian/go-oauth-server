//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
)

// Native Work bypasses pgx.QueryTracer. Its exact Parse/Bind frames are captured
// separately; ordinary pool calls retain their actual typed Go driver arguments.
// Only these OAuth query families are retained, never identity preparation,
// source verification, session rows, raw credentials or received row contents.
type apiKeySQLSample struct {
	sql       string
	arguments []any
	values    [][]byte
	oids      []uint32
	formats   []int16
}
type apiKeySQLTrace struct {
	mu             sync.Mutex
	active, failed bool
	executions     int
	samples        map[string]apiKeySQLSample
}

func selectedAPIKeySQL(sql string) bool {
	if strings.HasPrefix(sql, "SELECT count(*)=4 AND bool_and(convalidated) FROM pg_constraint") {
		return true
	}
	if !strings.Contains(sql, `"oauth_store".`) {
		return false
	}
	lookup := strings.HasPrefix(sql, "SELECT a.artifact_id,a.kind,") && strings.Contains(sql, "g.api_key_source")
	grantFence := strings.HasPrefix(sql, "SELECT state,version::text,") && strings.Contains(sql, "api_key_source")
	ancestry := strings.HasPrefix(sql, "SELECT COALESCE(parent_artifact_id,''),kind,state,payload,")
	grantInsert := strings.HasPrefix(sql, `INSERT INTO "oauth_store".grants(`) && strings.Contains(sql, "api_key_source")
	accessInsert := strings.HasPrefix(sql, `INSERT INTO "oauth_store".artifacts(`) && strings.Contains(sql, "api_key_only")
	return lookup || grantFence || ancestry || grantInsert || accessInsert
}

func (t *apiKeySQLTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.active || !selectedAPIKeySQL(data.SQL) {
		return ctx
	}
	key := "pool:" + data.SQL
	if _, exists := t.samples[key]; !exists {
		args := slices.Clone(data.Args)
		for i, arg := range args {
			if value, ok := arg.([]byte); ok {
				args[i] = slices.Clone(value)
			}
		}
		t.samples[key] = apiKeySQLSample{sql: data.SQL, arguments: args}
	}
	return ctx
}
func (*apiKeySQLTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

type apiKeySQLWriter struct {
	destination io.Writer
	trace       *apiKeySQLTrace
	statements  map[string]pgproto3.Parse
}

func (w *apiKeySQLWriter) Write(data []byte) (int, error) {
	n, err := w.destination.Write(data)
	if err != nil || n != len(data) {
		return n, err
	}
	w.trace.mu.Lock()
	defer w.trace.mu.Unlock()
	if !w.trace.active {
		return n, nil
	}
	for len(data) > 0 {
		if data[0] == 0 {
			break
		}
		if len(data) < 5 {
			w.trace.failed = true
			break
		}
		size := uint64(binary.BigEndian.Uint32(data[1:5]))
		if size < 4 || size+1 > uint64(len(data)) {
			w.trace.failed = true
			break
		}
		end := int(size) + 1
		switch data[0] {
		case 'P':
			var parsed pgproto3.Parse
			if parsed.Decode(data[5:end]) != nil {
				w.trace.failed = true
				break
			}
			delete(w.statements, parsed.Name)
			if selectedAPIKeySQL(parsed.Query) {
				w.statements[parsed.Name] = parsed
			}
		case 'B':
			w.trace.executions++
			// Read only the statement name before selecting a Bind. Unselected
			// parameter payloads are neither decoded nor retained.
			body := data[5:end]
			portal := slices.Index(body, byte(0))
			if portal < 0 {
				w.trace.failed = true
				break
			}
			body = body[portal+1:]
			nameEnd := slices.Index(body, byte(0))
			if nameEnd < 0 {
				w.trace.failed = true
				break
			}
			parsed, selected := w.statements[string(body[:nameEnd])]
			if !selected {
				break
			}
			var bound pgproto3.Bind
			if bound.Decode(data[5:end]) != nil {
				w.trace.failed = true
				break
			}
			if len(parsed.ParameterOIDs) == 0 {
				key := "pool:" + parsed.Query
				sample, ok := w.trace.samples[key]
				if ok && sample.formats == nil {
					sample.formats = slices.Clone(bound.ParameterFormatCodes)
					w.trace.samples[key] = sample
				}
				break
			}
			if len(bound.Parameters) != len(parsed.ParameterOIDs) {
				w.trace.failed = true
				break
			}
			key := "work:" + parsed.Query
			for i, value := range bound.Parameters {
				if value == nil {
					key += fmt.Sprintf(":null%d", i)
				}
			}
			if _, exists := w.trace.samples[key]; !exists {
				values := make([][]byte, len(bound.Parameters))
				for i, value := range bound.Parameters {
					values[i] = slices.Clone(value)
				}
				w.trace.samples[key] = apiKeySQLSample{sql: parsed.Query, values: values, oids: slices.Clone(parsed.ParameterOIDs), formats: slices.Clone(bound.ParameterFormatCodes)}
			}
		case 'Q':
			w.trace.executions++
		}
		data = data[end:]
	}
	return n, nil
}

func (t *apiKeySQLTrace) start() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active = true
	t.executions = 0
	t.failed = false
}
func (t *apiKeySQLTrace) stop(test *testing.T, label string, elapsed time.Duration) {
	test.Helper()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active = false
	if t.failed || t.executions == 0 {
		test.Fatal("actual OAuth SQL protocol observation failed", label)
	}
	test.Logf("complete %s: %d actual protocol executions, elapsed=%s; no production latency/SLO claim", label, t.executions, elapsed)
}

func observedAPIKeyPool(t *testing.T, h authenticatedPasswordFixture, trace *apiKeySQLTrace) *database.Pool {
	t.Helper()
	original := h.pool.Raw().Config().ConnConfig
	pool, err := database.Connect(h.ctx, database.Config{DSN: original.ConnString(), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = original.Database
		c.ConnConfig.RuntimeParams = maps.Clone(original.RuntimeParams)
		c.ConnConfig.Tracer = trace
		c.ConnConfig.BuildFrontend = func(reader io.Reader, writer io.Writer) *pgproto3.Frontend {
			return pgproto3.NewFrontend(reader, &apiKeySQLWriter{destination: writer, trace: trace, statements: make(map[string]pgproto3.Parse)})
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("observed primary pool cleanup", err)
		}
	})
	return pool
}

func TestNativeAPIKeyExchangeExactSQLBindingsAndScale(t *testing.T) {
	trace := &apiKeySQLTrace{samples: make(map[string]apiKeySQLSample)}
	h := apiKeyExchangeFixtureObserved(t, trace)
	_, keyWire := createAPIKeyExchangeSource(t, h, "m33-sql-source")
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, SubjectToken: keyWire, SubjectTokenType: oauth.APIKeyTokenType, Resource: h.client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.10"}
	trace.start()
	started := time.Now()
	root, err := h.service.Token(h.f.ctx, request)
	trace.stop(t, "real key-to-access exchange", time.Since(started))
	request.SubjectToken, keyWire = "", ""
	if err != nil {
		t.Fatal("actual key source for SQL measurement", err)
	}
	access, err := root.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	request.SubjectToken, request.SubjectTokenType = access, oauth.AccessTokenType
	trace.start()
	started = time.Now()
	child, err := h.service.Token(h.f.ctx, request)
	trace.stop(t, "real access-to-access exchange", time.Since(started))
	if err != nil {
		t.Fatal(err)
	}
	childWire, err := child.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	trace.start()
	started = time.Now()
	out, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: childWire})
	trace.stop(t, "real child introspection", time.Since(started))
	if err != nil || !out.Active {
		t.Fatal("actual child introspection for SQL measurement", err)
	}
	trace.start()
	started = time.Now()
	err = h.store.BootstrapAPIKeyExchangeClient(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic})
	trace.stop(t, "idempotent explicit client bootstrap", time.Since(started))
	if err != nil {
		t.Fatal(err)
	}
	// Filler is storage-distribution input, never authenticated credentials.
	// All permissions/owner/expiry above came from the actual issued source.
	_, err = h.f.pool.Raw().Exec(h.f.ctx, `INSERT INTO oauth_store.grants(grant_id,tenant_id,user_id,client_id,client_version,client_fingerprint,source_session,scopes,resource,state,created_at,expires_at,version,api_key_source,api_key_only)
 SELECT 'api-key-scale-grant-'||n::text,tenant_id,user_id,client_id,client_version,client_fingerprint,source_session,scopes,resource,state,created_at,expires_at,version,api_key_source,api_key_only FROM oauth_store.grants CROSS JOIN generate_series(1,100000) n WHERE grant_id=$1`, string(root.CommandID))
	if err != nil {
		t.Fatal("inert representative grant volume", err)
	}
	_, err = h.f.pool.Raw().Exec(h.f.ctx, `INSERT INTO oauth_store.artifacts(artifact_id,digest_version,digest,kind,client_id,grant_id,parent_artifact_id,issued_by,created_at,expires_at,state,transition_command,replay_command,payload,api_key_only,api_key_root)
 SELECT 'api-key-scale-artifact-'||n::text,a.digest_version,sha256(convert_to('inert-api-key-digest-'||n::text,'UTF8')),a.kind,a.client_id,'api-key-scale-grant-'||n::text,NULL,a.issued_by,a.created_at,a.expires_at,a.state,a.transition_command,a.replay_command,a.payload,true,true FROM oauth_store.artifacts a CROSS JOIN generate_series(1,20000) n WHERE a.issued_by=$1 AND a.api_key_root
 UNION ALL
 SELECT 'api-key-hot-child-'||n::text,a.digest_version,sha256(convert_to('inert-hot-api-key-digest-'||n::text,'UTF8')),a.kind,a.client_id,a.grant_id,a.parent_artifact_id,a.issued_by,a.created_at,a.expires_at,a.state,a.transition_command,a.replay_command,a.payload,true,false FROM oauth_store.artifacts a CROSS JOIN generate_series(1,80000) n WHERE a.issued_by=$2 AND NOT a.api_key_root`, string(root.CommandID), string(child.CommandID))
	if err != nil {
		t.Fatal("inert representative artifact volume", err)
	}
	for _, table := range []string{"oauth_store.grants", "oauth_store.artifacts"} {
		if _, err := h.f.pool.Raw().Exec(h.f.ctx, "ANALYZE "+table); err != nil {
			t.Fatal(err)
		}
	}
	var version string
	var grants, artifacts int
	var extraTriggers bool
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT current_setting('server_version'),(SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.artifacts),EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid IN('oauth_store.grants'::regclass,'oauth_store.artifacts'::regclass) AND NOT tgisinternal)`).Scan(&version, &grants, &artifacts, &extraTriggers); err != nil || extraTriggers || grants != 100001 || artifacts != 100002 {
		t.Fatal("scale/owned no-external-trigger boundary", err)
	}
	t.Logf("PostgreSQL %s; grants=%d artifacts=%d; one dense real tenant/user/client with 80002 artifacts in the live root grant and 20000 sparse grant roots; actual PK/FK indexes; no production-distribution or throughput claim", version, grants, artifacts)
	metadata, err := h.f.pool.Raw().Query(h.f.ctx, `SELECT a.attrelid::regclass::text,a.attname,format_type(a.atttypid,a.atttypmod),COALESCE(format_type(NULLIF(t.typbasetype,0),NULL),'') FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid WHERE a.attrelid IN('oauth_store.grants'::regclass,'oauth_store.artifacts'::regclass) AND a.attnum>0 AND NOT a.attisdropped AND a.attname IN('grant_id','tenant_id','user_id','client_id','artifact_id','parent_artifact_id','digest_version','digest','kind','api_key_only') ORDER BY 1,2`)
	if err != nil {
		t.Fatal(err)
	}
	for metadata.Next() {
		var table, column, kind, base string
		if err := metadata.Scan(&table, &column, &kind, &base); err != nil {
			metadata.Close()
			t.Fatal(err)
		}
		t.Logf("actual column %s.%s: %s base=%s", table, column, kind, base)
	}
	err = metadata.Err()
	metadata.Close()
	if err != nil {
		t.Fatal(err)
	}
	indexes, err := h.f.pool.Raw().Query(h.f.ctx, `SELECT c.relname,pg_relation_size(c.oid),i.indisvalid,i.indisunique,pg_get_indexdef(c.oid) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid IN('oauth_store.grants'::regclass,'oauth_store.artifacts'::regclass) ORDER BY c.relname`)
	if err != nil {
		t.Fatal(err)
	}
	for indexes.Next() {
		var name, definition string
		var bytes int64
		var valid, unique bool
		if err := indexes.Scan(&name, &bytes, &valid, &unique, &definition); err != nil {
			indexes.Close()
			t.Fatal(err)
		}
		if !valid {
			indexes.Close()
			t.Fatal("invalid representative index", name)
		}
		t.Logf("actual index %s: bytes=%d unique=%t definition=%s", name, bytes, unique, definition)
	}
	err = indexes.Err()
	indexes.Close()
	if err != nil {
		t.Fatal(err)
	}
	trace.mu.Lock()
	samples := maps.Clone(trace.samples)
	trace.mu.Unlock()
	var nativeRead, rawRead, inserts int
	for _, sample := range samples {
		if strings.HasPrefix(sample.sql, "INSERT") {
			inserts++
			measureAPIKeyInsert(t, h, sample)
			continue
		}
		if sample.values != nil {
			nativeRead++
		} else {
			rawRead++
		}
		measureAPIKeyRead(t, h, sample)
	}
	if nativeRead != 2 || rawRead != 3 || inserts != 3 {
		t.Fatal("actual query families or root/child nullable-parent binding arms changed", nativeRead, rawRead, inserts)
	}
	request.SubjectToken, request.SubjectTokenType = access, oauth.AccessTokenType
	trace.start()
	started = time.Now()
	hotChild, err := h.service.Token(h.f.ctx, request)
	trace.stop(t, "scaled hot-grant child exchange", time.Since(started))
	if err != nil || hotChild.Outcome != identity.CommitOutcomeCommitted || hotChild.ExpiresAt.After(root.ExpiresAt) {
		t.Fatal("dense grant fanout broke actual bounded child exchange", err)
	}
	// A new genuine source avoids retaining/replaying the original raw key or
	// extending an old access deadline merely to measure after scale setup.
	_, scaledWire := createAPIKeyExchangeSource(t, h, "m33-scaled-sql-source")
	request.SubjectToken, request.SubjectTokenType = scaledWire, oauth.APIKeyTokenType
	trace.start()
	started = time.Now()
	scaled, err := h.service.Token(h.f.ctx, request)
	trace.stop(t, "scaled real key-to-access exchange", time.Since(started))
	request.SubjectToken, scaledWire = "", ""
	if err != nil || scaled.Outcome != identity.CommitOutcomeCommitted || scaled.AccessToken == (oauth.Token{}) {
		t.Fatal("representative scale broke the actual public key exchange", err)
	}
}

func apiKeySampleRows(ctx context.Context, pool *database.Pool, s apiKeySQLSample, sql string, args []any, values [][]byte) (pgx.Rows, func(), error) {
	if s.values == nil {
		rows, err := pool.Raw().Query(ctx, sql, args...)
		return rows, func() {}, err
	}
	conn, err := pool.Raw().Acquire(ctx)
	if err != nil {
		return nil, func() {}, err
	}
	rows := pgx.RowsFromResultReader(pgtype.NewMap(), conn.Conn().PgConn().ExecParams(ctx, sql, values, s.oids, s.formats, nil))
	return rows, conn.Release, nil
}

func sanitizedAPIKeyPlan(plan []byte, s apiKeySQLSample) string {
	text := string(plan)
	for i, arg := range s.arguments {
		switch value := arg.(type) {
		case string:
			if len(value) >= 8 {
				text = strings.ReplaceAll(text, value, fmt.Sprintf("<arg%d:string>", i+1))
			}
		case []byte:
			if len(value) >= 16 {
				text = strings.ReplaceAll(text, hex.EncodeToString(value), fmt.Sprintf("<arg%d:bytes>", i+1))
			}
		}
	}
	for i, value := range s.values {
		if s.oids[i] == pgtype.TextOID && len(value) >= 8 {
			text = strings.ReplaceAll(text, string(value), fmt.Sprintf("<arg%d:wire>", i+1))
		}
		if s.oids[i] == pgtype.ByteaOID && len(value) >= 16 {
			text = strings.ReplaceAll(text, hex.EncodeToString(value), fmt.Sprintf("<arg%d:bytes>", i+1))
		}
	}
	return text
}

func measureAPIKeyRead(t *testing.T, h apiKeyNativeExchange, s apiKeySQLSample) {
	t.Helper()
	types := make([]string, len(s.arguments))
	for i, arg := range s.arguments {
		types[i] = fmt.Sprintf("%T", arg)
	}
	cases := []struct {
		name    string
		args    []any
		values  [][]byte
		present bool
	}{{"present", s.arguments, s.values, true}}
	if strings.Contains(s.sql, "FROM pg_constraint") {
		// Aggregate cardinality is exactly one; no-match would be a missing
		// regclass installation error rather than a meaningful row selectivity.
	} else if s.values != nil {
		for i := range s.values {
			if s.oids[i] != pgtype.TextOID || s.formats[i] != pgtype.BinaryFormatCode {
				t.Fatal("native identifier lost captured TextOID/binary representation")
			}
			values := slices.Clone(s.values)
			values[i] = []byte("missing-api-key-scope")
			cases = append(cases, struct {
				name    string
				args    []any
				values  [][]byte
				present bool
			}{fmt.Sprintf("no-match-arg-%d", i+1), nil, values, false})
		}
	} else {
		args := slices.Clone(s.arguments)
		if strings.HasPrefix(s.sql, "SELECT a.artifact_id,a.kind,") {
			digest := sha256.Sum256([]byte("absent-api-key-lookup"))
			args[1] = digest[:]
		} else {
			args[0] = "missing-api-key-artifact"
		}
		cases = append(cases, struct {
			name    string
			args    []any
			values  [][]byte
			present bool
		}{"no-match", args, nil, false})
		foreign := slices.Clone(s.arguments)
		foreign[len(foreign)-1] = "foreign-api-key-client"
		cases = append(cases, struct {
			name    string
			args    []any
			values  [][]byte
			present bool
		}{"foreign-client", foreign, nil, false})
	}
	for _, c := range cases {
		rows, release, err := apiKeySampleRows(h.f.ctx, h.f.pool, s, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+s.sql, c.args, c.values)
		if err != nil {
			release()
			t.Fatal(err)
		}
		var plan []byte
		ok := rows.Next() && rows.Scan(&plan) == nil
		extra, rowErr := rows.Next(), rows.Err()
		rows.Close()
		release()
		if !ok || extra || rowErr != nil {
			t.Fatal("actual native query plan unavailable", rowErr)
		}
		if !strings.Contains(s.sql, "FROM pg_constraint") && (strings.Contains(string(plan), `"Node Type": "Seq Scan"`) || !strings.Contains(string(plan), `"Index Name"`)) {
			t.Fatal("scaled point query lost indexed access", c.name)
		}
		redacted := s
		redacted.arguments, redacted.values = c.args, c.values
		safePlan := sanitizedAPIKeyPlan(plan, redacted)
		if !json.Valid([]byte(safePlan)) {
			t.Fatal("plan redaction changed measured JSON/metrics")
		}
		t.Logf("SQL=%s; case=%s; actual Go driver types=%v; explicit Work OIDs=%v; Bind formats=%v; plan=%s", s.sql, c.name, types, s.oids, s.formats, safePlan)
		var minimum, maximum time.Duration
		for repeat := 0; repeat < 5; repeat++ {
			started := time.Now()
			rows, release, err := apiKeySampleRows(h.f.ctx, h.f.pool, s, s.sql, c.args, c.values)
			if err != nil {
				release()
				t.Fatal(err)
			}
			count := 0
			for rows.Next() {
				if _, err := rows.Values(); err != nil {
					rows.Close()
					release()
					t.Fatal(err)
				}
				count++
			}
			err = rows.Err()
			rows.Close()
			release()
			elapsed := time.Since(started)
			if err != nil || count > 1 || c.present != (count == 1) {
				t.Fatal("measured result cardinality or cleanup mismatch", c.name, err)
			}
			if repeat == 0 || elapsed < minimum {
				minimum = elapsed
			}
			maximum = max(maximum, elapsed)
		}
		t.Logf("case=%s; five actual-driver executions including acquisition/transfer; min=%s max=%s; plans separately expose examined work", c.name, minimum, maximum)
	}
}

func measureAPIKeyInsert(t *testing.T, h apiKeyNativeExchange, s apiKeySQLSample) {
	t.Helper()
	if s.values == nil || len(s.oids) != len(s.values) || len(s.formats) != len(s.values) {
		t.Fatal("insert lost actual native Work binding metadata")
	}
	var minimum, maximum time.Duration
	for repeat := 0; repeat < 6; repeat++ {
		values := slices.Clone(s.values)
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(s.sql, `.grants(`) {
			values[0] = []byte(id)
		} else {
			values[10] = []byte(id)
			digest := sha256.Sum256([]byte("inert-insert-" + string(id)))
			values[1] = digest[:]
		}
		tx, err := h.f.pool.Raw().Begin(h.f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		query := s.sql
		if repeat == 0 {
			query = "EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) " + query
		}
		started := time.Now()
		rows := pgx.RowsFromResultReader(pgtype.NewMap(), tx.Conn().PgConn().ExecParams(h.f.ctx, query, values, s.oids, s.formats, nil))
		var plan []byte
		if repeat == 0 {
			if !rows.Next() || rows.Scan(&plan) != nil {
				rows.Close()
				_ = tx.Rollback(h.f.ctx)
				t.Fatal("insert plan unavailable")
			}
		}
		for rows.Next() {
		}
		err = rows.Err()
		rows.Close()
		elapsed := time.Since(started)
		if rollback := tx.Rollback(h.f.ctx); err != nil || rollback != nil {
			t.Fatal("owned insert measurement/rollback failed", err, rollback)
		}
		if repeat == 0 {
			copy := s
			copy.values = values
			safePlan := sanitizedAPIKeyPlan(plan, copy)
			if !json.Valid([]byte(safePlan)) {
				t.Fatal("insert plan redaction changed measured JSON/metrics")
			}
			t.Logf("actual Work INSERT=%s; OIDs=%v formats=%v; rollback-only plan=%s", s.sql, s.oids, s.formats, safePlan)
			continue
		}
		if repeat == 1 || elapsed < minimum {
			minimum = elapsed
		}
		maximum = max(maximum, elapsed)
	}
	t.Logf("five real native insert executions including constraint/index work, each rolled back; min=%s max=%s; not a throughput/concurrency claim", minimum, maximum)
}
