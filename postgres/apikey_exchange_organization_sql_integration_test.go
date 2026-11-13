//go:build integration && oauthflow

package oauthpostgres_test

import (
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestNativeOrganizationAPIKeyExactSQLDelta(t *testing.T) {
	trace := &apiKeySQLTrace{samples: make(map[string]apiKeySQLSample)}
	f := organizationAPIKeyExchangeFixtureObserved(t, trace)
	_, wire := createOrganizationExchangeSource(t, f, "m33-org-sql-original")
	trace.start()
	started := time.Now()
	err := f.h.store.BootstrapAPIKeyExchangeClient(f.h.f.ctx, oauth.IntrospectRequest{ClientID: f.h.client.ID, ClientAuthentication: f.h.basic})
	trace.stop(t, "organization schema-readiness and client bootstrap", time.Since(started))
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: f.h.client.ID, ClientAuthentication: f.h.basic, SubjectToken: wire, SubjectTokenType: oauth.APIKeyTokenType, Resource: f.h.client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.10"}
	trace.start()
	started = time.Now()
	issued, err := f.h.service.Token(f.h.f.ctx, request)
	trace.stop(t, "actual organization root exchange", time.Since(started))
	request.SubjectToken, wire = "", ""
	if err != nil {
		t.Fatal(err)
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	trace.start()
	started = time.Now()
	principal, err := f.resource.Verify(f.h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"})
	trace.stop(t, "actual typed organization resource read", time.Since(started))
	if err != nil || principal.RequireScope("identity:read") != nil || principal.Owner().Spec().Kind != apikey.OwnerOrganization {
		t.Fatal("measured public resource operation was not actually usable", err)
	}
	// Same-tenant/client/owner density exercises the new tagged-owner CHECK
	// and nullable-user binding. These are inert storage copies, not tokens.
	if _, err := f.h.f.pool.Raw().Exec(f.h.f.ctx, `INSERT INTO oauth_store.grants(grant_id,tenant_id,user_id,client_id,client_version,client_fingerprint,source_session,scopes,resource,state,created_at,expires_at,version,api_key_source,api_key_only) SELECT 'inert-org-scale-'||n::text,tenant_id,user_id,client_id,client_version,client_fingerprint,source_session,scopes,resource,state,created_at,expires_at,version,api_key_source,api_key_only FROM oauth_store.grants CROSS JOIN generate_series(1,10000) n WHERE grant_id=$1`, string(issued.CommandID)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.f.pool.Raw().Exec(f.h.f.ctx, `ANALYZE oauth_store.grants`); err != nil {
		t.Fatal(err)
	}
	var engine, userType string
	var rows, own, validated int
	var userNotNull bool
	if err := f.h.f.pool.Raw().QueryRow(f.h.f.ctx, `SELECT current_setting('server_version'),(SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.grants WHERE user_id IS NULL AND api_key_source#>>'{Owner,Kind}'='2'),(SELECT count(*) FROM pg_constraint WHERE conrelid='oauth_store.grants'::regclass AND conname IN('grants_api_key_organization_owner','grants_api_key_organization_source') AND convalidated),format_type(atttypid,atttypmod),attnotnull FROM pg_attribute WHERE attrelid='oauth_store.grants'::regclass AND attname='user_id'`).Scan(&engine, &rows, &own, &validated, &userType, &userNotNull); err != nil || rows != 10001 || own != rows || validated != 2 || userNotNull {
		t.Fatal("representative organization/nullable-user shape not installed", err)
	}
	t.Logf("PostgreSQL %s; grants=%d, all one organization/tenant/client with NULL user; user_id=%s nullable; both new checks validated; warm isolated primary, no competing services, no production/SLO claim", engine, rows, userType)
	indexes, err := f.h.f.pool.Raw().Query(f.h.f.ctx, `SELECT indexrelid::regclass::text,indisvalid,pg_get_indexdef(indexrelid) FROM pg_index WHERE indrelid='oauth_store.grants'::regclass ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	for indexes.Next() {
		var name, definition string
		var valid bool
		if err := indexes.Scan(&name, &valid, &definition); err != nil || !valid {
			indexes.Close()
			t.Fatal("representative grant index unavailable", err)
		}
		t.Logf("actual grant index %s: %s", name, definition)
	}
	err = indexes.Err()
	indexes.Close()
	if err != nil {
		t.Fatal(err)
	}
	trace.mu.Lock()
	samples := maps.Clone(trace.samples)
	trace.mu.Unlock()
	var catalog, nullUserInsert int
	for _, sample := range samples {
		if strings.HasPrefix(sample.sql, "SELECT count(*)=2 AND bool_and(convalidated) AND NOT (SELECT attnotnull") {
			catalog++
			if len(sample.arguments) != 1 {
				t.Fatal("new readiness query lost real schema binding")
			}
			if _, ok := sample.arguments[0].(string); !ok {
				t.Fatal("regclass schema binding no longer Go string")
			}
			measureAPIKeyRead(t, f.h, sample)
		}
		if strings.HasPrefix(sample.sql, `INSERT INTO "oauth_store".grants(`) {
			nullUserInsert++
			// The real closed Work encoder transmits untyped SQL NULL (OID0,
			// text format), inferred by PostgreSQL from the scope_id column.
			if len(sample.values) != 11 || sample.values[2] != nil || sample.oids[2] != 0 || sample.formats[2] != pgtype.TextFormatCode {
				t.Fatal("organization INSERT fabricated a USER or lost actual inferred NULL binding")
			}
			measureAPIKeyInsert(t, f.h, sample)
		}
	}
	if catalog != 1 || nullUserInsert != 1 {
		t.Fatal("actual changed query/binding families not captured", catalog, nullUserInsert)
	}
	trace.start()
	started = time.Now()
	principal, err = f.resource.Verify(f.h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"})
	trace.stop(t, "dense-grant typed organization resource read", time.Since(started))
	if err != nil || principal.RequireScope("identity:read") != nil {
		t.Fatal("dense-grant current owner/resource validation failed", err)
	}
	// Artifact lookup, ancestry, current-source and USER SQL are byte-identical
	// to their retained own gates. This delta measures only the new catalog read,
	// changed nil USER bind/CHECK arm and complete public owning operations.
}
