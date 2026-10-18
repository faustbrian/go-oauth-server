// Package oauthpostgres owns the selected OAuth protocol's durable records.
// Identity, credentials, local sessions and the command coordinator remain
// borrowed authorities. Installing this schema does not enable an endpoint.
package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MigrationSource supplies one forward-only, transactionally installed OAuth
// namespace in the application's existing migration history. Schema must be an
// unoccupied dedicated lowercase namespace; Version is a permanent allocation
// in 1..MaxInt64. Existing objects fail rather than being silently adopted.
// No device, OIDC or organization schema is required by this base profile.
// Load performs no IO, returns independently owned data and is concurrent-safe.
type MigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = MigrationSource{}

// Load preserves cancellation and rejects invalid names/allocations. No down
// migration is supplied: durable grants cannot safely be erased by rollback.
func (s MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	statement := strings.ReplaceAll(schemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	migration, err := migrations.NewMigration(s.Version, "oauth_authorization_code", migrations.TransactionModeDefault, statement, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{migration}, nil
}

func validSchema(s string) bool {
	if len(s) == 0 || len(s) > 63 || s == "public" || s == "identity" || s == "information_schema" || strings.HasPrefix(s, "pg_") {
		return false
	}
	for i := range len(s) {
		if !(s[i] >= 'a' && s[i] <= 'z' || s[i] == '_' || i > 0 && s[i] >= '0' && s[i] <= '9') {
			return false
		}
	}
	return true
}

// Protocol bearers never enter these tables: only domain-separated keyed
// digests and public provenance do. The coordinator owns generated-output
// ciphertext and command replay; these records own protocol one-use state.
// No FK to identity users/sessions duplicates another owner's lifecycle.
const schemaSQL = `CREATE SCHEMA @schema@;
CREATE DOMAIN @schema@.scope_id AS text COLLATE "C"
 CHECK(VALUE ~ '^[!-~]{1,128}$');
CREATE DOMAIN @schema@.version AS numeric
 CHECK(VALUE>=1 AND VALUE<=18446744073709551615 AND scale(VALUE)=0);
CREATE TABLE @schema@.grants(
 grant_id @schema@.scope_id PRIMARY KEY,
 tenant_id @schema@.scope_id NOT NULL,
 user_id @schema@.scope_id NOT NULL,
 client_id @schema@.scope_id NOT NULL,
 client_version @schema@.version NOT NULL,
 client_fingerprint bytea NOT NULL CHECK(octet_length(client_fingerprint)=32),
 source_session jsonb NOT NULL CHECK(jsonb_typeof(source_session)='array' AND jsonb_array_length(source_session)>0 AND octet_length(source_session::text)<=65536),
 scopes jsonb NOT NULL CHECK(jsonb_typeof(scopes)='array' AND jsonb_array_length(scopes) BETWEEN 1 AND 16 AND octet_length(scopes::text)<=4096),
 resource text COLLATE "C" NOT NULL CHECK(length(resource) BETWEEN 1 AND 2048),
 state text COLLATE "C" NOT NULL CHECK(state IN('active','revoked')),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
 version @schema@.version NOT NULL,
 CHECK(expires_at>created_at)
);
CREATE INDEX grant_subject_order ON @schema@.grants(tenant_id,user_id,grant_id);
CREATE TABLE @schema@.artifacts(
 artifact_id @schema@.scope_id NOT NULL UNIQUE,
 digest_version bigint NOT NULL CHECK(digest_version BETWEEN 1 AND 4294967295),
 digest bytea NOT NULL CHECK(octet_length(digest)=32 AND digest<>decode(repeat('00',32),'hex')),
 kind smallint NOT NULL CHECK(kind BETWEEN 1 AND 4),
 client_id @schema@.scope_id NOT NULL,
 grant_id @schema@.scope_id NOT NULL REFERENCES @schema@.grants(grant_id),
 parent_artifact_id @schema@.scope_id,
 issued_by @schema@.scope_id NOT NULL,
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
 state text COLLATE "C" NOT NULL CHECK(state IN('active','consumed','revoked')),
 transition_command @schema@.scope_id NOT NULL,
 replay_command @schema@.scope_id NOT NULL,
 consumed_by @schema@.scope_id,
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND octet_length(payload::text)<=32768),
 PRIMARY KEY(digest_version,digest),
 UNIQUE(artifact_id,grant_id),
 FOREIGN KEY(parent_artifact_id,grant_id) REFERENCES @schema@.artifacts(artifact_id,grant_id),
 CHECK((kind=1)=(parent_artifact_id IS NULL)),
 CHECK(parent_artifact_id IS NULL OR parent_artifact_id<>artifact_id),
 CHECK(expires_at>created_at),
 CHECK((state='consumed')=(consumed_by IS NOT NULL))
);
CREATE INDEX artifact_grant_order ON @schema@.artifacts(grant_id,kind,digest_version,digest);
CREATE INDEX artifact_expiry_order ON @schema@.artifacts(expires_at,digest_version,digest) WHERE state='active';
CREATE TABLE @schema@.consents(
	consent_id @schema@.scope_id NOT NULL UNIQUE CHECK(consent_id ~ '^[A-Za-z0-9_-]{22}$'),
 tenant_id @schema@.scope_id NOT NULL,
 user_id @schema@.scope_id NOT NULL,
 client_id @schema@.scope_id NOT NULL,
 client_version @schema@.version NOT NULL,
 scopes jsonb NOT NULL CHECK(jsonb_typeof(scopes)='array' AND jsonb_array_length(scopes) BETWEEN 1 AND 16),
 granted_at timestamptz NOT NULL CHECK(isfinite(granted_at)),
	version @schema@.version NOT NULL,
 PRIMARY KEY(tenant_id,user_id,client_id)
);
CREATE TABLE @schema@.effects(
 tenant_id @schema@.scope_id NOT NULL,
 command_id @schema@.scope_id NOT NULL,
 operation_id @schema@.scope_id NOT NULL,
 record_id @schema@.scope_id NOT NULL,
 grant_id @schema@.scope_id NOT NULL REFERENCES @schema@.grants(grant_id),
 before_version numeric NOT NULL CHECK(before_version>=0 AND before_version<=18446744073709551615 AND scale(before_version)=0),
 after_version @schema@.version NOT NULL,
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 CHECK(after_version=before_version+1)
);
`
