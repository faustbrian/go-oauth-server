package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// WorkloadMigrationSource appends typed machine grants to the installed OAuth
// history without changing published migration bytes. Base must include this
// schema's MigrationSource and Version must follow every Base version. Apply
// before selecting any Workload client; unchanged web-only composition does not
// require this extension. The migration preserves all existing human lineage.
//
// ALTER constraints/generated columns and the typed-reference unique index need
// an exclusive schema migration window and table/index/WAL headroom. This is a
// referential-integrity index, not a query-performance optimization. Do not run
// concurrently with issuance. No down migration erases durable grant history.
type WorkloadMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

// Load returns owned forward history; no IO, migration or adoption occurs.
// Nil/zero inputs, non-successor versions and cancellation fail closed.
func (s WorkloadMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_workload_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_workload_migration"}
	}
	for _, migration := range history {
		if migration.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_workload_migration"}
		}
	}
	statement := strings.ReplaceAll(workloadSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	next, err := migrations.NewMigration(s.Version, "oauth_configured_workload", migrations.TransactionModeDefault, statement, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

// Keep the original human-only parent constraint until this explicit forward
// extension is installed. The generated discriminator cannot relabel a user
// row; its composite FK prevents mismatched artifact/root subject namespaces.
const workloadSchemaSQL = `ALTER TABLE @schema@.grants
 ADD COLUMN workload_source jsonb,
 ADD COLUMN workload_only boolean GENERATED ALWAYS AS (workload_source IS NOT NULL) STORED,
 ALTER COLUMN user_id DROP NOT NULL,
 DROP CONSTRAINT grants_source_session_check,
 ADD CONSTRAINT grants_typed_subject CHECK (
  (workload_source IS NULL AND user_id IS NOT NULL AND jsonb_typeof(source_session)='array' AND jsonb_array_length(source_session)>0 AND octet_length(source_session::text)<=65536)
  OR (workload_source IS NOT NULL AND user_id IS NULL AND source_session='[]'::jsonb AND jsonb_typeof(workload_source)='object' AND octet_length(workload_source::text)<=4096)),
 ADD CONSTRAINT grants_typed_reference UNIQUE(grant_id,workload_only);
ALTER TABLE @schema@.artifacts
 ADD COLUMN workload_only boolean NOT NULL DEFAULT false,
 DROP CONSTRAINT artifacts_check,
 ADD CONSTRAINT artifacts_typed_parent CHECK ((kind=1 OR workload_only)=(parent_artifact_id IS NULL)),
 ADD CONSTRAINT artifacts_workload_access_only CHECK (NOT workload_only OR (kind=3 AND parent_artifact_id IS NULL AND state IN('active','revoked') AND consumed_by IS NULL)),
 ADD CONSTRAINT artifacts_typed_root FOREIGN KEY(grant_id,workload_only) REFERENCES @schema@.grants(grant_id,workload_only);
`
