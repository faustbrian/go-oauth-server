package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// WorkloadExchangeMigrationSource appends forward opaque-access lineage after
// WorkloadMigrationSource and any selected ConsentExpiryMigrationSource. The
// exchange suffix must be last: later consent-expiry activation is rejected
// before migration. Existing rows stay nonexchange roots. Install during
// an exclusive schema window, retire unaware writers, initialize each selected
// client's independent authorization epoch to its registration Version, then
// opt into exchange. Old roots lacking that epoch cannot be silently adopted.
// No down migration erases history; base/unselected construction needs no suffix.
type WorkloadExchangeMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

// Load returns owned forward-only history without IO or implicit schema adoption.
func (s WorkloadExchangeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_workload_exchange_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_workload_exchange_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_workload_exchange_migration"}
		}
	}
	statement := strings.ReplaceAll(workloadExchangeSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	next, err := migrations.NewMigration(s.Version, "oauth_workload_exchange", migrations.TransactionModeDefault, statement, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const workloadExchangeSQL = `ALTER TABLE @schema@.artifacts
 ADD COLUMN workload_exchange boolean NOT NULL DEFAULT false,
 ADD COLUMN metadata_version smallint NOT NULL DEFAULT 1 CHECK(metadata_version=1),
 DROP CONSTRAINT artifacts_typed_parent,
 DROP CONSTRAINT artifacts_workload_access_only,
 ADD CONSTRAINT artifacts_workload_access_only CHECK (NOT workload_only OR (kind=3 AND state IN('active','revoked') AND consumed_by IS NULL)),
 ADD CONSTRAINT artifacts_workload_exchange_shape CHECK (
  (NOT workload_exchange AND NOT (payload ? 'Exchange')) OR
  (workload_exchange AND workload_only AND parent_artifact_id IS NOT NULL AND jsonb_typeof(payload->'Exchange')='object'));
DO $exchange_parent$
BEGIN
 IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.artifacts'::regclass AND attname='silent_code' AND NOT attisdropped) THEN
  ALTER TABLE @schema@.artifacts ADD CONSTRAINT artifacts_typed_parent CHECK((kind=1 OR (workload_only AND NOT workload_exchange) OR silent_code)=(parent_artifact_id IS NULL));
 ELSE
  ALTER TABLE @schema@.artifacts ADD CONSTRAINT artifacts_typed_parent CHECK((kind=1 OR (workload_only AND NOT workload_exchange))=(parent_artifact_id IS NULL));
 END IF;
END $exchange_parent$;
`
