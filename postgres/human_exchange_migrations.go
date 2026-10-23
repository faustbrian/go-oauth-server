package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// HumanCodeExchangeMigrationSource appends optional human delegation metadata
// after the complete installed OAuth history. Install under exclusive schema
// access, retire unaware writers, explicitly bootstrap selected registration
// authority, then enable the profile. Existing code/refresh/silent/workload rows
// and installed migration bytes remain unchanged. No down migration erases it.
type HumanCodeExchangeMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

// Load returns immutable forward history without IO, bootstrap or implicit
// adoption. Missing/invalid bases, conflicting versions and cancellation deny.
func (s HumanCodeExchangeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_human_code_exchange_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_human_code_exchange_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_human_code_exchange_migration"}
		}
	}
	statement := strings.ReplaceAll(humanCodeExchangeSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	next, err := migrations.NewMigration(s.Version, "oauth_human_code_exchange", migrations.TransactionModeDefault, statement, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const humanCodeExchangeSQL = `ALTER TABLE @schema@.artifacts
 ADD COLUMN human_code_exchange boolean NOT NULL DEFAULT false,
 ADD CONSTRAINT artifacts_human_code_exchange_shape CHECK (
  (NOT human_code_exchange AND NOT (payload ? 'HumanExchange')) OR
  (human_code_exchange AND kind=3 AND parent_artifact_id IS NOT NULL AND state IN('active','revoked') AND consumed_by IS NULL AND NOT (payload ? 'Exchange') AND jsonb_typeof(payload->'HumanExchange')='object'));
DO $human_metadata$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.artifacts'::regclass AND attname='metadata_version' AND NOT attisdropped) THEN
  ALTER TABLE @schema@.artifacts ADD COLUMN metadata_version smallint NOT NULL DEFAULT 1 CHECK(metadata_version=1);
 ELSIF NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.artifacts'::regclass AND attname='workload_exchange' AND NOT attisdropped)
 OR NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.artifacts'::regclass AND attname='metadata_version' AND atttypid='smallint'::regtype AND attnotnull AND NOT attisdropped) THEN
  RAISE EXCEPTION 'conflicting OAuth artifact metadata history';
 END IF;
END $human_metadata$;
`
