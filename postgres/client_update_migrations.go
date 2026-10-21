package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// ClientUpdateMigrationSource appends independent registration authority after
// installed client-rotation history. It never rewrites prior SQL or digest bytes.
// Stop serving, install, replace every accepting instance with update-aware code,
// then enable ClientMetadataUpdates. Old/unselected binaries fail closed on
// separated versions and must not remain in the accepting fleet.
type ClientUpdateMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

func (s ClientUpdateMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_client_update_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_client_update_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_client_update_migration"}
		}
	}
	next, err := migrations.NewMigration(s.Version, "oauth_platform_client_metadata_authority", migrations.TransactionModeDefault, strings.ReplaceAll(clientUpdateSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

// LIFECYCLE_CASCADES.md binds grants/consent to every client configuration
// change. Digest generation advances only on secret rotation: updates preserve
// current/predecessor bytes and the original predecessor expiry, without fanout.
const clientUpdateSQL = `ALTER TABLE @schema@.managed_clients
 DROP CONSTRAINT managed_client_state_version,
 ADD CONSTRAINT managed_client_independent_authority CHECK(
  (state='active' AND version>=secret_version AND deleted_command IS NULL AND deleted_at IS NULL)
  OR (state='deleted' AND version>secret_version AND deleted_command IS NOT NULL AND deleted_at IS NOT NULL AND isfinite(deleted_at)));
`
