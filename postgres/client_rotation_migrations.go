package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// ClientRotationMigrationSource appends versioned secret rotation to the original
// client history without rewriting published migrations. Stop serving, install,
// then deploy only rotation-aware instances before selecting ClientSecretRotation.
// Overlap has at most one predecessor; timestamps are exact and exclusive.
type ClientRotationMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

func (s ClientRotationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_client_rotation_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_client_rotation_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_client_rotation_migration"}
		}
	}
	next, err := migrations.NewMigration(s.Version, "oauth_platform_client_secret_rotation", migrations.TransactionModeDefault, strings.ReplaceAll(clientRotationSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const clientRotationSQL = `ALTER TABLE @schema@.managed_clients
 DROP CONSTRAINT managed_clients_check,
 ADD COLUMN secret_version @schema@.version NOT NULL DEFAULT 1,
 ADD COLUMN previous_secret_digest bytea,
 ADD COLUMN previous_secret_version @schema@.version,
 ADD COLUMN previous_secret_expires_at timestamptz,
 ADD COLUMN rotated_command @schema@.scope_id,
 ADD COLUMN rotated_at timestamptz,
 ADD CONSTRAINT managed_client_state_version CHECK(
  (state='active' AND version=secret_version AND deleted_command IS NULL AND deleted_at IS NULL)
  OR (state='deleted' AND version=secret_version+1 AND deleted_command IS NOT NULL AND deleted_at IS NOT NULL AND isfinite(deleted_at))),
 ADD CONSTRAINT managed_client_predecessor CHECK(
  (previous_secret_digest IS NULL AND previous_secret_version IS NULL AND previous_secret_expires_at IS NULL)
  OR (previous_secret_digest IS NOT NULL AND octet_length(previous_secret_digest)=32 AND previous_secret_version IS NOT NULL AND previous_secret_version+1=secret_version AND previous_secret_expires_at IS NOT NULL AND isfinite(previous_secret_expires_at) AND rotated_at IS NOT NULL AND previous_secret_expires_at>rotated_at AND previous_secret_expires_at<=rotated_at+interval '24 hours' AND state='active')),
 ADD CONSTRAINT managed_client_rotation CHECK(
  (secret_version=1 AND rotated_command IS NULL AND rotated_at IS NULL)
  OR (secret_version>1 AND rotated_command IS NOT NULL AND rotated_at IS NOT NULL AND isfinite(rotated_at)));
`
