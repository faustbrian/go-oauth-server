package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// ClientMigrationSource appends terminal managed-client authority to the
// installed consent history. Install while issuance is stopped; retire all old
// accepting instances before selecting the registry. Existing history is intact.
type ClientMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

func (s ClientMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_client_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_client_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_client_migration"}
		}
	}
	next, err := migrations.NewMigration(s.Version, "oauth_platform_client_registry", migrations.TransactionModeDefault, strings.ReplaceAll(clientSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const clientSchemaSQL = `CREATE TABLE @schema@.managed_clients (
 client_id text COLLATE "C" PRIMARY KEY CHECK(client_id ~ '^managed\.[A-Za-z0-9_-]{22}$'),
 issuer text COLLATE "C" NOT NULL,environment text COLLATE "C" NOT NULL,
 platform_owner @schema@.scope_id NOT NULL,tenant_id @schema@.scope_id NOT NULL,
 version @schema@.version NOT NULL,registration jsonb NOT NULL,
 secret_digest bytea NOT NULL CHECK(octet_length(secret_digest)=32),
 state text COLLATE "C" NOT NULL CHECK(state IN('active','deleted')),
 created_command @schema@.scope_id NOT NULL,deleted_command @schema@.scope_id,
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),deleted_at timestamptz,
 CHECK((state='active' AND version=1 AND deleted_command IS NULL AND deleted_at IS NULL) OR (state='deleted' AND version=2 AND deleted_command IS NOT NULL AND deleted_at IS NOT NULL AND isfinite(deleted_at)))
);
ALTER TABLE @schema@.effects DROP CONSTRAINT effect_exact_owner;
ALTER TABLE @schema@.effects ADD COLUMN client_id text COLLATE "C" REFERENCES @schema@.managed_clients(client_id),
 ADD CONSTRAINT effect_exact_owner CHECK(num_nonnulls(grant_id,consent_id,client_id)=1);
`
