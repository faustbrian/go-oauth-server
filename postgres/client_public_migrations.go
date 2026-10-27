package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// ClientPublicMigrationSource appends no-secret public registrations without
// rewriting installed client, rotation or update history. Stop issuance, install
// after the complete selected history, replace unaware serving instances, then
// select matching native/protocol PublicClients flags. Confidential-only use
// requires neither this history nor the flags. Rollback to unaware binaries
// after public rows exist is unsupported; disable issuance instead.
// The single ALTER TABLE validates existing rows under ACCESS EXCLUSIVE,
// blocking reads and writes. Use a maintenance window with bounded lock_timeout
// and statement_timeout, or equivalent operator command deadlines; finish the
// schema install and public-aware binary rollout before enabling the flags.
// See https://www.postgresql.org/docs/18/sql-altertable.html.
type ClientPublicMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

func (s ClientPublicMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_client_public_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_client_public_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_client_public_migration"}
		}
	}
	next, err := migrations.NewMigration(s.Version, "oauth_platform_public_clients", migrations.TransactionModeDefault, strings.ReplaceAll(clientPublicSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

// RFC6749 section2.1 public clients cannot keep credentials confidential;
// the selected none/Basic matrix is binding in PROTOCOL_BASELINES.md. Preserve
// legacy confidential rows with absent Public, but make public secret absence
// and both classes' registered methods a durable invariant, including tombstones.
const clientPublicSQL = `ALTER TABLE @schema@.managed_clients
 ALTER COLUMN secret_digest DROP NOT NULL,
 DROP CONSTRAINT managed_clients_secret_digest_check,
 ADD CONSTRAINT managed_client_secret_class CHECK(
  (registration @> '{"Public":true,"AuthenticationMethod":"none"}'::jsonb AND secret_digest IS NULL)
  OR (COALESCE(registration->'Public','false'::jsonb)='false'::jsonb
   AND registration @> '{"AuthenticationMethod":"client_secret_basic"}'::jsonb
   AND secret_digest IS NOT NULL AND octet_length(secret_digest)=32));
`
