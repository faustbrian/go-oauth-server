package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// ClientRegistrationMigrationSource appends digest-only RFC7591 initial-token
// custody after the selected complete managed/public-client history. Install
// this additive table before enabling DynamicRegistration; no serving query
// touches it while disabled. It never rewrites existing client or journal rows.
// Rollback disables registration, retaining existing clients and recovery data.
type ClientRegistrationMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

func (s ClientRegistrationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_client_registration_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_client_registration_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_client_registration_migration"}
		}
	}
	next, err := migrations.NewMigration(s.Version, "oauth_public_dynamic_registration", migrations.TransactionModeDefault, strings.ReplaceAll(clientRegistrationSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const clientRegistrationSQL = `SET LOCAL lock_timeout = '5s';
CREATE TABLE @schema@.initial_registration_tokens (
 digest bytea PRIMARY KEY CHECK(octet_length(digest)=32),
 issuer text COLLATE "C" NOT NULL,environment text COLLATE "C" NOT NULL,
 platform_owner @schema@.scope_id NOT NULL,tenant_id @schema@.scope_id NOT NULL,
 audience text COLLATE "C" NOT NULL,policy_version @schema@.version NOT NULL,
 policy_digest bytea NOT NULL CHECK(octet_length(policy_digest)=32),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>created_at),
 consumed_command @schema@.scope_id UNIQUE,
 client_id text COLLATE "C" UNIQUE REFERENCES @schema@.managed_clients(client_id),
 consumed_at timestamptz,
 CHECK((consumed_command IS NULL AND client_id IS NULL AND consumed_at IS NULL)
  OR (consumed_command IS NOT NULL AND client_id IS NOT NULL AND consumed_at IS NOT NULL
   AND isfinite(consumed_at) AND consumed_at>=created_at AND consumed_at<expires_at))
);
`
