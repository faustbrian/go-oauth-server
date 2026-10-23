package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// EndSessionMigrationSource appends immutable issued-hint associations to the
// OAuth namespace. It does not install session history or enable logout. Apply
// after signing history, then the session owner's logout suffix, and retire
// unaware readers/writers before enabling RPInitiatedLogout. No down migration
// can safely erase a termination or its original recovery scope.
type EndSessionMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

func (s EndSessionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_logout_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_logout_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_logout_migration"}
		}
	}
	next, err := migrations.NewMigration(s.Version, "oauth_oidc_end_session", migrations.TransactionModeDefault, strings.ReplaceAll(endSessionSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const endSessionSQL = `CREATE TABLE @schema@.issued_id_token_hints(
 digest bytea PRIMARY KEY CHECK(octet_length(digest)=32),
 grant_id @schema@.scope_id NOT NULL REFERENCES @schema@.grants(grant_id),
 tenant_id @schema@.scope_id NOT NULL,
 client_id @schema@.scope_id NOT NULL,
 command_id @schema@.scope_id NOT NULL UNIQUE,
 projection jsonb NOT NULL CHECK(jsonb_typeof(projection)='object' AND octet_length(projection::text)<=65536)
);
CREATE UNIQUE INDEX end_session_original ON @schema@.effects(tenant_id,record_id) WHERE operation_id='identity.oauth-server.end-session';
`
