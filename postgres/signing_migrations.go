package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// SigningMigrationSource appends the selected public-key lifecycle, never
// private custody. Install before composing OIDC signing. Retired/compromised
// rows are permanent kid tombstones; rollback must not erase overlap history.
type SigningMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

func (s SigningMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_signing_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_signing_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_signing_migration"}
		}
	}
	next, err := migrations.NewMigration(s.Version, "oauth_oidc_public_signing", migrations.TransactionModeDefault, strings.ReplaceAll(signingSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const signingSchemaSQL = `CREATE TABLE @schema@.signing_keys(
 kid @schema@.scope_id PRIMARY KEY,
 slot smallint NOT NULL UNIQUE CHECK(slot BETWEEN 1 AND 64),
 public_key jsonb NOT NULL CHECK(jsonb_typeof(public_key)='object' AND octet_length(public_key::text)<=1024 AND NOT public_key ?| ARRAY['d','p','q','dp','dq','qi','k']),
 state text NOT NULL CHECK(state IN('registered','published','retired','compromised')),
 last_expiry timestamptz NOT NULL DEFAULT '-infinity',
 published_at timestamptz,
 CHECK(state IN('retired','compromised') OR (state='registered' AND published_at IS NULL) OR (state='published' AND published_at IS NOT NULL))
);
CREATE TABLE @schema@.signing_selection(
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 kid text REFERENCES @schema@.signing_keys(kid)
);
INSERT INTO @schema@.signing_selection(singleton) VALUES(true);
`
