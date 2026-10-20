package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PairwiseMigrationSource appends durable subject-key custody and stable native
// bindings. Install before selecting registered pairwise clients. Bindings and
// retired key-version tombstones have no down migration: deletion could reassign
// an RP identity on later key rotation. Base must include the OAuth grant schema.
type PairwiseMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

func (s PairwiseMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_pairwise_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_pairwise_migration"}
	}
	for _, migration := range history {
		if migration.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_pairwise_migration"}
		}
	}
	next, err := migrations.NewMigration(s.Version, "oauth_oidc_pairwise_subjects", migrations.TransactionModeDefault, strings.ReplaceAll(pairwiseSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const pairwiseSchemaSQL = `CREATE TABLE @schema@.subject_keys(
 context_id bytea NOT NULL CHECK(octet_length(context_id)=32),
 issuer text COLLATE "C" NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
 environment @schema@.scope_id NOT NULL,
 policy_id @schema@.scope_id NOT NULL,
 policy_version @schema@.version NOT NULL,
 key_version bigint NOT NULL CHECK(key_version BETWEEN 1 AND 4294967295),
 commitment bytea NOT NULL CHECK(octet_length(commitment)=32),
 envelope bytea CHECK(octet_length(envelope) BETWEEN 1 AND 16384),
 retired boolean NOT NULL DEFAULT false,
 CHECK(retired=(envelope IS NULL)),
 PRIMARY KEY(context_id,policy_id,policy_version,key_version)
);
CREATE INDEX subject_retained_keys ON @schema@.subject_keys(context_id,policy_id,policy_version,key_version) WHERE NOT retired;
CREATE TABLE @schema@.subject_selection(
 context_id bytea NOT NULL CHECK(octet_length(context_id)=32),
 issuer text COLLATE "C" NOT NULL,
 environment @schema@.scope_id NOT NULL,
 policy_id @schema@.scope_id NOT NULL,
 policy_version @schema@.version NOT NULL,
 key_version bigint,
 PRIMARY KEY(context_id,policy_id,policy_version),
 FOREIGN KEY(context_id,policy_id,policy_version,key_version)
  REFERENCES @schema@.subject_keys(context_id,policy_id,policy_version,key_version)
);
CREATE TABLE @schema@.subject_bindings(
 context_id bytea NOT NULL CHECK(octet_length(context_id)=32),
 issuer text COLLATE "C" NOT NULL,
 environment @schema@.scope_id NOT NULL,
 tenant_id @schema@.scope_id NOT NULL,
 sector_host text COLLATE "C" NOT NULL CHECK(octet_length(sector_host) BETWEEN 1 AND 253),
 user_id @schema@.scope_id NOT NULL,
 policy_id @schema@.scope_id NOT NULL,
 policy_version @schema@.version NOT NULL,
 origin_key_version bigint NOT NULL,
 subject text COLLATE "C" NOT NULL CHECK(subject ~ '^[A-Za-z0-9_-]{43}$'),
 PRIMARY KEY(context_id,tenant_id,sector_host,user_id),
 UNIQUE(context_id,subject),
 FOREIGN KEY(context_id,policy_id,policy_version,origin_key_version)
  REFERENCES @schema@.subject_keys(context_id,policy_id,policy_version,key_version)
);
CREATE TABLE @schema@.grant_subject_bindings(
 grant_id @schema@.scope_id PRIMARY KEY REFERENCES @schema@.grants(grant_id),
 context_id bytea NOT NULL CHECK(octet_length(context_id)=32),
 issuer text COLLATE "C" NOT NULL,
 environment @schema@.scope_id NOT NULL,
 tenant_id @schema@.scope_id NOT NULL,
 sector_host text COLLATE "C" NOT NULL,
 user_id @schema@.scope_id NOT NULL,
 FOREIGN KEY(context_id,tenant_id,sector_host,user_id)
  REFERENCES @schema@.subject_bindings(context_id,tenant_id,sector_host,user_id)
);
`
