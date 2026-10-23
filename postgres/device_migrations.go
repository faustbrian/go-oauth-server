package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// DeviceMigrationSource appends optional device state to the selected ordinary
// human/consent history. This first profile excludes workload and silent-OIDC
// artifact histories. Stop writers, install, then deploy only device-aware
// writers before activation. Base OAuth construction/bootstrap does not select
// this source. No down migration may erase committed grant/recovery authority.
type DeviceMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

func (s DeviceMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_device_migration"}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_device_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_device_migration"}
		}
	}
	next, err := migrations.NewMigration(s.Version, "oauth_optional_device", migrations.TransactionModeDefault, strings.ReplaceAll(deviceSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

// Digests, not device/user codes, are indexed. Details contain only bounded
// immutable policy and optional actual core-grant provenance; absence is the
// normal preapproval state, not fabricated stale subject or consent authority.
const deviceSchemaSQL = `CREATE TABLE @schema@.devices(
 device_id @schema@.scope_id PRIMARY KEY CHECK(device_id ~ '^[A-Za-z0-9_-]{22}$'),
 tenant_id @schema@.scope_id NOT NULL,
 client_id @schema@.scope_id NOT NULL,
 lookup_version bigint NOT NULL CHECK(lookup_version BETWEEN 1 AND 4294967295),
 device_digest bytea NOT NULL CHECK(octet_length(device_digest)=32),
 user_digest bytea NOT NULL CHECK(octet_length(user_digest)=32),
 state text COLLATE "C" NOT NULL CHECK(state IN('pending','approved','denied','cancelled','expired','consumed')),
 version @schema@.version NOT NULL,
 last_command @schema@.scope_id NOT NULL,
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
 next_poll_at timestamptz NOT NULL CHECK(isfinite(next_poll_at)),
 interval_seconds integer NOT NULL CHECK(interval_seconds BETWEEN 5 AND 60),
 details jsonb NOT NULL CHECK(jsonb_typeof(details)='object' AND octet_length(details::text)<=65536),
 CHECK(expires_at>created_at),
 CONSTRAINT devices_device_lookup UNIQUE(tenant_id,lookup_version,device_digest),
 CONSTRAINT devices_user_lookup UNIQUE(tenant_id,lookup_version,user_digest)
);
CREATE INDEX device_expiry_order ON @schema@.devices(tenant_id,expires_at,device_id) WHERE state IN('pending','approved');
CREATE TABLE @schema@.device_effects(
 tenant_id @schema@.scope_id NOT NULL,
 command_id @schema@.scope_id NOT NULL,
 operation_id @schema@.scope_id NOT NULL,
 device_id @schema@.scope_id NOT NULL REFERENCES @schema@.devices(device_id),
 before_version numeric NOT NULL CHECK(before_version>=0 AND before_version<=18446744073709551615 AND scale(before_version)=0),
 after_version @schema@.version NOT NULL,
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 CHECK(after_version=before_version+1)
);
ALTER TABLE @schema@.artifacts
 ADD COLUMN device_root boolean NOT NULL DEFAULT false,
 ADD COLUMN device_root_grant text GENERATED ALWAYS AS (CASE WHEN device_root THEN grant_id END) STORED,
 DROP CONSTRAINT artifacts_check,
 ADD CONSTRAINT artifacts_device_parent CHECK((kind=1 OR device_root)=(parent_artifact_id IS NULL)),
 ADD CONSTRAINT artifacts_device_root_kind CHECK(NOT device_root OR kind IN(3,4)),
 ADD CONSTRAINT artifacts_device_origin FOREIGN KEY(device_root_grant) REFERENCES @schema@.devices(device_id);
`
