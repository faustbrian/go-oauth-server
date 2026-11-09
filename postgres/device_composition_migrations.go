package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// DeviceCompositionMigrationSource adds optional device state to the exact
// selected workload/OIDC/exchange history, without rewriting installed SQL.
// Base must contain, in order, MigrationSource, ConsentMigrationSource,
// WorkloadMigrationSource, SigningMigrationSource, ConsentExpiryMigrationSource
// and WorkloadExchangeMigrationSource, with their original versions. Other
// histories, including an already installed DeviceMigrationSource, are rejected.
// Version and Version+1 permanently allocate installation and validation.
//
// Stop writers and install BOTH steps before enabling device operations. The
// stored generated column rewrites artifacts: reserve a maintenance window and
// table/index/WAL headroom. Lock acquisition is bounded to 1s and each statement
// to 5s; timeout rolls back that step. Validation is a separate transaction.
// Reverting feature selection retains history; no down migration erases grants.
type DeviceCompositionMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

// Load returns independent immutable history without IO, schema adoption or
// capability activation. Unknown, reordered or modified predecessor SQL denies.
func (s DeviceCompositionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := identity.InvalidInputError{Field: "oauth_device_composition_migration"}
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version >= migrations.Version(math.MaxInt64) {
		return nil, invalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	predecessors := []struct{ name, sql string }{
		{"oauth_authorization_code", schemaSQL},
		{"oauth_own_consent_withdrawal", consentSchemaSQL},
		{"oauth_configured_workload", workloadSchemaSQL},
		{"oauth_oidc_public_signing", signingSchemaSQL},
		{"oauth_explicit_consent_expiry", consentExpirySQL},
		{"oauth_workload_exchange", workloadExchangeSQL},
	}
	if len(history) != len(predecessors) {
		return nil, invalid
	}
	schema := pgx.Identifier{s.Schema}.Sanitize()
	for i, prior := range history {
		if prior.Version() >= s.Version || i > 0 && prior.Version() <= history[i-1].Version() {
			return nil, invalid
		}
		expected, err := migrations.NewMigration(prior.Version(), predecessors[i].name, migrations.TransactionModeDefault, strings.ReplaceAll(predecessors[i].sql, "@schema@", schema), "")
		if err != nil || prior.Checksum() != expected.Checksum() {
			return nil, invalid
		}
	}
	result := append([]migrations.Migration(nil), history...)
	for i, suffix := range []struct{ name, sql string }{
		{"oauth_composed_device", deviceCompositionSQL},
		{"oauth_composed_device_validation", deviceCompositionValidationSQL},
	} {
		next, err := migrations.NewMigration(s.Version+migrations.Version(i), suffix.name, migrations.TransactionModeDefault, strings.ReplaceAll(suffix.sql, "@schema@", schema), "")
		if err != nil {
			return nil, err
		}
		result = append(result, next)
	}
	return result, nil
}

// The historical device migration remains immutable. This distinct profile
// preserves all three existing root classes and the delegated-workload parent
// rule. A device marker cannot relabel a workload or silent-code artifact.
const deviceCompositionSQL = `SET LOCAL lock_timeout = '1s';
SET LOCAL statement_timeout = '5s';
CREATE TABLE @schema@.devices(
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
 DROP CONSTRAINT artifacts_typed_parent,
 ADD CONSTRAINT artifacts_typed_parent CHECK((kind=1 OR (workload_only AND NOT workload_exchange) OR silent_code OR device_root)=(parent_artifact_id IS NULL)) NOT VALID,
 ADD CONSTRAINT artifacts_device_root_kind CHECK(NOT device_root OR (kind IN(3,4) AND NOT workload_only AND NOT workload_exchange AND NOT silent_code)) NOT VALID,
 ADD CONSTRAINT artifacts_device_origin FOREIGN KEY(device_root_grant) REFERENCES @schema@.devices(device_id) NOT VALID;
`

const deviceCompositionValidationSQL = `SET LOCAL lock_timeout = '1s';
SET LOCAL statement_timeout = '5s';
ALTER TABLE @schema@.artifacts
 VALIDATE CONSTRAINT artifacts_typed_parent,
 VALIDATE CONSTRAINT artifacts_device_root_kind,
 VALIDATE CONSTRAINT artifacts_device_origin;
`
