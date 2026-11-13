package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// APIKeyExchangeMigrationSource appends seven forward-only steps to existing
// OAuth history. Version reserves Version..Version+6. Base may be plain OAuth
// or include already selected workload, consent, human or device suffixes; this
// suffix must be last. Installing it selects no runtime capability and requires
// no device/workload history. Original migration bytes and existing rows remain
// unchanged. New code with the profile disabled still serves the old schema.
//
// Install all steps before bootstrap/enablement. Expansion uses short lock
// waits and NOT VALID checks, then a separate concurrent reference index,
// attachment and validation. There is no generated-column rewrite or backfill.
// A failed concurrent index build may leave an invalid index/dirty migration:
// inspect and recover through the migration owner, never IF NOT EXISTS/adoption.
// Reverting code leaves schema/history intact; do not roll back to unaware
// writers after API-key grants exist. The caller owns bounded migration context,
// deployment sequencing, pool lifetime and maintenance headroom.
type APIKeyExchangeMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

// Load validates the allocation and returns independent owned history without
// IO, schema adoption, authority bootstrap or protocol activation.
func (s APIKeyExchangeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64-6) {
		return nil, identity.InvalidInputError{Field: "oauth_api_key_exchange_history"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_api_key_exchange_history"}
	}
	for _, step := range history {
		if step.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_api_key_exchange_history"}
		}
	}
	schema := pgx.Identifier{s.Schema}.Sanitize()
	steps := []struct {
		name string
		mode migrations.TransactionMode
		sql  string
	}{
		{"oauth_api_key_grant_expand", migrations.TransactionModeDefault, apiKeyGrantExpandSQL},
		{"oauth_api_key_artifact_expand", migrations.TransactionModeDefault, apiKeyArtifactExpandSQL},
		{"oauth_api_key_reference_index", migrations.TransactionModeNone, `CREATE UNIQUE INDEX CONCURRENTLY grants_api_key_reference_idx ON @schema@.grants(grant_id,api_key_only);`},
		{"oauth_api_key_reference_attach", migrations.TransactionModeDefault, `SET LOCAL lock_timeout='1s'; ALTER TABLE @schema@.grants ADD CONSTRAINT grants_api_key_reference UNIQUE USING INDEX grants_api_key_reference_idx;`},
		{"oauth_api_key_reference_fence", migrations.TransactionModeDefault, `SET LOCAL lock_timeout='1s'; ALTER TABLE @schema@.artifacts ADD CONSTRAINT artifacts_api_key_reference FOREIGN KEY(grant_id,api_key_only) REFERENCES @schema@.grants(grant_id,api_key_only) NOT VALID;`},
		{"oauth_api_key_grant_validate", migrations.TransactionModeDefault, `SET LOCAL lock_timeout='1s'; ALTER TABLE @schema@.grants VALIDATE CONSTRAINT grants_api_key_pair, VALIDATE CONSTRAINT grants_api_key_source;`},
		{"oauth_api_key_artifact_validate", migrations.TransactionModeDefault, `SET LOCAL lock_timeout='1s'; ALTER TABLE @schema@.artifacts VALIDATE CONSTRAINT artifacts_api_key_parent, VALIDATE CONSTRAINT artifacts_api_key_shape, VALIDATE CONSTRAINT artifacts_api_key_metadata, VALIDATE CONSTRAINT artifacts_api_key_reference;`},
	}
	out := append([]migrations.Migration(nil), history...)
	for i, step := range steps {
		next, err := migrations.NewMigration(s.Version+migrations.Version(i), step.name, step.mode, strings.ReplaceAll(step.sql, "@schema@", schema), "")
		if err != nil {
			return nil, identity.UnavailableError{}
		}
		out = append(out, next)
	}
	return out, nil
}

const apiKeyGrantExpandSQL = `SET LOCAL lock_timeout='1s';
ALTER TABLE @schema@.grants
 ADD COLUMN api_key_source jsonb,
 ADD COLUMN api_key_only boolean NOT NULL DEFAULT false,
 ADD CONSTRAINT grants_api_key_pair CHECK(api_key_only=(api_key_source IS NOT NULL)) NOT VALID;
DO $api_key_grants$
DECLARE
 ordinary text := '(user_id IS NOT NULL AND jsonb_typeof(source_session)=''array'' AND jsonb_array_length(source_session)>0 AND octet_length(source_session::text)<=65536)';
 selected text := '(api_key_only AND user_id IS NOT NULL AND source_session=''[]''::jsonb AND jsonb_typeof(api_key_source)=''object'' AND octet_length(api_key_source::text)<=65536';
BEGIN
 IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.grants'::regclass AND attname='workload_source' AND NOT attisdropped) THEN
  ordinary := '((workload_source IS NULL AND ' || ordinary || ') OR (workload_source IS NOT NULL AND user_id IS NULL AND source_session=''[]''::jsonb AND jsonb_typeof(workload_source)=''object'' AND octet_length(workload_source::text)<=4096))';
  selected := selected || ' AND workload_source IS NULL';
  ALTER TABLE @schema@.grants DROP CONSTRAINT grants_typed_subject;
 ELSE
  ALTER TABLE @schema@.grants DROP CONSTRAINT grants_source_session_check;
 END IF;
 IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.grants'::regclass AND attname='consent_id' AND NOT attisdropped) THEN
  selected := selected || ' AND consent_id IS NULL AND consent_generation IS NULL';
 END IF;
 EXECUTE 'ALTER TABLE @schema@.grants ADD CONSTRAINT grants_api_key_source CHECK((' || selected || ') OR (NOT api_key_only AND ' || ordinary || ')) IS TRUE) NOT VALID';
END $api_key_grants$;
`

const apiKeyArtifactExpandSQL = `SET LOCAL lock_timeout='1s';
ALTER TABLE @schema@.artifacts
 ADD COLUMN api_key_only boolean NOT NULL DEFAULT false,
 ADD COLUMN api_key_root boolean NOT NULL DEFAULT false;
DO $api_key_artifacts$
DECLARE
 roots text := 'kind=1';
 incompatible text := '';
 field text;
BEGIN
 IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.artifacts'::regclass AND attname='workload_only' AND NOT attisdropped) THEN
  IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.artifacts'::regclass AND attname='workload_exchange' AND NOT attisdropped) THEN
   roots := roots || ' OR (workload_only AND NOT workload_exchange)';
  ELSE
   roots := roots || ' OR workload_only';
  END IF;
 END IF;
 FOREACH field IN ARRAY ARRAY['silent_code','device_root'] LOOP
  IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.artifacts'::regclass AND attname=field AND NOT attisdropped) THEN
   roots := roots || ' OR ' || quote_ident(field);
  END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['workload_only','workload_exchange','human_code_exchange','silent_code','device_root'] LOOP
  IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.artifacts'::regclass AND attname=field AND NOT attisdropped) THEN
   incompatible := incompatible || ' AND NOT ' || quote_ident(field);
  END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='@schema@.artifacts'::regclass AND conname='artifacts_typed_parent') THEN
  ALTER TABLE @schema@.artifacts DROP CONSTRAINT artifacts_typed_parent;
 ELSIF EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='@schema@.artifacts'::regclass AND conname='artifacts_device_parent') THEN
  ALTER TABLE @schema@.artifacts DROP CONSTRAINT artifacts_device_parent;
 ELSE
  ALTER TABLE @schema@.artifacts DROP CONSTRAINT artifacts_check;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.artifacts'::regclass AND attname='metadata_version' AND NOT attisdropped) THEN
  ALTER TABLE @schema@.artifacts ADD COLUMN metadata_version smallint NOT NULL DEFAULT 1;
 ELSIF NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.artifacts'::regclass AND attname='metadata_version' AND atttypid='smallint'::regtype AND attnotnull AND NOT attisdropped) THEN
  RAISE EXCEPTION 'conflicting OAuth artifact metadata history';
 END IF;
 EXECUTE 'ALTER TABLE @schema@.artifacts ADD CONSTRAINT artifacts_api_key_parent CHECK(((' || roots || ' OR (api_key_only AND api_key_root))=(parent_artifact_id IS NULL)) IS TRUE) NOT VALID';
 EXECUTE 'ALTER TABLE @schema@.artifacts ADD CONSTRAINT artifacts_api_key_shape CHECK(((NOT api_key_only AND NOT api_key_root AND NOT(payload ? ''APIKeyExchange'')) OR (api_key_only AND kind=3 AND state IN(''active'',''revoked'') AND consumed_by IS NULL AND jsonb_typeof(payload->''APIKeyExchange'')=''object'' AND NOT(payload ?| ARRAY[''Exchange'',''HumanExchange'',''HumanRefresh'']) AND ((api_key_root AND payload#>>''{APIKeyExchange,Depth}''=''1'' AND payload#>>''{APIKeyExchange,ParentTokenType}''=''urn:golib:params:oauth:token-type:api-key'' AND payload#>>''{APIKeyExchange,RootID}''=payload#>>''{APIKeyExchange,ParentID}'') OR (NOT api_key_root AND payload#>>''{APIKeyExchange,Depth}'' IN(''2'',''3'',''4'') AND payload#>>''{APIKeyExchange,ParentTokenType}''=''urn:ietf:params:oauth:token-type:access_token''))' || incompatible || ')) IS TRUE) NOT VALID';
END $api_key_artifacts$;
ALTER TABLE @schema@.artifacts ADD CONSTRAINT artifacts_api_key_metadata CHECK(metadata_version=1) NOT VALID;
`
