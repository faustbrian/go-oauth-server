package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// OrganizationAPIKeyExchangeMigrationSource appends four forward-only steps to
// completed APIKeyExchangeMigrationSource history. Version reserves four unused
// versions; all original migration bytes and populated rows remain unchanged.
// Install every step before selecting the separate organization Store/Service
// and bootstrapping clients. Schema alone enables no runtime profile.
//
// The tagged-owner check is added NOT VALID then separately validated before
// relaxing the USER-only shape/NOT NULL. Replacement shape validation is another
// step; each ALTER has a short lock wait and no row rewrite/backfill. Existing
// USER and selected workload writers retain their shapes. Unaware instances
// must not serve org-token traffic; reverting code leaves schema/rows intact.
// No destructive Down, new journal, cross-owner FK or authority is installed.
// Deployment sequencing, bounded migration context and pools remain caller-owned.
type OrganizationAPIKeyExchangeMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

// Load returns owned history without executing schema or selecting authority.
func (s OrganizationAPIKeyExchangeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64-3) {
		return nil, identity.InvalidInputError{Field: "oauth_organization_api_key_history"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	required := map[string]bool{"oauth_api_key_grant_expand": false, "oauth_api_key_artifact_expand": false, "oauth_api_key_reference_index": false, "oauth_api_key_reference_attach": false, "oauth_api_key_reference_fence": false, "oauth_api_key_grant_validate": false, "oauth_api_key_artifact_validate": false}
	for _, step := range history {
		if step.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_organization_api_key_history"}
		}
		if _, ok := required[step.Name()]; ok {
			required[step.Name()] = true
		}
	}
	for _, found := range required {
		if !found {
			return nil, identity.InvalidInputError{Field: "oauth_organization_api_key_history"}
		}
	}
	steps := []struct{ name, sql string }{
		{"oauth_organization_api_key_owner_expand", organizationAPIKeyOwnerSQL},
		{"oauth_organization_api_key_owner_validate", `SET LOCAL lock_timeout='1s'; ALTER TABLE @schema@.grants VALIDATE CONSTRAINT grants_api_key_organization_owner;`},
		{"oauth_organization_api_key_source_expand", organizationAPIKeySourceSQL},
		{"oauth_organization_api_key_source_validate", `SET LOCAL lock_timeout='1s'; ALTER TABLE @schema@.grants VALIDATE CONSTRAINT grants_api_key_organization_source;`},
	}
	out := append([]migrations.Migration(nil), history...)
	schema := pgx.Identifier{s.Schema}.Sanitize()
	for i, step := range steps {
		next, err := migrations.NewMigration(s.Version+migrations.Version(i), step.name, migrations.TransactionModeDefault, strings.ReplaceAll(step.sql, "@schema@", schema), "")
		if err != nil {
			return nil, identity.UnavailableError{}
		}
		out = append(out, next)
	}
	return out, nil
}

const organizationAPIKeyOwnerSQL = `SET LOCAL lock_timeout='1s';
ALTER TABLE @schema@.grants ADD CONSTRAINT grants_api_key_organization_owner CHECK((NOT api_key_only OR (
 jsonb_typeof(api_key_source->'Owner')='object'
 AND jsonb_typeof(api_key_source#>'{Owner,TenantID}')='string'
 AND jsonb_typeof(api_key_source#>'{Owner,UserID}')='string'
 AND jsonb_typeof(api_key_source#>'{Owner,OrganizationID}')='string'
 AND jsonb_typeof(api_key_source#>'{Owner,Kind}')='number'
 AND api_key_source#>>'{Owner,TenantID}'=tenant_id::text
 AND CASE WHEN jsonb_typeof(api_key_source#>'{Owner,Version}')='number'
  AND api_key_source#>>'{Owner,Version}' ~ '^[1-9][0-9]{0,19}$'
  THEN (api_key_source#>>'{Owner,Version}')::numeric<=18446744073709551615 ELSE false END
 AND ((user_id IS NOT NULL AND api_key_source#>>'{Owner,Kind}'='1'
       AND api_key_source#>>'{Owner,UserID}'=user_id::text
       AND api_key_source#>>'{Owner,OrganizationID}'='')
   OR (user_id IS NULL AND api_key_source#>>'{Owner,Kind}'='2'
       AND api_key_source#>>'{Owner,UserID}'=''
       AND api_key_source#>>'{Owner,OrganizationID}' ~ '^[!-~]{1,128}$'))
)) IS TRUE) NOT VALID;`

const organizationAPIKeySourceSQL = `SET LOCAL lock_timeout='1s';
DO $organization_api_key_source$
DECLARE
 ordinary text := '(user_id IS NOT NULL AND jsonb_typeof(source_session)=''array'' AND jsonb_array_length(source_session)>0 AND octet_length(source_session::text)<=65536)';
 selected text := '(api_key_only AND source_session=''[]''::jsonb AND jsonb_typeof(api_key_source)=''object'' AND octet_length(api_key_source::text)<=65536';
BEGIN
 IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.grants'::regclass AND attname='workload_source' AND NOT attisdropped) THEN
  ordinary := '((workload_source IS NULL AND ' || ordinary || ') OR (workload_source IS NOT NULL AND user_id IS NULL AND source_session=''[]''::jsonb AND jsonb_typeof(workload_source)=''object'' AND octet_length(workload_source::text)<=4096))';
  selected := selected || ' AND workload_source IS NULL';
 END IF;
 IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='@schema@.grants'::regclass AND attname='consent_id' AND NOT attisdropped) THEN
  selected := selected || ' AND consent_id IS NULL AND consent_generation IS NULL';
 END IF;
 EXECUTE 'ALTER TABLE @schema@.grants DROP CONSTRAINT grants_api_key_source, ADD CONSTRAINT grants_api_key_organization_source CHECK((' || selected || ') OR (NOT api_key_only AND ' || ordinary || ')) IS TRUE) NOT VALID, ALTER COLUMN user_id DROP NOT NULL';
END $organization_api_key_source$;`
