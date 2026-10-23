package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// ConsentExpiryMigrationSource appends nullable approval expiry to installed
// consent-management history. NULL legacy approval is deliberately NOT reusable:
// migration cannot invent an original user's approval lifetime. Stop accepting
// writers, install forward history, replace old instances, then explicitly set
// positive ConsentReuseTTL on EVERY accepting writer. Mixed/zero-writer rollback
// is unsupported and history is not reversible; revoke consent to withdraw reuse.
// Original migration bytes and retained preparation are unchanged.
type ConsentExpiryMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

func (s ConsentExpiryMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_consent_expiry_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_consent_expiry_migration"}
	}
	for _, step := range history {
		// The published expiry SQL predates delegated workload children and
		// restores its historical root predicate. Preserve those SQL/checksum
		// bytes; compose selected expiry before the newer exchange suffix.
		if step.Name() == "oauth_workload_exchange" {
			return nil, identity.InvalidInputError{Field: "oauth_consent_expiry_migration_order"}
		}
		if step.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_consent_expiry_migration"}
		}
	}
	next, err := migrations.NewMigration(s.Version, "oauth_explicit_consent_expiry", migrations.TransactionModeDefault, strings.ReplaceAll(consentExpirySQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

// OAuth's product contract requires expiring reusable approval. OIDC Core1.0
// §3.1.2.1 requires existing consent for none but specifies no lifetime. The
// selected owner policy therefore requires an explicit conservative <=24h bound,
// anchored to original explicit approval, never backfilled or renewed silently.
const consentExpirySQL = `ALTER TABLE @schema@.consents
 ADD COLUMN expires_at timestamptz,
 ADD CONSTRAINT consent_expiry_bounded CHECK(expires_at IS NULL OR
  (isfinite(expires_at) AND expires_at>granted_at AND expires_at<=granted_at+interval '24 hours'));
ALTER TABLE @schema@.artifacts
 ADD COLUMN silent_code boolean NOT NULL DEFAULT false,
 ADD CONSTRAINT artifacts_silent_code CHECK(NOT silent_code OR (kind=2 AND parent_artifact_id IS NULL));
DO $silent_parent$
BEGIN
 IF EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='@schema@.artifacts'::regclass AND conname='artifacts_typed_parent') THEN
  ALTER TABLE @schema@.artifacts DROP CONSTRAINT artifacts_typed_parent;
  ALTER TABLE @schema@.artifacts ADD CONSTRAINT artifacts_typed_parent CHECK((kind=1 OR workload_only OR silent_code)=(parent_artifact_id IS NULL));
 ELSE
  ALTER TABLE @schema@.artifacts DROP CONSTRAINT artifacts_check;
  ALTER TABLE @schema@.artifacts ADD CONSTRAINT artifacts_check CHECK((kind=1 OR silent_code)=(parent_artifact_id IS NULL));
 END IF;
END $silent_parent$;
`
