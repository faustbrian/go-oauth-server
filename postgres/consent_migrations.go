package oauthpostgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// ConsentMigrationSource appends own-consent withdrawal authority to Base's
// installed OAuth history (with or without WorkloadMigrationSource). Version
// must follow every Base version. It preserves published migration bytes and
// populated human grants, binding already-approved grants to generation one.
// Stop issuance/old writers for this exclusive ALTER/backfill window, allow
// table/index/WAL headroom, then enable ConsentManagement on every serving
// instance. Old binaries/configurations must not continue accepting tokens.
// This is correctness/reference integrity, not a performance optimization.
type ConsentMigrationSource struct {
	Base    migrations.Source
	Schema  string
	Version migrations.Version
}

// Load returns independent forward-only history without IO or object adoption.
// Failure is transactional; no down migration erases durable withdrawal state.
func (s ConsentMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_consent_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "oauth_consent_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "oauth_consent_migration"}
		}
	}
	sql := strings.ReplaceAll(consentSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	next, err := migrations.NewMigration(s.Version, "oauth_own_consent_withdrawal", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

// One consent-generation barrier establishes denial; grants/artifacts retain
// immutable root/parent lineage. Reconfirmation never changes old generations.
// The added unique reference is deliberately owner-scoped, not an identity FK.
const consentSchemaSQL = `ALTER TABLE @schema@.consents
 ADD COLUMN state text COLLATE "C" NOT NULL DEFAULT 'active' CHECK(state IN('active','revoked')),
 ADD COLUMN generation @schema@.version NOT NULL DEFAULT 1,
 ADD COLUMN revoked_command @schema@.scope_id,
 ADD COLUMN revoked_at timestamptz,
 ADD COLUMN client_fingerprint bytea CHECK(octet_length(client_fingerprint)=32),
 ADD CONSTRAINT consent_withdrawal_state CHECK((state='active' AND revoked_command IS NULL AND revoked_at IS NULL) OR (state='revoked' AND revoked_command IS NOT NULL AND revoked_at IS NOT NULL AND isfinite(revoked_at))),
 ADD CONSTRAINT consent_owned_reference UNIQUE(consent_id,tenant_id,user_id,client_id);
ALTER TABLE @schema@.grants
 ADD COLUMN consent_id @schema@.scope_id,
 ADD COLUMN consent_generation @schema@.version,
 ADD CONSTRAINT grant_consent_pair CHECK((consent_id IS NULL)=(consent_generation IS NULL)),
 ADD CONSTRAINT grant_consent_human CHECK(consent_id IS NULL OR user_id IS NOT NULL),
 ADD CONSTRAINT grant_owned_consent FOREIGN KEY(consent_id,tenant_id,user_id,client_id) REFERENCES @schema@.consents(consent_id,tenant_id,user_id,client_id);
UPDATE @schema@.grants g SET consent_id=c.consent_id,consent_generation=c.generation
 FROM @schema@.consents c
 WHERE g.tenant_id=c.tenant_id AND g.user_id=c.user_id AND g.client_id=c.client_id
 AND EXISTS(SELECT 1 FROM @schema@.artifacts a WHERE a.grant_id=g.grant_id AND a.kind=2);
UPDATE @schema@.consents c SET client_fingerprint=(
 SELECT DISTINCT g.client_fingerprint FROM @schema@.grants g JOIN @schema@.artifacts a USING(grant_id)
 WHERE a.kind=2 AND a.created_at=c.granted_at AND g.tenant_id=c.tenant_id AND g.user_id=c.user_id
 AND g.client_id=c.client_id AND g.client_version=c.client_version);
ALTER TABLE @schema@.consents ALTER COLUMN client_fingerprint SET NOT NULL;
ALTER TABLE @schema@.effects
 ALTER COLUMN grant_id DROP NOT NULL,
 ADD COLUMN consent_id @schema@.scope_id REFERENCES @schema@.consents(consent_id),
 ADD CONSTRAINT effect_exact_owner CHECK((grant_id IS NULL)<>(consent_id IS NULL));
`
