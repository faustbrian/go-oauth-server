package oauthpostgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"strconv"

	oauth "github.com/faustbrian/go-oauth-server"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/jackc/pgx/v5"
)

// subjectContext is only a fixed-width index key, not an authority. Exact
// issuer/environment bytes are also stored/rechecked: indexing the full allowed
// 2048-byte issuer in every composite key would exceed bounded B-tree entries.
func (s *Store) subjectContext() [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("golib.oidc.subject-context.v1\x00"))
	for _, value := range []string{s.config.Protocol.Issuer.String(), s.config.Protocol.Environment} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func (s *Store) subjectPolicySelected(id string, version uint64) bool {
	for _, client := range s.config.Protocol.Clients {
		p := client.SubjectRegistration
		if p != nil && p.SubjectType() == "pairwise" && p.PolicyID() == id && p.PolicyVersion() == version {
			return true
		}
	}
	return false
}

// InstallSubjectKey authenticates and durably stages exact versioned encrypted
// HMAC custody for a configured pairwise policy. The same material/version may
// be explicitly rewrapped; different material or a retired version never may.
// It does not activate writers. Deployment callers supply configuration only,
// never end-user/HTTP authority. At most eight unretired versions are retained.
func (s *Store) InstallSubjectKey(ctx context.Context, registration oauth.OIDCSubjectKeyRegistration) error {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return err
	}
	defer stop()
	if !s.subjectPolicySelected(registration.PolicyID, registration.PolicyVersion) || registration.Issuer != s.config.Protocol.Issuer || registration.Environment != s.config.Protocol.Environment || registration.KeyVersion == 0 || registration.Commitment == ([32]byte{}) || len(registration.Envelope) == 0 || len(registration.Envelope) > 16384 {
		return oauth.ErrInvalidRequest
	}
	sealed, err := envelope.ParseEnvelope(registration.Envelope)
	if err != nil {
		return oauth.ErrAccessDenied
	}
	aad, _ := envelope.NewContext(map[string]string{"profile": "golib.oidc.pairwise-key.v1", "issuer": registration.Issuer.String(), "environment": registration.Environment, "policy_id": registration.PolicyID, "policy_version": strconv.FormatUint(registration.PolicyVersion, 10), "key_version": strconv.FormatUint(uint64(registration.KeyVersion), 10)})
	plain, err := s.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// NewStore borrows only the local keyring provider. A foreign AAD or
		// unavailable wrapping reference is invalid registration custody, not
		// a SQL/service outage; the envelope owner intentionally hides which.
		return oauth.ErrAccessDenied
	}
	commitment := sha256.Sum256(plain)
	valid := len(plain) == 32 && subtle.ConstantTimeCompare(commitment[:], registration.Commitment[:]) == 1
	var material [32]byte
	copy(material[:], plain)
	valid = valid && material != ([32]byte{})
	clear(material[:])
	clear(plain)
	if !valid {
		return oauth.ErrAccessDenied
	}
	tx, err := s.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	defer tx.Rollback(ctx)
	contextID := s.subjectContext()
	policyVersion := strconv.FormatUint(registration.PolicyVersion, 10)
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.subject_selection(context_id,issuer,environment,policy_id,policy_version) VALUES($1,$2,$3,$4,$5::numeric) ON CONFLICT DO NOTHING`, contextID[:], registration.Issuer.String(), registration.Environment, registration.PolicyID, policyVersion); err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if err := s.lockSubjectSelection(ctx, tx, registration.PolicyID, registration.PolicyVersion); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.subject_keys(context_id,issuer,environment,policy_id,policy_version,key_version,commitment,envelope) SELECT $1,$2::text,$3::text,$4::text,$5::numeric,$6,$7,$8 WHERE EXISTS(SELECT 1 FROM `+s.schema+`.subject_keys WHERE context_id=$1 AND policy_id=$4::text AND policy_version=$5::numeric AND key_version=$6) OR (SELECT count(*) FROM `+s.schema+`.subject_keys WHERE context_id=$1 AND policy_id=$4::text AND policy_version=$5::numeric AND NOT retired)<8 ON CONFLICT(context_id,policy_id,policy_version,key_version) DO UPDATE SET envelope=EXCLUDED.envelope WHERE NOT subject_keys.retired AND subject_keys.commitment=EXCLUDED.commitment AND subject_keys.issuer=EXCLUDED.issuer AND subject_keys.environment=EXCLUDED.environment`, contextID[:], registration.Issuer.String(), registration.Environment, registration.PolicyID, policyVersion, registration.KeyVersion, commitment[:], registration.Envelope)
	if err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if result.RowsAffected() != 1 {
		return oauth.ErrAccessDenied
	}
	return publicError(ctx, tx.Commit(ctx), oauth.ErrAccessDenied)
}

// ActivateSubjectKey selects a staged, unretired writer. Existing durable
// subjects are never changed. Selection/retirement/rewrap serialize on the same
// policy row before reading key predicates, including after a lock wait.
func (s *Store) ActivateSubjectKey(ctx context.Context, policyID string, policyVersion uint64, keyVersion uint32) error {
	return s.subjectKeyMutation(ctx, policyID, policyVersion, keyVersion, false)
}

// RetireSubjectKey drops inactive encrypted custody but retains its immutable
// version/material tombstone and all stable subject bindings. Active writers
// cannot retire. Native authorization Work holds the selection share lock until
// commit, so no pending first-binding operation can cross custody retirement.
// Existing grants need only stored subjects, never old derivation material.
func (s *Store) RetireSubjectKey(ctx context.Context, policyID string, policyVersion uint64, keyVersion uint32) error {
	return s.subjectKeyMutation(ctx, policyID, policyVersion, keyVersion, true)
}

// SubjectKeyRegistrations returns one statement-consistent, independently owned
// snapshot of at most eight unretired encrypted keys and the active writer.
// Reconstruct the child with its public NewSubjectPolicy constructor and the
// existing envelope provider. Retired ciphertext is never returned. A concurrent
// later selection change may make this snapshot stale; native Authorize still
// fences the actual current writer rather than trusting this read as authority.
func (s *Store) SubjectKeyRegistrations(ctx context.Context, policyID string, policyVersion uint64) ([]oauth.OIDCSubjectKeyRegistration, uint32, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer stop()
	if !s.subjectPolicySelected(policyID, policyVersion) {
		return nil, 0, oauth.ErrInvalidRequest
	}
	contextID := s.subjectContext()
	rows, err := s.pool.Raw().Query(ctx, `SELECT k.key_version,k.commitment,k.envelope,COALESCE(s.key_version,0),s.issuer,s.environment,k.issuer,k.environment FROM `+s.schema+`.subject_selection s JOIN `+s.schema+`.subject_keys k USING(context_id,policy_id,policy_version) WHERE s.context_id=$1 AND s.policy_id=$2 AND s.policy_version=$3::numeric AND NOT k.retired ORDER BY k.key_version LIMIT 9`, contextID[:], policyID, strconv.FormatUint(policyVersion, 10))
	if err != nil {
		return nil, 0, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	defer rows.Close()
	var out []oauth.OIDCSubjectKeyRegistration
	var active uint32
	foundActive := false
	for rows.Next() {
		var key oauth.OIDCSubjectKeyRegistration
		var commitment []byte
		var selected uint32
		var issuer, environment, keyIssuer, keyEnvironment string
		if rows.Scan(&key.KeyVersion, &commitment, &key.Envelope, &selected, &issuer, &environment, &keyIssuer, &keyEnvironment) != nil {
			return nil, 0, oauth.ErrUnavailable
		}
		if len(out) == 8 || len(commitment) != 32 || len(key.Envelope) == 0 || len(key.Envelope) > 16384 || key.KeyVersion == 0 || selected == 0 || active != 0 && active != selected || issuer != s.config.Protocol.Issuer.String() || environment != s.config.Protocol.Environment || issuer != keyIssuer || environment != keyEnvironment {
			return nil, 0, oauth.ErrAccessDenied
		}
		active = selected
		foundActive = foundActive || key.KeyVersion == active
		key.Issuer, key.Environment, key.PolicyID, key.PolicyVersion = s.config.Protocol.Issuer, environment, policyID, policyVersion
		copy(key.Commitment[:], commitment)
		if key.Commitment == ([32]byte{}) {
			return nil, 0, oauth.ErrAccessDenied
		}
		key.Envelope = append([]byte(nil), key.Envelope...)
		out = append(out, key)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if !foundActive {
		return nil, 0, oauth.ErrAccessDenied
	}
	return out, active, nil
}

func (s *Store) lockSubjectSelection(ctx context.Context, tx pgx.Tx, policyID string, policyVersion uint64) error {
	contextID := s.subjectContext()
	var issuer, environment string
	if err := tx.QueryRow(ctx, `SELECT issuer,environment FROM `+s.schema+`.subject_selection WHERE context_id=$1 AND policy_id=$2 AND policy_version=$3::numeric FOR UPDATE`, contextID[:], policyID, strconv.FormatUint(policyVersion, 10)).Scan(&issuer, &environment); err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if issuer != s.config.Protocol.Issuer.String() || environment != s.config.Protocol.Environment {
		return oauth.ErrAccessDenied
	}
	return nil
}

func (s *Store) subjectKeyMutation(ctx context.Context, policyID string, policyVersion uint64, keyVersion uint32, retire bool) error {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return err
	}
	defer stop()
	if !s.subjectPolicySelected(policyID, policyVersion) || keyVersion == 0 {
		return oauth.ErrInvalidRequest
	}
	tx, err := s.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	defer tx.Rollback(ctx)
	if err := s.lockSubjectSelection(ctx, tx, policyID, policyVersion); err != nil {
		return err
	}
	contextID := s.subjectContext()
	query := `UPDATE ` + s.schema + `.subject_selection SET key_version=$4 WHERE context_id=$1 AND policy_id=$2 AND policy_version=$3::numeric AND EXISTS(SELECT 1 FROM ` + s.schema + `.subject_keys k WHERE k.context_id=$1 AND k.policy_id=$2 AND k.policy_version=$3::numeric AND k.key_version=$4 AND NOT k.retired)`
	if retire {
		query = `UPDATE ` + s.schema + `.subject_keys SET retired=true,envelope=NULL WHERE context_id=$1 AND policy_id=$2 AND policy_version=$3::numeric AND key_version=$4 AND key_version IS DISTINCT FROM(SELECT key_version FROM ` + s.schema + `.subject_selection WHERE context_id=$1 AND policy_id=$2 AND policy_version=$3::numeric)`
	}
	result, err := tx.Exec(ctx, query, contextID[:], policyID, strconv.FormatUint(policyVersion, 10), keyVersion)
	if err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if result.RowsAffected() != 1 {
		return oauth.ErrAccessDenied
	}
	return publicError(ctx, tx.Commit(ctx), oauth.ErrAccessDenied)
}
