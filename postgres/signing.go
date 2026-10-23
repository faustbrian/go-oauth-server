package oauthpostgres

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/jackc/pgx/v5"
)

var _ oauth.SigningLifecycle = (*Store)(nil)
var _ oauth.SigningVerificationKeys = (*Store)(nil)

// VerificationSigningKey reads retained public verification custody without
// publishing or activating anything. RP-Initiated Logout permits expired hints;
// last_expiry therefore does not discard retired material. Registered (never
// published), compromised, foreign and unavailable material fail closed.
func (s *Store) VerificationSigningKey(ctx context.Context, kid string) (oauth.PublicSigningKey, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return oauth.PublicSigningKey{}, err
	}
	defer stop()
	if !boundedText(kid, 128) {
		return oauth.PublicSigningKey{}, oauth.ErrInvalidRequest
	}
	var raw []byte
	err = s.pool.Raw().QueryRow(ctx, `SELECT public_key FROM `+s.schema+`.signing_keys WHERE kid=$1 AND published_at IS NOT NULL AND state IN('published','retired')`, kid).Scan(&raw)
	if err != nil {
		return oauth.PublicSigningKey{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	var key oauth.PublicSigningKey
	if decodeJSON(raw, &key) != nil || !validPublicSigningKey(key) || key.Kid != kid {
		return oauth.PublicSigningKey{}, oauth.ErrUnavailable
	}
	return key, nil
}

func validPublicSigningKey(k oauth.PublicSigningKey) bool {
	if !boundedText(k.Kid, 128) || k.Kty != "EC" || k.Crv != "P-256" || k.Use != "sig" || k.Alg != "ES256" || len(k.X) != 43 || len(k.Y) != 43 {
		return false
	}
	x, err := base64.RawURLEncoding.Strict().DecodeString(k.X)
	if err != nil || len(x) != 32 {
		return false
	}
	y, err := base64.RawURLEncoding.Strict().DecodeString(k.Y)
	if err != nil || len(y) != 32 {
		return false
	}
	return elliptic.P256().IsOnCurve(new(big.Int).SetBytes(x), new(big.Int).SetBytes(y))
}

// RegisterSigningKey binds an immutable kid to public material idempotently.
// Existing retired/compromised identities can never be installed again. These
// deployment-authorized key operations accept no untrusted request/actor input.
func (s *Store) RegisterSigningKey(ctx context.Context, key oauth.PublicSigningKey) error {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return err
	}
	defer stop()
	if !validPublicSigningKey(key) {
		return oauth.ErrInvalidRequest
	}
	wire, err := json.Marshal(key)
	if err != nil {
		return oauth.ErrInvalidRequest
	}
	var kid string
	err = s.pool.Raw().QueryRow(ctx, `INSERT INTO `+s.schema+`.signing_keys(kid,slot,public_key,state) SELECT $1::text,COALESCE((SELECT slot FROM `+s.schema+`.signing_keys WHERE kid=$1::text),(SELECT min(candidate) FROM generate_series(1,64) candidate WHERE NOT EXISTS(SELECT 1 FROM `+s.schema+`.signing_keys WHERE slot=candidate))),$2::jsonb,'registered' ON CONFLICT(kid) DO UPDATE SET public_key=signing_keys.public_key WHERE signing_keys.public_key=EXCLUDED.public_key AND signing_keys.state IN('registered','published') RETURNING kid`, key.Kid, string(wire)).Scan(&kid)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth.ErrAccessDenied
	}
	return publicError(ctx, err, oauth.ErrAccessDenied)
}

// PublishSigningKeys durably publishes every registered key before projecting
// its public bytes. An unknown acknowledgement must not activate a new key;
// repeat this idempotent publication before activation. Private members cannot
// enter the table or public projection. No positive JWKS cache is maintained.
func (s *Store) PublishSigningKeys(ctx context.Context) ([]oauth.PublicSigningKey, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return nil, err
	}
	defer stop()
	rows, err := s.pool.Raw().Query(ctx, `WITH publication AS (UPDATE `+s.schema+`.signing_keys SET state='published',published_at=COALESCE(published_at,clock_timestamp()) WHERE state IN('registered','published') RETURNING public_key,kid) SELECT public_key FROM publication ORDER BY kid`)
	if err != nil {
		return nil, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	defer rows.Close()
	out := []oauth.PublicSigningKey{}
	for rows.Next() {
		var wire []byte
		if err := rows.Scan(&wire); err != nil {
			return nil, oauth.ErrUnavailable
		}
		var key oauth.PublicSigningKey
		if decodeJSON(wire, &key) != nil || !validPublicSigningKey(key) {
			return nil, oauth.ErrUnavailable
		}
		out = append(out, key)
	}
	if err := rows.Err(); err != nil {
		return nil, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	return out, nil
}

func (s *Store) ActivateSigningKey(ctx context.Context, kid string) error {
	return s.signingMutation(ctx, `UPDATE `+s.schema+`.signing_selection SET kid=$1 WHERE singleton AND EXISTS(SELECT 1 FROM `+s.schema+`.signing_keys WHERE kid=$1 AND state='published')`, kid)
}

// ReserveSigningKey atomically retains the greatest possible ID-token expiry
// under the current published selection. It is conservative on token rollback,
// timeout or restart; no retry resets an expiry or re-creates a token.
func (s *Store) ReserveSigningKey(ctx context.Context, kid string, expiry time.Time) error {
	return s.signingMutation(ctx, `UPDATE `+s.schema+`.signing_keys SET last_expiry=GREATEST(last_expiry,$2) WHERE kid=$1 AND state='published' AND kid=(SELECT kid FROM `+s.schema+`.signing_selection WHERE singleton) AND clock_timestamp()<$2 AND $2<=clock_timestamp()+interval '5 minutes'`, kid, expiry)
}

func (s *Store) RetireSigningKey(ctx context.Context, kid string) error {
	return s.signingMutation(ctx, `UPDATE `+s.schema+`.signing_keys SET state='retired' WHERE kid=$1 AND state IN('published','retired') AND last_expiry<=clock_timestamp() AND kid IS DISTINCT FROM(SELECT kid FROM `+s.schema+`.signing_selection WHERE singleton)`, kid)
}
func (s *Store) CompromiseSigningKey(ctx context.Context, kid string) error {
	return s.signingMutation(ctx, `UPDATE `+s.schema+`.signing_keys SET state='compromised' WHERE kid=$1 AND state IN('registered','published','retired','compromised')`, kid)
}
func (s *Store) signingMutation(ctx context.Context, query, kid string, extra ...any) error {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return err
	}
	defer stop()
	if !boundedText(kid, 128) {
		return oauth.ErrInvalidRequest
	}
	// All selection-sensitive lifecycle transitions take the singleton first,
	// then key rows. The subsequent READ COMMITTED statement re-reads predicates
	// after waiting: an earlier unlocked snapshot could select a retired key.
	// Publication/register touch only keys; token Work's final fence likewise
	// takes only its key, so neither introduces an inverse selection/key order.
	tx, err := s.pool.Raw().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	defer tx.Rollback(ctx)
	var singleton bool
	if err := tx.QueryRow(ctx, `SELECT singleton FROM `+s.schema+`.signing_selection WHERE singleton FOR UPDATE`).Scan(&singleton); err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if !singleton {
		return oauth.ErrAccessDenied
	}
	args := append([]any{kid}, extra...)
	result, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if result.RowsAffected() != 1 {
		return oauth.ErrAccessDenied
	}
	return publicError(ctx, tx.Commit(ctx), oauth.ErrAccessDenied)
}

// This final native Work fence shares the actual token transaction. A
// compromise cannot cross issuance commit unnoticed; holding a shared row lock
// until commit serializes the explicit compromise update with usable delivery.
func (p *phase) checkSigning(ctx context.Context, w kernel.Work) error {
	kid := p.output.SigningKeyID
	if kid == "" {
		return nil
	}
	var state string
	rows, err := w.Query(ctx, `SELECT state FROM `+p.store.schema+`.signing_keys WHERE kid=$1 AND last_expiry>=$2 FOR SHARE`, kid, p.output.Artifacts[0].ExpiresAt)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() || rows.Scan(&state) != nil || rows.Next() || rows.Err() != nil || state != "published" {
		return oauth.ErrAccessDenied
	}
	return nil
}
