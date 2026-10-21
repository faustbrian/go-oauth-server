package oauthpostgres

import (
	"context"
	"crypto/hmac"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/jackc/pgx/v5"
)

// Original primary-row projection retained in existing encrypted preparation,
// never caller authority or a second approval store. Silent use cannot mutate
// this record's version, generation, original approval time or exclusive expiry.
type silentConsent struct {
	ID                   string
	Version, Generation  uint64
	GrantedAt, ExpiresAt time.Time
}

func (s *Store) validSilentInput(i phaseInput, client oauth.Client) bool {
	c := i.SilentConsent
	if c == nil || s.config.ConsentReuseTTL == 0 || !s.config.ConsentManagement || i.Transition != createInteraction || i.Request.Prompt != "none" || i.Authentication == nil || i.Authentication.Requirement != oauth.OIDCAuthenticationSilent || i.Grant.ConsentID != c.ID || i.Grant.ConsentGeneration != c.Generation || c.Version == 0 || c.Generation == 0 || c.GrantedAt.After(i.CreatedAt) || !c.ExpiresAt.After(i.CreatedAt) || c.ExpiresAt.After(c.GrantedAt.Add(s.config.ConsentReuseTTL)) || i.Grant.ExpiresAt.After(c.ExpiresAt) || client.Workload != nil {
		return false
	}
	_, err := identity.ParseSubjectID(c.ID)
	return err == nil
}

func (s *Store) readSilentConsent(ctx context.Context, client oauth.Client, g grantRecord) (*silentConsent, error) {
	if s.config.ConsentReuseTTL == 0 || !s.config.ConsentManagement {
		return nil, oauth.ErrConsentRequired
	}
	var c silentConsent
	var version, generation, clientVersion, state string
	var scopes, fingerprint []byte
	var expiry *time.Time
	err := s.pool.Raw().QueryRow(ctx, `SELECT consent_id,version::text,generation::text,state,client_version::text,client_fingerprint,scopes,granted_at,expires_at FROM `+s.schema+`.consents WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3`, string(g.Tenant), string(g.User), g.ClientID).Scan(&c.ID, &version, &generation, &state, &clientVersion, &fingerprint, &scopes, &c.GrantedAt, &expiry)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oauth.ErrConsentRequired
	}
	if err != nil {
		return nil, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	c.Version, err = strconv.ParseUint(version, 10, 64)
	if err != nil || c.Version == 0 {
		return nil, oauth.ErrUnavailable
	}
	c.Generation, err = strconv.ParseUint(generation, 10, 64)
	if _, idErr := identity.ParseSubjectID(c.ID); err != nil || idErr != nil || c.Generation == 0 {
		return nil, oauth.ErrUnavailable
	}
	var approved []string
	fp := clientFingerprint(client)
	if decodeJSON(scopes, &approved) != nil {
		return nil, oauth.ErrUnavailable
	}
	now, err := s.introspectionTime(ctx)
	if err != nil {
		return nil, err
	}
	if state != "active" || clientVersion != strconv.FormatUint(client.Version, 10) || !hmac.Equal(fingerprint, fp[:]) || !scopeSubset(g.Scopes, approved) || expiry == nil || !now.Before(*expiry) || !s.now().Before(*expiry) || c.GrantedAt.After(now) || expiry.After(c.GrantedAt.Add(s.config.ConsentReuseTTL)) {
		return nil, oauth.ErrConsentRequired
	}
	c.ExpiresAt = *expiry
	return &c, nil
}

func (p *phase) checkSilentConsent(ctx context.Context, w kernel.Work) error {
	i, g := p.input, p.input.Grant
	c := i.SilentConsent
	if !p.store.validSilentInput(i, p.client) {
		return identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT consent_id,version::text,generation::text,state,client_version::text,client_fingerprint,scopes,granted_at,expires_at FROM `+p.store.schema+`.consents WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3 FOR UPDATE`, string(g.Tenant), string(g.User), g.ClientID)
	if err != nil {
		return err
	}
	var id, version, generation, state, clientVersion string
	var fingerprint, scopes []byte
	var granted time.Time
	var expiry *time.Time
	if !rows.Next() {
		err := rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	err = rows.Scan(&id, &version, &generation, &state, &clientVersion, &fingerprint, &scopes, &granted, &expiry)
	extra, rowErr := rows.Next(), rows.Err()
	rows.Close()
	if err != nil || extra || rowErr != nil {
		return identity.UnavailableError{}
	}
	var approved []string
	fp := clientFingerprint(p.client)
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if id != c.ID || version != strconv.FormatUint(c.Version, 10) || generation != strconv.FormatUint(c.Generation, 10) || state != "active" || clientVersion != strconv.FormatUint(p.client.Version, 10) || !hmac.Equal(fingerprint, fp[:]) || !granted.Equal(c.GrantedAt) || expiry == nil || !expiry.Equal(c.ExpiresAt) || !now.Before(c.ExpiresAt) || decodeJSON(scopes, &approved) != nil || !scopeSubset(i.Scopes, approved) {
		// Protected Work uses the kernel's closed denial type. A protocol
		// consent_required error belongs only to the non-started preflight;
		// a late command must retain its durability/recovery classification.
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *phase) finishSilentAuthorization(ctx context.Context) error {
	i := p.input
	if _, err := p.store.checkedClient(ctx, p.client); err != nil {
		return err
	}
	current, err := p.store.readSilentConsent(ctx, p.client, i.Grant)
	if err != nil || !sameJSON(current, i.SilentConsent) {
		if err != nil {
			return err
		}
		return oauth.ErrConsentRequired
	}
	observed, err := p.store.recoverySession(ctx, RecoveryRequest{TenantID: i.Grant.Tenant, Session: p.browser})
	if err != nil {
		return err
	}
	source, err := sessionpg.OriginalSessionFields(observed.Session)
	if err != nil || !sameJSON(source, i.Grant.Source) {
		return oauth.ErrAccessDenied
	}
	now, err := p.store.introspectionTime(ctx)
	if err != nil {
		return err
	}
	if p.observation.ValidateAt(p.store.now()) != nil || p.observation.ValidateAt(now) != nil || now.Before(i.CreatedAt) || !now.Before(i.ObservationUntil) || !now.Before(i.SilentConsent.ExpiresAt) || i.Authentication != nil && !i.Authentication.Until.IsZero() && !now.Before(i.Authentication.Until) {
		return oauth.ErrAccessDenied
	}
	return ctx.Err()
}
