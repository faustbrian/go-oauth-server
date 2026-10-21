package oauthpostgres

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

var _ oauth.ClientReader = (*Store)(nil)

// clientReadObservation independently resolves borrowed browser custody. The
// exported execution is not a credential: a caller's GetResult must match the
// actual current native session, and can never renew its original read deadline.
// Policy callbacks run without rows, transactions or protected locks held.
func (s *Store) clientReadObservation(ctx context.Context, e oauth.ClientReadExecution, list bool) (identity.UserID, error) {
	p := s.config.Protocol.ManagedClients
	if p == nil || e.ValidateAt(s.now()) != nil {
		return "", oauth.ErrAccessDenied
	}
	if _, err := oauth.ValidateClientReadRequest(e.Request, list, *p); err != nil {
		return "", err
	}
	original, err := sessionpg.OriginalSessionFields(e.Session.Session)
	if err != nil {
		return "", oauth.ErrAccessDenied
	}
	current, err := s.recoverySession(ctx, RecoveryRequest{TenantID: e.Request.TenantID, Session: e.Request.Session})
	if err != nil {
		return "", err
	}
	fields, err := sessionpg.OriginalSessionFields(current.Session)
	if err != nil || !sameJSON(original, fields) {
		return "", oauth.ErrAccessDenied
	}
	b, _ := current.Session.Bindings()
	action := "identity.oauth-server.client-get"
	if list {
		action = "identity.oauth-server.client-list"
	}
	if err := s.managementDecision(ctx, b.UserID, action); err != nil {
		return "", err
	}
	// A policy callback may withdraw the existing actor authority. Re-read the
	// public session owner after that callback; do not trust its earlier decision.
	current, err = s.recoverySession(ctx, RecoveryRequest{TenantID: e.Request.TenantID, Session: e.Request.Session})
	if err != nil {
		return "", err
	}
	fields, err = sessionpg.OriginalSessionFields(current.Session)
	if err != nil || !sameJSON(original, fields) || e.ValidateAt(s.now()) != nil {
		return "", oauth.ErrAccessDenied
	}
	return b.UserID, nil
}

func (s *Store) encodeClientReadCursor(id string, e oauth.ClientReadExecution, user identity.UserID) string {
	policy := s.managementPolicy()
	digest := s.intent("oauth-managed-client-cursor-v1", string(e.Request.TenantID), e.Request.Owner.PlatformID(), string(user), strconv.FormatUint(uint64(e.Request.Limit), 10), base64.RawURLEncoding.EncodeToString(policy[:]), id)
	return id + "." + base64.RawURLEncoding.EncodeToString(digest[:])
}

func (s *Store) clientReadCursor(e oauth.ClientReadExecution, user identity.UserID) (string, error) {
	wire := e.Request.Cursor.String()
	if wire == "" {
		return "", nil
	}
	// Managed IDs contain the existing canonical 22-character subject ID.
	const idLength = len(oauth.ManagedClientPrefix) + 22
	if len(wire) != idLength+1+43 || wire[idLength] != '.' || !strings.HasPrefix(wire, oauth.ManagedClientPrefix) {
		return "", oauth.ErrInvalidRequest
	}
	id := wire[:idLength]
	if _, err := identity.ParseSubjectID(strings.TrimPrefix(id, oauth.ManagedClientPrefix)); err != nil {
		return "", oauth.ErrInvalidRequest
	}
	if !hmac.Equal([]byte(wire), []byte(s.encodeClientReadCursor(id, e, user))) {
		return "", oauth.ErrAccessDenied
	}
	return id, nil
}

// readClientMetadata deliberately selects no secret, digest or encrypted input.
// The extra bounded list row determines whether a scoped continuation is needed.
func (s *Store) readClientMetadata(ctx context.Context, e oauth.ClientReadExecution, list bool, after string) ([]oauth.Client, error) {
	p := s.config.Protocol.ManagedClients
	query := `SELECT registration,version::text,client_id FROM ` + s.schema + `.managed_clients WHERE issuer=$1 AND environment=$2 AND platform_owner=$3 AND tenant_id=$4 AND state='active'`
	args := []any{s.config.Protocol.Issuer.String(), s.config.Protocol.Environment, p.Owner.PlatformID(), string(p.TenantID)}
	if list {
		query += ` AND client_id COLLATE "C">$5 ORDER BY client_id COLLATE "C" LIMIT $6`
		args = append(args, after, int(e.Request.Limit)+1)
	} else {
		query += ` AND client_id=$5 LIMIT 1`
		args = append(args, e.Request.ClientID)
	}
	rows, err := s.pool.Raw().Query(ctx, query, args...)
	if err != nil {
		return nil, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	defer rows.Close()
	items := make([]oauth.Client, 0)
	for rows.Next() {
		var wire []byte
		var version, id string
		if err := rows.Scan(&wire, &version, &id); err != nil {
			return nil, publicError(ctx, err, oauth.ErrAccessDenied)
		}
		c, err := decodeRegistration(wire)
		v, parseErr := strconv.ParseUint(version, 10, 64)
		if err != nil || parseErr != nil || c.Version != v || c.ID != id || !s.managedMetadata(c) || len(items) >= 101 {
			return nil, oauth.ErrUnavailable
		}
		items = append(items, c)
	}
	if err := rows.Err(); err != nil {
		return nil, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	return items, nil
}

func (s *Store) clientRead(ctx context.Context, e oauth.ClientReadExecution, list bool) ([]oauth.Client, oauth.Cursor, error) {
	user, err := s.clientReadObservation(ctx, e, list)
	if err != nil {
		return nil, oauth.Cursor{}, err
	}
	after, err := s.clientReadCursor(e, user)
	if err != nil {
		return nil, oauth.Cursor{}, err
	}
	items, err := s.readClientMetadata(ctx, e, list, after)
	if err != nil {
		return nil, oauth.Cursor{}, err
	}
	if _, err := s.clientReadObservation(ctx, e, list); err != nil {
		return nil, oauth.Cursor{}, err
	}
	current, err := s.readClientMetadata(ctx, e, list, after)
	if err != nil {
		return nil, oauth.Cursor{}, err
	}
	if !sameJSON(items, current) {
		return nil, oauth.Cursor{}, oauth.ErrAccessDenied
	}
	if _, err := s.clientReadObservation(ctx, e, list); err != nil {
		return nil, oauth.Cursor{}, err
	}
	// The final external policy callback may itself take time or cause a client
	// authority change. Fence registration/version again after it, without
	// holding a client lock over application-owned authorization.
	current, err = s.readClientMetadata(ctx, e, list, after)
	if err != nil {
		return nil, oauth.Cursor{}, err
	}
	if !sameJSON(items, current) {
		return nil, oauth.Cursor{}, oauth.ErrAccessDenied
	}
	now, err := s.introspectionTime(ctx)
	if err != nil {
		return nil, oauth.Cursor{}, err
	}
	if ctx.Err() != nil {
		return nil, oauth.Cursor{}, ctx.Err()
	}
	if e.ValidateAt(now) != nil || e.ValidateAt(s.now()) != nil || !list && len(items) != 1 {
		return nil, oauth.Cursor{}, oauth.ErrAccessDenied
	}
	var next oauth.Cursor
	if list && len(items) > int(e.Request.Limit) {
		items = items[:e.Request.Limit]
		next, err = oauth.ParseCursor(s.encodeClientReadCursor(items[len(items)-1].ID, e, user))
		if err != nil {
			return nil, oauth.Cursor{}, oauth.ErrUnavailable
		}
	}
	return items, next, nil
}

// ClientGet authenticates an actual current native human session and exact
// platform policy for one active safe registration. It has no mutation effects.
func (s *Store) ClientGet(ctx context.Context, e oauth.ClientReadExecution) (out oauth.ClientGetResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.ClientGetResult{}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	items, _, err := s.clientRead(ctx, e, false)
	if err != nil {
		return out, err
	}
	return oauth.ClientGetResult{Client: items[0]}, nil
}

// ClientList authenticates each bounded native page afresh. Scoped cursors are
// not authorization, and failures never disclose a partial page or continuation.
func (s *Store) ClientList(ctx context.Context, e oauth.ClientReadExecution) (out oauth.ClientListResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.ClientListResult{}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	items, next, err := s.clientRead(ctx, e, true)
	if err != nil {
		return out, err
	}
	page, err := oauth.NewClientListPage(items)
	if err != nil {
		return out, oauth.ErrUnavailable
	}
	return oauth.ClientListResult{Page: page, NextCursor: next}, nil
}
