package oauthpostgres

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

// The original observation is provenance, not a renewable lease or credential
// expiry. A later genuine primary read gets a separate invocation observation.
// RFC8693 leaves token policy to profiles; shared-issuer-v1 owns these bounds.
type exchangeLineage struct {
	// Artifact metadata revisions are durable and immutable. GrantVersion is
	// separate: a grant state/version transition may never masquerade as the
	// unchanged token metadata revision (shared-issuer-v1 root/parent binding).
	GrantID                                              string
	GrantVersion                                         uint64
	RootID, ParentID                                     string
	RootVersion, ParentVersion                           uint64
	Depth                                                uint8
	Issuer, Environment, PlatformOwner, WorkloadID       string
	TenantID                                             identity.TenantID
	ClientID                                             string
	ClientVersion, ClientAuthorizationVersion            uint64
	Resource                                             string
	RootScopes                                           []string
	RootExpiresAt, SourceReadStartedAt, SourceValidUntil time.Time
}

type exchangeObservation struct{ ReadStartedAt, ValidUntil time.Time }

func exchangeClientScope(g grantRecord) authority.AuthorityScope {
	return authority.AuthorityScope{TenantID: authorization.TenantID(g.Tenant), PolicyNamespace: g.Workload.ClientPolicyNamespace, SubjectID: authorization.SubjectID(g.ClientID)}
}

func (s *Store) validExchangeClientSource(g grantRecord, c oauth.Client) bool {
	if g.Workload == nil {
		return false
	}
	w := g.Workload
	if s.config.Protocol.WorkloadExchange == nil {
		return w.ClientPolicyNamespace == "" && w.ClientAuthorizationVersion == 0
	}
	return w.ClientPolicyNamespace == s.config.WorkloadExchangeClientNamespace && w.ClientAuthorizationVersion == c.Version && w.ClientAuthorizationVersion > 0
}

func (s *Store) validExchangeLineage(e *exchangeLineage, g grantRecord) bool {
	if e == nil || s.config.Protocol.WorkloadExchange == nil || g.Workload == nil {
		return false
	}
	_, rootErr := identity.ParseSubjectID(e.RootID)
	_, parentErr := identity.ParseSubjectID(e.ParentID)
	return rootErr == nil && parentErr == nil && e.GrantID == g.ID && e.GrantVersion == g.Version && e.RootVersion == 1 && e.ParentVersion == 1 && e.Depth > 0 && e.Depth <= s.config.Protocol.WorkloadExchange.MaximumDepth && e.Issuer == s.config.Protocol.Issuer.String() && e.Environment == s.config.Protocol.Environment && e.PlatformOwner == g.Workload.Platform && e.WorkloadID == g.Workload.ID && e.TenantID == g.Tenant && e.ClientID == g.ClientID && e.ClientVersion == g.ClientVersion && e.ClientAuthorizationVersion == g.Workload.ClientAuthorizationVersion && e.Resource == g.Resource && slices.Equal(e.RootScopes, g.Scopes) && !e.RootExpiresAt.After(g.ExpiresAt) && !e.SourceReadStartedAt.IsZero() && !e.SourceReadStartedAt.Before(g.CreatedAt) && e.SourceValidUntil.After(e.SourceReadStartedAt) && !e.SourceValidUntil.After(e.SourceReadStartedAt.Add(20*time.Second)) && !e.SourceValidUntil.After(e.RootExpiresAt)
}

func sameExchangeOrigin(a, b *exchangeLineage) bool {
	if a == nil || b == nil {
		return false
	}
	x, y := *a, *b
	x.ParentID, y.ParentID = "", ""
	x.Depth, y.Depth = 0, 0
	return sameJSON(x, y)
}

type exchangeRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}
type exchangeQuery func(context.Context, string, ...any) (exchangeRows, error)

// Bounded by the selected maximum, never recursive SQL or unbounded traversal.
// Work callers already hold the grant lock, then retain ancestor SHARE locks;
// revocation takes that same grant first, so exchange and withdrawal serialize.
func (s *Store) exchangeLineageCurrent(ctx context.Context, a artifactRecord, now time.Time, query exchangeQuery, locked bool) error {
	if s.config.Protocol.WorkloadExchange == nil || !s.validWorkload(a.Grant, s.clientForExchange(a.Grant.ClientID)) {
		return oauth.ErrInvalidGrant
	}
	depth := uint8(0)
	origin := a.Payload.Exchange
	if origin != nil {
		if !s.validExchangeLineage(origin, a.Grant) {
			return oauth.ErrInvalidGrant
		}
		depth = origin.Depth
	}
	seen := make(map[string]bool, 5)
	current := a.ID
	var descendantScopes []string
	var descendantExpiry time.Time
	for step := 0; step <= int(s.config.Protocol.WorkloadExchange.MaximumDepth); step++ {
		if seen[current] {
			return oauth.ErrInvalidGrant
		}
		seen[current] = true
		statement := `SELECT artifact_id,COALESCE(parent_artifact_id,''),kind,state,payload,created_at,expires_at,workload_exchange,metadata_version FROM ` + s.schema + `.artifacts WHERE artifact_id=$1 AND grant_id=$2 AND client_id=$3`
		if locked {
			statement += ` FOR SHARE`
		}
		rows, err := query(ctx, statement, current, a.Grant.ID, a.Grant.ClientID)
		if err != nil {
			return err
		}
		var id, parent, state string
		var kind int16
		var payload []byte
		var created, expires time.Time
		var derived bool
		var metadataVersion uint64
		if !rows.Next() {
			rowErr := rows.Err()
			rows.Close()
			if rowErr != nil {
				return rowErr
			}
			return oauth.ErrInvalidGrant
		}
		err = rows.Scan(&id, &parent, &kind, &state, &payload, &created, &expires, &derived, &metadataVersion)
		extra := rows.Next()
		rowErr := rows.Err()
		rows.Close()
		if err != nil || rowErr != nil || extra {
			return oauth.ErrUnavailable
		}
		var p artifactPayload
		if decodeJSON(payload, &p) != nil || p.Schema != 1 || id != current || metadataVersion != 1 || kind != int16(oauth.TokenAccess) || state != "active" || now.Before(created) || !now.Before(expires) || expires.After(a.Grant.ExpiresAt) || !scopeSubset(p.Scopes, a.Grant.Scopes) || descendantScopes != nil && !scopeSubset(descendantScopes, p.Scopes) || !descendantExpiry.IsZero() && descendantExpiry.After(expires) {
			return oauth.ErrInvalidGrant
		}
		canonical, err := selectedScopes(p.Scopes)
		if err != nil || !slices.Equal(canonical, p.Scopes) {
			return oauth.ErrInvalidGrant
		}
		if step == 0 && (!sameJSON(p, a.Payload) || !expires.Equal(a.ExpiresAt)) {
			return oauth.ErrInvalidGrant
		}
		if depth == 0 {
			if derived || parent != "" || p.Exchange != nil || origin != nil && (id != origin.RootID || !expires.Equal(origin.RootExpiresAt) || !slices.Equal(p.Scopes, origin.RootScopes)) {
				return oauth.ErrInvalidGrant
			}
			return nil
		}
		if !derived || p.Exchange == nil || !s.validExchangeLineage(p.Exchange, a.Grant) || p.Exchange.Depth != depth || p.Exchange.ParentID != parent || !sameExchangeOrigin(p.Exchange, origin) || created.Before(p.Exchange.SourceReadStartedAt) || parent == "" {
			return oauth.ErrInvalidGrant
		}
		descendantScopes, descendantExpiry = p.Scopes, expires
		current = parent
		depth--
	}
	return oauth.ErrInvalidGrant
}

func (s *Store) clientForExchange(id string) oauth.Client {
	for _, c := range s.config.Protocol.Clients {
		if c.ID == id {
			return c
		}
	}
	return oauth.Client{}
}

func (s *Store) readExchangeLineage(ctx context.Context, a artifactRecord, now time.Time) error {
	return s.exchangeLineageCurrent(ctx, a, now, func(ctx context.Context, sql string, args ...any) (exchangeRows, error) {
		return s.pool.Raw().Query(ctx, sql, args...)
	}, false)
}

func (p *phase) checkExchangeLineage(ctx context.Context, w kernel.Work, now time.Time) error {
	if p.input.Transition != exchangeWorkload {
		return nil
	}
	i := p.input
	if !p.store.validExchangeLineage(i.Exchange, i.Grant) || i.Exchange.ParentID != i.TargetID || i.Exchange.ParentVersion != i.TargetMetadataVersion || i.ExchangeObservation == nil {
		return identity.ForbiddenError{}
	}
	source := artifactRecord{ID: i.TargetID, Payload: i.TargetPayload, Grant: i.Grant, ExpiresAt: i.TargetExpires}
	if err := p.store.exchangeLineageCurrent(ctx, source, now, func(ctx context.Context, sql string, args ...any) (exchangeRows, error) {
		return w.Query(ctx, sql, args...)
	}, true); err != nil {
		return err
	}
	wantDepth := uint8(1)
	if i.TargetPayload.Exchange != nil {
		wantDepth = i.TargetPayload.Exchange.Depth + 1
		if !sameExchangeOrigin(i.Exchange, i.TargetPayload.Exchange) {
			return identity.ForbiddenError{}
		}
	} else if i.Exchange.RootID != i.TargetID || !i.Exchange.RootExpiresAt.Equal(i.TargetExpires) {
		return identity.ForbiddenError{}
	}
	if i.Exchange.Depth != wantDepth || !scopeSubset(i.Scopes, i.TargetPayload.Scopes) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (s *Store) exchangeWorkload(ctx context.Context, client oauth.Client, r oauth.TokenRequest, proof *clientAuthenticationSnapshot) (oauth.TokenResult, *phase, error) {
	fail := func(err error) (oauth.TokenResult, *phase, error) { return oauth.TokenResult{}, nil, err }
	if s.config.Protocol.WorkloadExchange == nil {
		return fail(oauth.ErrUnsupportedGrant)
	}
	if client.Workload == nil || client.Public || r.Code != "" || r.CodeVerifier != "" || r.RedirectURI != "" || r.RefreshToken != "" || r.SubjectTokenType != oauth.AccessTokenType || r.RequestedTokenType != "" && r.RequestedTokenType != oauth.AccessTokenType || (r.Resource == "") == (r.Audience == "") || r.Resource != client.Resource && r.Audience != client.Resource {
		return fail(oauth.ErrInvalidRequest)
	}
	command := r.CommandID
	if command == "" {
		var err error
		command, err = identity.NewCommandID()
		if err != nil {
			return fail(oauth.ErrUnavailable)
		}
	} else if _, err := identity.ParseCommandID(string(command)); err != nil {
		return fail(oauth.ErrInvalidRequest)
	}
	start := s.now()
	a, err := s.lookup(ctx, r.SubjectToken, client, []oauth.TokenKind{oauth.TokenAccess})
	if err != nil {
		return fail(publicError(ctx, err, oauth.ErrInvalidGrant))
	}
	now, err := s.introspectionTime(ctx)
	if err != nil {
		return fail(err)
	}
	if !activeIntrospectionArtifact(a, now) {
		return fail(oauth.ErrInvalidGrant)
	}
	if _, err := s.workloadIntrospectionAuthority(ctx, a.Grant, client); err != nil {
		return fail(publicError(ctx, err, oauth.ErrInvalidGrant))
	}
	if err := s.readExchangeLineage(ctx, a, now); err != nil {
		return fail(publicError(ctx, err, oauth.ErrInvalidGrant))
	}
	selected := r.Scopes
	if selected == nil {
		selected = slices.Clone(a.Payload.Scopes)
	}
	if !scopeSubset(selected, a.Payload.Scopes) || !scopeSubset(selected, client.Scopes) {
		return fail(oauth.ErrInvalidScope)
	}
	e := &exchangeLineage{GrantID: a.Grant.ID, GrantVersion: a.Grant.Version, RootID: a.ID, RootVersion: a.MetadataVersion, ParentID: a.ID, ParentVersion: a.MetadataVersion, Depth: 1, Issuer: s.config.Protocol.Issuer.String(), Environment: s.config.Protocol.Environment, PlatformOwner: a.Grant.Workload.Platform, WorkloadID: a.Grant.Workload.ID, TenantID: a.Grant.Tenant, ClientID: client.ID, ClientVersion: client.Version, ClientAuthorizationVersion: a.Grant.Workload.ClientAuthorizationVersion, Resource: a.Grant.Resource, RootScopes: slices.Clone(a.Grant.Scopes), RootExpiresAt: a.ExpiresAt, SourceReadStartedAt: start, SourceValidUntil: minTime(start.Add(20*time.Second), a.ExpiresAt)}
	if a.Payload.Exchange != nil {
		owned := *a.Payload.Exchange
		e = &owned
		e.ParentID = a.ID
		e.ParentVersion = a.MetadataVersion
		e.Depth++
		e.RootScopes = slices.Clone(e.RootScopes)
	}
	if !s.validExchangeLineage(e, a.Grant) {
		return fail(oauth.ErrInvalidGrant)
	}
	observation := &exchangeObservation{ReadStartedAt: start, ValidUntil: minTime(start.Add(20*time.Second), a.ExpiresAt)}
	if finished := s.now(); finished.Before(start) || !finished.Before(observation.ValidUntil) {
		return fail(oauth.ErrUnavailable)
	}
	// An access token is reusable (RFC8693 section2.1). Only the explicit
	// trusted command selects a retry; bearer ownership is not a retry key.
	p := s.targetPhase(a, client, exchangeWorkload, "identity.oauth-server.token", command, s.intent("token_exchange", a.ID, r.Resource, r.Audience, r.SubjectTokenType, r.RequestedTokenType, strings.Join(selected, " ")), r.Network)
	p.input.Scopes = selected
	p.input.Exchange = e
	p.input.ExchangeObservation = observation
	p.input.ClientAuthentication = proof
	result, err := p.execute(ctx)
	out := oauth.TokenResult{Outcome: result.Outcome, CommandID: command, Replayed: !p.applied}
	if err != nil {
		return out, p, publicError(ctx, err, oauth.ErrInvalidGrant)
	}
	if result.Outcome == identity.CommitOutcomeCommitted && p.applied {
		out.AccessToken = p.generatedToken(oauth.TokenAccess)
		out.ExpiresAt = p.generatedExpiry(oauth.TokenAccess)
		out.Resource = client.Resource
		out.Scopes = selected
		out.IssuedTokenType = oauth.AccessTokenType
	}
	return out, p, nil
}
