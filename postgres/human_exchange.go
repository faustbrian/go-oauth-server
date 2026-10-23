package oauthpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

// This is delegation ancestry, not authorization-code/continuation ancestry.
// The first access token keeps its actual consumed-code parent unchanged.
type humanExchangeLineage struct {
	GrantID string
	// Historical grant revision is provenance. Refresh legitimately advances it;
	// active grant state and immutable artifact revisions are fenced separately.
	GrantVersion                                         uint64
	RootID, ParentID                                     string
	RootVersion, ParentVersion                           uint64
	Depth                                                uint8
	Issuer, Environment, PlatformOwner                   string
	HumanOwner                                           identity.UserID
	HumanActor                                           identity.ActorID
	TenantID                                             identity.TenantID
	ClientID                                             string
	ClientVersion                                        uint64
	SourceFingerprint                                    [32]byte
	ConsentID                                            string
	ConsentGeneration                                    uint64
	ClientNamespace, ClientAuthoritySubject              string
	ClientAuthorityVersion                               uint64
	AuthorityDerivation                                  uint8
	Policy                                               oauth.HumanCodeExchangePolicy
	RootScopes                                           []string
	RootExpiresAt, SourceReadStartedAt, SourceValidUntil time.Time
}

func humanSourceFingerprint(g grantRecord) [32]byte {
	wire, _ := json.Marshal(g.Source)
	defer clear(wire)
	return sha256.Sum256(wire)
}

func (s *Store) humanExchangeScope(g grantRecord, c oauth.Client) authority.AuthorityScope {
	// The public owner initializes only epoch1 (authorization a55bbebb1060).
	// Scope each registration independently instead of equating that lifecycle
	// epoch to a possibly higher client version or advancing bootstrap in a loop.
	h := sha256.New()
	_, _ = h.Write([]byte("golib.oauth.human-code-client-authority.v1\x00"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(c.ID)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(c.ID))
	binary.BigEndian.PutUint64(size[:], c.Version)
	_, _ = h.Write(size[:])
	return authority.AuthorityScope{TenantID: authorization.TenantID(g.Tenant), PolicyNamespace: s.config.HumanCodeExchangeClientNamespace, SubjectID: authorization.SubjectID(base64.RawURLEncoding.EncodeToString(h.Sum(nil)))}
}

func (s *Store) humanExchangeSelected(c oauth.Client) bool {
	return s.config.Protocol.HumanCodeExchange != nil && c.HumanCodeExchange && !c.Public && c.Workload == nil && c.AuthenticationMethod == "client_secret_basic" && s.config.ConsentManagement
}

func (s *Store) humanExchangeAuthority(ctx context.Context, g grantRecord, c oauth.Client) error {
	if !s.humanExchangeSelected(c) || g.Workload != nil || g.User == "" || g.ClientID != c.ID || g.ClientVersion != c.Version {
		return oauth.ErrInvalidGrant
	}
	current, err := s.policy.Get(ctx, s.humanExchangeScope(g, c))
	if err != nil {
		return err
	}
	// An advanced epoch is withdrawal, never a new positive authority to adopt.
	if current.Version != 1 {
		return oauth.ErrInvalidGrant
	}
	return nil
}

func (s *Store) validHumanExchangeLineage(e *humanExchangeLineage, g grantRecord, c oauth.Client) bool {
	if e == nil || !s.humanExchangeSelected(c) || g.Workload != nil || g.User == "" {
		return false
	}
	_, rootErr := identity.ParseSubjectID(e.RootID)
	_, parentErr := identity.ParseSubjectID(e.ParentID)
	scope := s.humanExchangeScope(g, c)
	return rootErr == nil && parentErr == nil && e.GrantID == g.ID && e.GrantVersion > 0 && e.GrantVersion <= g.Version && e.RootVersion == 1 && e.ParentVersion == 1 && e.Depth > 0 && e.Depth <= s.config.Protocol.HumanCodeExchange.MaximumDepth && e.Issuer == s.config.Protocol.Issuer.String() && e.Environment == s.config.Protocol.Environment && e.PlatformOwner == c.Owner.PlatformID() && e.HumanOwner == g.User && e.HumanActor == identity.ActorID(g.User) && e.TenantID == g.Tenant && e.ClientID == c.ID && e.ClientVersion == c.Version && e.SourceFingerprint == humanSourceFingerprint(g) && e.ConsentID == g.ConsentID && e.ConsentID != "" && e.ConsentGeneration == g.ConsentGeneration && e.ConsentGeneration > 0 && e.ClientNamespace == scope.PolicyNamespace && e.ClientAuthoritySubject == string(scope.SubjectID) && e.AuthorityDerivation == 1 && e.ClientAuthorityVersion == 1 && e.Policy == *s.config.Protocol.HumanCodeExchange && scopeSubset(e.RootScopes, g.Scopes) && !e.RootExpiresAt.After(g.ExpiresAt) && !e.SourceReadStartedAt.IsZero() && !e.SourceReadStartedAt.Before(g.CreatedAt) && e.SourceValidUntil.After(e.SourceReadStartedAt) && !e.SourceValidUntil.After(e.SourceReadStartedAt.Add(20*time.Second)) && !e.SourceValidUntil.After(e.RootExpiresAt)
}

func sameHumanExchangeOrigin(a, b *humanExchangeLineage) bool {
	if a == nil || b == nil {
		return false
	}
	x, y := *a, *b
	x.ParentID, y.ParentID = "", ""
	x.Depth, y.Depth = 0, 0
	return sameJSON(x, y)
}

func (s *Store) humanExchangeLineageCurrent(ctx context.Context, a artifactRecord, c oauth.Client, now time.Time, query exchangeQuery, locked bool) error {
	if !s.humanExchangeSelected(c) || a.Grant.Workload != nil || a.Kind != oauth.TokenAccess {
		return oauth.ErrInvalidGrant
	}
	origin := a.Payload.HumanExchange
	depth := uint8(0)
	if origin != nil {
		if !s.validHumanExchangeLineage(origin, a.Grant, c) {
			return oauth.ErrInvalidGrant
		}
		depth = origin.Depth
	}
	current := a.ID
	seen := make(map[string]bool, 5)
	var descendantScopes []string
	var descendantExpiry time.Time
	for step := 0; step <= int(s.config.Protocol.HumanCodeExchange.MaximumDepth); step++ {
		if seen[current] {
			return oauth.ErrInvalidGrant
		}
		seen[current] = true
		statement := `SELECT artifact_id,COALESCE(parent_artifact_id,''),kind,state,payload,created_at,expires_at,human_code_exchange,metadata_version FROM ` + s.schema + `.artifacts WHERE artifact_id=$1 AND grant_id=$2 AND client_id=$3`
		if locked {
			statement += ` FOR SHARE`
		}
		rows, err := query(ctx, statement, current, a.Grant.ID, c.ID)
		if err != nil {
			return err
		}
		var id, parent, state string
		var kind int16
		var raw []byte
		var created, expires time.Time
		var derived bool
		var version uint64
		if !rows.Next() {
			err := rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			return oauth.ErrInvalidGrant
		}
		err = rows.Scan(&id, &parent, &kind, &state, &raw, &created, &expires, &derived, &version)
		extra, rowErr := rows.Next(), rows.Err()
		rows.Close()
		if err != nil || extra || rowErr != nil {
			return oauth.ErrUnavailable
		}
		var p artifactPayload
		if decodeJSON(raw, &p) != nil || p.Schema != 1 || p.Exchange != nil || id != current || version != 1 || kind != int16(oauth.TokenAccess) || state != "active" || now.Before(created) || !now.Before(expires) || expires.After(a.Grant.ExpiresAt) || !scopeSubset(p.Scopes, a.Grant.Scopes) || descendantScopes != nil && !scopeSubset(descendantScopes, p.Scopes) || !descendantExpiry.IsZero() && descendantExpiry.After(expires) {
			return oauth.ErrInvalidGrant
		}
		canonical, err := selectedScopes(p.Scopes)
		if err != nil || !slices.Equal(canonical, p.Scopes) || step == 0 && (!sameJSON(p, a.Payload) || !expires.Equal(a.ExpiresAt)) {
			return oauth.ErrInvalidGrant
		}
		if depth == 0 {
			if derived || p.HumanExchange != nil || parent == "" || origin != nil && (id != origin.RootID || !expires.Equal(origin.RootExpiresAt) || !slices.Equal(p.Scopes, origin.RootScopes)) {
				return oauth.ErrInvalidGrant
			}
			// The consumed code is issuance proof, not an active delegation
			// ancestor. Its original expiry must not truncate access validity.
			statement := `SELECT code.payload FROM ` + s.schema + `.artifacts code JOIN ` + s.schema + `.artifacts access ON access.parent_artifact_id=code.artifact_id AND access.grant_id=code.grant_id JOIN ` + s.schema + `.effects issued ON issued.command_id=access.issued_by AND issued.grant_id=access.grant_id AND issued.tenant_id=$4 WHERE access.artifact_id=$1 AND access.grant_id=$2 AND access.client_id=$3 AND code.kind=2 AND code.state='consumed' AND code.consumed_by=access.issued_by AND code.client_id=access.client_id AND issued.operation_id='identity.oauth-server.token'`
			if locked {
				statement += ` FOR SHARE OF code`
			}
			rows, err := query(ctx, statement, id, a.Grant.ID, c.ID, string(a.Grant.Tenant))
			if err != nil {
				return err
			}
			if !rows.Next() {
				err := rows.Err()
				rows.Close()
				if err != nil {
					return err
				}
				return oauth.ErrInvalidGrant
			}
			var codeRaw []byte
			err = rows.Scan(&codeRaw)
			extra, rowErr := rows.Next(), rows.Err()
			rows.Close()
			var code artifactPayload
			if err != nil || extra || rowErr != nil {
				return oauth.ErrUnavailable
			}
			if decodeJSON(codeRaw, &code) != nil || code.Schema != 1 || code.Exchange != nil || code.HumanExchange != nil || !sameJSON(code.Request, p.Request) || !scopeSubset(p.Scopes, code.Scopes) || p.Request.ClientID != c.ID || p.Request.Resource != c.Resource || p.Request.CodeChallenge == "" {
				return oauth.ErrInvalidGrant
			}
			return nil
		}
		if !derived || !s.validHumanExchangeLineage(p.HumanExchange, a.Grant, c) || p.HumanExchange.Depth != depth || p.HumanExchange.ParentID != parent || !sameHumanExchangeOrigin(p.HumanExchange, origin) || created.Before(p.HumanExchange.SourceReadStartedAt) || parent == "" {
			return oauth.ErrInvalidGrant
		}
		descendantScopes, descendantExpiry = p.Scopes, expires
		current, depth = parent, depth-1
	}
	return oauth.ErrInvalidGrant
}

func (s *Store) readHumanExchangeLineage(ctx context.Context, a artifactRecord, c oauth.Client, now time.Time) error {
	return s.humanExchangeLineageCurrent(ctx, a, c, now, func(ctx context.Context, statement string, args ...any) (exchangeRows, error) {
		return s.pool.Raw().Query(ctx, statement, args...)
	}, false)
}

func (s *Store) humanDelegationAuthority(ctx context.Context, a artifactRecord, c oauth.Client, now time.Time) error {
	if a.Payload.HumanExchange == nil {
		return nil
	}
	if !s.validHumanExchangeLineage(a.Payload.HumanExchange, a.Grant, c) {
		return oauth.ErrInvalidGrant
	}
	if err := s.humanExchangeAuthority(ctx, a.Grant, c); err != nil {
		return err
	}
	return s.readHumanExchangeLineage(ctx, a, c, now)
}

func (p *phase) checkHumanExchange(ctx context.Context, w kernel.Work, now time.Time) error {
	if p.input.Transition != exchangeHumanCode {
		return nil
	}
	i := p.input
	if !p.store.validHumanExchangeLineage(i.HumanExchange, i.Grant, p.client) || i.ExchangeObservation == nil || i.HumanExchange.ParentID != i.TargetID || i.HumanExchange.ParentVersion != i.TargetMetadataVersion {
		return identity.ForbiddenError{}
	}
	if err := authority.RequireAuthority(ctx, w, p.store.humanExchangeScope(i.Grant, p.client), i.HumanExchange.ClientAuthorityVersion, p.store.config.Protocol.MaximumDuration); err != nil {
		return workloadError(ctx, err)
	}
	source := artifactRecord{ID: i.TargetID, Kind: i.TargetKind, Grant: i.Grant, Payload: i.TargetPayload, ExpiresAt: i.TargetExpires}
	if err := p.store.humanExchangeLineageCurrent(ctx, source, p.client, now, func(ctx context.Context, statement string, args ...any) (exchangeRows, error) {
		return w.Query(ctx, statement, args...)
	}, true); err != nil {
		return err
	}
	depth := uint8(1)
	if i.TargetPayload.HumanExchange != nil {
		depth = i.TargetPayload.HumanExchange.Depth + 1
		if !sameHumanExchangeOrigin(i.HumanExchange, i.TargetPayload.HumanExchange) {
			return identity.ForbiddenError{}
		}
	} else if i.HumanExchange.RootID != i.TargetID || !i.HumanExchange.RootExpiresAt.Equal(i.TargetExpires) || !slices.Equal(i.HumanExchange.RootScopes, i.TargetPayload.Scopes) {
		return identity.ForbiddenError{}
	}
	if i.HumanExchange.Depth != depth || !scopeSubset(i.Scopes, i.TargetPayload.Scopes) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (s *Store) exchangeHumanCode(ctx context.Context, c oauth.Client, r oauth.TokenRequest, proof *clientAuthenticationSnapshot) (oauth.TokenResult, *phase, error) {
	fail := func(err error) (oauth.TokenResult, *phase, error) { return oauth.TokenResult{}, nil, err }
	if !s.humanExchangeSelected(c) {
		return fail(oauth.ErrUnsupportedGrant)
	}
	if c.Workload != nil || c.Public || r.Code != "" || r.CodeVerifier != "" || r.RedirectURI != "" || r.RefreshToken != "" || r.SubjectTokenType != oauth.AccessTokenType || r.RequestedTokenType != "" && r.RequestedTokenType != oauth.AccessTokenType || (r.Resource == "") == (r.Audience == "") || r.Resource != c.Resource && r.Audience != c.Resource {
		return fail(oauth.ErrInvalidRequest)
	}
	command := r.CommandID
	var err error
	if command == "" {
		command, err = identity.NewCommandID()
	} else {
		_, err = identity.ParseCommandID(string(command))
	}
	if err != nil {
		return fail(oauth.ErrInvalidRequest)
	}
	start := s.now()
	a, err := s.lookup(ctx, r.SubjectToken, c, []oauth.TokenKind{oauth.TokenAccess})
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
	credentialExpiry, err := s.introspectionAuthority(ctx, a.Grant, now)
	if err != nil {
		return fail(publicError(ctx, err, oauth.ErrInvalidGrant))
	}
	if err = s.humanExchangeAuthority(ctx, a.Grant, c); err != nil {
		return fail(publicError(ctx, err, oauth.ErrInvalidGrant))
	}
	if err = s.readHumanExchangeLineage(ctx, a, c, now); err != nil {
		return fail(publicError(ctx, err, oauth.ErrInvalidGrant))
	}
	selected := r.Scopes
	if selected == nil {
		selected = slices.Clone(a.Payload.Scopes)
	}
	if !scopeSubset(selected, a.Payload.Scopes) || !scopeSubset(selected, c.Scopes) {
		return fail(oauth.ErrInvalidScope)
	}
	for _, scope := range selected {
		if !s.config.Protocol.Scopes.Contains(scope) {
			return fail(oauth.ErrInvalidScope)
		}
	}
	until := minTime(start.Add(20*time.Second), a.ExpiresAt)
	if !credentialExpiry.IsZero() {
		until = minTime(until, credentialExpiry)
	}
	scope := s.humanExchangeScope(a.Grant, c)
	e := &humanExchangeLineage{GrantID: a.Grant.ID, GrantVersion: a.Grant.Version, RootID: a.ID, ParentID: a.ID, RootVersion: a.MetadataVersion, ParentVersion: a.MetadataVersion, Depth: 1, Issuer: s.config.Protocol.Issuer.String(), Environment: s.config.Protocol.Environment, PlatformOwner: c.Owner.PlatformID(), HumanOwner: a.Grant.User, HumanActor: identity.ActorID(a.Grant.User), TenantID: a.Grant.Tenant, ClientID: c.ID, ClientVersion: c.Version, SourceFingerprint: humanSourceFingerprint(a.Grant), ConsentID: a.Grant.ConsentID, ConsentGeneration: a.Grant.ConsentGeneration, ClientNamespace: scope.PolicyNamespace, ClientAuthoritySubject: string(scope.SubjectID), ClientAuthorityVersion: 1, AuthorityDerivation: 1, Policy: *s.config.Protocol.HumanCodeExchange, RootScopes: slices.Clone(a.Payload.Scopes), RootExpiresAt: a.ExpiresAt, SourceReadStartedAt: start, SourceValidUntil: until}
	if a.Payload.HumanExchange != nil {
		owned := *a.Payload.HumanExchange
		e = &owned
		e.ParentID = a.ID
		e.ParentVersion = a.MetadataVersion
		e.Depth++
		e.RootScopes = slices.Clone(e.RootScopes)
	}
	if !s.validHumanExchangeLineage(e, a.Grant, c) {
		return fail(oauth.ErrInvalidGrant)
	}
	if finished := s.now(); finished.Before(start) || !finished.Before(until) {
		return fail(oauth.ErrUnavailable)
	}
	p := s.targetPhase(a, c, exchangeHumanCode, "identity.oauth-server.token", command, s.intent("human_code_token_exchange", a.ID, r.Resource, r.Audience, r.SubjectTokenType, r.RequestedTokenType, strings.Join(selected, " ")), r.Network)
	p.input.Scopes = selected
	p.input.HumanExchange = e
	p.input.ExchangeObservation = &exchangeObservation{ReadStartedAt: start, ValidUntil: until}
	p.input.ClientAuthentication = proof
	result, err := p.execute(ctx)
	out := oauth.TokenResult{Outcome: result.Outcome, CommandID: command, Replayed: !p.applied}
	if err != nil {
		return out, p, publicError(ctx, err, oauth.ErrInvalidGrant)
	}
	if result.Outcome == identity.CommitOutcomeCommitted && p.applied {
		out.AccessToken = p.generatedToken(oauth.TokenAccess)
		out.ExpiresAt = p.generatedExpiry(oauth.TokenAccess)
		out.Resource = c.Resource
		out.Scopes = selected
		out.IssuedTokenType = oauth.AccessTokenType
	}
	return out, p, nil
}

// BootstrapHumanCodeExchangeClient explicitly initializes the selected native
// per-registration client authority from an actual code-issued access source
// and its owning Basic client. It accepts no asserted tenant/version/epoch.
// This is trusted installation/bootstrap, never an HTTP endpoint or an implicit
// issuance/read side effect. Install the forward history first. Repeating an
// existing epoch1 is idempotent; any advanced epoch denies and is never repaired.
// A commit acknowledgement failure returns Unavailable; retry re-observes the
// sole public authority row. No token, journal, source grant or permission is
// created or changed. Pool/key lifetimes remain borrowed and concurrent use safe.
func (s *Store) BootstrapHumanCodeExchangeClient(ctx context.Context, r oauth.IntrospectRequest) error {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return err
	}
	defer stop()
	c, a, proof, err := s.humanClientAuthoritySource(ctx, r)
	if err != nil {
		return err
	}
	scope := s.humanExchangeScope(a.Grant, c)
	current, err := s.policy.Get(ctx, scope)
	if err == nil {
		if current.Version != 1 {
			return oauth.ErrAccessDenied
		}
		return s.finishClientAuthentication(ctx, c, proof)
	}
	if !errors.Is(err, authority.ErrAuthorityDenied) {
		return publicError(ctx, err, oauth.ErrInvalidGrant)
	}
	tx, err := s.pool.Raw().Begin(ctx)
	if err != nil {
		return oauth.ErrUnavailable
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), s.config.Protocol.MaximumDuration)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	_, err = authority.InitializeAuthority(ctx, tx, scope, s.config.Protocol.MaximumDuration)
	if errors.Is(err, authority.ErrAuthorityConflict) {
		if rollback := tx.Rollback(ctx); rollback != nil {
			return oauth.ErrUnavailable
		}
		if err := s.humanExchangeAuthority(ctx, a.Grant, c); err != nil {
			return publicError(ctx, err, oauth.ErrAccessDenied)
		}
		return s.finishClientAuthentication(ctx, c, proof)
	}
	if err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if err = s.finishClientAuthentication(ctx, c, proof); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return oauth.ErrUnavailable
	}
	return s.humanExchangeAuthority(ctx, a.Grant, c)
}

// HumanCodeExchangeClientAuthority locates the real current public authority
// record for the selected source's actual tenant and registered client version.
// Owning Basic and a genuine active code-issued source are required. It accepts
// no subject hash, asserted version or tenant; consumers never copy the private
// derivation. An advanced epoch remains readable, not reset or authorized anew.
// Use the returned Scope/Version with authorization/postgres.AdvanceAuthority in
// the existing authorized owner's transaction and audit workflow to withdraw
// this registration's delegation. This projection grants no mutation permission
// or freshness lease, initializes nothing and reveals no bearer. Missing scopes
// and dependency failures deny with zero metadata. Calls are bounded and safe
// concurrently while the borrowed pool and keys remain alive.
func (s *Store) HumanCodeExchangeClientAuthority(ctx context.Context, r oauth.IntrospectRequest) (authority.AuthorityRecord, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return authority.AuthorityRecord{}, err
	}
	defer stop()
	c, a, proof, err := s.humanClientAuthoritySource(ctx, r)
	if err != nil {
		return authority.AuthorityRecord{}, err
	}
	current, err := s.policy.Get(ctx, s.humanExchangeScope(a.Grant, c))
	if err != nil {
		return authority.AuthorityRecord{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if err := s.finishClientAuthentication(ctx, c, proof); err != nil {
		return authority.AuthorityRecord{}, err
	}
	if err := ctx.Err(); err != nil {
		return authority.AuthorityRecord{}, err
	}
	return current, nil
}

func (s *Store) humanClientAuthoritySource(ctx context.Context, r oauth.IntrospectRequest) (oauth.Client, artifactRecord, *clientAuthenticationSnapshot, error) {
	fail := func(err error) (oauth.Client, artifactRecord, *clientAuthenticationSnapshot, error) {
		return oauth.Client{}, artifactRecord{}, nil, err
	}
	c, err := s.CurrentClient(ctx, r.ClientID)
	if err != nil || !s.humanExchangeSelected(c) {
		return fail(oauth.ErrInvalidClient)
	}
	proof, err := s.authenticateClientSnapshot(ctx, c, r.ClientAuthentication)
	if err != nil {
		return fail(err)
	}
	a, err := s.lookup(ctx, r.Token, c, []oauth.TokenKind{oauth.TokenAccess})
	if err != nil {
		return fail(publicError(ctx, err, oauth.ErrInvalidGrant))
	}
	now, err := s.introspectionTime(ctx)
	if err != nil {
		return fail(err)
	}
	if !activeIntrospectionArtifact(a, now) || a.Payload.HumanExchange != nil {
		return fail(oauth.ErrInvalidGrant)
	}
	if _, err = s.introspectionAuthority(ctx, a.Grant, now); err != nil {
		return fail(publicError(ctx, err, oauth.ErrInvalidGrant))
	}
	if err = s.readHumanExchangeLineage(ctx, a, c, now); err != nil {
		return fail(publicError(ctx, err, oauth.ErrInvalidGrant))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return c, a, proof, nil
}
