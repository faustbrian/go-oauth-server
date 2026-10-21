package oauthpostgres

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/jackc/pgx/v5"
)

var _ oauth.ConsentManager = (*Store)(nil)

type consentDeletion struct {
	ID                  string
	Version, Generation uint64
}
type consentRecord struct {
	ID, ClientID, State                string
	Tenant                             identity.TenantID
	User                               identity.UserID
	Version, ClientVersion, Generation uint64
	Scopes                             []string
	GrantedAt                          time.Time
	RevokedCommand                     identity.CommandID
	Fingerprint                        [32]byte
}

func (s *Store) prepareManagedConsent(ctx context.Context, g grantRecord) (consentMutation, error) {
	var id, version, generation, state string
	err := s.pool.Raw().QueryRow(ctx, `SELECT consent_id,version::text,generation::text,state FROM `+s.schema+`.consents WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3`, string(g.Tenant), string(g.User), g.ClientID).Scan(&id, &version, &generation, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		next, e := identity.NewSubjectID()
		if e != nil {
			return consentMutation{}, oauth.ErrUnavailable
		}
		return consentMutation{ID: string(next), AfterVersion: 1, Created: true, Generation: 1, State: "active"}, nil
	}
	if err != nil {
		return consentMutation{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	v, ve := strconv.ParseUint(version, 10, 64)
	gen, ge := strconv.ParseUint(generation, 10, 64)
	if _, e := identity.ParseSubjectID(id); e != nil || ve != nil || ge != nil || v == 0 || v == math.MaxUint64 || gen == 0 || gen == math.MaxUint64 || state != "active" && state != "revoked" {
		return consentMutation{}, oauth.ErrAccessDenied
	}
	return consentMutation{ID: id, BeforeVersion: v, AfterVersion: v + 1, Generation: gen, State: state}, nil
}

func (s *Store) consentObservation(ctx context.Context, c oauth.ConsentExecution, op oauth.ConsentOperation) (session.GetResult, authorization.DecisionContext, error) {
	if !s.config.ConsentManagement {
		return session.GetResult{}, authorization.DecisionContext{}, oauth.ErrAccessDenied
	}
	input := c.Command.Input()
	if _, err := oauth.NewConsentCommand(input); err != nil || input.Operation != op {
		return session.GetResult{}, authorization.DecisionContext{}, oauth.ErrInvalidRequest
	}
	if c.ValidateAt(s.now()) != nil {
		return session.GetResult{}, authorization.DecisionContext{}, oauth.ErrAccessDenied
	}
	observed, err := s.recoverySession(ctx, RecoveryRequest{TenantID: input.TenantID, Session: input.Session})
	if err != nil {
		return session.GetResult{}, authorization.DecisionContext{}, err
	}
	original, err := sessionpg.OriginalSessionFields(c.Session.Session)
	if err != nil {
		return session.GetResult{}, authorization.DecisionContext{}, oauth.ErrAccessDenied
	}
	current, err := sessionpg.OriginalSessionFields(observed.Session)
	if err != nil || !sameJSON(original, current) {
		return session.GetResult{}, authorization.DecisionContext{}, oauth.ErrAccessDenied
	}
	b, err := observed.Session.Bindings()
	if err != nil || b.TenantID != input.TenantID {
		return session.GetResult{}, authorization.DecisionContext{}, oauth.ErrAccessDenied
	}
	if op == oauth.ConsentRemove || op == oauth.ConsentNarrow {
		if input.Origin != s.config.Protocol.Issuer.String() {
			return session.GetResult{}, authorization.DecisionContext{}, oauth.ErrAccessDenied
		}
		matched := false
		for _, key := range s.config.CSRFKeys {
			if observed.Session.CSRFState().Check(session.CSRFBinding{TenantID: b.TenantID, SessionID: b.SessionID, SessionVersion: b.Version}, input.CSRF, key) == nil {
				matched = true
				break
			}
		}
		if !matched {
			return session.GetResult{}, authorization.DecisionContext{}, oauth.ErrAccessDenied
		}
	}
	// These are the same public session-owner expectations used in issuance;
	// no copied identity SQL, fabricated actor or alternate password proof.
	binding := identity.CommandBinding{TenantID: b.TenantID, UserID: b.UserID, ActorID: identity.ActorID(b.UserID), ActorKind: authorization.SubjectUser}
	if _, _, _, err := sessionpg.OriginalSessionAdmission(s.config.Session.Profile, observed.Session, binding); err != nil {
		return session.GetResult{}, authorization.DecisionContext{}, oauth.ErrAccessDenied
	}
	action := "identity.oauth-server.consent-get"
	if op == oauth.ConsentEnumerate {
		action = "identity.oauth-server.consent-list"
	}
	if op == oauth.ConsentRemove {
		action = "identity.oauth-server.consent-delete"
	}
	if op == oauth.ConsentNarrow {
		action = "identity.oauth-server.consent-update"
	}
	policy := s.config.Coordinator.AdmissionPolicy
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(policy.PolicyVersion), Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.UserID)}, Action: authorization.Action(action), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
	if err := s.consentDecision(ctx, caller); err != nil {
		return session.GetResult{}, caller, err
	}
	return observed, caller, nil
}
func (s *Store) consentDecision(ctx context.Context, caller authorization.DecisionContext) error {
	policy := s.config.Coordinator.AdmissionPolicy
	caller.Request.Environment.Time = policy.Clock.Now().UTC()
	decision, err := policy.Authorization.Decide(ctx, caller)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return oauth.ErrUnavailable
	}
	if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(policy.PolicyVersion) {
		return oauth.ErrAccessDenied
	}
	return nil
}
func (s *Store) finishConsentRead(ctx context.Context, c oauth.ConsentExecution, caller authorization.DecisionContext) error {
	if c.Session.ValidateAt(s.now()) != nil {
		return oauth.ErrAccessDenied
	}
	input := c.Command.Input()
	observed, err := s.recoverySession(ctx, RecoveryRequest{TenantID: input.TenantID, Session: input.Session})
	if err != nil {
		return err
	}
	a, err := sessionpg.OriginalSessionFields(c.Session.Session)
	if err != nil {
		return oauth.ErrAccessDenied
	}
	b, err := sessionpg.OriginalSessionFields(observed.Session)
	if err != nil || !sameJSON(a, b) || c.Session.ValidateAt(s.now()) != nil {
		return oauth.ErrAccessDenied
	}
	return s.consentDecision(ctx, caller)
}

func (s *Store) readConsent(ctx context.Context, tenant identity.TenantID, user identity.UserID, id string) (consentRecord, error) {
	var c consentRecord
	var version, clientVersion, generation string
	var scopes []byte
	var fingerprint []byte
	err := s.pool.Raw().QueryRow(ctx, `SELECT consent_id,client_id,client_version::text,version::text,generation::text,state,scopes,granted_at,COALESCE(revoked_command,''),client_fingerprint FROM `+s.schema+`.consents WHERE tenant_id=$1 AND user_id=$2 AND consent_id=$3`, string(tenant), string(user), id).Scan(&c.ID, &c.ClientID, &clientVersion, &version, &generation, &c.State, &scopes, &c.GrantedAt, &c.RevokedCommand, &fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, oauth.ErrAccessDenied
	}
	if err != nil {
		return c, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if len(fingerprint) != 32 {
		return consentRecord{}, oauth.ErrUnavailable
	}
	copy(c.Fingerprint[:], fingerprint)
	c.Tenant, c.User = tenant, user
	c.Version, err = strconv.ParseUint(version, 10, 64)
	if err != nil {
		return consentRecord{}, oauth.ErrUnavailable
	}
	c.ClientVersion, err = strconv.ParseUint(clientVersion, 10, 64)
	if err != nil {
		return consentRecord{}, oauth.ErrUnavailable
	}
	c.Generation, err = strconv.ParseUint(generation, 10, 64)
	if err != nil || c.Generation == 0 || c.Version == 0 || decodeJSON(scopes, &c.Scopes) != nil {
		return consentRecord{}, oauth.ErrUnavailable
	}
	return c, nil
}
func (s *Store) consentClient(ctx context.Context, c consentRecord) (oauth.Client, error) {
	client, err := s.CurrentClient(ctx, c.ClientID)
	if err != nil {
		return oauth.Client{}, err
	}
	if client.Workload == nil && client.Version == c.ClientVersion && clientFingerprint(client) == c.Fingerprint && scopeSubset(c.Scopes, client.Scopes) && (!s.managedID(client.ID) || c.Tenant == s.config.Protocol.ManagedClients.TenantID) {
		return client, nil
	}
	return oauth.Client{}, oauth.ErrAccessDenied
}
func consentProjection(c consentRecord) (oauth.Consent, error) {
	return oauth.NewConsent(oauth.ConsentSpec{ID: c.ID, Version: c.Version, ClientID: c.ClientID, Scopes: c.Scopes, GrantedAt: c.GrantedAt})
}

// ConsentGet reads only the genuine current session owner's approved row.
// Missing/foreign/revoked targets disclose no metadata; outages never become
// empty successful reads. Original admission cannot be renewed by final reads.
func (s *Store) ConsentGet(ctx context.Context, c oauth.ConsentExecution) (out oauth.ConsentGetResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.ConsentGetResult{}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	observed, caller, err := s.consentObservation(ctx, c, oauth.ConsentRead)
	if err != nil {
		return out, err
	}
	b, _ := observed.Session.Bindings()
	record, err := s.readConsent(ctx, b.TenantID, b.UserID, c.Command.Input().ID)
	if err != nil {
		return out, err
	}
	if record.State != "active" {
		return out, oauth.ErrAccessDenied
	}
	if _, err := s.consentClient(ctx, record); err != nil {
		return out, err
	}
	projection, err := consentProjection(record)
	if err != nil {
		return out, oauth.ErrUnavailable
	}
	if err := s.finishConsentRead(ctx, c, caller); err != nil {
		return out, err
	}
	// A second actual row read fences concurrent withdrawal/reconfirmation;
	// no local cached projection is accepted after that primary transition.
	final, err := s.readConsent(ctx, b.TenantID, b.UserID, record.ID)
	if err != nil {
		return out, err
	}
	if !sameJSON(final, record) {
		return out, oauth.ErrAccessDenied
	}
	if _, err := s.consentClient(ctx, record); err != nil {
		return out, err
	}
	if c.Session.ValidateAt(s.now()) != nil {
		return out, oauth.ErrAccessDenied
	}
	return oauth.ConsentGetResult{Consent: projection}, nil
}

// ConsentList is a bounded own-subject keyset read. A cursor is authenticated to
// this exact tenant/user/limit and carries no credentials or new read freshness.
// Pages are not snapshots: inserts/reconfirmations between calls may change them.
func (s *Store) ConsentList(ctx context.Context, c oauth.ConsentExecution) (out oauth.ConsentListResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.ConsentListResult{}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	observed, caller, err := s.consentObservation(ctx, c, oauth.ConsentEnumerate)
	if err != nil {
		return out, err
	}
	b, _ := observed.Session.Bindings()
	input := c.Command.Input()
	after, err := s.consentCursor(input.Cursor.String(), b.TenantID, b.UserID, input.Limit)
	if err != nil {
		return out, err
	}
	// There are at most64 configured clients, each with exactly one consent per
	// user. Bound reads independently of unconfigured historical registrations.
	ids := make([]string, 0, 64)
	for _, client := range s.config.Protocol.Clients {
		if client.Workload == nil {
			ids = append(ids, client.ID)
		}
	}
	selectedClients := `client_id=ANY($4::text[])`
	args := []any{string(b.TenantID), string(b.UserID), after, ids}
	if policy := s.config.Protocol.ManagedClients; policy != nil {
		selectedClients = `(client_id=ANY($4::text[]) OR client_id IN (SELECT client_id FROM ` + s.schema + `.managed_clients WHERE issuer=$5 AND environment=$6 AND platform_owner=$7 AND tenant_id=$1 AND state='active'))`
		args = append(args, s.config.Protocol.Issuer.String(), s.config.Protocol.Environment, policy.Owner.PlatformID())
	}
	rows, err := s.pool.Raw().Query(ctx, `SELECT consent_id FROM `+s.schema+`.consents WHERE tenant_id=$1 AND user_id=$2 AND state='active' AND consent_id>$3 AND `+selectedClients+` ORDER BY consent_id COLLATE "C" LIMIT 65`, args...)
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	var selected []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return out, oauth.ErrUnavailable
		}
		selected = append(selected, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	items := make([]oauth.Consent, 0, input.Limit)
	var records []consentRecord
	for _, id := range selected {
		record, err := s.readConsent(ctx, b.TenantID, b.UserID, id)
		if err != nil {
			return out, err
		}
		if record.State != "active" {
			return out, oauth.ErrAccessDenied
		}
		if _, err := s.consentClient(ctx, record); err != nil {
			if errors.Is(err, oauth.ErrInvalidClient) || errors.Is(err, oauth.ErrAccessDenied) {
				continue
			}
			return out, err
		}
		projection, err := consentProjection(record)
		if err != nil {
			return out, oauth.ErrUnavailable
		}
		records = append(records, record)
		items = append(items, projection)
		if len(items) > int(input.Limit) {
			break
		}
	}
	next := oauth.Cursor{}
	if len(items) > int(input.Limit) {
		items = items[:input.Limit]
		records = records[:input.Limit]
		next, _ = oauth.ParseCursor(s.encodeConsentCursor(items[len(items)-1].ID(), b.TenantID, b.UserID, input.Limit))
	}
	if err := s.finishConsentRead(ctx, c, caller); err != nil {
		return out, err
	}
	for _, record := range records {
		current, err := s.readConsent(ctx, b.TenantID, b.UserID, record.ID)
		if err != nil {
			return out, err
		}
		if !sameJSON(current, record) {
			return out, oauth.ErrAccessDenied
		}
		if _, err := s.consentClient(ctx, record); err != nil {
			return out, err
		}
	}
	if c.Session.ValidateAt(s.now()) != nil {
		return out, oauth.ErrAccessDenied
	}
	page, err := oauth.NewConsentListPage(items)
	if err != nil {
		return out, oauth.ErrUnavailable
	}
	return oauth.ConsentListResult{Page: page, NextCursor: next}, nil
}

func (s *Store) encodeConsentCursor(id string, tenant identity.TenantID, user identity.UserID, limit uint16) string {
	digest := s.intent("oauth-consent-cursor-v1", string(tenant), string(user), strconv.FormatUint(uint64(limit), 10), id)
	return id + "." + base64.RawURLEncoding.EncodeToString(digest[:])
}
func (s *Store) consentCursor(wire string, tenant identity.TenantID, user identity.UserID, limit uint16) (string, error) {
	if wire == "" {
		return "", nil
	}
	if len(wire) != 66 || wire[22] != '.' {
		return "", oauth.ErrInvalidRequest
	}
	id := wire[:22]
	if _, err := identity.ParseSubjectID(id); err != nil {
		return "", oauth.ErrInvalidRequest
	}
	if !hmac.Equal([]byte(wire), []byte(s.encodeConsentCursor(id, tenant, user, limit))) {
		return "", oauth.ErrAccessDenied
	}
	return id, nil
}

// ConsentDelete establishes one atomic consent-generation withdrawal, not an
// unbounded grant/artifact mutation. The same Work serializes approval/refresh
// admission against the root and persists its actual receipt, audit and primary
// consent.revoked.v1 event. Retry/recovery never redelivers bearer material.
func (s *Store) ConsentDelete(ctx context.Context, c oauth.ConsentExecution) (out oauth.ConsentDeleteResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.ConsentDeleteResult{Completion: oauth.Completion{Outcome: identity.CommitOutcomeUnknown}}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	observed, _, err := s.consentObservation(ctx, c, oauth.ConsentRemove)
	if err != nil {
		return out, err
	}
	input := c.Command.Input()
	if input.Origin != s.config.Protocol.Issuer.String() {
		return out, oauth.ErrAccessDenied
	}
	b, _ := observed.Session.Bindings()
	record, err := s.readConsent(ctx, b.TenantID, b.UserID, input.ID)
	if err != nil {
		return out, err
	}
	client, err := s.consentClient(ctx, record)
	if err != nil {
		return out, err
	}
	if record.State == "revoked" {
		if record.Version != input.Version+1 || record.RevokedCommand == "" {
			return out, oauth.ErrAccessDenied
		}
		// Authenticate the exact original prepared command, not today's tombstone
		// alone. This path never issues, reserves or fabricates journal completion.
		recovered, err := s.Recover(ctx, RecoveryRequest{OperationID: "identity.oauth-server.consent-delete", CommandID: record.RevokedCommand, ClientID: client.ID, ConsentID: record.ID, TenantID: input.TenantID, Session: input.Session})
		if c.ValidateAt(s.now()) != nil {
			return oauth.ConsentDeleteResult{}, oauth.ErrAccessDenied
		}
		return oauth.ConsentDeleteResult{Deleted: err == nil && recovered.Outcome == identity.CommitOutcomeCommitted, Completion: oauth.Completion{Outcome: recovered.Outcome, CommandID: recovered.CommandID, Replayed: true}}, err
	}
	if record.State != "active" || record.Version != input.Version || record.Generation == math.MaxUint64 {
		return out, oauth.ErrAccessDenied
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return out, oauth.ErrUnavailable
	}
	source, err := sessionpg.OriginalSessionFields(c.Session.Session)
	if err != nil {
		return out, oauth.ErrAccessDenied
	}
	p := s.consentDeletePhase(client, c.Session, record.ID, id, source)
	p.browser, p.csrf, p.consentCommand = c.Command.Input().Session, c.Command.Input().CSRF, c.Command
	p.input.Grant.Scopes = slices.Clone(record.Scopes)
	p.input.Scopes = slices.Clone(record.Scopes)
	p.input.CreatedAt = s.now()
	p.input.ObservationUntil = c.Session.ValidUntil()
	p.input.Network = input.Network
	p.input.Deletion = &consentDeletion{ID: record.ID, Version: record.Version, Generation: record.Generation}
	result, err := p.execute(ctx)
	return oauth.ConsentDeleteResult{Deleted: err == nil && result.Outcome == identity.CommitOutcomeCommitted, Completion: oauth.Completion{Outcome: result.Outcome, CommandID: id, Replayed: !p.applied}}, publicError(ctx, err, oauth.ErrAccessDenied)
}

func (s *Store) consentDeletePhase(client oauth.Client, observed session.GetResult, id string, command identity.CommandID, source []identity.FeatureField) *phase {
	b, _ := observed.Session.Bindings()
	p := &phase{store: s, client: client, observation: observed, input: phaseInput{Schema: 1, Configuration: s.identity, Transition: deleteConsent, Grant: grantRecord{Tenant: b.TenantID, User: b.UserID, ClientID: client.ID, ClientVersion: client.Version, ClientFingerprint: clientFingerprint(client), Source: source, Resource: client.Resource}, Intent: s.intent("consent-delete", id), Deletion: &consentDeletion{ID: id}}}
	p.bind(command, "identity.oauth-server.consent-delete", id)
	return p
}

func (p *phase) checkConsentDeletion(ctx context.Context, w kernel.Work, final bool) error {
	d := p.input.Deletion
	if d == nil || !p.store.config.ConsentManagement || d.ID != p.input.Binding.RecordID {
		return identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT version::text,generation::text,state,COALESCE(revoked_command,'') FROM `+p.store.schema+`.consents WHERE consent_id=$1 AND tenant_id=$2 AND user_id=$3 AND client_id=$4 AND client_version=$5::numeric FOR UPDATE`, d.ID, string(p.input.Grant.Tenant), string(p.input.Grant.User), p.client.ID, strconv.FormatUint(p.client.Version, 10))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return rows.Err()
		}
		return identity.ForbiddenError{}
	}
	var version, generation, state, command string
	if rows.Scan(&version, &generation, &state, &command) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	v, g := d.Version, d.Generation
	want := "active"
	if final && p.applied {
		v++
		g++
		want = "revoked"
		if command != string(p.input.Binding.CommandID) {
			return identity.ForbiddenError{}
		}
	}
	if version != strconv.FormatUint(v, 10) || generation != strconv.FormatUint(g, 10) || state != want {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *phase) mutateConsentDeletion(ctx context.Context, w kernel.Work) error {
	i, d := p.input, p.input.Deletion
	n, err := w.Exec(ctx, `UPDATE `+p.store.schema+`.consents SET state='revoked',version=version+1,generation=generation+1,revoked_command=$4,revoked_at=$5 WHERE consent_id=$1 AND version=$2::numeric AND generation=$3::numeric AND state='active'`, d.ID, strconv.FormatUint(d.Version, 10), strconv.FormatUint(d.Generation, 10), string(i.Binding.CommandID), i.CreatedAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	life := p.lifecycle()
	digest := effectDigest(i.Binding, p.registration(), life)
	n, err = w.Exec(ctx, `INSERT INTO `+p.store.schema+`.effects(tenant_id,command_id,operation_id,record_id,consent_id,before_version,after_version,binding_digest) VALUES($1,$2,$3,$4,$4,$5::numeric,$6::numeric,$7)`, string(i.Binding.TenantID), string(i.Binding.CommandID), i.Binding.OperationID, d.ID, strconv.FormatUint(life.BeforeVersion, 10), strconv.FormatUint(life.AfterVersion, 10), digest[:])
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// Consent locks precede grant/artifact locks in every relevant transition.
// A refresh holding this root cannot commit after a winning withdrawal; a
// withdrawal holds no grant locks and therefore cannot invert that order.
func (p *phase) checkGrantConsent(ctx context.Context, w kernel.Work, final bool) error {
	if !p.store.config.ConsentManagement || p.input.Grant.Workload != nil || p.input.Transition == createInteraction || p.input.Transition == createWorkload || p.input.Transition == deleteConsent {
		return nil
	}
	if p.input.Transition == approveInteraction {
		return p.checkManagedConsent(ctx, w, final)
	}
	// A pending denied interaction has no approved consent and can be consumed.
	if p.input.Transition == denyInteraction {
		return nil
	}
	g := p.input.Grant
	if g.ConsentID == "" || g.ConsentGeneration == 0 {
		return identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT state,generation::text FROM `+p.store.schema+`.consents WHERE consent_id=$1 AND tenant_id=$2 AND user_id=$3 AND client_id=$4 FOR UPDATE`, g.ConsentID, string(g.Tenant), string(g.User), g.ClientID)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return rows.Err()
		}
		return identity.ForbiddenError{}
	}
	var state, generation string
	if rows.Scan(&state, &generation) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	if state != "active" || generation != strconv.FormatUint(g.ConsentGeneration, 10) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *phase) checkManagedConsent(ctx context.Context, w kernel.Work, final bool) error {
	c, g := p.input.Consent, p.input.Grant
	rows, err := w.Query(ctx, `SELECT consent_id,version::text,generation::text,state,client_version::text,client_fingerprint,scopes,granted_at FROM `+p.store.schema+`.consents WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3 FOR UPDATE`, string(g.Tenant), string(g.User), g.ClientID)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return rows.Err()
		}
		if c.Created && !(final && p.applied) {
			return nil
		}
		return identity.ForbiddenError{}
	}
	var id, version, generation, state, clientVersion string
	var fingerprint, scopes []byte
	var grantedAt time.Time
	if rows.Scan(&id, &version, &generation, &state, &clientVersion, &fingerprint, &scopes, &grantedAt) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	want := c.BeforeVersion
	wantState := c.State
	if final && p.applied {
		want = c.AfterVersion
		wantState = "active"
	} else if c.Created {
		return identity.ForbiddenError{}
	}
	if id != c.ID || version != strconv.FormatUint(want, 10) || generation != strconv.FormatUint(c.Generation, 10) || state != wantState {
		return identity.ForbiddenError{}
	}
	if final && p.applied {
		fp := clientFingerprint(p.client)
		var actual []string
		if clientVersion != strconv.FormatUint(p.client.Version, 10) || !hmac.Equal(fingerprint, fp[:]) || decodeJSON(scopes, &actual) != nil || !slices.Equal(actual, p.input.Scopes) || !grantedAt.Equal(p.input.CreatedAt) {
			return identity.ForbiddenError{}
		}
	}
	return nil
}

func (p *phase) bindApprovedConsent(ctx context.Context, w kernel.Work) error {
	c, g := p.input.Consent, p.input.Grant
	n, err := w.Exec(ctx, `UPDATE `+p.store.schema+`.consents SET state='active',revoked_command=NULL,revoked_at=NULL WHERE consent_id=$1 AND version=$2::numeric AND generation=$3::numeric`, c.ID, strconv.FormatUint(c.AfterVersion, 10), strconv.FormatUint(c.Generation, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	n, err = w.Exec(ctx, `UPDATE `+p.store.schema+`.grants SET consent_id=$2,consent_generation=$3::numeric WHERE grant_id=$1 AND consent_id IS NULL AND consent_generation IS NULL`, g.ID, c.ID, strconv.FormatUint(c.Generation, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// SQL primary lookup fences actual current consent while retaining all original
// artifact/grant metadata for authenticated historical recovery.
func (s *Store) consentLookupState(ctx context.Context, g *grantRecord) (bool, error) {
	if !s.config.ConsentManagement || g.Workload != nil {
		return true, nil
	}
	var id, generation, state, currentGeneration string
	err := s.pool.Raw().QueryRow(ctx, `SELECT COALESCE(g.consent_id,''),COALESCE(g.consent_generation::text,''),COALESCE(c.state,''),COALESCE(c.generation::text,'') FROM `+s.schema+`.grants g LEFT JOIN `+s.schema+`.consents c ON c.consent_id=g.consent_id AND c.tenant_id=g.tenant_id AND c.user_id=g.user_id AND c.client_id=g.client_id WHERE g.grant_id=$1`, g.ID).Scan(&id, &generation, &state, &currentGeneration)
	if err != nil {
		return false, publicError(ctx, err, oauth.ErrInvalidGrant)
	}
	// Continuation grants have no consent until explicit approval; callers only
	// use this result to withdraw code/access/refresh activity, never continuations.
	if id == "" || generation == "" {
		return false, nil
	}
	parsed, err := strconv.ParseUint(generation, 10, 64)
	if err != nil || parsed == 0 {
		return false, oauth.ErrUnavailable
	}
	g.ConsentID, g.ConsentGeneration = id, parsed
	return state == "active" && generation == currentGeneration, nil
}
