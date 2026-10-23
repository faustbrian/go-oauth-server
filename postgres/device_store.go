package oauthpostgres

import (
	"context"
	"crypto/hmac"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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
	rate "github.com/faustbrian/go-rate-limit/v2"
	"github.com/jackc/pgx/v5"
)

type deviceDetails struct {
	Policy                        oauth.DevicePolicy
	Issuer, Environment, Resource string
	ClientVersion                 uint64
	ClientFingerprint             [32]byte
	GlobalAuthorityID             string
	GlobalVersion, TenantVersion  uint64
	Scopes                        []string
	// Grant is genuinely absent until explicit authenticated approval. It is
	// the original core-owned provenance, not a device-selected subject.
	Grant *grantRecord `json:",omitempty"`
}
type deviceRecord struct {
	ID                               string
	Tenant                           identity.TenantID
	ClientID                         string
	LookupVersion                    uint32
	DeviceDigest, UserDigest         [32]byte
	State                            string
	Version                          uint64
	LastCommand                      identity.CommandID
	CreatedAt, ExpiresAt, NextPollAt time.Time
	Interval                         time.Duration
	Details                          deviceDetails
}
type deviceMutation struct {
	Action        oauth.DeviceAction
	Before, After deviceRecord
	Condition     oauth.DeviceCondition
}
type devicePreparation struct{ Wire, UserCode string }

func (deviceRecord) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("native device record(redacted)"))
}
func (deviceMutation) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("native device mutation(redacted)"))
}
func (devicePreparation) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("native device preparation(redacted)"))
}

func deviceOperation(name string) identity.FeatureOperation {
	op := identity.FeatureOperation{Owner: "oauth-server/device", OperationID: name, SchemaID: name + ".native-device-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if name == "identity.oauth-server.device-authorize" || name == "identity.oauth-server.device-token" {
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	return op
}
func deviceOperationName(name string) bool {
	switch name {
	case "identity.oauth-server.device-authorize", "identity.oauth-server.device-approve", "identity.oauth-server.device-deny", "identity.oauth-server.device-token":
		return true
	}
	return false
}
func deviceOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{deviceOperation("identity.oauth-server.device-authorize"), deviceOperation("identity.oauth-server.device-approve"), deviceOperation("identity.oauth-server.device-deny"), deviceOperation("identity.oauth-server.device-token")}
}
func deviceOperationFor(action oauth.DeviceAction) string {
	switch action {
	case oauth.DeviceIssue:
		return "identity.oauth-server.device-authorize"
	case oauth.DeviceApprove:
		return "identity.oauth-server.device-approve"
	case oauth.DeviceDeny:
		return "identity.oauth-server.device-deny"
	case oauth.DevicePoll, oauth.DeviceCancel:
		return "identity.oauth-server.device-token"
	}
	return ""
}

func (d *DeviceStore) bounded(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if d == nil || d.core == nil || ctx == nil {
		return nil, nil, oauth.ErrInvalidRequest
	}
	return d.core.bounded(ctx)
}
func (d *DeviceStore) digest(key oauth.TokenDigestKey, wire, client string, user bool) (oauth.TokenDigest, error) {
	p := d.config.Policy
	return oauth.DeviceLookupDigest(key, oauth.DeviceDigestScope{Issuer: d.core.config.Protocol.Issuer, Environment: d.core.config.Protocol.Environment, TenantID: p.TenantID, VerificationURI: p.VerificationURI, TokenEndpoint: p.TokenEndpoint, ClientID: client, UserCode: user}, wire)
}
func (d *DeviceStore) admitRate(ctx context.Context, network string, poll bool) error {
	if !boundedText(network, 128) {
		return oauth.ErrInvalidRequest
	}
	policy := d.lookupPolicy
	purpose := "lookup"
	if poll {
		policy = d.pollPolicy
		purpose = "poll"
	}
	// Tenant, issuer/environment and trusted network are all separated by the
	// existing keyed caller-intent owner before the public rate-key projection.
	digest := d.core.intent("device-rate-v1", d.core.config.Protocol.Issuer.String(), d.core.config.Protocol.Environment, string(d.config.Policy.TenantID), purpose, network)
	key, err := rate.NewKey(rate.KeySpec{Namespace: "oauth-device", Version: "v1", Subject: rate.Subject{Kind: purpose, Value: fmt.Sprintf("%x", digest[:])}, Hash: true})
	if err != nil {
		return oauth.ErrUnavailable
	}
	decision, err := d.rates.Admit(ctx, rate.Request{Policy: policy, Key: key, Cost: 1, Now: d.core.now()})
	if err != nil {
		if errors.Is(err, rate.ErrRejected) {
			return oauth.ErrAccessDenied
		}
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if !decision.Allowed {
		return oauth.ErrAccessDenied
	}
	return nil
}

func scanDevice(row pgx.Row) (deviceRecord, error) {
	var r deviceRecord
	var version, tenant, lastCommand string
	var device, user, details []byte
	var seconds int64
	// Work deliberately permits only closed primitive destinations, not
	// application-defined Scanner hooks or named identity string types.
	err := row.Scan(&r.ID, &tenant, &r.ClientID, &r.LookupVersion, &device, &user, &r.State, &version, &lastCommand, &r.CreatedAt, &r.ExpiresAt, &r.NextPollAt, &seconds, &details)
	if err != nil {
		return r, err
	}
	r.Tenant, r.LastCommand = identity.TenantID(tenant), identity.CommandID(lastCommand)
	// PostgreSQL timestamptz scans may use the connection's local location.
	// Canonical UTC retains equal instants across frozen JSON commitments.
	r.CreatedAt, r.ExpiresAt, r.NextPollAt = r.CreatedAt.UTC(), r.ExpiresAt.UTC(), r.NextPollAt.UTC()
	r.Version, err = strconv.ParseUint(version, 10, 64)
	if err != nil || r.Version == 0 || r.Version == math.MaxUint64 || len(device) != 32 || len(user) != 32 || len(details) == 0 || len(details) > 65536 || decodeJSON(details, &r.Details) != nil || seconds < 5 || seconds > 60 {
		return deviceRecord{}, oauth.ErrUnavailable
	}
	copy(r.DeviceDigest[:], device)
	copy(r.UserDigest[:], user)
	r.Interval = time.Duration(seconds) * time.Second
	if _, err := identity.ParseCommandID(r.ID); err != nil || r.Tenant == "" || r.ClientID == "" || r.LookupVersion == 0 || r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) {
		return deviceRecord{}, oauth.ErrUnavailable
	}
	return r, nil
}

const deviceColumns = `device_id,tenant_id,client_id,lookup_version,device_digest,user_digest,state,version::text,last_command,created_at,expires_at,next_poll_at,interval_seconds,CASE WHEN octet_length(details::text)<=65536 THEN details ELSE NULL END`

func (d *DeviceStore) lookup(ctx context.Context, wire, client string, user bool) (deviceRecord, error) {
	column := "device_digest"
	if user {
		column = "user_digest"
	}
	for _, key := range d.config.LookupKeys {
		digest, err := d.digest(key, wire, client, user)
		if err != nil {
			return deviceRecord{}, oauth.ErrAccessDenied
		}
		r, err := scanDevice(d.core.pool.Raw().QueryRow(ctx, `SELECT `+deviceColumns+` FROM `+d.core.schema+`.devices WHERE tenant_id=$1 AND lookup_version=$2 AND `+column+`=$3`, string(d.config.Policy.TenantID), digest.KeyVersion, digest.Sum[:]))
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return deviceRecord{}, publicError(ctx, err, oauth.ErrAccessDenied)
		}
		if r.Details.Policy != d.config.Policy || r.Details.Issuer != d.core.config.Protocol.Issuer.String() || r.Details.Environment != d.core.config.Protocol.Environment || r.Details.Resource != d.core.config.Protocol.Resource || !user && r.ClientID != client {
			return deviceRecord{}, oauth.ErrAccessDenied
		}
		return r, nil
	}
	return deviceRecord{}, oauth.ErrAccessDenied
}
func (d *DeviceStore) currentClient(ctx context.Context, r deviceRecord) (oauth.Client, error) {
	c, err := d.core.CurrentClient(ctx, r.ClientID)
	if err != nil {
		return oauth.Client{}, err
	}
	if !c.DeviceAuthorization || c.Workload != nil || c.SubjectRegistration != nil || c.Version != r.Details.ClientVersion || clientFingerprint(c) != r.Details.ClientFingerprint || c.Resource != r.Details.Resource || !scopeSubset(r.Details.Scopes, c.Scopes) {
		return oauth.Client{}, oauth.ErrAccessDenied
	}
	return c, nil
}

// observeReview independently authenticates actual native session custody and
// conserves the core's original observation/freshness. No caller-written sealed
// projection or selected subject is accepted as a native permission assertion.
func (d *DeviceStore) observeReview(ctx context.Context, p oauth.DeviceSessionProjection, csrf session.CSRFToken, origin string, mutation bool) (session.GetResult, error) {
	if p.Request.TenantID != d.config.Policy.TenantID || p.ValidateAt(d.core.now()) != nil {
		return session.GetResult{}, oauth.ErrAccessDenied
	}
	current, err := d.core.recoverySession(ctx, RecoveryRequest{TenantID: p.Request.TenantID, Session: p.Request.Session})
	if err != nil {
		return session.GetResult{}, err
	}
	actual, err := sessionpg.OriginalSessionFields(current.Session)
	if err != nil {
		return session.GetResult{}, oauth.ErrAccessDenied
	}
	original, err := sessionpg.OriginalSessionFields(p.Session.Session)
	if err != nil || !sameJSON(actual, original) || (oauth.DeviceSessionProjection{Request: p.Request, Session: current}).ValidateAt(d.core.now()) != nil {
		return session.GetResult{}, oauth.ErrAccessDenied
	}
	if mutation {
		if origin != d.core.config.Protocol.Issuer.String() {
			return session.GetResult{}, oauth.ErrAccessDenied
		}
		b, _ := current.Session.Bindings()
		matched := false
		for _, key := range d.core.config.CSRFKeys {
			if current.Session.CSRFState().Check(session.CSRFBinding{TenantID: b.TenantID, SessionID: b.SessionID, SessionVersion: b.Version}, csrf, key) == nil {
				matched = true
				break
			}
		}
		if !matched {
			return session.GetResult{}, oauth.ErrAccessDenied
		}
	}
	return current, nil
}

// ExecuteDevice rechecks all actual native owners; public child projections do
// not bypass client authentication or current protected transaction admission.
func (d *DeviceStore) ExecuteDevice(ctx context.Context, e oauth.DeviceExecution) (out oauth.DeviceResult, err error) {
	defer func() {
		if recover() != nil {
			out = oauth.DeviceResult{Completion: oauth.Completion{Outcome: identity.CommitOutcomeUnknown, CommandID: out.Completion.CommandID}}
			err = oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := d.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if e.Policy != d.config.Policy || !boundedText(e.Network, 128) || deviceOperationFor(e.Action) == "" {
		return out, oauth.ErrInvalidRequest
	}
	if e.Action == oauth.DeviceIssue {
		return d.issue(ctx, e)
	}
	if e.Action == oauth.DeviceApprove || e.Action == oauth.DeviceDeny {
		return d.decide(ctx, e)
	}
	return d.poll(ctx, e)
}
func (d *DeviceStore) issue(ctx context.Context, e oauth.DeviceExecution) (oauth.DeviceResult, error) {
	if e.DeviceCode != "" || e.UserCode != "" || e.Session.Request.Session.Token() != "" || e.GeneratedUserCode == "" {
		return oauth.DeviceResult{}, oauth.ErrInvalidRequest
	}
	c, err := d.core.checkedClient(ctx, e.Client.Client)
	if err != nil || !c.DeviceAuthorization || c.Workload != nil || c.SubjectRegistration != nil || e.Client.Issuer != d.core.config.Protocol.Issuer || e.Client.Environment != d.core.config.Protocol.Environment || e.Client.Resource != c.Resource || !scopeSubset(e.Client.Scopes, c.Scopes) {
		return oauth.DeviceResult{}, oauth.ErrAccessDenied
	}
	selected, err := selectedScopes(e.Client.Scopes)
	if err != nil {
		return oauth.DeviceResult{}, err
	}
	for _, scope := range selected {
		if d.core.config.Protocol.OIDCScopes.Contains(scope) {
			return oauth.DeviceResult{}, oauth.ErrInvalidScope
		}
	}
	proof, err := d.core.authenticateClientSnapshot(ctx, c, e.ClientAuthentication)
	if err != nil {
		return oauth.DeviceResult{}, err
	}
	wire, err := e.GeneratedDeviceCode.Reveal()
	if err != nil {
		return oauth.DeviceResult{}, oauth.ErrInvalidRequest
	}
	digest, err := d.digest(d.active, wire, c.ID, false)
	if err != nil {
		return oauth.DeviceResult{}, err
	}
	user, err := d.digest(d.active, e.GeneratedUserCode, "", true)
	if err != nil {
		return oauth.DeviceResult{}, err
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return oauth.DeviceResult{}, oauth.ErrUnavailable
	}
	now := d.core.now()
	directory, err := d.core.domain.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: d.core.config.Session.Profile.GlobalAuthorityID, TenantID: d.config.Policy.TenantID})
	if err != nil || !directory.Enabled {
		return oauth.DeviceResult{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	r := deviceRecord{ID: string(id), Tenant: d.config.Policy.TenantID, ClientID: c.ID, LookupVersion: d.active.Version(), DeviceDigest: digest.Sum, UserDigest: user.Sum, State: "pending", Version: 1, LastCommand: id, CreatedAt: now, ExpiresAt: now.Add(d.config.Policy.TTL), NextPollAt: now.Add(d.config.Policy.PollInterval), Interval: d.config.Policy.PollInterval, Details: deviceDetails{Policy: d.config.Policy, Issuer: d.core.config.Protocol.Issuer.String(), Environment: d.core.config.Protocol.Environment, Resource: c.Resource, ClientVersion: c.Version, ClientFingerprint: clientFingerprint(c), Scopes: selected, GlobalAuthorityID: directory.Query.GlobalAuthorityID, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion}}
	p := d.newPhase(c, deviceMutation{Action: e.Action, After: r}, id, e.Network)
	p.input.ClientAuthentication = proof
	p.deviceCodes = &devicePreparation{Wire: wire, UserCode: e.GeneratedUserCode}
	result, err := p.execute(ctx)
	out := oauth.DeviceResult{Completion: oauth.Completion{Outcome: result.Outcome, CommandID: id, Replayed: !p.applied}}
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if err := d.core.finishClientAuthentication(ctx, c, proof, p.input.ClientAuthentication); err != nil {
		return out, err
	}
	if result.Outcome == identity.CommitOutcomeCommitted && p.applied {
		if p.output.DeviceCodes == nil || !d.core.now().Before(r.ExpiresAt) {
			return out, oauth.ErrUnavailable
		}
		out.DeviceCode, _ = oauth.ParseToken(p.output.DeviceCodes.Wire)
		out.UserCode = p.output.DeviceCodes.UserCode
		out.ExpiresAt = r.ExpiresAt
		out.Interval = r.Interval
	}
	return out, nil
}

func (d *DeviceStore) newPhase(c oauth.Client, m deviceMutation, id identity.CommandID, network string) *phase {
	r := m.Before
	if m.Action == oauth.DeviceIssue {
		r = m.After
	}
	g := grantRecord{ID: r.ID, Tenant: r.Tenant, ClientID: c.ID, ClientVersion: c.Version, ClientFingerprint: clientFingerprint(c), Resource: r.Details.Resource, Scopes: slices.Clone(r.Details.Scopes), CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt}
	if r.Details.Grant != nil {
		g = *r.Details.Grant
		g.Source = slices.Clone(g.Source)
		g.Scopes = slices.Clone(g.Scopes)
	}
	p := &phase{store: d.core, client: c, device: d, input: phaseInput{Schema: 1, Configuration: d.core.identity, Transition: deviceTransition(m.Action), Grant: g, Scopes: slices.Clone(r.Details.Scopes), CreatedAt: d.core.now(), Intent: d.core.intent("device-command-v1", deviceOperationFor(m.Action), string(id), r.ID, network), Network: network, Device: &m}}
	p.bind(id, deviceOperationFor(m.Action), r.ID)
	return p
}
func deviceTransition(a oauth.DeviceAction) transition {
	switch a {
	case oauth.DeviceIssue:
		return createDevice
	case oauth.DeviceApprove:
		return approveDevice
	case oauth.DeviceDeny:
		return denyDevice
	default:
		return pollDevice
	}
}

func (d *DeviceStore) decide(ctx context.Context, e oauth.DeviceExecution) (oauth.DeviceResult, error) {
	observed, err := d.observeReview(ctx, e.Session, e.CSRF, e.Origin, true)
	if err != nil {
		return oauth.DeviceResult{}, err
	}
	if err := d.admitRate(ctx, e.Network, false); err != nil {
		return oauth.DeviceResult{}, err
	}
	r, err := d.lookup(ctx, e.UserCode, "", true)
	if err != nil {
		return oauth.DeviceResult{}, err
	}
	c, err := d.currentClient(ctx, r)
	if err != nil {
		return oauth.DeviceResult{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if e.Action == oauth.DeviceDeny && r.State == "denied" {
		return oauth.DeviceResult{Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted, Replayed: true}, Condition: oauth.DeviceDenied}, nil
	}
	if r.State != "pending" || !d.core.now().Before(r.ExpiresAt) {
		return oauth.DeviceResult{}, oauth.ErrAccessDenied
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return oauth.DeviceResult{}, oauth.ErrUnavailable
	}
	after := r
	after.Version++
	after.LastCommand = id
	after.State = "denied"
	m := deviceMutation{Action: e.Action, Before: r, After: after, Condition: oauth.DeviceDenied}
	p := d.newPhase(c, m, id, e.Network)
	p.browser = e.Session.Request.Session
	p.observation = e.Session.Session
	p.csrf = e.CSRF
	p.input.ObservationUntil = e.Session.Session.ValidUntil()
	b, _ := observed.Session.Bindings()
	source, err := sessionpg.OriginalSessionFields(observed.Session)
	if err != nil {
		return oauth.DeviceResult{}, oauth.ErrAccessDenied
	}
	p.input.Grant.User = b.UserID
	p.input.Grant.Source = source
	if e.Action == oauth.DeviceApprove {
		p.input.Grant.Version = 1
		p.input.Grant.CreatedAt = p.input.CreatedAt
		p.input.Grant.ExpiresAt = p.input.CreatedAt.Add(d.core.config.Protocol.RefreshTTL)
		consent, err := d.core.prepareConsent(ctx, p.input.Grant)
		if err != nil {
			return oauth.DeviceResult{}, err
		}
		p.input.Consent = consent
		g := p.input.Grant
		g.Version = 2
		g.ConsentID = consent.ID
		g.ConsentGeneration = consent.Generation
		p.input.Device.After.State = "approved"
		p.input.Device.After.Details.Grant = &g
		p.input.Device.Condition = ""
	}
	p.bind(id, deviceOperationFor(e.Action), r.ID)
	result, err := p.execute(ctx)
	out := oauth.DeviceResult{Completion: oauth.Completion{Outcome: result.Outcome, CommandID: id, Replayed: !p.applied}, Condition: p.input.Device.Condition}
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if _, err := d.observeReview(ctx, e.Session, e.CSRF, e.Origin, true); err != nil {
		return oauth.DeviceResult{Completion: out.Completion}, err
	}
	return out, nil
}

func (d *DeviceStore) poll(ctx context.Context, e oauth.DeviceExecution) (oauth.DeviceResult, error) {
	c, err := d.core.checkedClient(ctx, e.Client.Client)
	if err != nil || !c.DeviceAuthorization || c.Workload != nil || c.SubjectRegistration != nil {
		return oauth.DeviceResult{}, oauth.ErrAccessDenied
	}
	proof, err := d.core.authenticateClientSnapshot(ctx, c, e.ClientAuthentication)
	if err != nil {
		return oauth.DeviceResult{}, err
	}
	if err := d.admitRate(ctx, e.Network, true); err != nil {
		return oauth.DeviceResult{}, err
	}
	r, err := d.lookup(ctx, e.DeviceCode, c.ID, false)
	if err != nil {
		return oauth.DeviceResult{}, err
	}
	if _, err := d.currentClient(ctx, r); err != nil {
		return oauth.DeviceResult{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if r.State == "denied" || r.State == "cancelled" || r.State == "consumed" {
		return oauth.DeviceResult{Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted, Replayed: true}, Condition: oauth.DeviceDenied}, nil
	}
	if r.State == "expired" {
		return oauth.DeviceResult{Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted, Replayed: true}, Condition: oauth.DeviceExpired}, nil
	}
	if r.State != "pending" && r.State != "approved" {
		return oauth.DeviceResult{}, oauth.ErrAccessDenied
	}
	now, err := d.core.introspectionTime(ctx)
	if err != nil {
		return oauth.DeviceResult{}, err
	}
	now = now.UTC()
	id, err := identity.NewCommandID()
	if err != nil {
		return oauth.DeviceResult{}, oauth.ErrUnavailable
	}
	after := r
	after.Version++
	after.LastCommand = id
	condition := oauth.DevicePending
	switch {
	case e.Action == oauth.DeviceCancel:
		after.State = "cancelled"
		condition = oauth.DeviceDenied
	case !now.Before(r.ExpiresAt):
		after.State = "expired"
		condition = oauth.DeviceExpired
	case now.Before(r.NextPollAt):
		if r.Interval > 55*time.Second {
			after.State = "cancelled"
			condition = oauth.DeviceDenied
		} else {
			after.Interval += 5 * time.Second
			after.NextPollAt = now.Add(after.Interval)
			condition = oauth.DeviceSlowDown
		}
	case r.State == "approved":
		after.State = "consumed"
		condition = oauth.DeviceSucceeded
	default:
		after.NextPollAt = now.Add(r.Interval)
	}
	p := d.newPhase(c, deviceMutation{Action: e.Action, Before: r, After: after, Condition: condition}, id, e.Network)
	p.input.ClientAuthentication = proof
	result, err := p.execute(ctx)
	out := oauth.DeviceResult{Completion: oauth.Completion{Outcome: result.Outcome, CommandID: id, Replayed: !p.applied}, Condition: condition, Interval: after.Interval}
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if err := d.core.finishClientAuthentication(ctx, c, proof, p.input.ClientAuthentication); err != nil {
		return oauth.DeviceResult{Completion: out.Completion}, err
	}
	if condition == oauth.DeviceSucceeded && p.applied && result.Outcome == identity.CommitOutcomeCommitted {
		out.Tokens = oauth.TokenResult{Outcome: result.Outcome, CommandID: id, AccessToken: p.generatedToken(oauth.TokenAccess), RefreshToken: p.generatedToken(oauth.TokenRefresh), ExpiresAt: p.generatedExpiry(oauth.TokenAccess), Resource: c.Resource, Scopes: slices.Clone(r.Details.Scopes)}
	}
	return out, nil
}

// InspectDevice returns only a safe bounded prompt after shared abuse admission
// and repeated actual current session/client/subject/consent reads. It creates no
// domain command, audit, lifecycle or consent and never approves a complete URI.
func (d *DeviceStore) InspectDevice(ctx context.Context, e oauth.DeviceInspection) (out oauth.DevicePrompt, err error) {
	defer func() {
		if recover() != nil {
			out, err = oauth.DevicePrompt{}, oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := d.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if e.Policy != d.config.Policy {
		return out, oauth.ErrInvalidRequest
	}
	if err := d.admitRate(ctx, e.Network, false); err != nil {
		return out, err
	}
	if _, err := d.observeReview(ctx, e.Session, session.CSRFToken{}, "", false); err != nil {
		return out, err
	}
	r, err := d.lookup(ctx, e.UserCode, "", true)
	if err != nil {
		return out, err
	}
	c, err := d.currentClient(ctx, r)
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if err := d.inspectCurrent(ctx, r, e.Session); err != nil {
		return out, err
	}
	again, err := d.lookup(ctx, e.UserCode, "", true)
	if err != nil || !sameJSON(r, again) {
		return out, oauth.ErrAccessDenied
	}
	if _, err := d.currentClient(ctx, again); err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if _, err := d.observeReview(ctx, e.Session, session.CSRFToken{}, "", false); err != nil {
		return out, err
	}
	if err := d.inspectCurrent(ctx, again, e.Session); err != nil {
		return out, err
	}
	return oauth.DevicePrompt{ClientID: c.ID, ClientDisplay: c.ID, UserCode: e.UserCode, Resource: r.Details.Resource, Scopes: slices.Clone(r.Details.Scopes), ExpiresAt: r.ExpiresAt}, nil
}
func (d *DeviceStore) inspectCurrent(ctx context.Context, r deviceRecord, review oauth.DeviceSessionProjection) error {
	now, err := d.core.introspectionTime(ctx)
	if err != nil {
		return err
	}
	if r.State != "pending" && r.State != "approved" || !now.Before(r.ExpiresAt) {
		return oauth.ErrAccessDenied
	}
	directory, err := d.core.domain.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: r.Details.GlobalAuthorityID, TenantID: r.Tenant})
	if err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if !directory.Enabled || directory.GlobalVersion != r.Details.GlobalVersion || directory.TenantVersion != r.Details.TenantVersion {
		return oauth.ErrAccessDenied
	}
	if r.Details.Grant == nil {
		if r.State != "pending" {
			return oauth.ErrAccessDenied
		}
		return nil
	}
	b, err := review.Session.Session.Bindings()
	g := *r.Details.Grant
	if err != nil || b.UserID != g.User {
		return oauth.ErrAccessDenied
	}
	if _, err := d.core.introspectionAuthority(ctx, g, now); err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	valid, err := d.core.consentLookupState(ctx, &g)
	if err != nil || !valid {
		return oauth.ErrAccessDenied
	}
	return nil
}

// RecoverDevice authenticates original client/device or human/user-code custody
// and delegates metadata-only recovery to the existing sole coordinator.
func (d *DeviceStore) RecoverDevice(ctx context.Context, e oauth.DeviceRecovery) (out oauth.Completion, err error) {
	defer func() {
		if recover() != nil {
			out = oauth.Completion{Outcome: identity.CommitOutcomeUnknown, CommandID: e.CommandID}
			err = oauth.ErrUnavailable
		}
	}()
	ctx, stop, err := d.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	if e.Policy != d.config.Policy || !deviceOperationName(e.OperationID) {
		return out, oauth.ErrInvalidRequest
	}
	if _, err := identity.ParseCommandID(string(e.CommandID)); err != nil {
		return out, oauth.ErrInvalidRequest
	}
	var r deviceRecord
	var c oauth.Client
	var observed session.GetResult
	switch e.OperationID {
	case "identity.oauth-server.device-authorize":
		c, err = d.core.checkedClient(ctx, e.Client.Client)
		if err == nil {
			_, err = d.core.authenticateClientSnapshot(ctx, c, e.ClientAuthentication)
		}
		r = deviceRecord{ID: string(e.CommandID), Tenant: d.config.Policy.TenantID, ClientID: c.ID}
	case "identity.oauth-server.device-token":
		c, err = d.core.checkedClient(ctx, e.Client.Client)
		if err == nil {
			_, err = d.core.authenticateClientSnapshot(ctx, c, e.ClientAuthentication)
		}
		if err == nil {
			r, err = d.lookup(ctx, e.DeviceCode, c.ID, false)
		}
	default:
		observed, err = d.observeReview(ctx, e.Session, session.CSRFToken{}, "", false)
		if err == nil {
			r, err = d.lookup(ctx, e.UserCode, "", true)
		}
		if err == nil {
			c, err = d.currentClient(ctx, r)
		}
	}
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	p := d.newPhase(c, deviceMutation{Before: r, After: r}, e.CommandID, "")
	p.input.Binding.OperationID = e.OperationID
	p.input.Binding.SchemaID = deviceOperation(e.OperationID).SchemaID
	if e.OperationID == "identity.oauth-server.device-authorize" || e.OperationID == "identity.oauth-server.device-token" {
		p.input.Binding.UserID = ""
		p.input.Binding.AnonymousFlowID = r.ID
		p.input.Binding.ActorID = identity.ActorID(c.ID)
		p.input.Binding.ActorKind = authorization.SubjectServiceAccount
	} else {
		b, _ := observed.Session.Bindings()
		p.input.Binding.UserID = b.UserID
		p.input.Binding.ActorID = identity.ActorID(b.UserID)
		p.input.Binding.ActorKind = authorization.SubjectUser
		p.input.Binding.AnonymousFlowID = ""
	}
	if err := d.core.coordinator(p); err != nil {
		return out, err
	}
	result, err := p.coordinator.RecoverFeatureCommand(ctx, p.query(), p.caller())
	out = oauth.Completion{Outcome: result.Outcome, CommandID: e.CommandID, Replayed: true}
	return out, publicError(ctx, err, oauth.ErrAccessDenied)
}

func (p *phase) deviceBinding() {
	if p.input.Device == nil {
		return
	}
	b := &p.input.Binding
	b.SchemaID = deviceOperation(b.OperationID).SchemaID
	if b.OperationID == "identity.oauth-server.device-authorize" || b.OperationID == "identity.oauth-server.device-token" {
		b.UserID = ""
		b.AnonymousFlowID = p.input.Grant.ID
		b.ActorID = identity.ActorID(p.client.ID)
		b.ActorKind = authorization.SubjectServiceAccount
	}
}
func (p *phase) deviceLifecycle() kernel.LifecyclePlan {
	m := p.input.Device
	before := m.Before.Version
	event := "oauth_device.polled.v1"
	switch {
	case m.Action == oauth.DeviceIssue:
		before = 0
		event = "oauth_device.created.v1"
	case m.Action == oauth.DeviceApprove:
		before = p.input.Grant.Version
		event = "grant.authorized.v1"
	case m.Action == oauth.DeviceDeny:
		event = "oauth_device.denied.v1"
	case m.Condition == oauth.DeviceSucceeded:
		before = p.input.Grant.Version
		event = "grant.code_exchanged.v1"
	case m.After.State == "expired":
		event = "oauth_device.expired.v1"
	case m.After.State == "cancelled":
		event = "oauth_device.cancelled.v1"
	}
	return kernel.LifecyclePlan{EventType: event, BeforeVersion: before, AfterVersion: before + 1}
}
func (p *phase) deviceAuditAction() string {
	switch p.input.Device.Action {
	case oauth.DeviceIssue:
		return "identity.oauth_server.authorize_device"
	case oauth.DeviceApprove:
		return "identity.oauth_server.approve_device"
	case oauth.DeviceDeny:
		return "identity.oauth_server.deny_device"
	default:
		return "identity.oauth_server.poll_device"
	}
}

func (p *phase) checkDevice(ctx context.Context, w kernel.Work, final bool) error {
	m := p.input.Device
	if p.device == nil || m == nil || p.device.config.Policy != m.After.Details.Policy || p.input.Configuration != p.store.identity || !p.client.DeviceAuthorization || p.client.Workload != nil || p.client.SubjectRegistration != nil {
		return identity.ForbiddenError{}
	}
	if p.input.Grant.ClientFingerprint != clientFingerprint(p.client) || p.input.Grant.ClientVersion != p.client.Version {
		return identity.ForbiddenError{}
	}
	if err := p.requireManagedClient(ctx, w); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	r := m.Before
	if m.Action == oauth.DeviceIssue {
		r = m.After
	}
	if m.Action == oauth.DeviceIssue && (now.Before(r.CreatedAt) || !now.Before(r.ExpiresAt)) {
		return identity.ForbiddenError{}
	}
	q := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: r.Details.GlobalAuthorityID, TenantID: r.Tenant}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: q, GlobalVersion: r.Details.GlobalVersion, TenantVersion: r.Details.TenantVersion}); err != nil {
		return err
	}
	if m.Action == oauth.DeviceIssue {
		if err := p.checkDeviceCodeUniqueness(ctx, w); err != nil {
			return err
		}
	}
	if m.Action == oauth.DeviceApprove || m.Action == oauth.DeviceDeny || m.Condition == oauth.DeviceSucceeded {
		if err := p.checkDeviceSource(ctx, w, now, m.Action == oauth.DeviceApprove || m.Action == oauth.DeviceDeny); err != nil {
			return err
		}
	}
	if m.Action == oauth.DeviceApprove || m.Action == oauth.DeviceDeny || m.Condition == oauth.DeviceSucceeded {
		if !now.Before(r.ExpiresAt) {
			return identity.ForbiddenError{}
		}
	}
	if m.Action != oauth.DeviceIssue || final {
		rows, err := w.Query(ctx, `SELECT `+deviceColumns+` FROM `+p.store.schema+`.devices WHERE device_id=$1 AND tenant_id=$2 AND client_id=$3 FOR UPDATE`, r.ID, string(r.Tenant), r.ClientID)
		if err != nil {
			return err
		}
		if !rows.Next() {
			rows.Close()
			return identity.ForbiddenError{}
		}
		actual, err := scanDevice(rows)
		extra := rows.Next()
		rowErr := rows.Err()
		rows.Close()
		if err != nil || extra || rowErr != nil {
			return identity.UnavailableError{}
		}
		expected := m.Before
		if final && p.applied {
			expected = m.After
		}
		if !sameJSON(actual, expected) {
			return identity.ConflictError{}
		}
	}
	if m.Action == oauth.DeviceApprove {
		old := p.input.Transition
		p.input.Transition = approveInteraction
		err := p.checkManagedConsent(ctx, w, final)
		p.input.Transition = old
		if err != nil {
			return err
		}
	}
	if m.Condition == oauth.DeviceSucceeded {
		if r.Details.Grant == nil {
			return identity.ForbiddenError{}
		}
		if err := p.checkGrantConsent(ctx, w, final); err != nil {
			return err
		}
		rows, err := w.Query(ctx, `SELECT state,version::text,source_session,scopes,resource,expires_at,client_version::text,client_fingerprint FROM `+p.store.schema+`.grants WHERE grant_id=$1 AND tenant_id=$2 AND user_id=$3 AND client_id=$4 FOR UPDATE`, p.input.Grant.ID, string(p.input.Grant.Tenant), string(p.input.Grant.User), p.client.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			return identity.ForbiddenError{}
		}
		var state, version, resource, clientVersion string
		var source, scopes, fingerprint []byte
		var expiry time.Time
		if rows.Scan(&state, &version, &source, &scopes, &resource, &expiry, &clientVersion, &fingerprint) != nil || rows.Next() || rows.Err() != nil {
			return identity.UnavailableError{}
		}
		want := p.input.Grant.Version
		if final && p.applied {
			want++
		}
		var fields []identity.FeatureField
		var actualScopes []string
		if state != "active" || version != strconv.FormatUint(want, 10) || clientVersion != strconv.FormatUint(p.client.Version, 10) || !hmac.Equal(fingerprint, p.input.Grant.ClientFingerprint[:]) || resource != p.input.Grant.Resource || !expiry.Equal(p.input.Grant.ExpiresAt) || decodeJSON(source, &fields) != nil || !sameJSON(fields, p.input.Grant.Source) || decodeJSON(scopes, &actualScopes) != nil || !slices.Equal(actualScopes, p.input.Scopes) {
			return identity.ForbiddenError{}
		}
	}
	if m.Action == oauth.DevicePoll && m.Condition == oauth.DeviceSlowDown && (!now.Before(m.Before.NextPollAt) || m.After.Interval != m.Before.Interval+5*time.Second) {
		return identity.ForbiddenError{}
	}
	// Repeat database time after all current-owner and row waits. A token can
	// never be authorized by the earlier application/DB sample alone.
	now, err = w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if m.Action == oauth.DeviceApprove || m.Action == oauth.DeviceDeny || m.Condition == oauth.DeviceSucceeded {
		if !now.Before(r.ExpiresAt) {
			return identity.ForbiddenError{}
		}
	}
	if m.Condition == oauth.DeviceSucceeded {
		for _, a := range p.output.Artifacts {
			if !now.Before(a.ExpiresAt) {
				return identity.ForbiddenError{}
			}
		}
	}
	return nil
}

func (p *phase) checkDeviceSource(ctx context.Context, w kernel.Work, now time.Time, browser bool) error {
	g := p.input.Grant
	original, err := sessionpg.OriginalSessionFromFields(g.Tenant, g.User, g.Source)
	if err != nil {
		return identity.ForbiddenError{}
	}
	b := p.input.Binding
	derive := sessionpg.OriginalSessionAdmission
	if !browser {
		// The session owner derives original human expectations without
		// relabeling this actual client actor or anonymous device flow.
		derive = sessionpg.OriginalDeviceGrantAdmission
	}
	directory, credential, authz, err := derive(p.store.config.Session.Profile, original, b)
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if browser {
		if _, err := w.RequireActiveActorCredential(ctx, p, credential); err != nil {
			return err
		}
		if err := w.RequireActiveActorAuthorization(ctx, p, authz); err != nil {
			return err
		}
	} else {
		if _, err := w.RequireOAuthDeviceGrantSource(ctx, p, credential, authz); err != nil {
			return err
		}
	}
	if browser {
		if p.observation.ValidateAt(now) != nil || !now.Before(p.input.ObservationUntil) || (oauth.DeviceSessionProjection{Request: oauth.DeviceSessionSourceRequest{TenantID: g.Tenant, Session: p.browser}, Session: p.observation}).ValidateAt(now) != nil {
			return identity.ForbiddenError{}
		}
		if err := p.checkBrowser(original); err != nil {
			return err
		}
		if err := sessionpg.RequireSession(ctx, w, p.store.config.Session.Repository, original); err != nil {
			return err
		}
		matched := false
		for _, key := range p.store.config.CSRFKeys {
			bindings, _ := original.Bindings()
			if original.CSRFState().Check(session.CSRFBinding{TenantID: g.Tenant, SessionID: bindings.SessionID, SessionVersion: bindings.Version}, p.csrf, key) == nil {
				if err := sessionpg.RequireCSRF(ctx, w, p.store.config.Session.Repository, original, p.csrf, key); err != nil {
					return err
				}
				matched = true
				break
			}
		}
		if !matched {
			return identity.ForbiddenError{}
		}
	} else if p.store.config.RPInitiatedLogout {
		if err := p.store.endSession.RequireNotRevoked(ctx, w, p, original); err != nil {
			return err
		}
	}
	return nil
}

func (p *phase) checkDeviceCodeUniqueness(ctx context.Context, w kernel.Work) error {
	codes := p.deviceCodes
	if codes == nil {
		codes = p.output.DeviceCodes
	}
	if codes == nil || p.device == nil || len(p.device.config.LookupKeys) < 1 || len(p.device.config.LookupKeys) > 4 {
		return identity.ForbiddenError{}
	}
	type lookup struct {
		version      uint32
		user, device [32]byte
	}
	lookups := make([]lookup, 0, len(p.device.config.LookupKeys))
	locks := make([]int64, 0, 2*len(p.device.config.LookupKeys))
	for _, key := range p.device.config.LookupKeys {
		user, err := p.device.digest(key, codes.UserCode, "", true)
		device, deviceErr := p.device.digest(key, codes.Wire, p.client.ID, false)
		if err != nil || deviceErr != nil {
			return identity.ForbiddenError{}
		}
		lookups = append(lookups, lookup{key.Version(), user.Sum, device.Sum})
		// Reinterpret all64 keyed bits as PostgreSQL's signed bigint lock key.
		// These are not plaintext, active-version-only or configuration digests.
		locks = append(locks, int64(binary.BigEndian.Uint64(user.Sum[:8])), int64(binary.BigEndian.Uint64(device.Sum[:8])))
	}
	// Per-version UNIQUE constraints alone permit a rotation collision. Every
	// retained version contributes locks, so overlapping retained sets share
	// a code lock despite different active/intent keys. Global signed ordering
	// avoids subset-order deadlocks. PostgreSQL18 §13.3.5 transaction advisory
	// locks release with this same bounded Work; no separate authority is added.
	slices.Sort(locks)
	for _, key := range slices.Compact(locks) {
		rows, err := w.Query(ctx, `SELECT pg_advisory_xact_lock($1)`, key)
		if err != nil {
			return err
		}
		one := rows.Next()
		extra := rows.Next()
		rowErr := rows.Err()
		rows.Close()
		if !one || extra || rowErr != nil {
			return identity.UnavailableError{}
		}
	}
	for _, lookup := range lookups {
		rows, err := w.Query(ctx, `SELECT device_id FROM `+p.store.schema+`.devices WHERE tenant_id=$1 AND lookup_version=$2 AND (user_digest=$3 OR (client_id=$4 AND device_digest=$5)) AND device_id<>$6 LIMIT 1`, string(p.input.Grant.Tenant), lookup.version, lookup.user[:], p.client.ID, lookup.device[:], p.input.Grant.ID)
		if err != nil {
			return err
		}
		found := rows.Next()
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			return rowErr
		}
		if found {
			return identity.ConflictError{}
		}
	}
	return nil
}

func (p *phase) mutateDevice(ctx context.Context, w kernel.Work) error {
	m := p.input.Device
	r := m.After
	if m.Action == oauth.DeviceApprove {
		g := p.input.Grant
		source, err := json.Marshal(g.Source)
		if err != nil {
			return err
		}
		defer clear(source)
		scopes, err := json.Marshal(g.Scopes)
		if err != nil {
			return err
		}
		defer clear(scopes)
		n, err := w.Exec(ctx, `INSERT INTO `+p.store.schema+`.grants(grant_id,tenant_id,user_id,client_id,client_version,client_fingerprint,source_session,scopes,resource,state,created_at,expires_at,version) VALUES($1,$2,$3,$4,$5::numeric,$6,$7::jsonb,$8::jsonb,$9,'active',$10,$11,1)`, g.ID, string(g.Tenant), string(g.User), g.ClientID, strconv.FormatUint(g.ClientVersion, 10), g.ClientFingerprint[:], string(source), string(scopes), g.Resource, g.CreatedAt, g.ExpiresAt)
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	}
	if m.Action == oauth.DeviceApprove || m.Condition == oauth.DeviceSucceeded {
		old := p.input.Transition
		if m.Action == oauth.DeviceApprove {
			p.input.Transition = approveInteraction
		} else {
			p.input.Transition = exchangeCode
		}
		err := p.mutateOAuth(ctx, w)
		p.input.Transition = old
		if err != nil {
			return err
		}
	} else if m.Before.Details.Grant != nil && (m.After.State == "expired" || m.After.State == "cancelled") {
		n, err := w.Exec(ctx, `UPDATE `+p.store.schema+`.grants SET state='revoked',version=version+1 WHERE grant_id=$1 AND tenant_id=$2 AND user_id=$3 AND client_id=$4 AND version=$5::numeric AND state='active'`, p.input.Grant.ID, string(p.input.Grant.Tenant), string(p.input.Grant.User), p.client.ID, strconv.FormatUint(p.input.Grant.Version, 10))
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	}
	details, err := json.Marshal(r.Details)
	if err != nil {
		return err
	}
	defer clear(details)
	var n int64
	if m.Action == oauth.DeviceIssue {
		n, err = w.Exec(ctx, `INSERT INTO `+p.store.schema+`.devices(device_id,tenant_id,client_id,lookup_version,device_digest,user_digest,state,version,last_command,created_at,expires_at,next_poll_at,interval_seconds,details) VALUES($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9,$10,$11,$12,$13,$14::jsonb)`, r.ID, string(r.Tenant), r.ClientID, r.LookupVersion, r.DeviceDigest[:], r.UserDigest[:], r.State, strconv.FormatUint(r.Version, 10), string(r.LastCommand), r.CreatedAt, r.ExpiresAt, r.NextPollAt, int64(r.Interval/time.Second), string(details))
	} else {
		n, err = w.Exec(ctx, `UPDATE `+p.store.schema+`.devices SET state=$4,version=$5::numeric,last_command=$6,next_poll_at=$7,interval_seconds=$8,details=$9::jsonb WHERE device_id=$1 AND tenant_id=$2 AND version=$3::numeric`, r.ID, string(r.Tenant), strconv.FormatUint(m.Before.Version, 10), r.State, strconv.FormatUint(r.Version, 10), string(r.LastCommand), r.NextPollAt, int64(r.Interval/time.Second), string(details))
	}
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	life := p.lifecycle()
	digest := effectDigest(p.input.Binding, p.registration(), life)
	n, err = w.Exec(ctx, `INSERT INTO `+p.store.schema+`.device_effects(tenant_id,command_id,operation_id,device_id,before_version,after_version,binding_digest) VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7)`, string(r.Tenant), string(p.input.Binding.CommandID), p.input.Binding.OperationID, r.ID, strconv.FormatUint(life.BeforeVersion, 10), strconv.FormatUint(life.AfterVersion, 10), digest[:])
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *phase) recoverDeviceParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, f, life, err := w.FeatureScope(p)
	if err != nil || f.Contributor != p.Descriptor() || f.Operation != deviceOperation(b.OperationID) || life.AfterVersion != life.BeforeVersion+1 {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT device_id,before_version::text,after_version::text,binding_digest FROM `+p.store.schema+`.device_effects WHERE tenant_id=$1 AND command_id=$2 AND operation_id=$3 AND device_id=$4`, string(b.TenantID), string(b.CommandID), b.OperationID, b.RecordID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			return kernel.RecoveryUnknown, rowErr
		}
		// Missing immutable evidence is not negative proof when this command's
		// owned state still exists. Creation owns the record ID permanently;
		// later mutations additionally leave their exact LastCommand pointer.
		state, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM `+p.store.schema+`.devices WHERE device_id=$1 AND tenant_id=$2 AND (last_command=$3 OR $4::boolean))`, b.RecordID, string(b.TenantID), string(b.CommandID), b.OperationID == "identity.oauth-server.device-authorize")
		if err != nil {
			return kernel.RecoveryUnknown, err
		}
		var contradiction bool
		one := state.Next()
		if !one || state.Scan(&contradiction) != nil || state.Next() || state.Err() != nil {
			state.Close()
			return kernel.RecoveryUnknown, identity.UnavailableError{}
		}
		state.Close()
		if contradiction {
			return kernel.RecoveryUnknown, nil
		}
		if life.EventType == "grant.authorized.v1" || life.EventType == "grant.code_exchanged.v1" {
			return p.recoverOAuthParticipant(ctx, w)
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var id, before, after string
	var digest []byte
	if rows.Scan(&id, &before, &after, &digest) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	want := effectDigest(b, f, life)
	if id != b.RecordID || before != strconv.FormatUint(life.BeforeVersion, 10) || after != strconv.FormatUint(life.AfterVersion, 10) || !hmac.Equal(digest, want[:]) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	rows.Close()
	if life.EventType == "grant.authorized.v1" || life.EventType == "grant.code_exchanged.v1" {
		status, err := p.recoverOAuthParticipant(ctx, w)
		if err != nil || status != kernel.RecoveryCommitted {
			return kernel.RecoveryUnknown, err
		}
	}
	return kernel.RecoveryCommitted, nil
}
