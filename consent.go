package oauthserver

import (
	"context"
	"fmt"
	"slices"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ConsentOperation is a closed own-consent query, withdrawal or strict scope
// narrowing. Zero is invalid; subject overrides and expansion remain unavailable.
type ConsentOperation uint8

const (
	ConsentRead ConsentOperation = iota + 1
	ConsentEnumerate
	ConsentRemove
	ConsentNarrow
)

// Cursor is bounded, opaque pagination custody. Empty means the first/final
// page. Native cursors are authenticated to the current tenant/user and limit;
// parsing alone establishes no authorization or snapshot isolation.
type Cursor struct{ value string }

// ParseCursor borrows at most 512 visible ASCII bytes; native ownership is
// checked on use. Empty is the explicit absent cursor.
func ParseCursor(value string) (Cursor, error) {
	if value != "" && !visible(value, 512) {
		return Cursor{}, ErrInvalidRequest
	}
	return Cursor{value}, nil
}

// String returns pagination metadata, never a credential or authority assertion.
func (c Cursor) String() string { return c.value }

// ConsentCommandSpec selects one bounded own-consent operation. Session and
// CSRF remain borrowed until the bounded call returns; do not destroy them
// concurrently. Read/remove require ID; enumerate requires Limit in 1..64 and
// accepts only Cursor. Remove additionally requires exact positive Version,
// issuer Origin, CSRF and trusted Network. Narrow has those same requirements;
// its separate update request binds client/resource/scopes/key. Other variant
// fields must be zero.
type ConsentCommandSpec struct {
	Operation ConsentOperation
	TenantID  identity.TenantID
	Session   auth.BearerCredential
	ID        string
	Version   uint64
	Limit     uint16
	Cursor    Cursor
	Origin    string
	CSRF      session.CSRFToken
	Network   string
}

// Format redacts borrowed credentials and correlated scope metadata.
func (ConsentCommandSpec) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ConsentCommandSpec(redacted)"))
}

// MarshalJSON forbids implicit credential export.
func (ConsentCommandSpec) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }

// MarshalText forbids implicit credential export.
func (ConsentCommandSpec) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ConsentCommand owns an immutable scalar operation projection and borrows
// credential custody. Its zero value is invalid. Safe concurrent use requires
// the borrowed credential owners to remain alive and concurrency-safe.
type ConsentCommand struct{ input ConsentCommandSpec }

// NewConsentCommand validates closed variant/pagination bounds without IO.
func NewConsentCommand(s ConsentCommandSpec) (ConsentCommand, error) {
	if !identifier(string(s.TenantID)) {
		return ConsentCommand{}, ErrInvalidRequest
	}
	if _, err := session.ParseToken(s.Session.Token()); err != nil {
		return ConsentCommand{}, ErrInvalidRequest
	}
	switch s.Operation {
	case ConsentRead, ConsentRemove, ConsentNarrow:
		if _, err := identity.ParseSubjectID(s.ID); err != nil || s.Limit != 0 || s.Cursor.value != "" {
			return ConsentCommand{}, ErrInvalidRequest
		}
	case ConsentEnumerate:
		if s.ID != "" || s.Limit < 1 || s.Limit > 64 {
			return ConsentCommand{}, ErrInvalidRequest
		}
	default:
		return ConsentCommand{}, ErrInvalidRequest
	}
	if s.Operation == ConsentRemove || s.Operation == ConsentNarrow {
		if s.Version == 0 || s.Version == ^uint64(0) || !validOrigin(s.Origin) || s.CSRF == (session.CSRFToken{}) || !visible(s.Network, 128) {
			return ConsentCommand{}, ErrInvalidRequest
		}
	} else if s.Version != 0 || s.Origin != "" || s.CSRF != (session.CSRFToken{}) || s.Network != "" {
		return ConsentCommand{}, ErrInvalidRequest
	}
	return ConsentCommand{input: s}, nil
}

// Input returns a scalar copy for native adapters; credentials remain borrowed.
func (c ConsentCommand) Input() ConsentCommandSpec { return c.input }

// Format redacts borrowed custody and correlated consent identifiers.
func (ConsentCommand) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("ConsentCommand(redacted)")) }

// MarshalJSON forbids implicit credential export.
func (ConsentCommand) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }

// MarshalText forbids implicit credential export.
func (ConsentCommand) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// ConsentSpec is a nonsecret approved-consent projection, without subject
// overrides, bearer credentials or inferred permission to use a grant.
type ConsentSpec struct {
	ID, ClientID string
	Version      uint64
	Scopes       []string
	GrantedAt    time.Time
}

// Consent owns validated immutable metadata. Zero is invalid. A returned
// consent is not a live authorization lease or a promise that it remains active.
type Consent struct{ spec ConsentSpec }

// NewConsent validates and copies a bounded approved-consent projection.
func NewConsent(s ConsentSpec) (Consent, error) {
	if _, err := identity.ParseSubjectID(s.ID); err != nil || !identifier(s.ClientID) || s.Version == 0 || s.GrantedAt.IsZero() {
		return Consent{}, ErrInvalidRequest
	}
	scopes, err := validatedScopes(s.Scopes)
	if err != nil {
		return Consent{}, err
	}
	s.Scopes = scopes
	return Consent{spec: s}, nil
}

// ID returns the independent consent root identifier.
func (c Consent) ID() string { return c.spec.ID }

// ClientID returns the configured client associated with this approval.
func (c Consent) ClientID() string { return c.spec.ClientID }

// Version is the exact optimistic concurrency version, not grant authority.
func (c Consent) Version() uint64 { return c.spec.Version }

// Scopes returns an owned copy of the approved set.
func (c Consent) Scopes() []string { return slices.Clone(c.spec.Scopes) }

// GrantedAt returns the persisted approval time, never ambient renewed time.
func (c Consent) GrantedAt() time.Time { return c.spec.GrantedAt }

// ConsentListPage owns 0..64 approved consents in stable ascending ID order.
// Pagination is keyset-based, not an enduring multi-request snapshot.
type ConsentListPage struct {
	items []Consent
	valid bool
}

// NewConsentListPage validates immutable, unique, sorted items and copies them.
func NewConsentListPage(items []Consent) (ConsentListPage, error) {
	if len(items) > 64 {
		return ConsentListPage{}, ErrInvalidRequest
	}
	for i, c := range items {
		if _, err := NewConsent(c.spec); err != nil || i > 0 && items[i-1].ID() >= c.ID() {
			return ConsentListPage{}, ErrInvalidRequest
		}
	}
	return ConsentListPage{items: slices.Clone(items), valid: true}, nil
}

// Items returns an owned slice of immutable values, including empty final pages.
func (p ConsentListPage) Items() []Consent { return slices.Clone(p.items) }

// ConsentGetRequest selects an own-consent read with original browser custody.
type ConsentGetRequest struct{ Consent ConsentCommand }

// ConsentListRequest selects an own-consent bounded keyset read.
type ConsentListRequest struct{ Consent ConsentCommand }

// ConsentDeleteRequest selects fresh-session, same-browser consent withdrawal.
type ConsentDeleteRequest struct{ Consent ConsentCommand }

// ConsentGetResult contains only currently approved own-consent metadata.
type ConsentGetResult struct{ Consent Consent }

// ConsentListResult contains a bounded page and an optional next cursor.
type ConsentListResult struct {
	Page       ConsentListPage
	NextCursor Cursor
}

// Completion is historical mutation durability, never a permission renewal.
type Completion struct {
	Outcome   identity.CommitOutcome
	CommandID identity.CommandID
	Replayed  bool
}

// ConsentDeleteResult reports committed withdrawal or metadata-only durability.
// Deleted is true only when a committed withdrawal/no-op is known; unknown or
// in-progress never proves withdrawal. It does not claim asynchronous cleanup.
type ConsentDeleteResult struct {
	Deleted    bool
	Completion Completion
}

// ConsentExecution carries genuine sealed session observation plus borrowed
// original browser/CSRF custody. Native owners must authenticate it again and
// enforce current subject/session/credential/policy and fresh-mutation fences.
type ConsentExecution struct {
	Command ConsentCommand
	Session session.GetResult
}

// ValidateAt checks original sealed session custody and selected recent-proof
// policy, not current database state, CSRF or authorization. Trusted adapters
// pass authoritative time and still repeat their owning primary fences.
func (e ConsentExecution) ValidateAt(now time.Time) error {
	input := e.Command.Input()
	if _, err := NewConsentCommand(input); err != nil {
		return ErrInvalidRequest
	}
	if e.Session.ValidateAt(now) != nil {
		return ErrAccessDenied
	}
	b, err := e.Session.Session.Bindings()
	if err != nil || b.TenantID != input.TenantID || b.Authentication.Kind != session.AuthenticationVerified || b.Authentication.Proof.Method != "password" || b.Authentication.Proof.Assurance != auth.AssuranceSingleFactor {
		return ErrAccessDenied
	}
	a, err := b.Authority.Bindings()
	if err != nil || a.Organization.Present || a.Factor.Present || a.Passkey.Present {
		return ErrAccessDenied
	}
	if input.Operation == ConsentRemove || input.Operation == ConsentNarrow {
		lifetime, err := e.Session.Session.Lifetime(now)
		// REFERENCE_CONFIGURATION session.fresh_for fixes sensitive operations
		// at 15min even when general session FreshFor permits 24h. Selected
		// password single-factor provenance preserves original completion time;
		// activity, session issuance/rotation and another read never renew it.
		completed := b.Authentication.Proof.IssuedAt
		if err != nil || !lifetime.Fresh || completed.IsZero() || now.Before(completed) || !now.Before(completed.Add(15*time.Minute)) {
			return ErrAccessDenied
		}
	}
	return nil
}

// ConsentManager is an optional native own-consent owner; absence denies. Reads
// must be bounded/current and withdrawal atomic with audit/lifecycle/recovery.
// Existing Store implementations and workload-only profiles need not enable it.
type ConsentManager interface {
	ConsentGet(context.Context, ConsentExecution) (ConsentGetResult, error)
	ConsentList(context.Context, ConsentExecution) (ConsentListResult, error)
	ConsentDelete(context.Context, ConsentExecution) (ConsentDeleteResult, error)
}

func (s *Service) consentSource(ctx context.Context, c ConsentCommand, operation ConsentOperation) (ConsentManager, session.GetResult, error) {
	input := c.Input()
	if _, err := NewConsentCommand(input); err != nil || input.Operation != operation {
		return nil, session.GetResult{}, ErrInvalidRequest
	}
	owner, ok := s.deps.Store.(ConsentManager)
	if !ok || nilDependency(owner) || s.deps.Sessions == nil {
		return nil, session.GetResult{}, ErrAccessDenied
	}
	if (operation == ConsentRemove || operation == ConsentNarrow) && input.Origin != s.config.Issuer.String() {
		return nil, session.GetResult{}, ErrAccessDenied
	}
	observed, err := s.source(ctx, input.TenantID, input.Session)
	if err != nil {
		return nil, session.GetResult{}, err
	}
	if !observed.Authenticated {
		return nil, session.GetResult{}, ErrAccessDenied
	}
	if err := (ConsentExecution{Command: c, Session: observed}).ValidateAt(s.config.Clock.Now()); err != nil {
		return nil, session.GetResult{}, err
	}
	return owner, observed, nil
}

// ConsentGet reads only the current session's approved consent. Missing,
// foreign, revoked and unsupported profile requests deny without metadata.
func (s *Service) ConsentGet(ctx context.Context, r ConsentGetRequest) (out ConsentGetResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = ConsentGetResult{}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	owner, observed, err := s.consentSource(ctx, r.Consent, ConsentRead)
	if err != nil {
		return out, err
	}
	out, err = owner.ConsentGet(ctx, ConsentExecution{r.Consent, observed})
	if err != nil || ctx.Err() != nil {
		return ConsentGetResult{}, operationError(ctx, err)
	}
	c := out.Consent
	client, e := s.currentClient(ctx, c.ClientID())
	if e != nil || client.Workload != nil || c.ID() != r.Consent.input.ID || !scopeSubset(c.Scopes(), client.Scopes) || observed.ValidateAt(s.config.Clock.Now()) != nil {
		return ConsentGetResult{}, ErrUnavailable
	}
	if _, err := NewConsent(c.spec); err != nil {
		return ConsentGetResult{}, ErrUnavailable
	}
	return out, nil
}

// ConsentList reads a current own-subject bounded page, never another actor's
// approvals. Cursors convey pagination only; native owners authenticate scope.
func (s *Service) ConsentList(ctx context.Context, r ConsentListRequest) (out ConsentListResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = ConsentListResult{}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	owner, observed, err := s.consentSource(ctx, r.Consent, ConsentEnumerate)
	if err != nil {
		return out, err
	}
	out, err = owner.ConsentList(ctx, ConsentExecution{r.Consent, observed})
	if err != nil || ctx.Err() != nil {
		return ConsentListResult{}, operationError(ctx, err)
	}
	if !out.Page.valid || len(out.Page.items) > int(r.Consent.input.Limit) || observed.ValidateAt(s.config.Clock.Now()) != nil {
		return ConsentListResult{}, ErrUnavailable
	}
	for _, c := range out.Page.items {
		client, e := s.currentClient(ctx, c.ClientID())
		if e != nil || client.Workload != nil || !scopeSubset(c.Scopes(), client.Scopes) {
			return ConsentListResult{}, ErrUnavailable
		}
	}
	if _, e := NewConsentListPage(out.Page.items); e != nil {
		return ConsentListResult{}, ErrUnavailable
	}
	return out, nil
}

// ConsentDelete withdraws the exact approved consent version under a fresh
// current genuine session and native synchronizer/current-authority fences.
// Replayed/unknown completion never re-executes or discloses bearer material.
func (s *Service) ConsentDelete(ctx context.Context, r ConsentDeleteRequest) (out ConsentDeleteResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = ConsentDeleteResult{Completion: Completion{Outcome: identity.CommitOutcomeUnknown}}, ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return out, err
	}
	defer stop()
	owner, observed, err := s.consentSource(ctx, r.Consent, ConsentRemove)
	if err != nil {
		return out, err
	}
	out, err = owner.ConsentDelete(ctx, ConsentExecution{r.Consent, observed})
	if err != nil || ctx.Err() != nil {
		return ConsentDeleteResult{Completion: out.Completion}, operationError(ctx, err)
	}
	if out.Deleted != (out.Completion.Outcome == identity.CommitOutcomeCommitted) {
		return ConsentDeleteResult{Completion: out.Completion}, ErrUnavailable
	}
	return out, nil
}
