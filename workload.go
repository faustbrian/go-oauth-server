package oauthserver

import (
	"fmt"
	"io"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// Workload is caller-owned startup policy for one confidential machine client.
// Tenant and service-account identity cannot come from token request data. The
// owning platform, scopes and sole resource belong to its enclosing Client.
// Nil selects the existing web profile; a nonnil zero value is invalid.
// No user, session, consent or customer delegation is created by this policy.
// Validation and service construction retain independent scalar snapshots;
// replacing a caller's whole value cannot change a constructed registration.
// Callers must not replace a value concurrently with reads or construction.
type Workload struct {
	tenant    identity.TenantID
	id        string
	accessTTL time.Duration
}

// NewWorkload constructs one exact tenant/service-account binding and a 1s..5min
// microsecond-aligned access ceiling. Config.AccessTTL may impose a smaller
// issuer ceiling. RFC6749 section4.4 permits only confidential, prearranged
// authority; this binding never authorizes a caller-selected human or tenant.
// Construction performs no IO or registration. Returned policy supports shared
// concurrent reads, but whole-value replacement must not race those reads.
// Validated clients and constructed services do not retain this mutable pointer.
func NewWorkload(tenant identity.TenantID, id string, accessTTL time.Duration) (*Workload, error) {
	w := &Workload{tenant: tenant, id: id, accessTTL: accessTTL}
	if !w.valid() {
		return nil, ErrInvalidRequest
	}
	w.tenant, w.id = identity.TenantID(strings.Clone(string(tenant))), strings.Clone(id)
	return w, nil
}

func (w *Workload) valid() bool {
	return w != nil && identifier(string(w.tenant)) && identifier(w.id) && w.accessTTL >= time.Second && w.accessTTL <= 5*time.Minute && w.accessTTL%time.Microsecond == 0
}

// TenantID returns the trusted isolation binding, not a request-selected account.
// Nil returns empty and grants no authority.
func (w *Workload) TenantID() identity.TenantID {
	if w == nil {
		return ""
	}
	return w.tenant
}

// ID returns the configured service-account identity, never a human user ID.
// Nil returns empty and grants no authority.
func (w *Workload) ID() string {
	if w == nil {
		return ""
	}
	return w.id
}

// AccessTTL returns the original configured ceiling. Nil returns zero.
func (w *Workload) AccessTTL() time.Duration {
	if w == nil {
		return 0
	}
	return w.accessTTL
}

// Format redacts correlated tenant/workload configuration for all fmt verbs.
func (*Workload) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "oauthserver.Workload(redacted)")
}

// MarshalJSON denies implicit correlated policy export; use explicit getters.
func (*Workload) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }

// MarshalText denies implicit correlated policy export; use explicit getters.
func (*Workload) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }
