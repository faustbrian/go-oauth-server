package oauthserver

import "time"

func (p ManagedClientPolicy) validatedWorkloads(accessTTL time.Duration) ([]*Workload, error) {
	// Config's client catalog is bounded to64; the same bound keeps an exact
	// trusted machine selection from introducing an unbounded policy search.
	if len(p.Workloads) > 64 {
		return nil, ErrInvalidRequest
	}
	if p.Workloads == nil {
		return nil, nil
	}
	owned := make([]*Workload, len(p.Workloads))
	for i, w := range p.Workloads {
		if !w.valid() || w.tenant != p.TenantID || w.accessTTL > accessTTL {
			return nil, ErrInvalidRequest
		}
		for _, earlier := range owned[:i] {
			if earlier.id == w.id {
				return nil, ErrInvalidRequest
			}
		}
		value := *w
		owned[i] = &value
	}
	return owned, nil
}

// AllowsWorkloadRegistration checks the exact immutable tenant, service-account
// and lifetime allowlist plus the OAuth scope ceiling. It establishes no
// manager, client-secret or current service-account authority. Public/device
// clients and OIDC scopes are not selected by this confidential machine profile.
func (p ManagedClientPolicy) AllowsWorkloadRegistration(public, device bool, scopes []string, w *Workload) bool {
	if public || device || !w.valid() || w.tenant != p.TenantID || len(p.Workloads) > 64 {
		return false
	}
	values, err := validatedScopes(scopes)
	if err != nil || hasExtensionScope(values) || !scopeSubset(values, p.Scopes.values) {
		return false
	}
	for _, allowed := range p.Workloads {
		if allowed.valid() && *allowed == *w {
			return true
		}
	}
	return false
}

// ValidateWorkloadClientManagementRequest explicitly opts an adapter into
// create-only confidential machine registrations. It snapshots original policy
// scalars, rejects mixed browser/device/OIDC metadata and checks common manager
// preconditions without authenticating a manager or registering an account.
// Older validators reject Workload rather than silently discarding it.
func ValidateWorkloadClientManagementRequest(r ClientManagementRequest, p ManagedClientPolicy, issuer Issuer) (ClientManagementRequest, error) {
	if err := validateClientManagementBinding(r, p, issuer); err != nil {
		return ClientManagementRequest{}, err
	}
	if r.ClientID != "" || r.Version != 0 || r.Public || r.DeviceAuthorization || len(r.Redirects) != 0 || len(r.PostLogoutRedirects) != 0 || r.SubjectRegistration != nil || !r.Workload.valid() {
		return ClientManagementRequest{}, ErrInvalidRequest
	}
	scopes, err := validatedScopes(r.Scopes)
	if err != nil || hasExtensionScope(scopes) || !scopeSubset(scopes, p.Scopes.values) {
		return ClientManagementRequest{}, ErrInvalidScope
	}
	if !p.AllowsWorkloadRegistration(false, false, scopes, r.Workload) {
		return ClientManagementRequest{}, ErrAccessDenied
	}
	w := *r.Workload
	r.Workload, r.Scopes = &w, scopes
	return r, nil
}
