package oauthpostgres

import (
	"context"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

// WorkloadAuthorityConfig selects exact existing directory and authorization
// owner namespaces. Subject IDs must be unique across machine identities in this
// trusted namespace. It creates no authority row, credential or policy. Required
// only when Client.Workload is selected; zero retains the prior web profile.
type WorkloadAuthorityConfig struct{ GlobalAuthorityID, PolicyNamespace string }

type workloadSource struct {
	ID, Platform, GlobalAuthorityID, PolicyNamespace   string
	GlobalVersion, TenantVersion, AuthorizationVersion uint64
}

func workloadSelected(clients []oauth.Client) bool {
	for _, c := range clients {
		if c.Workload != nil {
			return true
		}
	}
	return false
}
func webSelected(clients []oauth.Client) bool {
	for _, c := range clients {
		if c.Workload == nil {
			return true
		}
	}
	return false
}

func (s *Store) validWorkload(g grantRecord, client oauth.Client) bool {
	w := g.Workload
	return w != nil && client.Workload != nil && g.User == "" && len(g.Source) == 0 && g.Tenant == client.Workload.TenantID() && w.ID == client.Workload.ID() && w.Platform == client.Owner.PlatformID() && w.GlobalAuthorityID == s.config.WorkloadAuthority.GlobalAuthorityID && w.PolicyNamespace == s.config.WorkloadAuthority.PolicyNamespace && w.GlobalVersion > 0 && w.TenantVersion > 0 && w.AuthorizationVersion > 0 && !g.ExpiresAt.After(g.CreatedAt.Add(client.Workload.AccessTTL()))
}
func workloadScope(g grantRecord) authority.AuthorityScope {
	return authority.AuthorityScope{TenantID: authorization.TenantID(g.Tenant), PolicyNamespace: g.Workload.PolicyNamespace, SubjectID: authorization.SubjectID(g.Workload.ID)}
}

func (s *Store) workloadGrant(ctx context.Context, client oauth.Client, id identity.CommandID, scopes []string) (grantRecord, error) {
	directory, err := s.domain.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config.WorkloadAuthority.GlobalAuthorityID, TenantID: client.Workload.TenantID()})
	if err != nil {
		return grantRecord{}, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if !directory.Enabled {
		return grantRecord{}, oauth.ErrAccessDenied
	}
	now := s.now()
	g := grantRecord{ID: string(id), Tenant: client.Workload.TenantID(), ClientID: client.ID, ClientVersion: client.Version, ClientFingerprint: clientFingerprint(client), Source: []identity.FeatureField{}, Scopes: scopes, Resource: client.Resource, CreatedAt: now, ExpiresAt: now.Add(client.Workload.AccessTTL()), Workload: &workloadSource{ID: client.Workload.ID(), Platform: client.Owner.PlatformID(), GlobalAuthorityID: s.config.WorkloadAuthority.GlobalAuthorityID, PolicyNamespace: s.config.WorkloadAuthority.PolicyNamespace, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion}}
	current, err := s.policy.Get(ctx, workloadScope(g))
	if err != nil {
		return grantRecord{}, workloadError(ctx, err)
	}
	g.Workload.AuthorizationVersion = current.Version
	return g, nil
}

func (s *Store) issueWorkload(ctx context.Context, client oauth.Client, r oauth.TokenRequest) (oauth.TokenResult, error) {
	if client.Workload == nil || r.GrantType != oauth.ClientCredentialsGrant || r.Code != "" || r.RedirectURI != "" || r.CodeVerifier != "" || r.RefreshToken != "" {
		return oauth.TokenResult{}, oauth.ErrInvalidRequest
	}
	scopes := r.Scopes
	if scopes == nil {
		scopes = client.Scopes
	}
	selected, err := selectedScopes(scopes)
	if err != nil || !scopeSubset(selected, client.Scopes) {
		return oauth.TokenResult{}, oauth.ErrInvalidScope
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return oauth.TokenResult{}, oauth.ErrUnavailable
	}
	g, err := s.workloadGrant(ctx, client, id, selected)
	if err != nil {
		return oauth.TokenResult{}, err
	}
	p := &phase{store: s, client: client, input: phaseInput{Schema: 1, Configuration: s.identity, Transition: createWorkload, Grant: g, Scopes: selected, CreatedAt: g.CreatedAt, Intent: s.intent("client_credentials", string(id)), Network: r.Network}}
	p.bind(id, "identity.oauth-server.token", g.ID)
	result, err := p.execute(ctx)
	out := oauth.TokenResult{Outcome: result.Outcome, CommandID: id, Replayed: !p.applied}
	if err != nil {
		return out, publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if result.Outcome == identity.CommitOutcomeCommitted && p.applied {
		out.AccessToken = p.generatedToken(oauth.TokenAccess)
		out.ExpiresAt = p.generatedExpiry(oauth.TokenAccess)
		out.Resource = client.Resource
		out.Scopes = selected
	}
	return out, nil
}

func (p *phase) checkWorkload(ctx context.Context, w kernel.Work) error {
	g := p.input.Grant
	if !p.store.validWorkload(g, p.client) {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: g.Workload.GlobalAuthorityID, TenantID: g.Tenant}, GlobalVersion: g.Workload.GlobalVersion, TenantVersion: g.Workload.TenantVersion}); err != nil {
		return err
	}
	// The public authorization owner consumes generation-bound Work directly;
	// do not relabel a machine as a human to use user-only admission helpers.
	// A returned error aborts this exact coordinator invocation; never ignore it.
	if err := authority.RequireAuthority(ctx, w, workloadScope(g), g.Workload.AuthorizationVersion, p.store.config.Protocol.MaximumDuration); err != nil {
		return workloadError(ctx, err)
	}
	return nil
}

func workloadError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, authority.ErrAuthorityDenied) {
		return oauth.ErrAccessDenied
	}
	return oauth.ErrUnavailable
}

func (s *Store) workloadIntrospectionAuthority(ctx context.Context, g grantRecord, client oauth.Client) (time.Time, error) {
	if !s.validWorkload(g, client) {
		return time.Time{}, oauth.ErrInvalidGrant
	}
	directory, err := s.domain.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: g.Workload.GlobalAuthorityID, TenantID: g.Tenant})
	if err != nil {
		return time.Time{}, err
	}
	current, err := s.policy.Get(ctx, workloadScope(g))
	if err != nil {
		return time.Time{}, err
	}
	if !directory.Enabled || directory.GlobalVersion != g.Workload.GlobalVersion || directory.TenantVersion != g.Workload.TenantVersion || current.Version != g.Workload.AuthorizationVersion {
		return time.Time{}, oauth.ErrInvalidGrant
	}
	return time.Time{}, nil
}
