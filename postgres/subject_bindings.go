package oauthpostgres

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"slices"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

type subjectBinding struct {
	PolicyID, SectorHost, Subject string
	PolicyVersion                 uint64
}

func pairwiseClient(client oauth.Client) bool {
	return client.SubjectRegistration != nil && client.SubjectRegistration.SubjectType() == "pairwise"
}

func validSubject(value string) bool {
	if len(value) != 43 {
		return false
	}
	wire, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(wire) == 32
}

func validSubjectProposal(client oauth.Client, candidate *oauth.OIDCSubjectCandidate) bool {
	return pairwiseClient(client) && candidate != nil && candidate.Registration == *client.SubjectRegistration && validSubject(candidate.Subject) && candidate.KeyVersion != 0 && candidate.KeyCommitment != ([32]byte{})
}

func (s *Store) loadSubjectBinding(ctx context.Context, grant *grantRecord) error {
	contextID := s.subjectContext()
	var binding subjectBinding
	var version, issuer, environment, tenant, user string
	err := s.pool.Raw().QueryRow(ctx, `SELECT b.policy_id,b.policy_version::text,b.sector_host,b.subject,b.issuer,b.environment,b.tenant_id,b.user_id FROM `+s.schema+`.grant_subject_bindings g JOIN `+s.schema+`.subject_bindings b USING(context_id,tenant_id,sector_host,user_id) WHERE g.grant_id=$1 AND g.context_id=$2 AND g.issuer=b.issuer AND g.environment=b.environment`, grant.ID, contextID[:]).Scan(&binding.PolicyID, &version, &binding.SectorHost, &binding.Subject, &issuer, &environment, &tenant, &user)
	if err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if issuer != s.config.Protocol.Issuer.String() || environment != s.config.Protocol.Environment || tenant != string(grant.Tenant) || user != string(grant.User) || !validSubject(binding.Subject) {
		return oauth.ErrAccessDenied
	}
	binding.PolicyVersion, err = strconv.ParseUint(version, 10, 64)
	if err != nil || binding.PolicyVersion == 0 {
		return oauth.ErrAccessDenied
	}
	grant.Subject = &binding
	return nil
}

func bindingMatchesClient(binding *subjectBinding, client oauth.Client) bool {
	return binding != nil && pairwiseClient(client) && binding.PolicyID == client.SubjectRegistration.PolicyID() && binding.PolicyVersion == client.SubjectRegistration.PolicyVersion() && binding.SectorHost == client.SubjectRegistration.SectorHost() && validSubject(binding.Subject)
}

func subjectClaims(client oauth.Client, grant grantRecord) (*oauth.OIDCSubjectRegistration, string, error) {
	var registration *oauth.OIDCSubjectRegistration
	if client.SubjectRegistration != nil {
		owned := *client.SubjectRegistration
		registration = &owned
	}
	if pairwiseClient(client) {
		if !bindingMatchesClient(grant.Subject, client) {
			return nil, "", oauth.ErrAccessDenied
		}
		return registration, grant.Subject.Subject, nil
	}
	if grant.Subject != nil {
		return nil, "", oauth.ErrAccessDenied
	}
	return registration, "", nil
}

func (p *phase) checkSubjectBinding(ctx context.Context, w kernel.Work, final bool) error {
	i := p.input
	if i.Transition == deleteConsent {
		// Consent withdrawal owns no individual grant/subject association and
		// must remain possible independently of derivation-key custody.
		return nil
	}
	candidate := i.SubjectCandidate
	if i.Transition == createInteraction && candidate != nil {
		if !validSubjectProposal(p.client, candidate) || !slices.Contains(i.Request.Scopes, "openid") {
			return identity.ForbiddenError{}
		}
		// Share the policy-selection row before reading key predicates. This
		// prevents activation/retirement from crossing an authenticated Work;
		// separate statements re-read key state after any selection lock wait.
		contextID := p.store.subjectContext()
		var issuer, environment string
		var selected int64
		rows, err := w.Query(ctx, `SELECT issuer,environment,COALESCE(key_version,0) FROM `+p.store.schema+`.subject_selection WHERE context_id=$1 AND policy_id=$2 AND policy_version=$3::numeric FOR SHARE`, contextID[:], candidate.Registration.PolicyID(), strconv.FormatUint(candidate.Registration.PolicyVersion(), 10))
		if err != nil {
			return err
		}
		ok := rows.Next() && rows.Scan(&issuer, &environment, &selected) == nil
		extra, rowErr := rows.Next(), rows.Err()
		rows.Close()
		if !ok || extra || rowErr != nil || issuer != p.store.config.Protocol.Issuer.String() || environment != p.store.config.Protocol.Environment || selected != int64(candidate.KeyVersion) {
			return identity.ForbiddenError{}
		}
		rows, err = w.Query(ctx, `SELECT commitment FROM `+p.store.schema+`.subject_keys WHERE context_id=$1 AND policy_id=$2 AND policy_version=$3::numeric AND key_version=$4 AND NOT retired AND issuer=$5 AND environment=$6 FOR SHARE`, contextID[:], candidate.Registration.PolicyID(), strconv.FormatUint(candidate.Registration.PolicyVersion(), 10), candidate.KeyVersion, issuer, environment)
		if err != nil {
			return err
		}
		var commitment []byte
		ok = rows.Next() && rows.Scan(&commitment) == nil
		extra, rowErr = rows.Next(), rows.Err()
		rows.Close()
		if !ok || extra || rowErr != nil || subtle.ConstantTimeCompare(commitment, candidate.KeyCommitment[:]) != 1 {
			return identity.ForbiddenError{}
		}
		if !final || !p.applied {
			return nil
		}
	} else if i.Grant.Subject == nil {
		if pairwiseClient(p.client) && slices.Contains(i.Grant.Scopes, "openid") {
			return identity.ForbiddenError{}
		}
		return nil
	}
	contextID := p.store.subjectContext()
	rows, err := w.Query(ctx, `SELECT b.policy_id,b.policy_version::text,b.sector_host,b.subject FROM `+p.store.schema+`.grant_subject_bindings g JOIN `+p.store.schema+`.subject_bindings b USING(context_id,tenant_id,sector_host,user_id) WHERE g.grant_id=$1 AND g.context_id=$2 AND b.issuer=$3 AND b.environment=$4 AND b.tenant_id=$5 AND b.user_id=$6 AND g.issuer=b.issuer AND g.environment=b.environment FOR SHARE OF g,b`, i.Grant.ID, contextID[:], p.store.config.Protocol.Issuer.String(), p.store.config.Protocol.Environment, string(i.Grant.Tenant), string(i.Grant.User))
	if err != nil {
		return err
	}
	var actual subjectBinding
	var version string
	ok := rows.Next() && rows.Scan(&actual.PolicyID, &version, &actual.SectorHost, &actual.Subject) == nil
	extra, rowErr := rows.Next(), rows.Err()
	rows.Close()
	actual.PolicyVersion, err = strconv.ParseUint(version, 10, 64)
	if !ok || extra || rowErr != nil || err != nil || !bindingMatchesClient(&actual, p.client) || i.Grant.Subject != nil && actual != *i.Grant.Subject {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *phase) bindSubject(ctx context.Context, w kernel.Work) error {
	candidate := p.input.SubjectCandidate
	if candidate == nil {
		return nil
	}
	g := p.input.Grant
	contextID := p.store.subjectContext()
	r := candidate.Registration
	// Native authenticated Authorize Work creates the durable binding before
	// a code can ever be issued. Contending candidates never overwrite a prior
	// identity, including when their derivation-key versions differ.
	_, err := w.Exec(ctx, `INSERT INTO `+p.store.schema+`.subject_bindings(context_id,issuer,environment,tenant_id,sector_host,user_id,policy_id,policy_version,origin_key_version,subject) VALUES($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9,$10) ON CONFLICT(context_id,tenant_id,sector_host,user_id) DO NOTHING`, contextID[:], p.store.config.Protocol.Issuer.String(), p.store.config.Protocol.Environment, string(g.Tenant), r.SectorHost(), string(g.User), r.PolicyID(), strconv.FormatUint(r.PolicyVersion(), 10), candidate.KeyVersion, candidate.Subject)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `INSERT INTO `+p.store.schema+`.grant_subject_bindings(grant_id,context_id,issuer,environment,tenant_id,sector_host,user_id) SELECT $1,b.context_id,b.issuer,b.environment,b.tenant_id,b.sector_host,b.user_id FROM `+p.store.schema+`.subject_bindings b WHERE context_id=$2 AND issuer=$3 AND environment=$4 AND tenant_id=$5 AND sector_host=$6 AND user_id=$7 AND policy_id=$8 AND policy_version=$9::numeric`, g.ID, contextID[:], p.store.config.Protocol.Issuer.String(), p.store.config.Protocol.Environment, string(g.Tenant), r.SectorHost(), string(g.User), r.PolicyID(), strconv.FormatUint(r.PolicyVersion(), 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}
