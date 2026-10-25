package oauthpostgres

import (
	"context"
	"encoding/base64"
	"errors"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

// Refresh succession is not delegation depth. Retain fixed-size original
// issuance proof instead of traversing an unbounded refresh chain. These IDs
// establish historical S256 provenance, never active refresh authority; the
// current access, original grant/consent and current human owners still fence
// every exchange/read (shared-issuer-v1, restricted exchange and lineage).
type humanRefreshIssuance struct {
	CodeID, RootRefreshID string
}

func (s *Store) humanRefreshExchangeSelected(c oauth.Client) bool {
	return s.humanExchangeSelected(c) && s.config.Protocol.HumanCodeExchange.AllowRefreshIssuedAccess
}

func (s *Store) readHumanRefreshIssuance(ctx context.Context, e *humanRefreshIssuance, a artifactRecord, c oauth.Client, query exchangeQuery, locked bool) error {
	// Retained ordinary refresh preparation may resume after delegation is
	// disabled. This validates historical issuance only, not permission to
	// exchange; that selection is enforced separately at access admission.
	if e == nil || a.Grant.Workload != nil || a.Grant.User == "" || a.Grant.ClientID != c.ID || a.Grant.ClientVersion != c.Version {
		return oauth.ErrInvalidGrant
	}
	if _, err := identity.ParseSubjectID(e.CodeID); err != nil {
		return oauth.ErrInvalidGrant
	}
	if _, err := identity.ParseSubjectID(e.RootRefreshID); err != nil || e.CodeID == e.RootRefreshID {
		return oauth.ErrInvalidGrant
	}
	statement := `SELECT code.payload,root.payload FROM ` + s.schema + `.artifacts code JOIN ` + s.schema + `.artifacts root ON root.parent_artifact_id=code.artifact_id AND root.grant_id=code.grant_id AND root.client_id=code.client_id JOIN ` + s.schema + `.effects issued ON issued.command_id=root.issued_by AND issued.grant_id=root.grant_id AND issued.tenant_id=$4 WHERE code.artifact_id=$1 AND root.artifact_id=$2 AND root.grant_id=$3 AND root.client_id=$5 AND code.kind=2 AND code.state='consumed' AND root.kind=4 AND root.state IN('active','consumed') AND code.consumed_by=root.issued_by AND issued.operation_id='identity.oauth-server.token' AND code.metadata_version=1 AND root.metadata_version=1`
	if locked {
		statement += ` FOR SHARE OF code,root`
	}
	rows, err := query(ctx, statement, e.CodeID, e.RootRefreshID, a.Grant.ID, string(a.Grant.Tenant), c.ID)
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
	var codeRaw, rootRaw []byte
	err = rows.Scan(&codeRaw, &rootRaw)
	extra, rowErr := rows.Next(), rows.Err()
	rows.Close()
	if err != nil || extra || rowErr != nil {
		return oauth.ErrUnavailable
	}
	var code, root artifactPayload
	if decodeJSON(codeRaw, &code) != nil || decodeJSON(rootRaw, &root) != nil || code.Schema != 1 || root.Schema != 1 || code.Exchange != nil || code.HumanExchange != nil || code.HumanRefresh != nil || root.Exchange != nil || root.HumanExchange != nil || root.HumanRefresh != nil || !sameJSON(code.Request, root.Request) || !sameJSON(root.Request, a.Payload.Request) || !scopeSubset(root.Scopes, code.Scopes) || !scopeSubset(a.Payload.Scopes, root.Scopes) || root.Request.ClientID != c.ID || root.Request.Resource != c.Resource {
		return oauth.ErrInvalidGrant
	}
	challenge, err := base64.RawURLEncoding.DecodeString(code.Request.CodeChallenge)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != code.Request.CodeChallenge {
		return oauth.ErrInvalidGrant
	}
	return nil
}

func (s *Store) captureHumanRefreshIssuance(ctx context.Context, a artifactRecord, c oauth.Client) (*humanRefreshIssuance, error) {
	if !s.humanRefreshExchangeSelected(c) || a.Kind != oauth.TokenRefresh || a.Payload.Exchange != nil || a.Payload.HumanExchange != nil {
		return nil, nil
	}
	e := a.Payload.HumanRefresh
	if e == nil {
		e = &humanRefreshIssuance{CodeID: a.ParentID, RootRefreshID: a.ID}
	}
	err := s.readHumanRefreshIssuance(ctx, e, a, c, func(ctx context.Context, statement string, args ...any) (exchangeRows, error) {
		return s.pool.Raw().Query(ctx, statement, args...)
	}, false)
	if errors.Is(err, oauth.ErrInvalidGrant) && a.Payload.HumanRefresh == nil {
		// Device and preactivation multi-rotation sources retain ordinary native
		// refresh semantics, but cannot acquire invented S256 ancestry here.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	copy := *e
	return &copy, nil
}

func (p *phase) checkHumanRefreshIssuance(ctx context.Context, w kernel.Work) error {
	i := p.input
	if i.HumanRefresh == nil {
		return nil
	}
	if i.Transition != rotateRefresh || i.TargetKind != oauth.TokenRefresh || i.TargetPayload.HumanRefresh == nil && i.HumanRefresh.RootRefreshID != i.TargetID || i.TargetPayload.HumanRefresh != nil && *i.TargetPayload.HumanRefresh != *i.HumanRefresh {
		return identity.ForbiddenError{}
	}
	source := artifactRecord{ID: i.TargetID, Kind: i.TargetKind, Grant: i.Grant, Payload: i.TargetPayload}
	return p.store.readHumanRefreshIssuance(ctx, i.HumanRefresh, source, p.client, func(ctx context.Context, statement string, args ...any) (exchangeRows, error) {
		return w.Query(ctx, statement, args...)
	}, true)
}

func (s *Store) humanRefreshAccessIssuance(ctx context.Context, a artifactRecord, c oauth.Client, query exchangeQuery, locked bool) error {
	if !s.humanRefreshExchangeSelected(c) || a.Kind != oauth.TokenAccess || a.Payload.HumanExchange != nil || a.Payload.Exchange != nil {
		return oauth.ErrInvalidGrant
	}
	if err := s.readHumanRefreshIssuance(ctx, a.Payload.HumanRefresh, a, c, query, locked); err != nil {
		return err
	}
	// Only the immediate consumed refresh proves this access issuance. Its
	// expiry is intentionally irrelevant: consumption removed bearer issuance
	// authority, while the current access retains its own bounded lifetime.
	statement := `SELECT parent.artifact_id,parent.payload FROM ` + s.schema + `.artifacts access JOIN ` + s.schema + `.artifacts parent ON parent.artifact_id=access.parent_artifact_id AND parent.grant_id=access.grant_id AND parent.client_id=access.client_id JOIN ` + s.schema + `.effects issued ON issued.command_id=access.issued_by AND issued.grant_id=access.grant_id AND issued.tenant_id=$4 WHERE access.artifact_id=$1 AND access.grant_id=$2 AND access.client_id=$3 AND access.kind=3 AND parent.kind=4 AND parent.state='consumed' AND parent.consumed_by=access.issued_by AND parent.metadata_version=1 AND issued.operation_id='identity.oauth-server.token'`
	if locked {
		statement += ` FOR SHARE OF parent`
	}
	rows, err := query(ctx, statement, a.ID, a.Grant.ID, c.ID, string(a.Grant.Tenant))
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
	var parentID string
	var raw []byte
	err = rows.Scan(&parentID, &raw)
	extra, rowErr := rows.Next(), rows.Err()
	rows.Close()
	if err != nil || extra || rowErr != nil {
		return oauth.ErrUnavailable
	}
	var parent artifactPayload
	if decodeJSON(raw, &parent) != nil || parent.Schema != 1 || parent.Exchange != nil || parent.HumanExchange != nil || parentID != a.ParentID || !sameJSON(parent.Request, a.Payload.Request) || !scopeSubset(a.Payload.Scopes, parent.Scopes) {
		return oauth.ErrInvalidGrant
	}
	if parent.HumanRefresh == nil {
		if parentID != a.Payload.HumanRefresh.RootRefreshID {
			return oauth.ErrInvalidGrant
		}
	} else if *parent.HumanRefresh != *a.Payload.HumanRefresh {
		return oauth.ErrInvalidGrant
	}
	return nil
}
