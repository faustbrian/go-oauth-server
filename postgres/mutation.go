package oauthpostgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

func (p *phase) mutate(ctx context.Context, w kernel.Work) error {
	if p.input.Transition == deleteConsent {
		return p.mutateConsentDeletion(ctx, w)
	}
	i := p.input
	g := i.Grant
	s := p.store.schema
	source, err := json.Marshal(g.Source)
	if err != nil {
		return identity.UnavailableError{}
	}
	defer clear(source)
	scopes, err := json.Marshal(i.Scopes)
	if err != nil {
		return identity.UnavailableError{}
	}
	defer clear(scopes)
	if i.Transition == createInteraction {
		// Work deliberately fixes bytes to bytea, not a driver-selected JSON
		// codec. Bounded nonsecret projections use text with explicit jsonb casts.
		n, err := w.Exec(ctx, `INSERT INTO `+s+`.grants(grant_id,tenant_id,user_id,client_id,client_version,client_fingerprint,source_session,scopes,resource,state,created_at,expires_at,version) VALUES($1,$2,$3,$4,$5::numeric,$6,$7::jsonb,$8::jsonb,$9,'active',$10,$11,1)`, g.ID, string(g.Tenant), string(g.User), g.ClientID, strconv.FormatUint(g.ClientVersion, 10), g.ClientFingerprint[:], string(source), string(scopes), g.Resource, g.CreatedAt, g.ExpiresAt)
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	} else if i.Transition == createWorkload {
		workload, err := json.Marshal(g.Workload)
		if err != nil {
			return identity.UnavailableError{}
		}
		defer clear(workload)
		n, err := w.Exec(ctx, `INSERT INTO `+s+`.grants(grant_id,tenant_id,user_id,client_id,client_version,client_fingerprint,source_session,scopes,resource,state,created_at,expires_at,version,workload_source) VALUES($1,$2,NULL,$3,$4::numeric,$5,'[]'::jsonb,$6::jsonb,$7,'active',$8,$9,1,$10::jsonb)`, g.ID, string(g.Tenant), g.ClientID, strconv.FormatUint(g.ClientVersion, 10), g.ClientFingerprint[:], string(scopes), g.Resource, g.CreatedAt, g.ExpiresAt, string(workload))
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	} else if i.Transition != revokeAccess {
		state := "active"
		if i.Transition == denyInteraction || i.Transition == rejectReplay || i.Transition == revokeFamily {
			state = "revoked"
		}
		grantScopes := scopes
		if i.Transition != approveInteraction {
			grantScopes, err = json.Marshal(g.Scopes)
			if err != nil {
				return identity.UnavailableError{}
			}
			defer clear(grantScopes)
		}
		n, err := w.Exec(ctx, `UPDATE `+s+`.grants SET state=$3,scopes=$4::jsonb,version=version+1 WHERE grant_id=$1 AND version=$2::numeric AND state='active'`, g.ID, strconv.FormatUint(g.Version, 10), state, string(grantScopes))
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	}
	if i.Transition == approveInteraction || i.Transition == denyInteraction || i.Transition == exchangeCode || i.Transition == rotateRefresh {
		n, err := w.Exec(ctx, `UPDATE `+s+`.artifacts SET state='consumed',consumed_by=$4 WHERE digest_version=$1 AND digest=$2 AND kind=$3 AND state='active'`, i.Target.KeyVersion, i.Target.Sum[:], int16(i.TargetKind), string(i.Binding.CommandID))
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	}
	if i.Transition == denyInteraction || i.Transition == rejectReplay || i.Transition == revokeFamily {
		if _, err := w.Exec(ctx, `UPDATE `+s+`.artifacts SET state='revoked' WHERE grant_id=$1 AND state='active'`, g.ID); err != nil {
			return err
		}
	}
	if i.Transition == revokeAccess {
		n, err := w.Exec(ctx, `UPDATE `+s+`.artifacts SET state='revoked' WHERE digest_version=$1 AND digest=$2 AND kind=$3 AND state='active'`, i.Target.KeyVersion, i.Target.Sum[:], int16(oauth.TokenAccess))
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	}
	if i.Transition == approveInteraction {
		// An independent consent row is never inferred from the grant's version.
		// The frozen absence/ID/version is fenced in this same Work before and
		// after mutation; another grant cannot silently replace its identity.
		var n int64
		var err error
		if p.store.config.ConsentManagement {
			fp := clientFingerprint(p.client)
			if i.Consent.Created {
				n, err = w.Exec(ctx, `INSERT INTO `+s+`.consents(consent_id,tenant_id,user_id,client_id,client_version,scopes,granted_at,version,client_fingerprint) VALUES($7,$1,$2,$3,$4::numeric,$5::jsonb,$6,1,$8)`, string(g.Tenant), string(g.User), g.ClientID, strconv.FormatUint(g.ClientVersion, 10), string(scopes), i.CreatedAt, i.Consent.ID, fp[:])
			} else {
				n, err = w.Exec(ctx, `UPDATE `+s+`.consents SET client_version=$4::numeric,scopes=$5::jsonb,granted_at=$6,version=$9::numeric,client_fingerprint=$10 WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3 AND consent_id=$7 AND version=$8::numeric`, string(g.Tenant), string(g.User), g.ClientID, strconv.FormatUint(g.ClientVersion, 10), string(scopes), i.CreatedAt, i.Consent.ID, strconv.FormatUint(i.Consent.BeforeVersion, 10), strconv.FormatUint(i.Consent.AfterVersion, 10), fp[:])
			}
		} else if i.Consent.Created {
			n, err = w.Exec(ctx, `INSERT INTO `+s+`.consents(consent_id,tenant_id,user_id,client_id,client_version,scopes,granted_at,version) VALUES($7,$1,$2,$3,$4::numeric,$5::jsonb,$6,1)`, string(g.Tenant), string(g.User), g.ClientID, strconv.FormatUint(g.ClientVersion, 10), string(scopes), i.CreatedAt, i.Consent.ID)
		} else {
			n, err = w.Exec(ctx, `UPDATE `+s+`.consents SET client_version=$4::numeric,scopes=$5::jsonb,granted_at=$6,version=$9::numeric WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3 AND consent_id=$7 AND version=$8::numeric`, string(g.Tenant), string(g.User), g.ClientID, strconv.FormatUint(g.ClientVersion, 10), string(scopes), i.CreatedAt, i.Consent.ID, strconv.FormatUint(i.Consent.BeforeVersion, 10), strconv.FormatUint(i.Consent.AfterVersion, 10))
		}
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
		if p.store.config.ConsentManagement {
			if err := p.bindApprovedConsent(ctx, w); err != nil {
				return err
			}
		}
		if err := w.RecordOAuthConsent(p, kernel.OAuthConsentMutation{ID: i.Consent.ID, BeforeVersion: i.Consent.BeforeVersion, AfterVersion: i.Consent.AfterVersion, Created: i.Consent.Created}); err != nil {
			return err
		}
	}
	payload, err := json.Marshal(artifactPayload{Schema: 1, Request: i.Request, Scopes: i.Scopes, Subject: p.output.Subject, SigningKeyID: p.output.SigningKeyID})
	if err != nil {
		return identity.UnavailableError{}
	}
	defer clear(payload)
	var parent any
	if i.TargetID != "" {
		parent = i.TargetID
	}
	for _, artifact := range p.output.Artifacts {
		columns, values := "", ""
		args := []any{artifact.Digest.KeyVersion, artifact.Digest.Sum[:], int16(artifact.Kind), g.ClientID, g.ID, i.CreatedAt, artifact.ExpiresAt, string(artifact.Transition), string(artifact.Replay), string(payload), artifact.ID, parent, string(i.Binding.CommandID)}
		if workloadSelected(p.store.config.Protocol.Clients) {
			columns = ",workload_only"
			values = ",$14"
			args = append(args, g.Workload != nil)
		}
		n, err := w.Exec(ctx, `INSERT INTO `+s+`.artifacts(artifact_id,digest_version,digest,kind,client_id,grant_id,created_at,expires_at,state,transition_command,replay_command,payload,parent_artifact_id,issued_by`+columns+`) VALUES($11,$1,$2,$3,$4,$5,$6,$7,'active',$8,$9,$10::jsonb,$12::text,$13`+values+`)`, args...)
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	}
	life := p.lifecycle()
	digest := effectDigest(i.Binding, p.registration(), life)
	n, err := w.Exec(ctx, `INSERT INTO `+s+`.effects(tenant_id,command_id,operation_id,record_id,grant_id,before_version,after_version,binding_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8)`, string(g.Tenant), string(i.Binding.CommandID), i.Binding.OperationID, i.Binding.RecordID, g.ID, strconv.FormatUint(life.BeforeVersion, 10), strconv.FormatUint(life.AfterVersion, 10), digest[:])
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func effectDigest(b identity.CommandBinding, f kernel.FeatureRegistration, l kernel.LifecyclePlan) [32]byte {
	wire, _ := json.Marshal(struct {
		Profile   string
		Binding   identity.CommandBinding
		Feature   kernel.FeatureRegistration
		Lifecycle kernel.LifecyclePlan
	}{"oauth-participant-effect-v1", b, f, l})
	defer clear(wire)
	return sha256.Sum256(wire)
}

// RecoverParticipant observes immutable participant evidence for the original
// command transition. Today's grant/artifact state never manufactures a receipt;
// the sole coordinator separately reconciles its journal, audit and lifecycle.
func (p *phase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, f, life, err := w.FeatureScope(p)
	if err != nil || f.Contributor != p.Descriptor() || f.Operation != p.operation(b.OperationID) || !oauthLifecycle(life.EventType) || life.AfterVersion != life.BeforeVersion+1 {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	ownerColumn := "grant_id"
	if b.OperationID == "identity.oauth-server.consent-delete" {
		ownerColumn = "consent_id"
	}
	rows, err := w.Query(ctx, `SELECT `+ownerColumn+`,before_version::text,after_version::text,binding_digest FROM `+p.store.schema+`.effects WHERE tenant_id=$1 AND command_id=$2 AND operation_id=$3 AND record_id=$4`, string(b.TenantID), string(b.CommandID), b.OperationID, b.RecordID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, rows.Err()
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var grant, before, after string
	var digest []byte
	if rows.Scan(&grant, &before, &after, &digest) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	want := effectDigest(b, f, life)
	if before != strconv.FormatUint(life.BeforeVersion, 10) || after != strconv.FormatUint(life.AfterVersion, 10) || subtle.ConstantTimeCompare(digest, want[:]) != 1 || grant == "" {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if b.OperationID == "identity.oauth-server.consent-delete" && grant != b.RecordID {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}

func oauthLifecycle(event string) bool {
	switch event {
	case "grant.created.v1", "grant.authorized.v1", "grant.scope_changed.v1", "grant.code_exchanged.v1", "grant.refresh_rotated.v1", "grant.revoked.v1", "oauth_access.revoked.v1", "consent.revoked.v1":
		return true
	default:
		return false
	}
}
