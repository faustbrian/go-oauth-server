//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

func TestNativeManagedWorkloadRotationRejectsStaleObservedServiceAccountAuthority(t *testing.T) {
	f := passwordFixture(t)
	enableClientRotation(t, &f)
	w := installManagedWorkloadProfile(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.ClientCreate(f.ctx, managedWorkloadCreateRequest(t, f, w, "rotation-workload-fence-create"))
	if err != nil {
		t.Fatal(err)
	}
	barrier := &consentRaceBarrier{owner: f.oauth.Coordinator.AdmissionPolicy.Authorization, action: "identity.oauth-server.client-rotate-secret", ready: make(chan struct{}), release: make(chan struct{})}
	query, admission := *f.oauth.Coordinator.QueryPolicy, *f.oauth.Coordinator.AdmissionPolicy
	query.Authorization, admission.Authorization = barrier, barrier
	f.oauth.Coordinator.QueryPolicy, f.oauth.Coordinator.AdmissionPolicy = &query, &admission
	f.oauth.RequestKeys.Policy.Authorization = barrier
	late, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.WithValue(f.ctx, consentRaceKey{}, true))
	type answer struct {
		out oauth.ClientSecretRotationResult
		err error
	}
	done := make(chan answer, 1)
	joined := false
	defer func() {
		cancel()
		select {
		case <-barrier.release:
		default:
			close(barrier.release)
		}
		if !joined {
			<-done
		}
	}()
	r := clientRotationRequest(t, f, created.Client, "rotation-workload-fence-original", 0)
	go func() { out, err := late.ClientRotateSecret(ctx, r); done <- answer{out, err} }()
	select {
	case <-barrier.ready:
	case out := <-done:
		joined = true
		t.Fatal("rotation never reached its real prepared admission", out.err)
	case <-f.ctx.Done():
		t.Fatal("bounded rotation admission canceled")
	}
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err := authority.AdvanceAuthority(f.ctx, tx, authority.AuthorityScope{TenantID: authorization.TenantID(f.tenant), PolicyNamespace: "oauth-workloads", SubjectID: "oauth-worker"}, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	close(barrier.release)
	out := <-done
	joined = true
	if out.err == nil || out.out.Secret != (oauth.Token{}) {
		t.Fatal("stale observed machine authority rotated secret", out.err)
	}
	var version string
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-rotate-secret') FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&version, &effects); err != nil || version != "1" || effects != 0 {
		t.Fatal("stale machine rotation left effects", err)
	}
	if fresh, err := service.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, created.Client, "rotation-workload-current-epoch", 0)); err != nil || fresh.Client.Version != 2 {
		t.Fatal("actual current service-account epoch could not rotate", err)
	}
}

func TestNativeManagedWorkloadRotationFailsClosedAndRecoversUnknownMetadataOnly(t *testing.T) {
	for _, mode := range []string{"manager", "missing-client", "missing-authority", "authority-outage", "audit", "outbox", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			fault := &oauthCommitFault{}
			f := passwordFixture(t, fault)
			denied := enableClientRotation(t, &f)
			w := installManagedWorkloadProfile(t, &f)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			created, err := service.ClientCreate(f.ctx, managedWorkloadCreateRequest(t, f, w, "rotation-workload-denial-create"))
			if err != nil {
				t.Fatal(err)
			}
			r := clientRotationRequest(t, f, created.Client, "rotation-workload-denial-original", 0)
			switch mode {
			case "manager":
				denied.Store(true)
			case "missing-client":
				r.Management.ClientID = "managed.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			case "missing-authority":
				_, err = f.pool.Raw().Exec(f.ctx, `DELETE FROM public.authorization_subject_authorities WHERE policy_namespace='oauth-workloads'`)
			case "authority-outage":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.authorization_subject_authorities RENAME TO unavailable_rotation_authorities`)
			case "audit":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE audit.records ADD CONSTRAINT refuse_machine_rotation CHECK(action<>'identity.oauth_server.rotate_client_secret')`)
			case "outbox":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_machine_rotation CHECK(topic<>'oauth_client.secret_rotated.v1') NOT VALID`)
			case "unknown":
				fault.armed.Store(true)
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.ClientRotateSecret(f.ctx, r)
			if err == nil || out.Secret != (oauth.Token{}) {
				t.Fatal("denied/failed/unknown rotation revealed successor", err)
			}
			wantVersion, wantEffects := "1", 0
			if mode == "unknown" {
				if !fault.hit.Load() || out.Completion.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("original machine rotation did not reach COMMIT ambiguity")
				}
				store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				rr := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-rotate-secret", CommandID: out.Completion.CommandID, ClientID: created.Client.ID, TenantID: f.tenant, Session: f.browser}
				metadata, err := store.Recover(f.ctx, rr)
				if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted || metadata.CommandID != out.Completion.CommandID {
					t.Fatal("original machine rotation did not recover metadata", err)
				}
				retry, err := service.ClientRotateSecret(f.ctx, r)
				if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != out.Completion.CommandID || retry.Secret != (oauth.Token{}) {
					t.Fatal("unknown machine rotation retry redelivered or diverged", err)
				}
				wantVersion, wantEffects = "2", 1
			}
			var version string
			var effects, audits, events int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-rotate-secret'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.rotate_client_secret' AND outcome=1),(SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_client.secret_rotated.v1') FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&version, &effects, &audits, &events); err != nil || version != wantVersion || effects != wantEffects || audits != wantEffects || events != wantEffects {
				t.Fatal("rotation was not atomic with audit/lifecycle", mode, err)
			}
		})
	}
}

func TestNativeManagedWorkloadRotationRevealOverlapAndCurrentTokens(t *testing.T) {
	f := passwordFixture(t)
	enableClientRotation(t, &f)
	w := installManagedWorkloadProfile(t, &f)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.ClientCreate(f.ctx, managedWorkloadCreateRequest(t, f, w, "rotation-workload-create"))
	if err != nil {
		t.Fatal(err)
	}
	oldSecret, _ := created.Secret.Reveal()
	oldBasic := confidentialBasic(t, created.Client.ID, oldSecret)
	issued, err := service.Token(f.ctx, managedWorkloadTokenRequest(created.Client, oldBasic))
	if err != nil {
		t.Fatal("original managed workload cannot issue", err)
	}
	oldAccess, _ := issued.AccessToken.Reveal()
	r := clientRotationRequest(t, f, created.Client, "rotation-workload-original", 2*time.Second)
	rotated, err := service.ClientRotateSecret(f.ctx, r)
	if err != nil || rotated.Client.Version != 2 || rotated.Client.Workload == nil || rotated.Client.Workload.ID() != w.ID() || rotated.Completion.Outcome != identity.CommitOutcomeCommitted || rotated.PredecessorExpiresAt.IsZero() {
		t.Fatal("authorized managed workload rotation denied", err)
	}
	successor, err := rotated.Secret.Reveal()
	if err != nil || successor == oldSecret {
		t.Fatal("rotation did not reveal a distinct successor once", err)
	}
	if _, err := rotated.Secret.Reveal(); err == nil {
		t.Fatal("rotation secret revealed twice")
	}
	newBasic := confidentialBasic(t, created.Client.ID, successor)
	restarted, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	requireInactiveIntrospection(t, restarted, f.ctx, oauth.IntrospectRequest{ClientID: created.Client.ID, ClientAuthentication: newBasic, Token: oldAccess})
	for _, basic := range []oauth.ClientAuthentication{oldBasic, newBasic} {
		out, err := restarted.Token(f.ctx, managedWorkloadTokenRequest(rotated.Client, basic))
		if err != nil || out.AccessToken == (oauth.Token{}) || out.RefreshToken != (oauth.Token{}) {
			t.Fatal("bounded overlap could not issue current access-only authority", err)
		}
		access, _ := out.AccessToken.Reveal()
		if current, err := restarted.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: created.Client.ID, ClientAuthentication: newBasic, Token: access}); err != nil || !current.Active {
			t.Fatal("current machine access denied", err)
		}
	}
	retry, err := restarted.ClientRotateSecret(f.ctx, r)
	if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != rotated.Completion.CommandID || retry.Secret != (oauth.Token{}) || !retry.PredecessorExpiresAt.Equal(rotated.PredecessorExpiresAt) {
		t.Fatal("original workload rotation retry changed metadata or revealed secret", err)
	}
	changed := r
	changed.Overlap = time.Minute
	if _, err := restarted.ClientRotateSecret(f.ctx, changed); !errors.Is(err, oauth.ErrClientConflict) {
		t.Fatal("changed overlap reused original rotation key", err)
	}
	waitAuthenticationBoundary(t, f, rotated.PredecessorExpiresAt)
	if out, err := restarted.Token(f.ctx, managedWorkloadTokenRequest(rotated.Client, oldBasic)); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("expired predecessor issued machine authority")
	}
	if out, err := restarted.Token(f.ctx, managedWorkloadTokenRequest(rotated.Client, newBasic)); err != nil || out.AccessToken == (oauth.Token{}) {
		t.Fatal("successor stopped working after predecessor expiry", err)
	}
	second, err := restarted.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, rotated.Client, "rotation-workload-zero", 0))
	if err != nil || second.Client.Version != 3 || !second.PredecessorExpiresAt.IsZero() {
		t.Fatal("zero-overlap machine rotation failed", err)
	}
	latest, _ := second.Secret.Reveal()
	if out, err := restarted.Token(f.ctx, managedWorkloadTokenRequest(second.Client, newBasic)); err == nil || out.AccessToken != (oauth.Token{}) {
		t.Fatal("zero overlap retained predecessor")
	}
	if out, err := restarted.Token(f.ctx, managedWorkloadTokenRequest(second.Client, confidentialBasic(t, second.Client.ID, latest))); err != nil || out.AccessToken == (oauth.Token{}) {
		t.Fatal("latest managed workload secret denied", err)
	}
}
