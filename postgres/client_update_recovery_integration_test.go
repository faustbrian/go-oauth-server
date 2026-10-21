//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

func TestNativeClientUpdateRequiredEffectsAndOriginalRecovery(t *testing.T) {
	for _, mode := range []string{"risk", "audit", "outbox", "before", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			var provisional atomic.Bool
			fault := &oauthCommitFault{before: mode == "before", beforeWrite: func(wire []byte) {
				if bytes.Contains(wire, []byte(`UPDATE "oauth_store".managed_clients SET version=version+1,registration=$2::jsonb`)) {
					provisional.Store(true)
				}
			}}
			f := passwordFixture(t, fault)
			enableClientUpdates(t, &f)
			s, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			created, err := s.ClientCreate(f.ctx, clientCreateRequest(t, f, "update-fault-create"))
			if err != nil {
				t.Fatal(err)
			}
			var originalRegistration, originalDigest []byte
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&originalRegistration, &originalDigest); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "risk":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE risk_store.counter_snapshots RENAME TO unavailable_snapshots`)
			case "audit":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE audit.records ADD CONSTRAINT refuse_update CHECK(action<>'identity.oauth_server.update_client')`)
			case "outbox":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_update CHECK(topic<>'oauth_client.configuration_changed.v1') NOT VALID`)
			default:
				fault.armed.Store(true)
			}
			if err != nil {
				t.Fatal(err)
			}
			r := clientUpdateRequest(t, f, created.Client, "update-fault-original")
			out, err := s.ClientUpdate(f.ctx, r)
			if err == nil || out.Client.ID != "" || mode != "risk" && !provisional.Load() {
				t.Fatal("required failure did not suppress metadata after actual provisional work", err)
			}
			store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "before" || mode == "unknown" {
				if !fault.hit.Load() || out.Completion.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("actual pre/post COMMIT seam missed")
				}
				rr := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-update", CommandID: out.Completion.CommandID, ClientID: created.Client.ID, TenantID: f.tenant, Session: f.browser}
				metadata, err := store.Recover(f.ctx, rr)
				want := identity.CommitOutcomeCommitted
				if mode == "before" {
					want = identity.CommitOutcomeNotCommitted
					if err != nil || metadata.Outcome != identity.CommitOutcomeInProgress {
						t.Fatal("original live pending update not observational", err)
					}
				}
				deadline := time.Now().Add(8 * time.Second)
				for metadata.Outcome != want {
					if time.Now().After(deadline) {
						t.Fatal("original update recovery did not reconcile", err)
					}
					select {
					case <-time.After(100 * time.Millisecond):
					case <-f.ctx.Done():
						t.Fatal("original recovery canceled")
					}
					metadata, err = store.Recover(f.ctx, rr)
					if err != nil && !errors.Is(err, oauth.ErrUnavailable) {
						t.Fatal("original update recovery rejected", err)
					}
				}
				for i := 0; i < 2; i++ {
					again, err := store.Recover(f.ctx, rr)
					if err != nil && !(mode == "before" && errors.Is(err, oauth.ErrUnavailable)) || again.CommandID != rr.CommandID || again.Outcome != want {
						t.Fatal("original update metadata unstable", err)
					}
				}
			}
			var version, generation string
			var registration, digest []byte
			var effects, audits, events int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,secret_version::text,registration,secret_digest,(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-update'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.update_client' AND outcome=1),(SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_client.configuration_changed.v1') FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&version, &generation, &registration, &digest, &effects, &audits, &events); err != nil {
				t.Fatal(err)
			}
			want, wantVersion := 0, "1"
			if mode == "unknown" {
				want, wantVersion = 1, "2"
			}
			if version != wantVersion || generation != "1" || !bytes.Equal(digest, originalDigest) || effects != want || audits != want || events != want || mode != "unknown" && !bytes.Equal(registration, originalRegistration) {
				t.Fatal("required failure violated atomic registration/secret/effect/audit/outbox state")
			}
			if mode == "before" {
				retry, err := s.ClientUpdate(f.ctx, r)
				if err != nil && !errors.Is(err, oauth.ErrUnavailable) || retry.Completion.CommandID != out.Completion.CommandID || retry.Completion.Outcome != identity.CommitOutcomeNotCommitted || retry.Client.ID != "" {
					t.Fatal("terminal noncommit retry changed original outcome", err)
				}
			}
			if mode == "unknown" {
				retry, err := s.ClientUpdate(f.ctx, r)
				if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != out.Completion.CommandID || retry.Client.Version != 2 {
					t.Fatal("lost commit original retry not stable", err)
				}
				changed := clientUpdateRequest(t, f, retry.Client, "update-after-original")
				changed.Redirects = []string{"https://managed.example/callback"}
				if next, err := s.ClientUpdate(f.ctx, changed); err != nil || next.Client.Version != 3 {
					t.Fatal("later unrelated replacement control", err)
				}
				historical, err := s.ClientUpdate(f.ctx, r)
				if err != nil || historical.Client.Version != 2 || historical.Client.Redirects[0] != "https://managed.example/new" {
					t.Fatal("retry overwrote original result from today's aggregate", err)
				}
				var originalEffects int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.effects WHERE command_id=$1`, string(out.Completion.CommandID)).Scan(&originalEffects); err != nil || originalEffects != 1 {
					t.Fatal("original replacement effect repeated", err)
				}
			}
			switch mode {
			case "risk":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE risk_store.unavailable_snapshots RENAME TO counter_snapshots`)
			case "audit":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE audit.records DROP CONSTRAINT refuse_update`)
			case "outbox":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages DROP CONSTRAINT refuse_update`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode != "unknown" {
				if positive, err := s.ClientUpdate(f.ctx, clientUpdateRequest(t, f, created.Client, "update-restored-authority")); err != nil || positive.Client.Version != 2 {
					t.Fatal("restored required owners positive control", err)
				}
			}
		})
	}
}

func TestNativeClientUpdatePopulatedForwardHistoryRetainsLegacyPreparationAndSecretSlots(t *testing.T) {
	fault := &oauthCommitFault{before: true}
	f := passwordFixture(t, fault)
	enableClientRotation(t, &f)
	f.oauth.Protocol.ManagedClients.Redirects = []string{"https://managed.example/callback", "https://managed.example/new"}
	legacy, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	active, err := legacy.ClientCreate(f.ctx, clientCreateRequest(t, f, "populated-active"))
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := legacy.ClientCreate(f.ctx, clientCreateRequest(t, f, "populated-deleted"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ClientDelete(f.ctx, clientRotationRequest(t, f, deleted.Client, "populated-delete", 0).Management); err != nil {
		t.Fatal(err)
	}
	rotated, err := legacy.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, active.Client, "populated-rotate", time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	originalRequest := clientRotationRequest(t, f, rotated.Client, "legacy-retained-rotate", time.Minute)
	fault.armed.Store(true)
	lost, err := legacy.ClientRotateSecret(f.ctx, originalRequest)
	if err == nil || !fault.hit.Load() || lost.Completion.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("genuine legacy encrypted preparation not retained")
	}
	type snapshot struct {
		wire, current, previous                 []byte
		version, generation, predecessor, state string
		expiry                                  *time.Time
	}
	read := func(id string) snapshot {
		var r snapshot
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT registration,secret_digest,previous_secret_digest,version::text,secret_version::text,COALESCE(previous_secret_version::text,''),state,previous_secret_expires_at FROM oauth_store.managed_clients WHERE client_id=$1`, id).Scan(&r.wire, &r.current, &r.previous, &r.version, &r.generation, &r.predecessor, &r.state, &r.expiry); err != nil {
			t.Fatal(err)
		}
		return r
	}
	before := []snapshot{read(active.Client.ID), read(deleted.Client.ID)}
	installClientUpdates(t, &f)
	for i, id := range []string{active.Client.ID, deleted.Client.ID} {
		a, b := before[i], read(id)
		if !bytes.Equal(a.wire, b.wire) || !bytes.Equal(a.current, b.current) || !bytes.Equal(a.previous, b.previous) || a.version != b.version || a.generation != b.generation || a.predecessor != b.predecessor || a.state != b.state || (a.expiry == nil) != (b.expiry == nil) || a.expiry != nil && !a.expiry.Equal(*b.expiry) {
			t.Fatal("forward metadata history rewrote populated authority/digest/tombstone")
		}
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	rr := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-rotate-secret", CommandID: lost.Completion.CommandID, ClientID: active.Client.ID, TenantID: f.tenant, Session: f.browser}
	metadata, err := store.Recover(f.ctx, rr)
	if err != nil || metadata.Outcome != identity.CommitOutcomeInProgress {
		t.Fatal("new selected owner cannot restore original absent-secret-generation preparation", err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for metadata.Outcome != identity.CommitOutcomeNotCommitted {
		if time.Now().After(deadline) {
			t.Fatal("legacy original preparation failed recovery", err)
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-f.ctx.Done():
			t.Fatal("legacy recovery canceled")
		}
		metadata, err = store.Recover(f.ctx, rr)
		if err != nil && !errors.Is(err, oauth.ErrUnavailable) {
			t.Fatal(err)
		}
	}
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.ClientUpdate(f.ctx, clientUpdateRequest(t, f, rotated.Client, "populated-replacement"))
	if err != nil || updated.Client.Version != 3 {
		t.Fatal("populated original generation cannot update", err)
	}
	unchanged := read(active.Client.ID)
	if unchanged.generation != "2" || unchanged.predecessor != "1" || !bytes.Equal(unchanged.current, before[0].current) || !bytes.Equal(unchanged.previous, before[0].previous) || !unchanged.expiry.Equal(*before[0].expiry) {
		t.Fatal("first separated mutation changed populated secret slots")
	}
}
