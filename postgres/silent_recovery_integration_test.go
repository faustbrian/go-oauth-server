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
	"golang.org/x/oauth2"
)

func TestNativeOIDCSilentRequiredEffectsAndOriginalCommitRecovery(t *testing.T) {
	for _, mode := range []string{"risk", "audit", "outbox", "before", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			var tracking, provisional atomic.Bool
			fault := &oauthCommitFault{before: mode == "before", beforeWrite: func(wire []byte) {
				if tracking.Load() && bytes.Contains(wire, []byte(`INSERT INTO "oauth_store".grants`)) {
					provisional.Store(true)
				}
			}}
			f := passwordFixture(t, fault)
			service, _, _ := silentOIDCFixture(t, &f, time.Minute)
			oidcCode(t, f, service, "explicit-fault-original")
			state := func() [5]int {
				var counts [5]int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.artifacts),(SELECT count(*) FROM oauth_store.effects),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.authorize' AND outcome=1),(SELECT count(*) FROM public.outbox_messages WHERE topic='grant.created.v1')`).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4]); err != nil {
					t.Fatal(err)
				}
				return counts
			}
			before := state()
			var version, generation string
			var granted, expiry time.Time
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,generation::text,granted_at,expires_at FROM oauth_store.consents`).Scan(&version, &generation, &granted, &expiry); err != nil {
				t.Fatal(err)
			}
			var err error
			switch mode {
			case "risk":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE risk_store.counter_snapshots RENAME TO unavailable_snapshots`)
			case "audit":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE audit.records ADD CONSTRAINT refuse_silent CHECK(action<>'identity.oauth_server.authorize') NOT VALID`)
			case "outbox":
				_, err = f.pool.Raw().Exec(f.ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT refuse_silent CHECK(topic<>'grant.created.v1') NOT VALID`)
			default:
				fault.armed.Store(true)
			}
			if err != nil {
				t.Fatal(err)
			}
			tracking.Store(true)
			out, err := service.Authorize(f.ctx, silentRequest(f, oauth2.GenerateVerifier()))
			if err == nil || out.Code != (oauth.Token{}) || out.Continuation != (oauth.Token{}) || out.RedirectURI != "" || mode != "risk" && !provisional.Load() {
				t.Fatal("required silent failure did not suppress actual provisional issuance", err)
			}
			if mode == "before" || mode == "unknown" {
				if !fault.hit.Load() || out.Outcome != oauth.AuthorizationUnknown || out.CommandID == "" {
					t.Fatal("actual silent COMMIT ambiguity was guessed or seam missed")
				}
				fresh, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
				if err != nil {
					t.Fatal(err)
				}
				request := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.authorize", CommandID: out.CommandID, ClientID: "public-web", TenantID: f.tenant, Session: f.browser}
				metadata, err := fresh.Recover(f.ctx, request)
				want := identity.CommitOutcomeCommitted
				if mode == "before" {
					want = identity.CommitOutcomeNotCommitted
					if err != nil || metadata.Outcome != identity.CommitOutcomeInProgress {
						t.Fatal("live original silent pending preparation not observational", err)
					}
				}
				deadline := time.Now().Add(8 * time.Second)
				for metadata.Outcome != want {
					if time.Now().After(deadline) {
						t.Fatal("original silent recovery did not reconcile", err)
					}
					waitAuthenticationBoundary(t, f, time.Now().Add(100*time.Millisecond))
					metadata, err = fresh.Recover(f.ctx, request)
					if err != nil && !errors.Is(err, oauth.ErrUnavailable) {
						t.Fatal("original silent recovery rejected", err)
					}
				}
				for range 2 {
					again, err := fresh.Recover(f.ctx, request)
					if err != nil && !(mode == "before" && errors.Is(err, oauth.ErrUnavailable)) || again.CommandID != request.CommandID || again.Outcome != want {
						t.Fatal("original silent metadata repetition changed outcome", err)
					}
				}
			}
			delta := 0
			if mode == "unknown" {
				delta = 1
			}
			after := state()
			for i := range after {
				if after[i] != before[i]+delta {
					t.Fatal("silent rollback/recovery repeated or lost grant/code/effects/audit/outbox")
				}
			}
			var currentVersion, currentGeneration string
			var currentGranted, currentExpiry time.Time
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,generation::text,granted_at,expires_at FROM oauth_store.consents`).Scan(&currentVersion, &currentGeneration, &currentGranted, &currentExpiry); err != nil || currentVersion != version || currentGeneration != generation || !currentGranted.Equal(granted) || !currentExpiry.Equal(expiry) {
				t.Fatal("silent failure/recovery mutated or renewed original approval", err)
			}
		})
	}
}
