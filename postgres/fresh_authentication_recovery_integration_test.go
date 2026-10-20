//go:build integration && oauthflow

package oauthpostgres_test

import (
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

func TestNativeOIDCFreshLoginUnknownAdoptionRecoversOriginalMetadata(t *testing.T) {
	for _, before := range []bool{false, true} {
		name := "lost-commit"
		if before {
			name = "before-commit"
		}
		t.Run(name, func(t *testing.T) {
			fault := &oauthCommitFault{before: before}
			f := passwordFixture(t, fault)
			service, _, _, _, _ := oidcFixture(t, &f)
			request := pairwiseBegin(f)
			request.Request.Prompt = "login"
			begin, err := service.Authorize(f.ctx, request)
			if err != nil || begin.Outcome != oauth.FreshAuthenticationRequired {
				t.Fatal("fresh continuation unavailable", err)
			}
			continuation, err := begin.Continuation.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			browser, csrf := f.signInAgain()
			fault.armed.Store(true)
			out, err := service.Continue(f.ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: browser, CSRF: csrf, ClientID: "public-web", Continuation: continuation, Origin: f.oauth.Protocol.Issuer.String(), Approve: true, Network: "192.0.2.1"})
			if !fault.hit.Load() || err == nil || out.Outcome != oauth.AuthorizationUnknown || out.CommandID == "" {
				t.Fatal("real fresh-source/code commit fault was not unknown", err)
			}
			if _, err := out.Code.Reveal(); err == nil {
				t.Fatal("unknown fresh-source adoption delivered code")
			}
			reconstructed, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.continue", CommandID: out.CommandID, ClientID: "public-web", TenantID: f.tenant, Session: browser, Token: continuation}
			metadata, err := reconstructed.Recover(f.ctx, recovery)
			if err != nil || !before && metadata.Outcome != identity.CommitOutcomeCommitted || before && metadata.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("fresh-source original metadata recovery lost authenticated caller scope", err)
			}
			if before {
				deadline := time.Now().Add(8 * time.Second)
				for metadata.Outcome != identity.CommitOutcomeNotCommitted {
					if time.Now().After(deadline) {
						t.Fatal("original fresh-source noncommit did not reconcile", err)
					}
					timer := time.NewTimer(100 * time.Millisecond)
					select {
					case <-timer.C:
					case <-f.ctx.Done():
						timer.Stop()
						t.Fatal("fresh recovery cancelled")
					}
					metadata, err = reconstructed.Recover(f.ctx, recovery)
					// The native journal retains dependency-failure on proven
					// noncommit. Its terminal outcome, not a nil error, proves
					// rollback; unavailable alone must never count as evidence.
					if err != nil && !(metadata.Outcome == identity.CommitOutcomeNotCommitted && errors.Is(err, oauth.ErrUnavailable)) {
						t.Fatal(err)
					}
				}
			}
			for range 2 {
				terminal, err := reconstructed.Recover(f.ctx, recovery)
				if terminal.Outcome != metadata.Outcome || terminal.CommandID != out.CommandID || err != nil && !(before && errors.Is(err, oauth.ErrUnavailable)) {
					t.Fatal("original terminal recovery changed historical classification", err)
				}
			}
			recovery.Session = f.browser
			if _, err := reconstructed.Recover(f.ctx, recovery); !errors.Is(err, oauth.ErrAccessDenied) {
				t.Fatal("old session recovered a different newly authenticated attempt", err)
			}
			var codes, consumed int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE kind=2),count(*) FILTER(WHERE kind=1 AND state='consumed') FROM oauth_store.artifacts`).Scan(&codes, &consumed); err != nil || before && (codes != 0 || consumed != 0) || !before && (codes != 1 || consumed != 1) {
				t.Fatal("fresh adoption/code/consumption were not atomic", err)
			}
		})
	}
}
