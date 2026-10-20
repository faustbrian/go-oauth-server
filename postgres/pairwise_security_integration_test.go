//go:build integration && oauthflow

package oauthpostgres_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"golang.org/x/oauth2"
)

func TestNativeOIDCPairwiseKeyCustodyAuthenticationAndRewrap(t *testing.T) {
	f := passwordFixture(t)
	service, _, _, store, _ := pairwiseFixture(t, &f)
	if _, err := service.Authorize(f.ctx, pairwiseBegin(f)); err != nil {
		t.Fatal(err)
	}
	keys, _, err := store.SubjectKeyRegistrations(f.ctx, "subjects", 1)
	if err != nil || len(keys) != 1 {
		t.Fatal("native key custody unavailable", err)
	}
	original := keys[0]
	for _, change := range []func(*oauth.OIDCSubjectKeyRegistration){
		func(r *oauth.OIDCSubjectKeyRegistration) { r.Environment = "foreign" },
		func(r *oauth.OIDCSubjectKeyRegistration) { r.KeyVersion = 2 },
		func(r *oauth.OIDCSubjectKeyRegistration) { r.Commitment[0] ^= 1 },
		func(r *oauth.OIDCSubjectKeyRegistration) {
			r.Envelope = append([]byte(nil), r.Envelope...)
			r.Envelope[0] ^= 1
		},
	} {
		altered := original
		change(&altered)
		if err := store.InstallSubjectKey(f.ctx, altered); !errors.Is(err, oauth.ErrAccessDenied) && !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("unauthenticated/foreign key custody was staged", err)
		}
	}
	if err := store.RetireSubjectKey(f.ctx, "subjects", 1, 1); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("active derivation writer retired", err)
	}
	cipher, _ := envelope.NewService(f.keys)
	aad, _ := envelope.NewContext(map[string]string{"profile": "golib.oidc.pairwise-key.v1", "issuer": f.oauth.Protocol.Issuer.String(), "environment": f.oauth.Protocol.Environment, "policy_id": "subjects", "policy_version": "1", "key_version": "1"})
	material := [32]byte{1, 2, 3}
	sealed, err := cipher.Encrypt(f.ctx, envelope.EncryptRequest{Plaintext: material[:], KeyReference: "oauth-envelope-next", Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	rewrapped := original
	rewrapped.Envelope, err = sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.InstallSubjectKey(f.ctx, rewrapped); err != nil {
		t.Fatal("same-material rewrap denied", err)
	}
	keys, active, err := store.SubjectKeyRegistrations(f.ctx, "subjects", 1)
	if err != nil || len(keys) != 1 || active != 1 || keys[0].Commitment != original.Commitment {
		t.Fatal("rewrap changed key identity/writer", err)
	}
	restored, err := envelope.ParseEnvelope(keys[0].Envelope)
	if err != nil || restored.KeyReference() != "oauth-envelope-next" {
		t.Fatal("new wrapping custody did not persist", err)
	}
	var binding string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT subject FROM oauth_store.subject_bindings`).Scan(&binding); err != nil || binding == "" {
		t.Fatal("rewrap removed original native binding", err)
	}
	next := pairwisePolicy(t, f, 2, [32]byte{8})
	key2, _ := next.KeyRegistration(2)
	if err := store.InstallSubjectKey(f.ctx, key2); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateSubjectKey(f.ctx, "subjects", 1, 2); err != nil {
		t.Fatal(err)
	}
	if err := store.RetireSubjectKey(f.ctx, "subjects", 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.InstallSubjectKey(f.ctx, original); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("retired key version was resurrected", err)
	}
	var after string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT subject FROM oauth_store.subject_bindings`).Scan(&after); err != nil || after != binding {
		t.Fatal("rewrap/retirement reassigned stable subject", err)
	}
}

func pairwiseBegin(f authenticatedPasswordFixture) oauth.AuthorizeRequest {
	return oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: "public-web", RedirectURI: "https://client.example/callback", Resource: f.oauth.Protocol.Resource, Scopes: []string{"identity:read", "openid"}, Nonce: "pairwise-bound-nonce", CodeChallenge: oauth2.S256ChallengeFromVerifier(oauth2.GenerateVerifier())}}
}

func TestNativeOIDCPairwiseMissingForeignAndRetiredCustodyDenies(t *testing.T) {
	for _, mode := range []string{"missing-policy", "foreign-policy", "foreign-key", "retired-key", "missing-key", "missing-binding"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			service, _, signer, store, _ := pairwiseFixture(t, &f)
			if mode == "missing-binding" {
				code, verifier := oidcCode(t, f, service, "missing-binding")
				if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM oauth_store.grant_subject_bindings`); err != nil {
					t.Fatal(err)
				}
				out, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
				if err == nil {
					t.Fatal("missing original grant binding fell back to key derivation")
				}
				if _, err := out.IDToken.Reveal(); err == nil {
					t.Fatal("missing original binding exposed authentication token")
				}
				var active int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE kind=2 AND state='active'`).Scan(&active); err != nil || active != 1 {
					t.Fatal("missing binding consumed original code", err)
				}
				return
			}
			var policy *op.SubjectPolicy
			switch mode {
			case "foreign-policy":
				policy = pairwisePolicyNamed(t, f, "foreign", 1, 1, [32]byte{8})
			case "foreign-key":
				policy = pairwisePolicy(t, f, 2, [32]byte{8})
			case "retired-key":
				next := pairwisePolicy(t, f, 2, [32]byte{8})
				key, _ := next.KeyRegistration(2)
				if err := store.InstallSubjectKey(f.ctx, key); err != nil {
					t.Fatal(err)
				}
				if err := store.ActivateSubjectKey(f.ctx, "subjects", 1, 2); err != nil {
					t.Fatal(err)
				}
				if err := store.RetireSubjectKey(f.ctx, "subjects", 1, 1); err != nil {
					t.Fatal(err)
				}
			case "missing-key":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.subject_selection SET key_version=NULL`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "missing-policy" || policy != nil {
				service, _, _ = pairwiseService(t, f, signer, policy)
			}
			out, err := service.Authorize(f.ctx, pairwiseBegin(f))
			if !errors.Is(err, oauth.ErrAccessDenied) {
				t.Fatal("missing/foreign/retired policy custody admitted a native grant", err)
			}
			if _, err := out.Continuation.Reveal(); err == nil {
				t.Fatal("denied subject custody exposed continuation")
			}
			var count int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.grants)+(SELECT count(*) FROM oauth_store.subject_bindings)`).Scan(&count); err != nil || count != 0 {
				t.Fatal("denied subject custody created protected state", err)
			}
		})
	}
}

func TestNativeOIDCPairwiseBindingAtomicRollbackUnknownAndContention(t *testing.T) {
	for _, mode := range []string{"rollback", "unknown", "contention"} {
		t.Run(mode, func(t *testing.T) {
			fault := &oauthCommitFault{before: mode == "rollback"}
			f := passwordFixture(t, fault)
			service, _, _, store, _ := pairwiseFixture(t, &f)
			request := pairwiseBegin(f)
			grantsExpected := 1
			if mode == "contention" {
				grantsExpected = 0 // Independent commands may conflict on current risk counters.
				var wg sync.WaitGroup
				errs := make(chan error, 2)
				for range 2 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						out, err := service.Authorize(f.ctx, request)
						if err == nil && out.Outcome != oauth.ConsentRequired {
							err = oauth.ErrAccessDenied
						}
						errs <- err
					}()
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					if err == nil {
						grantsExpected++
					} else if !errors.Is(err, oauth.ErrAccessDenied) {
						t.Fatal("contending authorization returned an unexpected outcome", err)
					}
				}
				if grantsExpected == 0 {
					t.Fatal("no contending authorization committed")
				}
			} else {
				fault.armed.Store(true)
				out, err := service.Authorize(f.ctx, request)
				if !fault.hit.Load() || err == nil || out.Outcome != oauth.AuthorizationUnknown {
					t.Fatal("actual binding/grant transaction fault was not unknown", err)
				}
				if _, err := out.Continuation.Reveal(); err == nil {
					t.Fatal("unknown binding commit redelivered continuation")
				}
				recovered, err := store.Recover(f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.authorize", CommandID: out.CommandID, ClientID: "public-web", TenantID: f.tenant, Session: f.browser})
				if err != nil || recovered.CommandID != out.CommandID || mode == "unknown" && recovered.Outcome != identity.CommitOutcomeCommitted || mode == "rollback" && recovered.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("binding fault reconciliation changed original durability", err)
				}
				if mode == "rollback" {
					grantsExpected = 0
				}
			}
			var bindings, grants, associations int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.subject_bindings),(SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.grant_subject_bindings)`).Scan(&bindings, &grants, &associations); err != nil || grants != grantsExpected || associations != grantsExpected || bindings != min(grantsExpected, 1) {
				t.Fatal("binding/grant association was not one atomic stable effect", err)
			}
		})
	}
}

func TestNativeOIDCPairwiseSelectionAndRetirementSerialize(t *testing.T) {
	f := passwordFixture(t)
	_, _, _, store, _ := pairwiseFixture(t, &f)
	policy := pairwisePolicy(t, f, 2, [32]byte{8})
	key, _ := policy.KeyRegistration(2)
	if err := store.InstallSubjectKey(f.ctx, key); err != nil {
		t.Fatal(err)
	}
	blocker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(f.ctx)
	if _, err := blocker.Exec(f.ctx, `SELECT key_version FROM oauth_store.subject_selection FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	activated, retired := make(chan error, 1), make(chan error, 1)
	go func() { activated <- store.ActivateSubjectKey(f.ctx, "subjects", 1, 2) }()
	go func() { retired <- store.RetireSubjectKey(f.ctx, "subjects", 1, 2) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var waiting int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%subject_selection%'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("subject lifecycle did not reach common controlled selection lock")
		}
		time.Sleep(time.Millisecond)
	}
	if err := blocker.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	activationErr, retirementErr := <-activated, <-retired
	if activationErr == nil && retirementErr == nil {
		t.Fatal("selection and retirement both succeeded for one key")
	}
	var retiredSelection bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT k.retired FROM oauth_store.subject_selection s JOIN oauth_store.subject_keys k USING(context_id,policy_id,policy_version,key_version)`).Scan(&retiredSelection); err != nil || retiredSelection {
		t.Fatal("native selected a retired subject writer", err)
	}
}
