//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

func publicUpdateFixture(t *testing.T, faults ...*oauthCommitFault) (authenticatedPasswordFixture, *oauth.Service, oauth.Client) {
	t.Helper()
	f := passwordFixture(t, faults...)
	enableClientUpdates(t, &f)
	installPublicClients(t, &f)
	s, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	r := clientCreateRequest(t, f, "public-update-create")
	r.Public = true
	created, err := s.ClientCreate(f.ctx, r)
	if err != nil || !created.Client.Public || created.Secret != (oauth.Token{}) {
		t.Fatal("real manager could not create no-secret public client", err)
	}
	return f, s, created.Client
}

func publicClientUpdateRequest(t *testing.T, f authenticatedPasswordFixture, c oauth.Client, key string) oauth.ClientUpdateRequest {
	t.Helper()
	r := clientUpdateRequest(t, f, c, key)
	r.Management.Public = c.Public
	return r
}

func requirePublicUpdateState(t *testing.T, f authenticatedPasswordFixture, c oauth.Client, version, state string, updateEffects int) {
	t.Helper()
	var v, generation, st string
	var noSecrets bool
	var effects, audits, events int
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,secret_version::text,state,secret_digest IS NULL AND previous_secret_digest IS NULL AND previous_secret_version IS NULL AND previous_secret_expires_at IS NULL,(SELECT count(*) FROM oauth_store.effects WHERE client_id=$1 AND operation_id='identity.oauth-server.client-update'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.update_client' AND outcome=1),(SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_client.configuration_changed.v1') FROM oauth_store.managed_clients WHERE client_id=$1`, c.ID).Scan(&v, &generation, &st, &noSecrets, &effects, &audits, &events)
	if err != nil || v != version || generation != "1" || st != state || !noSecrets || effects != updateEffects || audits != updateEffects || events != updateEffects {
		t.Fatal("public update changed class/secret generation or duplicated effects", err, v, generation, st, noSecrets, effects, audits, events)
	}
}

func TestNativePublicClientUpdateCompleteNoSecretConsumer(t *testing.T) {
	f, original, client := publicUpdateFixture(t)
	access, refresh := issuedConfidentialTokens(t, f, original, client, oauth.ClientAuthentication{})
	code, proof := confidentialCode(t, f, original, client)
	consents, err := original.ConsentList(f.ctx, oauth.ConsentListRequest{Consent: ownConsentCommand(t, f, oauth.ConsentEnumerate, "", 0)})
	if err != nil || len(consents.Page.Items()) != 1 {
		t.Fatal("original public consent", err)
	}
	oldConsent := consents.Page.Items()[0]
	verifier, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, resourcePolicy(f, client))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := verifier.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"}); err != nil || p.RequireScope("identity:read") != nil {
		t.Fatal("original public resource control", err)
	}
	fresh, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	read := clientReadRequest(f, 0)
	read.ClientID = client.ID
	discovered, err := fresh.ClientGet(f.ctx, read)
	if err != nil || !discovered.Client.Public || discovered.Client.Version != client.Version {
		t.Fatal("fresh manager could not discover current public version", err)
	}
	r := publicClientUpdateRequest(t, f, discovered.Client, "public-update-original")
	updated, err := fresh.ClientUpdate(f.ctx, r)
	if err != nil || updated.Completion.Outcome != identity.CommitOutcomeCommitted || updated.Completion.Replayed || updated.Client.Version != 2 || !updated.Client.Public || updated.Client.AuthenticationMethod != "none" || updated.Client.Owner != client.Owner || updated.Client.ID != client.ID || updated.Client.Resource != client.Resource || !slices.Equal(updated.Client.Redirects, r.Redirects) || !slices.Equal(updated.Client.Scopes, r.Scopes) {
		t.Fatal("current public client could not replace exact metadata without changing class", err)
	}
	requirePublicUpdateState(t, f, client, "2", "active", 1)
	if out, err := original.ConsentGet(f.ctx, oauth.ConsentGetRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRead, oldConsent.ID(), 0)}); err == nil || out.Consent.ID() != "" {
		t.Fatal("old public consent survived changed registration authority")
	}
	requireInvalidResource(t, verifier, f.ctx, access)
	for _, request := range []oauth.TokenRequest{
		{GrantType: oauth.AuthorizationCodeGrant, ClientID: client.ID, Code: code, CodeVerifier: proof, RedirectURI: client.Redirects[0], Network: "192.0.2.1"},
		{GrantType: oauth.RefreshTokenGrant, ClientID: client.ID, RefreshToken: refresh, Network: "192.0.2.1"},
	} {
		if out, err := original.Token(f.ctx, request); err == nil || out.AccessToken != (oauth.Token{}) {
			t.Fatal("old public code/refresh authority survived update")
		}
	}
	issuedConfidentialTokens(t, f, original, updated.Client, oauth.ClientAuthentication{})
	replayed, err := fresh.ClientUpdate(f.ctx, r)
	if err != nil || !replayed.Completion.Replayed || replayed.Completion.CommandID != updated.Completion.CommandID || replayed.Client.Version != 2 || !replayed.Client.Public {
		t.Fatal("original public update was not recovered exactly once", err)
	}
	changedClass := r
	changedClass.Management.Public = false
	if out, err := fresh.ClientUpdate(f.ctx, changedClass); err == nil || out.Client.ID != "" {
		t.Fatal("original public update replay accepted changed class")
	}
	if out, err := fresh.ClientUpdate(f.ctx, publicClientUpdateRequest(t, f, client, "public-update-stale")); err == nil || out.Client.ID != "" {
		t.Fatal("stale public version accepted")
	}
	deletion := clientRotationRequest(t, f, updated.Client, "public-update-delete", 0).Management
	deleted, err := fresh.ClientDelete(f.ctx, deletion)
	if err != nil || deleted.Completion.Outcome != identity.CommitOutcomeCommitted || deleted.Secret != (oauth.Token{}) {
		t.Fatal("updated public client could not be deleted", err)
	}
	requirePublicUpdateState(t, f, client, "3", "deleted", 1)
	historical, err := fresh.ClientUpdate(f.ctx, r)
	if err != nil || !historical.Completion.Replayed || historical.Client.Version != 2 || !historical.Client.Public || historical.Completion.CommandID != updated.Completion.CommandID {
		t.Fatal("public update recovery revived or adopted today's tombstone", err)
	}
	requirePublicUpdateState(t, f, client, "3", "deleted", 1)
}

func TestNativePublicClientUpdateRejectsForeignClassAndAuthority(t *testing.T) {
	f, service, client := publicUpdateFixture(t)
	other, csrf := f.anotherUser()
	for _, mode := range []string{"class", "owner", "tenant", "csrf", "manager", "origin", "scope", "redirect", "version", "policy"} {
		r := publicClientUpdateRequest(t, f, client, "public-update-deny-"+mode)
		policy := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy)
		switch mode {
		case "class":
			r.Management.Public = false
		case "owner":
			r.Management.Owner, _ = oauth.NewPlatformOwner("foreign")
		case "tenant":
			r.Management.TenantID = "foreign"
		case "csrf":
			r.Management.CSRF, _ = session.NewCSRFToken()
		case "manager":
			r.Management.Session, r.Management.CSRF = other, csrf
		case "origin":
			r.Management.Origin = "https://foreign.example"
		case "scope":
			r.Scopes = []string{"openid"}
		case "redirect":
			r.Redirects = []string{"https://foreign.example/callback"}
		case "version":
			r.Management.Version++
		case "policy":
			policy.denied.Store(true)
		}
		out, err := service.ClientUpdate(f.ctx, r)
		policy.denied.Store(false)
		if err == nil || out.Client.ID != "" {
			t.Fatal("foreign public update admitted", mode, err)
		}
	}
	private, err := service.ClientCreate(f.ctx, clientCreateRequest(t, f, "private-class-control"))
	if err != nil {
		t.Fatal(err)
	}
	wrong := publicClientUpdateRequest(t, f, private.Client, "public-update-private-class")
	wrong.Management.Public = true
	if out, err := service.ClientUpdate(f.ctx, wrong); err == nil || out.Client.ID != "" {
		t.Fatal("confidential client accepted public expected class")
	}
	requirePublicUpdateState(t, f, client, "1", "active", 0)
	if out, err := service.ClientUpdate(f.ctx, publicClientUpdateRequest(t, f, client, "public-update-positive")); err != nil || !out.Client.Public || out.Client.Version != 2 {
		t.Fatal("genuine current public manager positive control", err)
	}
}

func TestNativePublicClientUpdateUnknownCommitRecoversOriginalWithoutDuplicateEffects(t *testing.T) {
	fault := &oauthCommitFault{}
	f, service, client := publicUpdateFixture(t, fault)
	fault.armed.Store(true)
	r := publicClientUpdateRequest(t, f, client, "public-update-unknown")
	out, err := service.ClientUpdate(f.ctx, r)
	if err == nil || !fault.hit.Load() || out.Completion.Outcome != identity.CommitOutcomeUnknown || out.Client.ID != "" {
		t.Fatal("actual lost COMMIT acknowledgement did not withhold public metadata", err)
	}
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.client-update", CommandID: out.Completion.CommandID, ClientID: client.ID, TenantID: f.tenant, Session: f.browser}
	deadline := time.Now().Add(8 * time.Second)
	for {
		recovered, err := store.Recover(f.ctx, recovery)
		if err != nil && !errors.Is(err, oauth.ErrUnavailable) {
			t.Fatal("original public command recovery denied", err)
		}
		if recovered.Outcome == identity.CommitOutcomeCommitted {
			if recovered.CommandID != out.Completion.CommandID {
				t.Fatal("public recovery substituted command identity")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("public command did not reconcile original commit", err)
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-f.ctx.Done():
			t.Fatal("public recovery canceled")
		}
	}
	for i := 0; i < 2; i++ {
		retry, err := service.ClientUpdate(f.ctx, r)
		if err != nil || !retry.Completion.Replayed || retry.Completion.CommandID != out.Completion.CommandID || !retry.Client.Public || retry.Client.Version != 2 {
			t.Fatal("original public update retry changed result", err)
		}
	}
	requirePublicUpdateState(t, f, client, "2", "active", 1)
}

func TestNativePublicClientUpdateFencesContendersAndWithdrawnAuthority(t *testing.T) {
	for _, mode := range []string{"update", "delete", "delete-late", "logout", "epoch"} {
		t.Run(mode, func(t *testing.T) {
			f, winner, client := publicUpdateFixture(t)
			action := "identity.oauth-server.client-update"
			if mode == "delete-late" {
				action = "identity.oauth-server.client-delete"
			}
			late, gate := updateBarrierService(t, f, action)
			ctx, cancel := context.WithCancel(context.WithValue(f.ctx, consentRaceKey{}, true))
			defer cancel()
			type answer struct {
				client oauth.Client
				secret oauth.Token
				err    error
			}
			done := make(chan answer, 1)
			joined := false
			defer func() {
				cancel()
				select {
				case <-gate.release:
				default:
					close(gate.release)
				}
				if !joined {
					<-done
				}
			}()
			request := publicClientUpdateRequest(t, f, client, "public-update-late")
			deletion := clientRotationRequest(t, f, client, "public-delete-late", 0).Management
			go func() {
				if mode == "delete-late" {
					out, err := late.ClientDelete(ctx, deletion)
					done <- answer{client: out.Client, secret: out.Secret, err: err}
					return
				}
				out, err := late.ClientUpdate(ctx, request)
				done <- answer{client: out.Client, err: err}
			}()
			select {
			case <-gate.ready:
			case out := <-done:
				joined = true
				t.Fatal("public update failed before native authority barrier", out.err)
			case <-f.ctx.Done():
				t.Fatal("public authority barrier canceled")
			}
			version, state, effects := "1", "active", 0
			switch mode {
			case "update", "delete-late":
				if _, err := winner.ClientUpdate(f.ctx, publicClientUpdateRequest(t, f, client, "public-update-winner")); err != nil {
					t.Fatal(err)
				}
				version, effects = "2", 1
			case "delete":
				if _, err := winner.ClientDelete(f.ctx, clientRotationRequest(t, f, client, "public-delete-winner", 0).Management); err != nil {
					t.Fatal(err)
				}
				version, state = "2", "deleted"
			case "logout":
				f.signOut()
			case "epoch":
				owner, err := authority.NewAuthorityStore(f.pool.Raw(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				manager := f.oauth.Coordinator.AdmissionPolicy.Authorization.(clientManagerPolicy).manager
				scope := authority.AuthorityScope{TenantID: authorization.TenantID(f.tenant), PolicyNamespace: f.oauth.Session.Profile.PolicyNamespace, SubjectID: manager}
				current, err := owner.Get(f.ctx, scope)
				if err != nil {
					t.Fatal(err)
				}
				tx, err := f.pool.Raw().Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := authority.AdvanceAuthority(f.ctx, tx, scope, current.Version, time.Second); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
			}
			close(gate.release)
			out := <-done
			joined = true
			if !errors.Is(out.err, oauth.ErrAccessDenied) || out.client.ID != "" || out.secret != (oauth.Token{}) {
				t.Fatal("stale/withdrawn public manager received metadata", out.err)
			}
			requirePublicUpdateState(t, f, client, version, state, effects)
		})
	}
}
