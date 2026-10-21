//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"golang.org/x/oauth2"
)

type silentConsentApplyGate struct {
	armed            atomic.Bool
	queries          atomic.Uint32
	reached, release chan struct{}
	done             <-chan struct{}
}

func (g *silentConsentApplyGate) observe(wire []byte) {
	if g.armed.Load() && bytes.Contains(wire, []byte(`FROM "oauth_store".consents WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3 FOR UPDATE`)) && g.queries.Add(1) == 2 {
		close(g.reached)
		select {
		case <-g.release:
		case <-g.done:
		}
	}
}

func TestNativeOIDCSilentOriginalObservationExpiresAcrossConsentLockWait(t *testing.T) {
	gate := &silentConsentApplyGate{reached: make(chan struct{}), release: make(chan struct{})}
	f := passwordFixture(t, &oauthCommitFault{beforeWrite: gate.observe})
	gate.done = f.ctx.Done()
	service, child, store := silentOIDCFixture(t, &f, time.Minute)
	oidcCode(t, f, service, "original-wait-approval")
	reader, err := sessionpg.NewSessionService(f.pool, f.oauth.Session)
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(f.browser.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	original, err := reader.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil || !original.Authenticated {
		t.Fatal("genuine original silent session", err)
	}
	// Age genuine sealed owner evidence outside the bounded call. Only the
	// original final three seconds occur in Work; no clock/source is fabricated.
	waitAuthenticationBoundary(t, f, original.ValidUntil().Add(-3*time.Second))
	blocker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	var blockerID uint32
	if err := blocker.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&blockerID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	type answer struct {
		out oauth.AuthorizeResult
		err error
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
		_ = blocker.Rollback(context.Background())
		if !joined {
			<-done
		}
	}()
	r := silentRequest(f, oauth2.GenerateVerifier())
	var client oauth.Client
	for _, candidate := range f.oauth.Protocol.Clients {
		if candidate.ID == r.Request.ClientID {
			client = candidate
		}
	}
	gate.armed.Store(true)
	go func() {
		out, err := store.Authorize(ctx, oauth.AuthorizationCommand{Request: r.Request, Client: client, Session: original, Browser: f.browser, Network: r.Network, OIDC: child.ValidateAuthorization})
		done <- answer{out, err}
	}()
	select {
	case <-gate.reached:
	case out := <-done:
		joined = true
		t.Fatal("silent request did not reach original Apply fence", out.err)
	case <-f.ctx.Done():
		t.Fatal("silent original Apply gate canceled")
	}
	if original.ValidateAt(time.Now()) != nil {
		t.Fatal("original silent observation not live at positive Apply control")
	}
	if _, err := blocker.Exec(f.ctx, `SELECT consent_id FROM oauth_store.consents FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	for {
		var waiting int
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, blockerID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if !time.Now().Before(original.ValidUntil()) {
			t.Fatal("silent request did not actually wait while original evidence live")
		}
		waitAuthenticationBoundary(t, f, time.Now().Add(10*time.Millisecond))
	}
	waitAuthenticationBoundary(t, f, original.ValidUntil().Add(time.Millisecond))
	if err := blocker.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	out := <-done
	joined = true
	if !errors.Is(out.err, oauth.ErrAccessDenied) || out.out.Code != (oauth.Token{}) || out.out.Continuation != (oauth.Token{}) || out.out.RedirectURI != "" {
		t.Fatal("original silent deadline renewed across actual lock wait", out.err)
	}
	var grants, codes, effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.artifacts WHERE kind=2),(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.authorize')`).Scan(&grants, &codes, &effects); err != nil || grants != 1 || codes != 1 || effects != 1 {
		t.Fatal("expired original observation committed silent descendants", err)
	}
	fresh, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err = fresh.WithOIDC(child)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := fresh.Authorize(f.ctx, silentRequest(f, oauth2.GenerateVerifier())); err != nil || out.Outcome != oauth.AuthorizationRedirect {
		t.Fatal("fresh independent silent observation positive control", err)
	}
}

func TestNativeOIDCSilentLateConsentOrIdentityWithdrawalDeniesCode(t *testing.T) {
	for _, mode := range []string{"narrow", "revoke", "logout", "credential"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixtureWithChange(t, mode == "credential")
			enableConsentNarrowing(t, &f)
			controller, child, _ := silentOIDCFixture(t, &f, time.Minute)
			oidcCode(t, f, controller, "explicit-late-original")
			var granted, expiry time.Time
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT granted_at,expires_at FROM oauth_store.consents`).Scan(&granted, &expiry); err != nil {
				t.Fatal(err)
			}
			consent := currentNarrowConsent(t, f, controller)
			late, gate := updateBarrierService(t, f, "identity.oauth-server.authorize")
			late, err := late.WithOIDC(child)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.WithValue(f.ctx, consentRaceKey{}, true))
			defer cancel()
			type answer struct {
				out oauth.AuthorizeResult
				err error
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
			request := silentRequest(f, oauth2.GenerateVerifier())
			go func() {
				out, err := late.Authorize(ctx, request)
				done <- answer{out, err}
			}()
			select {
			case <-gate.ready:
			case out := <-done:
				joined = true
				t.Fatal("silent original evidence did not reach native pre-Work boundary", out.err)
			case <-f.ctx.Done():
				t.Fatal("silent admission gate canceled")
			}
			if mode == "narrow" {
				if out, err := controller.ConsentUpdate(f.ctx, narrowRequest(t, f, consent, "narrow-during-silent", []string{"openid"})); err != nil || !out.Updated {
					t.Fatal("actual owner narrowing failed", err)
				}
			} else if mode == "revoke" {
				if _, err := controller.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRemove, consent.ID(), consent.Version())}); err != nil {
					t.Fatal("actual owner revocation failed", err)
				}
			} else if mode == "credential" {
				f.changePassword()
			} else {
				f.signOut()
			}
			close(gate.release)
			out := <-done
			joined = true
			if !errors.Is(out.err, oauth.ErrAccessDenied) {
				t.Fatal("late silent authority did not return expected denial", out.err)
			}
			if out.out.Code != (oauth.Token{}) || out.out.Continuation != (oauth.Token{}) || out.out.RedirectURI != "" || !out.out.ExpiresAt.IsZero() {
				t.Fatal("late withdrawn silent authority returned credential or redirect")
			}
			var grants, codes, effects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.artifacts WHERE kind=2),(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.authorize')`).Scan(&grants, &codes, &effects); err != nil || grants != 1 || codes != 1 || effects != 1 {
				t.Fatal("late silent denial committed descendants or effects", err)
			}
			var currentGranted, currentExpiry time.Time
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT granted_at,expires_at FROM oauth_store.consents`).Scan(&currentGranted, &currentExpiry); err != nil || !currentGranted.Equal(granted) || !currentExpiry.Equal(expiry) {
				t.Fatal("late withdrawal/narrowing renewed original approval", err)
			}
			if mode == "narrow" {
				request.Request.Scopes = []string{"openid"}
				if live, err := controller.Authorize(f.ctx, request); err != nil || live.Outcome != oauth.AuthorizationRedirect {
					t.Fatal("current narrowed approval positive control failed", err)
				}
			}
		})
	}
}
