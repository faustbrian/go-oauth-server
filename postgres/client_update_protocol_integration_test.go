//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestNativeClientUpdateFencesLateApprovalExchangeAndRefresh(t *testing.T) {
	for _, mode := range []string{"approval", "exchange", "refresh"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			enableClientUpdates(t, &f)
			controller, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			created, err := controller.ClientCreate(f.ctx, clientCreateRequest(t, f, "late-protocol-update-create"))
			if err != nil {
				t.Fatal(err)
			}
			secret, _ := created.Secret.Reveal()
			basic := confidentialBasic(t, created.Client.ID, secret)
			var continuation string
			var request oauth.TokenRequest
			if mode == "approval" {
				challenge, _ := oauth.S256Challenge(strings.Repeat("a", 43))
				begin, err := controller.Authorize(f.ctx, oauth.AuthorizeRequest{TenantID: f.tenant, Session: f.browser, Network: "192.0.2.1", Request: oauth.AuthorizationRequest{ClientID: created.Client.ID, RedirectURI: created.Client.Redirects[0], Resource: created.Client.Resource, Scopes: []string{"identity:read"}, CodeChallenge: challenge}})
				if err != nil {
					t.Fatal(err)
				}
				continuation, err = begin.Continuation.Reveal()
				if err != nil {
					t.Fatal(err)
				}
			} else if mode == "exchange" {
				code, proof := confidentialCode(t, f, controller, created.Client)
				request = oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: created.Client.ID, ClientAuthentication: basic, Code: code, CodeVerifier: proof, RedirectURI: created.Client.Redirects[0], Network: "192.0.2.1"}
			} else {
				_, refresh := issuedConfidentialTokens(t, f, controller, created.Client, basic)
				request = oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: created.Client.ID, ClientAuthentication: basic, RefreshToken: refresh, Network: "192.0.2.1"}
			}
			action := "identity.oauth-server.token"
			if mode == "approval" {
				action = "identity.oauth-server.continue"
			}
			late, gate := updateBarrierService(t, f, action)
			ctx, cancel := context.WithCancel(context.WithValue(f.ctx, consentRaceKey{}, true))
			defer cancel()
			type answer struct {
				authorization oauth.AuthorizeResult
				token         oauth.TokenResult
				err           error
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
			var before int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			go func() {
				if mode == "approval" {
					out, err := late.Continue(ctx, oauth.ContinueRequest{TenantID: f.tenant, Session: f.browser, CSRF: f.csrf, Origin: f.oauth.Protocol.Issuer.String(), ClientID: created.Client.ID, Continuation: continuation, Approve: true, Scopes: []string{"identity:read"}, Network: "192.0.2.1"})
					done <- answer{authorization: out, err: err}
				} else {
					out, err := late.Token(ctx, request)
					done <- answer{token: out, err: err}
				}
			}()
			select {
			case <-gate.ready:
			case out := <-done:
				joined = true
				t.Fatal("old protocol snapshot did not reach native pre-Work boundary", out.err)
			case <-f.ctx.Done():
				t.Fatal("protocol update contention canceled")
			}
			updated, err := controller.ClientUpdate(f.ctx, clientUpdateRequest(t, f, created.Client, "late-protocol-update-winner"))
			if err != nil {
				t.Fatal(err)
			}
			close(gate.release)
			out := <-done
			joined = true
			denied := oauth.ErrInvalidGrant
			if mode == "approval" {
				denied = oauth.ErrAccessDenied
			}
			if !errors.Is(out.err, denied) {
				t.Fatal("old client authority did not return expected denial after replacement", out.err)
			}
			if out.authorization.Continuation != (oauth.Token{}) || out.authorization.Code != (oauth.Token{}) || !out.authorization.ExpiresAt.IsZero() || out.authorization.RedirectURI != "" || out.authorization.State != "" || out.authorization.Issuer != (oauth.Issuer{}) || !reflect.DeepEqual(out.authorization.Request, oauth.AuthorizationRequest{}) {
				t.Fatal("denied old registration disclosed authorization metadata or credential custody")
			}
			if out.token.AccessToken != (oauth.Token{}) || out.token.RefreshToken != (oauth.Token{}) || out.token.IDToken != (oauth.IDToken{}) || !out.token.ExpiresAt.IsZero() || out.token.Resource != "" || len(out.token.Scopes) != 0 {
				t.Fatal("denied old registration disclosed token custody or grant metadata")
			}
			var after int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_store.artifacts`).Scan(&after); err != nil || after != before {
				t.Fatal("late old client created descendants", err)
			}
			issuedConfidentialTokens(t, f, controller, updated.Client, basic)
		})
	}
}

func TestNativeClientUpdateFencesLateWarmResourcePrimaryRead(t *testing.T) {
	f := passwordFixture(t)
	enableClientUpdates(t, &f)
	controller, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := controller.ClientCreate(f.ctx, clientCreateRequest(t, f, "resource-update-create"))
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := created.Secret.Reveal()
	basic := confidentialBasic(t, created.Client.ID, secret)
	access, _ := issuedConfidentialTokens(t, f, controller, created.Client, basic)
	gate := &resourceReadGate{reached: make(chan struct{}), proceed: make(chan struct{})}
	original := f.pool.Raw().Config().ConnConfig
	pool, err := database.Connect(f.ctx, database.Config{DSN: original.ConnString(), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = original.Database
		c.ConnConfig.RuntimeParams = maps.Clone(original.RuntimeParams)
		c.ConnConfig.Tracer = gate
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if pool.Close(ctx) != nil {
			t.Error("resource update pool cleanup")
		}
	}()
	verifier, err := oauthpostgres.NewResourceVerifier(pool, f.oauth, f.keys, resourcePolicy(f, created.Client))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := verifier.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"}); err != nil || p.RequireScope("identity:read") != nil {
		t.Fatal("live warm resource control", err)
	}
	ctx, cancel := context.WithCancel(context.WithValue(f.ctx, resourceReadKey{}, true))
	defer cancel()
	type answer struct {
		p   oauth.ResourcePrincipal
		err error
	}
	done := make(chan answer, 1)
	joined := false
	defer func() {
		cancel()
		select {
		case <-gate.proceed:
		default:
			close(gate.proceed)
		}
		if !joined {
			<-done
		}
	}()
	go func() {
		p, err := verifier.Verify(ctx, oauth.ResourceVerifyRequest{AccessToken: access, Scope: "identity:read"})
		done <- answer{p, err}
	}()
	select {
	case <-gate.reached:
	case out := <-done:
		joined = true
		t.Fatal("warm resource did not reach second real primary lookup", out.err)
	case <-f.ctx.Done():
		t.Fatal("resource update gate canceled")
	}
	updated, err := controller.ClientUpdate(f.ctx, clientUpdateRequest(t, f, created.Client, "resource-update-winner"))
	if err != nil {
		t.Fatal(err)
	}
	close(gate.proceed)
	out := <-done
	joined = true
	if out.err == nil || out.p.RequireScope("identity:read") == nil {
		t.Fatal("late warm resource released old client authority")
	}
	newAccess, _ := issuedConfidentialTokens(t, f, controller, updated.Client, basic)
	// Trusted resource policy must explicitly adopt BOTH the new version and
	// narrowed supported scope catalog; it may not retain the removed write scope.
	newPolicy := resourcePolicy(f, updated.Client)
	newPolicy.Scopes, err = oauth.NewScopeCatalog(updated.Client.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	newVerifier, err := oauthpostgres.NewResourceVerifier(f.pool, f.oauth, f.keys, newPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := newVerifier.Verify(f.ctx, oauth.ResourceVerifyRequest{AccessToken: newAccess, Scope: "identity:read"}); err != nil || p.RequireScope("identity:read") != nil {
		t.Fatal("new explicit client-version resource control", err)
	}
}
