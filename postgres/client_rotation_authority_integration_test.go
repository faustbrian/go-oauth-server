//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type rotationFinalReadKey struct{}
type rotationFinalReadGate struct {
	mutated, reachedOnce atomic.Bool
	reached, release     chan struct{}
}

func (g *rotationFinalReadGate) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if selected, _ := ctx.Value(rotationFinalReadKey{}).(bool); !selected {
		return ctx
	}
	// Protected Work reads this row with SELECT version/state ... FOR SHARE.
	// The first *primary-pool* registration read after actual artifact mutation
	// is the delivery fence, reached only after execute has returned its outcome.
	if g.mutated.Load() && strings.HasPrefix(q.SQL, `SELECT registration,secret_digest,state,version::text`) && g.reachedOnce.CompareAndSwap(false, true) {
		close(g.reached)
		select {
		case <-g.release:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (*rotationFinalReadGate) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// The first native clock sample is the actual matching snapshot's Start, not a
// fabricated source timestamp. Time keeps advancing normally; natural aging is
// outside the bounded retry. The real pre-COMMIT disconnect retains encrypted
// generation A; its expired lease can be taken over with fresh invocation B.
func TestNativeClientRotationRetainedAuthenticationDeadlineSurvivesFinalRead(t *testing.T) {
	for _, operation := range []string{"token", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			var liveGate atomic.Pointer[rotationFinalReadGate]
			// Work deliberately uses raw ExecParams with fixed codecs, not pgx
			// caller tracers. Observe its real transport; trace only the later
			// ordinary primary-pool delivery read. Neither seam changes SQL.
			fault := &oauthCommitFault{before: true, beforeWrite: func(wire []byte) {
				if g := liveGate.Load(); g != nil && bytes.Contains(wire, []byte(`UPDATE "oauth_store".artifacts SET state=`)) {
					g.mutated.Store(true)
				}
			}}
			f := passwordFixture(t, fault)
			enableClientRotation(t, &f)
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			created, err := service.ClientCreate(f.ctx, clientCreateRequest(t, f, "retained-deadline-create"))
			if err != nil {
				t.Fatal(err)
			}
			secret, _ := created.Secret.Reveal()
			basic := confidentialBasic(t, created.Client.ID, secret)
			var armed atomic.Bool
			var mu sync.Mutex
			var sampled time.Time
			config := f.oauth
			config.Protocol.Clock = emailClock(func() time.Time {
				now := time.Now().UTC().Truncate(time.Microsecond)
				if armed.CompareAndSwap(true, false) {
					mu.Lock()
					sampled = now
					mu.Unlock()
				}
				return now
			})
			store, err := oauthpostgres.NewStore(f.pool, config, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			type pending struct {
				request    oauth.TokenRequest
				revoke     oauth.RevokeRequest
				deadline   time.Time
				id         identity.CommandID
				ciphertext []byte
				generation string
			}
			var originals []pending
			for _, label := range []string{"positive", "expired"} {
				var p pending
				if operation == "token" {
					code, proof := confidentialCode(t, f, service, created.Client)
					p.request = oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: created.Client.ID, ClientAuthentication: basic, Code: code, CodeVerifier: proof, RedirectURI: created.Client.Redirects[0], Network: "192.0.2.1"}
				} else {
					access, _ := issuedConfidentialTokens(t, f, service, created.Client, basic)
					p.revoke = oauth.RevokeRequest{ClientID: created.Client.ID, ClientAuthentication: basic, Token: access, Network: "192.0.2.1"}
				}
				fault.hit.Store(false)
				fault.armed.Store(true)
				armed.Store(true)
				if operation == "token" {
					out, err := store.Token(f.ctx, oauth.TokenCommand{Client: created.Client, Request: p.request})
					if err == nil || out.Outcome != identity.CommitOutcomeUnknown || !fault.hit.Load() {
						t.Fatal("original token preparation not retained", label, err)
					}
					p.id = out.CommandID
				} else {
					out, err := store.Revoke(f.ctx, oauth.RevocationCommand{Client: created.Client, Request: p.revoke})
					if err == nil || out.Outcome != identity.CommitOutcomeUnknown || !fault.hit.Load() {
						t.Fatal("original revoke preparation not retained", label, err)
					}
					p.id = out.CommandID
				}
				fault.armed.Store(false)
				rawID, _ := base64.RawURLEncoding.DecodeString(string(p.id))
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text FROM identity.commands WHERE command_id=$1`, rawID).Scan(&p.ciphertext, &p.generation); err != nil || len(p.ciphertext) == 0 || p.generation == "" {
					t.Fatal("original encrypted generation absent", err)
				}
				mu.Lock()
				p.deadline = sampled.Add(20 * time.Second)
				mu.Unlock()
				if p.id == "" || time.Until(p.deadline) < 18*time.Second {
					t.Fatal("original match timestamp not captured")
				}
				originals = append(originals, p)
			}
			for i, p := range originals {
				gate := &rotationFinalReadGate{reached: make(chan struct{}), release: make(chan struct{})}
				liveGate.Store(gate)
				original := f.pool.Raw().Config().ConnConfig
				pool, err := database.Connect(f.ctx, database.Config{DSN: original.ConnString(), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = original.Database
					c.ConnConfig.RuntimeParams = maps.Clone(original.RuntimeParams)
					c.ConnConfig.DialFunc = original.DialFunc
					c.ConnConfig.Tracer = gate
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				func() {
					defer func() {
						cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						if pool.Close(cleanup) != nil {
							t.Error("retry traced pool cleanup")
						}
					}()
					retry, err := oauthpostgres.NewStore(pool, config, f.keys)
					if err != nil {
						t.Fatal(err)
					}
					waitAuthenticationBoundary(t, f, p.deadline.Add(-2*time.Second))
					ctx, cancel := context.WithCancel(context.WithValue(f.ctx, rotationFinalReadKey{}, true))
					defer cancel()
					type answer struct {
						err     error
						id      identity.CommandID
						outcome identity.CommitOutcome
						secret  bool
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
					go func() {
						if operation == "token" {
							out, err := retry.Token(ctx, oauth.TokenCommand{Client: created.Client, Request: p.request})
							_, reveal := out.AccessToken.Reveal()
							done <- answer{err, out.CommandID, out.Outcome, reveal == nil}
						} else {
							out, err := retry.Revoke(ctx, oauth.RevocationCommand{Client: created.Client, Request: p.revoke})
							done <- answer{err, out.CommandID, out.Outcome, false}
						}
					}()
					select {
					case <-gate.reached:
					case out := <-done:
						joined = true
						t.Fatal("retained takeover did not reach post-COMMIT primary fence", out.err, out.outcome, gate.mutated.Load())
					case <-f.ctx.Done():
						t.Fatal("bounded retained retry canceled")
					}
					if !time.Now().Before(p.deadline) {
						t.Fatal("original deadline expired before final-read positive control")
					}
					var retained []byte
					var ciphertextGeneration, currentGeneration string
					var effects int
					rawID, _ := base64.RawURLEncoding.DecodeString(string(p.id))
					if err := f.pool.Raw().QueryRow(f.ctx, `SELECT preparation_ciphertext,preparation_ciphertext_generation::text,generation::text,(SELECT count(*) FROM oauth_store.effects WHERE command_id=$2) FROM identity.commands WHERE command_id=$1`, rawID, string(p.id)).Scan(&retained, &ciphertextGeneration, &currentGeneration, &effects); err != nil || !bytes.Equal(retained, p.ciphertext) || ciphertextGeneration != p.generation || currentGeneration == p.generation || effects != 1 {
						t.Fatal("retry did not commit original retained encrypted generation once", err)
					}
					if i == 1 {
						waitAuthenticationBoundary(t, f, p.deadline)
					}
					close(gate.release)
					out := <-done
					joined = true
					if out.id != p.id || out.outcome != identity.CommitOutcomeCommitted {
						t.Fatal("retained command did not commit exactly once", out.err, out.outcome)
					}
					if i == 0 {
						if out.err != nil || operation == "token" && !out.secret {
							t.Fatal("live original retained authentication denied", out.err)
						}
					} else if out.err == nil || out.secret {
						t.Fatal("final delivery renewed retained original authentication deadline")
					}
				}()
				liveGate.Store(nil)
			}
		})
	}
}

func TestNativeClientRotationExactManagerAndImmutableVersionDenials(t *testing.T) {
	f := passwordFixture(t)
	denied := enableClientRotation(t, &f)
	s, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.ClientCreate(f.ctx, clientCreateRequest(t, f, "denial-create"))
	if err != nil {
		t.Fatal(err)
	}
	r := clientRotationRequest(t, f, created.Client, "denial-rotation", time.Minute)
	other, csrf := f.anotherUser()
	for _, mode := range []string{"owner", "tenant", "manager", "csrf", "origin", "public", "static", "version", "zero-version", "redirect", "scope", "negative", "long", "precision", "policy"} {
		bad := r
		switch mode {
		case "owner":
			bad.Management.Owner, _ = oauth.NewPlatformOwner("foreign")
		case "tenant":
			bad.Management.TenantID = "foreign"
		case "manager":
			bad.Management.Session, bad.Management.CSRF = other, csrf
		case "csrf":
			bad.Management.CSRF, _ = session.NewCSRFToken()
		case "origin":
			bad.Management.Origin = "https://foreign.example"
		case "public":
			bad.Management.Public = true
		case "static":
			bad.Management.ClientID = "public-web"
		case "version":
			bad.Management.Version = 2
		case "zero-version":
			bad.Management.Version = 0
		case "redirect":
			bad.Management.Redirects = []string{"https://foreign.example/cb"}
		case "scope":
			bad.Management.Scopes = []string{"identity:read"}
		case "negative":
			bad.Overlap = -time.Microsecond
		case "long":
			bad.Overlap = 24*time.Hour + time.Microsecond
		case "precision":
			bad.Overlap = time.Nanosecond
		case "policy":
			denied.Store(true)
		}
		out, err := s.ClientRotateSecret(f.ctx, bad)
		if err == nil || out.Client.ID != "" {
			t.Fatal("invalid manager rotation admitted", mode)
		}
		if _, err := out.Secret.Reveal(); err == nil {
			t.Fatal("denial revealed successor", mode)
		}
		denied.Store(false)
	}
	var version string
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,(SELECT count(*) FROM oauth_store.effects WHERE operation_id='identity.oauth-server.client-rotate-secret') FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&version, &effects); err != nil || version != "1" || effects != 0 {
		t.Fatal("denial changed durable authority", err)
	}
	// A direct native caller cannot replace sealed original session custody with
	// an Authenticated boolean. The public service obtains its real source above.
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RotateClientSecret(f.ctx, oauth.ClientSecretRotationExecution{Request: r, Session: session.GetResult{Authenticated: true}}); err == nil {
		t.Fatal("fabricated manager observation authorized rotation")
	}
	token, _ := session.ParseToken(f.browser.Token())
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	original, err := f.sessions.Get(f.ctx, session.GetRequest{TenantID: f.tenant, Credential: credential})
	if err != nil {
		t.Fatal(err)
	}
	stale := f.oauth
	stale.Protocol.Clock = emailClock(func() time.Time { return original.ValidUntil() })
	staleStore, err := oauthpostgres.NewStore(f.pool, stale, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staleStore.RotateClientSecret(f.ctx, oauth.ClientSecretRotationExecution{Request: r, Session: original}); err == nil {
		t.Fatal("original sensitive observation renewed")
	}
	if _, err := s.ClientRotateSecret(f.ctx, r); err != nil {
		t.Fatal("live exact manager positive control", err)
	}
}

func TestNativeClientRotationSerializesWithOtherRotationAndDeletion(t *testing.T) {
	for _, mode := range []string{"rotation-wins-rotation", "delete-wins-rotation", "rotation-wins-delete"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			enableClientRotation(t, &f)
			winner, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			created, err := winner.ClientCreate(f.ctx, clientCreateRequest(t, f, "contention-create"))
			if err != nil {
				t.Fatal(err)
			}
			lateRequest := clientRotationRequest(t, f, created.Client, "contention-late", time.Minute)
			action := authorization.Action("identity.oauth-server.client-rotate-secret")
			lateDelete := mode == "rotation-wins-delete"
			if lateDelete {
				action = "identity.oauth-server.client-delete"
			}
			barrier := &consentRaceBarrier{owner: f.oauth.Coordinator.AdmissionPolicy.Authorization, action: action, ready: make(chan struct{}), release: make(chan struct{})}
			admission := *f.oauth.Coordinator.AdmissionPolicy
			admission.Authorization = barrier
			f.oauth.Coordinator.AdmissionPolicy = &admission
			late, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.WithValue(f.ctx, consentRaceKey{}, true))
			defer cancel()
			done := make(chan error, 1)
			joined := false
			secretLeaked := false
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
			go func() {
				if lateDelete {
					_, err := late.ClientDelete(ctx, lateRequest.Management)
					done <- err
				} else {
					out, err := late.ClientRotateSecret(ctx, lateRequest)
					if _, reveal := out.Secret.Reveal(); reveal == nil {
						secretLeaked = true
					}
					done <- err
				}
			}()
			select {
			case <-barrier.ready:
			case err := <-done:
				joined = true
				t.Fatal("original management did not reach late native gate", err)
			case <-f.ctx.Done():
				t.Fatal("bounded contention canceled")
			}
			winning := clientRotationRequest(t, f, created.Client, "contention-winner", 0)
			wantState := "active"
			if mode == "delete-wins-rotation" {
				wantState = "deleted"
				if out, err := winner.ClientDelete(f.ctx, winning.Management); err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("delete winner", err)
				}
			} else {
				if out, err := winner.ClientRotateSecret(f.ctx, winning); err != nil || out.Completion.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("rotation winner", err)
				}
			}
			close(barrier.release)
			err = <-done
			joined = true
			if err == nil || secretLeaked {
				t.Fatal("late stale management changed winning version")
			}
			var version, state string
			var effects int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::text,state,(SELECT count(*) FROM oauth_store.effects WHERE client_id=$1) FROM oauth_store.managed_clients WHERE client_id=$1`, created.Client.ID).Scan(&version, &state, &effects); err != nil || version != "2" || state != wantState || effects != 2 {
				t.Fatal("contended management repeated authority/effects", err)
			}
		})
	}
}
