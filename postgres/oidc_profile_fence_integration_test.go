//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	op "github.com/faustbrian/go-oauth-server/oidc"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type profileReadTraceKey struct{}
type profileReadTrace struct {
	reads atomic.Uint32
	at    uint32
	late  func()
}

func (p *profileReadTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, profileReadTraceKey{}, strings.Contains(data.SQL, "LEFT JOIN identity.user_profiles"))
}
func (p *profileReadTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	if selected, _ := ctx.Value(profileReadTraceKey{}).(bool); selected && p.reads.Add(1) == p.at {
		p.late()
	}
}

func TestNativeOIDCProfileLateWithdrawalAndMixedSnapshotsReturnZeroClaims(t *testing.T) {
	for _, mode := range []string{"profile-snapshot", "profile-version", "credential", "owner", "consent", "narrow-consent", "grant", "access", "subject", "key", "deadline", "cancel", "caller-deadline", "source-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f := profilePasswordFixture(t, mode == "credential")
			if mode == "narrow-consent" {
				enableConsentNarrowing(t, &f)
			} else if mode == "consent" {
				enableConsentManagement(t, &f)
			}
			service, child, signer, _, _ := profileFixture(t, &f)
			profile := mutateNativeProfile(t, f, "Original authorized name")
			code, proof := oidcCode(t, f, service, "late-profile-fence")
			issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: proof, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			access, err := issued.AccessToken.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			refresh, err := issued.RefreshToken.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			request := oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}
			if out, err := child.UserInfo(f.ctx, request); err != nil || out.Name != profile.Name {
				t.Fatal("baseline profile disclosure unavailable", err)
			}
			var consent oauth.Consent
			if mode == "consent" || mode == "narrow-consent" {
				consent = currentNarrowConsent(t, f, service)
			}
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			var shift atomic.Int64
			f.oauth.Protocol.Clock = emailClock(func() time.Time { return time.Now().Add(time.Duration(shift.Load())) })
			var mutationErr error
			trace := &profileReadTrace{at: 2}
			if mode == "profile-snapshot" || mode == "profile-version" || mode == "source-unavailable" {
				trace.at = 1
			}
			trace.late = func() {
				switch mode {
				case "profile-snapshot":
					mutateNativeProfile(t, f, "New committed name during read")
				case "profile-version":
					mutateNativeProfile(t, f, profile.Name)
				case "credential":
					f.changePassword()
				case "owner":
					suspendResourceUser(t, f, profile.ID)
				case "consent":
					_, mutationErr = service.ConsentDelete(f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, f, oauth.ConsentRemove, consent.ID(), consent.Version())})
				case "narrow-consent":
					_, mutationErr = service.ConsentUpdate(f.ctx, narrowRequest(t, f, consent, "late-profile-narrow", []string{"identity:read", "openid"}))
				case "grant":
					_, mutationErr = service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: "public-web", Token: refresh, Hint: oauth.TokenRefresh, Network: "192.0.2.1"})
				case "access":
					_, mutationErr = service.Revoke(f.ctx, oauth.RevokeRequest{ClientID: "public-web", Token: access, Hint: oauth.TokenAccess, Network: "192.0.2.1"})
				case "subject":
					_, mutationErr = f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{Subject}','"foreign"'::jsonb) WHERE kind=3`)
				case "key":
					mutationErr = signer.Compromise(f.ctx, "initial")
				case "deadline":
					shift.Store(int64(20 * time.Second))
				case "cancel":
					cancel()
				case "caller-deadline":
					<-ctx.Done()
				case "source-unavailable":
					_, mutationErr = f.pool.Raw().Exec(f.ctx, `ALTER TABLE identity.user_profiles RENAME TO unavailable_user_profiles`)
				}
			}
			pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("OAUTH_POSTGRES_TEST_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.Tracer = trace
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := pool.Close(cleanup); err != nil {
					t.Error("profile traced pool cleanup failed")
				}
			}()
			store, err := oauthpostgres.NewStore(pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "caller-deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 20*time.Millisecond)
				defer stop()
			}
			out, err := store.UserInfo(ctx, oauth.UserInfoCommand{Request: request, Client: f.oauth.Protocol.Clients[0]})
			if mutationErr != nil {
				t.Fatal("actual late profile fixture mutation failed", mutationErr)
			}
			if trace.reads.Load() < trace.at {
				t.Fatal("late primary profile boundary not reached")
			}
			if err == nil || out.Profile != nil || out.ExpectedSubject != "" || out.Identifiers != nil {
				t.Fatal("late authority failure returned partial profile claims", err)
			}
		})
	}
}

func TestNativeOIDCProfileSchemaAndSelectionFailClosed(t *testing.T) {
	f := profilePasswordFixture(t, false)
	service, child, _, _, _ := profileFixture(t, &f)
	mutateNativeProfile(t, f, "Private current name")
	code, proof := oidcCode(t, f, service, "schema-profile")
	issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: proof, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	access, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}
	if info, err := child.UserInfo(f.ctx, request); err != nil || info.Name == "" {
		t.Fatal("baseline name unavailable", err)
	}
	for _, mode := range []string{"missing", "unknown-schema", "changed-definition"} {
		t.Run(mode, func(t *testing.T) {
			config := f.oauth
			selected := *config.ProfileUserInfo
			selected.AttributeSchemas = []identity.AttributeSchema{nativeProfileSchema()}
			config.ProfileUserInfo = &selected
			if mode == "missing" {
				config.ProfileUserInfo = nil
			} else if mode == "unknown-schema" {
				selected.ProfileSchema.ID = "unselected"
			} else {
				selected.AttributeSchemas[0].Fields[0].Default.Scalar.String = "different-immutable-definition"
			}
			store, err := oauthpostgres.NewStore(f.pool, config, f.keys)
			if mode != "changed-definition" {
				if err == nil {
					t.Fatal("missing/unknown profile source configured")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := store.UserInfo(f.ctx, oauth.UserInfoCommand{Request: request, Client: config.Protocol.Clients[0]})
			if err == nil || out.Profile != nil || out.ExpectedSubject != "" {
				t.Fatal("immutable stored/configured schema mismatch disclosed profile", err)
			}
		})
	}
	// A disabled child must neither accept profile scope nor expose the name
	// even when the native adapter itself supports that selected source.
	core, err := oauth.NewService(f.oauth.Protocol, oauth.Dependencies{Sessions: f.sessions, Store: mustProfileStore(t, f)})
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := op.NewService(op.Config{Issuer: f.oauth.Protocol.Issuer, JWKSURI: f.oauth.Protocol.Issuer.String() + "/oauth2/jwks", UserInfoEndpoint: f.oauth.Protocol.Issuer.String() + "/oauth2/userinfo", Signing: new(oauth.SigningService), SubjectKey: [32]byte{42}, Clock: f.oauth.Protocol.Clock, MaximumDuration: time.Second}, core)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := disabled.UserInfo(f.ctx, request); err == nil || out != (op.UserInfo{}) {
		t.Fatal("disabled child disclosed a profile name", err)
	}
}

func mustProfileStore(t *testing.T, f authenticatedPasswordFixture) *oauthpostgres.Store {
	t.Helper()
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
