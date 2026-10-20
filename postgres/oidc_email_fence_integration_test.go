//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type emailReadTraceKey struct{}

// The tracer controls only the timing of real committed primary changes. It
// does not replace token, consent, identifier, credential or session authority.
type emailReadTrace struct {
	reads atomic.Uint32
	late  func()
}

func (t *emailReadTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, emailReadTraceKey{}, strings.Contains(data.SQL, "FROM identity.users u\n LEFT JOIN LATERAL"))
}

func (t *emailReadTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	selected, _ := ctx.Value(emailReadTraceKey{}).(bool)
	if selected && t.reads.Add(1) == 2 {
		t.late()
	}
}

type emailClock func() time.Time

func (f emailClock) Now() time.Time { return f() }

func TestNativeOIDCEmailLateAuthorityChangesReturnNoClaims(t *testing.T) {
	for _, mode := range []string{"identifier", "verification", "token", "subject", "consent", "credential", "deadline", "cancel", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f := passwordFixture(t)
			if mode == "consent" {
				enableConsentManagement(t, &f)
			}
			service, child, _, _, _ := emailFixture(t, &f)
			code, verifier := oidcCode(t, f, service, "late-email-fence")
			issued, err := service.Token(f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: "public-web", Code: code, CodeVerifier: verifier, RedirectURI: "https://client.example/callback", Network: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			access, err := issued.AccessToken.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			if info, err := child.UserInfo(f.ctx, oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}); err != nil || info.Email == "" {
				t.Fatal("baseline email unavailable", err)
			}
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			var shift atomic.Int64
			f.oauth.Protocol.Clock = emailClock(func() time.Time { return time.Now().Add(time.Duration(shift.Load())) })
			var mutationErr error
			trace := &emailReadTrace{late: func() {
				statement := ""
				switch mode {
				case "identifier":
					statement = `UPDATE identity.users SET identifier_version=identifier_version+1`
				case "verification":
					statement = `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=3,version=version+1,verification_version=verification_version+1`
				case "token":
					statement = `UPDATE oauth_store.artifacts SET state='revoked' WHERE kind=3`
				case "subject":
					statement = `UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{Subject}','"foreign"'::jsonb) WHERE kind=3`
				case "consent":
					statement = `UPDATE oauth_store.consents SET state='revoked',version=version+1,revoked_command='late-consent-withdrawal',revoked_at=clock_timestamp()`
				case "credential":
					statement = `UPDATE identity.credential_references SET enabled=false`
				case "deadline":
					shift.Store(int64(20 * time.Second))
				case "cancel":
					cancel()
				case "unavailable":
					statement = `ALTER TABLE identity.identifiers RENAME TO unavailable_identifiers`
				}
				if statement != "" {
					_, mutationErr = f.pool.Raw().Exec(f.ctx, statement)
				}
			}}
			pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("OAUTH_POSTGRES_TEST_DSN"), MaxConns: 2, Configure: func(config *database.PoolConfig) error {
				config.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
				config.ConnConfig.Tracer = trace
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := pool.Close(cleanup); err != nil {
					t.Error("traced pool cleanup failed")
				}
			}()
			store, err := oauthpostgres.NewStore(pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			out, err := store.UserInfo(ctx, oauth.UserInfoCommand{Request: oauth.UserInfoRequest{ClientID: "public-web", AccessToken: access}, Client: f.oauth.Protocol.Clients[0]})
			if mutationErr != nil {
				t.Fatal("late fixture mutation failed", mutationErr)
			}
			if trace.reads.Load() < 2 {
				t.Fatal("late authoritative boundary was not reached")
			}
			if err == nil || out.ExpectedSubject != "" || out.Identifiers != nil {
				t.Fatal("late authority failure returned partial UserInfo custody", err)
			}
		})
	}
}
