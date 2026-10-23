package oauthserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestEndSessionRequiresSelectedOwnerAndClosedDelivery(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	core, err := oauth.NewService(coreConfig(t, now), oauth.Dependencies{Sessions: sessions, Store: authorizationStore{}})
	if err != nil {
		t.Fatal(err)
	}
	if core.EndSessionConfigured() {
		t.Fatal("ordinary OAuth store advertised logout")
	}
	if _, err := core.EndSession(context.Background(), oauth.EndSessionInput{}); err == nil {
		t.Fatal("unselected logout admitted")
	}
	command, _ := identity.NewCommandID()
	committed := oauth.Completion{Outcome: identity.CommitOutcomeCommitted, CommandID: command}
	for _, invalid := range []oauth.EndSessionResult{
		{},
		{Outcome: oauth.EndSessionRedirect, Completion: committed},
		{Outcome: oauth.EndSessionLocalOnly, RedirectURI: "https://client.example/out", Completion: committed},
		{Outcome: oauth.EndSessionUnknownReconciliation, RedirectURI: "https://client.example/out", Completion: oauth.Completion{Outcome: identity.CommitOutcomeUnknown, CommandID: command}},
		{Outcome: oauth.EndSessionRedirect, RedirectURI: "https://client.example/out", State: "original", Completion: oauth.Completion{Outcome: identity.CommitOutcomeUnknown, CommandID: command}},
		{Outcome: oauth.EndSessionRedirect, RedirectURI: "https://client.example/out", Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted, CommandID: command, Replayed: true}},
		{Outcome: oauth.EndSessionLocalOnly, State: "not-a-redirect", Completion: committed},
		{Outcome: oauth.EndSessionLocalOnly, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted, CommandID: command, Replayed: true}, ValidUntil: now.Add(time.Second)},
		{Outcome: oauth.EndSessionUnknownReconciliation, Completion: oauth.Completion{Outcome: identity.CommitOutcomeUnknown, CommandID: command}, ValidUntil: now.Add(time.Second)},
	} {
		if _, err := json.Marshal(invalid); err == nil {
			t.Fatal("mixed/zero end-session result serialized as success")
		}
	}
	for _, valid := range []oauth.EndSessionResult{
		{Outcome: oauth.EndSessionRedirect, RedirectURI: "https://client.example/out", State: "opaque +/%?=&", Completion: committed, ValidUntil: now.Add(time.Second)},
		{Outcome: oauth.EndSessionLocalOnly, Completion: committed, ValidUntil: now.Add(time.Second)},
		{Outcome: oauth.EndSessionUnknownReconciliation, Completion: oauth.Completion{Outcome: identity.CommitOutcomeUnknown, CommandID: command}},
	} {
		if _, err := json.Marshal(valid); err != nil {
			t.Fatal("closed valid result denied", err)
		}
	}
}

type endSessionDeliveryStore struct {
	oauth.Store
	call func(context.Context, oauth.EndSessionExecution) (oauth.EndSessionResult, error)
}

func (endSessionDeliveryStore) EndSessionSelected() bool { return true }
func (s endSessionDeliveryStore) EndSession(ctx context.Context, e oauth.EndSessionExecution) (oauth.EndSessionResult, error) {
	return s.call(ctx, e)
}

// This adversarial adapter proves core delivery conservation only. It cannot
// prove genuine issuance, session invalidation, native effects or recovery.
func TestEndSessionCoreCannotDeliverAlteredLateOrUnknownRedirect(t *testing.T) {
	sessions, browser, now, _ := coreSessionFixture(t)
	originalTime := now
	config := coreConfig(t, now)
	config.Clock = clockFunc(func() time.Time { return now })
	config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
	config.Clients[0].Scopes = append(config.Clients[0].Scopes, "openid")
	config.Clients[0].PostLogoutRedirects = []string{"https://client.example/out"}
	authority, _ := oauth.NewSigningAuthority(clockFunc(func() time.Time { return now }), time.Minute)
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = authority.AddKey("test", private)
	keys, _ := authority.PublicKeys(context.Background())
	_ = authority.Activate("test")
	wire, _ := authority.SignCompact(context.Background(), []byte(`{"test":"signature-only"}`), now.Add(time.Minute))
	signer, _ := oauth.NewSigningService(authority, &retainedVerificationKey{key: keys[0]})
	hint, err := signer.VerifyCompact(context.Background(), wire)
	if err != nil {
		t.Fatal(err)
	}
	csrf, _ := session.NewCSRFToken()
	input := oauth.EndSessionInput{TenantID: "tenant", Session: browser, CSRF: csrf, Origin: config.Issuer.String(), Network: "192.0.2.1", Hint: hint, ClientID: config.Clients[0].ID, Subject: "opaque-subject", IssuedAt: now, ExpiresAt: now.Add(time.Minute), PostLogoutRedirectURI: "https://client.example/out", State: "original"}
	command, _ := identity.NewCommandID()
	valid := oauth.EndSessionResult{Outcome: oauth.EndSessionRedirect, RedirectURI: input.PostLogoutRedirectURI, State: input.State, Completion: oauth.Completion{Outcome: identity.CommitOutcomeCommitted, CommandID: command}, ValidUntil: now.Add(time.Second)}
	for _, mode := range []string{"valid", "uri", "state", "late", "renewed", "unknown-redirect", "historical-redirect", "local-fallback", "cancel", "unknown", "unknown-error", "proof-read-start"} {
		t.Run(mode, func(t *testing.T) {
			now = originalTime
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			out := valid
			switch mode {
			case "uri":
				out.RedirectURI = "https://foreign.example/out"
			case "state":
				out.State = "foreign"
			case "late":
				out.ValidUntil = now
			case "renewed":
				out.ValidUntil = now.Add(20*time.Second + time.Nanosecond)
			case "unknown-redirect":
				out.Completion.Outcome = identity.CommitOutcomeUnknown
			case "historical-redirect":
				out.Completion.Replayed = true
			case "local-fallback":
				out.Outcome = oauth.EndSessionLocalOnly
				out.RedirectURI = ""
				out.State = ""
			case "unknown", "unknown-error":
				out = oauth.EndSessionResult{Outcome: oauth.EndSessionUnknownReconciliation, Completion: oauth.Completion{Outcome: identity.CommitOutcomeUnknown, CommandID: command}}
			case "proof-read-start":
				now = originalTime.Add(time.Second)
				out.ValidUntil = now.Add(20 * time.Second)
			}
			store := endSessionDeliveryStore{call: func(ctx context.Context, e oauth.EndSessionExecution) (oauth.EndSessionResult, error) {
				if e.Input.State != input.State || mode != "proof-read-start" && e.StartedAt != now || e.Client.PostLogoutRedirects[0] != input.PostLogoutRedirectURI {
					t.Fatal("core lost original policy/custody")
				}
				if mode == "cancel" {
					cancel()
				}
				if mode == "unknown-error" {
					return out, oauth.ErrUnavailable
				}
				return out, nil
			}}
			service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
			if err != nil || !service.EndSessionConfigured() {
				t.Fatal("selected adapter setup", err)
			}
			got, err := service.EndSession(ctx, input)
			if mode == "valid" {
				if err != nil || got.RedirectURI != input.PostLogoutRedirectURI || got.State != input.State {
					t.Fatal("exact delivery denied", err)
				}
				return
			}
			if mode == "unknown" {
				if err != nil || got.Outcome != oauth.EndSessionUnknownReconciliation || got.RedirectURI != "" || got.State != "" {
					t.Fatal("unknown became redirect", err)
				}
				return
			}
			if mode == "unknown-error" {
				if !errors.Is(err, oauth.ErrUnavailable) || got.Outcome != oauth.EndSessionUnknownReconciliation || got.Completion.CommandID != command || got.RedirectURI != "" || got.State != "" || !got.ValidUntil.IsZero() {
					t.Fatal("failed acknowledgement lost original unknown metadata", err)
				}
				return
			}
			if err == nil || got.RedirectURI != "" || got.State != "" {
				t.Fatal("altered/late/historical redirect escaped adapter boundary", err)
			}
		})
	}
}
