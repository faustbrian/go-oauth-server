package oauthserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestConsentCommandsBoundAndRedactBorrowedBrowserCustody(t *testing.T) {
	_, bearer, _, _ := coreSessionFixture(t)
	spec := oauth.ConsentCommandSpec{Operation: oauth.ConsentRead, TenantID: "tenant", Session: bearer, ID: "abcdefghijklmnopqrstuw"}
	command, err := oauth.NewConsentCommand(spec)
	if err != nil || command.Input().ID != spec.ID {
		t.Fatal("own bounded query rejected", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", command), bearer.Token()) {
		t.Fatal("browser leaked")
	}
	if _, err := json.Marshal(command); err == nil {
		t.Fatal("borrowed browser serialized")
	}
	for _, change := range []func(*oauth.ConsentCommandSpec){
		func(s *oauth.ConsentCommandSpec) { s.ID = "" },
		func(s *oauth.ConsentCommandSpec) { s.Version = 1 },
		func(s *oauth.ConsentCommandSpec) { s.Limit = 1 },
		func(s *oauth.ConsentCommandSpec) { s.Operation = oauth.ConsentRemove },
		func(s *oauth.ConsentCommandSpec) { s.Operation = oauth.ConsentEnumerate; s.ID = ""; s.Limit = 65 },
	} {
		invalid := spec
		change(&invalid)
		if _, err := oauth.NewConsentCommand(invalid); err == nil {
			t.Fatal("cross-variant/unbounded command admitted")
		}
	}
}

func TestConsentProjectionOwnsScopesAndPage(t *testing.T) {
	_, _, now, _ := coreSessionFixture(t)
	scopes := []string{"identity:read"}
	consent, err := oauth.NewConsent(oauth.ConsentSpec{ID: "abcdefghijklmnopqrstuw", ClientID: "public-client", Version: 1, Scopes: scopes, GrantedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	scopes[0] = "identity:write"
	copy := consent.Scopes()
	copy[0] = "other"
	if consent.Scopes()[0] != "identity:read" {
		t.Fatal("consent aliases caller scopes")
	}
	items := []oauth.Consent{consent}
	page, err := oauth.NewConsentListPage(items)
	if err != nil {
		t.Fatal(err)
	}
	items[0] = oauth.Consent{}
	copyItems := page.Items()
	copyItems[0] = oauth.Consent{}
	if page.Items()[0].ID() != consent.ID() {
		t.Fatal("page aliases consumer")
	}
}

func TestConsentManagementFailsClosedWithoutNativeOwnerOrSession(t *testing.T) {
	sessions, bearer, now, _ := coreSessionFixture(t)
	service, err := oauth.NewService(coreConfig(t, now), oauth.Dependencies{Sessions: sessions, Store: authorizationStore{}})
	if err != nil {
		t.Fatal(err)
	}
	command, _ := oauth.NewConsentCommand(oauth.ConsentCommandSpec{Operation: oauth.ConsentRead, TenantID: "tenant", Session: bearer, ID: "abcdefghijklmnopqrstuw"})
	out, err := service.ConsentGet(context.Background(), oauth.ConsentGetRequest{Consent: command})
	if !errors.Is(err, oauth.ErrAccessDenied) || out.Consent.ID() != "" {
		t.Fatal("unselected management disclosed consent", err)
	}
	if _, err := service.ConsentList(context.Background(), oauth.ConsentListRequest{}); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("zero list admitted", err)
	}
	if _, err := service.ConsentDelete(context.Background(), oauth.ConsentDeleteRequest{}); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("zero delete admitted", err)
	}
}

// Core delegation only; native tests retain real current identity, transaction,
// CSRF, audit and lifecycle ownership rather than this storage-neutral seam.
type consentStore struct {
	oauth.Store
	get    func(context.Context, oauth.ConsentExecution) (oauth.ConsentGetResult, error)
	remove func(context.Context, oauth.ConsentExecution) (oauth.ConsentDeleteResult, error)
}

func (s consentStore) ConsentGet(ctx context.Context, c oauth.ConsentExecution) (oauth.ConsentGetResult, error) {
	return s.get(ctx, c)
}
func (consentStore) ConsentList(context.Context, oauth.ConsentExecution) (oauth.ConsentListResult, error) {
	return oauth.ConsentListResult{}, oauth.ErrAccessDenied
}
func (s consentStore) ConsentDelete(ctx context.Context, c oauth.ConsentExecution) (oauth.ConsentDeleteResult, error) {
	return s.remove(ctx, c)
}

func TestConsentDeleteRequiresFifteenMinuteOriginalProofNotGeneralSessionFreshness(t *testing.T) {
	sessions, bearer, now, observation := coreSessionFixture(t)
	spec, _ := observation.Session.Bindings()
	spec.Remember, _ = session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: 24 * time.Hour})
	spec.Authentication.Proof.IssuedAt = now.Add(-16 * time.Minute)
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	observation.Session = record
	lifetime, err := record.Lifetime(now)
	if err != nil || !lifetime.Fresh {
		t.Fatal("fixture must remain generally fresh", err)
	}
	called := false
	store := consentStore{remove: func(context.Context, oauth.ConsentExecution) (oauth.ConsentDeleteResult, error) {
		called = true
		return oauth.ConsentDeleteResult{}, oauth.ErrUnavailable
	}}
	service, err := oauth.NewService(coreConfig(t, now), oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	csrf, _ := session.NewCSRFToken()
	command, err := oauth.NewConsentCommand(oauth.ConsentCommandSpec{Operation: oauth.ConsentRemove, TenantID: "tenant", Session: bearer, ID: "abcdefghijklmnopqrstuw", Version: 1, CSRF: csrf, Origin: "https://issuer.example", Network: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConsentDelete(context.Background(), oauth.ConsentDeleteRequest{Consent: command}); !errors.Is(err, oauth.ErrAccessDenied) || called {
		t.Fatal("24h session freshness admitted stale sensitive proof", err)
	}
}

func TestConsentGetDelegatesGenuineOriginalCustodyAndWithholdsFailedReads(t *testing.T) {
	sessions, bearer, now, observation := coreSessionFixture(t)
	projection, err := oauth.NewConsent(oauth.ConsentSpec{ID: "abcdefghijklmnopqrstuw", ClientID: "public-client", Version: 1, Scopes: []string{"identity:read"}, GrantedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	fail := false
	store := consentStore{get: func(ctx context.Context, c oauth.ConsentExecution) (oauth.ConsentGetResult, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok || c.Session.ValidateAt(now) != nil || c.Session.ValidUntil() != observation.ValidUntil.Add(-time.Millisecond) || c.Command.Input().Session.Token() != bearer.Token() {
			t.Fatal("genuine bounded original session custody lost")
		}
		bindings, _ := c.Session.Session.Bindings()
		if bindings.UserID != "user" {
			t.Fatal("caller selected another actor")
		}
		if fail {
			return oauth.ConsentGetResult{Consent: projection}, oauth.ErrUnavailable
		}
		return oauth.ConsentGetResult{Consent: projection}, nil
	}}
	service, err := oauth.NewService(coreConfig(t, now), oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	command, _ := oauth.NewConsentCommand(oauth.ConsentCommandSpec{Operation: oauth.ConsentRead, TenantID: "tenant", Session: bearer, ID: projection.ID()})
	out, err := service.ConsentGet(context.Background(), oauth.ConsentGetRequest{Consent: command})
	if err != nil || out.Consent.ID() != projection.ID() {
		t.Fatal("own consent unavailable", err)
	}
	fail = true
	if out, err := service.ConsentGet(context.Background(), oauth.ConsentGetRequest{Consent: command}); !errors.Is(err, oauth.ErrUnavailable) || out.Consent.ID() != "" {
		t.Fatal("failed read disclosed consent", err)
	}
	observation.Active = false
	if out, err := service.ConsentGet(context.Background(), oauth.ConsentGetRequest{Consent: command}); !errors.Is(err, oauth.ErrAccessDenied) || out.Consent.ID() != "" || calls != 2 {
		t.Fatal("inactive session reached consent owner", err)
	}
}
