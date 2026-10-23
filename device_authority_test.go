package oauthserver_test

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestDeviceLookupDigestSeparatesAuthorityAndRejectsInexactEndpoints(t *testing.T) {
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		t.Fatal("lookup entropy unavailable")
	}
	key, err := oauth.NewTokenDigestKey(7, material[:])
	clear(material[:])
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := oauth.NewIssuer("https://issuer.example")
	scope := oauth.DeviceDigestScope{Issuer: issuer, Environment: "production", TenantID: "tenant", VerificationURI: issuer.String() + "/device", TokenEndpoint: issuer.String() + "/token", ClientID: "screen"}
	wire := strings.Repeat("A", 43)
	baseline, err := oauth.DeviceLookupDigest(key, scope, wire)
	if err != nil || baseline.KeyVersion != 7 {
		t.Fatal("canonical scoped device lookup rejected", err)
	}
	for _, mutate := range []func(*oauth.DeviceDigestScope){
		func(s *oauth.DeviceDigestScope) { s.Environment = "staging" },
		func(s *oauth.DeviceDigestScope) { s.TenantID = "another-tenant" },
		func(s *oauth.DeviceDigestScope) { s.ClientID = "another-screen" },
		func(s *oauth.DeviceDigestScope) { s.VerificationURI += "/other" },
		func(s *oauth.DeviceDigestScope) { s.TokenEndpoint += "/other" },
	} {
		changed := scope
		mutate(&changed)
		got, err := oauth.DeviceLookupDigest(key, changed, wire)
		if err != nil || got.Sum == baseline.Sum {
			t.Fatal("device lookup crossed immutable authority namespace", err)
		}
	}
	for _, suffix := range []string{"?", "#"} {
		changed := scope
		changed.VerificationURI += suffix
		if _, err := oauth.DeviceLookupDigest(key, changed, wire); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("device digest admitted inexact verification endpoint", err)
		}
	}
}

func TestDeviceClientSourceRequiresExplicitRegisteredPermission(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	c := coreConfig(t, now)
	request := oauth.DeviceClientSourceRequest{ClientID: "public-client", Scopes: []string{"identity:read"}}
	service, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: authorizationStore{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.DeviceClientSource(context.Background(), request); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("ordinary browser registration acquired device permission", err)
	}
	c.Clients[0].DeviceAuthorization = true
	service, err = oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: authorizationStore{}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.DeviceClientSource(context.Background(), request)
	if err != nil || out.Client.ID != request.ClientID || out.Issuer != c.Issuer || out.Resource != c.Resource || len(out.Scopes) != 1 {
		t.Fatal("registered public device client was not admitted", err)
	}
	out.Client.Scopes[0] = "identity:write"
	out.Scopes[0] = "identity:write"
	if _, err := service.DeviceClientSource(context.Background(), request); err != nil {
		t.Fatal("projection mutated registered authority", err)
	}
	request.Scopes = []string{"identity:write"}
	if _, err := service.DeviceClientSource(context.Background(), request); !errors.Is(err, oauth.ErrInvalidScope) {
		t.Fatal("expanding device scope admitted", err)
	}
	request.Scopes = []string{"identity:read"}
	request.Resource = "https://foreign.example"
	if _, err := service.DeviceClientSource(context.Background(), request); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("foreign device resource admitted", err)
	}
}

func TestDeviceClientSourceUsesActualConfidentialAuthentication(t *testing.T) {
	sessions, _, _, _ := coreSessionFixture(t)
	c, wire := confidentialCoreConfig(t)
	c.Clients[0].DeviceAuthorization = true
	s, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: authorizationStore{}})
	if err != nil {
		t.Fatal(err)
	}
	r := oauth.DeviceClientSourceRequest{ClientID: c.Clients[0].ID, Scopes: []string{"identity:read"}}
	if _, err := s.DeviceClientSource(context.Background(), r); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatal("confidential device client omitted authentication", err)
	}
	r.ClientAuthentication, err = oauth.ParseClientAuthentication([]string{clientBasicHeader(r.ClientID, wire)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeviceClientSource(context.Background(), r); err != nil {
		t.Fatal("actual Basic credential was not admitted", err)
	}
}

func TestDeviceSessionSourceConservesRealRecentSession(t *testing.T) {
	sessions, bearer, now, observed := coreSessionFixture(t)
	c := coreConfig(t, now)
	s, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: authorizationStore{}})
	if err != nil {
		t.Fatal(err)
	}
	r := oauth.DeviceSessionSourceRequest{TenantID: "tenant", Session: bearer}
	out, err := s.DeviceSessionSource(context.Background(), r)
	if err != nil || out.ValidateAt(now) != nil || out.Session.ValidUntil() != observed.ValidUntil.Add(-time.Millisecond) {
		t.Fatal("real session custody/deadline was lost", err)
	}
	if out.ValidateAt(now.Add(20*time.Second)) == nil {
		t.Fatal("expired observation became renewable device authority")
	}
	observed.Active = false
	if _, err := s.DeviceSessionSource(context.Background(), r); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("inactive browser authorized device review", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.DeviceSessionSource(ctx, r); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled device review admitted", err)
	}
}
