package oauthserver_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestSectorHTTPSRegistrationBindsExactClientAndRedirectSet(t *testing.T) {
	now := time.Now().UTC()
	config := coreConfig(t, now)
	client := config.Clients[0]
	client.Redirects = []string{"https://client.example/callback", "https://other.example/callback"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/sector.json" {
			t.Error("validator fetched a different registration URI")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(client.Redirects)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	uri := "https://example.com:" + u.Port() + "/sector.json"
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	validator, err := oauth.NewSectorValidator(oauth.SectorValidatorConfig{Issuer: config.Issuer, Environment: config.Environment, MaximumDuration: time.Second, RootCAs: roots, Endpoints: []oauth.SectorEndpoint{{URI: uri, Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}})
	if err != nil {
		t.Fatal(err)
	}
	validated, err := validator.Validate(context.Background(), oauth.SectorRegistrationRequest{Client: client, URI: uri, PolicyID: "subjects", PolicyVersion: 1})
	if err != nil {
		t.Fatal("actual HTTPS sector document did not authorize exact multi-host registration", err)
	}
	registration := validated.SubjectRegistration()
	if registration.SectorHost() != "example.com" || registration.SectorIdentifierURI() != uri {
		t.Fatal("sector did not come from exact validated URI")
	}
	client.SubjectRegistration = &registration
	config.Clients = []oauth.Client{client}
	if _, err := config.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("serialized policy alone granted multi-host authority")
	}
	config.SectorRegistrations = []oauth.ValidatedSectorRegistration{validated}
	if _, err := config.Validated(); err != nil {
		t.Fatal("fetched exact registration denied", err)
	}
	wire, err := json.Marshal(registration)
	var restored oauth.OIDCSubjectRegistration
	if err != nil || json.Unmarshal(wire, &restored) != nil || restored != registration {
		t.Fatal("comparable sector policy did not preserve stored JSON identity", err)
	}
	for _, broken := range []string{
		string(wire[:len(wire)-1]) + `,"SectorIdentifierURI":"https://foreign.example/sector.json"}`,
		`{"Type":"pairwise","SectorHost":"example.com","PolicyID":"subjects","PolicyVersion":1,"SectorIdentifierURI":"https://example.com/sector.json"}`,
	} {
		if json.Unmarshal([]byte(broken), &restored) == nil || restored != registration {
			t.Fatal("duplicate/incomplete URI policy changed validated stored identity")
		}
	}
	duplicate := config
	duplicate.SectorRegistrations = []oauth.ValidatedSectorRegistration{validated, validated}
	if _, err := duplicate.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("duplicate registration ownership admitted")
	}
	forged := config
	forged.SectorRegistrations = []oauth.ValidatedSectorRegistration{{}}
	if _, err := forged.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("zero provenance admitted URI policy")
	}
	for _, change := range []func(*oauth.Client){
		func(c *oauth.Client) { c.ID = "foreign" },
		func(c *oauth.Client) { c.Version++ },
		func(c *oauth.Client) {
			c.Redirects = []string{"https://client.example/changed", "https://other.example/callback"}
		},
	} {
		changed := client
		change(&changed)
		config.Clients = []oauth.Client{changed}
		if _, err := config.Validated(); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("foreign/stale/changed registration reused HTTPS evidence")
		}
	}
	if err := validated.ValidateClient(config.Issuer, "foreign", client); !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("registration evidence crossed environment")
	}
}
