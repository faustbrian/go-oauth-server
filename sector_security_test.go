package oauthserver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sectorTestValidator(t *testing.T, handler http.Handler, duration time.Duration) (*SectorValidator, SectorRegistrationRequest) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	uri := "https://example.com:" + u.Port() + "/sector.json"
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	issuer, _ := NewIssuer("https://issuer.example")
	owner, _ := NewPlatformOwner("platform")
	v, err := NewSectorValidator(SectorValidatorConfig{Issuer: issuer, Environment: "test", MaximumDuration: duration, RootCAs: roots, Endpoints: []SectorEndpoint{{URI: uri, Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}})
	if err != nil {
		t.Fatal(err)
	}
	return v, SectorRegistrationRequest{URI: uri, PolicyID: "subjects", PolicyVersion: 1, Client: Client{ID: "client", Owner: owner, Version: 1, Public: true, AuthenticationMethod: "none", Resource: "https://resource.example", Redirects: []string{"https://client.example/cb", "https://other.example/cb"}, Scopes: []string{"openid"}}}
}

func TestSectorRemoteDocumentsAndTransportFailClosed(t *testing.T) {
	good := `["https://client.example/cb","https://other.example/cb"]`
	for _, tc := range []struct {
		name, body, media, encoding, location string
		status                                int
	}{
		{"valid", good, "application/json", "", "", 200},
		{"superset", `["https://client.example/cb","https://other.example/cb","https://third.example/cb"]`, "application/json", "", "", 200},
		{"missing", `["https://client.example/cb"]`, "application/json", "", "", 200},
		{"wrong-case", `["https://Client.example/cb","https://other.example/cb"]`, "application/json", "", "", 200},
		{"duplicate", `["https://client.example/cb","https://client.example/cb","https://other.example/cb"]`, "application/json", "", "", 200},
		{"escaped-duplicate", `["https://client.example/cb","https://client.example/\u0063b","https://other.example/cb"]`, "application/json", "", "", 200},
		{"object", `{"redirects":` + good + `}`, "application/json", "", "", 200},
		{"nested", `[["https://client.example/cb"]]`, "application/json", "", "", 200},
		{"null", `null`, "application/json", "", "", 200},
		{"trailing", good + `[]`, "application/json", "", "", 200},
		{"oversize", strings.Repeat(" ", 65537) + good, "application/json", "", "", 200},
		{"chunked-oversize", strings.Repeat(" ", 65537) + good, "application/json", "", "", 200},
		{"downgrade-value", `["http://client.example/cb","https://other.example/cb"]`, "application/json", "", "", 200},
		{"wrong-media", good, "text/html", "", "", 200},
		{"duplicate-media", good, "application/json", "", "", 200},
		{"compressed", good, "application/json", "gzip", "", 200},
		{"not-found", good, "application/json", "", "", 404},
		{"redirect", good, "application/json", "", "https://elsewhere.example/sector.json", 302},
		{"downgrade-redirect", good, "application/json", "", "http://127.0.0.1/sector.json", 302},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			v, request := sectorTestValidator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" || r.URL.RequestURI() != "/sector.json" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Accept-Encoding") != "" {
					t.Error("registration fetch changed target or forwarded ambient credentials/compression")
				}
				w.Header().Set("Content-Type", tc.media)
				w.Header().Set("Content-Encoding", tc.encoding)
				w.Header().Set("Location", tc.location)
				if tc.name == "duplicate-media" {
					w.Header().Add("Content-Type", "text/html")
				}
				w.WriteHeader(tc.status)
				if tc.name == "chunked-oversize" {
					w.(http.Flusher).Flush()
				}
				_, _ = w.Write([]byte(tc.body))
			}), time.Second)
			validated, err := v.Validate(context.Background(), request)
			allowed := tc.name == "valid" || tc.name == "superset"
			if allowed != (err == nil) || !allowed && (validated.state != nil || !errors.Is(err, ErrAccessDenied)) || calls.Load() != 1 {
				t.Fatal("incorrect closed registration outcome", err)
			}
		})
	}
}

func TestSectorExactEgressAndTLSOwnership(t *testing.T) {
	var calls atomic.Int32
	v, request := sectorTestValidator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`["https://client.example/cb","https://other.example/cb"]`))
	}), time.Second)
	for _, uri := range []string{strings.Replace(request.URI, "/sector.json", "/changed.json", 1), strings.Replace(request.URI, "example.com", "foreign.example", 1), strings.Replace(request.URI, "https:", "http:", 1), request.URI + "#fragment", "https://user:pass@example.com/sector.json"} {
		changed := request
		changed.URI = uri
		if result, err := v.Validate(context.Background(), changed); err == nil || result.state != nil {
			t.Fatal("unregistered/unsafe exact URI admitted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid URI reached network")
	}
	// Root trust is owned and copied; accepting arbitrary HTTP clients or
	// InsecureSkipVerify here would turn fetched provenance into caller assertion.
	untrusted := *v
	untrusted.config.RootCAs = x509.NewCertPool()
	if result, err := untrusted.Validate(context.Background(), request); err == nil || result.state != nil {
		t.Fatal("untrusted TLS minted registration evidence")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.Validate(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was not preserved", err)
	}
	if result, err := (*SectorValidator)(nil).Validate(context.Background(), request); err == nil || result.state != nil {
		t.Fatal("zero validator minted evidence")
	}
}

func TestSectorImplicitDNSAddressesRejectSpecialRanges(t *testing.T) {
	// IANA special-purpose registries include globally-unicast anycast and
	// transition destinations not rejected by netip's ordinary address classes.
	for _, prefix := range []string{"192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.175.48.0/24", "2620:4f:8000::/48"} {
		t.Run(prefix, func(t *testing.T) {
			p := netip.MustParsePrefix(prefix)
			for _, address := range []netip.Addr{p.Addr(), p.Addr().Next()} {
				if publicSectorAddress(address) {
					t.Fatal("implicit IANA special-purpose DNS destination admitted", address)
				}
			}
		})
	}
	if publicSectorAddress(netip.MustParseAddr("192.88.99.2")) || publicSectorAddress(netip.MustParseAddr("::ffff:192.88.99.2")) {
		t.Fatal("special-purpose relay reached implicit outbound admission")
	}
	for _, value := range []string{"0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.0.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "::", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "64:ff9b::7f00:1", "2001:db8::1", "2002:7f00:1::", "3fff::1"} {
		if publicSectorAddress(netip.MustParseAddr(value)) {
			t.Fatal("implicit private/special DNS destination admitted")
		}
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "2606:4700:4700::1111"} {
		if !publicSectorAddress(netip.MustParseAddr(value)) {
			t.Fatal("public address was incorrectly excluded")
		}
	}
}

func TestSectorImplicitLocalDNSAndBodyTimeoutDeny(t *testing.T) {
	v, request := sectorTestValidator(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}), 100*time.Millisecond)
	if result, err := v.Validate(context.Background(), request); !errors.Is(err, ErrAccessDenied) || result.state != nil {
		t.Fatal("expired fetch budget minted registration evidence", err)
	}
	local := *v
	local.config.Endpoints = []SectorEndpoint{{URI: strings.Replace(request.URI, "example.com", "localhost", 1)}}
	request.URI = local.config.Endpoints[0].URI
	if result, err := local.Validate(context.Background(), request); !errors.Is(err, ErrAccessDenied) || result.state != nil {
		t.Fatal("implicit loopback DNS was allowed", err)
	}
}

func FuzzSectorDocumentFlatBounded(f *testing.F) {
	f.Add([]byte(`["https://client.example/cb"]`))
	f.Add([]byte(`[[null]]`))
	f.Add([]byte(`["https://client.example/cb","https://client.example/\u0063b"]`))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if sectorDocument(wire, []string{"https://client.example/cb"}) {
			var decoded []string
			if len(wire) > 65536 || json.Unmarshal(wire, &decoded) != nil || len(decoded) == 0 || len(decoded) > 64 {
				t.Fatal("unbounded/foreign document authorized registration")
			}
			seen, required := map[string]bool{}, false
			for _, value := range decoded {
				if seen[value] || !validRedirect(value) {
					t.Fatal("duplicate or invalid redirect authorized registration")
				}
				seen[value] = true
				required = required || value == "https://client.example/cb"
			}
			if !required {
				t.Fatal("missing registered redirect authorized registration")
			}
		}
	})
}
