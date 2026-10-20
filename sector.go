package oauthserver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// SectorEndpoint is trusted deployment egress policy for one exact HTTPS URI.
// Empty Addresses uses public-only DNS. Nonempty Addresses pins the only dial
// destinations, including explicitly trusted private endpoints; TLS still checks
// the URI host. No request, redirect, proxy or subsequent DNS can change them.
type SectorEndpoint struct {
	URI       string
	Addresses []netip.Addr
}

// SectorValidatorConfig selects registration-time HTTPS validation, not a
// dynamic-registration endpoint. Issuer/environment bind resulting provenance.
// Endpoints contains 1..64 exact allowed URIs. MaximumDuration is 1ms..5s for
// DNS, connection, TLS, headers and body together. RootCAs selects deployment
// trust (nil uses system roots); construction copies the selected pool and pins.
type SectorValidatorConfig struct {
	Issuer          Issuer
	Environment     string
	Endpoints       []SectorEndpoint
	MaximumDuration time.Duration
	RootCAs         *x509.CertPool
}

// SectorValidator owns bounded HTTPS fetching and validation. It is immutable,
// concurrent-safe and has no background work, shared transport or response cache.
// Each call closes its connection/response; callers own supplied contexts.
type SectorValidator struct{ config SectorValidatorConfig }

// NewSectorValidator freezes explicit egress/TLS policy without IO. There is no
// generic HTTP/fetch callback: only this owner can create fetched provenance.
func NewSectorValidator(config SectorValidatorConfig) (*SectorValidator, error) {
	if !validOrigin(config.Issuer.String()) || !identifier(config.Environment) || config.MaximumDuration < time.Millisecond || config.MaximumDuration > 5*time.Second || len(config.Endpoints) < 1 || len(config.Endpoints) > 64 {
		return nil, ErrInvalidRequest
	}
	config.Endpoints = slices.Clone(config.Endpoints)
	seen := make(map[string]bool, len(config.Endpoints))
	for i, endpoint := range config.Endpoints {
		if _, err := sectorURI(endpoint.URI); err != nil || seen[endpoint.URI] || len(endpoint.Addresses) > 16 {
			return nil, ErrInvalidRequest
		}
		seen[endpoint.URI] = true
		endpoint.URI = strings.Clone(endpoint.URI)
		endpoint.Addresses = slices.Clone(endpoint.Addresses)
		for j, address := range endpoint.Addresses {
			if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || slices.Contains(endpoint.Addresses[:j], address) {
				return nil, ErrInvalidRequest
			}
		}
		config.Endpoints[i] = endpoint
	}
	if config.RootCAs != nil {
		config.RootCAs = config.RootCAs.Clone()
	}
	return &SectorValidator{config: config}, nil
}

// SectorRegistrationRequest contains exact trusted client registration inputs.
// URI must match an allowed endpoint byte-for-byte. All registered redirects
// must occur in the fetched document. Policy identity never selects a key version.
type SectorRegistrationRequest struct {
	Client        Client
	URI, PolicyID string
	PolicyVersion uint64
}

type sectorRegistrationState struct {
	issuer        Issuer
	environment   string
	clientID      string
	clientVersion uint64
	registration  OIDCSubjectRegistration
}

// ValidatedSectorRegistration is immutable, opaque registration-time provenance
// created only after this package fetched/authenticated the exact HTTPS URI.
// It binds issuer/environment/client/version/policy/URI/exact redirect set. Copies
// are concurrent-safe. Zero denies. It is not serialized authority; deployments
// reconstruct it by fetching again when loading their selected configuration.
// OIDC Registration 1.0 errata2 section5 does not require periodic refetch/expiry.
type ValidatedSectorRegistration struct{ state *sectorRegistrationState }

// SubjectRegistration returns comparable, storable policy identity, not proof
// of retrieval by itself. Config admission separately requires this provenance.
func (v ValidatedSectorRegistration) SubjectRegistration() OIDCSubjectRegistration {
	if v.state == nil {
		return OIDCSubjectRegistration{}
	}
	return v.state.registration
}

// ValidateClient checks exact original registration ownership without IO or time
// renewal. Changed client version, URI, policy or redirect set requires refetch.
// It does not replace current account, grant, consent or revocation authority.
func (v ValidatedSectorRegistration) ValidateClient(issuer Issuer, environment string, client Client) error {
	if v.state == nil || v.state.issuer != issuer || v.state.environment != environment || v.state.clientID != client.ID || v.state.clientVersion != client.Version || client.SubjectRegistration == nil || *client.SubjectRegistration != v.state.registration {
		return ErrAccessDenied
	}
	if _, err := ValidateClient(client); err != nil {
		return ErrAccessDenied
	}
	return nil
}

func (ValidatedSectorRegistration) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (ValidatedSectorRegistration) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

func validateSectorRegistrations(config Config) error {
	if len(config.SectorRegistrations) > 64 {
		return ErrInvalidRequest
	}
	used := make([]bool, len(config.SectorRegistrations))
	for _, client := range config.Clients {
		if client.SubjectRegistration == nil || client.SubjectRegistration.uri == "" {
			continue
		}
		matches := 0
		for i, registration := range config.SectorRegistrations {
			if registration.ValidateClient(config.Issuer, config.Environment, client) == nil {
				matches++
				used[i] = true
			}
		}
		if matches != 1 {
			return ErrInvalidRequest
		}
	}
	for _, selected := range used {
		if !selected {
			return ErrInvalidRequest
		}
	}
	return nil
}

// Validate fetches the exact URI with verified TLS, no proxies, cookies,
// redirects, decompression or credential forwarding. Documents are <=64KiB,
// one flat JSON array of 1..64 unique HTTPS redirects, each <=2048 bytes. Network,
// TLS and remote validation failures return redacted ErrAccessDenied; malformed
// caller configuration returns ErrInvalidRequest. Cancellation is preserved.
func (v *SectorValidator) Validate(ctx context.Context, request SectorRegistrationRequest) (ValidatedSectorRegistration, error) {
	if v == nil || ctx == nil || !identifier(request.PolicyID) || request.PolicyVersion == 0 {
		return ValidatedSectorRegistration{}, ErrInvalidRequest
	}
	u, err := sectorURI(request.URI)
	if err != nil {
		return ValidatedSectorRegistration{}, err
	}
	var selected *SectorEndpoint
	for i := range v.config.Endpoints {
		if v.config.Endpoints[i].URI == request.URI {
			selected = &v.config.Endpoints[i]
			break
		}
	}
	if selected == nil {
		return ValidatedSectorRegistration{}, ErrAccessDenied
	}
	client := request.Client
	client.SubjectRegistration = nil
	client, err = ValidateClient(client)
	if err != nil || client.Workload != nil {
		return ValidatedSectorRegistration{}, ErrInvalidRequest
	}
	bounded, cancel := context.WithTimeout(ctx, v.config.MaximumDuration)
	defer cancel()
	addresses := slices.Clone(selected.Addresses)
	if len(addresses) == 0 {
		addresses, err = net.DefaultResolver.LookupNetIP(bounded, "ip", u.Hostname())
		if err != nil || len(addresses) == 0 || len(addresses) > 16 {
			return ValidatedSectorRegistration{}, sectorFailure(ctx)
		}
		for _, address := range addresses {
			if !publicSectorAddress(address) {
				return ValidatedSectorRegistration{}, ErrAccessDenied
			}
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialer := net.Dialer{Timeout: v.config.MaximumDuration}
	transport := &http.Transport{
		TLSClientConfig:    &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: v.config.RootCAs},
		DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 8192,
		TLSHandshakeTimeout: v.config.MaximumDuration, ResponseHeaderTimeout: v.config.MaximumDuration,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			// DNS is resolved and checked once, then literal dialing fences
			// rebinding; the transport still authenticates the original TLS host.
			for _, ip := range addresses {
				conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
			}
			return nil, ErrAccessDenied
		},
	}
	defer transport.CloseIdleConnections()
	remote := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(bounded, http.MethodGet, request.URI, nil)
	if err != nil {
		return ValidatedSectorRegistration{}, ErrInvalidRequest
	}
	req.Header.Set("Accept", "application/json")
	response, err := remote.Do(req)
	if err != nil {
		return ValidatedSectorRegistration{}, sectorFailure(ctx)
	}
	defer response.Body.Close()
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	encoded := false
	for _, encoding := range response.Header.Values("Content-Encoding") {
		encoded = encoded || encoding != ""
	}
	if err != nil || len(response.Header.Values("Content-Type")) != 1 || media != "application/json" || response.StatusCode != http.StatusOK || encoded || response.ContentLength > 65536 {
		return ValidatedSectorRegistration{}, ErrAccessDenied
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(wire) > 65536 || !sectorDocument(wire, client.Redirects) {
		return ValidatedSectorRegistration{}, sectorFailure(ctx)
	}
	if bounded.Err() != nil {
		return ValidatedSectorRegistration{}, sectorFailure(ctx)
	}
	registration, _ := NewOIDCSubjectRegistration("pairwise", u.Hostname(), request.PolicyID, request.PolicyVersion)
	registration.uri, registration.redirects = strings.Clone(request.URI), sectorRedirectDigest(client.Redirects)
	return ValidatedSectorRegistration{state: &sectorRegistrationState{issuer: v.config.Issuer, environment: v.config.Environment, clientID: client.ID, clientVersion: client.Version, registration: registration}}, nil
}

func sectorFailure(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrAccessDenied
}

func sectorURI(value string) (*url.URL, error) {
	if !visible(value, 2048) || strings.ContainsAny(value, "\\#*") {
		return nil, ErrInvalidRequest
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || !sectorHost(u.Hostname()) || u.String() != value || strings.HasSuffix(u.Host, ":") {
		return nil, ErrInvalidRequest
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, ErrInvalidRequest
		}
	}
	return u, nil
}

func sectorRedirectDigest(redirects []string) [32]byte {
	owned := slices.Clone(redirects)
	slices.Sort(owned)
	h := sha256.New()
	_, _ = h.Write([]byte("golib.oidc.sector-redirect-set.v1\x00"))
	for _, redirect := range owned {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(redirect)))
		_, _ = h.Write(size[:])
		_, _ = io.WriteString(h, redirect)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func sectorDocument(wire []byte, redirects []string) bool {
	if len(wire) > 65536 || !json.Valid(wire) {
		return false
	}
	d := json.NewDecoder(strings.NewReader(string(wire)))
	start, err := d.Token()
	if err != nil || start != json.Delim('[') {
		return false
	}
	seen := make(map[string]bool, 16)
	for d.More() {
		token, err := d.Token()
		value, ok := token.(string)
		if err != nil || !ok || len(seen) == 64 || !validRedirect(value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	end, err := d.Token()
	if err != nil || end != json.Delim(']') || len(seen) == 0 {
		return false
	}
	if _, err := d.Token(); err != io.EOF {
		return false
	}
	for _, redirect := range redirects {
		if !seen[redirect] {
			return false
		}
	}
	return true
}

func publicSectorAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.Zone() != "" {
		return false
	}
	// IANA's IPv4/IPv6 special-purpose registries (2025-10-09 editions) include
	// unicast/anycast allocations not excluded by Go's ordinary address classes:
	// https://www.iana.org/assignments/iana-ipv4-special-registry/
	// https://www.iana.org/assignments/iana-ipv6-special-registry/
	// This policy excludes even globally reachable special-purpose services;
	// trusted deployments can instead pin their exact destinations explicitly.
	for _, prefix := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3fff::/20"} {
		if netip.MustParsePrefix(prefix).Contains(address) {
			return false
		}
	}
	return address.Is4() || netip.MustParsePrefix("2000::/3").Contains(address)
}
