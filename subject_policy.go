package oauthserver

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// OIDCSubjectKeyRegistration is non-plaintext deployment custody for one exact
// pairwise derivation-key version. Envelope contains the authenticated binary
// secret-envelope representation, not a wrapping key or clear HMAC key. The
// native adapter authenticates it before durable staging. Callers own Envelope;
// consumers must copy it. A key version selects writers, never subject namespace.
type OIDCSubjectKeyRegistration struct {
	Issuer                Issuer
	Environment, PolicyID string
	PolicyVersion         uint64
	KeyVersion            uint32
	Commitment            [32]byte
	Envelope              []byte
}

func (OIDCSubjectKeyRegistration) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("oauthserver.OIDCSubjectKeyRegistration(redacted)"))
}
func (OIDCSubjectKeyRegistration) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRequest }
func (OIDCSubjectKeyRegistration) MarshalText() ([]byte, error) { return nil, ErrInvalidRequest }

// OIDCSubjectRegistration is immutable client registration, independent of the
// client's public/confidential authentication class. Policy identity/version
// select the issuer's subject policy, never its current derivation-key version.
// The zero value is invalid; a nil Client.SubjectRegistration preserves the
// original public-subject profile. Copies may be shared concurrently.
type OIDCSubjectRegistration struct {
	kind, sector, policy string
	version              uint64
	uri                  string
	redirects            [32]byte
}

// NewOIDCSubjectRegistration selects public or the registered-single-host
// pairwise profile. Policy IDs use the core identifier grammar. Pairwise sector
// hosts are exact lowercase ASCII DNS names (no port, URI or normalization).
// Multi-host registration is obtained from SectorValidator instead. This pure
// constructor checks syntax, not the existence of issuer policy/key custody.
func NewOIDCSubjectRegistration(kind, sector, policy string, version uint64) (OIDCSubjectRegistration, error) {
	if !identifier(policy) || version == 0 || kind != "public" && kind != "pairwise" || kind == "public" && sector != "" || kind == "pairwise" && !sectorHost(sector) {
		return OIDCSubjectRegistration{}, ErrInvalidRequest
	}
	return OIDCSubjectRegistration{kind: strings.Clone(kind), sector: strings.Clone(sector), policy: strings.Clone(policy), version: version}, nil
}

// SubjectType returns public or pairwise; zero returns empty.
func (p OIDCSubjectRegistration) SubjectType() string { return p.kind }

// SectorHost returns the exact registered host, empty for public and zero.
func (p OIDCSubjectRegistration) SectorHost() string { return p.sector }

// SectorIdentifierURI returns the exact HTTPS registration URI, empty for the
// original public/single-host profiles. The policy is not retrieval authority;
// Config additionally requires its opaque ValidatedSectorRegistration.
func (p OIDCSubjectRegistration) SectorIdentifierURI() string { return p.uri }

// PolicyID returns the immutable subject-policy selector, empty for zero.
func (p OIDCSubjectRegistration) PolicyID() string { return p.policy }

// PolicyVersion returns the policy schema version, zero for invalid zero.
func (p OIDCSubjectRegistration) PolicyVersion() uint64 { return p.version }

// MarshalJSON preserves the complete nonsecret policy identity. Zero is invalid.
func (p OIDCSubjectRegistration) MarshalJSON() ([]byte, error) {
	if !p.valid() {
		return nil, ErrInvalidRequest
	}
	digest := ""
	if p.uri != "" {
		digest = hex.EncodeToString(p.redirects[:])
	}
	return json.Marshal(struct {
		Type, SectorHost, PolicyID string
		PolicyVersion              uint64
		SectorIdentifierURI        string `json:",omitempty"`
		RedirectSet                string `json:",omitempty"`
	}{p.kind, p.sector, p.policy, p.version, p.uri, digest})
}

// UnmarshalJSON restores only a complete validated closed object; duplicate,
// unknown or missing fields deny without changing the receiver. Callers own the
// receiver and must not mutate it concurrently with use by another goroutine.
func (p *OIDCSubjectRegistration) UnmarshalJSON(wire []byte) error {
	if p == nil || len(wire) > 4096 {
		return ErrInvalidRequest
	}
	d := json.NewDecoder(bytes.NewReader(wire))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return ErrInvalidRequest
	}
	var kind, sector, policy, uri, digest string
	var version uint64
	seen := make(map[string]bool, 4)
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] || len(seen) == 6 {
			return ErrInvalidRequest
		}
		seen[name] = true
		switch name {
		case "Type":
			err = d.Decode(&kind)
		case "SectorHost":
			err = d.Decode(&sector)
		case "PolicyID":
			err = d.Decode(&policy)
		case "PolicyVersion":
			err = d.Decode(&version)
		case "SectorIdentifierURI":
			err = d.Decode(&uri)
		case "RedirectSet":
			err = d.Decode(&digest)
		default:
			return ErrInvalidRequest
		}
		if err != nil {
			return ErrInvalidRequest
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || !seen["Type"] || !seen["SectorHost"] || !seen["PolicyID"] || !seen["PolicyVersion"] || len(seen) != 4 && len(seen) != 6 {
		return ErrInvalidRequest
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalidRequest
	}
	owned, err := NewOIDCSubjectRegistration(kind, sector, policy, version)
	if err != nil {
		return err
	}
	if len(seen) == 6 {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || digest != strings.ToLower(digest) || uri == "" {
			return ErrInvalidRequest
		}
		owned.uri = uri
		copy(owned.redirects[:], decoded)
		if !owned.valid() {
			return ErrInvalidRequest
		}
	}
	if owned.uri == "" && len(wire) > 1024 {
		return ErrInvalidRequest
	}
	*p = owned
	return nil
}

func (p OIDCSubjectRegistration) valid() bool {
	if _, err := NewOIDCSubjectRegistration(p.kind, p.sector, p.policy, p.version); err != nil {
		return false
	}
	if p.uri == "" {
		return p.redirects == ([32]byte{})
	}
	u, err := sectorURI(p.uri)
	return err == nil && p.kind == "pairwise" && u.Hostname() == p.sector && p.redirects != ([32]byte{})
}

func sectorHost(host string) bool {
	if len(host) < 1 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			b := label[i]
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	return true
}

func validSubjectRegistration(c Client) bool {
	if c.SubjectRegistration == nil {
		return true
	}
	p := *c.SubjectRegistration
	if !p.valid() || c.Workload != nil {
		return false
	}
	if p.kind == "pairwise" {
		if p.uri != "" {
			return p.redirects == sectorRedirectDigest(c.Redirects)
		}
		// OIDC Core 1.0 errata 2 section 8.1: without a separately validated
		// sector_identifier_uri, every registered redirect must share its host.
		for _, redirect := range c.Redirects {
			u, err := url.Parse(redirect)
			if err != nil || u.Hostname() != p.sector {
				return false
			}
		}
	}
	return true
}
