package oauthpostgres

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/jackc/pgx/v5"
)

var _ oauth.CurrentClientRegistry = (*Store)(nil)

type managedClientRecord struct {
	Client          oauth.Client
	Digest          []byte
	State           string
	Version         uint64
	SecretVersion   uint64
	PreviousVersion uint64
	PreviousExpiry  time.Time
	PreviousDigest  []byte
	DatabaseNow     time.Time
}

// Owner intentionally has no generic JSON representation. Native registration
// persists its explicit immutable platform identity, never an empty struct.
type managedRegistration struct {
	ID, Platform, Resource, AuthenticationMethod string
	Version                                      uint64
	Redirects, Scopes                            []string
	PostLogoutRedirects                          []string                       `json:",omitempty"`
	DeviceAuthorization                          bool                           `json:",omitempty"`
	Public                                       bool                           `json:",omitempty"`
	SubjectRegistration                          *oauth.OIDCSubjectRegistration `json:",omitempty"`
}

func registrationWire(c oauth.Client) managedRegistration {
	return managedRegistration{c.ID, c.Owner.PlatformID(), c.Resource, c.AuthenticationMethod, c.Version, c.Redirects, c.Scopes, c.PostLogoutRedirects, c.DeviceAuthorization, c.Public, c.SubjectRegistration}
}
func registrationClient(r managedRegistration) (oauth.Client, error) {
	owner, err := oauth.NewPlatformOwner(r.Platform)
	if err != nil {
		return oauth.Client{}, err
	}
	return oauth.ValidateClient(oauth.Client{ID: r.ID, Owner: owner, Version: r.Version, Public: r.Public, Resource: r.Resource, AuthenticationMethod: r.AuthenticationMethod, Redirects: r.Redirects, PostLogoutRedirects: r.PostLogoutRedirects, Scopes: r.Scopes, DeviceAuthorization: r.DeviceAuthorization, SubjectRegistration: r.SubjectRegistration})
}
func decodeRegistration(wire []byte) (oauth.Client, error) {
	var r managedRegistration
	if err := decodeJSON(wire, &r); err != nil {
		return oauth.Client{}, err
	}
	return registrationClient(r)
}

func (s *Store) managedID(id string) bool {
	return s.config.Protocol.ManagedClients != nil && strings.HasPrefix(id, oauth.ManagedClientPrefix)
}

// CurrentClient resolves only the server-reserved namespace from actual primary
// state. Missing/tombstoned IDs never fall back to static registrations.
func (s *Store) CurrentClient(ctx context.Context, id string) (oauth.Client, error) {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return oauth.Client{}, err
	}
	defer stop()
	if !boundedText(id, 128) {
		return oauth.Client{}, oauth.ErrInvalidClient
	}
	if !s.managedID(id) {
		for _, c := range s.config.Protocol.Clients {
			if c.ID == id {
				// This public getter must not re-expose the constructor's frozen
				// slices or nested policy pointers as mutable native authority.
				return oauth.ValidateClient(c)
			}
		}
		return oauth.Client{}, oauth.ErrInvalidClient
	}
	r, err := s.readManagedClient(ctx, id)
	if err != nil {
		return oauth.Client{}, err
	}
	if r.State != "active" {
		return oauth.Client{}, oauth.ErrInvalidClient
	}
	return r.Client, nil
}
func (s *Store) readManagedClient(ctx context.Context, id string) (managedClientRecord, error) {
	var r managedClientRecord
	var wire []byte
	var version string
	query := `SELECT registration,secret_digest,state,version::text`
	targets := []any{&wire, &r.Digest, &r.State, &version}
	var secretVersion, previousVersion string
	var previousExpiry *time.Time
	if s.config.ClientSecretRotation {
		query += `,secret_version::text,COALESCE(previous_secret_version::text,''),previous_secret_digest,previous_secret_expires_at,clock_timestamp()`
		targets = append(targets, &secretVersion, &previousVersion, &r.PreviousDigest, &previousExpiry, &r.DatabaseNow)
	}
	err := s.pool.Raw().QueryRow(ctx, query+` FROM `+s.schema+`.managed_clients WHERE client_id=$1 AND issuer=$2 AND environment=$3 AND platform_owner=$4 AND tenant_id=$5`, id, s.config.Protocol.Issuer.String(), s.config.Protocol.Environment, s.config.Protocol.ManagedClients.Owner.PlatformID(), string(s.config.Protocol.ManagedClients.TenantID)).Scan(targets...)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, oauth.ErrInvalidClient
	}
	if err != nil {
		return r, publicError(ctx, err, oauth.ErrInvalidClient)
	}
	if r.Client, err = decodeRegistration(wire); err != nil {
		return r, oauth.ErrUnavailable
	}
	r.Version, err = strconv.ParseUint(version, 10, 64)
	if err != nil || r.Version == 0 || r.Client.Public && len(r.Digest) != 0 || !r.Client.Public && len(r.Digest) != 32 || !s.managedMetadata(r.Client) || r.Client.ID != id || r.State != "active" && r.State != "deleted" || r.State == "active" && r.Client.Version != r.Version {
		return managedClientRecord{}, oauth.ErrUnavailable
	}
	r.SecretVersion = r.Client.Version
	if s.config.ClientSecretRotation {
		r.SecretVersion, err = strconv.ParseUint(secretVersion, 10, 64)
		if err != nil || r.SecretVersion == 0 || r.SecretVersion > r.Client.Version || !s.config.ClientMetadataUpdates && r.SecretVersion != r.Client.Version {
			return managedClientRecord{}, oauth.ErrUnavailable
		}
		if previousVersion != "" {
			r.PreviousVersion, err = strconv.ParseUint(previousVersion, 10, 64)
			if err != nil || r.PreviousVersion == 0 || r.PreviousVersion+1 != r.SecretVersion || len(r.PreviousDigest) != 32 || previousExpiry == nil || previousExpiry.IsZero() {
				return managedClientRecord{}, oauth.ErrUnavailable
			}
			r.PreviousExpiry = *previousExpiry
		} else if previousExpiry != nil || len(r.PreviousDigest) != 0 {
			return managedClientRecord{}, oauth.ErrUnavailable
		}
		if r.Client.Public && (r.SecretVersion != 1 || r.PreviousVersion != 0) {
			return managedClientRecord{}, oauth.ErrUnavailable
		}
	}
	return r, nil
}
func (s *Store) managedMetadata(c oauth.Client) bool {
	p := s.config.Protocol.ManagedClients
	if p == nil || c.Owner != p.Owner || !strings.HasPrefix(c.ID, oauth.ManagedClientPrefix) || c.Public && (!s.config.PublicClients || !p.PublicClients) || c.Workload != nil || c.Resource != s.config.Protocol.Resource || !p.AllowsRegistration(c.Public, c.DeviceAuthorization, c.Scopes, c.SubjectRegistration) {
		return false
	}
	if _, err := oauth.ValidateClient(c); err != nil {
		return false
	}
	for _, r := range c.Redirects {
		if !slices.Contains(p.Redirects, r) {
			return false
		}
	}
	for _, r := range c.PostLogoutRedirects {
		if !slices.Contains(p.PostLogoutRedirects, r) {
			return false
		}
	}
	return true
}

// AuthenticateCurrentClient verifies the registered none/Basic class after
// primary status/version admission. It never authenticates a human manager.
func (s *Store) AuthenticateCurrentClient(ctx context.Context, c oauth.Client, a oauth.ClientAuthentication) error {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return err
	}
	defer stop()
	if !s.managedID(c.ID) {
		return s.config.Protocol.AuthenticateClient(ctx, c.ID, a)
	}
	_, err = s.authenticateClientSnapshot(ctx, c, a)
	return err
}
func (s *Store) checkedClient(ctx context.Context, c oauth.Client) (oauth.Client, error) {
	if !s.managedID(c.ID) {
		return s.client(c)
	}
	current, err := s.CurrentClient(ctx, c.ID)
	if err != nil {
		return oauth.Client{}, err
	}
	if clientFingerprint(current) != clientFingerprint(c) {
		return oauth.Client{}, oauth.ErrInvalidClient
	}
	return current, nil
}

// Every mutating protocol participant holds this SHARE fence before grant or
// consent locks. Terminal deletion takes UPDATE on the same client first, so
// either issuance precedes deletion or it denies; no unbounded artifact fanout.
func (p *phase) requireManagedClient(ctx context.Context, w kernel.Work) error {
	if !p.store.managedID(p.client.ID) {
		return nil
	}
	if p.input.Grant.Tenant != p.store.config.Protocol.ManagedClients.TenantID {
		return identity.ForbiddenError{}
	}
	var version, state string
	var wire []byte
	query := `SELECT version::text,state,registration`
	var secretVersion, previousVersion string
	var previousExpiry *time.Time
	targets := []any{&version, &state, &wire}
	if p.input.ClientAuthentication != nil {
		query += `,secret_version::text,COALESCE(previous_secret_version::text,''),previous_secret_expires_at`
		targets = append(targets, &secretVersion, &previousVersion, &previousExpiry)
	}
	rows, err := w.Query(ctx, query+` FROM `+p.store.schema+`.managed_clients WHERE client_id=$1 AND issuer=$2 AND environment=$3 AND platform_owner=$4 AND tenant_id=$5 FOR SHARE`, p.client.ID, p.store.config.Protocol.Issuer.String(), p.store.config.Protocol.Environment, p.store.config.Protocol.ManagedClients.Owner.PlatformID(), string(p.store.config.Protocol.ManagedClients.TenantID))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return identity.ForbiddenError{}
	}
	if rows.Scan(targets...) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	c, decodeErr := decodeRegistration(wire)
	if decodeErr != nil || state != "active" || version != strconv.FormatUint(p.client.Version, 10) || clientFingerprint(c) != clientFingerprint(p.client) {
		return identity.ForbiddenError{}
	}
	if a := p.input.ClientAuthentication; a != nil {
		if !p.store.config.ClientSecretRotation || !a.matches(secretVersion, previousVersion, previousExpiry) {
			return identity.ForbiddenError{}
		}
	}
	return nil
}
