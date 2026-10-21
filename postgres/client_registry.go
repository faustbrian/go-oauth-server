package oauthpostgres

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/jackc/pgx/v5"
)

var _ oauth.CurrentClientRegistry = (*Store)(nil)

type managedClientRecord struct {
	Client  oauth.Client
	Digest  []byte
	State   string
	Version uint64
}

// Owner intentionally has no generic JSON representation. Native registration
// persists its explicit immutable platform identity, never an empty struct.
type managedRegistration struct {
	ID, Platform, Resource, AuthenticationMethod string
	Version                                      uint64
	Redirects, Scopes                            []string
}

func registrationWire(c oauth.Client) managedRegistration {
	return managedRegistration{c.ID, c.Owner.PlatformID(), c.Resource, c.AuthenticationMethod, c.Version, c.Redirects, c.Scopes}
}
func registrationClient(r managedRegistration) (oauth.Client, error) {
	owner, err := oauth.NewPlatformOwner(r.Platform)
	if err != nil {
		return oauth.Client{}, err
	}
	return oauth.ValidateClient(oauth.Client{ID: r.ID, Owner: owner, Version: r.Version, Resource: r.Resource, AuthenticationMethod: r.AuthenticationMethod, Redirects: r.Redirects, Scopes: r.Scopes})
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
	err := s.pool.Raw().QueryRow(ctx, `SELECT registration,secret_digest,state,version::text FROM `+s.schema+`.managed_clients WHERE client_id=$1 AND issuer=$2 AND environment=$3 AND platform_owner=$4 AND tenant_id=$5`, id, s.config.Protocol.Issuer.String(), s.config.Protocol.Environment, s.config.Protocol.ManagedClients.Owner.PlatformID(), string(s.config.Protocol.ManagedClients.TenantID)).Scan(&wire, &r.Digest, &r.State, &version)
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
	if err != nil || r.Version == 0 || len(r.Digest) != 32 || !s.managedMetadata(r.Client) || r.Client.ID != id || r.State != "active" && r.State != "deleted" || r.State == "active" && r.Client.Version != r.Version {
		return managedClientRecord{}, oauth.ErrUnavailable
	}
	return r, nil
}
func (s *Store) managedMetadata(c oauth.Client) bool {
	p := s.config.Protocol.ManagedClients
	if p == nil || c.Owner != p.Owner || !strings.HasPrefix(c.ID, oauth.ManagedClientPrefix) || c.Public || c.Workload != nil || c.SubjectRegistration != nil || c.Resource != s.config.Protocol.Resource || !scopeSubset(c.Scopes, p.Scopes.Scopes()) {
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
	return true
}

// AuthenticateCurrentClient verifies digest-only random Basic custody after
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
	r, err := s.readManagedClient(ctx, c.ID)
	if err != nil {
		return err
	}
	if r.State != "active" || clientFingerprint(r.Client) != clientFingerprint(c) {
		return oauth.ErrInvalidClient
	}
	var digest oauth.ClientSecretDigest
	copy(digest[:], r.Digest)
	return a.VerifySecretDigest(c.ID, c.Version, digest)
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
	rows, err := w.Query(ctx, `SELECT version::text,state,registration FROM `+p.store.schema+`.managed_clients WHERE client_id=$1 AND issuer=$2 AND environment=$3 AND platform_owner=$4 AND tenant_id=$5 FOR SHARE`, p.client.ID, p.store.config.Protocol.Issuer.String(), p.store.config.Protocol.Environment, p.store.config.Protocol.ManagedClients.Owner.PlatformID(), string(p.store.config.Protocol.ManagedClients.TenantID))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return identity.ForbiddenError{}
	}
	if rows.Scan(&version, &state, &wire) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	c, decodeErr := decodeRegistration(wire)
	if decodeErr != nil || state != "active" || version != strconv.FormatUint(p.client.Version, 10) || clientFingerprint(c) != clientFingerprint(p.client) {
		return identity.ForbiddenError{}
	}
	return nil
}
