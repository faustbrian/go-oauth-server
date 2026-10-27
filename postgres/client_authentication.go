package oauthpostgres

import (
	"context"
	"strconv"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

// The original actual digest match is private encrypted participant input, never
// caller-supplied authority. Version identifies the immutable matching slot;
// Until bounds *all* work/delivery, and a predecessor cannot be rematched as a
// fresh credential after a wait. No secret/digest enters scalar command fields.
type clientAuthenticationSnapshot struct {
	Version                         uint64
	Start, Until, PredecessorExpiry time.Time
}

func (a clientAuthenticationSnapshot) validAt(now, db time.Time) bool {
	return a.Version > 0 && !a.Start.IsZero() && !now.Before(a.Start) && now.Before(a.Until) && !db.Before(a.Start) && db.Before(a.Until) && !a.Until.After(a.Start.Add(20*time.Second)) && (a.PredecessorExpiry.IsZero() || a.Until.Equal(a.PredecessorExpiry) || a.Until.Before(a.PredecessorExpiry))
}
func (a clientAuthenticationSnapshot) matches(current, previous string, expiry *time.Time) bool {
	v := strconv.FormatUint(a.Version, 10)
	if a.PredecessorExpiry.IsZero() {
		return current == v
	}
	return previous == v && expiry != nil && expiry.Equal(a.PredecessorExpiry)
}
func (s *Store) authenticateClientSnapshot(ctx context.Context, c oauth.Client, a oauth.ClientAuthentication) (*clientAuthenticationSnapshot, error) {
	if !s.managedID(c.ID) {
		return nil, s.config.Protocol.AuthenticateClient(ctx, c.ID, a)
	}
	start := s.now()
	r, err := s.readManagedClient(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	if r.State != "active" || clientFingerprint(r.Client) != clientFingerprint(c) {
		return nil, oauth.ErrInvalidClient
	}
	if c.Public {
		if a.Method() != "none" {
			return nil, oauth.ErrInvalidClient
		}
		// No credential snapshot is invented for none. The existing exact
		// registration SHARE/version fence still serializes issuance with delete.
		return nil, nil
	}
	var digest oauth.ClientSecretDigest
	copy(digest[:], r.Digest)
	matched := a.VerifySecretDigest(c.ID, r.SecretVersion, digest) == nil
	proof := &clientAuthenticationSnapshot{Version: r.SecretVersion, Start: start, Until: start.Add(20 * time.Second)}
	if !matched && s.config.ClientSecretRotation && r.PreviousVersion > 0 {
		copy(digest[:], r.PreviousDigest)
		matched = a.VerifySecretDigest(c.ID, r.PreviousVersion, digest) == nil
		proof.Version = r.PreviousVersion
		proof.PredecessorExpiry = r.PreviousExpiry
		if r.PreviousExpiry.Before(proof.Until) {
			proof.Until = r.PreviousExpiry
		}
	}
	if !matched {
		return nil, oauth.ErrInvalidClient
	}
	if !s.config.ClientSecretRotation {
		return nil, nil
	}
	if !proof.validAt(s.now(), r.DatabaseNow) || ctx.Err() != nil {
		return nil, oauth.ErrInvalidClient
	}
	return proof, nil
}

func (s *Store) finishClientAuthentication(ctx context.Context, c oauth.Client, proofs ...*clientAuthenticationSnapshot) error {
	needed := false
	for _, proof := range proofs {
		needed = needed || proof != nil
	}
	if !needed {
		return nil
	}
	r, err := s.readManagedClient(ctx, c.ID)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var previous *time.Time
	if !r.PreviousExpiry.IsZero() {
		previous = &r.PreviousExpiry
	}
	if r.State != "active" || clientFingerprint(r.Client) != clientFingerprint(c) {
		return oauth.ErrInvalidClient
	}
	// A retry authenticates its current invocation separately, but restoring
	// encrypted preparation retains the original matching slot/deadline too.
	// Neither may replace the other at delivery; one primary read fences both.
	now := s.now()
	for _, a := range proofs {
		if a != nil && (!a.matches(strconv.FormatUint(r.SecretVersion, 10), strconv.FormatUint(r.PreviousVersion, 10), previous) || !a.validAt(now, r.DatabaseNow)) {
			return oauth.ErrInvalidClient
		}
	}
	return nil
}
