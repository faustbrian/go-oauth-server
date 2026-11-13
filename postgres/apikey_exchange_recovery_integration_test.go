//go:build integration && oauthflow

package oauthpostgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	"github.com/jackc/pgx/v5/pgproto3"
)

func withForeignAPIKeyBasicClient(t *testing.T, h apiKeyNativeExchange) (apiKeyNativeExchange, oauth.Client, oauth.ClientAuthentication) {
	t.Helper()
	other := h.client
	other.ID = "m33-other-basic"
	secretToken, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := secretToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := primitive.NewSecret([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oauth.NewClientSecretVerifier(other.ID, other.Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	basic := confidentialBasic(t, other.ID, wire)
	h.f.oauth.Protocol.Clients = append(h.f.oauth.Protocol.Clients, other)
	h.f.oauth.Protocol.ClientSecrets = append(h.f.oauth.Protocol.ClientSecrets, verifier)
	h.store, err = oauthpostgres.NewStore(h.f.pool, h.f.oauth, h.f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.BootstrapAPIKeyExchangeClient(h.f.ctx, oauth.IntrospectRequest{ClientID: other.ID, ClientAuthentication: basic}); err != nil {
		t.Fatal(err)
	}
	h.service, err = oauthpostgres.NewService(h.f.pool, h.f.oauth, h.f.keys)
	if err != nil {
		t.Fatal(err)
	}
	return h, other, basic
}

func createAPIKeyExchangeSource(t *testing.T, h apiKeyNativeExchange, name string) (apikey.Record, string) {
	t.Helper()
	id, err := identity.NewIdempotencyKey([]byte(name))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := h.keys.Create(h.f.ctx, apikey.CreateRequest{Authentication: h.manager, IdempotencyKey: id, Name: name, Permissions: []string{"identity:read", "identity:write"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.10"})
	if err != nil {
		t.Fatal("genuine modern USER key", err)
	}
	record, ok := issued.Record()
	if !ok {
		t.Fatal("missing actual source record")
	}
	wire, err := issued.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return record, wire
}

func TestNativeAPIKeyExchangePendingLeaseRetainsOriginalRecoveryHandle(t *testing.T) {
	var armed, attaching, hit atomic.Bool
	var cancel context.CancelFunc
	var statementsMu sync.Mutex
	statements := map[string]byte{}
	fault := &oauthCommitFault{beforeWrite: func(wire []byte) {
		// The fixture may already have prepared this statement. Follow its real
		// Parse/Bind names; never decode or retain credential parameters.
		statementsMu.Lock()
		defer statementsMu.Unlock()
		for len(wire) >= 5 && wire[0] != 0 {
			size := uint64(binary.BigEndian.Uint32(wire[1:5]))
			if size < 4 || size+1 > uint64(len(wire)) {
				return
			}
			end := int(size) + 1
			first, rest, ok := bytes.Cut(wire[5:end], []byte{0})
			if ok && wire[0] == 'P' {
				query, _, _ := bytes.Cut(rest, []byte{0})
				selected := byte(0)
				if bytes.HasPrefix(query, []byte("SELECT preparation_ciphertext,preparation_ciphertext_generation::text,command_plan FROM identity.commands")) {
					selected = 1
				} else if bytes.HasPrefix(query, []byte("SELECT state,generation::text,lease_owner,lease_until FROM identity.commands")) {
					selected = 2
				}
				statements[string(first)] = selected
			}
			if ok && wire[0] == 'B' {
				name, _, _ := bytes.Cut(rest, []byte{0})
				selected := statements[string(name)]
				if armed.Load() && selected != 0 {
					// These selected statements have only command, tenant and
					// purpose parameters. Leave the verifier's preparation alone.
					var bound pgproto3.Bind
					if bound.Decode(wire[5:end]) == nil && len(bound.Parameters) == 3 && string(bound.Parameters[2]) == "identity.oauth-server.token" {
						if selected == 1 {
							attaching.Store(true)
						} else if attaching.Load() && hit.CompareAndSwap(false, true) {
							// Begin follows the committed attachment, before Apply.
							cancel()
						}
					}
				}
			}
			wire = wire[end:]
		}
	}}
	h := apiKeyExchangeFixture(t, fault)
	_, wire := createAPIKeyExchangeSource(t, h, "m33-pending-source")
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, CommandID: command, SubjectToken: wire, SubjectTokenType: oauth.APIKeyTokenType, Resource: h.client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.10"}
	firstCtx, stop := context.WithCancel(h.f.ctx)
	cancel = stop
	defer stop()
	armed.Store(true)
	lost, err := h.service.Token(firstCtx, request)
	var original oauth.APIKeyExchangeUnknownError
	if !hit.Load() || !errors.As(err, &original) || lost.Outcome != identity.CommitOutcomeUnknown || lost.CommandID != command || lost.AccessToken != (oauth.Token{}) || original.Verification.Validate() != nil {
		t.Fatal("interrupted real preparation did not preserve original recovery metadata", hit.Load(), lost.Outcome, err)
	}
	id, err := base64.RawURLEncoding.DecodeString(string(command))
	if err != nil {
		t.Fatal(err)
	}
	var state string
	var retained, attached, leased bool
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT state,preparation_ciphertext IS NOT NULL,command_plan IS NOT NULL,lease_until > clock_timestamp() FROM identity.commands WHERE command_id=$1`, id).Scan(&state, &retained, &attached, &leased); err != nil || state != "pending" || !retained || !attached || !leased {
		t.Fatal("interruption did not leave actual attached preparation with a live lease", state, retained, attached, leased, err)
	}
	// The exact retry must retain custody even when the kernel reports its live
	// original lease as InProgress without an error. It must not issue tokens.
	retry, err := h.service.Token(h.f.ctx, request)
	request.SubjectToken, wire = "", ""
	var pending oauth.APIKeyExchangeUnknownError
	if !errors.As(err, &pending) || retry.Outcome != identity.CommitOutcomeInProgress || retry.CommandID != command || retry.AccessToken != (oauth.Token{}) || retry.RefreshToken != (oauth.Token{}) || retry.IDToken != (oauth.IDToken{}) || pending.CommandID != command || pending.Verification != original.Verification {
		t.Fatal("live original preparation lost its nonsecret recovery handle", retry.Outcome, err)
	}
	out, err := h.store.Recover(h.f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: command, ClientID: h.client.ID, ClientAuthentication: h.basic, APIKeyVerification: &pending.Verification})
	if err != nil || out.Outcome != identity.CommitOutcomeInProgress || out.CommandID != command {
		t.Fatal("original handle did not recover actual pending metadata without the raw key", err)
	}
	var grants, artifacts, effects int
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT (SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.artifacts),(SELECT count(*) FROM oauth_store.effects WHERE command_id=$1)`, string(command)).Scan(&grants, &artifacts, &effects); err != nil || grants != 0 || artifacts != 0 || effects != 0 {
		t.Fatal("pending retry or recovery created OAuth credentials or effects", err)
	}
}

func TestNativeAPIKeyExchangeRecoveryNeverRedeliversOrRenewsSource(t *testing.T) {
	fault := &oauthCommitFault{}
	h := apiKeyExchangeFixture(t, fault)
	h, other, otherBasic := withForeignAPIKeyBasicClient(t, h)
	_, wire := createAPIKeyExchangeSource(t, h, "m33-recovery-original-source")
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, CommandID: command, SubjectToken: wire, SubjectTokenType: oauth.APIKeyTokenType, Resource: h.client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.10"}
	knownRequest := request
	knownRequest.CommandID = ""
	known, err := h.service.Token(h.f.ctx, knownRequest)
	knownRequest.SubjectToken = ""
	if err != nil {
		t.Fatal("known source before interrupted exchange", err)
	}
	knownAccess, err := known.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	fault.armed.Store(true)
	lost, err := h.service.Token(h.f.ctx, request)
	request.SubjectToken, wire = "", ""
	var unknown oauth.APIKeyExchangeUnknownError
	if !fault.hit.Load() || !errors.As(err, &unknown) || lost.Outcome != identity.CommitOutcomeUnknown || lost.CommandID != command || lost.AccessToken != (oauth.Token{}) || unknown.Verification.Validate() != nil {
		t.Fatal("actual API-key OAuth commit acknowledgement loss was not recoverable metadata only", err)
	}
	var originalSource string
	var until time.Time
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT api_key_source::text,(api_key_source->>'ValidUntil')::timestamptz FROM oauth_store.grants WHERE grant_id=$1`, string(command)).Scan(&originalSource, &until); err != nil {
		t.Fatal("actual committed frozen API-key source", err)
	}
	recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: command, ClientID: h.client.ID, ClientAuthentication: h.basic, APIKeyVerification: &unknown.Verification}
	for _, expired := range []bool{false, true} {
		if expired {
			wait := time.Until(until.Add(time.Millisecond))
			if wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-timer.C:
				case <-h.f.ctx.Done():
					timer.Stop()
					t.Fatal(h.f.ctx.Err())
				}
			}
		}
		out, err := h.store.Recover(h.f.ctx, recovery)
		if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.CommandID != command {
			t.Fatal("original committed key exchange lost read-only recovery across source expiry", expired, err)
		}
	}
	var currentSource string
	var grants, artifacts, effects int
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT api_key_source::text,(SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.artifacts),(SELECT count(*) FROM oauth_store.effects WHERE command_id=$1) FROM oauth_store.grants WHERE grant_id=$1`, string(command)).Scan(&currentSource, &grants, &artifacts, &effects); err != nil || currentSource != originalSource || grants != 2 || artifacts != 2 || effects != 1 {
		t.Fatal("recovery renewed original source evidence or repeated issuance", err)
	}
	// A later true source observation permits current use; copying the original
	// verification would already be expired. The persisted origin must not move.
	var knownSource string
	var originalUntil time.Time
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT api_key_source::text,(api_key_source->>'ValidUntil')::timestamptz FROM oauth_store.grants WHERE grant_id=$1`, string(known.CommandID)).Scan(&knownSource, &originalUntil); err != nil || time.Now().Before(originalUntil) {
		t.Fatal("original earlier source observation has not actually expired", err)
	}
	active, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: knownAccess})
	if err != nil || !active.Active || active.Subject != string(h.user) {
		t.Fatal("genuine later source observation did not permit still-current key-derived access", err)
	}
	childRequest := request
	childRequest.CommandID = ""
	childRequest.SubjectToken, childRequest.SubjectTokenType = knownAccess, oauth.AccessTokenType
	child, err := h.service.Token(h.f.ctx, childRequest)
	if err != nil || child.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("later separate source observation could not derive a valid child", err)
	}
	var unchanged string
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT api_key_source::text FROM oauth_store.grants WHERE grant_id=$1`, string(known.CommandID)).Scan(&unchanged); err != nil || unchanged != knownSource {
		t.Fatal("new current observation rewrote original bearer verification provenance", err)
	}
	for _, mutate := range []func(*oauthpostgres.RecoveryRequest){
		func(r *oauthpostgres.RecoveryRequest) { r.ClientAuthentication = oauth.ClientAuthentication{} },
		func(r *oauthpostgres.RecoveryRequest) { r.ClientID, r.ClientAuthentication = other.ID, otherBasic },
		func(r *oauthpostgres.RecoveryRequest) {
			q := *r.APIKeyVerification
			q.Fingerprint[0] ^= 1
			r.APIKeyVerification = &q
		},
		func(r *oauthpostgres.RecoveryRequest) { r.CommandID, _ = identity.NewCommandID() },
		func(r *oauthpostgres.RecoveryRequest) {
			q := *r.APIKeyVerification
			q.Original.UserID = "m33-foreign-user"
			r.APIKeyVerification = &q
		},
	} {
		bad := recovery
		mutate(&bad)
		if out, err := h.store.Recover(h.f.ctx, bad); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("foreign initial recovery correlation disclosed committed history")
		}
	}
}

func TestNativeAPIKeyExchangeCommittedAccessCustodyRecoversOnlyOriginalMetadata(t *testing.T) {
	h := apiKeyExchangeFixture(t)
	_, wire := createAPIKeyExchangeSource(t, h, "m33-committed-source")
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, SubjectToken: wire, SubjectTokenType: oauth.APIKeyTokenType, Audience: h.client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.10"}
	first, err := h.service.Token(h.f.ctx, request)
	request.SubjectToken, wire = "", ""
	if err != nil {
		t.Fatal(err)
	}
	access, err := first.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	initial, err := h.store.Recover(h.f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: first.CommandID, ClientID: h.client.ID, ClientAuthentication: h.basic, Token: access})
	if err != nil || initial.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual committed access custody lost original key-root metadata", err)
	}
	request.SubjectToken, request.SubjectTokenType = access, oauth.AccessTokenType
	child, err := h.service.Token(h.f.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	out, err := h.store.Recover(h.f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: child.CommandID, ClientID: h.client.ID, ClientAuthentication: h.basic, Token: access})
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual child original-parent custody lost metadata", err)
	}
}
