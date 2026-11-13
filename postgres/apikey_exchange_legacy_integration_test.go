//go:build integration && oauthflow

package oauthpostgres_test

import (
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

func legacyExchangeCommandID(t *testing.T) identity.CommandID {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func importLegacyExchangeSource(t *testing.T, h apiKeyNativeExchange) (apikey.ImportRequest, identity.CommandResult, string) {
	t.Helper()
	directory, err := kernel.NewRepository(h.f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	status, err := directory.GetStatus(h.f.ctx, identity.UserStatusQuery{TenantID: h.f.tenant, UserID: h.user})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: h.f.tenant, Kind: apikey.OwnerUser, UserID: h.user, Version: status.AuthorityVersion})
	if err != nil {
		t.Fatal(err)
	}
	entropy, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	unique, err := entropy.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	// Historical bare bytes need no generated prefix. Exercise the real owning
	// boundary's full limit without passing plaintext to the importer.
	bare := strings.Repeat("b", 4096-len(unique)) + unique
	digest, err := apikey.NewLegacyDigest(sha256.Sum256([]byte(bare)))
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewIdempotencyKey([]byte("m33-legacy-original-import"))
	if err != nil {
		t.Fatal(err)
	}
	spec := h.configuration.Spec()
	const keyID apikey.KeyID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	request := apikey.ImportRequest{Authentication: h.manager, IdempotencyKey: id, Record: apikey.Record{ID: keyID, Owner: owner, Version: 3, AuthorityVersion: 2, RootID: keyID, RootVersion: 2, PreviousID: "01ARZ3NDEKTSV4RRFFQ69G5FAT", ConfigurationID: spec.ID, ConfigurationRevision: spec.Revision, Status: apikey.KeyActive, Grant: []string{"identity:read", "identity:write"}, CreatedAt: time.Now().UTC().Add(-500 * 24 * time.Hour).Truncate(time.Microsecond), Issuer: spec.Issuer, Environment: spec.Environment, Audience: spec.Audience}, Digest: digest, SourceID: "m33-authenticated-import", SourceVersion: 7, Network: "192.0.2.10"}
	imported, err := h.keys.Import(h.f.ctx, request)
	if err != nil || imported.Outcome != identity.CommitOutcomeCommitted || imported.Binding.RecordID != string(keyID) {
		t.Fatal("authorized digest-only import did not preserve its original USER key", err)
	}
	return request, imported, bare
}

func TestNativeLegacyAPIKeyExchangePreservesImportedRootAndModernIssuance(t *testing.T) {
	h := legacyAPIKeyExchangeFixture(t)
	wrongPolicy := h.f.oauth
	policy := *wrongPolicy.Protocol.APIKeyExchange
	policy.LegacySHA256 = false
	wrongPolicy.Protocol.APIKeyExchange = &policy
	if _, err := oauthpostgres.NewStore(h.f.pool, wrongPolicy, h.f.keys); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("modern protocol policy adopted a legacy native source", err)
	}
	wrongSource := h.f.oauth
	source := *wrongSource.APIKeyExchange
	modernSpec := source.Configuration.Spec()
	modernSpec.ID, modernSpec.Algorithm, modernSpec.State, modernSpec.AllowLegacyNoExpiry = "m33-modern-user", apikey.AlgorithmModernHMACSHA256, apikey.ConfigurationActive, false
	var err error
	source.Configuration, err = apikey.NewConfiguration(modernSpec)
	if err != nil {
		t.Fatal(err)
	}
	wrongSource.APIKeyExchange = &source
	if _, err := oauthpostgres.NewStore(h.f.pool, wrongSource, h.f.keys); !errors.Is(err, oauth.ErrInvalidRequest) {
		t.Fatal("legacy protocol policy selected modern verification implicitly", err)
	}
	modern, modernWire := createAPIKeyExchangeSource(t, h, "m33-still-modern-issuance")
	modernSecret, err := apikey.ParseSecret(modernWire)
	if err != nil || modern.ConfigurationID == h.configuration.Spec().ID || modern.ExpiresAt.IsZero() {
		t.Fatal("legacy source selection enabled legacy issuance or changed modern custody", err)
	}
	verification, err := h.keys.VerifyAndConsume(h.f.ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(legacyExchangeCommandID(t)), TenantID: h.f.tenant, ConfigurationID: modern.ConfigurationID, ConfigurationRevision: modern.ConfigurationRevision, Secret: modernSecret, RequiredPermissions: []string{"identity:read"}})
	modernSecret = apikey.Secret{}
	if err != nil || verification.Result == nil || verification.Result.Record.ID != modern.ID {
		t.Fatal("newly issued modern key stopped verifying under its original profile", err)
	}
	wrongProfile, err := h.service.Token(h.f.ctx, oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, SubjectToken: modernWire, SubjectTokenType: oauth.APIKeyTokenType, Resource: h.client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.10"})
	modernWire = ""
	if err == nil || wrongProfile.AccessToken != (oauth.Token{}) {
		t.Fatal("modern-looking credential selected modern verification under explicit legacy policy")
	}
	importRequest, imported, bare := importLegacyExchangeSource(t, h)
	if repeated, err := h.keys.Import(h.f.ctx, importRequest); err != nil || repeated.Binding != imported.Binding {
		t.Fatal("digest-only import retry changed original correlation", err)
	}
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, SubjectToken: bare[:4095] + "!", SubjectTokenType: oauth.APIKeyTokenType, Resource: h.client.Resource, Scopes: slices.Clone(importRequest.Record.Grant), Network: "192.0.2.10"}
	if denied, err := h.service.Token(h.f.ctx, request); err == nil || denied.AccessToken != (oauth.Token{}) {
		t.Fatal("wrong but bounded historical bare secret authenticated")
	}
	request.SubjectToken = bare
	started := time.Now()
	first, err := h.service.Token(h.f.ctx, request)
	request.SubjectToken, bare = "", ""
	if err != nil || first.Outcome != identity.CommitOutcomeCommitted || first.IssuedTokenType != oauth.AccessTokenType || first.RefreshToken != (oauth.Token{}) || first.IDToken != (oauth.IDToken{}) || first.ExpiresAt.After(started.Add(5*time.Minute)) || !first.ExpiresAt.After(started) || !slices.Equal(first.Scopes, importRequest.Record.Grant) {
		t.Fatal("real imported bare key did not issue bounded access-only authority", err)
	}
	firstWire, err := first.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	parent := checkAPIKeyLineage(t, h, first, importRequest.Record, 1, string(importRequest.Record.ID), oauth.APIKeyTokenType)
	request.SubjectToken, request.SubjectTokenType = firstWire, oauth.AccessTokenType
	request.Scopes = []string{"identity:read"}
	child, err := h.service.Token(h.f.ctx, request)
	request.SubjectToken = ""
	if err != nil || child.Outcome != identity.CommitOutcomeCommitted || child.ExpiresAt.After(first.ExpiresAt) || !slices.Equal(child.Scopes, request.Scopes) || child.RefreshToken != (oauth.Token{}) || child.IDToken != (oauth.IDToken{}) {
		t.Fatal("legacy-root descendant expanded its actual parent", err)
	}
	checkAPIKeyLineage(t, h, child, importRequest.Record, 2, parent, oauth.AccessTokenType)
	childWire, err := child.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	request.SubjectToken, request.Scopes = childWire, []string{"identity:write"}
	if denied, err := h.service.Token(h.f.ctx, request); err == nil || denied.AccessToken != (oauth.Token{}) {
		t.Fatal("legacy-root descendant recovered removed parent permissions")
	}
	request.SubjectToken = ""
	for i, wire := range []string{firstWire, childWire} {
		active, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: wire})
		expected := first.Scopes
		if i == 1 {
			expected = child.Scopes
		}
		if err != nil || !active.Active || active.Subject != string(h.user) || active.ClientID != h.client.ID || active.Resource != h.client.Resource || !slices.Equal(active.Scopes, expected) {
			t.Fatal("legacy source confused key actor, USER owner or owning Basic caller", err)
		}
	}
	recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: first.CommandID, ClientID: h.client.ID, ClientAuthentication: h.basic, Token: firstWire}
	if original, err := h.store.Recover(h.f.ctx, recovery); err != nil || original.Outcome != identity.CommitOutcomeCommitted || original.CommandID != first.CommandID {
		t.Fatal("actual original legacy-key exchange lost metadata-only recovery", err)
	}
	current, err := h.keys.Get(h.f.ctx, apikey.GetRequest{Authentication: h.manager, KeyID: importRequest.Record.ID})
	if err != nil || current.Record.ID != importRequest.Record.ID || current.Record.Owner != importRequest.Record.Owner || current.Record.AuthorityVersion != importRequest.Record.AuthorityVersion || current.Record.RootVersion != importRequest.Record.RootVersion || current.Record.PreviousID != importRequest.Record.PreviousID || !current.Record.CreatedAt.Equal(importRequest.Record.CreatedAt) || !current.Record.ExpiresAt.IsZero() || !slices.Equal(current.Record.Grant, importRequest.Record.Grant) {
		t.Fatal("OAuth exchange changed imported identity, lineage, restrictions or absent expiry", err)
	}
	revokeID, err := identity.NewIdempotencyKey([]byte("m33-legacy-source-revoke"))
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := h.keys.Revoke(h.f.ctx, apikey.Revocation{Authentication: h.manager, IdempotencyKey: revokeID, KeyID: current.Record.ID, ExpectedVersion: current.Record.Version, Network: "192.0.2.10"})
	if err != nil || revoked.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual imported key root revocation", err)
	}
	if repeated, err := h.keys.Import(h.f.ctx, importRequest); err != nil || repeated.Binding != imported.Binding {
		t.Fatal("revoked import lost its original status-only correlation", err)
	}
	current, err = h.keys.Get(h.f.ctx, apikey.GetRequest{Authentication: h.manager, KeyID: importRequest.Record.ID})
	if err != nil || current.Record.Status != apikey.KeyRevoked || !current.Record.ExpiresAt.IsZero() {
		t.Fatal("import retry resurrected a revoked legacy root", err)
	}
	for _, wire := range []string{firstWire, childWire} {
		inactive, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: wire})
		if err != nil || inactive.Active || inactive.Subject != "" || inactive.ClientID != "" || inactive.Resource != "" || inactive.Scopes != nil || !inactive.ExpiresAt.IsZero() || inactive.Issuer.String() != "" {
			t.Fatal("revoked imported root retained descendant authority or inactive metadata", err)
		}
	}
	request.SubjectToken, request.Scopes = childWire, []string{"identity:read"}
	if denied, err := h.service.Token(h.f.ctx, request); err == nil || denied.AccessToken != (oauth.Token{}) {
		t.Fatal("revoked imported root issued another descendant")
	}
	if original, err := h.store.Recover(h.f.ctx, recovery); err != nil || original.Outcome != identity.CommitOutcomeCommitted || original.CommandID != first.CommandID {
		t.Fatal("withdrawal replaced original historical metadata with current authority", err)
	}
}

func TestNativeLegacyAPIKeyUnknownExchangeRetainsExactRecoveryAndTimestamps(t *testing.T) {
	fault := &oauthCommitFault{}
	h := legacyAPIKeyExchangeFixture(t, fault)
	h, other, otherBasic := withForeignAPIKeyBasicClient(t, h)
	_, _, bare := importLegacyExchangeSource(t, h)
	command := legacyExchangeCommandID(t)
	fault.armed.Store(true)
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, CommandID: command, SubjectToken: bare, SubjectTokenType: oauth.APIKeyTokenType, Resource: h.client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.10"}
	lost, err := h.service.Token(h.f.ctx, request)
	request.SubjectToken, bare = "", ""
	var unknown oauth.APIKeyExchangeUnknownError
	if !fault.hit.Load() || !errors.As(err, &unknown) || lost.Outcome != identity.CommitOutcomeUnknown || lost.CommandID != command || lost.AccessToken != (oauth.Token{}) || unknown.Verification.Validate() != nil {
		t.Fatal("actual legacy OAuth commit acknowledgement loss discarded recovery metadata", err)
	}
	var before string
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT api_key_source::text FROM oauth_store.grants WHERE grant_id=$1`, string(command)).Scan(&before); err != nil {
		t.Fatal(err)
	}
	recovery := oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: command, ClientID: h.client.ID, ClientAuthentication: h.basic, APIKeyVerification: &unknown.Verification}
	if original, err := h.store.Recover(h.f.ctx, recovery); err != nil || original.Outcome != identity.CommitOutcomeCommitted || original.CommandID != command {
		t.Fatal("actual legacy source could not recover original metadata without raw key", err)
	}
	var after string
	var effects int
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT api_key_source::text,(SELECT count(*) FROM oauth_store.effects WHERE command_id=$1) FROM oauth_store.grants WHERE grant_id=$1`, string(command)).Scan(&after, &effects); err != nil || before != after || effects != 1 {
		t.Fatal("legacy recovery renewed source timestamps or repeated issuance", err)
	}
	for _, change := range []func(*oauthpostgres.RecoveryRequest){
		func(r *oauthpostgres.RecoveryRequest) { r.ClientAuthentication = oauth.ClientAuthentication{} },
		func(r *oauthpostgres.RecoveryRequest) { r.ClientID, r.ClientAuthentication = other.ID, otherBasic },
		func(r *oauthpostgres.RecoveryRequest) { r.CommandID = legacyExchangeCommandID(t) },
		func(r *oauthpostgres.RecoveryRequest) {
			q := *r.APIKeyVerification
			q.Fingerprint[0] ^= 1
			r.APIKeyVerification = &q
		},
	} {
		bad := recovery
		change(&bad)
		if out, err := h.store.Recover(h.f.ctx, bad); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("legacy original recovery accepted wrong caller/command/source correlation")
		}
	}
}
