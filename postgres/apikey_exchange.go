package oauthpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

// APIKeyExchangeConfig selects one trusted modern USER-key source, not a tenant
// chosen by an OAuth request. Source must be the actual native owner on this
// Store's primary database and outlive it. Configuration must describe that
// owner's exact issuer/environment/audience/revision. This initial profile is
// uncached and unlimited-quota only; other profiles are not silently weakened.
// ClientPolicyNamespace is an independent existing authorization namespace,
// bootstrapped explicitly per configured Basic registration after all seven
// APIKeyExchangeMigrationSource steps. An advanced epoch is withdrawal, not
// permission to adopt a new generation. Construction performs no bootstrap.
type APIKeyExchangeConfig struct {
	TenantID              identity.TenantID
	Configuration         apikey.Configuration
	Source                *apikeypg.Service
	ClientPolicyNamespace string
}

func (APIKeyExchangeConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.APIKeyExchangeConfig(redacted)"))
}
func (APIKeyExchangeConfig) MarshalJSON() ([]byte, error) { return nil, oauth.ErrInvalidRequest }

func (c APIKeyExchangeConfig) validated(parent Config, protocol oauth.Config) (APIKeyExchangeConfig, error) {
	p := c.Configuration.Spec()
	selectedSource := c.Source != nil && c.Configuration.Validate() == nil && c.Configuration.AllowsVerification() && p.Algorithm == apikey.AlgorithmModernHMACSHA256 && p.Quota == apikey.QuotaUnlimited && p.Cache == apikey.CacheDisabled
	exactAudience := p.Issuer == protocol.Issuer.String() && p.Environment == protocol.Environment && p.Audience == protocol.Resource
	if !selectedSource || !exactAudience || (authority.AuthorityScope{TenantID: authorization.TenantID(c.TenantID), PolicyNamespace: c.ClientPolicyNamespace, SubjectID: "scope-validation"}).Validate() != nil {
		return APIKeyExchangeConfig{}, oauth.ErrInvalidRequest
	}
	for _, namespace := range []string{parent.Session.Profile.PolicyNamespace, parent.WorkloadAuthority.PolicyNamespace, parent.WorkloadExchangeClientNamespace, parent.HumanCodeExchangeClientNamespace} {
		if c.ClientPolicyNamespace == namespace {
			return APIKeyExchangeConfig{}, oauth.ErrInvalidRequest
		}
	}
	for _, client := range protocol.Clients {
		if client.APIKeyExchange && strings.HasPrefix(client.ID, oauth.ManagedClientPrefix) {
			return APIKeyExchangeConfig{}, oauth.ErrInvalidRequest
		}
	}
	c.ClientPolicyNamespace = strings.Clone(c.ClientPolicyNamespace)
	return c, nil
}

// Persist only explicit nonsecret provenance, not SourceAuthorityObservation or
// its current Record. The latter remains invocation-local and must come from a
// real primary read before protected Work. Historical verification timestamps
// never become a reusable bearer proof or a freshly copied observation.
type apiKeyGrantSource struct {
	ConfigurationID                               string
	ConfigurationRevision, ConfigurationAuthority uint64
	KeyID, RootID                                 apikey.KeyID
	Owner                                         apikey.OwnerSpec
	AuthorityVersion, RootVersion                 uint64
	Issuer, Environment, Audience                 string
	Grant                                         []string
	ExpiresAt                                     time.Time
	ReadStartedAt, VerifiedAt, ValidUntil         time.Time
	ClientNamespace, ClientAuthoritySubject       string
	ClientAuthorityVersion                        uint64
	Policy                                        oauth.APIKeyExchangePolicy
}

func (apiKeyGrantSource) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth API-key source(redacted)"))
}

func apiKeySourceFromVerification(r apikey.VerificationResult, configuration apikey.Configuration, now time.Time) (*apiKeyGrantSource, error) {
	b, err := apikey.NewSourceAuthorityBinding(r, configuration, now)
	if err != nil {
		return nil, err
	}
	return &apiKeyGrantSource{ConfigurationID: b.ConfigurationAuthority.ConfigurationID, ConfigurationRevision: b.ConfigurationRevision, ConfigurationAuthority: b.ConfigurationAuthority.Version, KeyID: b.KeyID, RootID: b.RootID, Owner: b.Owner.Spec(), AuthorityVersion: b.AuthorityVersion, RootVersion: b.RootVersion, Issuer: b.Issuer, Environment: b.Environment, Audience: b.Audience, Grant: slices.Clone(b.Grant), ExpiresAt: b.ExpiresAt, ReadStartedAt: r.ReadStartedAt, VerifiedAt: r.VerifiedAt, ValidUntil: r.ValidUntil}, nil
}

func (s apiKeyGrantSource) binding(configuration apikey.Configuration) (apikey.SourceAuthorityBinding, error) {
	owner, err := apikey.NewOwner(s.Owner)
	if err != nil {
		return apikey.SourceAuthorityBinding{}, oauth.ErrInvalidGrant
	}
	b := apikey.SourceAuthorityBinding{ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: s.Owner.TenantID, ConfigurationID: s.ConfigurationID, Version: s.ConfigurationAuthority}, ConfigurationRevision: s.ConfigurationRevision, KeyID: s.KeyID, Owner: owner, AuthorityVersion: s.AuthorityVersion, RootID: s.RootID, RootVersion: s.RootVersion, Issuer: s.Issuer, Environment: s.Environment, Audience: s.Audience, Grant: slices.Clone(s.Grant), ExpiresAt: s.ExpiresAt}
	historicalWindow := !s.ReadStartedAt.IsZero() && !s.VerifiedAt.Before(s.ReadStartedAt) && s.VerifiedAt.Sub(s.ReadStartedAt) <= configuration.Spec().MaximumRead && s.ValidUntil.After(s.VerifiedAt) && !s.ValidUntil.After(s.ReadStartedAt.Add(20*time.Second)) && !s.ValidUntil.After(s.ExpiresAt)
	if b.Validate(configuration) != nil || !historicalWindow {
		return apikey.SourceAuthorityBinding{}, oauth.ErrInvalidGrant
	}
	return b, nil
}

func (s *Store) apiKeyExchangeSelected(client oauth.Client) bool {
	return s.config.APIKeyExchange != nil && s.config.Protocol.APIKeyExchange != nil && client.APIKeyExchange && !client.Public && client.Workload == nil && !client.HumanCodeExchange && client.AuthenticationMethod == "client_secret_basic" && !s.managedID(client.ID)
}

func (s *Store) apiKeyClientScope(client oauth.Client) authority.AuthorityScope {
	h := sha256.New()
	_, _ = h.Write([]byte("golib.oauth.user-api-key-client-authority.v1\x00"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(client.ID)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(client.ID))
	binary.BigEndian.PutUint64(size[:], client.Version)
	_, _ = h.Write(size[:])
	return authority.AuthorityScope{TenantID: authorization.TenantID(s.config.APIKeyExchange.TenantID), PolicyNamespace: s.config.APIKeyExchange.ClientPolicyNamespace, SubjectID: authorization.SubjectID(base64.RawURLEncoding.EncodeToString(h.Sum(nil)))}
}

func (s *Store) validAPIKeyGrant(g grantRecord, client oauth.Client) bool {
	if !s.apiKeyExchangeSelected(client) || g.APIKeySource == nil || g.Workload != nil || len(g.Source) != 0 || g.ConsentID != "" || g.ConsentGeneration != 0 || g.Subject != nil {
		return false
	}
	source := g.APIKeySource
	binding, err := source.binding(s.config.APIKeyExchange.Configuration)
	scope := s.apiKeyClientScope(client)
	ownerMatches := g.Tenant == s.config.APIKeyExchange.TenantID && g.Tenant == binding.Owner.Spec().TenantID && g.User == binding.Owner.Spec().UserID
	clientMatches := g.ClientID == client.ID && g.ClientVersion == client.Version && g.ClientFingerprint == clientFingerprint(client) && source.ClientNamespace == scope.PolicyNamespace && source.ClientAuthoritySubject == string(scope.SubjectID) && source.ClientAuthorityVersion == 1
	ceilingMatches := g.Resource == source.Audience && g.Resource == client.Resource && scopeSubset(g.Scopes, source.Grant) && scopeSubset(g.Scopes, client.Scopes) && !hasExtensionScopes(g.Scopes) && !g.ExpiresAt.After(source.ExpiresAt) && g.ExpiresAt.After(g.CreatedAt) && !g.ExpiresAt.After(g.CreatedAt.Add(s.config.Protocol.AccessTTL))
	return err == nil && ownerMatches && clientMatches && ceilingMatches && source.Policy == *s.config.Protocol.APIKeyExchange
}

func hasExtensionScopes(scopes []string) bool {
	for _, scope := range scopes {
		switch scope {
		case "openid", "profile", "email", "address", "phone", "offline_access":
			return true
		}
	}
	return false
}

func apiKeySourceFingerprint(source *apiKeyGrantSource) [32]byte {
	wire, _ := json.Marshal(source)
	defer clear(wire)
	return sha256.Sum256(wire)
}

type apiKeyExchangeLineage struct {
	RootID, ParentID, ParentTokenType       string
	RootVersion, ParentVersion              uint64
	Depth                                   uint8
	SourceFingerprint                       [32]byte
	Issuer, Environment, ClientID, Resource string
	ClientVersion                           uint64
	SourceReadStartedAt, SourceValidUntil   time.Time
}

func (s *Store) apiKeyClientAuthority(ctx context.Context, client oauth.Client) error {
	if !s.apiKeyExchangeSelected(client) {
		return oauth.ErrInvalidGrant
	}
	current, err := s.policy.Get(ctx, s.apiKeyClientScope(client))
	if err != nil {
		return err
	}
	if current.Version != 1 {
		return oauth.ErrInvalidGrant
	}
	return nil
}

// BootstrapAPIKeyExchangeClient initializes only the selected registration's
// independent policy epoch. It requires its real configured Basic secret and
// the completed API-key schema; it grants neither key authority nor a session.
// Repeating epoch one is idempotent. Advanced epochs remain withdrawn. This is
// trusted installation, never an implicit issuance/read effect or HTTP endpoint.
// The borrowed Store and source must remain alive; calls are bounded and safe
// concurrently. A failed commit acknowledgement returns unavailable, not success.
func (s *Store) BootstrapAPIKeyExchangeClient(ctx context.Context, request oauth.IntrospectRequest) error {
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return err
	}
	defer stop()
	client, err := s.CurrentClient(ctx, request.ClientID)
	if err != nil || !s.apiKeyExchangeSelected(client) || request.Token != "" {
		return oauth.ErrInvalidRequest
	}
	proof, err := s.authenticateClientSnapshot(ctx, client, request.ClientAuthentication)
	if err != nil {
		return err
	}
	// A catalog read is installation readiness, not a runtime capability probe.
	var ready bool
	err = s.pool.Raw().QueryRow(ctx, `SELECT count(*)=4 AND bool_and(convalidated) FROM pg_constraint WHERE conrelid=($1||'.artifacts')::regclass AND conname IN('artifacts_api_key_parent','artifacts_api_key_shape','artifacts_api_key_metadata','artifacts_api_key_reference')`, s.config.Schema).Scan(&ready)
	if err != nil || !ready {
		return oauth.ErrUnavailable
	}
	scope := s.apiKeyClientScope(client)
	current, err := s.policy.Get(ctx, scope)
	if err == nil {
		if current.Version != 1 {
			return oauth.ErrAccessDenied
		}
		return s.finishClientAuthentication(ctx, client, proof)
	}
	if !errors.Is(err, authority.ErrAuthorityDenied) {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	tx, err := s.pool.Raw().Begin(ctx)
	if err != nil {
		return oauth.ErrUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), s.config.Protocol.MaximumDuration)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	_, err = authority.InitializeAuthority(ctx, tx, scope, s.config.Protocol.MaximumDuration)
	if errors.Is(err, authority.ErrAuthorityConflict) {
		if tx.Rollback(ctx) != nil {
			return oauth.ErrUnavailable
		}
		if err := s.apiKeyClientAuthority(ctx, client); err != nil {
			return publicError(ctx, err, oauth.ErrAccessDenied)
		}
		return s.finishClientAuthentication(ctx, client, proof)
	}
	if err != nil {
		return publicError(ctx, err, oauth.ErrAccessDenied)
	}
	if err = s.finishClientAuthentication(ctx, client, proof); err != nil {
		return err
	}
	if tx.Commit(ctx) != nil {
		return oauth.ErrUnavailable
	}
	return publicError(ctx, s.apiKeyClientAuthority(ctx, client), oauth.ErrAccessDenied)
}

func apiKeyError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, apikey.ErrDenied) || errors.Is(err, apikey.ErrInvalid) || errors.Is(err, authority.ErrAuthorityDenied) {
		return oauth.ErrInvalidGrant
	}
	return publicError(ctx, err, oauth.ErrInvalidGrant)
}

// The coordinator owns terminal failure classification. A current source or
// ancestor denial inside Work must use its existing typed denial, not a protocol
// sentinel that the generic owner correctly classifies as dependency failure.
func apiKeyWorkError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, oauth.ErrInvalidGrant) || errors.Is(err, apikey.ErrDenied) || errors.Is(err, authority.ErrAuthorityDenied) {
		return identity.ForbiddenError{}
	}
	return err
}

func (s *Store) observeAPIKey(ctx context.Context, g grantRecord, client oauth.Client) (apikey.SourceAuthorityObservation, error) {
	if !s.validAPIKeyGrant(g, client) {
		return apikey.SourceAuthorityObservation{}, oauth.ErrInvalidGrant
	}
	if err := s.apiKeyClientAuthority(ctx, client); err != nil {
		return apikey.SourceAuthorityObservation{}, apiKeyError(ctx, err)
	}
	binding, _ := g.APIKeySource.binding(s.config.APIKeyExchange.Configuration)
	observation, err := s.config.APIKeyExchange.Source.ObserveSourceAuthority(ctx, binding)
	if err != nil {
		return apikey.SourceAuthorityObservation{}, apiKeyError(ctx, err)
	}
	if !scopeSubset(g.Scopes, observation.Grant) {
		return apikey.SourceAuthorityObservation{}, oauth.ErrInvalidGrant
	}
	return observation, nil
}

func (s *Store) validAPIKeyLineage(e *apiKeyExchangeLineage, g grantRecord, client oauth.Client) bool {
	if !s.validAPIKeyGrant(g, client) || e == nil {
		return false
	}
	source := g.APIKeySource
	_, parentErr := identity.ParseSubjectID(e.ParentID)
	if e.Depth == 1 {
		_, parentErr = apikey.ParseKeyID(e.ParentID)
	}
	rootMatches := e.RootID == string(source.RootID) && e.RootVersion == source.RootVersion && e.Depth > 0 && e.Depth <= source.Policy.MaximumDepth
	profileMatches := e.Issuer == source.Issuer && e.Environment == source.Environment && e.ClientID == client.ID && e.ClientVersion == client.Version && e.Resource == g.Resource
	originMatches := e.SourceFingerprint == apiKeySourceFingerprint(source) && e.SourceReadStartedAt.Equal(source.ReadStartedAt) && e.SourceValidUntil.Equal(source.ValidUntil)
	keyParent := e.Depth == 1 && e.ParentTokenType == oauth.APIKeyTokenType && e.ParentID == e.RootID && e.ParentVersion == e.RootVersion
	accessParent := e.Depth > 1 && e.ParentTokenType == oauth.AccessTokenType && e.ParentVersion == 1
	return parentErr == nil && e.ParentVersion > 0 && rootMatches && profileMatches && originMatches && (keyParent || accessParent)
}

func (s *Store) apiKeyLineageCurrent(ctx context.Context, a artifactRecord, client oauth.Client, now time.Time, query exchangeQuery, locked bool) error {
	if a.Kind != oauth.TokenAccess || !s.validAPIKeyLineage(a.Payload.APIKeyExchange, a.Grant, client) {
		return oauth.ErrInvalidGrant
	}
	current, depth := a.ID, a.Payload.APIKeyExchange.Depth
	seen := make(map[string]bool, 4)
	var childScopes []string
	var childExpiry time.Time
	for depth > 0 {
		if seen[current] {
			return oauth.ErrInvalidGrant
		}
		seen[current] = true
		statement := `SELECT COALESCE(parent_artifact_id,''),kind,state,payload,created_at,expires_at,api_key_only,api_key_root,metadata_version FROM ` + s.schema + `.artifacts WHERE artifact_id=$1 AND grant_id=$2 AND client_id=$3`
		if locked {
			statement += ` FOR SHARE`
		}
		rows, err := query(ctx, statement, current, a.Grant.ID, client.ID)
		if err != nil {
			return err
		}
		if !rows.Next() {
			err := rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			return oauth.ErrInvalidGrant
		}
		var parent, state string
		var kind int16
		var raw []byte
		var created, expires time.Time
		var selected, root bool
		var version uint64
		err = rows.Scan(&parent, &kind, &state, &raw, &created, &expires, &selected, &root, &version)
		extra, rowErr := rows.Next(), rows.Err()
		rows.Close()
		if err != nil || extra || rowErr != nil {
			return oauth.ErrUnavailable
		}
		var payload artifactPayload
		if decodeJSON(raw, &payload) != nil || payload.Schema != 1 || payload.Exchange != nil || payload.HumanExchange != nil || payload.HumanRefresh != nil || !s.validAPIKeyLineage(payload.APIKeyExchange, a.Grant, client) || payload.APIKeyExchange.Depth != depth || !selected || root != (depth == 1) || version != 1 || kind != int16(oauth.TokenAccess) || state != "active" || now.Before(created) || !now.Before(expires) || expires.After(a.Grant.ExpiresAt) || !scopeSubset(payload.Scopes, a.Grant.Scopes) || childScopes != nil && !scopeSubset(childScopes, payload.Scopes) || !childExpiry.IsZero() && childExpiry.After(expires) {
			return oauth.ErrInvalidGrant
		}
		canonical, err := selectedScopes(payload.Scopes)
		if err != nil || !slices.Equal(canonical, payload.Scopes) || current == a.ID && (!sameJSON(payload, a.Payload) || !expires.Equal(a.ExpiresAt)) {
			return oauth.ErrInvalidGrant
		}
		if depth == 1 {
			if parent != "" {
				return oauth.ErrInvalidGrant
			}
			return nil
		}
		if parent == "" || payload.APIKeyExchange.ParentID != parent {
			return oauth.ErrInvalidGrant
		}
		childScopes, childExpiry = payload.Scopes, expires
		current, depth = parent, depth-1
	}
	return oauth.ErrInvalidGrant
}

func (s *Store) readAPIKeyLineage(ctx context.Context, a artifactRecord, client oauth.Client, now time.Time) error {
	return s.apiKeyLineageCurrent(ctx, a, client, now, func(ctx context.Context, q string, args ...any) (exchangeRows, error) {
		return s.pool.Raw().Query(ctx, q, args...)
	}, false)
}

func (p *phase) checkAPIKeySource(ctx context.Context, w kernel.Work) error {
	g := p.input.Grant
	if !p.store.validAPIKeyGrant(g, p.client) || p.input.Binding.ActorKind != authorization.SubjectAPIKey || p.input.Binding.ActorID != identity.ActorID(g.APIKeySource.KeyID) || p.input.Binding.UserID != g.User {
		return identity.ForbiddenError{}
	}
	if !p.issuing() {
		return nil
	}
	if p.apiKeyObservation == nil || p.input.ExchangeObservation == nil {
		return identity.ForbiddenError{}
	}
	binding, err := g.APIKeySource.binding(p.store.config.APIKeyExchange.Configuration)
	if err != nil || p.apiKeyObservation.Validate(binding, p.store.config.APIKeyExchange.Configuration, p.store.now()) != nil {
		return identity.ForbiddenError{}
	}
	if err := authority.RequireAuthority(ctx, w, p.store.apiKeyClientScope(p.client), 1, p.store.config.Protocol.MaximumDuration); err != nil {
		return apiKeyWorkError(ctx, err)
	}
	if err := p.store.config.APIKeyExchange.Source.RequireSourceAuthority(ctx, w, p, *p.apiKeyObservation); err != nil {
		return apiKeyWorkError(ctx, err)
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(p.input.ExchangeObservation.ValidUntil) || !p.store.now().Before(p.input.ExchangeObservation.ValidUntil) || !scopeSubset(p.input.Scopes, p.apiKeyObservation.Grant) {
		return identity.ForbiddenError{}
	}
	if p.input.Transition == createAPIKeyGrant {
		if !now.Before(g.APIKeySource.ValidUntil) || !p.store.now().Before(g.APIKeySource.ValidUntil) {
			return identity.ForbiddenError{}
		}
		return nil
	}
	if p.input.Transition == exchangeAPIKeyAccess {
		a := artifactRecord{ID: p.input.TargetID, Kind: p.input.TargetKind, Grant: g, Payload: p.input.TargetPayload, ExpiresAt: p.input.TargetExpires}
		if err := p.store.apiKeyLineageCurrent(ctx, a, p.client, now, func(ctx context.Context, q string, args ...any) (exchangeRows, error) {
			return w.Query(ctx, q, args...)
		}, true); err != nil {
			return apiKeyWorkError(ctx, err)
		}
	}
	return nil
}

func (s *Store) apiKeyVerificationAttempt(client oauth.Client, command identity.CommandID) apikey.VerificationAttemptID {
	c := s.config.APIKeyExchange.Configuration.Spec()
	digest := s.intent("oauth-user-api-key-verification-v1", string(command), client.ID, strconv.FormatUint(client.Version, 10), string(s.config.APIKeyExchange.TenantID), c.ID, strconv.FormatUint(c.Revision, 10))
	return apikey.VerificationAttemptID(base64.RawURLEncoding.EncodeToString(digest[:16]))
}

func (s *Store) initialAPIKeyRecoveryPhase(ctx context.Context, client oauth.Client, request RecoveryRequest) (*phase, error) {
	if request.APIKeyVerification == nil {
		return nil, oauth.ErrAccessDenied
	}
	q := *request.APIKeyVerification
	expected := s.apiKeyVerificationAttempt(client, request.CommandID)
	if q.Validate() != nil || q.AttemptID != expected || q.TenantID != s.config.APIKeyExchange.TenantID || q.Original.ActorKind != authorization.SubjectAPIKey || q.Original.UserID == "" || q.Original.AnonymousFlowID != "" {
		return nil, oauth.ErrAccessDenied
	}
	actual, err := s.config.APIKeyExchange.Source.ReconcileVerifyAndConsume(ctx, q)
	// Expired original success intentionally returns no principal and Denied.
	// Its authenticated historical routing can still address the ORIGINAL OAuth
	// preparation, which independently proves source/intent; it never issues.
	if actual.Original != q.Original || actual.Fingerprint != q.Fingerprint || actual.Outcome != identity.CommitOutcomeCommitted || err != nil && !errors.Is(err, apikey.ErrDenied) {
		return nil, oauth.ErrUnavailable
	}
	g := grantRecord{ID: string(request.CommandID), Tenant: q.Original.TenantID, User: q.Original.UserID, Source: []identity.FeatureField{}, APIKeySource: &apiKeyGrantSource{KeyID: apikey.KeyID(q.Original.ActorID)}}
	p := &phase{store: s, client: client, input: phaseInput{Schema: 1, Configuration: s.identity, Transition: createAPIKeyGrant, Grant: g, Intent: s.intent("recover")}, metadataRecovery: true}
	p.bind(request.CommandID, request.OperationID, g.ID)
	return p, nil
}

func (s *Store) exchangeAPIKey(ctx context.Context, client oauth.Client, request oauth.TokenRequest, proof *clientAuthenticationSnapshot) (oauth.TokenResult, *phase, error) {
	fail := func(err error) (oauth.TokenResult, *phase, error) { return oauth.TokenResult{}, nil, err }
	if !s.apiKeyExchangeSelected(client) {
		return fail(oauth.ErrUnsupportedGrant)
	}
	command := request.CommandID
	var err error
	if command == "" {
		command, err = identity.NewCommandID()
	} else {
		_, err = identity.ParseCommandID(string(command))
	}
	if err != nil {
		return fail(oauth.ErrInvalidRequest)
	}
	if request.Code != "" || request.CodeVerifier != "" || request.RedirectURI != "" || request.RefreshToken != "" || (request.Resource == "") == (request.Audience == "") || request.Resource != client.Resource && request.Audience != client.Resource || request.RequestedTokenType != "" && request.RequestedTokenType != oauth.AccessTokenType {
		return fail(oauth.ErrInvalidRequest)
	}
	selected := slices.Clone(request.Scopes)
	var p *phase
	var verificationQuery apikey.VerificationReconcileQuery
	if request.SubjectTokenType == oauth.APIKeyTokenType {
		secret, err := apikey.ParseSecret(request.SubjectToken)
		if err != nil {
			return fail(oauth.ErrInvalidGrant)
		}
		// Separate domain-separated coordinator command, stable across retries.
		attempt := s.apiKeyVerificationAttempt(client, command)
		configuration := s.config.APIKeyExchange.Configuration
		verification, err := s.config.APIKeyExchange.Source.VerifyAndConsume(ctx, apikey.AtomicVerificationRequest{AttemptID: attempt, TenantID: s.config.APIKeyExchange.TenantID, ConfigurationID: configuration.Spec().ID, ConfigurationRevision: configuration.Spec().Revision, Secret: secret, RequiredPermissions: selected})
		verificationQuery = apikey.VerificationReconcileQuery{AttemptID: verification.AttemptID, TenantID: s.config.APIKeyExchange.TenantID, Fingerprint: verification.Fingerprint, Original: verification.Original}
		request.SubjectToken = ""
		secret = apikey.Secret{}
		if verification.Outcome == identity.CommitOutcomeUnknown || verification.Outcome == identity.CommitOutcomeInProgress {
			if verificationQuery.Validate() != nil {
				verificationQuery = apikey.VerificationReconcileQuery{}
			}
			return oauth.TokenResult{Outcome: verification.Outcome, CommandID: command}, nil, oauth.APIKeyExchangeUnknownError{CommandID: command, Verification: verificationQuery}
		}
		if err != nil {
			return fail(apiKeyError(ctx, err))
		}
		if verification.Validate() != nil || verification.Result == nil || verification.State != apikey.VerificationAttemptNotApplicable {
			return fail(oauth.ErrInvalidGrant)
		}
		source, err := apiKeySourceFromVerification(*verification.Result, configuration, s.now())
		if err != nil {
			return fail(apiKeyError(ctx, err))
		}
		if selected == nil {
			selected = slices.Clone(source.Grant)
		}
		if !scopeSubset(selected, source.Grant) || !scopeSubset(selected, client.Scopes) || hasExtensionScopes(selected) {
			return fail(oauth.ErrInvalidScope)
		}
		scope := s.apiKeyClientScope(client)
		source.ClientNamespace = scope.PolicyNamespace
		source.ClientAuthoritySubject = string(scope.SubjectID)
		source.ClientAuthorityVersion = 1
		source.Policy = *s.config.Protocol.APIKeyExchange
		now := s.now()
		g := grantRecord{ID: string(command), Tenant: source.Owner.TenantID, User: source.Owner.UserID, ClientID: client.ID, ClientVersion: client.Version, ClientFingerprint: clientFingerprint(client), Source: []identity.FeatureField{}, Scopes: selected, Resource: client.Resource, CreatedAt: now, ExpiresAt: minTime(source.ExpiresAt, now.Add(min(s.config.Protocol.AccessTTL, 5*time.Minute))), APIKeySource: source}
		p = &phase{store: s, client: client, input: phaseInput{Schema: 1, Configuration: s.identity, Transition: createAPIKeyGrant, Grant: g, CreatedAt: now, Scopes: selected, Intent: s.intent("api-key-exchange-v1", string(command), string(source.KeyID), request.Resource, request.Audience, strings.Join(selected, " ")), Network: request.Network}}
		p.input.APIKeyExchange = &apiKeyExchangeLineage{RootID: string(source.RootID), RootVersion: source.RootVersion, ParentID: string(source.RootID), ParentVersion: source.RootVersion, ParentTokenType: oauth.APIKeyTokenType, Depth: 1, SourceFingerprint: apiKeySourceFingerprint(source), Issuer: source.Issuer, Environment: source.Environment, ClientID: client.ID, ClientVersion: client.Version, Resource: client.Resource, SourceReadStartedAt: source.ReadStartedAt, SourceValidUntil: source.ValidUntil}
		p.bind(command, "identity.oauth-server.token", g.ID)
	} else if request.SubjectTokenType == oauth.AccessTokenType {
		a, err := s.lookup(ctx, request.SubjectToken, client, []oauth.TokenKind{oauth.TokenAccess})
		if err != nil {
			return fail(err)
		}
		now, err := s.introspectionTime(ctx)
		if err != nil {
			return fail(err)
		}
		if !activeIntrospectionArtifact(a, now) || !s.validAPIKeyLineage(a.Payload.APIKeyExchange, a.Grant, client) {
			return fail(oauth.ErrInvalidGrant)
		}
		if err := s.readAPIKeyLineage(ctx, a, client, now); err != nil {
			return fail(err)
		}
		if selected == nil {
			selected = slices.Clone(a.Payload.Scopes)
		}
		if !scopeSubset(selected, a.Payload.Scopes) || hasExtensionScopes(selected) {
			return fail(oauth.ErrInvalidScope)
		}
		e := *a.Payload.APIKeyExchange
		e.ParentID = a.ID
		e.ParentVersion = a.MetadataVersion
		e.ParentTokenType = oauth.AccessTokenType
		e.Depth++
		p = s.targetPhase(a, client, exchangeAPIKeyAccess, "identity.oauth-server.token", command, s.intent("api-key-child-exchange-v1", a.ID, request.Resource, request.Audience, strings.Join(selected, " ")), request.Network)
		p.input.APIKeyExchange = &e
		p.input.Scopes = selected
	} else {
		return fail(oauth.ErrInvalidRequest)
	}
	if !s.validAPIKeyLineage(p.input.APIKeyExchange, p.input.Grant, client) {
		return fail(oauth.ErrInvalidGrant)
	}
	for _, scope := range selected {
		if !s.config.Protocol.Scopes.Contains(scope) {
			return fail(oauth.ErrInvalidScope)
		}
	}
	observation, err := s.observeAPIKey(ctx, p.input.Grant, client)
	if err != nil {
		return fail(err)
	}
	p.apiKeyObservation = &observation
	until := observation.ValidUntil
	if p.input.Transition == createAPIKeyGrant {
		until = minTime(until, p.input.Grant.APIKeySource.ValidUntil)
	} else {
		until = minTime(until, p.input.TargetExpires)
	}
	p.input.ExchangeObservation = &exchangeObservation{ReadStartedAt: observation.ReadStartedAt, ValidUntil: until}
	p.input.ClientAuthentication = proof
	result, err := p.execute(ctx)
	out := oauth.TokenResult{Outcome: result.Outcome, CommandID: command, Replayed: !p.applied}
	if p.input.Transition == createAPIKeyGrant && (result.Outcome == identity.CommitOutcomeUnknown || result.Outcome == identity.CommitOutcomeInProgress) {
		return out, p, oauth.APIKeyExchangeUnknownError{CommandID: command, Verification: verificationQuery}
	}
	if err != nil {
		return out, p, apiKeyError(ctx, err)
	}
	if result.Outcome == identity.CommitOutcomeCommitted && p.applied {
		out.AccessToken = p.generatedToken(oauth.TokenAccess)
		out.ExpiresAt = p.generatedExpiry(oauth.TokenAccess)
		out.Resource = client.Resource
		out.Scopes = selected
		out.IssuedTokenType = oauth.AccessTokenType
	}
	return out, p, nil
}
