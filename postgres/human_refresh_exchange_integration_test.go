//go:build integration && oauthflow

package oauthpostgres_test

import (
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

func selectHumanRefreshExchange(t *testing.T, h *humanNativeExchange) {
	t.Helper()
	h.f.oauth.Protocol.HumanCodeExchange.AllowRefreshIssuedAccess = true
	var err error
	h.store, err = oauthpostgres.NewStore(h.f.pool, h.f.oauth, h.f.keys)
	if err != nil {
		t.Fatal(err)
	}
	h.service, err = oauthpostgres.NewService(h.f.pool, h.f.oauth, h.f.keys)
	if err != nil {
		t.Fatal(err)
	}
}

func rotateHumanRefresh(t *testing.T, h humanNativeExchange, refresh string) (string, string) {
	t.Helper()
	out, err := h.service.Token(h.f.ctx, oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, RefreshToken: refresh, Scopes: []string{"identity:read"}, Network: "192.0.2.1"})
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine native refresh rotation", err)
	}
	access, err := out.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	next, err := out.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return access, next
}

func TestNativeHumanRefreshIssuedAccessExchangeRepeatedRotation(t *testing.T) {
	h := nativeHumanExchange(t, false)
	selectHumanRefreshExchange(t, &h)
	code, verifier := confidentialCodeScopes(t, h.f, h.service, h.client, []string{"identity:read", "identity:write"})
	original, err := h.service.Token(h.f.ctx, oauth.TokenRequest{GrantType: oauth.AuthorizationCodeGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, Code: code, CodeVerifier: verifier, RedirectURI: h.client.Redirects[0], Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("genuine two-scope code redemption", err)
	}
	h.source, err = original.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	h.refresh, err = original.RefreshToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	access, refresh := h.source, h.refresh
	// Refresh succession is not delegation depth. More than four native
	// rotations must retain bounded original S256 proof without a chain walk.
	for range 6 {
		access, refresh = rotateHumanRefresh(t, h, refresh)
	}
	request := humanExchangeRequest(h.client, h.basic, access)
	expanded := request
	expanded.Scopes = []string{"identity:read", "identity:write"}
	if out, err := h.service.Token(h.f.ctx, expanded); !errors.Is(err, oauth.ErrInvalidScope) || out.AccessToken != (oauth.Token{}) {
		t.Fatal("refresh-source exchange restored an original scope removed by rotation", err)
	}
	request.CommandID, _ = identity.NewCommandID()
	issued, err := h.service.Token(h.f.ctx, request)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted || issued.RefreshToken != (oauth.Token{}) || issued.IssuedTokenType != oauth.AccessTokenType {
		t.Fatal("explicit refreshed human access source could not delegate", err)
	}
	child, err := issued.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	descendants := []string{child}
	for range 3 {
		descendants = append(descendants, humanChild(t, h, descendants[len(descendants)-1]))
	}
	if out, err := h.service.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, descendants[3])); !errors.Is(err, oauth.ErrInvalidGrant) || out.AccessToken != (oauth.Token{}) {
		t.Fatal("refresh-issued root exceeded four delegation steps", err)
	}
	var starts, deadlines int
	var bounded bool
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT count(DISTINCT payload->'HumanExchange'->>'SourceReadStartedAt'),count(DISTINCT payload->'HumanExchange'->>'SourceValidUntil'),bool_and((payload->'HumanExchange'->>'SourceValidUntil')::timestamptz<=(payload->'HumanExchange'->>'SourceReadStartedAt')::timestamptz+interval '20 seconds') FROM oauth_store.artifacts WHERE human_code_exchange`).Scan(&starts, &deadlines, &bounded); err != nil || starts != 1 || deadlines != 1 || !bounded {
		t.Fatal("refreshed-source delegation renewed original lineage freshness", err)
	}
	v, err := oauthpostgres.NewResourceVerifier(h.f.pool, h.f.oauth, h.f.keys, resourcePolicy(h.f, h.client))
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range []string{access, child} {
		out, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: wire})
		if err != nil || !out.Active || out.ClientID != h.client.ID || out.Subject == "" || out.Resource != h.client.Resource || len(out.Scopes) != 1 || out.Scopes[0] != "identity:read" {
			t.Fatal("refreshed access consumer lost original human authority", err)
		}
		if _, err := v.Verify(h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: wire, Scope: "identity:read"}); err != nil {
			t.Fatal("direct refreshed access/resource consumer denied", err)
		}
	}
	retried, err := h.service.Token(h.f.ctx, request)
	if err != nil || !retried.Replayed || retried.Outcome != identity.CommitOutcomeCommitted || retried.AccessToken != (oauth.Token{}) {
		t.Fatal("refreshed source retry duplicated or redisclosed child", err)
	}
	metadata, err := h.store.Recover(h.f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: request.CommandID, ClientID: h.client.ID, ClientAuthentication: h.basic, Token: access})
	if err != nil || metadata.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("refreshed source metadata-only recovery", err)
	}
	request.SubjectToken = refresh
	if out, err := h.service.Token(h.f.ctx, request); !errors.Is(err, oauth.ErrInvalidGrant) || out.AccessToken != (oauth.Token{}) {
		t.Fatal("refresh bearer became delegation authority", err)
	}
	if _, err := h.service.Revoke(h.f.ctx, oauth.RevokeRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: access, Hint: oauth.TokenAccess, Network: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	for _, wire := range descendants {
		if out, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: wire}); err != nil || out.Active {
			t.Fatal("refreshed access parent withdrawal retained child", err)
		}
		if _, err := v.Verify(h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: wire, Scope: "identity:read"}); err == nil {
			t.Fatal("warm resource verifier retained withdrawn refreshed parent")
		}
	}
}

func TestNativeHumanRefreshIssuedAccessRetainsCodeOnlyDefault(t *testing.T) {
	h := nativeHumanExchange(t, false)
	codeChild := humanChild(t, h, h.source)
	access, _ := rotateHumanRefresh(t, h, h.refresh)
	if out, err := h.service.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, access)); !errors.Is(err, oauth.ErrInvalidGrant) || out.AccessToken != (oauth.Token{}) {
		t.Fatal("default profile accepted refreshed access", err)
	}
	selectHumanRefreshExchange(t, &h)
	if out, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: codeChild}); err != nil || !out.Active {
		t.Fatal("additive refreshed-source selection withdrew code-root child", err)
	}
	if out, err := h.service.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, access)); !errors.Is(err, oauth.ErrInvalidGrant) || out.AccessToken != (oauth.Token{}) {
		t.Fatal("activation fabricated missing historical refresh provenance", err)
	}
	selectedCodeChild := humanChild(t, h, h.source)
	h.f.oauth.Protocol.HumanCodeExchange.AllowRefreshIssuedAccess = false
	var err error
	h.service, err = oauthpostgres.NewService(h.f.pool, h.f.oauth, h.f.keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range []string{codeChild, selectedCodeChild} {
		if out, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: wire}); err != nil || !out.Active {
			t.Fatal("disabling refreshed sources withdrew a code-root child", err)
		}
	}
}

func TestNativeHumanRefreshIssuedAccessWithdrawalUsesCurrentOwners(t *testing.T) {
	for _, mode := range []string{"grant", "consent", "user", "credential", "authorization", "client", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			h := nativeHumanExchange(t, mode == "credential")
			selectHumanRefreshExchange(t, &h)
			access, refresh := rotateHumanRefresh(t, h, h.refresh)
			child := humanChild(t, h, access)
			grandchild := humanChild(t, h, child)
			metadata, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: child})
			if err != nil || !metadata.Active {
				t.Fatal(err)
			}
			v, err := oauthpostgres.NewResourceVerifier(h.f.pool, h.f.oauth, h.f.keys, resourcePolicy(h.f, h.client))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.Verify(h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: grandchild, Scope: "identity:read"}); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "grant":
				if _, err := h.service.Revoke(h.f.ctx, oauth.RevokeRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: refresh, Network: "192.0.2.1"}); err != nil {
					t.Fatal(err)
				}
			case "consent":
				consent := currentNarrowConsent(t, h.f, h.service)
				if out, err := h.service.ConsentDelete(h.f.ctx, oauth.ConsentDeleteRequest{Consent: ownConsentCommand(t, h.f, oauth.ConsentRemove, consent.ID(), consent.Version())}); err != nil || !out.Deleted {
					t.Fatal(err)
				}
			case "user":
				suspendResourceUser(t, h.f, identity.UserID(metadata.Subject))
			case "credential":
				h.f.changePassword()
			case "authorization":
				advanceHumanAuthority(t, h, authority.AuthorityScope{TenantID: authorization.TenantID(h.f.tenant), PolicyNamespace: h.f.oauth.Session.Profile.PolicyNamespace, SubjectID: authorization.SubjectID(metadata.Subject)})
			case "client":
				advanceHumanAuthority(t, h, humanClientEpoch(t, h))
			case "disabled":
				h.f.oauth.Protocol.HumanCodeExchange.AllowRefreshIssuedAccess = false
				h.service, err = oauthpostgres.NewService(h.f.pool, h.f.oauth, h.f.keys)
				if err != nil {
					t.Fatal(err)
				}
				v, err = oauthpostgres.NewResourceVerifier(h.f.pool, h.f.oauth, h.f.keys, resourcePolicy(h.f, h.client))
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, wire := range []string{child, grandchild} {
				if out, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: wire}); err != nil || out.Active {
					t.Fatal("withdrawn current owner retained refreshed descendants", err)
				}
				if _, err := v.Verify(h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: wire, Scope: "identity:read"}); err == nil {
					t.Fatal("warm direct consumer retained withdrawn refreshed authority")
				}
				if out, err := h.service.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, wire)); err == nil || out.AccessToken != (oauth.Token{}) {
					t.Fatal("withdrawal renewed refreshed descendant", err)
				}
			}
		})
	}
}

func TestNativeHumanRefreshIssuedAccessOutlivesExpiredConsumedRefreshProof(t *testing.T) {
	f := passwordFixture(t)
	enableConsentManagement(t, &f)
	client, _, basic := addConfiguredConfidentialClient(t, &f)
	enableHumanCodeExchange(t, &f, &client)
	f.oauth.Protocol.HumanCodeExchange.AllowRefreshIssuedAccess = true
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	source, refresh := issuedConfidentialTokens(t, f, service, client, basic)
	store, err := oauthpostgres.NewStore(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapHumanCodeExchangeClient(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: basic, Token: source}); err != nil {
		t.Fatal(err)
	}
	h := humanNativeExchange{f: f, client: client, basic: basic, service: service, store: store, source: source, refresh: refresh}
	access, refresh := rotateHumanRefresh(t, h, refresh)
	// Native refreshes share their grant's terminal expiry, so naturally waiting
	// for the old refresh would also expire today's authority. This deliberate
	// temporal partition advances only consumed historical proof expiry; genuine
	// code redemption/rotation, current access/refresh and grant are unchanged.
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE oauth_store.artifacts SET expires_at=created_at+interval '1 microsecond' WHERE kind IN(2,4) AND state='consumed'`); err != nil {
		t.Fatal(err)
	}
	access, _ = rotateHumanRefresh(t, h, refresh)
	var expired bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT bool_and(expires_at<=clock_timestamp()) FROM oauth_store.artifacts WHERE kind=2 OR (kind=4 AND state='consumed' AND parent_artifact_id IN (SELECT artifact_id FROM oauth_store.artifacts WHERE kind=2))`).Scan(&expired); err != nil || !expired {
		t.Fatal("historical issuance proof expiry partition was not exercised", err)
	}
	child := humanChild(t, h, access)
	if out, err := service.Introspect(f.ctx, oauth.IntrospectRequest{ClientID: client.ID, ClientAuthentication: basic, Token: child}); err != nil || !out.Active {
		t.Fatal("expired consumed proof withdrew live access authority", err)
	}
}

func TestNativeHumanRefreshIssuedAccessAmbiguousCommitRecovery(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(map[bool]string{false: "after", true: "before"}[before], func(t *testing.T) {
			fault := &oauthCommitFault{before: before}
			h := nativeHumanExchange(t, false, fault)
			selectHumanRefreshExchange(t, &h)
			access, _ := rotateHumanRefresh(t, h, h.refresh)
			request := humanExchangeRequest(h.client, h.basic, access)
			request.CommandID, _ = identity.NewCommandID()
			fault.armed.Store(true)
			out, err := h.service.Token(h.f.ctx, request)
			if !fault.hit.Load() || out.Outcome != identity.CommitOutcomeUnknown || !errors.Is(err, oauth.ErrUnavailable) || out.AccessToken != (oauth.Token{}) {
				t.Fatal("actual refreshed-source COMMIT ambiguity concealed", err, out.Outcome)
			}
			want := identity.CommitOutcomeCommitted
			if before {
				want = identity.CommitOutcomeNotCommitted
				timer := time.NewTimer(21 * time.Second)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-h.f.ctx.Done():
					t.Fatal("original refreshed-source admission expiry cancelled")
				}
			}
			retried, _ := h.service.Token(h.f.ctx, request)
			if retried.AccessToken != (oauth.Token{}) || retried.Outcome != want {
				t.Fatal("ambiguous refreshed-source retry reissued or renewed", retried.Outcome)
			}
			metadata, err := h.store.Recover(h.f.ctx, oauthpostgres.RecoveryRequest{OperationID: "identity.oauth-server.token", CommandID: request.CommandID, ClientID: h.client.ID, ClientAuthentication: h.basic, Token: access})
			if err != nil && !(before && errors.Is(err, oauth.ErrUnavailable)) || metadata.Outcome != want {
				t.Fatal("refreshed-source metadata recovery contradicted durability", err, metadata.Outcome)
			}
			var children int
			if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT count(*) FROM oauth_store.artifacts WHERE human_code_exchange`).Scan(&children); err != nil || children != map[bool]int{false: 1, true: 0}[before] {
				t.Fatal("recovery invented or duplicated child", err, children)
			}
		})
	}
}

func TestNativeHumanRefreshIssuedAccessRejectsCorruptS256Provenance(t *testing.T) {
	h := nativeHumanExchange(t, false)
	selectHumanRefreshExchange(t, &h)
	_, refresh := rotateHumanRefresh(t, h, h.refresh)
	access, _ := rotateHumanRefresh(t, h, refresh)
	child := humanChild(t, h, access)
	v, err := oauthpostgres.NewResourceVerifier(h.f.pool, h.f.oauth, h.f.keys, resourcePolicy(h.f, h.client))
	if err != nil {
		t.Fatal(err)
	}
	var snapshot string
	if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT jsonb_agg(jsonb_build_object('id',artifact_id,'payload',payload,'parent',parent_artifact_id))::text FROM oauth_store.artifacts`).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{HumanRefresh,CodeID}','"foreign"') WHERE payload ? 'HumanRefresh'`,
		`UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{HumanRefresh,RootRefreshID}',to_jsonb(artifact_id)) WHERE kind=3 AND payload ? 'HumanRefresh'`,
		`UPDATE oauth_store.artifacts SET payload=payload-'HumanRefresh' WHERE kind=3 AND payload ? 'HumanRefresh'`,
		`UPDATE oauth_store.artifacts SET payload=jsonb_set(payload,'{Request,CodeChallenge}','""') WHERE kind=2`,
		`UPDATE oauth_store.artifacts SET parent_artifact_id=(SELECT artifact_id FROM oauth_store.artifacts WHERE kind=4 AND parent_artifact_id IN (SELECT artifact_id FROM oauth_store.artifacts WHERE kind=2)) WHERE kind=3 AND payload ? 'HumanRefresh'`,
	} {
		if _, err := h.f.pool.Raw().Exec(h.f.ctx, statement); err != nil {
			t.Fatal(err)
		}
		if out, err := h.service.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, access)); err == nil || out.AccessToken != (oauth.Token{}) {
			t.Fatal("corrupt historical issuance provenance delegated", err)
		}
		if _, err := v.Verify(h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: child, Scope: "identity:read"}); err == nil {
			t.Fatal("corrupt original S256 proof retained descendant authority")
		}
		if _, err := h.f.pool.Raw().Exec(h.f.ctx, `UPDATE oauth_store.artifacts a SET payload=s.payload,parent_artifact_id=s.parent FROM jsonb_to_recordset($1::jsonb) AS s(id text,payload jsonb,parent text) WHERE a.artifact_id=s.id`, snapshot); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(h.f.ctx, oauth.ResourceVerifyRequest{AccessToken: child, Scope: "identity:read"}); err != nil {
			t.Fatal("restored provenance was not a positive control", err)
		}
	}
}

func TestNativeHumanRefreshPreparedRotationSurvivesDelegationDisable(t *testing.T) {
	for _, mode := range []string{"refresh_sources", "human_profile"} {
		t.Run(mode, func(t *testing.T) {
			fault := &oauthCommitFault{before: true}
			h := nativeHumanExchange(t, false, fault)
			selectHumanRefreshExchange(t, &h)
			request := oauth.TokenRequest{GrantType: oauth.RefreshTokenGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, RefreshToken: h.refresh, Scopes: []string{"identity:read"}, Network: "192.0.2.1"}
			fault.armed.Store(true)
			lost, err := h.service.Token(h.f.ctx, request)
			if !fault.hit.Load() || lost.Outcome != identity.CommitOutcomeUnknown || !errors.Is(err, oauth.ErrUnavailable) || lost.AccessToken != (oauth.Token{}) || lost.RefreshToken != (oauth.Token{}) {
				t.Fatal("actual interrupted prepared refresh was not unknown", err, lost.Outcome)
			}
			// Observe the existing coordinator's normal lease, not an edited
			// journal or a fabricated preparation. Static Basic and the original
			// native grant remain current throughout this interrupted attempt.
			timer := time.NewTimer(h.f.oauth.Coordinator.LeaseDuration + 100*time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-h.f.ctx.Done():
				t.Fatal("original coordinator lease wait cancelled")
			}
			if mode == "refresh_sources" {
				h.f.oauth.Protocol.HumanCodeExchange.AllowRefreshIssuedAccess = false
			} else {
				h.f.oauth.Protocol.HumanCodeExchange = nil
				h.f.oauth.HumanCodeExchangeClientNamespace = ""
			}
			disabled, err := oauthpostgres.NewService(h.f.pool, h.f.oauth, h.f.keys)
			if err != nil {
				t.Fatal(err)
			}
			resumed, err := disabled.Token(h.f.ctx, request)
			if err != nil || resumed.Outcome != identity.CommitOutcomeCommitted || resumed.CommandID != lost.CommandID {
				t.Fatal("delegation disable stranded original ordinary refresh preparation", err, resumed.Outcome)
			}
			access, err := resumed.AccessToken.Reveal()
			if err != nil {
				t.Fatal("known resumed commit omitted ordinary access", err)
			}
			refresh, err := resumed.RefreshToken.Reveal()
			if err != nil {
				t.Fatal("known resumed commit omitted ordinary refresh", err)
			}
			if out, err := disabled.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: access}); err != nil || !out.Active {
				t.Fatal("resumed ordinary access was unusable", err)
			}
			if out, err := disabled.Token(h.f.ctx, humanExchangeRequest(h.client, h.basic, access)); err == nil || out.AccessToken != (oauth.Token{}) {
				t.Fatal("preserving original provenance re-enabled disabled delegation", err)
			}
			ordinary := h
			ordinary.service = disabled
			_, _ = rotateHumanRefresh(t, ordinary, refresh)
			var originalEffects, retainedWitnesses int
			if err := h.f.pool.Raw().QueryRow(h.f.ctx, `SELECT (SELECT count(*) FROM oauth_store.effects WHERE command_id=$1),(SELECT count(*) FROM oauth_store.artifacts WHERE issued_by=$1 AND payload ? 'HumanRefresh')`, string(lost.CommandID)).Scan(&originalEffects, &retainedWitnesses); err != nil || originalEffects != 1 || retainedWitnesses != 2 {
				t.Fatal("resume rewrote original preparation or duplicated ordinary rotation", err, originalEffects, retainedWitnesses)
			}
		})
	}
}
