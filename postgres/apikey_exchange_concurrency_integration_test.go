//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestNativeAPIKeyExchangeConcurrentAccessRevocationPreservesKnownOutcomes(t *testing.T) {
	h := apiKeyExchangeFixture(t)
	_, keyWire := createAPIKeyExchangeSource(t, h, "m33-revoke-versus-child-source")
	request := oauth.TokenRequest{GrantType: oauth.TokenExchangeGrant, ClientID: h.client.ID, ClientAuthentication: h.basic, SubjectToken: keyWire, SubjectTokenType: oauth.APIKeyTokenType, Resource: h.client.Resource, Scopes: []string{"identity:read"}, Network: "192.0.2.10"}
	first, err := h.service.Token(h.f.ctx, request)
	request.SubjectToken, keyWire = "", ""
	if err != nil {
		t.Fatal("actual API-key root before concurrent revocation", err)
	}
	access, err := first.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	request.SubjectToken, request.SubjectTokenType = access, oauth.AccessTokenType
	// Establish the ordinary owning-client revocation contract before the race;
	// a setup/restore failure must not be mislabeled as a lock-order result.
	control, err := h.service.Token(h.f.ctx, request)
	if err != nil {
		t.Fatal("actual control child before revocation ordering", err)
	}
	controlAccess, err := control.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := h.service.Revoke(h.f.ctx, oauth.RevokeRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: controlAccess, Hint: oauth.TokenAccess, Network: "192.0.2.10"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("ordinary owning-client access revocation failed before lock ordering", err)
	}
	ctx, cancel := context.WithTimeout(h.f.ctx, h.f.oauth.Protocol.MaximumDuration)
	defer cancel()
	type issueResult struct {
		out oauth.TokenResult
		err error
	}
	type revokeResult struct {
		out oauth.RevokeResult
		err error
	}
	issued, revoked := make(chan issueResult, 1), make(chan revokeResult, 1)
	var calls sync.WaitGroup
	defer calls.Wait()
	// The real kernel takes its existing tenant advisory lock before aggregate
	// access. Race actual public calls; do not force an unreachable row-lock
	// interleaving by suspending a caller while it owns that earlier lock.
	start := make(chan struct{})
	calls.Go(func() { <-start; out, err := h.service.Token(ctx, request); issued <- issueResult{out, err} })
	calls.Go(func() {
		<-start
		out, err := h.service.Revoke(ctx, oauth.RevokeRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: access, Hint: oauth.TokenAccess, Network: "192.0.2.10"})
		revoked <- revokeResult{out, err}
	})
	close(start)
	issue, revoke := <-issued, <-revoked
	if revoke.err != nil || revoke.out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("owning access revocation lost a known commit in the issuance race", revoke.err)
	}
	if issue.err != nil && !errors.Is(issue.err, oauth.ErrInvalidGrant) && !errors.Is(issue.err, oauth.ErrAccessDenied) {
		t.Fatal("current-key issuance versus access revocation became unavailable or deadlocked", issue.err)
	}
	if issue.err == nil && issue.out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("race returned issuance without a known outcome")
	}
	if out, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: access}); err != nil || out.Active {
		t.Fatal("revoked actual parent remained active", err)
	}
	if issue.out.AccessToken != (oauth.Token{}) {
		child, err := issue.out.AccessToken.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		if out, err := h.service.Introspect(h.f.ctx, oauth.IntrospectRequest{ClientID: h.client.ID, ClientAuthentication: h.basic, Token: child}); err != nil || out.Active {
			t.Fatal("concurrent child bypassed its revoked actual OAuth parent", err)
		}
	}
}
