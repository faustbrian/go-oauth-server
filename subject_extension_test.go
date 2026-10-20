package oauthserver_test

import (
	"context"
	"errors"
	"testing"

	oauth "github.com/faustbrian/go-oauth-server"
)

// This extension tests core's trusted callback projection boundary only. The
// child/native integration consumer proves real HMAC and binding persistence.
type subjectExtension struct {
	oauth.OIDCExtension
	validate func(oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error)
}

func (subjectExtension) Scopes() oauth.ScopeCatalog {
	c, _ := oauth.NewOIDCScopeCatalog([]string{"openid"})
	return c
}
func (s subjectExtension) ValidateAuthorization(_ context.Context, in oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error) {
	return s.validate(in)
}

func TestAuthorizeConservesRegisteredSubjectCandidateAcrossExtensionBoundary(t *testing.T) {
	sessions, bearer, now, _ := coreSessionFixture(t)
	c := coreConfig(t, now)
	c.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid"})
	c.Clients[0].Scopes = append(c.Clients[0].Scopes, "openid")
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	c.Clients[0].SubjectRegistration = &registration
	candidate := oauth.OIDCSubjectCandidate{Registration: registration, Subject: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE", KeyVersion: 1, KeyCommitment: [32]byte{1}}
	seen := false
	store := authorizationStore{call: func(_ context.Context, command oauth.AuthorizationCommand) (oauth.AuthorizeResult, error) {
		if command.SubjectCandidate == nil || *command.SubjectCandidate != candidate {
			t.Fatal("extension candidate lost or replaced before native owner")
		}
		seen = true
		return oauth.AuthorizeResult{}, oauth.ErrAccessDenied
	}}
	extension := subjectExtension{validate: func(in oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error) {
		if in.Environment != c.Environment || in.Issuer != c.Issuer || in.Client.SubjectRegistration == nil || *in.Client.SubjectRegistration != registration {
			t.Fatal("extension lacks exact configured issuer/environment/client registration")
		}
		return oauth.OIDCAuthorizationProjection{Accepted: true, SubjectCandidate: &candidate}, nil
	}}
	service, err := oauth.NewService(c, oauth.Dependencies{Sessions: sessions, Store: store, OIDC: extension})
	if err != nil {
		t.Fatal(err)
	}
	request := coreAuthorization()
	request.Scopes = append(request.Scopes, "openid")
	_, err = service.Authorize(context.Background(), oauth.AuthorizeRequest{TenantID: "tenant", Session: bearer, Request: request, Network: "127.0.0.1"})
	if !seen || !errors.Is(err, oauth.ErrAccessDenied) {
		t.Fatal("registered subject candidate did not reach native boundary", err)
	}
}
