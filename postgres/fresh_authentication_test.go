package oauthpostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
)

// Only callback projection ownership is isolated here; authenticated source and
// protected mutation authority are exercised by the genuine native consumers.
func TestAuthenticationPolicyOwnsCallbackClientAndRequest(t *testing.T) {
	owner, err := oauth.NewPlatformOwner("platform")
	if err != nil {
		t.Fatal(err)
	}
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	client := oauth.Client{ID: "client", Owner: owner, Version: 1, AuthenticationMethod: "none", Public: true, Redirects: []string{"https://client.example/cb"}, Resource: "https://api.example", Scopes: []string{"openid"}, SubjectRegistration: &registration}
	store := &Store{config: Config{Protocol: oauth.Config{Clients: []oauth.Client{client}}}}
	age := uint32(0)
	request := oauth.AuthorizationRequest{ClientID: client.ID, MaxAge: &age, Scopes: []string{"openid"}}
	_, err = store.authenticationPolicy(context.Background(), func(_ context.Context, in oauth.OIDCAuthorizationInput) (oauth.OIDCAuthorizationProjection, error) {
		in.Client.Redirects[0] = "https://foreign.example/cb"
		in.Client.Scopes[0] = "profile"
		*in.Client.SubjectRegistration = oauth.OIDCSubjectRegistration{}
		*in.Request.MaxAge = 300
		in.Request.Scopes[0] = "profile"
		return oauth.OIDCAuthorizationProjection{Accepted: true, Authentication: oauth.OIDCAuthenticationFresh}, nil
	}, client, request, session.GetResult{}, nil)
	retained := store.config.Protocol.Clients[0]
	if err != nil || retained.Redirects[0] != "https://client.example/cb" || retained.Scopes[0] != "openid" || retained.SubjectRegistration.SubjectType() != "pairwise" || age != 0 || request.Scopes[0] != "openid" {
		t.Fatal("borrowed child callback changed retained native client/request configuration", err)
	}
}
