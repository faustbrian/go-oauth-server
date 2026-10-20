package oauthpostgres

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestSubjectRegistrationFingerprintSeparatesPoliciesAndPreservesLegacy(t *testing.T) {
	owner, _ := oauth.NewPlatformOwner("platform")
	c := oauth.Client{ID: "client", AuthenticationMethod: "none", Resource: "https://api.example", Owner: owner, Version: 1, Public: true, Redirects: []string{"https://client.example/cb"}, Scopes: []string{"openid"}}
	legacy, err := json.Marshal([]struct {
		ID, Method, Resource, Platform string
		Version                        uint64
		Public                         bool
		Redirects, Scopes              []string
	}{{c.ID, c.AuthenticationMethod, c.Resource, owner.PlatformID(), c.Version, c.Public, c.Redirects, c.Scopes}})
	if err != nil || clientFingerprint(c) != sha256.Sum256(legacy) {
		t.Fatal("nil subject policy changed original fingerprint framing", err)
	}
	first, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	second, _ := oauth.NewOIDCSubjectRegistration("pairwise", "other.example", "other-subjects", 2)
	c.SubjectRegistration = &first
	a := clientFingerprint(c)
	c.SubjectRegistration = &second
	if a == clientFingerprint(c) || a == sha256.Sum256(legacy) {
		t.Fatal("different registered sector/policy identities collided")
	}
}
