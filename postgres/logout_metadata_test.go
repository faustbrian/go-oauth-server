package oauthpostgres

import (
	"encoding/json"
	"strings"
	"testing"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestLogoutMetadataSurvivesNativeRegistrationAndIndependentCeiling(t *testing.T) {
	owner, _ := oauth.NewPlatformOwner("platform")
	scopes, _ := oauth.NewScopeCatalog([]string{"identity:read"})
	policy := &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, PostLogoutRedirects: []string{"https://client.example/out"}, Scopes: scopes}
	s := &Store{config: Config{Protocol: oauth.Config{ManagedClients: policy, Resource: "https://api.example"}}}
	c := oauth.Client{ID: "managed.client", Owner: owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: s.config.Protocol.Resource, Redirects: policy.Redirects, PostLogoutRedirects: policy.PostLogoutRedirects, Scopes: scopes.Scopes()}
	wire, err := json.Marshal(registrationWire(c))
	if err != nil {
		t.Fatal(err)
	}
	retained, err := decodeRegistration(wire)
	if err != nil || !oauth.PostLogoutRedirectAllowed(retained, "https://client.example/out") || !s.managedMetadata(retained) {
		t.Fatal("native registration lost independent logout policy", err)
	}
	before := clientFingerprint(c)
	retained.PostLogoutRedirects = []string{"https://client.example/cb"}
	if s.managedMetadata(retained) || clientFingerprint(retained) == before {
		t.Fatal("native policy admits auth redirect as logout or omits logout metadata from authority")
	}
	replacement := &clientReplacement{Redirects: policy.Redirects, Scopes: scopes.Scopes(), PostLogoutRedirects: policy.PostLogoutRedirects}
	updated, err := s.updatedClient(c, replacement)
	if err != nil || updated.Version != c.Version+1 || !oauth.PostLogoutRedirectAllowed(updated, "https://client.example/out") {
		t.Fatal("native update lost selected logout metadata", err)
	}
	replacement.PostLogoutRedirects = nil
	cleared, err := s.updatedClient(updated, replacement)
	if err != nil || len(cleared.PostLogoutRedirects) != 0 {
		t.Fatal("complete replacement retained withdrawn logout targets", err)
	}
	// Omitting optional metadata conserves the original published registration
	// bytes/fingerprint; no synthetic logout registration is backfilled.
	c.PostLogoutRedirects = nil
	legacyWire, _ := json.Marshal(registrationWire(c))
	if strings.Contains(string(legacyWire), "PostLogoutRedirects") {
		t.Fatal("legacy registration encoding changed")
	}
	legacy, err := decodeRegistration(legacyWire)
	if err != nil || len(legacy.PostLogoutRedirects) != 0 {
		t.Fatal("legacy decoding invented logout targets", err)
	}
}
