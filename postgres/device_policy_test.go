package oauthpostgres

import (
	"strings"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestNativeDeviceConfigMustFitCompleteVerificationURI(t *testing.T) {
	issuer := "https://issuer.example"
	p := oauth.DevicePolicy{Enabled: true, TenantID: "tenant", VerificationURI: issuer + "/" + strings.Repeat("v", 120), TokenEndpoint: issuer + "/token", AuthorizationEndpoint: issuer + "/device_authorization", TTL: time.Minute, PollInterval: 5 * time.Second, VerificationURICompleteBytes: 128, LookupLimit: 32}
	if validDevicePolicy(p, issuer) {
		t.Fatal("native factory selected a profile incapable of bounded complete URI issuance")
	}
	p.VerificationURICompleteBytes = 512
	if !validDevicePolicy(p, issuer) {
		t.Fatal("native factory rejected bounded complete URI profile")
	}
}

func TestDevicePermissionChangesNativeClientAuthorityFingerprint(t *testing.T) {
	client := oauth.Client{ID: "screen", AuthenticationMethod: "none", Public: true, Version: 1, Resource: "https://resource.example", Redirects: []string{"https://screen.example/callback"}, Scopes: []string{"identity:read"}}
	before := clientFingerprint(client)
	client.DeviceAuthorization = true
	if clientFingerprint(client) == before {
		t.Fatal("native client authority fingerprint ignores explicit device grant permission")
	}
	client.DeviceAuthorization = false
	if clientFingerprint(client) != before {
		t.Fatal("absent device selection changed legacy authority fingerprint")
	}
}
