package oauthpostgres

import (
	"crypto/sha256"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

// These are the actual pre-selection canonical persisted registration bytes,
// not public JSON or a registration assertion. Retained grants/preparations use
// this digest across binary upgrades, so an omitted default must remain absent.
func TestHumanExchangeDefaultPreservesLegacyClientCommitments(t *testing.T) {
	owner, err := oauth.NewPlatformOwner("platform")
	if err != nil {
		t.Fatal(err)
	}
	client := oauth.Client{ID: "client", AuthenticationMethod: "client_secret_basic", Resource: "https://resource.example", Owner: owner, Version: 1, Redirects: []string{"https://client.example/cb"}, Scopes: []string{"identity:read"}}
	web := `[{"ID":"client","Method":"client_secret_basic","Resource":"https://resource.example","Platform":"platform","Version":1,"Public":false,"Redirects":["https://client.example/cb"],"Scopes":["identity:read"]}]`
	if clientFingerprint(client) != sha256.Sum256([]byte(web)) {
		t.Fatal("unselected confidential registration no longer authenticates its retained fingerprint")
	}
	client.Redirects = nil
	client.Workload, err = oauth.NewWorkload("tenant", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	machine := `[{"ID":"client","Method":"client_secret_basic","Resource":"https://resource.example","Platform":"platform","Version":1,"Public":false,"Redirects":null,"Scopes":["identity:read"],"Workload":{"Tenant":"tenant","ID":"worker","AccessTTL":60000000000}}]`
	if clientFingerprint(client) != sha256.Sum256([]byte(machine)) {
		t.Fatal("unselected workload registration no longer authenticates its retained fingerprint")
	}
}
