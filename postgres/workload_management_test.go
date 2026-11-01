package oauthpostgres

import (
	"encoding/json"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestManagedWorkloadRegistrationRetainsExactScalarBinding(t *testing.T) {
	owner, _ := oauth.NewPlatformOwner("platform")
	w, _ := oauth.NewWorkload("tenant", "worker", 30*time.Second)
	c := oauth.Client{ID: "managed.abcdefghijklmnopqrstuw", Owner: owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: "https://resource.example", Scopes: []string{"identity:read"}, Workload: w}
	original := registrationWire(c)
	other, _ := oauth.NewWorkload("tenant", "other", time.Minute)
	*w = *other
	wire, err := json.Marshal(original)
	if err != nil {
		t.Fatal("explicit scalar registration could not serialize", err)
	}
	decoded, err := decodeRegistration(wire)
	if err != nil || decoded.Workload == nil || decoded.Workload.TenantID() != "tenant" || decoded.Workload.ID() != "worker" || decoded.Workload.AccessTTL() != 30*time.Second {
		t.Fatal("durable managed registration lost original workload binding", err)
	}
	scopes, _ := oauth.NewScopeCatalog([]string{"identity:read", "identity:write"})
	selected, _ := oauth.NewWorkload("tenant", "worker", 30*time.Second)
	p := &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Scopes: scopes, Workloads: []*oauth.Workload{selected}}
	s := &Store{config: Config{Protocol: oauth.Config{Resource: c.Resource, ManagedClients: p}}}
	if !s.managedMetadata(decoded) {
		t.Fatal("selected restored machine metadata denied")
	}
	for _, bad := range []*oauth.Workload{w, nil} {
		changed := decoded
		changed.Workload = bad
		if s.managedMetadata(changed) {
			t.Fatal("restored metadata changed class or exact allowlist binding")
		}
	}
}

func TestManagedWorkloadAdditionPreservesOriginalWebRegistrationBytes(t *testing.T) {
	owner, _ := oauth.NewPlatformOwner("platform")
	c := oauth.Client{ID: "managed.abcdefghijklmnopqrstuw", Owner: owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: "https://resource.example", Redirects: []string{"https://client.example/cb"}, Scopes: []string{"identity:read"}}
	wire, err := json.Marshal(registrationWire(c))
	const original = `{"ID":"managed.abcdefghijklmnopqrstuw","Platform":"platform","Resource":"https://resource.example","AuthenticationMethod":"client_secret_basic","Version":1,"Redirects":["https://client.example/cb"],"Scopes":["identity:read"]}`
	if err != nil || string(wire) != original {
		t.Fatal("original omitted-workload registration bytes changed", err)
	}
}

func FuzzManagedWorkloadRegistration(f *testing.F) {
	f.Add([]byte(`{"ID":"managed.abcdefghijklmnopqrstuw","Platform":"platform","Resource":"https://resource.example","AuthenticationMethod":"client_secret_basic","Version":1,"Scopes":["identity:read"],"Workload":{"Tenant":"tenant","ID":"worker","AccessTTL":30000000000}}`))
	f.Add([]byte(`{"Workload":{"Tenant":"tenant","ID":"worker","AccessTTL":-1}}`))
	f.Add([]byte(`{"Workload":{"Tenant":[],"ID":null,"AccessTTL":1e100}}`))
	f.Fuzz(func(t *testing.T, wire []byte) {
		client, err := decodeRegistration(wire)
		if err != nil {
			return
		}
		canonical, err := json.Marshal(registrationWire(client))
		if err != nil {
			t.Fatal("validated scalar registration could not serialize", err)
		}
		restored, err := decodeRegistration(canonical)
		if err != nil || clientFingerprint(client) != clientFingerprint(restored) {
			t.Fatal("validated registration round trip changed policy", err)
		}
	})
}
