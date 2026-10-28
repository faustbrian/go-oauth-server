package oauthpostgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestManagedRegistrationPreservesPublicClassAndLegacyConfidentialEncoding(t *testing.T) {
	owner, _ := oauth.NewPlatformOwner("platform")
	client := oauth.Client{ID: "managed.abcdefghijklmnopqrstuw", Owner: owner, Version: 1, Public: true, AuthenticationMethod: "none", Resource: "https://api.example", Redirects: []string{"https://client.example/cb"}, Scopes: []string{"identity:read"}}
	wire, err := json.Marshal(registrationWire(client))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeRegistration(wire)
	if err != nil || !decoded.Public || decoded.AuthenticationMethod != "none" {
		t.Fatal("durable public metadata lost class", err)
	}
	client.Public, client.AuthenticationMethod = false, "client_secret_basic"
	wire, err = json.Marshal(registrationWire(client))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["Public"]; ok {
		t.Fatal("unchanged confidential registration bytes gained a field")
	}
	decoded, err = decodeRegistration(wire)
	if err != nil || decoded.Public || decoded.AuthenticationMethod != "client_secret_basic" {
		t.Fatal("legacy confidential class changed", err)
	}
}

func TestManagedPublicOIDCMetadataUsesSelectedRootScopeCeiling(t *testing.T) {
	owner, _ := oauth.NewPlatformOwner("platform")
	resourceScopes, _ := oauth.NewScopeCatalog([]string{"identity:read"})
	for _, variant := range []string{"selected", "default", "confidential", "extra-claim", "mixed-oauth", "device"} {
		t.Run(variant, func(t *testing.T) {
			policy := &oauth.ManagedClientPolicy{Owner: owner, TenantID: "tenant", Redirects: []string{"https://client.example/cb"}, Scopes: resourceScopes, PublicClients: true, PublicOIDC: variant != "default", DeviceAuthorization: true}
			client := oauth.Client{ID: "managed.abcdefghijklmnopqrstuw", Owner: owner, Version: 1, Public: true, AuthenticationMethod: "none", Resource: "https://api.example", Redirects: policy.Redirects, Scopes: []string{"openid"}}
			switch variant {
			case "confidential":
				client.Public, client.AuthenticationMethod = false, "client_secret_basic"
			case "extra-claim":
				client.Scopes = []string{"openid", "email"}
			case "mixed-oauth":
				client.Scopes = []string{"openid", "identity:read"}
			case "device":
				client.DeviceAuthorization = true
			}
			store := &Store{config: Config{PublicClients: true, Protocol: oauth.Config{Resource: client.Resource, ManagedClients: policy}}}
			wire, err := json.Marshal(registrationWire(client))
			if err != nil {
				t.Fatal(err)
			}
			restored, err := decodeRegistration(wire)
			if err != nil {
				t.Fatal(err)
			}
			if store.managedMetadata(restored) != (variant == "selected") {
				t.Fatal("durable metadata did not retain the exact selected managed OIDC class")
			}
		})
	}
}

func TestCurrentClientOwnsEveryStaticProjection(t *testing.T) {
	owner, _ := oauth.NewPlatformOwner("platform")
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	workload, _ := oauth.NewWorkload("tenant", "worker", time.Minute)
	for _, kind := range []string{"public", "pairwise", "workload"} {
		t.Run(kind, func(t *testing.T) {
			client := oauth.Client{ID: "client", Owner: owner, Version: 1, Public: true, AuthenticationMethod: "none", Resource: "https://api.example", Redirects: []string{"https://client.example/cb"}, Scopes: []string{"identity:read"}}
			switch kind {
			case "pairwise":
				client.Scopes = []string{"openid"}
				client.SubjectRegistration = &registration
			case "workload":
				client.Public = false
				client.AuthenticationMethod = "client_secret_basic"
				client.Redirects = nil
				client.Workload = workload
			}
			expectedScope := client.Scopes[0]
			store := &Store{config: Config{Protocol: oauth.Config{MaximumDuration: time.Second, Clients: []oauth.Client{client}}}}
			first, err := store.CurrentClient(context.Background(), client.ID)
			if err != nil {
				t.Fatal(err)
			}
			first.Scopes[0] = "expanded"
			if len(first.Redirects) > 0 {
				first.Redirects[0] = "https://foreign.example/cb"
			}
			if first.Workload != nil {
				*first.Workload = oauth.Workload{}
			}
			if first.SubjectRegistration != nil {
				*first.SubjectRegistration = oauth.OIDCSubjectRegistration{}
			}
			second, err := store.CurrentClient(context.Background(), client.ID)
			if err != nil {
				t.Fatal("caller corrupted subsequent native projection", err)
			}
			if second.Scopes[0] != expectedScope || len(second.Redirects) > 0 && second.Redirects[0] != "https://client.example/cb" || kind == "pairwise" && second.SubjectRegistration.SubjectType() != "pairwise" || kind == "workload" && second.Workload.ID() != "worker" {
				t.Fatal("caller changed retained static native authority")
			}
		})
	}
}
