package oauthpostgres

import (
	"errors"
	"testing"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestManagedMetadataReplacementCannotChangeAnOIDCSource(t *testing.T) {
	store, execution, id := cursorReadFixture()
	store.config.Protocol.Resource = "https://api.example"
	client := oauth.Client{ID: id, Owner: execution.Request.Owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: store.config.Protocol.Resource, Redirects: store.config.Protocol.ManagedClients.Redirects, Scopes: []string{"openid"}}
	replacement := &clientReplacement{Redirects: client.Redirects, Scopes: []string{"identity:read"}}
	if out, err := store.updatedClient(client, replacement); !errors.Is(err, oauth.ErrAccessDenied) || out.ID != "" {
		t.Fatal("native replacement transformed an excluded original OIDC class", err)
	}
	client.Scopes = []string{"identity:read"}
	if out, err := store.updatedClient(client, replacement); err != nil || out.Version != client.Version+1 {
		t.Fatal("native OIDC exclusion broke existing OAuth replacement", err)
	}
}

func TestPublicOIDCMetadataReplacementUsesExplicitOriginalProfile(t *testing.T) {
	store, execution, id := cursorReadFixture()
	store.config.Protocol.Resource = "https://api.example"
	store.config.PublicClients = true
	policy := store.config.Protocol.ManagedClients
	policy.PublicClients, policy.PublicOIDC, policy.PublicOIDCUpdates = true, true, true
	client := oauth.Client{ID: id, Owner: execution.Request.Owner, Version: 1, Public: true, AuthenticationMethod: "none", Resource: store.config.Protocol.Resource, Redirects: policy.Redirects, Scopes: []string{"openid"}}
	replacement := &clientReplacement{Redirects: client.Redirects, Scopes: []string{"openid"}}
	selectedPolicy := store.managementPolicy()
	updated, err := store.updatedClient(client, replacement)
	if err != nil || updated.Version != 2 || !updated.Public || updated.AuthenticationMethod != "none" || updated.SubjectRegistration != nil || updated.Resource != client.Resource || updated.Owner != client.Owner {
		t.Fatal("selected native public OIDC replacement unavailable", err)
	}
	policy.PublicOIDCUpdates = false
	if store.managementPolicy() != selectedPolicy {
		t.Fatal("update-only selection stranded original policy fingerprints")
	}
	if out, err := store.updatedClient(client, replacement); !errors.Is(err, oauth.ErrAccessDenied) || out.ID != "" {
		t.Fatal("creation selection implicitly selected native replacement", err)
	}
}

func TestConfidentialOIDCMetadataReplacementPreservesOriginalClassAndPolicyIdentity(t *testing.T) {
	store, execution, id := cursorReadFixture()
	store.config.Protocol.Resource = "https://api.example"
	policy := store.config.Protocol.ManagedClients
	policy.ConfidentialOIDC = true
	originalPolicy := store.managementPolicy()
	policy.ConfidentialOIDCUpdates = true
	if store.managementPolicy() != originalPolicy {
		t.Fatal("update-only opt-in changed original management fingerprint")
	}
	client := oauth.Client{ID: id, Owner: execution.Request.Owner, Version: 4, AuthenticationMethod: "client_secret_basic", Resource: store.config.Protocol.Resource, Redirects: policy.Redirects, Scopes: []string{"openid"}}
	replacement := &clientReplacement{Redirects: client.Redirects, Scopes: []string{"openid"}}
	updated, err := store.updatedClient(client, replacement)
	if err != nil || updated.Version != 5 || updated.Public || updated.AuthenticationMethod != "client_secret_basic" || updated.SubjectRegistration != nil || updated.Owner != client.Owner || updated.Resource != client.Resource {
		t.Fatal("selected confidential native replacement changed original profile", err)
	}
	for _, variant := range []string{"public", "method", "pairwise", "device", "claims", "oauth-source", "oauth-target"} {
		t.Run(variant, func(t *testing.T) {
			current := client
			target := *replacement
			switch variant {
			case "public":
				current.Public, current.AuthenticationMethod = true, "none"
			case "method":
				current.AuthenticationMethod = "none"
			case "pairwise":
				registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
				current.SubjectRegistration = &registration
			case "device":
				current.DeviceAuthorization = true
			case "claims":
				current.Scopes = []string{"email", "openid"}
			case "oauth-source":
				current.Scopes = []string{"identity:read"}
			case "oauth-target":
				target.Scopes = []string{"identity:read"}
			}
			if out, err := store.updatedClient(current, &target); !errors.Is(err, oauth.ErrAccessDenied) || out.ID != "" {
				t.Fatal("native confidential replacement converted an unselected original/target class", err)
			}
		})
	}
	policy.ConfidentialOIDCUpdates = false
	if out, err := store.updatedClient(client, replacement); !errors.Is(err, oauth.ErrAccessDenied) || out.ID != "" {
		t.Fatal("creation-only policy admitted confidential replacement", err)
	}
}
