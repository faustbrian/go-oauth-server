package oauthpostgres

import (
	"errors"
	"slices"
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

func TestRetainedOIDCMetadataReplacementKeepsOriginalRegistration(t *testing.T) {
	store, execution, id := cursorReadFixture()
	store.config.Protocol.Resource = "https://api.example"
	p := store.config.Protocol.ManagedClients
	p.ConfidentialOIDC, p.ConfidentialOIDCUpdates = true, true
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	p.PairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
	retainedPolicy := store.managementPolicy()
	p.ConfidentialPairwiseUpdates = true
	client := oauth.Client{ID: id, Owner: execution.Request.Owner, Version: 1, Resource: store.config.Protocol.Resource, AuthenticationMethod: "client_secret_basic", SubjectRegistration: &registration, Redirects: p.Redirects, Scopes: []string{"openid"}}
	updated, err := store.updatedClient(client, &clientReplacement{Redirects: client.Redirects, Scopes: client.Scopes})
	if err != nil || updated.SubjectRegistration == nil || *updated.SubjectRegistration != registration || updated.Public || updated.AuthenticationMethod != client.AuthenticationMethod {
		t.Fatal("native pairwise replacement did not retain its original registration", err)
	}
	if out, err := store.updatedClient(client, &clientReplacement{Redirects: []string{"https://foreign.example/cb"}, Scopes: client.Scopes}); err == nil || out.ID != "" {
		t.Fatal("native replacement attached a foreign registered sector")
	}
	p.PublicClients, p.PublicOIDC, p.PublicOIDCUpdates = true, true, true
	store.config.PublicClients = true
	p.PublicOIDCScopes = []string{"openid", "email", "phone", "profile"}
	p.PublicOIDCClaimsUpdates = true
	client.Public, client.AuthenticationMethod, client.SubjectRegistration = true, "none", nil
	client.Scopes = []string{"email", "openid", "phone", "profile"}
	updated, err = store.updatedClient(client, &clientReplacement{Redirects: client.Redirects, Scopes: []string{"email", "openid"}})
	if err != nil || !updated.Public || updated.SubjectRegistration != nil || !slices.Equal(updated.Scopes, []string{"email", "openid"}) {
		t.Fatal("native public claims replacement escaped its selected scope ceiling", err)
	}
	if store.managementPolicy() != retainedPolicy {
		t.Fatal("new operation selections changed retained management preparation identity")
	}
}
