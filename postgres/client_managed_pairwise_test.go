package oauthpostgres

import (
	"context"
	"encoding/json"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestManagedPairwiseRegistrationMutationOwnsNoGrantSubject(t *testing.T) {
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	client := oauth.Client{SubjectRegistration: &registration}
	p := &phase{client: client, input: phaseInput{ClientChange: &clientMutation{Client: client}, Grant: grantRecord{Scopes: []string{"openid"}}}}
	if err := p.checkSubjectBinding(context.Background(), kernel.Work{}, false); err != nil {
		t.Fatal("registration lifecycle incorrectly requires an issued grant's subject binding", err)
	}
}

func TestManagedPairwiseRegistrationRetainsPolicyAndOriginalDefaultBytes(t *testing.T) {
	owner, _ := oauth.NewPlatformOwner("platform")
	client := oauth.Client{ID: "managed.abcdefghijklmnopqrstuw", Owner: owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: "https://api.example", Redirects: []string{"https://client.example/cb"}, Scopes: []string{"openid"}}
	before, err := json.Marshal(registrationWire(client))
	const original = `{"ID":"managed.abcdefghijklmnopqrstuw","Platform":"platform","Resource":"https://api.example","AuthenticationMethod":"client_secret_basic","Version":1,"Redirects":["https://client.example/cb"],"Scopes":["openid"]}`
	if err != nil || string(before) != original {
		t.Fatal("default-subject registration changed its original canonical bytes", err)
	}
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	client.SubjectRegistration = &registration
	wire, err := json.Marshal(registrationWire(client))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodeRegistration(wire)
	if err != nil || restored.SubjectRegistration == nil || *restored.SubjectRegistration != registration || restored.Public || restored.AuthenticationMethod != "client_secret_basic" {
		t.Fatal("managed registration discarded exact pairwise policy", err)
	}
	foreign, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "foreign", 1)
	registration = foreign
	if restored.SubjectRegistration.PolicyID() != "subjects" {
		t.Fatal("restored registration aliases mutable input")
	}
	restored.SubjectRegistration = nil
	after, err := json.Marshal(registrationWire(restored))
	if err != nil || string(after) != original {
		t.Fatal("nil registration no longer restores the exact original wire", err)
	}
}

func TestManagedPairwiseIntentBindsSelectionWithoutResettingDefaults(t *testing.T) {
	store, _, _ := cursorReadFixture()
	policy := store.config.Protocol.ManagedClients
	policy.ConfidentialOIDC = true
	request := oauth.ClientManagementRequest{Owner: policy.Owner, TenantID: policy.TenantID, Redirects: policy.Redirects, Scopes: []string{"openid"}, Origin: "https://issuer.example", Network: "192.0.2.1"}
	p := &phase{store: store, input: phaseInput{Transition: createManagedClient, ClientChange: &clientMutation{}}}
	original, err := p.clientIntent(request)
	if err != nil {
		t.Fatal(err)
	}
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	policy.PairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
	retained, err := p.clientIntent(request)
	a, _ := original.Fields()
	b, _ := retained.Fields()
	if err != nil || !sameJSON(a, b) {
		t.Fatal("pairwise activation rewrote an original default-subject intent", err)
	}
	request.SubjectRegistration = &registration
	selected, err := p.clientIntent(request)
	b, _ = selected.Fields()
	if err != nil || sameJSON(a, b) {
		t.Fatal("pairwise request reused the default-subject management intent", err)
	}
	foreign, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 2)
	request.SubjectRegistration = &foreign
	changed, err := p.clientIntent(request)
	a, _ = selected.Fields()
	b, _ = changed.Fields()
	if err != nil || sameJSON(a, b) {
		t.Fatal("a different pairwise registration reused the original intent", err)
	}
}

func TestManagedPairwiseTrustedPolicyOwnsMetadataAndKeySelection(t *testing.T) {
	store, _, id := cursorReadFixture()
	store.config.Protocol.Resource = "https://api.example"
	policy := store.config.Protocol.ManagedClients
	policy.ConfidentialOIDC = true
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	policy.PairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
	client := oauth.Client{ID: id, Owner: policy.Owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: store.config.Protocol.Resource, Redirects: policy.Redirects, Scopes: []string{"openid"}, SubjectRegistration: &registration}
	if !store.managedMetadata(client) {
		t.Fatal("trusted managed-only pairwise registration is not readable")
	}
	if !store.subjectPolicySelected("subjects", 1) {
		t.Fatal("actual trusted management policy cannot install its subject key")
	}
	for _, changed := range []oauth.OIDCSubjectRegistration{
		func() oauth.OIDCSubjectRegistration {
			r, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "foreign", 1)
			return r
		}(),
		func() oauth.OIDCSubjectRegistration {
			r, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 2)
			return r
		}(),
		func() oauth.OIDCSubjectRegistration {
			r, _ := oauth.NewOIDCSubjectRegistration("pairwise", "foreign.example", "subjects", 1)
			return r
		}(),
	} {
		client.SubjectRegistration = &changed
		if store.managedMetadata(client) {
			t.Fatal("foreign sector or policy crossed the trusted registration ceiling")
		}
	}
	if store.subjectPolicySelected("foreign", 1) || store.subjectPolicySelected("subjects", 2) {
		t.Fatal("unselected subject policy acquired native key custody")
	}
	policy.PairwiseRegistrations = nil
	client.SubjectRegistration = &registration
	if store.managedMetadata(client) || store.subjectPolicySelected("subjects", 1) {
		t.Fatal("withdrawn management selection retained metadata or key authority")
	}
}

func TestManagedPublicPairwiseTrustedPolicyOwnsMetadataAndKeySelection(t *testing.T) {
	store, _, id := cursorReadFixture()
	store.config.Protocol.Resource = "https://api.example"
	store.config.PublicClients = true
	policy := store.config.Protocol.ManagedClients
	policy.PublicClients, policy.PublicOIDC = true, true
	registration, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	policy.PublicPairwiseRegistrations = []oauth.OIDCSubjectRegistration{registration}
	client := oauth.Client{ID: id, Owner: policy.Owner, Public: true, Version: 1, AuthenticationMethod: "none", Resource: store.config.Protocol.Resource, Redirects: policy.Redirects, Scopes: []string{"openid"}, SubjectRegistration: &registration}
	if !store.managedMetadata(client) {
		t.Fatal("trusted public-only pairwise registration is not readable")
	}
	if !store.subjectPolicySelected("subjects", 1) {
		t.Fatal("actual public-only management policy cannot install its subject key")
	}
	if policy.ConfidentialOIDC || len(policy.PairwiseRegistrations) != 0 {
		t.Fatal("public key selection borrowed confidential authority")
	}
	if store.subjectPolicySelected("foreign", 1) || store.subjectPolicySelected("subjects", 2) {
		t.Fatal("unselected public subject policy acquired native key custody")
	}
	policy.PublicPairwiseRegistrations = nil
	if store.managedMetadata(client) || store.subjectPolicySelected("subjects", 1) {
		t.Fatal("withdrawn public-only selection retained metadata or key authority")
	}
}
