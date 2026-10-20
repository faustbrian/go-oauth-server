package oauthserver_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestOIDCSubjectRegistrationSerializationPreservesClosedIdentity(t *testing.T) {
	first, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	second, _ := oauth.NewOIDCSubjectRegistration("pairwise", "other.example", "subjects-next", 2)
	a, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(second)
	if err != nil || string(a) == string(b) {
		t.Fatal("different sector/policy identities collapsed during serialization", err)
	}
	var restored oauth.OIDCSubjectRegistration
	if json.Unmarshal(a, &restored) != nil || restored != first {
		t.Fatal("subject registration did not restore exact validated state")
	}
	for _, wire := range []string{`{}`, `null`, `{"Type":"pairwise","SectorHost":"client.example","PolicyID":"subjects","PolicyVersion":1,"unknown":true}`, `{"Type":"public","Type":"pairwise","SectorHost":"client.example","PolicyID":"subjects","PolicyVersion":1}`} {
		if json.Unmarshal([]byte(wire), &restored) == nil || restored != first {
			t.Fatal("malformed registration changed closed state")
		}
	}
}

func TestOIDCSubjectRegistrationIsIndependentAndOwned(t *testing.T) {
	registration, err := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
	if err != nil {
		t.Fatal(err)
	}
	client := coreConfig(t, time.Now()).Clients[0]
	client.SubjectRegistration = &registration
	owned, err := oauth.ValidateClient(client)
	if err != nil {
		t.Fatal("public authentication class cannot select pairwise subjects", err)
	}
	registration, err = oauth.NewOIDCSubjectRegistration("public", "", "other", 2)
	if err != nil {
		t.Fatal(err)
	}
	if owned.SubjectRegistration.SubjectType() != "pairwise" || owned.SubjectRegistration.SectorHost() != "client.example" || owned.SubjectRegistration.PolicyID() != "subjects" || owned.SubjectRegistration.PolicyVersion() != 1 {
		t.Fatal("caller mutation changed frozen subject registration")
	}
	confidential := owned
	confidential.Public, confidential.AuthenticationMethod = false, "client_secret_basic"
	if _, err := oauth.ValidateClient(confidential); err != nil {
		t.Fatal("confidential authentication class cannot select pairwise subjects", err)
	}
	for _, redirects := range [][]string{{"https://other.example/cb"}, {"https://client.example/cb", "https://other.example/cb"}} {
		invalid := owned
		invalid.Redirects = redirects
		if _, err := oauth.ValidateClient(invalid); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("foreign/multiple registered redirect hosts admitted", err)
		}
	}
	for _, args := range []struct {
		kind, sector, policy string
		version              uint64
	}{
		{"pairwise", "", "subjects", 1},
		{"pairwise", "https://client.example/sector.json", "subjects", 1},
		{"unknown", "client.example", "subjects", 1},
		{"pairwise", "client.example", "", 1},
		{"pairwise", "client.example", "subjects", 0},
	} {
		if _, err := oauth.NewOIDCSubjectRegistration(args.kind, args.sector, args.policy, args.version); !errors.Is(err, oauth.ErrInvalidRequest) {
			t.Fatal("invalid subject registration admitted", err)
		}
	}
}

func FuzzOIDCSubjectRegistrationClosedRestore(f *testing.F) {
	f.Add([]byte(`{"Type":"pairwise","SectorHost":"client.example","PolicyID":"subjects","PolicyVersion":1}`))
	f.Add([]byte(`{"Type":"pairwise","SectorHost":"sector.example","PolicyID":"subjects","PolicyVersion":1,"SectorIdentifierURI":"https://sector.example/sector.json","RedirectSet":"1111111111111111111111111111111111111111111111111111111111111111"}`))
	f.Add([]byte(`{"Type":"public","Type":"pairwise"}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, wire []byte) {
		original, _ := oauth.NewOIDCSubjectRegistration("pairwise", "client.example", "subjects", 1)
		restored := original
		err := json.Unmarshal(wire, &restored)
		if err != nil {
			if restored != original {
				t.Fatal("failed restore changed immutable policy")
			}
			return
		}
		validated, err := oauth.NewOIDCSubjectRegistration(restored.SubjectType(), restored.SectorHost(), restored.PolicyID(), restored.PolicyVersion())
		if restored.SectorIdentifierURI() == "" && (err != nil || validated != restored || len(wire) > 1024) {
			t.Fatal("closed restore admitted invalid/unbounded policy")
		}
		encoded, err := json.Marshal(restored)
		var again oauth.OIDCSubjectRegistration
		if err != nil || json.Unmarshal(encoded, &again) != nil || again != restored || len(wire) > 4096 {
			t.Fatal("stored URI policy lost closed identity or exceeded its bound")
		}
	})
}
