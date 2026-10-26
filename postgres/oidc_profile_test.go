package oauthpostgres_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

func TestOIDCProfileConfigurationDoesNotExposePrivateSchemaDefaults(t *testing.T) {
	c := oauthpostgres.ProfileUserInfoConfig{AttributeSchemas: []identity.AttributeSchema{{ID: "private-schema", Version: 1, Fields: []identity.FieldPolicy{{Name: "private-field", Default: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "private-default-value"}}}}}}}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		wire := fmt.Sprintf(format, c)
		if strings.Contains(wire, "private-") || wire != "oauthpostgres.ProfileUserInfoConfig(redacted)" {
			t.Fatal("profile source configuration disclosed private defaults")
		}
	}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("profile source defaults implicitly serialized")
	}
	if _, err := c.MarshalText(); err == nil {
		t.Fatal("profile source defaults implicitly serialized to text")
	}
}
