package oauthserver

import (
	"encoding/json"
	"strings"
)

// ParseIntrospectionForm parses the explicitly selected RFC7662 owning-client
// profile. Exactly one bounded Basic header is separate from the inspected
// token. Body/URI client credentials are unsupported; transports reject URI
// credentials and bound the whole request. Duplicates/unknown fields deny.
// Unknown hints are ignored and recognized hints never constrain lookup
// (RFC7662 section2.1). Parsing authenticates neither caller nor inspected token.
func ParseIntrospectionForm(raw string, authorization []string) (IntrospectRequest, error) {
	values, err := parseFields(raw, []string{"token", "token_type_hint"})
	if err != nil || !visible(values.Get("token"), 2048) {
		return IntrospectRequest{}, ErrInvalidRequest
	}
	credential, err := ParseClientAuthentication(authorization)
	if err != nil || credential.Method() != "client_secret_basic" {
		return IntrospectRequest{}, ErrInvalidClient
	}
	r := IntrospectRequest{ClientID: credential.ClientID(), Token: values.Get("token"), ClientAuthentication: credential}
	switch values.Get("token_type_hint") {
	case "access_token":
		r.Hint = TokenAccess
	case "refresh_token":
		r.Hint = TokenRefresh
	}
	return r, nil
}

// MarshalJSON projects RFC7662's selected nonsecret metadata. Inactive results
// always encode only active=false, even if a caller supplied stray metadata.
// Active values should come only from Service.Introspect, not caller assertions.
// No bearer, client secret, grant ID or source-session custody is represented.
func (r IntrospectResult) MarshalJSON() ([]byte, error) {
	if !r.Active {
		return []byte(`{"active":false}`), nil
	}
	var expiry *int64
	if !r.ExpiresAt.IsZero() {
		v := r.ExpiresAt.Unix()
		expiry = &v
	}
	return json.Marshal(struct {
		Active   bool   `json:"active"`
		ClientID string `json:"client_id,omitempty"`
		Subject  string `json:"sub,omitempty"`
		Resource string `json:"aud,omitempty"`
		Issuer   string `json:"iss,omitempty"`
		Scopes   string `json:"scope,omitempty"`
		Expiry   *int64 `json:"exp,omitempty"`
	}{true, r.ClientID, r.Subject, r.Resource, r.Issuer.String(), strings.Join(r.Scopes, " "), expiry})
}
