package oauthserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
)

func TestProfileCustodyRemainsRedactedAndCannotRenewNativeDeadline(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	config := coreConfig(t, now)
	config.Clock = clockFunc(func() time.Time { return now })
	config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "profile"})
	config.Clients[0].Scopes = append(config.Clients[0].Scopes, "openid", "profile")
	deadline := now.Add(time.Second)
	profile := &identity.ProfileRecord{Profile: identity.UserProfile{Name: "private-display-name"}}
	input := oauth.OIDCClaimsInput{Profile: profile}
	if strings.Contains(fmt.Sprintf("%#v", input), "private-display-name") {
		t.Fatal("profile custody leaked through diagnostics")
	}
	if _, err := json.Marshal(input); err == nil {
		t.Fatal("profile custody implicitly serialized")
	}
	store := userInfoDeadlineStore{read: func(context.Context, oauth.UserInfoCommand) (oauth.OIDCClaimsInput, error) {
		now = deadline
		return oauth.OIDCClaimsInput{Issuer: config.Issuer, ClientID: config.Clients[0].ID, TenantID: "tenant", UserID: "user", ExpectedSubject: "subject", Scopes: []string{"openid", "profile"}, UserInfo: true, ExpiresAt: now.Add(time.Minute), AuthorityExpiresAt: deadline, Profile: profile}, nil
	}}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := oauth.NewToken()
	wire, _ := token.Reveal()
	if out, err := service.UserInfoSource(context.Background(), oauth.UserInfoRequest{ClientID: config.Clients[0].ID, AccessToken: wire}); !errors.Is(err, oauth.ErrAccessDenied) || out.Profile != nil || out.UserID != "" {
		t.Fatal("expired native profile custody returned partial state", err)
	}
}
