package oauthserver_test

import (
	"context"
	"errors"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

type userInfoDeadlineStore struct {
	oauth.Store
	read func(context.Context, oauth.UserInfoCommand) (oauth.OIDCClaimsInput, error)
}

func (s userInfoDeadlineStore) UserInfo(ctx context.Context, c oauth.UserInfoCommand) (oauth.OIDCClaimsInput, error) {
	return s.read(ctx, c)
}

func TestUserInfoSourceCannotRenewOriginalNativeAuthorityDeadline(t *testing.T) {
	sessions, _, now, _ := coreSessionFixture(t)
	config := coreConfig(t, now)
	config.Clock = clockFunc(func() time.Time { return now })
	config.OIDCScopes, _ = oauth.NewOIDCScopeCatalog([]string{"openid", "email"})
	config.Clients[0].Scopes = append(config.Clients[0].Scopes, "openid", "email")
	deadline := now.Add(time.Second)
	store := userInfoDeadlineStore{read: func(context.Context, oauth.UserInfoCommand) (oauth.OIDCClaimsInput, error) {
		now = deadline
		return oauth.OIDCClaimsInput{Issuer: config.Issuer, ClientID: config.Clients[0].ID, TenantID: "tenant", UserID: "user", ExpectedSubject: "subject", Scopes: []string{"openid", "email"}, UserInfo: true, ExpiresAt: now.Add(time.Minute), AuthorityExpiresAt: deadline}, nil
	}}
	service, err := oauth.NewService(config, oauth.Dependencies{Sessions: sessions, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := oauth.NewToken()
	wire, _ := token.Reveal()
	if out, err := service.UserInfoSource(context.Background(), oauth.UserInfoRequest{ClientID: config.Clients[0].ID, AccessToken: wire}); !errors.Is(err, oauth.ErrAccessDenied) || out.UserID != "" || out.Identifiers != nil {
		t.Fatal("return boundary renewed original native deadline", err)
	}
}
