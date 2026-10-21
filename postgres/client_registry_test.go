package oauthpostgres

import (
	"context"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

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
