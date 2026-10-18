package oauthpostgres

import (
	"testing"
	"time"

	oauth "github.com/faustbrian/go-oauth-server"
)

func TestIntrospectionArtifactAndGrantExpiryAreExclusive(t *testing.T) {
	created := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	expires := created.Add(time.Minute)
	for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		a := artifactRecord{Kind: oauth.TokenAccess, State: "active", GrantState: "active", CreatedAt: created, ExpiresAt: expires, Grant: grantRecord{CreatedAt: created, ExpiresAt: expires}}
		if got := activeIntrospectionArtifact(a, expires.Add(offset)); got != (offset < 0) {
			t.Fatalf("expiry offset %s had active=%v", offset, got)
		}
	}
	a := artifactRecord{State: "active", GrantState: "active", CreatedAt: created, ExpiresAt: expires, Grant: grantRecord{CreatedAt: created, ExpiresAt: expires}}
	if activeIntrospectionArtifact(a, created.Add(-time.Nanosecond)) {
		t.Fatal("future token accepted")
	}
	for _, withdraw := range []func(*artifactRecord){func(a *artifactRecord) { a.State = "consumed" }, func(a *artifactRecord) { a.State = "revoked" }, func(a *artifactRecord) { a.GrantState = "revoked" }, func(a *artifactRecord) { a.ExpiresAt = a.Grant.ExpiresAt.Add(time.Second) }} {
		b := a
		withdraw(&b)
		if activeIntrospectionArtifact(b, created.Add(time.Second)) {
			t.Fatal("withdrawn or expanding artifact accepted")
		}
	}
}
