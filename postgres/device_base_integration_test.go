//go:build integration && oauthflow

package oauthpostgres_test

import (
	"testing"

	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

// This consumer imports only the base native module. The separate device test
// dependency is not runtime composition, schema installation or configuration.
func TestNativeBaseConstructsAndIssuesWithoutDeviceHistoryOrSelection(t *testing.T) {
	f := passwordFixture(t)
	service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal("base service required optional device composition", err)
	}
	if refresh := freshRefresh(t, f, service); len(refresh) != 43 {
		t.Fatal("ordinary base OAuth issuance required device history")
	}
	var absent bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT to_regclass('oauth_store.devices') IS NULL AND to_regclass('oauth_store.device_effects') IS NULL`).Scan(&absent); err != nil || !absent {
		t.Fatal("base bootstrap silently installed device authority", err)
	}
}
