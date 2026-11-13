package oauthpostgres_test

import (
	"context"
	"errors"
	"math"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

func TestAPIKeyExchangeHistoryPreservesInstalledPrefixAndConcurrentIndexBoundary(t *testing.T) {
	ctx := context.Background()
	base := oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}
	before, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	source := oauthpostgres.APIKeyExchangeMigrationSource{Base: base, Schema: "oauth_store", Version: 7200}
	after, err := source.Load(ctx)
	if err != nil || len(after) != len(before)+7 {
		t.Fatal("API-key history did not append the complete forward suffix", err)
	}
	for i, step := range before {
		if after[i].Version() != step.Version() || after[i].Checksum() != step.Checksum() {
			t.Fatal("existing installed history changed")
		}
	}
	for i, step := range after[len(before):] {
		mode := migrations.TransactionModeDefault
		if i == 2 {
			mode = migrations.TransactionModeNone
		}
		if step.Version() != 7200+migrations.Version(i) || step.DownSQL() != "" || step.TransactionMode() != mode {
			t.Fatal("forward schema lost its concurrent-index/attachment/validation allocation")
		}
	}
	after[0] = after[len(after)-1]
	reloaded, err := source.Load(ctx)
	if err != nil || reloaded[0].Checksum() != before[0].Checksum() {
		t.Fatal("caller mutation changed original history", err)
	}
}

func TestAPIKeyExchangeHistoryRejectsIncompleteAllocationAndPreservesFailures(t *testing.T) {
	base := oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}
	for _, source := range []oauthpostgres.APIKeyExchangeMigrationSource{
		{Schema: "oauth_store", Version: 7200},
		{Base: base, Schema: "oauth_store"},
		{Base: base, Schema: "public", Version: 7200},
		{Base: base, Schema: "oauth_store", Version: 7000},
		{Base: base, Schema: "oauth_store", Version: migrations.Version(math.MaxInt64 - 5)},
		{Base: deviceCompositionHistory{}, Schema: "oauth_store", Version: 7200},
	} {
		if steps, err := source.Load(context.Background()); err == nil || len(steps) != 0 {
			t.Fatal("invalid API-key history allocation was accepted")
		}
	}
	source := oauthpostgres.APIKeyExchangeMigrationSource{Base: base, Schema: "oauth_store", Version: 7200}
	if _, err := source.Load(nil); err == nil {
		t.Fatal("nil migration context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("migration cancellation was lost", err)
	}
	failure := errors.New("base unavailable")
	source.Base = deviceCompositionHistory{err: failure}
	if _, err := source.Load(context.Background()); !errors.Is(err, failure) {
		t.Fatal("base migration failure was hidden", err)
	}
}
