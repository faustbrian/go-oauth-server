package oauthpostgres_test

import (
	"context"
	"errors"
	"math"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

func TestOrganizationAPIKeyHistoryPreservesEveryPublishedPrefix(t *testing.T) {
	ctx := context.Background()
	base := migrations.Source(oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000})
	for _, workload := range []bool{false, true} {
		prefix := base
		if workload {
			prefix = oauthpostgres.WorkloadMigrationSource{Base: prefix, Schema: "oauth_store", Version: 7100}
		}
		prefix = oauthpostgres.APIKeyExchangeMigrationSource{Base: prefix, Schema: "oauth_store", Version: 7200}
		before, err := prefix.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		source := oauthpostgres.OrganizationAPIKeyExchangeMigrationSource{Base: prefix, Schema: "oauth_store", Version: 7400}
		after, err := source.Load(ctx)
		if err != nil || len(after) != len(before)+4 {
			t.Fatal("organization extension lost the four-step forward allocation", err)
		}
		for i, step := range before {
			if step.Version() != after[i].Version() || step.Checksum() != after[i].Checksum() {
				t.Fatal("published USER/API-key/workload history changed")
			}
		}
		for i, step := range after[len(before):] {
			if step.Version() != 7400+migrations.Version(i) || step.TransactionMode() != migrations.TransactionModeDefault || step.DownSQL() != "" {
				t.Fatal("organization extension lost forward-only expand/validate sequencing")
			}
		}
		after[0] = after[len(after)-1]
		reloaded, err := source.Load(ctx)
		if err != nil || reloaded[0].Checksum() != before[0].Checksum() {
			t.Fatal("caller mutation changed retained migration history", err)
		}
	}
}

func TestOrganizationAPIKeyHistoryRejectsMissingPrefixAndPreservesFailures(t *testing.T) {
	base := oauthpostgres.APIKeyExchangeMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7200}
	for _, source := range []oauthpostgres.OrganizationAPIKeyExchangeMigrationSource{
		{Schema: "oauth_store", Version: 7400},
		{Base: base, Schema: "oauth_store"},
		{Base: base, Schema: "public", Version: 7400},
		{Base: base, Schema: "oauth_store", Version: 7206},
		{Base: base, Schema: "oauth_store", Version: migrations.Version(math.MaxInt64 - 2)},
		{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7400},
	} {
		if steps, err := source.Load(context.Background()); err == nil || steps != nil {
			t.Fatal("incomplete/reserved organization history accepted")
		}
	}
	source := oauthpostgres.OrganizationAPIKeyExchangeMigrationSource{Base: base, Schema: "oauth_store", Version: 7400}
	if _, err := source.Load(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("history cancellation hidden", err)
	}
	failure := errors.New("base unavailable")
	source.Base = deviceCompositionHistory{err: failure}
	if _, err := source.Load(context.Background()); !errors.Is(err, failure) {
		t.Fatal("base failure hidden", err)
	}
}
