package oauthpostgres_test

import (
	"context"
	"errors"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

type deviceCompositionHistory struct {
	steps []migrations.Migration
	err   error
}

func (s deviceCompositionHistory) Load(context.Context) ([]migrations.Migration, error) {
	return s.steps, s.err
}

func deviceCompositionBase() migrations.Source {
	base := oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}
	consent := oauthpostgres.ConsentMigrationSource{Base: base, Schema: "oauth_store", Version: 7002}
	workload := oauthpostgres.WorkloadMigrationSource{Base: consent, Schema: "oauth_store", Version: 7010}
	signing := oauthpostgres.SigningMigrationSource{Base: workload, Schema: "oauth_store", Version: 7011}
	expiry := oauthpostgres.ConsentExpiryMigrationSource{Base: signing, Schema: "oauth_store", Version: 7012}
	return oauthpostgres.WorkloadExchangeMigrationSource{Base: expiry, Schema: "oauth_store", Version: 7013}
}

func TestDeviceCompositionHistoryRetainsOriginalChecksumsAndIsForwardOnly(t *testing.T) {
	ctx := context.Background()
	base := deviceCompositionBase()
	before, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	source := oauthpostgres.DeviceCompositionMigrationSource{Base: base, Schema: "oauth_store", Version: 7020}
	history, err := source.Load(ctx)
	if err != nil || len(history) != len(before)+2 {
		t.Fatal("complete selected history did not append two owned steps", err)
	}
	for i, prior := range before {
		if history[i].Checksum() != prior.Checksum() || history[i].Version() != prior.Version() {
			t.Fatal("installed prefix identity changed")
		}
	}
	for i, suffix := range history[len(before):] {
		if suffix.Version() != 7020+migrations.Version(i) || suffix.DownSQL() != "" || suffix.TransactionMode() != migrations.TransactionModeDefault {
			t.Fatal("device suffix lost permanent version, transaction or irreversible custody")
		}
	}
	history[0] = history[len(history)-1]
	reloaded, err := source.Load(ctx)
	if err != nil || reloaded[0].Checksum() != before[0].Checksum() {
		t.Fatal("caller mutation changed original source history", err)
	}
	legacy, err := (oauthpostgres.DeviceMigrationSource{Base: oauthpostgres.MigrationSource{Schema: "oauth_store", Version: 7000}, Schema: "oauth_store", Version: 7020}).Load(ctx)
	if err != nil || legacy[len(legacy)-1].Checksum().String() != "sha256:c5359cfaf8874108243939388fdc546d189c741affadd439510f98e1089e773c" {
		t.Fatal("published original device migration checksum changed", err)
	}
}

func TestDeviceCompositionRejectsUnknownModifiedAndReorderedHistory(t *testing.T) {
	ctx := context.Background()
	base, err := deviceCompositionBase().Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	modified := append([]migrations.Migration(nil), base...)
	modified[2], err = migrations.NewMigration(base[2].Version(), base[2].Name(), migrations.TransactionModeDefault, base[2].UpSQL()+"\n", "")
	if err != nil {
		t.Fatal(err)
	}
	reordered := append([]migrations.Migration(nil), base...)
	reordered[1], reordered[2] = reordered[2], reordered[1]
	for _, tc := range []struct {
		name   string
		source oauthpostgres.DeviceCompositionMigrationSource
	}{
		{"empty", oauthpostgres.DeviceCompositionMigrationSource{Base: deviceCompositionHistory{}, Schema: "oauth_store", Version: 7020}},
		{"missing-exchange", oauthpostgres.DeviceCompositionMigrationSource{Base: deviceCompositionHistory{steps: base[:5]}, Schema: "oauth_store", Version: 7020}},
		{"unknown-extra", oauthpostgres.DeviceCompositionMigrationSource{Base: deviceCompositionHistory{steps: append(append([]migrations.Migration(nil), base...), base[5])}, Schema: "oauth_store", Version: 7020}},
		{"modified", oauthpostgres.DeviceCompositionMigrationSource{Base: deviceCompositionHistory{steps: modified}, Schema: "oauth_store", Version: 7020}},
		{"reordered", oauthpostgres.DeviceCompositionMigrationSource{Base: deviceCompositionHistory{steps: reordered}, Schema: "oauth_store", Version: 7020}},
		{"foreign-schema", oauthpostgres.DeviceCompositionMigrationSource{Base: deviceCompositionBase(), Schema: "other_store", Version: 7020}},
		{"conflicting-version", oauthpostgres.DeviceCompositionMigrationSource{Base: deviceCompositionBase(), Schema: "oauth_store", Version: 7013}},
		{"second-version-overflow", oauthpostgres.DeviceCompositionMigrationSource{Base: deviceCompositionBase(), Schema: "oauth_store", Version: migrations.Version(math.MaxInt64)}},
		{"zero-version", oauthpostgres.DeviceCompositionMigrationSource{Base: deviceCompositionBase(), Schema: "oauth_store"}},
		{"invalid-schema", oauthpostgres.DeviceCompositionMigrationSource{Base: deviceCompositionBase(), Schema: "public", Version: 7020}},
		{"nil-base", oauthpostgres.DeviceCompositionMigrationSource{Schema: "oauth_store", Version: 7020}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var invalid identity.InvalidInputError
			if steps, err := tc.source.Load(ctx); !errors.As(err, &invalid) || len(steps) != 0 {
				t.Fatal("unsupported history was implicitly adopted", err)
			}
		})
	}
}

func TestDeviceCompositionPreservesCancellationAndBaseFailure(t *testing.T) {
	source := oauthpostgres.DeviceCompositionMigrationSource{Base: deviceCompositionBase(), Schema: "oauth_store", Version: 7020}
	if _, err := source.Load(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	failed := errors.New("source unavailable")
	source.Base = deviceCompositionHistory{err: failed}
	if _, err := source.Load(context.Background()); !errors.Is(err, failed) {
		t.Fatal("base failure concealed", err)
	}
}
