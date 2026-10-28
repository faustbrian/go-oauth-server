//go:build integration && oauthflow

package oauthpostgres_test

import (
	"errors"
	"strings"
	"testing"

	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
)

func clientReadRequest(f authenticatedPasswordFixture, limit uint16) oauth.ClientReadRequest {
	return oauth.ClientReadRequest{Owner: f.oauth.Protocol.ManagedClients.Owner, TenantID: f.tenant, Session: f.browser, Limit: limit}
}

func TestNativeClientReadOriginalSignupUnknownRecoveryDoesNotRepeatDelivery(t *testing.T) {
	fault := &oauthCommitFault{signup: true}
	f := passwordFixtureWithSignupRecovery(t, false, nil, true, fault)
	if !fault.hit.Load() || originalSignupEffectCounts(t, f.ctx, f.pool) != ([4]int{1, 1, 1, 1}) {
		t.Fatal("original unknown signup was resubmitted or duplicated its delivery")
	}
}

func TestNativeClientReadFreshInstanceDiscoversCurrentVersionsForExistingMutations(t *testing.T) {
	f := passwordFixtureWithSignupRecovery(t, false, nil, true)
	enableClientRotation(t, &f)
	seed, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if empty, err := seed.ClientList(f.ctx, clientReadRequest(f, 100)); err != nil || len(empty.Page.Items()) != 0 || empty.NextCursor.String() != "" {
		t.Fatal("empty managed registry exposed static clients", err)
	}
	// The later consumer retains no creation results, IDs or secret responses.
	for _, label := range []string{"read-seed-a", "read-seed-b", "read-seed-c"} {
		if _, err := seed.ClientCreate(f.ctx, clientCreateRequest(t, f, label)); err != nil {
			t.Fatal(err)
		}
	}
	func() {
		created, err := seed.ClientCreate(f.ctx, clientCreateRequest(t, f, "read-seed-deleted"))
		if err != nil {
			t.Fatal(err)
		}
		remove := clientRotationRequest(t, f, created.Client, "read-seed-delete", 0).Management
		if _, err := seed.ClientDelete(f.ctx, remove); err != nil {
			t.Fatal(err)
		}
	}()
	seed = nil
	fresh, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	var beforeCommands, beforeEffects, beforeEvents, beforeAudits int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.commands),(SELECT count(*) FROM oauth_store.effects),(SELECT count(*) FROM public.outbox_messages),(SELECT count(*) FROM audit.records)`).Scan(&beforeCommands, &beforeEffects, &beforeEvents, &beforeAudits); err != nil {
		t.Fatal(err)
	}
	r := clientReadRequest(f, 1)
	var discovered []oauth.Client
	for i := 0; i < 4; i++ {
		out, err := fresh.ClientList(f.ctx, r)
		if err != nil {
			t.Fatal("fresh manager cannot discover safe clients", err)
		}
		items := out.Page.Items()
		if len(items) != 1 {
			t.Fatal("list leaked static/deleted rows or missed bounded page")
		}
		discovered = append(discovered, items...)
		if out.NextCursor.String() == "" {
			break
		}
		r.Cursor = out.NextCursor
	}
	if len(discovered) != 3 {
		t.Fatal("pagination did not discover exactly active managed registrations")
	}
	for i, c := range discovered {
		if i > 0 && discovered[i-1].ID >= c.ID || c.Version != 1 || c.Public || c.Workload != nil || c.SubjectRegistration != nil || !strings.HasPrefix(c.ID, oauth.ManagedClientPrefix) {
			t.Fatal("unsafe or unordered managed projection")
		}
		get := clientReadRequest(f, 0)
		get.ClientID = c.ID
		out, err := fresh.ClientGet(f.ctx, get)
		if err != nil || out.Client.Version != c.Version || out.Client.Owner != c.Owner {
			t.Fatal("discovered private client get", err)
		}
		out.Client.Scopes[0] = "foreign"
		again, err := fresh.ClientGet(f.ctx, get)
		if err != nil || again.Client.Scopes[0] == "foreign" {
			t.Fatal("get projection mutated native authority", err)
		}
	}
	var afterCommands, afterEffects, afterEvents, afterAudits int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.commands),(SELECT count(*) FROM oauth_store.effects),(SELECT count(*) FROM public.outbox_messages),(SELECT count(*) FROM audit.records)`).Scan(&afterCommands, &afterEffects, &afterEvents, &afterAudits); err != nil || beforeCommands != afterCommands || beforeEffects != afterEffects || beforeEvents != afterEvents || beforeAudits != afterAudits {
		t.Fatal("safe discovery created durable mutation effects", err)
	}
	rotated, err := fresh.ClientRotateSecret(f.ctx, clientRotationRequest(t, f, discovered[0], "discovered-rotate", 0))
	if err != nil || rotated.Client.Version != 2 {
		t.Fatal("discovered current version could not rotate", err)
	}
	secret, err := rotated.Secret.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	issuedConfidentialTokens(t, f, fresh, rotated.Client, confidentialBasic(t, rotated.Client.ID, secret))
	get := clientReadRequest(f, 0)
	get.ClientID = discovered[0].ID
	current, err := fresh.ClientGet(f.ctx, get)
	if err != nil || current.Client.Version != 2 {
		t.Fatal("get retained stale pre-rotation version", err)
	}
	if _, err := fresh.ClientDelete(f.ctx, clientRotationRequest(t, f, discovered[0], "discovered-stale-delete", 0).Management); err == nil {
		t.Fatal("stale discovered version bypassed existing mutation fence")
	}
	if _, err := fresh.ClientDelete(f.ctx, clientRotationRequest(t, f, current.Client, "discovered-current-delete", 0).Management); err != nil {
		t.Fatal("freshly discovered current version could not delete", err)
	}
	if out, err := fresh.ClientGet(f.ctx, get); err == nil || out.Client.ID != "" {
		t.Fatal("deleted client leaked private metadata")
	}
	for _, mode := range []string{"owner", "tenant", "manager", "cursor-limit", "forged"} {
		bad := clientReadRequest(f, 1)
		first, err := fresh.ClientList(f.ctx, bad)
		if err != nil || first.NextCursor.String() == "" {
			t.Fatal("cursor control missing", err)
		}
		bad.Cursor = first.NextCursor
		switch mode {
		case "owner":
			bad.Owner, _ = oauth.NewPlatformOwner("foreign")
		case "tenant":
			bad.TenantID = "foreign"
		case "manager":
			bad.Session, _ = f.anotherUser()
		case "cursor-limit":
			bad.Limit = 2
		case "forged":
			wire := bad.Cursor.String()
			tail := "A"
			if strings.HasSuffix(wire, tail) {
				tail = "B"
			}
			bad.Cursor, _ = oauth.ParseCursor(wire[:len(wire)-1] + tail)
		}
		if out, err := fresh.ClientList(f.ctx, bad); err == nil || len(out.Page.Items()) != 0 || out.NextCursor.String() != "" {
			t.Fatal("unscoped cursor or owner disclosed page", mode)
		}
	}
	missing := clientReadRequest(f, 0)
	missing.ClientID = "managed.abcdefghijklmnopqrstuw"
	if out, err := fresh.ClientGet(f.ctx, missing); !errors.Is(err, oauth.ErrAccessDenied) || out.Client.ID != "" {
		t.Fatal("unknown managed metadata enumerated", err)
	}
}
