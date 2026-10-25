# Restricted human code-access exchange

This explicitly selected RFC 8693 profile permits a configured confidential
`client_secret_basic` web client to narrow its own genuine password-session/S256
authorization-code access token. It is separate from `WorkloadExchangePolicy`:
nil/false defaults preserve existing workload, registration and preparation
identities. It does not complete M33 or select public clients,
device/session/API-key/organization sources, JWT/cache profiles,
OIDC claims, HTTP routes or reference composition.

Set `Client.HumanCodeExchange=true` for each selected configured web client,
`Config.HumanCodeExchange=&HumanCodeExchangePolicy{MaximumDepth: 4,
ClockUncertainty: time.Second}`, and native `ConsentManagement=true` with a
distinct `HumanCodeExchangeClientNamespace`. Maximum depth defaults to four and
may only be lowered. Read budget plus declared clock uncertainty must fit ten
seconds. Operation selection is deliberately outside legacy client/configuration
commitments: enabling it does not invalidate previously issued code access or
rewrite its original source. Actual registration version, secret, status and
owner checks remain mandatory.

### Optional refresh-issued access sources

`HumanCodeExchangePolicy.AllowRefreshIssuedAccess=true` additionally admits
human opaque **access** tokens produced by native refresh rotation. The default
remains code-issued access only; refresh bearers are never exchange sources.
Enable the flag on every accepting instance before rotating eligible sources.
Existing consent and human-client bootstrap/history remain prerequisites; no
additional schema migration is required. Old writers do not preserve this
provenance, so mixed old/new writers are unsupported for the selected profile.

The first selected rotation must consume a refresh directly issued by genuine
S256 code redemption. It records fixed-size original consumed-code/root-refresh
issuance provenance. Every successor retains that exact provenance; arbitrary
preactivation refresh histories are not backfilled. Reauthorize such a client
instead. Bounded checks of the original code, initial refresh, immediate consumed
parent and native issuance effects prove the source without walking refresh
history. Consumed code/refresh expiry is historical issuance proof, not current
delegation authority. The active refreshed access and original current grant,
consent, account, credential and client remain the authority owners.

Delegation starts at that refreshed access, with at most four exchanges and the
same parent/five-minute expiry ceiling. A later refresh is not another exchange
depth and does not renew an existing child's lineage freshness or permissions.
Disabling the extra flag denies refreshed-root descendants, not ordinary native
refresh or code-root delegation.
Already prepared ordinary rotations retain and revalidate their original S256
metadata even when the extra flag or whole human exchange profile is disabled;
resuming them does not re-enable delegation or regenerate preparation.

The human namespace must differ from session, workload-principal and
workload-client namespaces. The shared public authorization owner keys only
tenant/namespace/subject, so namespace aliasing could turn one profile's explicit
bootstrap or withdrawal into another profile's authority.

## Adoption and withdrawal

During an exclusive schema window, append `HumanCodeExchangeMigrationSource`
after the complete installed OAuth history, including any selected workload,
consent-expiry and workload-exchange suffixes. Do not rewrite old migration bytes
or run unaware writers afterward. The suffix adds no authority to existing rows.
Prepare an actual existing code-issued access source (or an explicitly selected
refresh-issued access with native S256 provenance), then explicitly bootstrap:

```go
source := oauthserver.IntrospectRequest{
    ClientID: clientID,
    ClientAuthentication: basic,
    Token: codeIssuedOpaqueAccess,
}
if err := store.BootstrapHumanCodeExchangeClient(ctx, source); err != nil {
    return err
}
```

This trusted bootstrap operation derives tenant and immutable registration
version from actual native source/client owners. It uses the existing public
authorization owner to initialize a missing per-registration scope at epoch1.
An existing epoch1 is idempotent; an advanced epoch is withdrawn and never
reset. Exchange, introspection and resource verification never bootstrap.
Ambiguous bootstrap acknowledgement returns a redacted error; an explicit retry
re-observes the same authoritative row without token issuance.

Registration version and authority epoch are deliberately separate. The public
authorization baseline initializes only epoch1, so a domain-separated bounded
digest of actual client ID/version selects each registration's authority subject.
Canonical client ID/version remain explicit lineage fields. This permits a
version7 registration created before activation, without invented SQL or advancing epochs
in a loop. Consumers must not reproduce that internal derivation. Obtain the
actual owner record instead:

```go
current, err := store.HumanCodeExchangeClientAuthority(ctx, source)
if err != nil {
    return err
}
// In the existing authorized lifecycle transaction, with its required audit:
_, err = authority.AdvanceAuthority(
    ctx, tx, current.Scope, current.Version, maximumDuration,
)
```

The projection does not authorize mutation or supply a validity lease. Advancing
the real epoch withdraws new human exchange and all affected children, including
after preflight. Ordinary source OAuth access remains governed by its existing
grant. A newer actual registration selects its own scope; old registrations and
epochs are not revived. Missing, unavailable and advanced authority fail closed.

## Issuance, authority and recovery

Use the same closed RFC form as workload exchange: standard token-exchange grant,
one Basic header, issuer-owned opaque `subject_token`, access-token type, exactly
one configured `resource` or `audience`, and optional narrower OAuth `scope`.
Actors, arbitrary subjects/tenants, duplicate/conflicting fields, API-key/ID-token
types and alternate credential channels deny. Output is access-only with the
standard `issued_token_type`; no refresh or ID token is created.

The platform client-management owner stays distinct from human user/actor, source
tenant and authenticated calling client. Children retain the same grant, original
session/authentication commitment and consent generation. Scopes intersect the
actual source, original ceiling and current client policy. Expiry cannot exceed
the parent or five minutes; depth, cycles, missing/mismatched roots and corrupt
bindings deny.

The first access root retains its actual consumed authorization-code parent and
the code's continuation history. That consumed code proves genuine issuance; it
is not an active delegation ancestor and its expiry does not truncate access.
Delegation ancestry stops at that code-issued access root. Root/parent withdrawal,
consent deletion/narrowing, credential replacement, user blocking and original
authorization withdrawal deny descendants through primary owners and protected
coordinator locks. Refresh can advance the grant revision without invalidating
unchanged code-source authority; immutable artifact revisions remain separate.
Ordinary browser logout retains approved-grant semantics. Explicit selected
RP-initiated logout retains its stronger existing source-withdrawal behavior.

Every invocation reads real current owners with an original read-start-based
deadline of at most twenty seconds. Later genuine primary reads can establish a
separate current observation, but descendant copies, waits and retries preserve
the original lineage timestamps and credential expiry. There is no positive
cache, stale fallback or invalidation-event dependency. This is not JWT/cache
freshness qualification.

Sources remain reusable. A zero trusted `TokenRequest.CommandID` creates another
independent narrowed child; the original returned ID selects exact intent-bound
retry. Changing source, scopes or target selector does not reuse that intent.
`Store.Recover` uses the same original source, owning Basic credentials and command
ID. Replays, uncertain COMMIT and historical recovery never redeliver bearer
material or invent another usable child. Original expired preparation is
reconciliation-only, not a renewable issuance lease.

Disabling global or client selection denies new human exchange and child validity
while preserving ordinary roots. Migrations/tombstones remain installed. Full
API-key/organization delegation, HTTP/reference wiring, JWT/cache guarantees and
whole-unit/release qualification remain retained work.

Source: [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html), January 2020,
sections 2.1, 2.2 and 3. Four exchanges, five minutes and the 20/30-second bounds
are local shared-issuer profile policy, not RFC-mandated limits.
