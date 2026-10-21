# Native OAuth PostgreSQL adapter

Experimental persistence and public service composition for the
[selected authorization-code profile](../docs/selected-profile.md).

## Optional platform-owned confidential client management

Select `Config.Protocol.ManagedClients` with one exact platform owner, tenant,
redirect allowlist and OAuth-only scope ceiling, plus installed/selected consent
management and existing native prepared request keys. Append
`ClientMigrationSource` after the installed consent history at a new version.
Install while issuance is stopped and replace every accepting old instance
before activation; never rewrite an installed migration. The `managed.` prefix
is exclusive and static collisions deny construction. Constructors do no IO.
The existing selected OAuth discovery advertises this human-web/Basic capability
without requiring a static confidential client. Existing configured workload
clients may coexist; their separate migration and authority requirements remain.

`ClientCreate/Delete` authenticate genuine original current password-session
custody, its nonrenewing sensitive-proof/read deadline, exact origin/CSRF and
the configured application policy on resource `oauth.platform` with the exact
platform-owner ID. Owner configuration is not a manager credential. The policy
decision runs outside protected SQL locks. Its revision is immutable configured
policy; permission changes must advance the existing actor authorization epoch
in `Session.Profile.PolicyNamespace`. The original sealed actor epoch, directory,
credential, session and synchronizer are fenced through their actual owners in
the sole coordinator Work. Changing an unversioned callback is not an atomic
permission-revocation mechanism.

Creation allocates one server-random reserved ID/version1 and random 32-byte
Basic secret. Only its digest persists in the client registry; secret custody
in existing encrypted preparation is never redelivered by retry or recovery.
Delete requires the exact current client/version and advances it to a terminal
tombstone. Registrations cannot edit owner or reactivate; redirect/scope
replacement requires the separately selected metadata-update profile below.
Warm services and direct native readers repeatedly resolve current
registry status. Mutating protocol paths take the client SHARE fence before
grant/consent locks; deletion takes UPDATE, avoiding unbounded artifact fanout.
Lifecycle topics are exactly `oauth_client.created.v1` and
`oauth_client.revoked.v1`, as required by the binding lifecycle catalog.

`Recover` accepts the original current manager session/tenant and exact managed
client ID for `identity.oauth-server.client-create/client-delete`. For an unknown
create, its ID is `ManagedClientPrefix + string(CommandID)`. Retained native
request preparation authenticates original identity/input; the existing journal
alone determines durability. Pending/Unknown is not rollback, and terminal
NotCommitted can retain its original classified error. No recovery returns
secret material, tokens, or new management permission. Retain original policy,
keys and history while recovery remains supported. This profile is not dynamic
registration transport, user/org ownership, workload or OIDC
client management, nor complete M30 support.

### Authenticated safe metadata discovery

The same selected managed-client profile supplies optional `ClientReader` via
`Service.ClientGet/List`. No new migration or endpoint is installed. A fresh
service can list active managed IDs/versions, get one safe registration, then
submit the discovered current version to the existing rotation/deletion APIs.
Those mutations still require their original fresh password proof, CSRF and
request-key authority; a read result grants none of them.

Each private read independently authenticates the borrowed native session and
exact `identity.oauth-server.client-get` or `client-list` platform permission.
It compares the original sealed session/actor/tenant, repeats current policy,
owner and client-version/status checks, and preserves the original exclusive
<=20s app/primary-read deadline without renewal. Reads require a current verified
password session, but not the mutation-only 15-minute freshness or CSRF fields.
Policy callbacks run without SQL locks. Permission withdrawal must still advance
the existing actor epoch, as for management above.

List requires limit1..100 and returns stable ID-ordered keyset pages. A cursor
binds tenant, immutable owner, authenticated actor, limit and configured policy;
it is neither authorization nor an enduring multi-page snapshot. Deleted/static
clients are excluded. Only safe registration metadata is selected: no current or
predecessor secret digest, encrypted preparation or bearer custody. Projections
own their collections. Late rotation/deletion/permission changes, cancellation
and unavailable authority return no partial page or cursor; retries recheck
current authority. Reads do not create commands, audit, outbox or lifecycle
effects and do not use a positive cache.

### Optional bounded secret rotation

Append `ClientRotationMigrationSource{Base: installedClientHistory, Schema: ...,
Version: nextVersion}` without rewriting prior bytes. Stop serving, install the
forward history, replace every old accepting instance, then set
`Config.ClientSecretRotation=true`. Managed clients/consent management are
prerequisites. Constructors do not install or inspect schema.

`ClientRotateSecret` requires the exact current client/version, original fresh
password-session/manager policy, origin/CSRF and native request key. `Overlap`
is explicit 0..24h at microsecond precision. The registry retains only digest
verification and at most one predecessor. The successor is immediately valid;
the predecessor expires exclusively at the original stored timestamp. Zero
overlap withdraws it immediately; a second rotation drops any older predecessor.
Deletion withdraws both. No positive authentication cache or outage fallback
exists. All Basic consumers retain the original matched slot and earliest
<=20s read/predecessor deadline through SQL waits and final delivery fences.

Every rotation advances actual client authority. **All pre-rotation grants,
codes, access/refresh tokens and consent are invalid, including during overlap.**
The application must request and explicitly approve a new authorization at the
new version; old Basic can only authenticate those new-version grants while its
overlap remains live. A resource verifier's trusted selected client version must
likewise be advanced explicitly; it never retargets itself.

`identity.oauth-server.client-rotate-secret` uses original encrypted request-key
preparation and the same sole Work, required audit and outbox owners. Its event
is `oauth_client.secret_rotated.v1`. Only the fresh known-committed invocation
reveals the successor; keyed retries, unknown COMMIT and metadata-only `Recover`
never disclose it or repeat the version change. Recover uses the original
CommandID/ClientID/TenantID/current original manager Session, without Token or
client authentication, including after deletion.

### Optional complete managed metadata replacement

Append `ClientUpdateMigrationSource{Base: installedRotationHistory, Schema: ...,
Version: nextVersion}` without changing prior migration bytes. **Stop serving,
install the forward history, replace every accepting old/unselected instance,
then enable `Config.ClientMetadataUpdates=true`.** `ClientSecretRotation` and
its installed history remain required. Do not return to old binaries after a
metadata update: they assume registration version equals secret generation and
fail closed on separated counters. Constructors neither install nor infer schema.

`ClientUpdate` accepts exact existing management custody (current ID/version,
immutable owner/tenant, original fresh password session, origin/CSRF and native
request key) plus complete nonempty `Redirects` and `Scopes` replacements within
the configured immutable ceilings. No patch merge, resource/authentication-method
edit, secret input or additional ownership/client class is accepted. Even an
identical replacement advances authority exactly once. **All old consent,
interactions, codes, access and refresh grants are invalid.** Unchanged Basic
custody performs only NEW explicit consent/code/S256 authorization at the new
registration version; removed redirects/scopes deny on warm ordinary services.

Only registration authority advances. Both digest bytes/generations and any
predecessor's original exclusive overlap expiry remain unchanged. Later rotation
advances registration and secret generation independently; the immediately older
generation alone overlaps, and deletion still retires every slot. New encrypted
preparation captures the actual secret generation. Published preparation without
that optional field retains its original coupled client-version interpretation,
never a generation inferred from today's aggregate. Existing history, digest
framing and original recovery remain intact.

The existing sole Work serializes update/rotation/deletion and ordinary grant
admission on the same client root, preserving original <=20s authority through
callbacks, SQL waits, commit, delivery and retries. Exact platform policy runs
outside protected locks; existing actor-epoch withdrawal and required risk,
audit/outbox effects still apply. The canonical operation is
`identity.oauth-server.client-update`, audit action
`identity.oauth_server.update_client`, and lifecycle topic
`oauth_client.configuration_changed.v1`. Failure/unknown returns Completion only.
Committed retry metadata describes the ORIGINAL replacement, not today's client;
it never repeats a mutation or reveals a secret. `Recover` uses the original
operation/command/client/tenant/current original manager Session and reconciles
metadata only. Fresh invocation custody cannot renew retained preparation's
original deadline. Use a current read and new explicit key for a later change.

The optional [selected OIDC profile](../docs/selected-oidc-profile.md) adds native
encrypted ID-token preparation, subject-bound UserInfo and public signing-key
lifecycle. Install SigningMigrationSource before enabling it; existing OAuth
history and current identity/session/grant owners are retained.
Explicit child `EmailUserInfo` with a matching openid/email extension catalog
adds consented email UserInfo from the existing native identity repository.
Repeated owner/token/consent/key checks retain the original earliest validity
deadline; changed identifier authority denies old grants. No claim callback,
email copy in OAuth persistence, or new migration is required.
Registered pairwise clients additionally require `PairwiseMigrationSource`
appended at a fresh version. Native `InstallSubjectKey` authenticates/stages
encrypted HMAC custody; `ActivateSubjectKey` selects new writers. Authenticated
Authorize Work atomically resolves the stable sector binding before any ID-token
preparation. Original grants keep that binding through code/refresh/UserInfo.
`SubjectKeyRegistrations` reconstructs retained encrypted custody/current writer;
same-material rewrap and `RetireSubjectKey` preserve all subjects and immutable
key-version tombstones. These are trusted deployment operations, not client CRUD.
No migration or IO runs in constructors. See the linked profile for activation,
overlap, fail-closed stale-instance behavior and wrapping-key removal boundaries.

Multi-host clients select root `SectorValidator`'s actual HTTPS-validated
registration and its opaque `Config.Protocol.SectorRegistrations` evidence
before native construction. The URI host is the sector. Missing/foreign/stale
client version or changed URI/redirect set denies admission; loading stored
policy requires another actual validation fetch. Existing bindings and migration
bytes are reused, with no runtime document TTL or network renewal. See the
selected OIDC profile for explicit egress pins, TLS trust and document limits.

Selected OIDC login/maximum-age requests retain their original encrypted native
continuation and return `FreshAuthenticationRequired` when another password
authentication is needed. Complete genuine password sign-in, then call
`Continue` with that continuation, the new current session and its synchronizer.
The native owner checks the same tenant/user, distinct post-request proof and
both source authorities; source adoption, consent and code commit atomically.
Original client/request/subject/deadlines survive. Metadata-only `Recover`
requires the exact new session authenticated by original preparation even when
the grant update rolled back; historical `NotCommitted` retains its failure error.
Use matching core/child/native versions: selected results echo the original
request, and native pre-Work child decisions remain fenced through core return.
If a committed code/continuation expires before core delivery, retain the
metadata-only historical command ID for `Recover`; the withheld credential
cannot be replayed and its delivery error does not prove absence of commit.
Append the shared kernel's `OAuthReauthenticationMigrationSource` at a fresh
allocated version before enabling this profile. It permits the closed denied
`OAuthReauthenticationRequiredError` classification without rewriting installed
journal migrations.
Only its actual terminal `NotCommitted` receipt permits a genuinely new login
to select another random attempt on the same original continuation. The sole
coordinator checks that receipt and advances the native current-attempt pointer
atomically with acknowledged preparation start. Pending, Unknown, committed and
other failures never permit that handoff. Original-attempt recovery remains
independent of the pointer; no private login engine or outcome journal is added.

`NewService(pool, Config, keys)` composes the native primary session reader,
OAuth participant and root protocol. `NewStore` exposes that same participant
for explicit composition and metadata-only `Recover`; applications do not
implement a domain store, transaction callback or authentication engine.

## Startup and migrations

Supply an existing primary PostgreSQL pool and actual public native
configuration for the identity coordinator, password-session admission,
authorization policy, risk counters/lockouts, token digests and envelope keys.
Configured clients are immutable platform-owned public or confidential Basic
registrations. Statically configured confidential clients require exactly one startup verifier matching
their ID/version; the root's [configured secret policy](../docs/selected-profile.md)
requires retiring old instances and advancing client version when secrets change.
No plaintext client secret enters OAuth SQL, preparation, audit or outbox. All four
canonical OAuth operations must select the current Privileged risk policy with
exactly `velocity` required. Unavailable additional mandatory providers deny at
construction; CredentialMutation provider custody is not reused for Privileged.

Before enabling calls, install public owners' histories: identity kernel and
generated-output/counter preparation, directory/credential/authorization
authority, password sessions/CSRF, protected counters/lockouts, audit, outbox and
the identity outbox participant. Install this module's `MigrationSource` in a
dedicated schema with a permanently allocated positive migration version.
Use the migration backend's separate **`ForNamespace` history**; do not mix
unrelated owners' histories under the default ledger.

Construction never installs/adopts tables, generates a token or performs IO.
The base OAuth schema requires no device, OIDC, organization or API-key store.
It owns no foreign keys over identity users or local sessions. Durable records
contain keyed bearer digests and bounded nonsecret projections. Only existing
coordinator authenticated encrypted preparation retains generated delivery
custody. Child records retain exact root, parent and issuing-command lineage;
parents cannot be deleted while descendants reference them.

Optional `Protocol.Discovery` selects the core's typed OAuth-only metadata on
the existing native service. Install a matching discovery-capable root/module
version and provide the actual trusted endpoint URLs before enabling it; no
schema migration or native recovery-identity change is involved. The application
still owns TLS and endpoint registration. The
[independent client consumer](discovery_integration_test.go) loads that metadata
and uses the pinned `golang.org/x/oauth2` client for real code/S256 exchange and
refresh before revoking through the discovered endpoint. Its in-process
transport is a test seam, not a shipped HTTP server or resource verifier.

Consent has an independent server-owned ID and positive version. Explicit
approval inserts 0-to-1 or advances that same row's version using a fenced CAS;
it is not derived from a grant ID. The native owner records the actual SQL
mutation in the sole Work, and the real outbox atomically writes the primary
grant event and secondary `consent.created.v1`/`consent.reconfirmed.v1` event.
Failure of either notification rolls back consent, code, success-audit and grant
effects; the coordinator may retain its separate failed-attempt audit.
The exact [owner event catalog](../docs/selected-profile.md#native-lifecycle-owner-catalog)
explains new informational transitions and consumer impact.

Use independently generated versioned keys for token/session lookup, CSRF,
command intent/fingerprints and envelope custody. Retain every key/configuration
required by outstanding grants and command recovery. Client policy/version
changes cannot silently widen historical authority.

## Optional workload profile installation

For an explicit `Client.Workload`, append `WorkloadMigrationSource{Base: prior,
Schema: dedicatedSchema, Version: nextAllocatedVersion}` to the **same OAuth
history namespace**. `prior` includes the exact published `MigrationSource` and
`nextAllocatedVersion` follows every prior version. Apply before selecting the
workload client. The forward extension preserves populated human grants,
consents, parent links and existing history checksums; web-only configuration
does not require it. It does not backfill humans into machine identities.

The extension changes nullable user/typed source checks, adds a generated root
discriminator and a unique composite root reference plus artifact foreign key.
Workload artifacts must be root access records with no consumed/refresh/code
state; their discriminator must match the actual root. Schedule an exclusive
migration window without concurrent issuance and allow table/index/WAL
headroom. This correctness index is not a performance optimization. There is no
down migration deleting grant history; retain old configurations for recovery.

Supply immutable platform/client/tenant/service-account/scopes/resource/TTL
policy and `Config.WorkloadAuthority` naming the actual directory and workload
authorization namespace. Explicit trusted owner bootstrap must already exist;
constructors/readers never create it. Workload-only configuration may leave
`Session`/CSRF empty; mixed configuration still requires the existing genuine
password-session owner. The [workload consumer](workload_integration_test.go)
installs actual public owner histories but performs no human signup or session
issuance, and asserts actual service-actor audits and root-access lineage.

Workload unknown issuance recovery uses the returned original command ID,
token operation, owning Basic client custody, and **empty Token, TenantID and
Session**. It authenticates retained encrypted preparation before metadata
reconciliation; it never delivers access or creates another command. A fresh
`client_credentials` call is a separate issuance, not an unknown-outcome retry.
Retain original configuration/keys and retire old instances on configured-secret
changes as for web clients. Owning introspection reads workload epochs instead
of human/session authority; its subject is the configured service account.

## Optional own-consent profile installation

The separately selected [direct resource verification profile](../docs/selected-resource-profile.md)
uses this installed consent-generation barrier; it cannot select a legacy
adapter without `ConsentManagement`.

Append `ConsentMigrationSource{Base: prior, Schema: dedicatedSchema,
Version: nextAllocatedVersion}` to the same OAuth history namespace. Base may
include the workload extension but need not require it. The migration retains
installed history bytes and grant/artifact lineage, binds already-approved human
grants to their actual independent consent, and records exact original client
policy fingerprints from code-issuance provenance. Missing/ambiguous provenance
or conflicting objects fail transactionally rather than being adopted.

This ALTER/backfill/reference-constraint migration requires an exclusive window
with issuance stopped and table/index/WAL headroom. Retire old binaries and
unselected configurations, install the extension, then enable
`Config.ConsentManagement=true` on **every** serving human-token instance before
resuming traffic. A configuration that omits consent fences must not remain a
parallel accepting path. No workload-only service selects human management.
Published base/workload migration bytes are unchanged; there is no destructive
down migration or background cleanup journal.

`Service.ConsentGet/List/Delete` and the native Store implement the canonical
own-consent operations. Commands borrow current genuine browser/CSRF custody and
never select another effective user. Delete rechecks actual current session,
directory, credential and policy through public owners, same-browser CSRF and
the sensitive 15-minute original-authentication cap before and after waits.
It advances one versioned consent-generation barrier and writes its actual
participant receipt/audit/`consent.revoked.v1` in the sole Work. Approval and
refresh lock that consent before grant/artifact state; withdrawal does not lock
an unbounded grant set. Tokens fail closed against current consent state and
generation. Explicit later approval does not revive earlier generations.

Unknown delete recovery supplies `OperationID=identity.oauth-server.consent-delete`,
the original CommandID/ConsentID/ClientID/TenantID and current original Session,
with Token/client-authentication empty. It authenticates the retained original
preparation before metadata reconciliation. Do not retry a new withdrawal to
resolve uncertain commitment. Keep original configuration and keys for recovery.

### Optional strict own-consent narrowing

After the consent profile is installed and selected everywhere,
`Config.ConsentNarrowing=true` adds `Service.ConsentUpdate` and the optional
`ConsentUpdater` capability; it does not change `ConsentManager`. Configure the
existing kernel `Config.RequestKeys` owner and install its
`RequestKeyPreparationMigrationSource` before selection. No further OAuth
migration is needed. Application authorization must explicitly permit
`identity.oauth-server.consent-update` (Privileged risk) and its recovery action;
the same real session, CSRF, admission, audit and outbox owners remain in use.

The request fixes the own consent ID/version, configured client ID/version and
resource. Only a nonempty strict subset of the persisted approved scopes is
accepted; empty, unchanged, expanded and foreign sets deny. Subject, actor,
tenant, client and resource cannot be edited. Original password completion must
remain younger than 15 minutes and generally fresh, including after lock waits;
repeated reads or retries do not renew the original admission deadline.

The kernel binds the request key to its original random command and
authenticated encrypted input before execution. Retry with the same original
browser, exact CSRF and intent; a changed intent returns `ErrConsentConflict`,
not another command. Neither the key nor historical mapping possession proves
authentication. Keep the original key, command, configuration and encryption
keys while outcome reconciliation may be needed. Selecting this new capability
does not change the configuration identity of existing grants or delete recovery.

One sole-coordinator Work advances the same consent's version and generation,
narrows its scopes and emits `consent.scope_changed.v1` with the actual consent
identity/version and `identity.oauth_server.revoke_consent` audit action. Every
old-generation code, access, refresh and UserInfo authority denies, even when
its scopes happen to fit the new set. An explicit new narrowed authorization is
required; no old descendant is rebound and no new token is returned by update.
Required outbox failure rolls back the scope/version/generation and receipt.

Unknown update recovery supplies
`OperationID=identity.oauth-server.consent-update`, the original
CommandID/ConsentID/ClientID/TenantID and current original Session, with
Token/client-authentication empty. A new Store authenticates both the original
kernel request preparation and feature preparation before reconciling metadata.
It neither executes narrowing again nor redelivers credentials. A same-key
retry returns only the original completion, never another generation advance.

## Unknown outcomes

Cancellation, connection failure and lost COMMIT acknowledgement do not prove
rollback. Preserve the returned original `CommandID` and original custody.
Do not retry issuance or generate a replacement token to resolve uncertainty.

`Store.Recover(ctx, RecoveryRequest)` supports exactly selected authorize,
continue, token and revoke canonical operation IDs:

- Initial authorization: original current browser, tenant, configured client
  and command ID. The encrypted original client/session binding is authenticated.
- Consent: the same browser/tenant plus original client-bound continuation and
  its preallocated transition ID.
- Token or revocation: original client-bound protocol bearer and its exact
  preallocated transition/replay ID, plus `ClientAuthentication` under that
  client's configured method, without a browser or caller-selected user.

The result contains only outcome, command ID and bounded retry metadata.
Live leases remain observational. Only the original coordinator and unanimous
native participant evidence reconcile noncommit after expiry. Committed
recovery never reveals an unknown code/token, renews authority or executes again.
When committed delivery was lost, start a new authorized interaction instead
of treating historical metadata as a recoverable bearer.

## Verification and ownership

Integration tests are explicitly tagged `integration,oauthflow`; the base
migration test uses `integration`. Explicitly opt into a task-owned disposable
PostgreSQL18 loopback cluster with `OAUTH_POSTGRES_TEST_DSN` and its exact
`OAUTH_POSTGRES_TEST_DATA_DIRECTORY`. Tests create/drop only private databases.
The full consumer also requires all audit roles absent before installation and
removes only roles proven task-created and unused after private DB cleanup.
Never point these fixtures at production or a shared user-owned cluster.

The consumer performs real signup, confirmed email, password sign-in, consent,
code exchange, refresh and revocation. Fault tests withhold actual PostgreSQL
COMMIT acknowledgements and check native reconciliation, not fabricated
outcomes. Contention races real consumption; credential withdrawal uses real
password reauthentication/replacement; browser withdrawal uses the session owner.

The application owns pool/key lifetime, migrations, endpoint rate limits and
transport. Operations are context-bounded. Immutable instances support
concurrent calls with invocation-local participants and serial Work lifetimes.
There is no background cleanup, private coordinator, second command journal,
resource verifier or replacement local-session issuer.

`Config.Protocol.OwningClientIntrospection=true` separately selects read-only
RFC7662 introspection through both Service and Store. It requires the owning
confidential client's actual Basic secret before any token lookup. Current
primary OAuth state and original directory/user/identifier/password-credential/
authorization expectations are checked without copying source-owner SQL or
opening a private transaction. Browser logout alone does not revoke approved
grants. Unknown, inactive, expired, foreign and withdrawn tokens return only
`Active=false`; unavailable authority and cancellation return zero metadata plus
a redacted error. No cache, renewable validity evidence or HTTP route is added.
