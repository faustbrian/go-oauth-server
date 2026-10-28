# Native OAuth PostgreSQL adapter

Experimental persistence and public service composition for the
[selected authorization-code profile](../docs/selected-profile.md).

## Optional current profile-name UserInfo

Select native `Config.ProfileUserInfo=&ProfileUserInfoConfig{...}` with the exact
existing identity owner's immutable `AttributeSchemas` and `ProfileSchema`.
Both that source and the protocol's `profile` scope must be selected together.
The same primary pool and existing public `identity/postgres.GetProfile` owner
are used; no name callback, raw identity-table reader or migration is introduced.
Use matching published root/child/native versions, installed identity profile
history and a schema compatible with actual stored attributes before enabling.
Reserved profile names cannot masquerade as custom fields; schema definitions
are neither guessed nor rewritten during reads.

Enable child `oidc.Config.ProfileUserInfo`, allow `openid`/`profile` for the human
client and obtain real consent through the existing code/S256 flow. Only current
optional display `name` is projected in UserInfo. A committed native
`ProfileService.ProfileUpdate` is visible on the next authorized call using the
same grant/token; image, custom attributes and other profile claims are omitted.
ID tokens remain minimized and RPs must independently verify them and equal
UserInfo `sub`. Openid-only consent never discloses a name.

The source validates the full immutable stored document before selecting name.
Two consistent aggregate snapshots and repeated original current-authority,
grant/client/consent/subject/key fences deny mixed profile versions and late
withdrawal. Cancellation, unavailable/mismatched source and original exclusive
deadline failures return no partial claims. The earliest original token/grant/
session/credential/read-start+20s ceiling never refreshes. Existing default,
email, phone, pairwise and approved-grant browser-logout behavior is retained.
See the [selected name profile](../docs/selected-oidc-profile.md#optional-consented-profile-name-userinfo).

## Optional human code-access delegation

Select the separate [human code-access exchange profile](../docs/human-code-exchange.md)
only with real consent management, the final forward
`HumanCodeExchangeMigrationSource` and explicit source-bound native client
bootstrap. `BootstrapHumanCodeExchangeClient` and
`HumanCodeExchangeClientAuthority` derive actual tenant/registration scope from
a genuine S256-derived root and owning Basic credentials, never a caller's
asserted epoch. The public authorization owner remains the sole lifecycle owner.
Turning selection off denies derived tokens without altering ordinary roots.

The additional `HumanCodeExchangePolicy.AllowRefreshIssuedAccess` flag admits
opaque access from native human refresh rotation, never refresh bearers. Its
zero value retains code-only exchange. Replace all old writers before enabling;
the first selected rotation must still descend directly from genuine S256 code
redemption. Subsequent rotations retain fixed-size original issuance proof,
without traversing arbitrary refresh history or reviving expired consumed
refresh authority. No additional migration is needed; unproven preactivation
refresh histories require reauthorization. See the linked profile for withdrawal
and original-lineage freshness semantics.


## Optional platform-owned public client management

The same genuine platform-manager, owner/tenant, session, origin/CSRF and keyed
management authority can create public human-web clients with `Public=true`.
Select both native `Config.PublicClients` and
`Config.Protocol.ManagedClients.PublicClients`; mismatched activation denies
construction. Append `ClientPublicMigrationSource` at a new version after the
installed client history (including any selected rotation/update histories).
Stop issuance, install this forward history, and replace every accepting
instance with a public-aware version before enabling either flag. Never rewrite
installed history or roll back to unaware binaries after public rows exist.
Unchanged confidential-only deployments require neither the history nor flags.
Plan a read/write-blocking maintenance window: the single `ALTER TABLE` validates
existing rows under `ACCESS EXCLUSIVE`. Bound lock acquisition and execution
with `lock_timeout`/`statement_timeout` or equivalent operator command deadlines.
Complete schema installation and the public-aware rollout before enabling flags.
See [PostgreSQL18 ALTER TABLE](https://www.postgresql.org/docs/18/sql-altertable.html).

Public registrations persist `Public=true`, method `none`, and a NULL secret
digest. No public secret is generated, encrypted, stored or revealed, including
unknown results and original retries/recovery. Public clients use the existing
explicit consent/S256 code, refresh and client-bound revocation flow without
Basic credentials; supplied Basic credentials deny. Fresh get/list and protocol
services read the current native registration, not a creation-response cache.
Deletion accepts the discovered ID/version with the ordinary closed delete
request (`Public` omitted/false); it withdraws descendants under existing client
fences. Public secret rotation and metadata replacement remain unselected and
deny; `Public=false` confidential creation and rotation are unchanged.

The forward schema preserves existing confidential metadata/digests and denies
public rows carrying a secret. Activation does not change the original native
configuration/management-policy identity for unchanged confidential commands;
the class is bound separately in each create intent and encrypted registration.
Old confidential grant and metadata-only recovery custody therefore remains
original, while using one request key for another class conflicts.

This OAuth-only selection adds no RFC7591 registration, OIDC/device management,
HTTP, organization delegation or token exchange. Minimal managed OIDC requires
the separate selection below.

## Optional minimal managed public OIDC

With public management enabled, separately set
`Config.Protocol.ManagedClients.PublicOIDC=true` and configure the existing
`Protocol.OIDCScopes` with `openid`. Keep `ManagedClients.Scopes` OAuth-only and
unchanged. This permits exactly a managed `Public=true`, browser-only client
requesting `openid` alone, with nil `SubjectRegistration` selecting the existing
default public subject. It does not select confidential OIDC, pairwise subjects,
additional identity claims, device flow, RFC7591 or managed public replacement
and secret rotation. Existing independently configured OAuth/static profiles
retain their own settings.

Use matching published root/native versions. Preserve the existing public-client
history and append the existing `SigningMigrationSource` to the exact selected
history when signing is not already installed; no new migration is introduced.
Construct the actual core signing owner and OIDC child, publish its public JWKS,
activate the published key, and use `core.WithOIDC(child)` for client creation,
private get/list, authorization/continuation and token issuance. The actual child
still reads trusted `UserInfoSource` through its original core. An uncomposed
service denies this profile before creating a client, approving an interaction
or consuming a code/refresh bearer. Consumers must independently validate
discovery, issuer, audience, signature, nonce and expiry, then require equal
ID-token/UserInfo subjects.

Public OIDC registration persists the existing public/none metadata and NULL
secret digest. Fresh services resolve it from native current authority. The
selector leaves existing configuration/management identities unchanged: each
new intent binds its exact class/scopes separately, while original command
recovery retains original configuration, keys and current manager authority.
Keep that original custody; changing other configuration is not this selector.
Current client/consent/credential/owner and original freshness fences remain
mandatory. Refresh retains the original subject, revocation withdraws its
access, and terminal deletion never falls back to static authority or revives
through original retry/recovery. Recovery is metadata-only, never token delivery.
This native profile registers no HTTP/Reference routes or private substitute
authority and is not full M31 or whole-platform qualification.

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
Explicit child `PhoneUserInfo` with matching openid/phone scope permission uses
that same native custody path. Actual phone workflow/OTP owners establish
canonical E.164 possession; the child omits pending/revoked contacts and emits
only consented UserInfo phone claims. Native removal/replacement withdraws old
grant authority immediately; a new genuine session/approval is needed to reflect
the changed contact. Identifier cascades may remain pending: epoch-based denial
does not claim every downstream cleanup acknowledgement completed.
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

Exact OIDC `prompt=consent` always uses this existing protected interaction,
including when bounded prior consent is reusable for `prompt=none`. No approval
row is renewed before explicit `Continue` approval; denial spends only this
interaction and issues no code/token. Current session/CSRF and maximum-age policy,
original authority/deadlines, required effects and metadata-only recovery remain
unchanged. Compose matching core/child/native versions; no additional migration
or mandatory silent-consent bootstrap is introduced.
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

## Optional workload access exchange

The [finite restricted profile](../docs/workload-exchange.md) uses existing
`Store.Token`/`NewService` and `Store.Recover`. Append
`WorkloadExchangeMigrationSource` after `WorkloadMigrationSource` during an
exclusive schema window. Existing rows remain intact and ordinary unselected
services retain their history. Replace unaware accepting writers before
selecting `Protocol.WorkloadExchange`; mixed or off-profile rollback is unsafe.

Set `WorkloadExchangeClientNamespace` to a separate authorization namespace,
different from `WorkloadAuthority.PolicyNamespace`. An authorized consumer
lifecycle explicitly initializes each real public authorization `AuthorityScope`
at `(tenant, namespace, client.ID)` to the registration's exact `client.Version`.
Requests never create rows or adopt whatever current version happens to exist.
`AdvanceAuthority` withdraws that client's roots/descendants **and new issuance
from its unchanged registration**, without withdrawing another client sharing
the service account. Reactivation needs explicit newer matching registration/
secret adoption; old lineage never revives. Preactivation roots lacking the
original client epoch cannot be adopted by selected exchange: reissue explicitly.

Each root and immediate parent link refers to its stored `metadata_version`,
not the mutable grant version. The forward migration records existing rows as
known original metadata revision one, without asserting their past active state.
This revision owns immutable token identity, purpose, payload, parent and expiry;
legitimate native transitions never replace them. Mutable active/revoked state
remains a separate actual primary read and protected fence for every ancestor.

Every exchange/introspection checks actual current client/workload/directory and
root/ancestor state. Missing, stale or unavailable required authority denies.
Original source-observation provenance remains unchanged; a genuine subsequent
primary read creates a separate bounded current observation, not a longer token
expiry. No positive cache or invalidation message is introduced.

Active sources remain reusable for independent exchanges. Zero trusted
`TokenRequest.CommandID` creates a fresh command; an explicit original ID retries
only the retained source/client/scope/target intent. No nonstandard form or header
is required or accepted. Lost COMMIT acknowledgement, exact retry and
`Store.Recover` reconcile that original command with source token and Basic
client; changed intent conflicts. Metadata recovery never reveals the generated child. Child, required
service audit, `oauth_access.exchanged.v1` lifecycle and native effect commit
atomically. The source token and original grant are not consumed or widened.

Compose any selected `ConsentExpiryMigrationSource` before the final exchange
suffix. Existing populated parentless silent codes remain valid, and both silent
and delegated workload issuance continue afterward. Loading consent-expiry
history after exchange is rejected before database mutation; historical migration
SQL and checksums are unchanged.

The standard request adds `SubjectToken`, `SubjectTokenType`,
`RequestedTokenType` and exclusive `Audience`/`Resource`, as required by the
shared-issuer amendment over the historical three-grant planning row. API-key,
actor, organization, human, private-session, JWT, device and HTTP/reference
exchange variants remain unselected; this is not full M33/unit closure.

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

## Optional bounded OIDC silent reauthorization

Select matching root/OIDC child versions and existing consent management, append
`ConsentExpiryMigrationSource{Base: installedOAuthHistory, Schema: ...,
Version: nextVersion}`, then explicitly set `ConsentReuseTTL` to 1s..24h at
microsecond precision. Zero selects legacy writers before activation only.
Stop accepting writers, install the forward history, and replace every old
accepting instance before activation;
old published SQL and retained preparation must not be rewritten. After activation
EVERY accepting writer must retain a positive TTL; mixed/zero-writer rollback is
unsupported, and history is not reversible. Revoke consent to withdraw reuse.
The additive
history preserves existing ordinary/workload parent constraints and marks only
genuine silent root codes. Constructors perform no migration or IO.

Only a new explicit approval captures `granted_at + ConsentReuseTTL`. Legacy NULL
expiry is never backfilled or reusable. Silent issuance, scope narrowing,
recovery and configuration increases never renew that original bound; a reduced
configured ceiling may conservatively deny an older approval. The TTL stays
outside the legacy configuration identity so changing a reuse ceiling does not
strand unrelated grants or retained original preparation.

`prompt=none` independently verifies the exact current session, client/version,
tenant/subject/resource and approved scope subset. Current approval is locked
and fenced in the sole existing authorize Work; no continuation, approval audit
or consent write is created. Session/max-age failures before a command starts
return `login_required`; missing/NULL/expired/withdrawn/insufficient/stale-client
approval returns `consent_required`. Already-started late denials preserve their
command/durability classification and disclose no credentials or redirect.
Original exclusive session/credential/read/max-age/approval deadlines survive
SQL waits and final delivery, without positive caching or fresh observation
renewal. Required risk/audit/outbox failures roll back issuance atomically.

Original authorize COMMIT ambiguity uses the existing `Recover` operation and
metadata only: neither retry nor recovery reveals a code, creates a replacement
grant, or renews approval. The selected consumer is static human OIDC
registration. Managed OAuth client update/rotation/deletion remain OAuth-only,
not newly supported OIDC-management variants.

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
opening a private transaction. Ordinary browser signout alone does not revoke approved
grants. Unknown, inactive, expired, foreign and withdrawn tokens return only
`Active=false`; unavailable authority and cancellation return zero metadata plus
a redacted error. No cache, renewable validity evidence or HTTP route is added.

Optional `Config.RPInitiatedLogout` selects a distinct exact-source termination
through the existing session owner's effect in the same OAuth Work. Append
`EndSessionMigrationSource` after installed signing history and install the
session owner's `OIDCEndSessionMigrationSource` after its single-session history.
Use matching public kernel/session-owner dependencies and replace all unaware
readers/writers before enabling. This explicit purpose, unlike ordinary signout,
withdraws that source's refresh/UserInfo/resource authority. No grant fanout or
private session/revocation engine is introduced. See the [selected logout
profile](../docs/selected-oidc-profile.md#native-rp-initiated-logout) for hint
association, historical recovery, redirect registration and rollback constraints.

## Optional native device authorization

`Store.DeviceStore(DeviceConfig)` explicitly selects the unbound OAuth-only
RFC 8628 consumer documented in the [`device` module](../device/README.md).
The factory uses this existing store/coordinator and root-owned typed
projections; the production PostgreSQL package imports no device child.
Ordinary `NewStore`/`NewService` perform no device bootstrap and need no device
policy, lookup keys or schema. The child remains a test-only dependency of the
native integration consumer, not a mandatory production module.

Before selecting this profile, install the existing rate-limit owner migration
and append `DeviceMigrationSource` after ordinary OAuth/consent history. This
first forward history excludes installed workload and silent-OIDC artifact
variants. Stop writers for the schema change, replace unaware writers before
activation, and retain the original shared coordinator/recovery and lookup-key
versions. There is no down migration or automatic background cleanup. Device
expiry and terminal recovery records must not be deleted while original
command recovery can still reference them.

The registered client's `DeviceAuthorization` flag defaults to false and enters
the actual native authority fingerprint when selected. Public and Basic client
authentication remain independent of actual reviewing-session/CSRF admission.
The native owner retains the original approved human source separately from
the polling client actor and fences current authority before the sole atomic
root-owned token winner. A complete verification URI is not approval.
