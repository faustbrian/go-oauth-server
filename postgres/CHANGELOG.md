# Changelog

## Unreleased

- Supply existing native identifier/verification custody for approved OIDC phone
  scopes, preserving original grant/session/credential and exclusive freshness
  fences. Identifier-authority changes deny old grants rather than silently
  replacing their contact. No new OAuth migration or grant engine is introduced.

- Add opt-in bounded explicit-consent reuse for OIDC `prompt=none`, issuing fresh
  one-use codes without interaction or approval mutation. Append
  `ConsentExpiryMigrationSource`, replace old accepting writers, then select
  positive `ConsentReuseTTL` (1s..24h) on every accepting writer; mixed/zero-writer
  rollback after activation is unsupported. Legacy NULL is never reusable.
  Original expiry, current authority and <=20s observation fences survive waits,
  required-effect rollback and original metadata-only COMMIT recovery.

- Add selected managed metadata replacement with independent registration and
  secret generations, preserving both digest slots and original overlap expiry.
  Install forward `ClientUpdateMigrationSource`, replace all accepting old
  instances, then select `ClientMetadataUpdates` with rotation enabled. Existing
  encrypted preparation retains its original generation interpretation; sole
  Work, required risk/audit/outbox and original metadata-only recovery remain.
  Emit `oauth_client.configuration_changed.v1`; old grants require new approval.

- Add private managed-client metadata reads over genuine current session and
  exact platform policy, preserving original <=20s deadlines and late current
  owner/client fences. Scoped limit1..100 keyset pages select no secret material
  and create no commands, audit or lifecycle effects. No new migration is needed;
  existing rotation/deletion still independently require their mutation authority.

- Verify native adapters using patched Go 1.27.3 for GO-2026-6809 in
  `crypto/x509`. Consumers must also use a patched Go build toolchain.

- Add optional bounded confidential-secret rotation through existing manager,
  prepared-key, encrypted input, sole Work, audit/outbox and recovery owners.
  Install forward `ClientRotationMigrationSource` and replace old accepting
  instances before enabling `ClientSecretRotation`. Every rotation advances
  actual client authority, invalidating old grants/consent; overlap authenticates
  only new-version authorization and keeps at most one predecessor. Original
  matching-slot/deadline fences survive waits and final delivery; retries and
  recovery never reveal the successor. Emit `oauth_client.secret_rotated.v1`.

- Add selected platform-owned confidential-client creation/terminal deletion
  using existing authenticated human/session/CSRF, exact platform policy,
  prepared request keys, encrypted preparation, coordinator, audit and outbox.
  Append `ClientMigrationSource` after installed consent history and replace old
  accepting instances before activation. Current registry version/tombstones
  fence ordinary protocol, resource, consent and recovery paths without a
  positive registration cache or unbounded token revocation writes.
  Emit canonical OAuth-client creation/revocation lifecycle topics and return
  independently owned static registry projections, including nested policies.

- Compose direct opaque human-access verification over actual stored digest
  namespace, token/consent generation and current directory/user/identifier/
  credential/authorization owners. Fixed trusted policy rejects refresh and
  foreign custody; repeated late fences conserve original expiry and return no
  principal on cancellation or unavailable authority. The profile is uncached,
  read-only and requires installed/selected consent management; no new migration
  or change to existing grant/recovery configuration identities is introduced.

- Add separately selected strict own-consent narrowing through the existing
  kernel prepared request-key owner and sole coordinator. Preserve original
  fresh-session/CSRF authority and immutable tenant/subject/client/resource;
  advance the consent version/generation atomically to deny every older
  descendant. Required outbox failures roll back all effects; uncertain commits
  and same-key retries reconcile only original metadata across instances.
  Select `ConsentNarrowing` only after consent and kernel request-preparation
  histories are installed and the actual request-key/risk policies configured.
  Existing consent management and encrypted preparation identities are retained.

- Project selected email UserInfo custody through the existing identity
  primary repository with repeated identifier/token/consent/subject/key fences.
  Preserve the earliest original session, credential, OAuth and 20-second read
  deadline without storing email in OAuth grants or introducing a migration.

- Complete original OIDC login/maximum-age continuations with genuine newly
  authenticated same-user password sessions. Fence both original and new
  authority, preserve original deadlines/subject/request, and atomically adopt
  the source with consent and one-use code issuance. Existing encrypted
  preparation authenticates metadata-only recovery of ambiguous adoption;
  recovery and spent continuations never restart or redeliver the flow.
- Preserve terminal authentication-age denial and allow genuine fresh login
  to complete the same original continuation through the sole coordinator's
  checked preparation-start handoff. Install the shared kernel's forward
  `OAuthReauthenticationMigrationSource` before selecting this profile;
  other failures and ambiguous outcomes cannot start another attempt.

- Adopt core-validated HTTPS multi-host sector policy through existing client
  admission, fingerprints and durable bindings. Missing or changed registration
  provenance denies before execution. No new migration or document-expiry
  lifecycle is required; existing public/single-host grants remain unchanged.

- Add forward pairwise subject/key-custody history and atomic stable bindings
  in existing authenticated Authorize Work. Exact registered sector, policy and
  original grant association fence ID preparation and UserInfo. Stage/activate,
  encrypted readback, same-material rewrap and inactive retirement survive
  restart without changing existing subjects; install before opting in. Nil
  subject policy leaves original public/OAuth framing unchanged.

- Add selected OIDC preparation to the existing consent/code/S256 transaction
  and subject-bound current-authority UserInfo. Install forward signing history
  before selection: publication, active kid, greatest reserved expiry and
  compromise/retirement survive restart without private persistence. Unknown
  or replayed commands never redeliver signed material.
- Serialize signing selection, reservation, retirement and compromise against
  one native selection lock, rechecking key predicates after contention. Bound
  optional nonces before encoding and require the extension for inherited
  identity refresh authority without consuming rejected credentials.
- Conserve one whole-second access/ID-token expiry through native preparation,
  restoration, commit and return; recheck expiry after signing-key lock waits.
  Selected OIDC code access lifetime may be shortened by less than one second.

- Expose explicitly selected core OAuth discovery through the existing native
  service, without changing stored grants, migrations or recovery identity.
  A matching discovery-capable root pin is required; existing configuration
  remains unselected. A metadata-driven independent client exercises real
  password-session consent, S256 exchange, refresh and owning-client revocation.
- Add explicitly selected own-consent get/list/withdrawal using genuine current
  password sessions, current authority and a 15-minute sensitive-proof cap.
  Install `ConsentMigrationSource` in an exclusive window and retire old or
  unselected serving instances before enabling `ConsentManagement` everywhere.
  A versioned consent-generation barrier atomically denies all associated
  code/access/refresh descendants without fanout, emits `consent.revoked.v1`
  with the actual consent identity/version and supports original metadata-only
  recovery. Existing grant/parent lineage and published migrations are retained;
  explicit reconfirmation cannot resurrect an old generation.
- Add configured workload access through the existing coordinator, current
  directory/workload authorization owners, service-actor audit and lifecycle.
  Install `WorkloadMigrationSource` before enabling workloads, using an exclusive
  migration window and table/index/WAL headroom. Published base history and
  installed human code/refresh lineage remain intact; workload-only services
  require no password-session configuration. Unknown issuance recovers only
  original metadata, never access delivery or another issuance.
- Read actual issued opaque access/refresh state for explicitly selected,
  separately authenticated owning-confidential-client introspection. Recheck
  original primary subject/credential authority without caching or
  renewing freshness; inactive and foreign tokens disclose no metadata.
- Verify configured confidential-client Basic credentials before native token,
  revocation or historical token/revocation recovery effects or disclosure.
  Preserve installed unchanged public-client grants when adding confidential
  clients, and retain the existing current-primary-authority fences.
- Bind each explicit consent's independent identity/version to actual SQL and
  a same-transaction secondary lifecycle event. Use canonical transition names,
  distinguish actual scope changes from unchanged authorization, and preserve
  consent identity on explicit reconfirmation.
- Revoke a refresh family when concurrent use observes the winner's completed
  issuance, without credential redelivery or mutation during metadata recovery.
  Consumed refresh possession can withdraw its own surviving family.

- Add native password-session/public-client authorization, explicit consent,
  atomic S256 code exchange, rotating refresh and narrowly scoped revocation
  through the existing identity coordinator and current primary owners.
- Persist digest-only artifacts with exact root/parent/command lineage,
  explicit consent, immutable participant effects and forward-only migrations.
- Add metadata-only original-command recovery without credential regeneration
  or redelivery after ambiguous commits. Install native owner histories and
  retain original keys/configuration for outstanding grants and recovery.
