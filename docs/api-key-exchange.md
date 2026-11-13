# USER API-key access exchange

This separately selected finite profile uses `Service.Token` and the RFC8693
grant with the private source type
`urn:golib:params:oauth:token-type:api-key`. A genuine modern USER-owned key
authenticates its integration actor. The USER owner is the OAuth subject; the
configured confidential Basic client remains the separately authenticated caller.
None of these identities can substitute for either of the others.

Select `Config.APIKeyExchange` and each intended `Client.APIKeyExchange`.
`MaximumDepth` defaults to four and may only be lowered. The trusted
`ClockUncertainty` and `MaximumDuration` must fit the ten-second race budget.
The owning client uses its existing configured Basic verifier. Public clients,
managed clients, human-code/workload relabeling, organization keys,
JWT sources, actor tokens, refresh bearers and private-session inputs are not
selected. This does not add an HTTP or Reference route.

Modern HMAC-with-pepper keys remain the default. The separately selected
`APIKeyExchangePolicy.LegacySHA256=true` profile admits existing imported bare
SHA-256 USER keys only through their actual verify-only native configuration.
The selection comes from trusted startup configuration, not credential text,
prefixes or a form parameter; it is not a fallback between algorithms.

Use the additive `ParseAPIKeyExchangeForm(rawForm, basicHeaders, policy)` for
that explicit selection. It preserves the owning `LegacySecret` parser's
1..4096-byte historical limit and unchanged decoded bytes, including a value
that happens to look like a modern key. It still requires one Basic header,
closed fields and an exact resource or audience; other fields keep their old
bounds. The existing generic parser and omitted-zero modern policy are unchanged.
Parsing proves no client or key authority. `Service.Token` and the matching
native owner must authenticate independently.

## Native composition and rollout

Use matching published root/native and identity API-key modules. Set native
`Config.APIKeyExchange` to one trusted `APIKeyExchangeConfig`:

- `TenantID` is startup scope, never a request-selected tenant.
- `Configuration` is the actual modern, active, uncached, unlimited-quota key
  configuration, or the exact verify-only legacy configuration when
  `LegacySHA256` is selected. Its issuer, environment and audience must exactly equal the
  OAuth issuer, environment and configured resource. An unrelated API audience
  is not mapped into new OAuth authority.
- `Source` is the real `apikey/postgres.Service` on the same primary database.
  Borrowed pool, source, keys and policy owners must outlive concurrent calls.
- `ClientPolicyNamespace` is independent from session/workload/human namespaces.

Append `APIKeyExchangeMigrationSource` **last** to the complete installed OAuth
history, reserving seven consecutive versions. Preserve old migration bytes.
Deploy and apply this schema before enabling new consuming code: metadata-only
expansion, a concurrent typed-reference index, short-lock attachment, and separate
constraint validations. There is no backfill or new outcome journal. A failed
concurrent build must be inspected/recovered through the migration owner; an
invalid index is not silently adopted. The migration requires bounded caller
context and index/WAL headroom. Reverting runtime selection retains the schema.
Do not return to unaware writers after API-key grants exist.

The suffix can follow plain OAuth history; workload/device history is not a
prerequisite. Installing shared lineage columns enables no protocol capability.
Unselected existing readers/writers retain their old column projection and
ordinary grants. Replace unaware selected instances before activation, then call
`Store.BootstrapAPIKeyExchangeClient` with each actual configured Basic client.
Epoch one is idempotent; an advanced epoch is withdrawal, never repaired by
bootstrap. Construction and token/introspection calls initialize nothing.

For imported keys, install the source owner's existing `LegacyMigrationSource`
and initialize its distinct legacy configuration before import or OAuth bootstrap.
The actual key service retains modern `ServiceConfig.Configuration` for all new
issuance and the selected verify-only `LegacyConfiguration` for existing records.
Authorized digest-only imports preserve IDs, USER ownership/tenant, restrictions,
versions, replacement lineage and tombstones without plaintext or a new paid-key
issuance. Import retries cannot revive revoked material. Existing keys need no
invented prefix or forced rotation; optional rotation uses the owning service's
modern successor workflow.

`AllowLegacyNoExpiry` preserves an actually absent historical credential expiry.
It does not mean an already-expired source, invent a far-future expiry, renew
verification timestamps or permit unbounded OAuth access. New access remains
bounded by configured TTL and five minutes; descendants also retain their actual
parent's expiry. Current evidence still expires from the original primary read
start, and original metadata-only recovery cannot issue or redeliver a token.

## Issuance and authority

The authenticated form parser requires one Basic header, `subject_token`, the
private API-key source type, one exact `resource` **or** `audience`, and optional
narrowing `scope`. `requested_token_type`, when present, must be the standard
access-token type. Secret syntax belongs to `apikey.ParseSecret`; syntax is not
verification. Duplicate/conflicting fields, body credentials and arbitrary
subject/tenant/actor fields deny. A raw API key is never labeled as standard OAuth
access. Later descendants use `subject_token_type=urn:ietf:params:oauth:token-type:access_token`.

The native owner verifies the actual secret with a distinct stable coordinator
attempt bound to the original OAuth command, client/version and trusted source
tenant/configuration/revision. Only explicit nonsecret provenance enters OAuth
preparation and storage; raw source keys remain invocation-local. There is no
claim of erasing immutable Go string copies.

The first opaque access token records the actual key ID/security root as its
parent and root, without a fictitious OAuth/session/code/workload parent. Each
later token points to its actual preceding OAuth access artifact. Every hop
retains source/root, issuer/environment, owner, client, audience and original
verification provenance; scopes cannot recover permissions removed by a parent.
Expiry cannot exceed the parent, source credential, configured access lifetime
or five minutes. No refresh or ID token is emitted.

Current uncached primary observations and actual registered Work fences check
the real source owner, directory, user, policy, configuration and exact key root
before and after mutation. A key rename may advance the current metadata owner
without changing the immutable security root. Root revocation, permission-root
change, withdrawal and outages fail closed. No invalidation cache or asynchronous
sweep is required. Owning-client introspection checks actual OAuth ancestry and
fresh source facts, returning no subject/client/scope/expiry metadata when inactive.

Original verification times never change through exchange or recovery. A
genuinely later primary observation is distinct current evidence, not renewed
bearer authentication or extended source credential expiry. Every invocation
retains its original exclusive deadline through waits, retries and final checks.

## Unknown outcomes and recovery

Preserve the returned original `CommandID`. Exact retries authenticate the
original intent and return metadata only, never an original/replacement token.
An expired original verification cannot be turned into fresh authentication by
copying it or selecting another observation.

`APIKeyExchangeUnknownError` contains only the exact original nonsecret
`VerificationReconcileQuery` and OAuth command correlation. Native `Store.Recover`
accepts that handle as `RecoveryRequest.APIKeyVerification`, with the owning Basic
client and an empty `Token`. The real source reconciliation owner authenticates
historical routing; the original encrypted OAuth preparation independently binds
the full source, configuration, client and intent. The handle itself grants no
actor or principal. If no usable handle was disclosed, do not guess a replacement
verification attempt or retain the raw key for recovery.

Use `errors.As` to retain this disclosed handle even when cancellation also
matches through `errors.Is`. Cancellation is not rollback proof and does not
discard original correlation or authorize a new verification attempt.

Committed access custody can also recover its original first-command metadata.
Derived-command recovery uses the actual original parent access token. Recovery
does not reserve, generate, debit, issue, reveal credentials or renew timestamps;
only the existing coordinator determines whether the command committed or
is proven not to have committed.
