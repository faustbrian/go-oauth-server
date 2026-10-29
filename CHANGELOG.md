# Changelog

## Unreleased

- Add independent `ManagedClientPolicy.PublicPairwiseRegistrations` selection
  for secretless managed public browser clients requesting `openid` alone.
  Exact single-host registration survives creation, safe reads and authorization;
  existing public/default and confidential-only selections remain unchanged.
  Matching native key/persistence support and OIDC composition are required.
  Sector-identifier URIs, additional claims and metadata replacement remain
  unselected.

- Add an exact trusted pairwise-registration ceiling for managed confidential
  Basic/openid browser clients. Selected creation, safe reads and authorization
  preserve the immutable single-host registration; nil retains the default
  subject profile. Matching native persistence/key support and OIDC composition
  are required. This does not select managed-public pairwise, sector-identifier
  URI, additional claims or metadata replacement.

- Add independent `ManagedClientPolicy.ConfidentialOIDC` selection for managed
  Basic browser clients requesting `openid` alone with the default public
  subject. Creation, safe reads, authorization and issuance require the actual
  OIDC composition and matching native support. Existing confidential secret
  custody and rotation remain the owners; neither public-client selector,
  additional claims, pairwise subjects nor metadata replacement is enabled.

- Add explicit `ManagedClientPolicy.PublicOIDC` selection for no-secret managed
  public browser clients requesting `openid` alone with the existing default
  public subject. Creation, safe reads, authorization and token issuance require
  the composed OIDC extension and matching native support; the actual child can
  still read trusted `UserInfoSource` through its original core. OAuth scope
  ceilings and existing static/confidential profiles remain unchanged;
  additional claims, pairwise, device and confidential OIDC management are
  not selected.

- Accept explicit managed public-client creation and safe private metadata with
  registered `none` authentication. Public creation never reveals a secret;
  existing confidential Basic creation, rotation and custody stay unchanged.
  Durable public clients require matching native support and its forward schema
  activation; this core change alone does not install or select native storage.

- Add optional trusted native profile custody to OIDC UserInfo projections,
  preserving the existing four-method extension and minimized ID-token contract.
  Select matching native and child versions for consented display-name disclosure.

- Add explicit `HumanCodeExchangePolicy.AllowRefreshIssuedAccess` selection for
  human opaque access produced by native S256-derived refresh rotation. Code-only
  defaults and refresh-bearer denial remain unchanged; adopt matching native
  support and replace old writers before activating the selected profile.

- Add a separate opt-in human authorization-code access-source exchange for
  owning configured Basic web clients. Opaque descendants preserve original
  human/session/consent authority, scopes and lifetime across refresh and
  ordinary browser logout. Workload-only exchange remains unchanged; selecting
  human delegation requires matching native history and explicit client bootstrap.

- Add opt-in restricted RFC 8693 exchange for an owning Basic workload client,
  narrowing its original or delegated opaque access token without refresh,
  actor overrides or customer delegation. Native adoption requires matching
  forward lineage history; other exchange source profiles remain unselected.
  Sources remain reusable; optional trusted command metadata selects exact
  intent-bound metadata-only retries without adding a wire-protocol parameter.

- Add explicit zero-default device-authorization client permission, managed
  creation ceiling and optional native device projections for the separately
  composed RFC 8628 child. Existing mandatory Store methods and legacy default
  registration fingerprints remain unchanged; adopt matching child/native
  versions only when selecting this profile.

- Add optional native RP-initiated logout with separately registered exact
  post-logout redirects, read-only retained signing-key verification and closed
  metadata-only unknown/history results. Only the genuine issued hint's exact
  initiating session can terminate; existing Store and OIDC extension methods
  remain unchanged. Use matching child/native versions and forward histories.

- Select exact OIDC `prompt=consent` to require a new protected approval despite
  reusable consent, while retaining current-session/maximum-age policy. Fail
  closed when custom adapters skip the initial interaction; denial and unknown
  recovery never disclose code/token material. Use matching child/native versions.

- Select OIDC `prompt=none` with typed login/consent-required redirects and no
  interactive fallback. Matching native bounded explicit approval is required;
  silent issuance preserves original authority deadlines and metadata-only
  unknown/history recovery. Other prompt variants remain unselected.

- Add optional complete managed-client redirect/scope replacement under existing
  fresh manager/CSRF/keyed authority and immutable configured ceilings. Every
  commit invalidates old consent/grants but preserves Basic secret generations
  and original overlap expiry; new explicit authorization is required. Matching
  native forward history/fleet activation is necessary; Store remains compatible.

- Add optional authenticated managed-client get/list safe metadata, enabling a
  fresh manager service to discover current versions for existing mutations.
  Bounded scoped pagination excludes static/deleted clients and all secret
  custody; current reads do not require mutation-only freshness or CSRF.
  Existing mandatory Store interfaces and mutation requirements are unchanged.

- Use the patched Go 1.27.3 verification toolchain for the GO-2026-6809
  `crypto/x509` fix. Consumers must also build with a patched Go toolchain;
  the module/API minimum remains Go 1.27.0.

- Add optional managed confidential-client secret rotation with explicit 0..24h
  overlap and reveal-once successor. Rotation advances client authority: old
  code/access/refresh/grants/consent are denied and require new explicit approval.
  Predecessor Basic works only for new-version grants until its original exact
  exclusive deadline; static clients and existing Store interfaces are unchanged.

- Add optional authenticated platform-owned confidential-client creation and
  terminal deletion, leaving existing Store implementations and static clients
  unchanged. Managed IDs occupy an exclusive server-owned namespace; selected
  ordinary protocol/read paths use current native version/status rather than a
  cached registration. Secrets reveal once only after fresh known commitment.
  Selected discovery reflects managed Basic/web and owning-client introspection
  capability; registry projections cannot mutate retained static policy.

- Add separately composed access-only resource verification with immutable
  trusted tenant/client/version/issuer/environment/resource/scope policy and an
  opaque scope-bound result. Preserve the earliest original read, token and
  credential expiry without renewal, cache or caller-created principal; use the
  matching native profile rather than treating introspection metadata as access
  authority. Existing OAuth services and Store interfaces are unchanged.

- Add optional authenticated own-consent strict scope narrowing with exact
  consent/client versions, immutable resource, original sensitive-session
  freshness, same-browser CSRF and native request-key custody. Existing
  `ConsentManager` implementations remain source-compatible; use a matching
  explicitly selected native adapter for durable generation invalidation and
  metadata-only retry/recovery. Empty, unchanged and expanding sets deny.

- Carry optional native identifier custody and its original validity deadline
  for explicitly selected consented email UserInfo, without adding claim
  semantics to OAuth core or changing default openid-only composition.

- Preserve selected OIDC `prompt=login` and optional `max_age`, distinguishing
  absence from explicit zero. Return a bound fresh-authentication continuation
  rather than an unbound login loop; genuine completion retains the original
  client, redirect, state, nonce and S256 request. Other prompt variants deny.
- Fail closed when an older adapter drops selected authentication intent or
  ignores the child decision. Retain the earliest observed age deadline through
  Store waits/return; historical and unknown results disclose only metadata.
- Preserve the original command's historical correlation when a known native
  commitment returns after an authentication or original code/continuation
  deadline, without revealing a code, continuation or redirect or implying the
  consumed interaction is pending.

- Validate explicitly allowed HTTPS sector identifier URIs against actual
  registered redirect sets, enabling multi-host pairwise clients only with
  opaque issuer/environment/client/version-bound fetch provenance. Keep legacy
  public/single-host JSON and fingerprints unchanged; reconstruct URI evidence
  by fetching before admitting configuration, without runtime network renewal.

- Add optional immutable OIDC subject registration independently of client
  authentication type, with exact single-sector-host validation and trusted
  first-binding/native-claim projections. Nil policy preserves legacy client
  and grant framing; the four-method extension and concrete Service remain.

- Add the optional four-method OIDC seam without replacing the Service struct,
  bounded nonce custody, explicit reserved-scope composition and core-owned
  ES256/durable signing. ID tokens are reveal-once existing native grant output.
- Keep resource and extension scope catalogs separately owned at configuration
  admission; uncomposed services deny explicit or inherited identity refresh
  authority before native credential consumption.

- Add opt-in OAuth authorization-server discovery with immutable trusted
  endpoints and metadata derived from actual selected public, Basic and workload
  profiles. It publishes no OIDC, device, registration or signing capabilities;
  existing zero configuration remains unadvertised and unchanged.
- Add bounded own-consent get/list and fresh-session, origin/CSRF-protected
  withdrawal through the optional native `ConsentManager`. Withdrawal reports
  original durability metadata, never replacement credentials or unbounded
  per-grant results. Native use requires the matching forward consent profile.
- Snapshot workload policy at validation, construction and adapter boundaries
  so caller or adapter whole-value replacement cannot change tenant, identity
  or the access ceiling of an already constructed service.
- Add explicit configured platform/workload-owned Basic client-credentials
  access with immutable tenant/service-account/resource/scope/lifetime bindings,
  owning-client introspection and revocation. No human session, consent or
  refresh is created. Nil workload policy preserves existing web clients.
- Add explicitly enabled owning-confidential-client RFC7662 introspection for
  opaque access and refresh tokens, with separate Basic caller authentication,
  inactive-only unknown/foreign results and bounded native current-authority
  checks. Introspection remains disabled unless selected independently of client
  configuration; it is not resource-server authorization or cache evidence.
- Extend the configured platform-owned web profile with confidential
  `client_secret_basic` authentication for code exchange, refresh, revocation
  and their metadata recovery. Secrets are startup-only primitive-owned digests;
  secret/configuration changes require a new client version and retirement of
  old instances, not hot rotation or fleet-wide revocation. Public clients remain
  supported. Require exclusive bounded OAuth Basic credential channels.
- Add the experimental public-web-client/password-session OAuth profile:
  exact redirect/issuer policy, explicit bound consent, S256 codes, opaque
  access tokens, rotating refresh and client-bound native revocation.
- Add bounded grant-discriminated parsing, OAuth-owned reveal-once token
  custody and historical/unknown outcomes without credential redelivery.
- Reject unselected grants, confidential issuance, OIDC/device profiles and
  unauthenticated introspection instead of advertising partial support.
