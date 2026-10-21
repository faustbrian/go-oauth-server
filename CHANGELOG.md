# Changelog

## Unreleased

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
