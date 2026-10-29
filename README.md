# go-oauth-server

Experimental authorization-code/S256 OAuth protocol contracts
for configured platform-owned public and Basic-authenticated confidential web clients and genuine password
single-factor user sessions, plus explicitly configured workload client-credentials access.
This is not a complete OAuth/OIDC provider or a
stable released API.

The optional [restricted workload exchange profile](docs/workload-exchange.md)
uses the standard RFC 8693 grant at `Service.Token`. It is distinct from private
session exchange and does not enable customer, API-key or organization delegation.

The separate [human code-access exchange profile](docs/human-code-exchange.md)
lets an explicitly selected configured Basic web client narrow its genuine
password-session/S256 access source. It preserves existing human/consent authority
and adds no API-key, organization, JWT/cache or HTTP composition profile.

The optional [OIDC child](oidc/README.md) selects public or registered pairwise
subjects (single-host or validated HTTPS sector URI) for ES256 code flow
through the same native password-session/consent authority. Its
[finite profile](docs/selected-oidc-profile.md) explains composition and remaining
full-goal work; existing OAuth-only configuration remains unchanged.
The child separately opts into consented email UserInfo; openid-only remains
the default and email never expands the ID token.

The root package owns bounded protocol parsing, exact HTTPS redirect/issuer/
resource policy, explicit consent and scope ceilings. The optional
[PostgreSQL adapter](postgres/README.md) implements the durable flow using the
existing identity coordinator, current primary authorities, counters, audit and
lifecycle owners. Applications supply configuration, not a domain store or
replacement authentication engine.

## Public surface

- `ParseAuthorizationQuery` and `ParseTokenForm` bound and discriminate input
  before credential work. Parsing authenticates nothing.
- `ParseTokenFormWithClientAuthentication` and `ParseRevocationForm` enforce
  exclusive public-none or confidential-Basic credential channels. Configure
  each confidential client's startup-only `ClientSecretVerifier` from a borrowed
  `password.Secret`, then destroy that startup secret.
- `Service.Authorize` admits a genuine current browser and returns an opaque
  consent interaction, never a code before consent. Explicitly selected OIDC
  `prompt=none` can reuse an original unexpired approval for a fresh code without
  an interaction; it cannot create or renew consent.
  Exact `prompt=consent` forces a new protected approval despite reusable consent;
  it does not itself force new authentication or renew original deadlines.
- `Service.Continue` checks the exact original browser, synchronizer, issuer
  origin and non-expanding scopes before a one-use code response or denial.
- `Service.Token` exchanges an exact client/redirect/S256 code or rotates a
  refresh token. Reused parents revoke their related family. A client with an
  explicit immutable `Workload` instead selects Basic-only `client_credentials`,
  bound to its startup tenant, service-account identity, scopes and resource;
  it produces access only, never a human session, consent or refresh token.
- `Service.Revoke` handles owning-client token possession. Unknown and foreign
  tokens are indistinguishable no-ops; access revocation is narrower than
  refresh-family revocation.
- Optional `Service.EndSession` composes native RP-initiated logout through the
  OIDC child and existing session owner. Client `PostLogoutRedirects` are exact
  independent registrations, never authorization callbacks. See the selected
  [logout profile](docs/selected-oidc-profile.md#native-rp-initiated-logout) for
  required migrations, issued-hint custody and metadata-only recovery.
- `Service.Introspect` is disabled by default. Explicit
  `OwningClientIntrospection` selects separately authenticated confidential
  clients inspecting only their own actual opaque access/refresh tokens.
  Public client ID or inspected-token possession alone never authorizes lookup.
- `ResourceVerifier.Verify` separately admits only opaque human access tokens
  for one trusted configured tenant/client/version/issuer/resource/scope policy.
  Its opaque result's `RequireScope` checks the demanded OAuth scope and original
  deadline before a selected resource read; it is not business authorization or
  an RFC7662 `Active` wrapper. Use the matching native `NewResourceVerifier`.
- `Service.ConsentGet/List/Delete` use genuine current own-session custody.
  Deletion additionally requires recent original authentication, issuer origin
  and same-browser CSRF; native consent-root withdrawal denies associated
  code/access/refresh authority without unbounded grant fanout.
- `Service.ConsentUpdate` separately selects optional `ConsentUpdater` support
  for a nonempty strict scope subset of the same own consent. Exact consent and
  client versions, resource, original fresh password session, issuer origin,
  same-browser CSRF and a native request key are required. Success invalidates
  every old-generation descendant; newly approved narrowed authorization is
  needed to obtain new tokens. Existing `ConsentManager` implementations do not
  acquire a new mandatory method.
- `Service.ClientCreate/Delete` optionally manage one immutable platform-owned
  public (`Public=true`, `none`) or confidential (`Public=false`, Basic) class
  through `Config.ManagedClients` and matching native
  `CurrentClientRegistry`. Genuine fresh password-session custody, exact current
  platform-management policy, origin/CSRF and native request keys are required;
  configuring the owner does not authorize a manager. Creation allocates a
  reserved `managed.` ID. Only confidential creation reveals a random secret,
  once after known commitment; public creation never generates or reveals one.
  Public creation requires `ManagedClientPolicy.PublicClients` and matching
  native `PublicClients` activation and its
  forward schema; unchanged confidential-only deployments need neither.
  Separately selecting `ManagedClientPolicy.PublicOIDC` permits exactly
  `Public=true`, browser-only, `openid`-alone registrations with the existing
  default public subject. Configure `OIDCScopes` containing `openid` and use
  the actual composed OIDC service for creation, safe reads, authorization and
  token issuance. Trusted `UserInfoSource` remains usable through the original
  core passed to the actual child before composition.
  The OAuth-only managed `Scopes` ceiling stays unchanged. This selector adds
  no confidential OIDC, pairwise subjects, extra identity scopes, device flow
  or managed metadata replacement/secret rotation. Use matching native support;
  core selection alone supplies neither persistence nor signing.
  Independently select `ManagedClientPolicy.ConfidentialOIDC` for the same
  minimal browser/default-subject `openid` profile with `Public=false` and
  existing `client_secret_basic` custody. It requires the configured OIDC scope
  and composed extension, not `PublicClients` or `PublicOIDC`. Adopt matching
  native support before selection; existing confidential rotation history and
  signing history remain their separate prerequisites. Confidential rotation
  retains its existing grant invalidation and fresh-authorization rules.
  Neither selector alone permits pairwise/additional claims, managed OIDC metadata
  replacement or device flow; turning one on does not select the other class.
  To select confidential single-host pairwise registration, additionally supply
  an exact trusted `ManagedClientPolicy.PairwiseRegistrations` ceiling built
  with `NewOIDCSubjectRegistration`, and select one member through
  `ClientManagementRequest.SubjectRegistration`. Every redirect must use that
  registered sector host. Nil preserves default public subjects. The ceiling
  grants no manager authority and contains no key material; the existing OIDC
  `SubjectPolicy` and native encrypted key installation, activation and stable
  binding owners remain required. Use matching native support before selection.
  Updated adapters explicitly consume `ValidatePairwiseClientManagementRequest`;
  the original validator rejects non-nil subject registrations so older writers
  cannot silently commit a default-subject client instead.
  Root support for managed-public pairwise additionally requires the separate
  exact `ManagedClientPolicy.PublicPairwiseRegistrations` ceiling and both
  `PublicClients` and `PublicOIDC`; the confidential ceiling never selects it.
  Matching [native public-pairwise support](postgres/README.md#optional-public-single-host-managed-pairwise-subjects)
  composes encrypted subject custody and stable bindings without a confidential
  or static client; root selection alone does not deliver that journey. Sector-identifier
  URI, additional claims and metadata replacement remain unselected. Safe
  metadata returns independent copies of this nonsecret registration, never
  derivation or wrapping keys.
  Existing warm services resolve actual registry status on every
  call; terminal deletion denies all descendants without token fanout.
  Selected OAuth discovery includes the managed human-web/Basic capability,
  including when no static confidential registration exists.
- `Service.ClientRotateSecret` optionally rotates that confidential class using
  the same exact manager/CSRF authority and keyed original recovery. Explicit
  overlap is 0..24h at microsecond precision; the successor is revealed once.
  Rotation advances actual client authority and invalidates every earlier
  code/access/refresh/grant/consent. New explicit authorization is required even
  during overlap; only the immediately preceding Basic secret can authenticate
  those new grants, until its original exclusive expiry. Static clients are
  unchanged. See the native forward-migration and fleet adoption requirements.
- `Service.ClientGet/List` optionally read safe active managed-client metadata
  through `ClientReader`. A fresh service can discover current IDs/versions for
  the existing rotation/deletion calls without retaining creation responses.
  Reads require an actual current password session and exact platform policy,
  not mutation-only password freshness or CSRF. List limits are 1..100, with
  actor/tenant/owner/limit/configuration-bound cursors; no
  static/deleted client, secret, digest or encrypted preparation is returned.
  Pages are snapshots, not permission or mutation-version leases.
- `Service.ClientUpdate` optionally replaces the complete redirect/scope sets of
  one exact discovered managed confidential-human client/version within fixed
  configured ceilings. Existing fresh manager, origin/CSRF and request-key
  authority remain required. Every commit advances registration authority and
  invalidates old consent/grants, including a replacement with identical sets.
  ID/owner/resource/method and both secret generations/overlap expiry are
  unchanged; unchanged Basic requires NEW explicit consent/code/S256 afterward.
  Matching native forward history and compatible-fleet activation are required.
- `Service.DiscoveryOauth` returns OAuth-only RFC8414 metadata when explicitly
  selected by `Config.Discovery`. Trusted issuer-origin endpoint configuration
  and actual configured clients determine grants, authentication methods, S256,
  scopes and optional owning-client introspection. It registers no HTTP route.

This root prerequisite alone does not supply durable execution. The selected
native composition uses `oauthpostgres.NewService(pool, config, keys)` and is
provided by the optional native module consuming this public core. Its
[consumer proof](postgres/flow_integration_test.go) starts
with actual signup, registration confirmation and password sign-in. The
[selected contract](docs/selected-profile.md) defines that integration boundary.

## Transport and custody

Applications own TLS, routing, browser UI, cookies, trusted network attribution,
endpoint rate limits and response encoding. No HTTP routes are registered here.
Supply `TokenRequest.Network` from the trusted
transport after parsing; the OAuth form cannot provide it. Untrusted headers
cannot establish network attribution without the transport owner's policy.

Requests borrow credential strings until their bounded call returns. Tokens
have explicit reveal-once custody; copies cannot restore delivery permission or
durable one-use authority. Never log or implicitly serialize requests, token
results, cookies, synchronizers, verifiers, codes or bearer values. Deliver only
fresh known-committed output. Unknown/historical results contain no credential.

All external operations require a non-nil context and honor earlier deadlines.
Immutable services support concurrent calls; borrowed pools, clocks, policy and
key providers must remain alive and concurrency-safe. The packages start no
background work and own no pool or process shutdown.

## Adoption boundary

Public clients with method `none` and configured confidential clients with
`client_secret_basic`, exact HTTPS callbacks, OAuth-only scopes,
opaque access tokens of at most five minutes and rotating opaque refresh tokens
are selected. Each statically configured confidential client uses one fixed random 32-byte startup
secret; changes require a new client version and retiring old service instances.
This is not hot rotation or fleet-wide client/secret revocation. Optional workload
issuance requires the native forward migration and actual directory/workload
authorization owners; workload-only composition needs no session configuration.
Core policy alone does not make an older native adapter workload-capable: adopt
an adapter version pinned to this workload-capable core and install its forward
migration before enabling that profile. Local paired-source development does
not establish canonical public-module installability.
Own-consent management similarly requires a matching native version implementing
`ConsentManager`, its forward `ConsentMigrationSource`, and explicit
`ConsentManagement` selection. Retire old/unselected accepting instances before
activation; a new core alone cannot add these fences to an older adapter.
Narrowing additionally requires native `ConsentNarrowing`, its configured kernel
request-key owner/history and an explicit application permission for
`identity.oauth-server.consent-update`. A request key is retry correlation,
never authentication. See the native adoption and recovery requirements before
enabling this separate profile.
Device authorization is separately selected through the
[`device` child](device/README.md) and the native adapter's optional factory.
Only clients with explicit `DeviceAuthorization` permission can use it; default
registration and base OAuth bootstrap remain unchanged. The first native
profile is unbound OAuth-only issuance reviewed by a recent authenticated
password human. It provides no device UI or HTTP/reference routes and does not
by itself establish complete device milestone qualification.

Client administration, OIDC, organization delegation, API-key exchange and
general resource-server policy and positive-cache composition remain
unsupported. The separately selected [direct access-only resource profile](docs/selected-resource-profile.md)
adds no transport, JWT or remote introspection endpoint. No vendor authorization
engine is embedded.

See the [selected contract](docs/selected-profile.md),
[security model](docs/security.md) and [changelog](CHANGELOG.md).
The complete [repository goal](docs/goal.md) remains broader than this profile.

See [contributing](CONTRIBUTING.md) for the bounded structural/security checks
and the selected runtime checks used by CI.

## License

MIT. See [LICENSE](LICENSE).

Continue with the [documentation index](docs/README.md).
