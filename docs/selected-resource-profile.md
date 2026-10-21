# Selected direct opaque-access resource verification

This finite M30 profile is a direct, in-process resource consumer. It is not
whole M30 completion, generic resource authorization, JWT/JWKS verification,
remote introspection, protected-resource metadata, HTTP routing or reference
composition. Existing `Service`, `Store` and RFC7662 introspection behavior are
unchanged. In particular, `IntrospectResult.Active` can describe a refresh token
and must never be used as an access principal.

## Composition and trusted policy

Use native `oauthpostgres.NewResourceVerifier(pool, nativeConfig, keys, policy)`
with `oauth.ResourceVerificationConfig`. Trusted startup policy fixes the exact
issuer, environment, tenant, configured human client and version, resource
origin, supported OAuth-only `ScopeCatalog`, clock and bounded call duration.
Native construction rejects a different current client version; selecting one
is an immutable precondition, not permission to reuse older grants. Request
input can supply only borrowed `AccessToken` custody and one demanded `Scope`.
Neither request hosts, token hints, subject IDs nor caller-selected audiences
can retarget verification. Client Basic authentication belongs to issuance, not
the resource's access-token presentation.

Install the existing native consent history and select `ConsentManagement` on
every accepting human-token instance before enabling this verifier. Its
constructor rejects unselected consent fencing and workload clients. No new
migration, private authentication engine, authority table, callback policy or
transaction coordinator is introduced. Pools, clocks and key providers remain
borrowed and concurrency-safe; the verifier owns no goroutine or shutdown.

The root `ResourceAccessReader`/`ResourceAccessProjection` contract is a trusted
adapter seam, not an authentication credential or a recipe for applications to
invent authority. The native constructor captures policy in a private reader;
the reader accepts only token custody. The genuine consumer in
[`resource_integration_test.go`](../postgres/resource_integration_test.go) uses
actual registration, verification, password signin, confidential-client consent,
code/S256 exchange and an independent scope-bound resource read.

## Admission and result custody

Native lookup accepts only the actual access-artifact kind. The persisted
HMAC digest predicate cryptographically binds the original exact issuer,
environment, client and kind through `Token.Digest`'s existing domain-separated
length framing; values are not inferred from absent issuer columns. Exact
stored tenant, client/version, resource, active grant/artifact, consent generation
and approved scope ceiling must also match. Code, continuation, refresh, unknown,
expired, revoked, foreign and old-generation custody cannot produce a principal.
See [RFC6749 section 1.5](https://www.rfc-editor.org/rfc/rfc6749#section-1.5)
for the distinct authorization-server-only purpose of refresh tokens.

Original session provenance is decoded by its real native owner; current
directory, user/status, identifier, credential and authorization expectations
are read through their public primary owners. Later OAuth work is followed by
a repeated owner pass and final token/consent check. Browser logout alone does
not withdraw an explicitly approved OAuth grant, but actual user suspension,
credential withdrawal, token/family revocation or consent-generation change
denies subsequent verification without relying on cascade workers.

`Verify` returns an opaque `ResourcePrincipal` with no public constructor.
`RequireScope` must succeed immediately before the selected read. It permits
only the exact demanded OAuth credential scope, not every scope in the token
or arbitrary business access. Applications still own resource ownership and
business authorization; the metadata getters alone grant nothing. Zero,
serialized/reconstructed values, a different scope, a backwards clock before
the original read start or an expired result deny. Borrowed bearer custody and
native projections must never be logged or implicitly serialized.

## Freshness, failures and concurrency

Each `Verify` performs new primary reads; there is no positive cache or stale
fallback. Result expiry is the earliest original contributing token, grant,
credential or primary-read deadline, never later than read-start plus 20 seconds.
Copies and metadata access preserve that exact deadline. `RequireScope` uses
the verifier's original trusted clock, not a caller-provided time, and cannot
refresh evidence. Do not cache/reuse principals across resource operations;
verify current custody for each operation and consume its scope check promptly.
Bounded positive evidence is not an atomic lease over every later domain change.

Invalid custody returns `ErrInvalidResourceToken`; an unsupported or ungranted
scope returns `ErrInvalidScope`. Dependency failures return `ErrUnavailable`,
and cancellation/deadlines retain their context error. Every error returns a
zero principal. A transient read failure does not consume, revoke, issue or
otherwise mutate tokens or audit/outbox/journal state; retry performs only
another current read and cannot renew a previously returned principal.
Earlier caller deadlines win. Actual late withdrawal, token expiry, outage and
cancellation are exercised during native reads in
[`resource_authority_integration_test.go`](../postgres/resource_authority_integration_test.go).
