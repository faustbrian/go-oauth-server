# go-oauth-server

Experimental authorization-code/S256 OAuth protocol contracts
for configured platform-owned public and Basic-authenticated confidential web clients and genuine password
single-factor user sessions. This is not a complete OAuth/OIDC provider or a
stable released API.

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
  consent interaction, never a code before consent.
- `Service.Continue` checks the exact original browser, synchronizer, issuer
  origin and non-expanding scopes before a one-use code response or denial.
- `Service.Token` exchanges an exact client/redirect/S256 code or rotates a
  refresh token. Reused parents revoke their related family.
- `Service.Revoke` handles owning-client token possession. Unknown and foreign
  tokens are indistinguishable no-ops; access revocation is narrower than
  refresh-family revocation.
- `Service.Introspect` is disabled by default. Explicit
  `OwningClientIntrospection` selects separately authenticated confidential
  clients inspecting only their own actual opaque access/refresh tokens.
  Public client ID or inspected-token possession alone never authorizes lookup.

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
are selected. Each confidential client uses one fixed random 32-byte startup
secret; changes require a new client version and retiring old service instances.
This is not hot rotation or fleet-wide client/secret revocation. Workload
issuance, client administration, OIDC,
device flow, organization delegation, API-key exchange and
resource-server verification/cache composition remain
unsupported. No vendor authorization engine is embedded.

See the [selected contract](docs/selected-profile.md),
[security model](docs/security.md) and [changelog](CHANGELOG.md).
The complete [repository goal](docs/goal.md) remains broader than this profile.

See [contributing](CONTRIBUTING.md) for the bounded structural/security checks
and the selected runtime checks used by CI.

## License

MIT. See [LICENSE](LICENSE).

Continue with the [documentation index](docs/README.md).
