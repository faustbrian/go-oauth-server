# Restricted organization API-key delegation

This is an explicitly selected modern, uncached, unlimited-quota API-key source
and a separately configured confidential Basic client. It is not general
organization OAuth, legacy organization-key exchange, a managed-client profile,
JWT verification, positive caching or a human-session override.

## Composition and ownership

Use the actual native API-key `NewOrganizationService` with the existing
organization repository on the same primary. Its modern configuration must have
the exact OAuth issuer, environment and audience, and permissions within the
configured client/resource ceiling. Applications supply their normal policy and
owner configuration; no substitute organization store, authentication callback,
authority service or coordinator is needed.

Select native `OrganizationAPIKeyExchangeConfig` with the existing source
configuration and one fixed `OrganizationID`. Leave `Config.APIKeyExchange` nil
and use `NewOrganizationAPIKeyExchangeStore` / `NewOrganizationAPIKeyExchangeService`.
The request cannot select an organization, source configuration or tenant.
Existing `NewStore` / `NewService` remain USER-only; their public configuration
shapes and omitted-default identities are unchanged. The explicit organization
selector is bound into retained configuration/command/client-authority identity.

The API key is the actor. The tagged organization is its owner, and the separately
authenticated Basic client is its OAuth caller. None becomes a USER, workload,
creator session or consent. Creator membership is not the integration credential:
removing the creator denies that human's current key management and delegation,
but an otherwise-valid organization key continues to authorize its integration.
Remaining managers still need actual current organization management authority.

## Protocol and resource use

The existing RFC 8693 token exchange accepts the real modern key as
`urn:golib:params:oauth:token-type:api-key`. It issues opaque access only, never
refresh/ID tokens or a session. Access cannot expand the source/configured
resource or scopes; lifetime is bounded by the key, configured TTL and five
minutes. Access descendants retain the same owner/key/client/root and narrower
scopes, expire no later than their parent, and use the bounded depth ceiling.
The first token's parent is the actual key; later parents are actual OAuth
artifacts. No fake code/session or workload ancestry is installed.

Use native `NewOrganizationResourceVerifier` with a trusted
`OrganizationResourceVerificationConfig`: exact organization, tenant, issuer,
environment, configured client/version, resource and scope ceiling. Its reader
authenticates actual access-token custody and current source/client/root/parent
state. `Verify` returns an opaque `OrganizationResourcePrincipal` exposing typed
read-only owner, API-key actor, caller, tenant, resource and root/parent lineage.
Call `RequireScope` for the original demanded scope at the protected operation.
The application still owns its business policy. The principal is not a bearer,
replay grant, refreshed observation or reusable authentication factory.

Current primary reads retain the earliest original owner/key/token/client read
window. Copies do not reset freshness: positive evidence ends within twenty
seconds of the earliest contributing read start and earlier at any contributing
deadline. Key/organization withdrawal or OAuth parent revocation denies current
resource use, introspection and new descendants; child revocation does not revoke
an independent root. This profile stores no positive cache.

RFC 7662 introspection is separately authenticated owning-client metadata, not
resource authorization. An active organization token omits `sub`; it must not
invent a USER. A malformed nonempty subject is still rejected.

## Schema before activation

Append `OrganizationAPIKeyExchangeMigrationSource` after all seven installed
`APIKeyExchangeMigrationSource` steps. Reserve four unused successor versions.
Keep every installed migration byte unchanged. The library owns no deployment:
the caller must apply and verify the complete schema before selecting the new
profile or bootstrapping its independent Basic-client authority.

| Step | Operation and locking |
| --- | --- |
| 1 | Add tagged USER/organization owner CHECK `NOT VALID`; short ALTER lock, one-second lock wait. |
| 2 | Validate owner CHECK separately; bounded caller context, ordinary writes remain available. |
| 3 | Replace USER-only source CHECK with tagged nullable-owner shape `NOT VALID` and relax `user_id` NOT NULL; short ALTER lock, no row rewrite. |
| 4 | Validate the new source CHECK separately before profile activation. |

There is no backfill, table rewrite, new index, journal or destructive Down.
Original populated USER rows/writers and already-installed optional workload
shapes remain valid. Schema installation does not enable workload, device or
human capabilities and has no mandatory device dependency. Old USER-serving
instances may coexist, but must not receive organization-token traffic. Failed
lock acquisition or validation leaves a known prefix: inspect and resume through
the migration owner; never fabricate history. Bootstrap fails closed until both
new named checks are validated and `user_id` is nullable. Reverting application
selection leaves schema/history and durable rows intact; do not remove them or
route organization tokens to unaware binaries.

## Original unknown-outcome recovery

Keep the returned nonsecret `APIKeyExchangeUnknownError.Verification` handle and
original OAuth command. Use native `Recover` with the same authenticated Basic
client and original command/verification attempt. Existing encrypted preparation,
source reconciliation and coordinator owners recover metadata only: no original
key, access credential, principal, renewed timestamp or second effect is returned.
Wrong client, command or handle fails. After source withdrawal, an exact owning
caller may still recover historical original commitment; that metadata cannot
authorize a resource or create another token.

See the [USER profile](api-key-exchange.md) for the separate modern/default and
explicit imported legacy USER compositions, and the [native adapter](../postgres/README.md).
