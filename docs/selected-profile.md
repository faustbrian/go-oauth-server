# Selected authorization-code profile

This is the experimental OAuth-server implementation's bounded profile, not
release qualification or completion of the full identity-platform OAuth goals.
The selected outcome is a real authenticated password-session user granting a
platform-owned public or configured confidential client a narrow resource authorization through explicit
consent, S256 code exchange, refresh rotation and revocation.

## Owning public boundary

Core owns protocol policy and typed requests/results. `postgres/` owns OAuth
durable state as a registered participant in the existing identity PostgreSQL
coordinator. It does not own a second transaction coordinator, authentication
engine, identity store, session issuer, capability journal or authorization engine.
Applications supply configuration and existing owned native adapters, not missing
domain orchestration. Service/store constructors perform no migration, credential
generation or network IO; the explicit startup verifier constructor generates
only its reviewed primitive's local digest key.

The selected runtime accepts immutable configured platform-owned public clients
with authentication method `none` and confidential clients with
`client_secret_basic`. Each confidential client has exactly one configured
canonical Base64URL-encoded 32-byte independently random secret at its exact
positive `Client.Version`. `NewClientSecretVerifier` borrows `password.Secret`
during construction; the application destroys its startup secret. The reviewed
`authentication/basic.Static` owner retains only keyed digests and performs actual
verification. No human-password hashing scheme or OAuth-owned crypto is added.
Unsupported methods/grants are rejected and never advertised.

This is **startup-only configured secret authority**, not durable client
administration, overlapping secrets, hot rotation or fleet-wide client/secret
revocation. Changing a secret or client configuration requires advancing that
client's version, replacing the service configuration and retiring all old
instances. Old grants cannot silently acquire the changed client policy. Retain
the original configuration and keys for outstanding original-command recovery;
that historical recovery remains metadata-only, not permission to issue. Adding
another configured client preserves unchanged clients' installed code/refresh
authority, but does not replace original configuration retention for recovery.
Current user/session/credential/authorization withdrawal and the shared issuer's
30-second bound remain mandatory; a startup secret snapshot does not weaken them.

## Typed operation catalog

These preserve the canonical `contract:operation:<operation>:v1` identities.
There is no HTTP registration in this root module.

| Operation | Public method | Typed input and outcome |
| --- | --- | --- |
| `identity.oauth-server.authorize` | `Service.Authorize(context.Context, AuthorizeRequest) (AuthorizeResult, error)` | Exact code/S256 request, tenant, borrowed original browser-session bearer and trusted network attribution. Genuine native session admission yields login-required or opaque consent-required interaction; no caller-supplied user/actor/owner override. |
| `identity.oauth-server.continue` | `Service.Continue(context.Context, ContinueRequest) (AuthorizeResult, error)` | Original continuation, same current browser/session, explicit issuer origin, synchronizer, consent decision and non-expanding scopes. Committed success yields one bound code response; denial redirects only to the originally validated exact target/state. |
| `identity.oauth-server.token` | `Service.Token(context.Context, TokenRequest) (TokenResult, error)` | Closed code or refresh variant, registered none/Basic client authentication and trusted transport network attribution supplied after form parsing. Code binds issuer/environment/client/exact redirect/S256/resource/user/scopes. Refresh narrows authority and rotates; reused parents revoke the family. Unknown/replay results disclose no fresh token. |
| `identity.oauth-server.revoke` | `Service.Revoke(context.Context, RevokeRequest) (RevokeResult, error)` | Possessed token and owning client authenticated under its registered none/Basic method; non-enumerating result. Revocation never revives a grant. |
| `identity.oauth-server.introspect` | `Service.Introspect(context.Context, IntrospectRequest) (IntrospectResult, error)` when explicitly enabled | Separately authenticated owning confidential client reads actual opaque access/refresh state. Disabled/public/method-downgraded callers deny before lookup; inactive, unknown and foreign tokens return only `Active=false`. No route or general resource-server authorization is selected. |

`AuthorizationRequest` and `TokenRequest` are parsed before credential work.
Every parameter is unique and grant-discriminated; missing required fields,
foreign variant fields, duplicate scopes, unsupported resources and method
downgrades fail closed. Code/verifier/refresh wire strings are borrowed,
redacted request custody. They must not enter scalar durable command fields,
logs, traces, snapshots or audit payloads.

`ClientAuthentication` is opaque borrowed credential custody, never a verified
principal or durable command field. Its zero value selects public `none` only.
`ParseTokenFormWithClientAuthentication` and `ParseRevocationForm` accept exactly
one Basic Authorization field for confidential clients and reject body client
identity/secret/assertion channels when that header is present. Each Basic
component is form-unescaped once as required by
[RFC6749 section2.3.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1),
after the reviewed HTTP extractor's strict bounded Base64 parse. Duplicate,
malformed, oversized, missing, cross-client or method-downgraded credentials
deny before durable effects; native direct calls repeat actual verification.
Applications reject URI credentials, require TLS, bound whole HTTP requests and
map `ErrInvalidClient` to the protocol's protected endpoint error response,
including the Basic challenge when appropriate. The library registers no route.

### Optional owning-client introspection

Set `Config.OwningClientIntrospection=true` explicitly and supply a Store that
also implements the optional `Introspector` interface; the PostgreSQL Store does.
The existing `Store` interface remains unchanged. Confidential-client
configuration alone does not select this feature. `ParseIntrospectionForm`
accepts only `token` and optional `token_type_hint` plus exactly one separate
Basic Authorization header. It rejects body credential channels and duplicates.
Recognized, incorrect and unknown hints cannot hide a supported token type, as
required by [RFC7662 section2.1](https://www.rfc-editor.org/rfc/rfc7662#section-2.1).

Only the authenticated owning client can learn an active token's actual issuer,
resource, client, subject, scopes and expiry. Public callers, inspected-token
possession alone and incorrect secrets never authorize lookup. The native reader
checks primary grant/artifact state and the original password source's
subject, directory, identifier, credential and authorization
authority through their public owners. An access revocation affects only that
access token; refresh-family revocation/reuse withdraws its descendants.
Ordinary browser-session logout does not revoke an independently approved OAuth
grant; credential or subject withdrawal still makes its tokens inactive.

Unknown, foreign, expired, withdrawn and inactive tokens return a successful
zero result. JSON encoding produces exactly `{"active":false}` with no reason or
other token metadata ([RFC7662 section2.2](https://www.rfc-editor.org/rfc/rfc7662#section-2.2)).
Operational authority failures and cancellation return redacted errors, never an
active result or stale fallback. No tokens, client secrets or source records are
returned. Each call is bounded and uncached; output is not reusable freshness
evidence and must not be promoted into a cache or renewed by copying. This does
not implement a resource verifier, JWT/OIDC, workload/exchange introspection,
hot client-secret rotation, fleet revocation or HTTP registration.

OAuth-owned `Token` is explicit reveal-once secret custody, not a session token
or one-use authority. It uses standard cryptographic entropy and hash-based
message authentication codes with SHA-256 for
lookup commitments bound to issuer, environment, client, purpose and key version.
Durable OAuth state owns protocol consumption; custody copies cannot restore
spent grants or renew a timestamp.

## Transaction and authority catalog

The selected operations inherit `tx.foundation` in the canonical transaction
contract. Server-owned random command identities, canonical keyed fingerprints,
preparation, generation, audit/outbox, commit classification and reconciliation
belong to `identity/postgres.Coordinator`. Protocol requests do not require a
proprietary `Idempotency-Key` header. OAuth-owned continuation/code/refresh
records bind their preallocated transition identities and exact preconditions.

Native composition consumes genuine `session.SessionService.Get` custody,
unchanged `GetResult.ValidateAt`/`ValidUntil`, session-owned
`OriginalSessionAdmission` and `OriginalSessionFields` mappings, and the public
primary directory/credential/authorization/session/CSRF checks on the original
coordinator Work. Preparation, protected mutation and final commit recheck current
applicable owners. No copied identity/session SQL, inferred active user, synthetic
MFA state or replacement local-session issuer is permitted.

The selected native policy requires the actual Privileged velocity counter
profile, with exact actor/resource/network dimensions and enforced lockouts.
Configured additional risk signals are rejected rather than silently dropped.
Each generated artifact retains its same-grant parent and issuing command;
durable storage contains keyed digests, not raw code or bearer credentials.

`postgres.Store.Recover` authenticates the original browser or client-bound
artifact and, for token/revoke, its current configured client authentication,
then returns only the original coordinator's outcome metadata. A lost
acknowledgement never authorizes re-execution or credential redelivery. Operators
must retain digest and envelope keys for every live grant or retained command;
changing active writer keys does not replace original authority or renew expiry.

### Native lifecycle owner catalog

These exact names extend the OAuth-server row in `LIFECYCLE_CASCADES.md` for
the selected opaque-token profile. Each primary event carries the actual grant
version transition, except access revocation, which carries that access record's
0-to-1 transition. Pending grant creation conveys no consent or token authority.

| Actual protected transition | Primary event |
| --- | --- |
| Create pending interaction/grant | `grant.created.v1` |
| Approve with actual persisted strict-subset grant scopes | `grant.scope_changed.v1` |
| Approve without changing persisted grant scopes | `grant.authorized.v1` |
| Consume code and create access/refresh children | `grant.code_exchanged.v1` |
| Consume refresh and create its access/refresh children | `grant.refresh_rotated.v1` |
| Deny pending interaction, detect reuse, or revoke refresh family | `grant.revoked.v1` |
| Revoke only the presented access record | `oauth_access.revoked.v1` |

Every approval additionally records an independent consent mutation in the same
Work and outbox: first creation emits `consent.created.v1` at 0-to-1; later
explicit approval emits `consent.reconfirmed.v1` at the actual positive version's
successor. Reconfirmation may replace the consent's explicitly approved scope
set and client policy version; it never silently approves another interaction.
Consent has its own server-random identity, not a grant alias. Secondary events
use subject type `oauth_consent`, that identity, the command's bound user and the
actual consent versions. Scope-change events are not emitted for unchanged sets.

Consumer impact: the new authorization/code/rotation/access/reconfirmation
notifications are informational lineage, not bearer delivery, identity proof,
cache validity or reusable authorization. Existing consumers of
`grant.revoked.v1` receive family withdrawal under that canonical name. Access
withdrawal is deliberately narrower; consent confirmation does not revoke or
create an unrelated token family. No authority/cache cascade, new acknowledgement
owner, private journal or arbitrary application-selected event is introduced.

Authorization and consent remain bound to the actual original browser/session.
Code and refresh credentials subsequently authenticate their OAuth grant rather
than requiring another browser cookie. They retain the original admitted root
credential/user/directory/policy epochs and recheck current applicable authority;
they cannot select a different customer, tenant or human actor.

## Protocol and acceptance catalog

The owning baseline is RFC6749, RFC7636 S256, RFC9207 issuer identification,
RFC7009 revocation, RFC7662 owning-client introspection and RFC9700 security, with the canonical
`PROTOCOL_BASELINES.md` restrictions. The official RFC7636 AppendixB vector is
the deterministic S256 oracle. Issuer/resource are configured exact HTTPS origins;
callbacks use exact registered HTTPS URI matching. Native loopback exceptions
and OIDC scopes are unselected, not silently normalized or interpreted.

Finite runtime acceptance must prove real PostgreSQL success, denial, rollback,
code and refresh contention/reuse, current-owner withdrawal, expiry, actual lost
commit acknowledgement/reconciliation, secret custody and a public consumer.
Access lifetime cannot exceed five minutes or its contributing grant lifetime.
Original source evidence timestamps cannot be renewed by copies or retries.
Root/family revocation must deny descendants; unavailable current authority denies.

This covers the selected M30 authorization-code/refresh profile only. It does
not close `journey.oauth-oidc-provider.v1`, the complete OAuth units, or all
shared-issuer SI01–SI10 cases. Client management, trusted consent, dynamic
registration, workload/client-credentials issuance, general resource-server
introspection, OIDC, device flow, organization delegation, API-key exchange and
shared-issuer cache/resource-verifier composition
remain unselected follow-on profiles with their original requirements intact.
Standard RFC8693 exchange and the private session-JWT extension remain distinct
unsupported grants; neither substitutes for the other or local-session issuance.
