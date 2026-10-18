# Selected OAuth profiles

This is the experimental OAuth-server implementation's bounded profile, not
release qualification or completion of the full identity-platform OAuth goals.
The selected outcome is a real authenticated password-session user granting a
platform-owned public or configured confidential client a narrow resource authorization through explicit
consent, S256 code exchange, refresh rotation and revocation.
An additional explicit startup workload policy selects confidential
client-credentials access without a human/session/consent substitute.

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
| `identity.oauth-server.token` | `Service.Token(context.Context, TokenRequest) (TokenResult, error)` | Closed code/refresh web variant or explicitly configured Basic-only workload `client_credentials`; trusted transport network attribution is supplied after parsing. Code binds issuer/environment/client/exact redirect/S256/resource/user/scopes. Refresh narrows authority and rotates; reused parents revoke the family. Workload access binds only its trusted startup tenant/service account/resource/scope ceiling and never yields refresh. Unknown/replay results disclose no fresh token. |
| `identity.oauth-server.revoke` | `Service.Revoke(context.Context, RevokeRequest) (RevokeResult, error)` | Possessed token and owning client authenticated under its registered none/Basic method; non-enumerating result. Revocation never revives a grant. |
| `identity.oauth-server.introspect` | `Service.Introspect(context.Context, IntrospectRequest) (IntrospectResult, error)` when explicitly enabled | Separately authenticated owning confidential client reads actual opaque access/refresh state. Disabled/public/method-downgraded callers deny before lookup; inactive, unknown and foreign tokens return only `Active=false`. No route or general resource-server authorization is selected. |
| `identity.oauth-server.consent-get` | `Service.ConsentGet(context.Context, ConsentGetRequest) (ConsentGetResult, error)` | Current genuine password-session owner reads only its approved independent consent ID/version/client/scopes/time. Foreign, revoked or unavailable targets disclose no metadata. |
| `identity.oauth-server.consent-list` | `Service.ConsentList(context.Context, ConsentListRequest) (ConsentListResult, error)` | Current genuine session reads 1..64 own approved consents per page with a tenant/user/limit-bound opaque cursor. Pages use stable ID keyset order, not cross-request snapshot isolation. |
| `identity.oauth-server.consent-delete` | `Service.ConsentDelete(context.Context, ConsentDeleteRequest) (ConsentDeleteResult, error)` | Exact own consent/version, fresh current password session, issuer Origin and same-browser CSRF. Atomic consent-root withdrawal returns Deleted plus original Completion metadata, not unbounded grant IDs or bearer material. |
| `identity.oauth-server.discovery-oauth` | `Service.DiscoveryOauth(context.Context, DiscoveryOauthRequest) (DiscoveryOauthResult, error)` | Public read-only OAuth metadata when explicitly selected; no request-supplied issuer, host, client, tenant or capability override. |

### Optional authorization-server discovery

`Config.Discovery.Enabled` requires exact trusted authorization/token/revocation
endpoint URLs for the selected web profile. Endpoints must be distinct canonical
HTTPS paths on the configured issuer origin, with no query, fragment, userinfo,
percent/dot/slash normalization or discovery-route collision. This is a deliberately
narrow deployment policy, not a universal same-origin requirement of RFC8414.
Zero configuration is disabled; nonzero fields with Enabled=false are rejected.
Changing metadata endpoints does not rewrite existing grant/recovery authority.

The returned `DiscoveryOauthMetadata` is a caller-owned public JSON projection;
serve only that member as `application/json` at the issuer's
`/.well-known/oauth-authorization-server` URL. This library registers no route,
infers no Host and fetches no remote metadata. Consumers must validate the exact
returned issuer before trusting endpoint locations (RFC8414 section3.3) and
validate returned authorization `iss`/state before code exchange (RFC9207).

Metadata derives grants and methods from actual immutable configured clients:
web clients select authorization_code/refresh_token, code/query and S256 only;
workloads add only client_credentials. Workload-only services omit authorization,
PKCE and browser-issuer-response claims. This profile explicitly selects an empty
response_types_supported array: RFC8414 section2 requires the member, while
section3.2 requires empty claims omitted. [Reported erratum7793](https://www.rfc-editor.org/errata/eid7793)
proposes making the member optional when no grant uses authorization; it is not
an approved correction. The selected empty array is an interoperability policy,
not an unambiguous RFC requirement. Token/revocation methods are the actual none/Basic
union. Introspection is advertised only with explicit OwningClientIntrospection,
an eligible confidential client and its exact configured endpoint; its method is
Basic only. Inconsistent selections fail construction. Scopes are exactly the
effective OAuth ScopeCatalog, not a per-client privilege promise.

`authorization_response_iss_parameter_supported=true` describes the existing web
response behavior. The RFC9728 section4 `protected_resources` array contains exactly
Config.Resource so a client can select the same resource used in authorization,
code and token binding. This is authorization-server metadata, not protected-
resource metadata or a resource-verification/cache claim. No OIDC scopes, JWKS,
registration, device, exchange, client IDs, owners or secrets are published.

The independent native consumer uses `golang.org/x/oauth2 v0.37.0` (module checksum
and BSD-3-Clause source license) for AuthCodeURL, S256, Exchange and TokenSource.
It selects URLs, resource, supported scopes and authentication from actual
metadata, checks issuer/state, then traverses genuine signup/password-session,
explicit consent, exchange, refresh and discovered revocation. The bounded
in-process transport delegates to the real public native owners; it does not
replace domain authority or claim a production HTTP composition.

Protocol source provenance (official text fetched 2026-10-18; SHA-256 of exact
UTF-8/ASCII response bytes, recheck before changing these profile decisions):

| Source | Applied sections | Official text SHA-256 |
| --- | --- | --- |
| [RFC8414](https://www.rfc-editor.org/rfc/rfc8414.txt) | 2,3.2,3.3: metadata fields, JSON, exact issuer | `16c816e4e0fdbffb7e910ff3017867bf39debe9cb7f52f5cbc508a052ed660e8` |
| [RFC9207](https://www.rfc-editor.org/rfc/rfc9207.txt) | 2.3,2.4,3: issuer response and metadata flag | `c9c17b9824315aca9bda5c0b5e3627cb24aa28d54324292f3761006209b705fd` |
| [RFC9728](https://www.rfc-editor.org/rfc/rfc9728.txt) | 4: authorization-server protected_resources | `b65bcd0d9daf90fd7006a42cf48e0ac3ba24b7f5637d5197f2de41c6b91c8a89` |

### Optional own-consent management

The additive `ConsentManager` interface does not alter existing `Store`
implementations. Native `ConsentManagement` is separately selected after its
forward migration; workload-only composition cannot select human management.
`NewConsentCommand` owns a closed scalar read/list/delete projection and borrows
browser/CSRF custody. No command accepts an effective user or actor override.
`Consent` and `ConsentListPage` own copied immutable metadata; zero is invalid.
Cursor parsing alone establishes neither ownership nor authorization. Native
cursors authenticate the exact current tenant/user/page limit and never renew
original read validity. Get/list repeat genuine primary session/policy and
consent reads; a failed query is not an empty successful page.

Delete requires both the session owner's actual `Lifetime.Fresh` and an
exclusive 15-minute cap from original completed password authentication, as fixed
by `REFERENCE_CONFIGURATION.md`'s sensitive-operation `session.fresh_for` row.
General session FreshFor may be 24h; activity, issuance, rotation and another
session read cannot renew sensitive proof. This selected single-factor password
profile does not accept an invented fresh flag or repurpose a password-change
action proof. Preparation/apply/final checks retain original sealed admission,
current directory/user/credential/authorization/session and CSRF owners.

Each approved human grant binds the independent consent root and its generation.
Withdrawal advances that root's actual version/generation and state in the sole
coordinator Work. Every code/access/refresh admission and introspection observes
the current primary root; missing/revoked/mismatched consent denies, and outages
fail closed. No unbounded grant/artifact fanout establishes denial, and no
asynchronous cleanup completion is claimed. Explicit new approval may reactivate
the consent at its new generation, never rebind or revive older grants.
Current client version and full policy fingerprint remain exact; changing client
owner/resource/scopes without a version advance does not preserve stale consent.

Keep the original command ID after unknown withdrawal. Native `Recover` accepts
the consent-delete operation, original consent/client/tenant and current original
browser, authenticates retained preparation, and reconciles only original
durability metadata. It cannot withdraw again or redeliver credentials. Delete
repetition of the exact revoked version returns that same historical metadata;
a stale version cannot withdraw later reconfirmed consent.

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
not implement a resource verifier, JWT/OIDC, exchange introspection,
hot client-secret rotation, fleet revocation or HTTP registration.

### Configured workload client credentials

`NewWorkload(tenant, serviceAccountID, accessTTL)` creates opaque caller-owned policy
for a confidential platform-owned client's optional `Client.Workload`. Nil keeps
the existing browser/code/refresh profile, including its original durable client
fingerprint bytes.
`ValidateClient` and service constructors snapshot the entire workload value;
each adapter command receives an independent policy copy. Replacing a caller's
or adapter's whole value cannot alter retained policy or in-flight output limits.
A workload registration has no redirect URIs and accepts only
`client_secret_basic` and `client_credentials`. The closed Basic form accepts
only `grant_type`, optional `scope` and the sole configured `resource`; tenant,
subject, actor, human credentials, code/PKCE/redirect and refresh channels deny.
Omitted scope uses the registered ceiling; supplied scope can only narrow it.
Access expires at the earlier configured workload/issuer ceiling (at most five
minutes). No refresh is issued, following the selected policy for
[RFC6749 section4.4](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.4).
The platform and workload/tenant ownership are trusted startup arrangements, not
customer delegation or request-selected authority.

Native `Config.WorkloadAuthority` fixes the existing global directory ID and
authorization namespace in which workload IDs are unique across subject kinds.
The existing authorization owner must already hold that exact tenant/namespace/
service-account epoch; construction and reads never initialize it. Issuance
captures directory and workload authorization epochs from primary owners and
share-locks/rechecks them on the sole generation-bound Work before effects and
commit. Its command has an empty user, the real configured service-account
actor, and a server-owned grant ID as its anonymous issuance-flow correlation;
that correlation is not a workload/user identity. Current native policy and
Privileged velocity counters remain mandatory. Workload-only composition uses
no session configuration; mixed composition retains every original web fence.

Explicit owning-client introspection checks the actual root access record,
startup client/owner/tenant/resource binding and current primary workload epochs.
Its `Subject` is the service-account ID, never a human. Unknown, expired,
foreign, revoked and withdrawn tokens are metadata-free inactive; primary
authority outages deny rather than reuse an earlier positive result. The same
uncached original 20-second read bound applies. Basic-authenticated revocation
may still remove a token after epoch withdrawal; it never grants new authority.
Concurrent duplicate revocation can return `ErrUnavailable` with the actual
native conflict outcome while the original owner is unfinished. This does not
claim completion, rollback or permission to issue a replacement token. A later
call observing the revoked token returns the ordinary successful no-op. Applications use the
unavailable/retry semantics of
[RFC7009 section2.2.1](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.2.1),
not an invalid-client/access-denied response for this authenticated claim race.

Each fresh client-credentials call is a separate server-owned issuance, not a
caller-selected command or new idempotency journal. After an unknown result,
preserve its command ID and use native `Recover` with token operation, original
client Basic custody and **empty Token/Session/TenantID**. The existing encrypted
preparation authenticates the original configuration/flow before metadata-only
reconciliation; it cannot redeliver access or execute again. A live lease stays
pending. If the command did not commit, the result retains its original
dependency-failure error along with `NotCommitted`. Do not retry issuance to
resolve uncertainty. Original configuration/key retention and startup-secret
instance retirement still apply;
no durable secret management, hot rotation, fleet revocation or dynamic client
administration is selected.

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
the selected opaque-token profile. Each primary event carries its actual owning
record's version transition: the grant, independent consent root, or access
record's 0-to-1 withdrawal. Pending grant creation conveys no consent or token authority.

| Actual protected transition | Primary event |
| --- | --- |
| Create pending interaction/grant | `grant.created.v1` |
| Create configured workload grant and its root access | `grant.created.v1` |
| Approve with actual persisted strict-subset grant scopes | `grant.scope_changed.v1` |
| Approve without changing persisted grant scopes | `grant.authorized.v1` |
| Consume code and create access/refresh children | `grant.code_exchanged.v1` |
| Consume refresh and create its access/refresh children | `grant.refresh_rotated.v1` |
| Deny pending interaction, detect reuse, or revoke refresh family | `grant.revoked.v1` |
| Revoke only the presented access record | `oauth_access.revoked.v1` |
| Withdraw the independent approved consent root | `consent.revoked.v1` |

Consent withdrawal's primary subject is `oauth_consent` and its persisted
positive version advances once. Associated grants retain their historical
versions/lineage and lose authority through the root generation; no fictitious
per-grant `grant.revoked.v1` transitions are emitted. Consumers caching human
grant validity must consume `consent.revoked.v1` and compare that primary root
generation within the shared-issuer bound, not listen only for grant events.
Workload grants remain independent of human consents.

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

This covers the selected M30 authorization-code/refresh and configured workload
client-credentials profiles only. It does
not close `journey.oauth-oidc-provider.v1`, the complete OAuth units, or all
shared-issuer SI01–SI10 cases. Client management, trusted consent, dynamic
registration, general resource-server
introspection, OIDC, device flow, organization delegation, API-key exchange and
shared-issuer cache/resource-verifier composition
remain unselected follow-on profiles with their original requirements intact.
Standard RFC8693 exchange and the private session-JWT extension remain distinct
unsupported grants; neither substitutes for the other or local-session issuance.
