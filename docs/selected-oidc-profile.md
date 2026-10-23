# Selected public and registered pairwise OIDC code profile

This finite M31 RP consumer is not full M31 or unit verification. Existing
OAuth-only configuration remains available without the child.

## Composition and authority

Install SigningMigrationSource at a fresh version appended to the exact selected
base/consent/workload history; preserve published migration bytes. Configure
OAuth resource Scopes separately from OIDCScopes, with openid explicitly allowed
for human clients. Workloads cannot acquire identity scopes.

Construct the native store, concrete core Service, core SigningAuthority and
SigningService(authority, store). Install copies private P-256 custody only into
core; PostgreSQL receives public JWKs. Construct oidc.Service(config, core),
publish/serve child.JWKS, then activate the published kid. The immutable
core.WithOIDC(child) result performs authorization/token calls. The four frozen
extension signatures and established Service struct remain compatible; older
goal wording proposing an interface does not replace the existing API. Core
imports no child.

Genuine password-session custody and consent precede a one-use code/S256
exchange. The child receives actual native human grant/client/issuer/scope/nonce
and original session-owner authentication time, not caller identity overrides.
Signed output exists only in invocation memory or the existing coordinator's
authenticated encrypted preparation. Only a fresh known commit delivers it;
historical/unknown recovery never redelivers credentials or renews time.
Selected code issuance floors the native access deadline to the ID token's
whole-second `exp`, shortening the original lifetime by less than one second.
The same deadline survives encrypted restoration, final post-key-lock expiry
fencing, persistence and return; it never rounds past native grant authority.

ID-token audience/authorized party is the actual authenticated client, not the
resource. A dedicated stable subject key hides the internal ID and gives public
subjects across this issuer/tenant's clients. UserInfo reads actual access and
grant/client state, original primary directory/user/credential/authorization,
selected consent and key compromise. OAuth state is rechecked after the original
authority read without positive caching, then the child compares the persisted
grant/client subject. Ordinary browser signout keeps the existing approved-grant policy;
credential/owner withdrawal and grant/access revocation deny UserInfo.

## Optional consented email UserInfo

Select `oidc.Config.EmailUserInfo=true` and configure the root extension catalog
and allowed human client scopes with both `openid` and `email`. The original
native consent/code/S256/token flow must approve email; an openid-only grant
still returns only `sub`. Discovery advertises email scope/claims only when
selected. ID tokens are unchanged, including their original public or pairwise
subject. No new migration is needed; retain installed identity identifier and
OIDC signing/pairwise histories and use matching core/child/native versions.

[OIDC Core1.0 errata2 sections5.1 and5.4](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
define email as preferred addr-spec, actual possession verification, and voluntary
UserInfo claims in code flows. The child selects verified primary email first,
then verified non-primary by lowest IdentifierID, then pending by lowest ID.
An actual pending verification maps to false; revoked records are excluded.
No eligible email omits both claims. Inconsistent or malformed owner custody
denies; the child never fabricates verification or normalizes owner bytes.
Email is not a stable identity key: RPs must use the unchanged verified `sub`.

The native adapter reads its existing identity primary repository, not a caller
callback or user-supplied email. It repeats identifier and original authority
reads and token/client/grant/consent/subject/key fences after projection work.
The earliest original OAuth, session, credential and primary-read-start+20s
deadline survives every read and child projection. There is no positive cache
or deadline renewal. An identifier-authority change denies the old grant;
revoke/remove/replace never silently changes its contact. Cancellation or owner
failure returns no partial subject or email. Approved-grant browser logout
policy remains unchanged.

## Optional consented phone UserInfo

Select `oidc.Config.PhoneUserInfo=true`, root extension scope `phone` and the
same allowed human-client scope. Explicit native approval is required. The
selected phone owner must commit actual purpose-bound OTP verification before
`phone_number_verified:true` can be disclosed. Pending and revoked contacts omit
both phone claims. Prefer the owner's per-kind primary among verified contacts;
otherwise choose the verified contact with lowest IdentifierID. Retain original
E.164 canonical bytes. This conservative selection is local policy permitted by
[Core1.0 errata2 sections5.1/5.4](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims),
not a claim that the specification requires this ordering or omission policy.

In code/access-token flows those scope claims are UserInfo-only. ID tokens stay
subject/authentication-only; independent RP validation and equal `sub` remain
mandatory. Email and phone can coexist; openid/email-only grants disclose no
phone. The existing primary identifier transport and earliest original
token/grant/session/credential/read-start+20s ceiling apply without another
cache, claims source, parser, grant engine or extension method. Current identity
authority changes deny original grants rather than silently substituting a
replacement contact; cancellation and owner errors return no partial claims.
No new OAuth schema is required; native phone workflow/OTP history remains the
identity owner's prerequisite, not a migration this extension installs.

## Original authorization and fresh login

[OIDC Core 1.0 errata2 section3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
defines `prompt=login` and elapsed authentication age: `max_age=0` is equivalent
to requesting login, and `auth_time` is required with maximum age. This profile
selects exact `login`, `consent` and the optional silent `none` profile below;
`select_account`, empty/duplicate values and combinations deny rather than being
ignored. `AuthorizationRequest.MaxAge` is optional uint32
seconds: nil preserves absence, a non-nil zero explicitly requires fresh login.
Request snapshots and encrypted preparation preserve that distinction.

When selected policy needs authentication, `Authorize` returns
`FreshAuthenticationRequired` and the existing opaque native continuation, not
an invented login URL or permission to issue a code. The application retains it
through actual password sign-in and submits the new session's cookie custody
and synchronizer to the existing protected `Continue`. The child requires a
different same-user/tenant session and authentication proof issued strictly
after the original native request. A timestamp, reissued session or a different
preexisting session is insufficient. Native Work checks current primary
directory/credential/authorization/session state for both original and new
sources and checks the submitted new cookie/CSRF. Original session withdrawal
or flow expiry prevents adoption; a successful new login does not revive them.

Without login or explicit zero, a still-young positive maximum age permits the
original session. Its exclusive age deadline is checked by native Work, including
after protected waits. Absence retains ordinary consent behavior. Old or
insufficient authentication returns `ErrLoginRequired` without issuing code.
Source adoption, consent and one-use code issuance share the existing sole
transaction. Original client/version/redirect/state/PKCE/nonce, pairwise binding
and exclusive flow deadline remain fixed; the code cannot renew that deadline.
Token preparation uses the adopted session owner's authentic `auth_time`.

### Explicit consent

Exact `prompt=consent` requires a new protected approval of the original request,
even when the same session/client/scopes already have reusable consent. It does
not itself require a new login: current genuine session custody remains usable
unless `max_age` requires fresh authentication. `Authorize` returns only the
opaque consent continuation (or the existing fresh-authentication continuation),
never a code from cached approval. An unaware/custom Store that skips this
interaction fails closed at core delivery.

Complete the original continuation through `Continue` with current original
session/CSRF authority, or the existing permitted same-account fresh-login
adoption. Explicit approval alone commits consent and a one-use S256 code;
denial creates no code/token and spends this interaction without revoking prior
approval. Tenant/client/subject, requested scope ceiling, callback/nonce,
pairwise binding and original exclusive deadlines stay fixed. Required effects
commit atomically; unknown or late outcomes and recovery remain metadata-only.
This selects no prompt lists, account selector, UI or new session/proof engine,
and needs no additional native schema beyond the selected existing profiles.

Select matching core/child/native versions for this optional profile. An older
adapter cannot silently drop login or explicit-zero/positive-age intent: known
initial results must echo the exact retained request, and a fresh child decision
requires the typed fresh-authentication result. Protected continuation adapters
must invoke the configured policy synchronously before Work. Core conserves
those observed decisions and the earliest positive-age deadline through Store
waits and return, without a new authority read or freshness renewal. Missing,
changed or ignored policy fails closed; absent-policy clients remain unchanged.
If a known native commitment returns after an authentication-age or original
code/continuation deadline, core withholds all code/continuation/redirect
material. The error remains `ErrLoginRequired` for authentication age and
`ErrUnavailable` for expired credential delivery, with only
`AuthorizationHistorical` and the original `CommandID`. Retain that ID for
`Recover`; no delivery error alone implies a pending interaction or rollback.

Spent continuations deny before reevaluating authentication, never creating a
new login loop. Ambiguous continuation commits are recovered as historical
metadata only through the existing coordinator: exact authenticated encrypted
preparation binds the attempting new session even when the grant's source update
rolled back. Old/foreign sessions cannot substitute. Committed recovery cannot
redeliver code; proven absence of commit retains the original dependency-failure
error alongside `NotCommitted`. Neither result starts another flow or renews time.
A distinct attempt is permitted only for actual terminal `NotCommitted` with
the shared kernel's closed `OAuthReauthenticationRequiredError` classification:
a genuine newer login may select another random attempt on the same original
continuation. The sole
coordinator rechecks the immutable predecessor receipt and advances the native
current-attempt pointer in its existing acknowledged-start transaction. It does
not reopen the old command or change the original token/request/deadline. Install
the shared kernel's forward `OAuthReauthenticationMigrationSource` before this
profile; pending, Unknown, committed and unrelated failures never permit handoff.
Original attempts remain independently recoverable through their authenticated
encrypted preparation after pointer advancement and service reconstruction.

## Optional registered pairwise subjects

The selected pairwise profile implements OIDC Core 1.0 errata 2 section 8.1's
registered redirect-host sector. `NewOIDCSubjectRegistration("pairwise", host,
policyID, policyVersion)` freezes one exact lowercase ASCII DNS host matching
every registered redirect. Alternatively, the HTTPS sector URI profile below
supports multiple registered redirect hosts. Registration is independent of public/confidential client
authentication. Nil registration preserves the original public subject and
client/grant/preparation framing; explicit registration includes all four policy
dimensions in validated JSON and client fingerprints.

### HTTPS sector identifier URI registration

[OIDC Core 1.0 errata2 section8.1](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)
uses the sector URI's host, not its path or the redirect hosts, as the sector.
[Registration 1.0 errata2 section5](https://openid.net/specs/openid-connect-registration-1_0.html#SectorIdentifierValidation)
requires an actual HTTPS fetch at registration and inclusion of every registered
redirect in the JSON array. A document may include other clients' redirects.

Construct root `NewSectorValidator` with the exact issuer/environment,
1..64 trusted `SectorEndpoint` URIs and a 1ms..5s total fetch budget. Call
`Validate(ctx, SectorRegistrationRequest{Client: client, URI: exactURI,
PolicyID: policyID, PolicyVersion: policyVersion})` before store/core admission.
Assign the result's `SubjectRegistration()` to that client and the opaque result
to core `Config.SectorRegistrations`. Every URI-backed client needs exactly one
matching proof; zero, foreign, stale client version, changed URI/policy/redirect
set and unused/duplicate proofs deny configuration. No caller-writable verified
flag or caller HTTP callback supplies this authority.

Default DNS egress admits only public addresses outside special-purpose ranges;
all answers must pass, and dialing uses checked literal addresses to prevent
rebinding. Optional
trusted `Addresses` pins replace DNS entirely and allow only those exact
destinations, including explicitly trusted private deployment endpoints. Never
derive pins or the endpoint allowlist from a protocol request. TLS authenticates
the original URI host even with pins. `RootCAs` selects the whole trust pool
(nil uses system roots), not an insecure certificate bypass. Configuration is
copied. HTTP proxies, redirects, cookies, credentials and compression are not
used. Responses require HTTP200/application-json, <=8KiB headers and <=64KiB
body, a flat array of 1..64 unique valid HTTPS callbacks of <=2048 bytes each.
Nested, duplicate, missing, malformed, oversized or downgrade data denies.
Caller cancellation is preserved; other remote/TLS/budget failures are redacted
`ErrAccessDenied` and produce no registration authority.

The comparable stored policy adds URI and a commitment to the exact sorted
registered redirect set. Legacy four-field JSON remains byte-compatible.
Stored URI JSON is structural identity, not retrieval evidence: reconstruct
opaque evidence with another real fetch when loading configuration. Unchanged
revalidation keeps the same client fingerprint and durable subject namespace.
Do not bump policy identity merely to re-fetch. Changed registration requires
revalidation and the existing client-version deployment/retirement discipline.
The spec requires registration-time validation, not periodic network renewal.
There is no transient proof TTL, background fetch, runtime availability
dependency or grant-stranding document-expiry state machine. Account/grant/
consent/revocation checks remain the existing uncached current-authority owners.

Append `PairwiseMigrationSource` at a fresh allocated version over the exact
existing migration history before enabling pairwise clients. Preserve the
dedicated public-subject key. For pairwise custody use distinct 32-byte HMAC key
material and secret-envelope/v2 binary envelopes. Associated data is exactly:
`profile=golib.oidc.pairwise-key.v1`, configured `issuer`, `environment`,
`policy_id`, decimal `policy_version` and decimal `key_version`.
`oidc.NewSubjectPolicy` opens/copies 1..8 retained envelopes (each at most16KiB)
under a five-second ceiling; construction activates no native capability.
Select the immutable result in child `Config.SubjectPolicy`, authenticate/stage
each `KeyRegistration` with native `InstallSubjectKey`, then explicitly
`ActivateSubjectKey`. Missing/foreign/unselected/retired custody denies.

Authenticated native Authorize Work atomically inserts a binding keyed by exact
issuer/environment/tenant/sector/internal-user context and associates the grant
before a consent code or ID token exists. Existing bindings win under contention;
client ID, policy key version and current writer are not identity namespaces.
HMAC-SHA256 uses `golib.oidc.pairwise-subject.v1` plus a NUL and four-byte
big-endian length-framed issuer/environment/tenant/sector/user values. Subjects
are base64url without padding. Neither raw internal IDs nor unrequested claims
are exposed. Code, refresh and UserInfo require the original native association;
missing associations never cause fresh derivation. Revocation retains bindings
so a later genuine grant does not reassign RP identity.

For rotation, stage a new key version, explicitly activate it, and reconstruct
child policy with that active version. Stale instances cannot create new bindings
under the old selection. Existing bound subjects remain unchanged, including
across same-sector clients. `SubjectKeyRegistrations` returns retained encrypted
custody and the actual selected writer for reconstruction. A same-version,
same-material `InstallSubjectKey` may explicitly replace its authenticated
envelope for rewrap; a different material commitment denies. Retire only an
inactive version. Shared policy selection fencing prevents pending Work crossing
activation/retirement; retired ciphertext is logically removed while the version
tombstone and subjects remain. Already bound grants need no old HMAC material.
This does **not** retire wrapping-provider keys: their removal still requires
the envelope owner's proof that every retained ciphertext has been rewrapped.
Changing subject-policy ID/version is not key rotation and does not authorize
reassignment or automatic policy migration.

Constructed child services/policies keep plaintext only in opaque HMAC closures;
nested diagnostics cannot traverse the key bytes. Exported raw Config inputs
remain explicitly sensitive caller-owned projections and must not be logged.

## Signing and failures

The durable registry has 64 lifetime kid slots including terminal tombstones.
Same-key registration is idempotent; conflicting material or retired/compromised
identities cannot reuse a kid. Publication precedes activation. Restart requires
reinstalling private custody but cannot reset publication, selection, compromise
or greatest reserved expiry. No private member is persisted or published.

Signing conservatively reserves maximum verification expiry. Rollback, timeout
or unknown acknowledgement can retain overlap longer, never shorten it or
deliver another token. The existing native token transaction fences compromise
before commit. Inactive retirement waits for all reserved expiry by database
time. Compromise overrides overlap and denies signing/UserInfo. Already cached
offline RP keys need explicit invalidation; ID tokens are not current resource
authorization. Key management is trusted deployment composition, not a new
tenant-facing management API/journal; full management authorization/audit/public
operations remain broader unverified-goal work.

## Optional silent authorization

[OIDC Core1.0 errata2 sections3.1.2.1 and3.1.2.6](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
require `prompt=none` to avoid authentication/consent UI, forbid combinations,
and define `login_required`/`consent_required`. Select the matching native
`ConsentExpiryMigrationSource` and explicitly configure `ConsentReuseTTL`
(1s..24h) after replacing old accepting writers. Zero selects legacy writers
only before activation; afterward every accepting writer must retain positive TTL;
mixed/zero-writer rollback is unsupported and migration history is not reversible.
Revoke consent to withdraw reuse. OIDC specifies
existing consent, not its lifetime; this conservative owner policy requires
bounded original explicit approval rather than inventing expiry for legacy
history. Legacy NULL expiry always requires a new explicit approval.

After genuine explicit consent, exact `none` creates a fresh one-use root code
without a continuation or approval mutation. Ordinary S256 exchange and the
independent RP verify the ID token and same-subject UserInfo. Current exact
session/maximum age, client/tenant/subject/resource/scope subset and consent
version/generation/expiry are repeatedly fenced, including after protected
waits and late work. Silent reuse, narrowing and a larger configured TTL never
renew original approval. Original read/session/credential/code/approval
deadlines remain exclusive; final reads cannot restart the <=20s observation.

Missing/withdrawn authentication or unmet maximum age returns `login_required`;
missing/expired/revoked/insufficient/stale-client approval returns
`consent_required`. Only a non-started condition becomes a standard validated
redirect with original state/issuer. Invalid redirects remain local; unknown or
late commands preserve their durability metadata without code/continuation or
redirect. Required-effect failure rolls back; original pre/post-COMMIT recovery
never redelivers code or renews consent. Other prompt values and all combinations
remain unselected. Managed client mutations are not OIDC registration support; their
ordinary-grant controls do not prove an OIDC-management variant.

## Native RP-initiated logout

Select native `RPInitiatedLogout` and configure `oidc.Config.EndSessionEndpoint`
plus the actual initiating browser's `SessionCookie` policy. The endpoint is a
trusted same-issuer URL distinct from authorization, token, JWKS and UserInfo;
unselected composition advertises none and denies invocation. This is an exported
native library operation, not an HTTP route or confirmation UI.

Install the forward OAuth `EndSessionMigrationSource` after signing history and
the session owner's `OIDCEndSessionMigrationSource` after single-session history.
Retain original migration bytes, keys, configuration, encrypted preparations and
terminal evidence. Upgrade all serving readers/writers before activation; an
unaware/off instance cannot enforce explicit termination against old grants, so
mixed/off rollback after activation is unsupported. The base OAuth schema does
not acquire mandatory logout/session bootstrap. Use matching published root,
child, native kernel and session-owner versions.
The forward unique source-effect index scans existing OAuth effect history and
uses a transactional, write-blocking build. Schedule that DDL with OAuth writers
quiescent and sufficient index/build headroom; no online-build claim is implied.
Only RP terminations add index entries; existing non-logout effects remain outside
its predicate. Deployment-specific build duration/storage remain operator inputs.

Each newly prepared selected **actually committed** ID token gets an immutable digest association
to its original issuer/environment, tenant/client/subject, signing key/source
session and original command locator, atomically with issuance. Existing minimized claims stay
unchanged; no `sid`, subject-equality heuristic or caller-selected session is used.
Preactivation hints have no association and deny; no history is backfilled.
An authenticated token response prepared before activation can complete its
original pending execution while its original admission remains valid. Its
signed bytes, expiry and preparation generation stay unchanged; it gains no
logout association. A newly selected preparation still requires the atomic
association. Activation does not regenerate older output or renew its authority.
Managed-client metadata conserves separately registered logout targets, but does
not expand the existing OAuth-only managed issuance profile into OIDC registration.

[RP-Initiated Logout 1.0 section 2](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout)
defines `id_token_hint`, `client_id`, `post_logout_redirect_uri` and opaque `state`.
This selected profile requires the genuine hint **and its exact current source
browser/CSRF** even without a redirect. A valid hint from session A cannot end
same-user/client session B. Root verifies strict ES256/JWT signature and current
eligible public key; child checks issuer/audience/authorized party/subject and
closed issued claims; native verifies actual durable issuance and original source
custody plus current client/account/credential/authorization/session owners.
Compromised keys deny. Retained previously published retired public material is
eligible without retired private custody. Expired hints are accepted only while
their exact original source remains currently valid; expiry is not recent-session
or absent-session permission.

`Client.PostLogoutRedirects` and the managed ceiling of the same name are independent
of authorization redirects. Matching is byte-exact with no normalization, prefix,
default callback or cross-client fallback. Only fresh known commitment returns
`redirect` with the exact supplied registered URI and original opaque state.
Without URI the result is `local-only`, with no redirect/state. Only these fresh
successes include session-owned deletion attributes; applications own transport.

The existing sole coordinator commits the exact session owner's invalidation,
protected `identity.oauth_server.end_session` audit and `session.revoked.v1`
lifecycle together. Siblings and family/user epochs are unchanged. Only this RP
purpose's retained tombstone withdraws source grant exchange/refresh/UserInfo and
resource authority; ordinary signout keeps its existing approved-grant policy.
Current primary reads and token Work fences do not cache absence or renew time.
Original hint-key read-start+20s, genuine session observation, credential and caller
deadlines remain exclusive; protected waits and final reads cannot restart them.
`VerifiedCompact.ReadStartedAt` exposes only the immutable original start, not a
lease. Public native calls retain the minimum of that sealed start and any
caller-supplied narrower start; changing deployment namespace cannot adopt an
old association or renew its observation window.

Ambiguous completion returns `unknown-reconciliation` with the original command
locator, never redirect/state/deletion or replacement permission. Native `Recover`
accepts operation `identity.oauth-server.end-session`, original command/client,
tenant, browser cookie and exact raw issued hint. Matching original cookie lookup
commitment, authenticated encrypted preparation and current result-access authority
permit historical observation **without re-authenticating the self-revoked session**.
No CSRF, new execution or fresh validity is inferred by recovery. Known matching
repeat is metadata-only local completion; pending/unknown repeat reconciles the
original command and cannot resume execution or redeliver a callback.

Static public/confidential human clients and registered public/pairwise subjects
remain distinct selected variants. Front/back-channel notifications, provider
orchestration, hintless UI, device/private exchange and generic HTTP/reference
integration remain separate unselected work.

## Protocol and evidence scope

References: OpenID Connect Core 1.0 and Discovery 1.0, errata set 2. Only actual
code/query/S256/ES256, public subjects, selected pairwise policy and configured
client methods are advertised.
Core 3.1.3.6 does not require at_hash/c_hash for this token-endpoint-only ID token.
Other prompt variants and identity scopes,
implicit/hybrid, request objects,
front/back-channel logout, private session exchange, shared-issuer access-JWT/delegation and
HTTP/reference integration remain open/unadvertised.

Native tests use test-only
[coreos/go-oidc v3.21.0](https://github.com/coreos/go-oidc/releases/tag/v3.21.0)
(Apache 2.0, Go 1.25 baseline) and its independent go-jose signature verifier.
That RP validates discovery/JWKS/signature/issuer/audience/time and parses
UserInfo. Its caller checks nonce on the verified token, following its documented
contract. Acceptance covers real password-session/consent, authority withdrawal,
rotation/restart overlap, revocation, native COMMIT faults and one-use contention.
This is not official conformance-suite or complete provider qualification.

These sector-URI additions need new actual published-source pins before
clean-consumer/release qualification. Workspace evidence does not prove their
later public dependency adoption; the earlier public and single-host pairwise
consumers remain separately qualified outcomes.
