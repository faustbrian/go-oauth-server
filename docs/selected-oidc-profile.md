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
grant/client subject. Browser logout keeps the existing approved-grant policy;
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

## Original authorization and fresh login

[OIDC Core 1.0 errata2 section3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
defines `prompt=login` and elapsed authentication age: `max_age=0` is equivalent
to requesting login, and `auth_time` is required with maximum age. This profile
selects exact `login` and the optional silent `none` profile below; `consent`,
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
(1s..24h) after replacing old accepting writers. Zero selects preactivation legacy
writers only: after activation every accepting writer must retain positive TTL;
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
never redelivers code or renews consent. Other prompts and combinations remain
unselected. Managed client mutations are not OIDC registration support; their
ordinary-grant controls do not prove an OIDC-management variant.

## Protocol and evidence scope

References: OpenID Connect Core 1.0 and Discovery 1.0, errata set 2. Only actual
code/query/S256/ES256, public subjects, selected pairwise policy and configured
client methods are advertised.
Core 3.1.3.6 does not require at_hash/c_hash for this token-endpoint-only ID token.
Other prompt variants and identity scopes,
implicit/hybrid, request objects,
logout, private session exchange, shared-issuer access-JWT/delegation and
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
