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

Default DNS egress admits only public, nonspecial addresses; all answers must
pass, and dialing uses checked literal addresses to prevent rebinding. Optional
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

## Protocol and evidence scope

References: OpenID Connect Core 1.0 and Discovery 1.0, errata set 2. Only actual
code/query/S256/ES256, public subjects, selected pairwise policy and configured
client methods are advertised.
Core 3.1.3.6 does not require at_hash/c_hash for this token-endpoint-only ID token.
Prompt/max_age, other identity scopes,
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
