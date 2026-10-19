# Selected public-subject OIDC code profile

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
code/query/S256/public/ES256 and configured client methods are advertised.
Core 3.1.3.6 does not require at_hash/c_hash for this token-endpoint-only ID token.
Pairwise, prompt/max_age, other identity scopes, implicit/hybrid, request objects,
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

The new child and consumer modules need actual published-source pins before
clean-consumer/release qualification. Workspace evidence does not prove that
later public dependency adoption.
