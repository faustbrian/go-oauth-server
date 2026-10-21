# Security model

[Documentation index](README.md)

This experimental profile is not a complete OAuth/OIDC provider or a supported
production release. The broader repository goal remains open; this profile does
not qualify shared-issuer resource verification/cache, dynamic workload/client
administration, device, OIDC,
organization or API-key behavior.

## Authority and atomicity

Protocol input, public client ID, parsed token, session record, command ID and
structural binding never grant identity or permission by themselves.
Authorization/consent require genuine current password single-factor custody,
the original browser and exact origin/CSRF. Native execution rechecks current
directory, credential, user-policy and applicable session owners before
generation, mutation and final commit. Code/refresh grants retain original
epochs and current grant authority without substituting another browser login.

The existing identity coordinator alone owns command identity, generation,
fencing, atomic mutation/audit/lifecycle, commit classification and recovery.
Code consumption and refresh rotation cannot commit without their related
effects. Reused parents revoke only their original family. Access revocation
does not revoke independent refresh authority. Unknown and foreign-client
revocation tokens are indistinguishable no-ops.

## Secrets and hostile boundaries

Inputs are bounded and grant-discriminated before credential work. Redirects
use exact registered HTTPS strings, S256 cannot downgrade, scopes cannot expand,
and issuer/environment/client/resource/purpose bind lookup commitments.
Only explicitly revealed fresh known-committed output may cross transport.
Requests and secret custody deny implicit serialization and redact formatting.
Never log transport bodies, cookie headers, synchronizers, codes, verifiers,
bearers, Authorization headers, client secrets, keys or encrypted preparation plaintext.

Configured confidential clients use exactly one independently random 32-byte
secret and the existing reviewed Basic verifier's keyed-digest retention. The
startup `password.Secret` is borrowed only during construction and remains the
application's destruction responsibility. OAuth Basic components are individually
form-unescaped once; body/URI secret channels, multiple headers or authentication
locations, method downgrade and cross-client credentials are rejected. Both core
and direct native token/revoke calls verify actual credentials before effects;
metadata recovery also authenticates the selected client without issuing again.
No raw Basic credential enters the native command or encrypted preparation.

Durable OAuth tables store keyed digests, not bearer wire values. Generated
delivery custody is retained only in existing secret-envelope preparation,
authenticated to original configuration, command and generation. Go does not
guarantee erasure of string copies. Keys and requests remain caller-owned;
retain required versions until outstanding grants and recovery are retired.

## Deployment obligations and exclusions

Applications own TLS, trusted network attribution, routing/UI, endpoint rate
limits, key custody, supported PostgreSQL, native migrations and resource-server
authorization. No routes, workers or resource-token verifier are implicitly
installed. Base PostgreSQL composition requires no device flow.

Introspection is disabled by default. Explicit owning-client selection requires
separate confidential Basic authentication before lookup, current native source
authority and metadata-free inactive results. Public client ID plus inspected
token possession cannot authorize RFC7662 disclosure. Confidential Basic authority
is a startup snapshot: secret/config changes require a new client version and
retirement of old instances. It does not provide hot rotation, durable secret
management or fleet-wide secret revocation. Current subject/session/credential
withdrawal fences still apply. Explicit configured workload credentials instead
bind an immutable platform, tenant, service account, resource and access ceiling;
they create no human, session or consent and cannot request refresh. Their
directory and workload authorization epochs remain current-primary checks.
See the [selected workload policy](selected-profile.md#configured-workload-client-credentials)
and install its typed forward migration before enabling it. Client management
outside the separately selected finite platform-owned profile is unsupported.
That [native profile](../postgres/README.md#optional-bounded-secret-rotation)
supports one bounded predecessor only for new-version grants: rotation advances
actual client authority and invalidates all older grants/consent. It retains
original matching-slot/deadline custody through waits, never an error-only
preflight or a renewed snapshot as late authentication authority.
Signing-key administration, trusted/dynamic
consent, OIDC, device and delegation/exchange remain unsupported, not aliases.

Independent review, public dependency/consumer verification and applicable
release gates remain prerequisites for adoption. No production qualification
or whole-goal closure is asserted by this experimental surface. See
[SECURITY.md](../SECURITY.md) for private vulnerability reporting.
