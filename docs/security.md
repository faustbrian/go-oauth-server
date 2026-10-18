# Security model

This experimental profile is not a complete OAuth/OIDC provider or a supported
production release. The broader repository goal remains open; this profile does
not qualify shared-issuer resource verification/cache, workload, device, OIDC,
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
bearers, keys or encrypted preparation plaintext.

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

Introspection is unselected and fails closed: public client ID plus inspected
token possession cannot authorize RFC7662 disclosure. Confidential/workload
credentials, client management, signing-key administration, trusted/dynamic
consent, OIDC, device and delegation/exchange remain unsupported, not aliases.

Independent review, public dependency/consumer verification and applicable
release gates remain prerequisites for adoption. No production qualification
or whole-goal closure is asserted by this experimental surface. See
[SECURITY.md](../SECURITY.md) for private vulnerability reporting.
