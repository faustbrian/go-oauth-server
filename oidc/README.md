# Selected OIDC provider extension

This experimental module implements public and registered pairwise
subjects for the finite ES256 authorization-code/S256 profile. It is not complete
OIDC qualification.

Declare Config.OIDCScopes with NewOIDCScopeCatalog([]string{"openid"}) and
allow openid in selected human clients. Build the native store and established
concrete *oauthserver.Service; construct this child with NewService(config, core),
then use core.WithOIDC(child) for OAuth authorization/token calls. The original
core rejects extension issuance. This preserves Service struct compatibility,
reconciling historical goal wording about a proposed Service interface.
The transport explicitly selects core ParseAuthorizationQueryWithOIDC; the
ordinary OAuth parser still rejects nonce and other unselected fields.

The child implements exactly the frozen four-method OIDCExtension. Claims
consumes trusted native grant results, never token forms/client credentials.
By default only openid is selected and UserInfo contains only sub. ID tokens contain issuer,
selected subject, actual client audience/authorized party, issued/expiry time,
original password auth_time/amr and the original nonce when supplied. Resource
scopes add no identity attributes. Signature/issuer/audience/time/nonce and the
UserInfo subject must be validated by the relying party.

## Optional consented email UserInfo

Set child `Config.EmailUserInfo=true`, declare root `Config.OIDCScopes` with
`NewOIDCScopeCatalog([]string{"openid", "email"})`, and allow both scopes for
the selected human client. Explicit native consent must include email. This
adds only `email` and `email_verified` to UserInfo and discovery, never ID tokens.
The native adapter supplies its actual primary identifier/verification partition;
applications do not supply email strings or a claim callback.

Selection prefers the verified primary email, then the verified email with the
lowest IdentifierID, then the pending email with the lowest IdentifierID. Pending
means `email_verified:false`, not a claimed possession proof. Revoked contacts
are never selected; no eligible contact omits both claims. Canonical addr-spec
bytes remain unchanged. Identifier changes invalidate original identifier
authority, so existing grants deny instead of silently adopting a new contact.
All errors/cancellation return zero claims; the original earliest native
20-second/credential/session/token deadline is never renewed by projection.

## Optional consented phone UserInfo

Set `Config.PhoneUserInfo=true`, include `phone` with `openid` in the root
extension catalog and selected human client, and obtain actual native consent.
The phone owner must first commit `SendVerification` and purpose-bound OTP
`Verify`; a pending SMS challenge or sender callback is not possession proof.
The child receives the existing native identifier snapshot, not an application
phone string or verification flag. Select compatible public native owner versions
and installed phone/OTP histories before enabling that composition.

Only UserInfo receives `phone_number` and Boolean `phone_number_verified:true`;
ID tokens remain minimized. This conservative profile omits pending/revoked
phones, preferring the owner's per-kind primary among verified contacts and
otherwise the lowest IdentifierID. E.164 canonical bytes remain unchanged.
Both optional email and phone may be selected without replacing either claim
projection. Openid-only and email-only grants disclose no phone.

The original earliest native validity deadline and all grant/client/consent/
subject/key fences remain unchanged. Native identifier-authority advancement
denies old grants rather than silently adopting another number. Relying parties
must independently verify the ID token and compare UserInfo `sub`; the phone is
not a stable identity key. This finite extension is not full M31 qualification.
See [OIDC Core sections5.1 and5.4](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims).

Signing requires core SigningService with the native durable SigningLifecycle,
not an isolated in-memory SigningAuthority. Private custody stays in core.
Install the forward signing migration first; publish/serve JWKS before explicit
activation. Retain the dedicated stable subject key: replacement changes all
legacy public subjects. Serve exact configured HTTPS endpoints, no-store token/UserInfo
responses and no positive JWKS cache across activation.

## Optional pairwise policy

Register `Client.SubjectRegistration` with `NewOIDCSubjectRegistration` and an
immutable policy ID/version. Without a sector URI its host must match **every**
registered redirect host. For multi-host redirects, root `SectorValidator`
fetches the exact registered HTTPS URI and checks the actual redirect set;
select its policy and opaque evidence in root configuration before constructing
the native store/core. URI host becomes the sector, not individual redirect
hosts. `Client.Public` still means authentication, not subject type.

Supply dedicated 32-byte HMAC material encrypted with the existing envelope
owner. `NewSubjectPolicy` authenticates/copies up to eight retained envelopes;
its Go documentation specifies exact issuer/environment/policy/version AAD.
Select it through `Config.SubjectPolicy`. Install the native forward pairwise
migration, stage authenticated `policy.KeyRegistration(version)` through the
native store and explicitly activate that writer before serving pairwise grants.
No caller supplies a domain store or private session/grant engine.

Native authenticated Authorize Work resolves one stable subject before signing.
Existing bindings win across clients in the same sector, new grants, restart and
key rotation; different sectors are unlinkable. Original code/refresh/UserInfo
grants use that binding, never rederive it under a new key. Key version is writer
custody, not an identity namespace. Native encrypted key readback reconstructs
the policy. Explicit same-material envelope rewrap and inactive-key retirement
preserve subjects; retired versions cannot be resurrected. Do not change policy
identity/version merely to rotate a key. See the detailed adoption/security
contract in the [selected profile](../docs/selected-oidc-profile.md).

Constructed services/policies retain plaintext HMAC material only behind opaque
closures. Exported `Config.SubjectKey` is still explicit sensitive caller input:
do not log or nest-format caller-owned configuration or plaintext buffers.

Selected `prompt=login` and optional `max_age` use the original native
authorization continuation. `nil` age is absent; explicit zero requires a new
password authentication. Retain the opaque continuation while signing in, then
submit it with the new current session and its synchronizer. A timestamp or
refreshed old session is not proof; the native owner fences both sources and
the child evaluates freshness. See the [selected profile](../docs/selected-oidc-profile.md#original-authorization-and-fresh-login).

Exact `prompt=none` instead requires current genuine session custody, satisfied
`max_age` and native original unexpired explicit approval. It returns a fresh
one-use code without interaction or consent mutation, or a validated
`login_required`/`consent_required` redirect; invalid redirects stay local. Select
the native forward expiry history and `ConsentReuseTTL` explicitly before use.
The child supplies authentication policy, never consent permission. Silent
requests cannot be completed through `Continue` or combined with other prompts.

Other prompt variants,
profile/address/offline scopes, logout, private session JWT exchange,
shared-issuer access-JWT/delegation, HTTP/reference integration and complete
conformance/release qualification remain open, unadvertised and unstubbed.
