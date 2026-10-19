# Selected OIDC provider extension

This experimental module implements the finite public-subject, ES256,
authorization-code/S256 profile. It is not complete OIDC qualification.

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
Only openid is selected. UserInfo contains only sub; ID tokens contain issuer,
public subject, actual client audience/authorized party, issued/expiry time,
original password auth_time/amr and the original nonce when supplied. Resource
scopes add no identity attributes. Signature/issuer/audience/time/nonce and the
UserInfo subject must be validated by the relying party.

Signing requires core SigningService with the native durable SigningLifecycle,
not an isolated in-memory SigningAuthority. Private custody stays in core.
Install the forward signing migration first; publish/serve JWKS before explicit
activation. Retain the dedicated stable subject key: replacement changes all
subjects. Serve exact configured HTTPS endpoints, no-store token/UserInfo
responses and no positive JWKS cache across activation.

See [selected profile](../docs/selected-oidc-profile.md). Pairwise, prompt/max_age,
profile/email/address/phone/offline scopes, logout, private session JWT exchange,
shared-issuer access-JWT/delegation, HTTP/reference integration and complete
conformance/release qualification remain open, unadvertised and unstubbed.
