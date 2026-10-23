# Changelog

## Unreleased

- Select native RP-initiated logout with bounded standard parameters, verified
  issued hints and exact URI/state or local-only outcomes. Retained retired
  public keys can verify expired hints only for their still-current exact source
  session. Compromised keys deny; unknown/history never clear cookies or redirect.
  Front/back-channel, hintless UI and provider orchestration remain unselected.

- Select exact `prompt=consent` without conflating approval with fresh login.
  Preserve original maximum-age policy through the existing native interaction;
  prompt combinations and account selection remain unsupported.

- Opt into consented phone UserInfo with canonical `phone_number` and Boolean
  `phone_number_verified:true` from actual verified primary custody. Prefer the
  owner's verified primary, otherwise lowest IdentifierID; omit pending/revoked
  contacts. ID tokens and default scopes remain unchanged.

- Select exact `prompt=none` through the existing four-method extension. Require
  actual current authentication and original maximum-age bounds without login
  interaction or consent authority; native explicit approval remains mandatory.

- Select patched Go 1.27.3 for verification of GO-2026-6809 in `crypto/x509`.
  Consumers must also build with a patched toolchain; the API minimum is unchanged.

- Opt into consented email/email_verified UserInfo from current native
  identifier and verification authority. Prefer verified primary, then verified
  and pending contacts in stable ID order; omit absent/revoked email and deny
  invalid or stale custody. Default UserInfo and all ID tokens remain minimized.

- Evaluate selected login/maximum-authentication-age policy against genuine
  session custody, including explicit zero and an exclusive positive-age
  deadline. New password authentication completes the original native flow;
  signed `auth_time` comes from its actual adopted session-owner proof.

- Accept the core's HTTPS-validated multi-host sector registration through the
  existing subject-policy and original native binding, without a new child
  fetcher, policy namespace or derivation algorithm. Configure fetched core
  provenance before composition; URI host, not redirect host, selects sector.

- Add opt-in registered-single-host pairwise subjects using authenticated,
  versioned dedicated HMAC envelopes and native stable grant bindings. Key
  rotation/rewrap preserves existing RP identity and same-sub UserInfo; absent
  or foreign policy never falls back to public derivation. Other sector
  registration profiles remain unavailable.
- Keep constructed public/pairwise HMAC custody opaque to nested diagnostics
  without changing existing public subject bytes or the exported Config input.

- Add the experimental public-subject ES256 code/S256 extension, minimized
  nonce/client/issuer-bound ID tokens, subject-only current-authority UserInfo
  and selected discovery/JWKS through existing native grant transactions and
  core-owned durable signing lifecycle.
- Reject ID-token issuance when no future whole-second expiry fits the native
  grant ceiling, retaining the unconsumed authorization code.
