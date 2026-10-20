# Changelog

## Unreleased

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
