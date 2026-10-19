# Changelog

## Unreleased

- Add the experimental public-subject ES256 code/S256 extension, minimized
  nonce/client/issuer-bound ID tokens, subject-only current-authority UserInfo
  and selected discovery/JWKS through existing native grant transactions and
  core-owned durable signing lifecycle.
- Reject ID-token issuance when no future whole-second expiry fits the native
  grant ceiling, retaining the unconsumed authorization code.
