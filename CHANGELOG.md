# Changelog

## Unreleased

- Add explicitly enabled owning-confidential-client RFC7662 introspection for
  opaque access and refresh tokens, with separate Basic caller authentication,
  inactive-only unknown/foreign results and bounded native current-authority
  checks. Introspection remains disabled unless selected independently of client
  configuration; it is not resource-server authorization or cache evidence.
- Extend the configured platform-owned web profile with confidential
  `client_secret_basic` authentication for code exchange, refresh, revocation
  and their metadata recovery. Secrets are startup-only primitive-owned digests;
  secret/configuration changes require a new client version and retirement of
  old instances, not hot rotation or fleet-wide revocation. Public clients remain
  supported. Require exclusive bounded OAuth Basic credential channels.
- Add the experimental public-web-client/password-session OAuth profile:
  exact redirect/issuer policy, explicit bound consent, S256 codes, opaque
  access tokens, rotating refresh and client-bound native revocation.
- Add bounded grant-discriminated parsing, OAuth-owned reveal-once token
  custody and historical/unknown outcomes without credential redelivery.
- Reject unselected grants, confidential issuance, OIDC/device profiles and
  unauthenticated introspection instead of advertising partial support.
