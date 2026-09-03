# Goal: planned go-oauth-server boundary

Status: planned

The coordination plan identifies `github.com/faustbrian/go-oauth-server` as the
future storage-neutral owner of OAuth 2.1 authorization-server clients,
authorization and consent, grants, token issuance, refresh rotation,
revocation, introspection, metadata, and signing-key lifecycle.

The source planning record is
`.ai/identity-platform/goals/oauth-server.md` in the Golib coordination tree,
with SHA-256
`fd9b2cb2cb832799f89ef727c9118be512a71eb156b819292109316accd69b50`.
That record contains proposed contracts; it is not implementation evidence.

## Current planning acceptance

- Keep this repository visibly planned and absent from installable consumer
  catalogs.
- Record the frozen Service Edge family, OAuth capability, ownership, and
  delivery lifecycle in schema-v2 engineering metadata.
- Validate the metadata locally and in hosted CI with immutable,
  checksum-verified `go-library-tools` v1.4.0 tooling.
- Do not claim a public package identifier, installation path, runtime API,
  compatibility promise, or released behavior.

## Deferred implementation

Source packages, nested modules, dependencies, protocol and API contracts,
behavior, hardening evidence, compatibility commitments, tags, and releases
remain outside this planning-only goal. They require separately authorized
work and their own executable acceptance evidence.
