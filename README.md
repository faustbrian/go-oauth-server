# go-oauth-server

> **Status: planned.** This repository does not currently provide an
> installable package, a released version, or a runtime API.

`go-oauth-server` reserves the planned Golib boundary for OAuth 2.1
authorization-server clients, authorization and consent, grants, token
issuance, refresh rotation, revocation, introspection, metadata, and signing-key
lifecycle. The plan keeps those concepts separate from extensions, storage,
resource authorization, and application concerns.

## Planned responsibility

The future root package is intended to own storage-neutral OAuth authorization
server policy, requests and outcomes, protocol transitions, and explicit
coordination through caller-supplied resources. Its contracts remain proposals
until they are implemented, reviewed, verified, and released.

## Non-goals

The planned root boundary does not own:

- OpenID Connect claims, discovery representation, or user information;
- device authorization flow or resource-server authorization policy;
- user interfaces or application routing; or
- database clients, migrations, transactions, caches, or background workers.

Those concerns may become separate modules or compose existing Golib packages.
Their presence in planning material does not make them available here.

## Lifecycle and ownership

Implementation, hardening, and release have not started. The current module
declaration exists only so repository tooling can validate the planned module
identity, family, ownership, and lifecycle metadata.

The plan requires caller-owned configuration and runtime resources, copied
mutable inputs, context-bounded external operations, and no package-owned
background work. These are design constraints, not claims about released
behavior.

## Planning and verification

The [repository goal](docs/goal.md) and `modules.json` record the planning scope
and schema-v2 engineering inventory. Planned lifecycle state excludes this
module from installable and released consumer catalogs. The local
`make cohesion` target validates that boundary with the exact checksum-pinned
`go-library-tools` release declared in `.golib.yaml`.

Passing repository checks proves only that the planning scaffold and metadata
are internally consistent. It does not prove OAuth behavior or an API.

Use Go 1.27.2 and the qualified public Tools v2.1.2 binary; the planned
module minimum remains Go 1.27.0. `make check`, `make ci` and `make fast-check`
validate configuration, repository structure, cohesion, offline specification
decisions, local documentation links and whole-tree/history secrets.
CI uses the same structural commands plus validated PR-base or push-before
changed-content secret checks on every change. Ordinary Required has a
five-minute job limit; changed secrets have a forty-second fatal timeout.
Scheduled/manual runs retain whole-tree secrets and online authority refresh.
`make check-full` explicitly preserves the previous full/online contract.
These commands do not run application tests or establish runtime/release proof.
See [contributing](CONTRIBUTING.md) for public tooling installation and scope.

The [planned security boundary](docs/security.md) records the assets, trust
boundaries, required controls, and release blockers that any future runtime
must satisfy. See [SECURITY.md](SECURITY.md) to report a vulnerability
privately; no released version is currently supported.

See the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/README.md)
and [package-family guidance](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/design-language.md#package-families-and-selection)
for the shared design language.

## License

MIT. See [LICENSE](LICENSE).

Continue with the [documentation index](docs/README.md).
