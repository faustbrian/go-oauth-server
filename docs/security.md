# Planned security model

This repository contains planning metadata only. It has no runtime package,
public API, parser, persistence adapter, network operation, background work, or
supported release. The controls below are release requirements, not claims
about implemented behavior.

## Assets and trust boundaries

The planned core will protect authorization codes, access and refresh tokens,
client credentials, signing-key references, grants, consent, registered
redirect URIs, scopes, issuer metadata, and revocation state. Trust boundaries
will include authorization and token endpoint inputs, client authentication,
resource-owner decisions, caller-supplied stores and signers, introspection and
revocation callers, metadata rendering, and any protocol adapters.

Applications will continue to own user authentication, transport security,
route and database authorization, tenant isolation, persistence transactions,
rate limiting, audit delivery, key custody, and user interfaces. The core must
not infer those capabilities from ambient process state.

## Required controls before implementation or release

- Parse every untrusted request through endpoint-specific byte, field, item,
  scope, URI, and diagnostic ceilings before allocation or normalization.
- Require exact registered redirect matching, authorization-code single use,
  PKCE verification where applicable, explicit client authentication policy,
  bounded token lifetimes, and fail-closed grant and scope evaluation.
- Keep client secrets, authorization codes, refresh tokens, access tokens, key
  material, and raw requests out of errors, logs, traces, fixtures, snapshots,
  and generated evidence.
- Make token issuance, authorization-code consumption, refresh rotation,
  revocation, and consent transitions atomic through caller-owned persistence;
  expose classified durable-outcome ambiguity rather than retrying blindly.
- Require a non-nil caller context for external work, propagate cancellation
  and deadlines, close every acquired resource, and start no unowned goroutine.
- Copy mutable inputs, make concurrency ownership explicit, compare secrets in
  constant time where secrecy depends on comparison, and use cryptographic
  randomness only through an explicit bounded source.
- Authenticate introspection and revocation callers, prevent cross-client and
  cross-tenant disclosure, and return stable protocol errors without reflecting
  secret-bearing input.
- Bind supported OAuth profiles and security decisions to versioned standards,
  conformance fixtures, hostile tests, fuzzing, resource evidence, dependency
  and source scanners, and direct-consumer verification.

## Release disposition

**OAUTH-SERVER-RISK-001 — unimplemented security boundary**

- **Severity:** critical if treated as deployable.
- **Disposition:** release blocker; not accepted for production.
- **Owner:** go-oauth-server maintainers.
- **Rationale:** no executable contract currently enforces the planned OAuth,
  credential, token, persistence, cancellation, or resource invariants.
- **Mitigation:** keep the module planned, unpublished, non-installable, and
  non-releasable; consumers must use an independently supported implementation.
- **Review condition:** reassess only after implementation, a complete threat
  model, executable hostile and conformance evidence, scanner results, API and
  migration policy, and independent Tier C review are present.
