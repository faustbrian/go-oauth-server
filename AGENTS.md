# Engineering Policy

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC2119] [RFC8174] when, and only when, they appear in all capitals, as
shown here.

## Scope And Authority

- This file is the canonical policy for the complete repository.
- Package policies MAY add stricter domain rules but MUST NOT weaken this file.
- `CLAUDE.md` and tool-specific files MUST point here rather than duplicate it.
- Historical `.ai/GOAL*.md` files are requirements and evidence, not proof of
  completion. Fresh or valid reusable evidence is REQUIRED for each affected
  claim and material risk.

## Repository Structure

- The public root module MUST live at the repository root.
- Intentional optional or test modules MAY live in explicit nested directories.
- Commands MUST live under `cmd/`; private shared code MUST live under
  `internal/`; root automation MUST live under `scripts/`.
- Public module paths MUST match their repository-relative directories beneath
  the module path declared by the root `go.mod`.
- Every module MUST be declared in `modules.json`, and every package MUST be
  declared in `packages.json`.
- Independently releasable modules MUST retain independent `go.mod` files and
  directory-prefixed semantic-version tags.
- Cross-module dependencies MUST remain acyclic and MUST use public contracts.
- Permanent `replace` directives, sibling repositories, and absolute developer
  paths are forbidden in releasable modules.

## Design

- Prefer standard-library interfaces and explicit composition over hidden
  registration, global state, reflection-driven wiring, or service locators.
- Public APIs MUST make ownership, cancellation, retries, timeouts, resource
  limits, error semantics, and concurrency behavior observable.
- Interfaces SHOULD be defined by consumers and MUST remain narrowly scoped.
- Optional integrations SHOULD be adapters or nested modules, not mandatory
  dependencies of a core package.
- Breaking protocol or specification ambiguities MUST be documented as explicit
  decisions and covered by tests.

## Safety And Concurrency

- Shared mutable state MUST have one documented synchronization owner.
- Goroutines MUST have explicit lifetime, cancellation, and shutdown ownership.
  Fire-and-forget goroutines are forbidden.
- Channels MUST have documented ownership and closure rules.
- Locks MUST NOT be held across caller callbacks, network IO, blocking channel
  operations, or unbounded work.
- Every external operation MUST accept or derive a bounded `context.Context`.
- Response bodies, files, rows, transactions, timers, tickers, connections,
  and temporary resources MUST be closed on every path.
- Integer conversions, sizes, offsets, recursion, decompression, and allocation
  from untrusted input MUST be bounded before allocation or conversion.
- Secrets and credentials MUST NOT appear in errors, logs, traces, snapshots,
  fixtures, mutation reports, or generated artifacts.

## Testing

- Behavioral changes MUST include meaningful tests before completion.
- Tests MUST assert outcomes, invariants, errors, cleanup, and state transitions;
  line execution without behavioral assertions is not acceptable coverage.
- Coverage MUST be evaluated by behavioral risk, not a universal percentage.
- Mutation, race, fuzz, leak, performance, conformance, and external-service
  tests MUST run only when they exercise a material risk of the change or an
  applicable release boundary.
- Parsers and hostile boundaries SHOULD have focused fuzzing or deterministic
  regression cases when the changed input surface creates that risk.
- Concurrent code SHOULD use targeted race, stress, or leak tests when the
  changed behavior can expose concurrency or lifecycle failures.
- Specification claims SHOULD use pinned official fixtures or independent
  implementations when a material Tier C or Tier D conformance risk requires
  that evidence.
- Performance claims MUST use benchmarks that compare equivalent behavior and
  identify the material environment and corpus.

## Proportional Assurance

Every change MUST be classified before verification. Verification follows the
highest-risk material change in the batch, not the most expensive gate that
exists in the repository.

- **Tier A: documentation, metadata, and registration.** Validate the affected
  structure, links, examples, or generation; inspect the final diff; and use
  ordinary review when meaningful. Runtime mutation, broad fuzzing, race
  testing, reverse-consumer execution, and release rehearsal are not required
  unless the changed artifact is itself an executable public contract.
- **Tier B: internal behavior without a public contract change.** Run a focused
  behavior test, affected package or module tests, applicable formatting and
  static checks, and one complete review. A reasonably bounded repository gate
  SHOULD run; unrelated expensive checks MAY remain scheduled.
- **Tier C: public API, lifecycle, security, persistence, or concurrency.**
  Require an observable regression or characterization test, focused behavior,
  API compatibility where applicable, affected package and integration tests,
  direct owned reverse consumers reached by the changed contract, and one
  independent complete-diff review. Additional expensive gates MUST correspond
  to a named material risk.
- **Tier D: public release or ecosystem milestone.** Bind immutable release or
  milestone inputs once and run only the relevant compatibility, composition,
  consumer, release, and aggregate checks.

Race, fuzz, mutation, leak, performance, conformance, external-service,
clean-consumer, release-rehearsal, and aggregate fleet checks MUST NOT block an
unrelated change merely because the check exists.

## Required Commands

- `make inventory` validates repository and package manifests.
- `make check` runs the repository's bounded baseline contract.
- `make ci` runs the CI-selected contract for the classified change.
- Local commands and CI MUST use the same scripts and thresholds for the same
  selected gate.
- A missing prerequisite MUST fail only when it is required by the selected
  assurance tier or the material risk being exercised.

## Evidence Validity And Reuse

- The same claim SHOULD be proven once for the same immutable inputs. Evidence
  MAY be reused when the affected source, dependencies, tool behavior, and
  environmental assumptions are unchanged.
- Evidence reuse MUST record enough identity to establish applicability. It
  MUST NOT require complete temporary workspaces, routine execution logs,
  recursive provenance, or a new fingerprint for mutable planning prose.
- Commit hashes MAY be recorded for traceability. A history-only or unrelated
  metadata change MUST NOT force an expensive gate rerun when its material
  inputs are unchanged.
- After a change, rerun only the gates, modules, packages, and direct owned
  reverse dependants affected by the changed contract or named risk.
- Long-running work MAY checkpoint independently reusable results, but routine
  changes MUST NOT require checkpoint artifacts as a condition of completion.
- Evidence already bound to an immutable commit and CI run MUST NOT require a
  second provenance chain unless another trust boundary requires it.
- Hashes or content fingerprints SHOULD be required only for downloaded tools,
  public release assets, published compatibility receipts, final ecosystem
  source locks, immutable external specifications, or reused expensive evidence
  whose applicability depends on exact inputs.
- Hashes MUST NOT be required for mutable progress ledgers, ordinary plans,
  intermediate review notes, prose-only changes, or evidence already bound to
  an immutable commit and CI run unless another trust boundary requires it.
- Task-owned execution output, caches, temporary directories, containers,
  images, and volumes MUST be removed after their evidence is captured.

## CI And Workflows

- `.github/workflows/ci.yml` is the only owned GitHub Actions workflow.
- Package-local workflows MUST NOT be added.
- Actions and external tools MUST be pinned to immutable versions.
- Every selected module MUST have an attributable result. A durable evidence
  artifact is required only when it has a defined consumer or trust boundary.
- The stable required job MUST fail for failed, cancelled, skipped, or missing
  selected module results.
- Required checks MUST NOT use `continue-on-error`, `|| true`, permissive
  thresholds, or warning substitutions.

## Dependencies And Supply Chain

- Dependencies MUST be necessary, maintained, license-compatible, and pinned to
  reviewed compatible versions.
- Standard-library functionality MUST NOT be wrapped merely to create an owned
  abstraction; wrappers require a stable policy or portability boundary.
- Generated code and vendored corpora MUST record source, version, checksum,
  license, generation command, and update procedure when those artifacts are
  maintained or distributed.
- Vulnerability, secret, license, SBOM, provenance, and clean-consumer checks
  MUST be selected by the actual release risk. Required release evidence is
  generated once at the applicable public release boundary.

## Documentation

- Public identifiers MUST have useful Go documentation describing semantics,
  invariants, ownership, errors, concurrency, and caveats where relevant.
- Comments MUST explain why a constraint or non-obvious implementation exists;
  they MUST NOT narrate obvious syntax.
- Public modules SHOULD provide practical entry documentation appropriate to
  their consumers, such as a quick start, examples, adoption guidance,
  tradeoffs, security notes, or release notes where those sections are useful.
- Changed executable examples MUST compile. Other documentation MUST receive
  only the structural and link validation affected by the change.

## Changelogs

- Material user-visible behavior, compatibility, security, dependency, or
  deprecation changes MUST update the affected module `CHANGELOG.md`.
- Entries MUST describe behavior and migration impact, not internal activity.
- Internal engineering-policy, evidence, formatting, and administrative changes
  MUST NOT require a changelog or module release solely because they changed.
- Unreleased entries MUST NOT be silently rewritten or removed.

## Completion

- Run the assurance tier's narrowest sufficient affected gates during
  development and the relevant release gates only at a release boundary.
- Re-run affected gates after the final source, test, dependency, documentation,
  workflow, or generated-file change.
- Report exact commands and results. A skipped, blocked, stale, or warning-only
  required gate is not a pass; an unrelated unselected gate is not a blocker.
