# Engineering Policy

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC2119] [RFC8174] when, and only when, they appear in all capitals, as
shown here.

This file is the canonical, self-contained repository policy. `CLAUDE.md` and
tool-specific instructions MUST point here. Historical plans remain product
requirements/evidence, not an alternate execution workflow or proof of completion.

## Shared Repository Development Workflow

This self-contained workflow is identical in every repository's `AGENTS.md`.
Repository additions MAY define concrete domain contracts and named risks, not
another lifecycle, gate sequence, review count or evidence framework. This
user-approved Golib workflow replaces conflicting inherited procedural defaults,
not correctness, security or mandatory CI. Explicit user authority and higher-
priority system/developer instructions remain controlling.

### Scope and verification

- Before writing, identify the outcome, owner, affected contracts/direct
  consumers, named risks and smallest sufficient checks in one compact plan.
  Preserve existing work; separate role factories, signed lifecycle receipts
  and recursive approval chains MUST NOT be routine stages.
- Classify the semantic change, not its filename or line count:
  - **Tier A:** non-runtime prose/metadata/registration: affected structure,
    links, examples/generation and final-diff inspection.
  - **Tier B:** internal behavior: focused regression, affected package/module
    tests, applicable format/static checks and one complete review.
  - **Tier C:** public API, lifecycle, security, persistence or concurrency:
    regression/characterization, affected integration/API/direct-consumer
    proof and one independent complete-final-diff review.
  - **Tier D:** release/milestone: relevant immutable-input compatibility,
    composition, public-consumer and release-integrity proof.
  Metadata, dependency, workflow and policy edits MUST retain their actual
  security/trust checks; names/extensions MUST NOT conceal executable changes.
  Actions and external tools MUST use immutable pinned identities. Preserve
  authenticated inputs, least privilege and untrusted-PR/release separation.
- Behavioral fixes MUST demonstrate the regression and corrected behavior.
  Tests assert outcomes, invariants, failures and cleanup, not just line counts.
  Behavioral PRs use affected tests, fuzz seeds/saved crashes and applicable
  static/security checks; changed hostile inputs add bounded active fuzzing.
  Cheap changed-content secret checks remain applicable to every change.
- Mutation campaigns MUST NOT run on PRs or become required PR statuses.
  Optional local mutation and bounded selected main/scheduled assurance remain
  separate. Race/leak, fuzz, service, conformance and performance checks require
  a named risk/release boundary. Material concurrency/lifetime changes MUST
  retain targeted race/leak proof; conformance claims MUST use applicable pinned
  official fixtures and independent oracles; performance claims MUST compare
  equivalent workloads with reproducible environment/corpus evidence.
  Selected timeouts, partial results and viable survivors are not passing
  proof; equivalent/invalid mutants need narrow independently reviewed proof.
  Coverage scores MUST NOT replace behavioral adequacy or waive required gates.

### Commands, review and evidence

- Choose actual commands from `CONTRIBUTING.md`, the Makefile and CI; run native
  focused tests in the affected module. Use the bounded local target where
  provided. `make check`/`make ci` MUST NOT be assumed cheap or made universal
  full qualification. Local/CI executions of the same selected gate preserve
  its scripts/thresholds. Missing prerequisites fail only an applicable gate.
  NilAway remains advisory with visible findings; mandatory failures stay fatal.
- One independent complete-final-diff review is the default for meaningful
  Tier C/D work; more reviews require a distinct named high-risk domain. Fix
  material findings, rerun affected checks and review the changed final diff,
  without restarting planning for clerical changes.
- Reuse evidence only when material source, dependency, fixture, tool and
  environment inputs still prove the same claim. Retain original identity and
  result; ambiguous/forged/partial evidence is not proof. A new SHA or mutable
  prose MUST NOT force broad reruns or provenance chains. Keep real integrity
  checksums, signatures, source locks and atomic publication at their actual
  supply-chain/reuse boundaries.
- Required aggregation MUST reject failed, cancelled, missing or skipped
  applicable work and classifier failures. Inapplicable work is not a passed
  check. Protection, scanner and dependency-authentication bypasses are forbidden.

### Delivery and resources

- Work/releases stay on main using the pinned Go 1.27 toolchain, required major
  module/import suffixes and Git tags, not versioned source branches/directories.
  CI-only protected-main carriers require applicable authority and advance the
  exact green reviewed source. Preserve user work, stage explicit owned paths
  and honor push/publication/destructive safeguards; carry approvals within scope.
  No routine amend, force-push, history rewrite or hook bypass is permitted.
- A changed repository is handled only on remote main with applicable exact-
  source CI green. Required releases also need published tags and actual clean
  public consumers. Pure internal policy/prose without consumer-visible contract
  impact MUST NOT force changelogs, repins or releases. Material consumer changes
  require the affected changelog before publication; preserve Unreleased entries.
- Agent Go runs MUST use task-owned `GOCACHE`, `GOMODCACHE` and `GOTMPDIR`,
  reused within a bounded local session rather than rebuilt per adjacent command.
  Clean exact owned caches/resources on success, failure and interruption;
  never remove user/shared resources. Serialize local heavy runs and honor
  hosted-only system-risk restrictions.
- Distinguish local, committed, pushed, CI-qualified and released states. Report
  failures, skipped checks and unverified boundaries; reused proof MUST NOT be
  described as newly executed.

## Repository Structure

- The public root module MUST live at the repository root.
- Intentional optional or test modules MAY live in explicit nested directories.
- Commands MUST live under `cmd/`; private shared code MUST live under
  `internal/`; root automation MUST live under `scripts/`.
- Public module paths MUST match their repository-relative directories beneath
  the module path declared by the root `go.mod`.
- Every module MUST be declared in `modules.json`, and every package MUST be
  declared in `packages.json`.
- Independently releasable modules MUST retain independent `go.mod` files.
  Root-module tags use `v<version>`; nested-module tags use
  `<module-directory>/v<version>`.
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

## Dependencies And Supply Chain

- Dependencies MUST be necessary, maintained, license-compatible, and pinned to
  reviewed compatible versions.
- Standard-library functionality MUST NOT be wrapped merely to create an owned
  abstraction; wrappers require a stable policy or portability boundary.
- Generated code and vendored corpora MUST record source, version, checksum,
  license, generation command, and update procedure when those artifacts are
  maintained or distributed.

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

[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC8174]: https://www.rfc-editor.org/rfc/rfc8174
