# Contributing

This repository is a planned, non-releasable scaffold, not an implemented Go
application or installable library. Read [AGENTS.md](AGENTS.md),
[the current planning scope](docs/goal.md) and [SECURITY.md](SECURITY.md).
Implementation programs and frozen planning records require their own
authorization; changing verification does not activate them.

## Verification

Use Go 1.27.2; the module minimum remains Go 1.27.0. An isolated checkout
needs no sibling repositories or coordination goal files for these checks.
Install the public v2.1.2 binary archive for your platform from
[go-library-tools releases](https://github.com/faustbrian/go-library-tools/releases/tag/v2.1.2).
Verify `checksums.txt` against the digest in `.golib.yaml`, then verify the
archive against that checksum set. Put the extracted binary on `PATH` or
select its path through `GOLIB`; do not build Tools from source. CI uses the
immutable published setup action to install and attest this release.

Run one bounded disposable-cache session:

```bash
(
  set -eu
  planning_cache="$(mktemp -d)"
  trap 'chmod -R u+w "$planning_cache"; find "$planning_cache" -depth -delete' EXIT
  mkdir "$planning_cache/build" "$planning_cache/modules" "$planning_cache/tmp"
  export GOCACHE="$planning_cache/build"
  export GOMODCACHE="$planning_cache/modules"
  export GOTMPDIR="$planning_cache/tmp"
  make check
)
```

`make check`, `make ci` and `make fast-check` run six ordered commands:
configuration, repository, cohesion, offline specification, local links and
unconditional full secret checking. Whole-tree/history checks cover local
dirty and untracked work; a changed-range scan must not replace them locally.
`make planning-check` omits secrets only to let CI add its separately validated
scan; it is not a complete verification claim.

Ordinary PR/push CI requires the exact event base commit, present in Git and
an ancestor of HEAD. No missing-range fallback exists. Changed-content secrets
run on every change, including documentation, with a fatal forty-second
deadline and five-second termination grace. They cover committed additions
and current contents of changed paths, not an arbitrary dirty workspace.
Required is the sole job, capped at five minutes for ordinary events; failures,
timeouts and cancellations cannot be converted into success. Public tooling,
scanner caches and temporary resources are task-owned and cleaned on failure.

Select broader planning checks explicitly:

```bash
make check-full
make specification-check-online
make secrets-check
```

Scheduled/manual Required retains online authority refresh and whole-tree/history
secrets with the existing twenty-minute outer cap. These commands preserve
planning acceptance only. There are no application tests, active fuzz targets,
mutation campaigns, runtime conformance claims or releasable modules to qualify.
No application release is authorized by a green planning check.
