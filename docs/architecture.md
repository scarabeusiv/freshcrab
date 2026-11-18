# Architecture

freshcrab is the automatic updater and validator for openSUSE
Tumbleweed/Factory — the updater crab, paired with rpmcrab (the linter
crab). It watches upstream releases, queues updates for packages that
are behind on Factory, and — via an agent — branches the package from
its devel project, bumps the version, cleans the spec, builds it in
OBS, validates it, and submits the update to the devel project.

## Components

```
                    ┌─────────────────────┐
                    │      config.yaml     │
                    │  packages / excludes │
                    │  caps / kill switch  │
                    └────────┬────────────┘
                             │
   ┌─────────────┐  ┌────────▼────────┐  ┌──────────────────┐
   │  Repology   │  │     Watcher     │  │     Factory      │
   │  (primary)  │  │  collectors +   │  │  (OBS API)       │
   ├─────────────┤  │  confirmation + │  │  Factory version │
   │  Anitya     │──▶│  RPM version    │◀─│  per package     │
   ├─────────────┤  │  comparison     │  └──────────────────┘
   │  PyPI       │  └────────┬────────┘
   ├─────────────┤           │ queue entry per package behind
   │ Distrowatch │           ▼
   │  (signal)   │  ┌──────────────────┐
   └─────────────┘  │      Queue       │
   ┌─────────────┐  │  state file +    │      (later phase)
   │  Upstream   │  │  deduplication   │  ┌──────────────────┐
   │  (confirm)  │  └────────┬────────┘  │    Dispatcher    │
   └─────────────┘           │           │  picks entries,   │
                             ▼           │  spawns a worker  │
                    ┌──────────────────┐ └────────┬─────────┘
                    │  queue.json      │          │
                    │  (pending / in   │          ▼
                    │   progress / done)│  ┌──────────────────┐
                    └──────────────────┘  │      Worker      │
                                            │  agent + brief   │
                                            │  branch, bump,   │
                                            │  clean, build,   │
                                            │  validate, file  │
                                            └────────┬─────────┘
                                                     │ SR
                                                     ▼
                                            ┌──────────────────┐
                                            │  devel project   │
                                            └──────────────────┘
```

## Data flow

1. **Watcher** (`src/watcher.rs`). For each package in scope (all of
   Factory except the exclusions, or the configured list), it queries
   the collectors in priority order, confirms the candidate version,
   compares it against the Factory version with proper RPM version
   comparison, and emits a queue entry when the upstream version is
   newer. Report-only by default: it queues and reports, and files
   nothing.
2. **Queue** (`src/queue.rs`). The queue state file (`queue.json`)
   holds one entry per package behind, with a status (pending /
   in_progress / done / blocked / escalated). Before an entry is added,
   the deduplication checks run: skip when the devel project already
   has the new version, when an open submit request already targets
   the package, or when a task for the package is already in flight.
3. **Dispatcher** (later phase). Picks pending entries (respecting the
   concurrency limit and the daily SR cap) and spawns one worker per
   package.
4. **Worker** (later phase). An agent following `worker/brief.md`:
   branch from the devel project, bump Version + tarball + one
   `.changes` entry, spec-cleaner full mode, OBS build, rpmcrab 0E/0W,
   pre-filing adversarial audit, file the SR to the devel project via
   the OBS API. Escalates to a human on build failure, unfixable
   findings, a spec logic change, or a conflicting SR.

## Collectors (priority order)

| Priority | Collector | What it gives |
|---|---|---|
| 1 (primary) | **Repology** (repology.org) | Newest version across hundreds of distros and upstreams, JSON API (`GET /api/v1/project/<name>`). Statuses: newest, devel, unique, outdated, legacy, rolling, noscheme, incorrect, untrusted, ignored. Rate limit 1 request/second — the collector paces itself. |
| 2 | **Anitya / release-monitoring.org** | Upstream releases (GitHub, GitLab, PyPI, ...), JSON API (`GET /api/v2/projects/?name=<name>`). |
| 3 | **PyPI JSON API** | `https://pypi.org/pypi/<name>/json`, for Python packages only. |
| 4 (signal) | **Distrowatch** | A secondary signal only — never confirms a version on its own. |

**Freshmeat is defunct** (shut down in 2014) and is deliberately not
used.

**Direct upstream checks** (the package's source URL / GitHub releases)
confirm a candidate when the collectors disagree or when a version
needs a second source.

## Confirmation rule

A candidate version is queued only when it is confirmed:

- the Repology candidate has status `newest` (it aggregates many
  sources, so `newest` is multi-source by construction), or
- at least two collectors agree on the same version (RPM version
  equality), or
- a direct upstream check confirms the version.

A Distrowatch-only candidate never confirms alone. A pre-release
(`1.0~rc1`, `2.0~beta`) is never newer than the released version.

## Version comparison

Comparison is proper RPM version comparison (`rpmvercmp`), implemented
in pure Rust in `src/version.rs` — never a naive string compare:

- numeric segments compare numerically (`1.10` > `1.9`),
- `~` sorts before everything including the end (a tilde version is a
  pre-release),
- `^` sorts after the end but before any other character (a snapshot),
- alpha segments compare lexicographically, numeric beats alpha,
- separators (`.`, `-`, `_`, `+`, `%`, `{`, `}`) are skipped,
- epoch dominates version, version dominates release.

## Gate rules (for the worker phase)

- Branch from the devel project, never from Factory directly.
- One `.changes` entry per package per SR, describing the net change.
- spec-cleaner in full mode as the final step; if its output is wrong,
  fix spec-cleaner, never hand-pick parts of its diff.
- rpmcrab over the built RPMs: target 0 errors / 0 warnings. Findings
  are fixed, never filtered. Info-severity findings are not fix
  targets.
- Pre-filing adversarial audit over the exact final diff, evaluated
  for every product the spec builds for (openSUSE / Leap / SLE /
  SL Micro).
- File the SR to the devel project via the OBS API.
- Escalate to a human on build failure, unfixable findings, a spec
  logic change, or a conflicting SR.

## Dry-run

Dry-run is the default in this phase, and it is global: one mode
governs the watcher, the queue, and the worker. Every mutating
operation goes through the single dry-run guard (`src/dry_run.rs`:
`DryRun::allow`) before any write, API call, or external action. Reads
are not gated (the watcher still polls the collectors; the queue still
evaluates the dedup rules). In dry-run, the operation is skipped and
the would-do plan is printed (to stderr) and recorded; in live mode,
the operation proceeds. The effective mode resolves as CLI flag
(`--dry-run` / `--live`) > env var (`FRESHCRAB_DRY_RUN`) > config
(`dry_run`, default `true`) and is logged loudly at startup.

## Secrets

No credentials are read from the repo. OBS credentials (oscrc) and the
GitHub token are injected via environment variables / mounted secrets
(GitHub Actions secrets in CI, a mounted file in the container). The
Factory and devel-project reads use the OBS public API and need no
credentials; the open-submit-request dedup check uses the OBS search
API, which has no public equivalent — without credentials it warns and
proceeds (fail-open; the worker re-checks before filing).

## Layout

```
config.yaml            broad defaults; exclusions; concurrency; SR cap; kill switch
Dockerfile             multi-stage: build the static binary, then a minimal
                       image with the binary + distro worker tools
.github/workflows/
  test.yml             cargo test on every PR
src/
  lib.rs               library root
  main.rs              CLI entry point
  config.rs            load + validate config.yaml (strict subset parser)
  version.rs           pure-Rust rpmvercmp + EVR comparison
  http.rs              HTTP client trait (ureq) + fake for tests
  dry_run.rs           global dry-run mode + the single guard every
                       mutation consults (CLI > env > config)
  collectors/          Repology, Anitya, PyPI, Distrowatch, upstream check
  factory.rs           Factory version via the OBS API
  watcher.rs           collectors + confirmation + Factory compare
  queue.rs             queue state file, deduplication
  obs.rs               OBS client for the dedup checks
worker/
  brief.md             agent brief for the update worker (later phase)
tests/
  test_version.rs      version comparison contract
  test_watcher.rs      watcher with canned fixtures (no live network)
  test_queue.rs        deduplication + persistence
  test_config.rs       config loading, validation, exclusions
  fixtures/            canned Repology / Anitya / PyPI / Distrowatch / spec
docs/
  architecture.md      this file
  runbook.md           run the container, configure the package set, pause, read the queue
  assets/logo.svg      project icon (hand-built vector, rpmcrab style)
skills/
  opensuse-packaging-skill/   vendored skill docs (unpackaged upstream docs),
                              copied into the container at
                              /usr/share/doc/freshcrab/opensuse-packaging-skill/
```
