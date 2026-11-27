# Architecture

freshcrab is the automatic updater and validator for openSUSE
Tumbleweed/Factory — the updater crab, paired with rpmcrab (the linter
crab). It watches upstream releases, queues updates for packages that
are behind on Factory, and — via an agent — branches the package from
its devel project, bumps the version, cleans the spec, builds it in
OBS, validates it, and submits the update to the devel project.

## OBS access rule

All OBS interaction goes through geectl's library. freshcrab implements
no OBS logic of its own: it has no OBS client, no request/response XML
handling, no endpoint construction, no OBS URL building. The Factory
reads (`src/factory.rs`: the spec via `cat`, the package list via
`list_packages`), the devel lookup, the open-SR check, and SR filing
all run through geectl.

Any new OBS need goes to geectl first and freshcrab picks it up from a
geectl release; local implementation stays out. Reviewers enforce
this: a freshcrab PR adding OBS logic is refused.

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
   ┌─────────────┐  │  state file +    │
   │  Upstream   │  │  deduplication   │  ┌──────────────────┐
   │  (confirm)  │  └────────┬────────┘  │    Dispatcher    │
   └─────────────┘           │           │  picks entries,   │
                             ▼           │  drives a worker  │
                    ┌──────────────────┐ └────────┬─────────┘
                    │  queue.json      │          │
                    │  (pending / in   │          ▼
                    │   progress / done)│  ┌──────────────────┐
                    └──────────────────┘  │      Worker      │
                                            │  plan + payload  │
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
3. **Dispatcher** (`src/dispatcher.rs`). Picks pending entries
   (security first, respecting the concurrency limit and the daily SR
   cap) and drives one worker per package. Applies the outcome to the
   queue status (`done` when the SR was filed or the update was already
   handled, `escalated` when a human must look, unchanged when the run
   was a dry-run plan) and saves the queue. Runs only when
   `report_only` is false.
4. **Worker** (`src/worker.rs`). For one queue entry: resolves the
   devel project, re-checks the deduplication rules (fail-closed),
   resolves the branch project (`home_project` from config, else
   `home:{OBS username}`), builds the update plan (one `.changes`
   entry, the SR description) enforcing the changelog rules (a security
   entry must name its CVE), builds the SR payload
   (geectl's `SrPayload` — validated, well-formed OBS request XML), executes
   the update steps through the executor, and files the SR to the devel
   project via the OBS API. The executor is the `UpdateExecutor` trait:
   only the `DryRunExecutor` is shipped (dry-run: logs the
   would-do steps and returns `Planned`; live: refuses, so an SR is filed
   only on a plan that was executed). The live executor — the agent/CI step
   that actually performs the branch, bump, spec-cleaner, OBS build,
   rpmcrab and audit steps, following `worker/brief.md` — is the
   remaining work. Escalates to a human on build
   failure, unfixable findings, a spec logic change, or a conflicting
   SR.

## Collectors (priority order)

| Priority | Collector | What it gives |
|---|---|---|
| 1 (primary) | **Repology** (repology.org) | Newest version across hundreds of distros and upstreams, JSON API (`GET /api/v1/project/<name>`). Statuses: newest, devel, unique, outdated, legacy, rolling, noscheme, incorrect, untrusted, ignored. Rate limit 1 request/second — the collector paces itself. |
| 2 | **Anitya / release-monitoring.org** | Upstream releases (GitHub, GitLab, PyPI, ...), JSON API (`GET /api/v2/projects/?name=<name>`). |
| 3 | **PyPI JSON API** | `https://pypi.org/pypi/<name>/json`, for Python packages only. |
| 4 (signal) | **Distrowatch** | A secondary signal only — it confirms a version only with another source. |

**Freshmeat is excluded as a source.**

**Direct upstream checks** (the package's source URL / GitHub releases)
confirm a candidate when the collectors disagree or when a version
needs a second source.

## Confirmation rule

A candidate version is queued only when it is confirmed:

- the Repology candidate has status `newest` in at least two distinct
  repos (a single `newest` entry is a max, not a consensus, so it
  confirms only with another source), or
- at least two collectors agree on the same version (RPM version
  equality), or
- a direct upstream check confirms the version.

A Distrowatch-only candidate confirms only with another source. A pre-release
(`1.0~rc1`, `2.0~beta`) stays below the released version.

## Version comparison

Comparison is proper RPM version comparison (`rpmvercmp`), implemented
in pure Rust in `src/version.rs` — version-segment ordering:

- numeric segments compare numerically (`1.10` > `1.9`),
- `~` sorts before everything including the end (a tilde version is a
  pre-release),
- `^` sorts after the end but before any other character (a snapshot),
- alpha segments compare lexicographically, numeric beats alpha,
- separators (`.`, `-`, `_`, `+`, `%`, `{`, `}`) are skipped,
- epoch dominates version, version dominates release.

## Gate rules (for the worker phase)

- Branch from the devel project; Factory takes submissions from devel only.
- One `.changes` entry per package per SR, describing the net change.
- spec-cleaner in full mode as the final step; if its output is wrong,
  fix spec-cleaner and apply its diff whole.
- rpmcrab over the built RPMs: target 0 errors / 0 warnings. Findings
  are fixed at the cause. Info-severity findings stay informational.
- Pre-filing adversarial audit over the exact final diff, evaluated
  for every product the spec builds for (openSUSE / Leap / SLE /
  SL Micro).
- File the SR to the devel project via the OBS API.
- Escalate to a human on build failure, unfixable findings, a spec
  logic change, or a conflicting SR.

## Dry-run

Dry-run is the default, and it is global: one mode
governs the watcher, the queue, the dispatcher, and the worker. Every mutating
operation goes through the single dry-run guard (`src/dry_run.rs`:
`DryRun::allow`) before any write, API call, or external action. Reads
are not gated (the watcher still polls the collectors; the queue still
evaluates the dedup rules). In dry-run, the operation is skipped and
the would-do plan is printed (to stderr) and recorded; in live mode,
the operation proceeds. The effective mode resolves as CLI flag
(`--dry-run` / `--live`) > env var (`FRESHCRAB_DRY_RUN`) > config
(`dry_run`, default `true`) and is logged loudly at startup.

## Project hygiene (report-only)

`src/hygiene.rs` sweeps a project for obsolete repositories and
long-broken packages, reporting only — the sweeps take no `--live`
flag and make no mutations. `freshcrab hygiene` (see the runbook)
runs both sweeps per project and prints the report as JSON.

- **Obsolete repositories.** A repository whose build path targets
  a project or repository that is not found. The sweep reads the
  swept project's meta, then each distinct path target's meta; a
  target project that answers 404 is not found (gone or not
  visible to these credentials — the API does not distinguish the
  two), a target project without
  the repository has no such repository. Any other read failure fails
  the sweep loudly instead of reporting a partial list.
- **Long-broken packages.** A package is long-broken when it fails
  in every repository that counts for it (Tumbleweed counts only for
  packages in Factory — a Tumbleweed repository is one whose primary
  build path targets the Tumbleweed family: `openSUSE:Factory`,
  `openSUSE:Tumbleweed`, or any `openSUSE:Factory:*` subproject; the
  check follows the first path transitively through the swept
  project's own tree only, so a repo building against a subproject
  repo ultimately builds against that repo's target, while a repo
  whose first path points at a different project is a direct build
  target), has no successful build in the last 90 days
  (via the job history on a failing architecture), and was never
  integrated (no accepted submit request from the project or a branch
  of it). A package building in any counting repository is skipped,
  and a history that does not reach back past the 90-day threshold
  with no success does not qualify — both fail closed. All reads go
  through geectl: the build-results matrix, job history, and request
  search.

## Leap and CVE validation (planned, scaffolded)

Leap and CVE validation are the remaining work — see
`docs/leap-and-cve.md` for the full design. The scaffold provides named,
tested seams:

- **Targets** (`src/target.rs`): a `Target` is `Factory` or
  `Leap { version }`, with the OBS project and an
  implemented/planned gate. Config has a `targets:`
  list (default `[factory]`); a Leap target parses but the pipeline
  refuses to run it. Queue entries carry their target.
- **CVE validation** (`src/cve.rs`): the rule is that a security
  fix's changelog (`.changes`) entry must carry the CVE reference,
  and validation compares the changelog against the CVE list. The
  `changelog_names_cve` check is implemented and tested; the
  `CveValidator` trait is the interface an implementation uses
  against the CVE data source and the OBS changelog. The Factory
  path skips the validator. The trait also carries a
  `has_regression_test` hook: a backport is not complete without a
  `%check` regression test that fails on the unpatched code and
  passes with the fix (or a documented reason why none is
  feasible) — the changelog is the claim, the test is the proof.
- **Security-first ordering** (`src/queue.rs`): entries carry a
  kind — `Routine` or `Security` (CVE-driven) — and `pending()`
  returns security entries before routine ones. The Factory path is
  routine-only.

Why Leap is different: stable distros backport security patches
instead of bumping versions, so a CVE is fixed when the backported
patch is present (the changelog names it), not when the version
number rises. Security is the highest-priority work the system does
(see `docs/leap-and-cve.md` for the security-first rationale: the
queue ordering, the changelog verification, and the system itself
staying secure — credentials outside the repo/image/fixtures, every
SR through the review gate, the dedup/review checks in the path for
every submission).

## Secrets

Credentials live outside the repo. OBS credentials (oscrc) and the
GitHub token are injected via environment variables / mounted secrets
(GitHub Actions secrets in CI, a mounted file in the container). The
Factory and devel-project reads use the OBS public API and need no
credentials; the open-submit-request dedup check uses the OBS search
API, which has no public equivalent — without credentials it fails and
the package is skipped (fail-closed) instead of being queued on an
unchecked dedup. The credentials are read from the `OSC_USERNAME` /
`OSC_PASSWORD` environment variables; the search uses them (HTTP Basic
auth) when present, and filing a submit request requires them (the OBS
API accepts HTTP Basic auth with oscrc credentials). The values are
Logging excludes the values.

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
  factory.rs           Factory version via geectl's public reads
                       (`cat` for the spec, `list_packages` for the list)
  hygiene.rs           project-hygiene sweeps (report-only): obsolete
                       repositories + long-broken packages
  target.rs            distribution targets (Factory / Leap) + the
                       per-target update-policy hook
  cve.rs               CVE validation: the changelog-carries-the-CVE rule
                       + the validator interface (planned)
  watcher.rs           collectors + confirmation + Factory compare
  queue.rs             queue state file, deduplication, security-first
                       ordering (kind: routine / security); filed SR ids
                       and the daily-cap count
  geectl (dependency)  OBS client for the Factory reads, the dedup
                       checks + filing a submit request
                       (POST /request?cmd=create)
  dispatcher.rs        picks pending entries (security first, concurrency
                       limit, daily SR cap), drives the worker, applies
                       outcomes to the queue, prints the dispatch report
  worker.rs            one queue entry through the pipeline: devel
                       resolution, dedup re-check, branch project, update
                       plan (.changes entry + SR description, CVE rules),
                       the executor trait + DryRunExecutor
worker/
  brief.md             agent brief for the update worker (the live
                       executor step)
tests/
  test_version.rs      version comparison contract
  test_watcher.rs      watcher with canned fixtures (no live network)
  test_queue.rs        deduplication + persistence
  test_config.rs       config loading, validation, exclusions
  test_cve.rs          CVE id parsing + the changelog rule + the stub
  test_sr.rs           SR filing: dry-run logs the exact payload and
                       files nothing; live POSTs the XML and returns the
                       request id; no credentials fails closed
  test_hygiene.rs      hygiene sweeps over canned OBS responses
                       (no live network)
  fixtures/            canned Repology / Anitya / PyPI / Distrowatch / spec
docs/
  architecture.md      this file
  leap-and-cve.md      Leap + CVE validation design (planned, scaffolded)
  runbook.md           run the container, configure the package set, pause, read the queue
  assets/logo.svg      project icon

(The opensuse-packaging-skill docs live outside this repo: they are
fetched at image build time from a tagged release, see the Dockerfile.)
```
