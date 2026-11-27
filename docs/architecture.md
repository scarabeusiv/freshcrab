# Architecture

Tracking: [reviewer queue](https://github.com/scarabeusiv/freshcrab/issues/21),
[cleanups](https://github.com/scarabeusiv/freshcrab/issues/22),
[submitter, Leap maintenance filing](https://github.com/scarabeusiv/freshcrab/issues/15),
[Leap maintenance](https://github.com/scarabeusiv/freshcrab/issues/7),
[multi-forge](https://github.com/scarabeusiv/freshcrab/issues/26).

freshcrab is the automatic updater and validator for openSUSE
Tumbleweed/Factory — the updater crab, paired with rpmcrab (the linter
crab). It runs queues over updates and submissions: it watches upstream
releases, files updates, triages submissions through a ruleset, and
sweeps projects for hygiene. All forge access goes through geectl's
library — freshcrab implements no forge logic of its own.

## Architecture

```
                    ┌──────────────────────┐
                    │ central queue planner │
                    │ runs queues, cleanups │
                    └──────┬───────┬────────┘
                           │       │
              ┌────────────▼──┐ ┌──▼──────────────┐
              │  cleanups     │ │  queues         │
              │  (hygiene)    │ │  updater        │
              └───────────────┘ │  reviewer       │
                                │  submitter      │
                                └──────┬──────────┘
                                       │
                                ┌──────▼──────────┐
                                │ central observer │
                                │ token budget /   │
                                │ cost, coherent   │
                                │ queue, forge     │
                                │ assignment       │
                                └──────┬───────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │ OBS (geectl)           │ Gitea (geectl)         │ GitHub / GitLab (geectl)
              └────────────────────────┴────────────────────────┘
```

### Central queue planner

- Owns running the queues and the cleanups. It spawns the
  individual queues: updater, reviewer, submitter.
- The planner is a long-running daemon, not a one-shot invocation:
  you start its container, set its budget and data, and it processes
  things until they go quiet.
- The planner is the entry point: one freshcrab run is one planner
  run. Each queue runs under the planner's run; the queues share the
  one queue store.

### Updater queue

- Watches upstream releases, confirms a newer version, queues an
  update, and — via the worker — branches the package from its
  devel project, bumps the version, cleans the spec, builds it in
  OBS, validates it, and files the update. Detail: the updater
  pipeline sections below.
- State: one entry per package behind in the queue store (pending /
  in_progress / done / blocked / escalated). Security-first
  ordering: CVE-driven entries before routine ones.
- Factory is implemented. Leap and CVE validation are scaffolded
  (per-target policy, CVE validator interface); the Leap watcher
  logic, the CVE data-source integration, and Leap SR filing are
  remaining work. Detail: `docs/leap-and-cve.md`.

### Reviewer queue

- Triages submissions: OBS submit requests and Gitea pull requests,
  read and acted on through geectl's unified pull-request surface.
  A ruleset auto-comments or rejects the clear cases,
  mid-confidence items sit in a maintained queue, and the rest go to
  a human for review or decision. Detail: `docs/review-queue.md`.
- State: one record per ref in the queue store, with the same shape
  and conventions as the updater entries.
- An updater-filed SR enters the reviewer queue by re-discovery,
  not direct handoff: the reviewer finds it on its next sweep by
  matching the SR id. A self-filed submission gets a cooldown
  before the reviewer acts on it — a self-owned submission getting
  self-approved is a last-instance effort — unless a human
  overrides it directly with geectl. The cooldown duration is
  open. See Open questions.
- A hotfix queue carries concentrated nits that were quick-fixed:
  quick commit and forward, processed and reviewed as priority. It
  bypasses the cooldown on self-owned submissions — the priority
  exception to the re-discovery/cooldown rule. The queue's exact
  shape, its priority ordering, and what counts as a concentrated
  nit are open. See Open questions.

### Submitter queue

- Files submissions: the SR to the devel project (Factory updates),
  and maintenance-request filing for Leap
  ([#15](https://github.com/scarabeusiv/freshcrab/issues/15),
  [#7](https://github.com/scarabeusiv/freshcrab/issues/7)).
- Filing is the submitter queue's job: the worker builds the SR
  payload and hands filing to the submitter queue, which works in
  the one queue. Filing items are inserted with priority, not
  appended at the tail: the work (branch, bump, build, validate) is
  already done when filing is queued, so a tail-appended filing
  would sit while the completed work waits. The exact insertion
  position is open. See Open questions.
- [#15](https://github.com/scarabeusiv/freshcrab/issues/15) reworks Leap
  maintenance-request filing to go through geectl only.

### Cleanups

- The planner runs cleanups.
  [#22](https://github.com/scarabeusiv/freshcrab/issues/22) is the
  hygiene sweep:
  report-only sweeps for obsolete repositories and long-broken
  never-integrated packages (90-day threshold; broken means not
  building anywhere, Tumbleweed counting only for Factory packages;
  never-integrated means no accepted submit request ever; scope is
  both devel and home projects).
- [#22](https://github.com/scarabeusiv/freshcrab/issues/22) is a CLI
  sweep (`freshcrab hygiene`), report-only. Whether
  the planner invokes it on a schedule or it stays manual is open.
  See Open questions.

### Central observer

- Controls the token budget and runs the coherent queue. As more
  forges are added, it assigns the items to execute.
- Token budget: LLM/agent token spend — real money. A lab has a token
  budget for the month; the observer paces spending so the month's
  budget lasts the month. The daemon must not spend it in a day or a
  week. The daemon is built for labs that pay per token, so pacing is
  a first-class concern. Cost is token spend, not API call count or
  wall time. The budget unit is token cost (money), scoped per lab,
  per month, with day/week pacing. The budget values are per-lab
  config; the pacing mechanism is open. The initial setup is
  'unlimited' by default; budget enforcement is left open and
  figured in later phases for someone that needs it. See Open
  questions.
- Clients that exist: the forge clients — OBS, Gitea, and later
  GitHub and GitLab — all reached through geectl's library; and the
  collectors (Repology, Anitya, PyPI, Distrowatch) that the updater
  polls. Credentials for all of them live outside the repo
  (environment variables / mounted secrets). Which of these the
  observer budgets is open. See Open questions.
- Budgets already enforced, per component (not observer-enforced):
  the dispatcher concurrency limit, the daily SR cap
  (`daily_sr_cap`, config), Repology pacing (1 request/second),
  the queue lock (one writer at a time). The observer's budget
  values are per-lab config and open. See Open questions.
- Exhaustion: when the token budget is out, the daemon finishes: it
  stops processing. Whether it then exits or idles waiting for the
  next budget period is open. See Open questions.
- Coherent queue: one queue across forges, in one store for the whole
  queue — not the union of the per-queue state files. An item is
  identified by its handle, not by who filed it; one record per ref
  (`obs:<id>` / `gitea:<owner>/<repo>#<number>`); re-discovery
  updates the record in place, never duplicates it. No cross-forge
  dedup: the same logical change on two forges is two items, one per
  forge — there might be a reason it exists in two places (an OBS
  submission copied to an internal SUSE instance for security
  patching). Discovery runs across ALL configured instances — every
  OBS and every Gitea instance in the config, not just the default. Priorities are
  adjustable at runtime: a human can tell the daemon to prioritise
  CVEs, or cleanups, as they see fit. The daemon runs until the token
  budget is exhausted, so the order items are processed in — what
  goes first within the budget — is a human decision. Items are
  locked on assignment to one executor. Locks carry timestamps and
  the daemon tracks them — if an item runs long, the daemon returns
  it to the queue. Each worker is limited on duration; the duration
  limit and the reclaim timeout are open. How a human tells the
  daemon is open. See Open questions.
- Forge assignment: an item executes on the forge that owns it (its
  handle's forge). Capability differences are per forge: OBS decline
  is human-only; Gitea labels are Gitea-only library operations,
  not part of the queue surface. What happens when an item's forge
  is down or unconfigured is open. See Open questions.
- Fail-closed throughout: a failed signal read is never read as
  green; a malformed forge response bails out with a wrong-response
  error carrying the trace; a missing credential fails the dedup
  check and the package is skipped, never queued on an unchecked
  dedup.

### Piece map

| Piece | Queue | Status |
|---|---|---|
| Version watching (watcher, collectors, confirmation) | Updater | Implemented (Factory); Leap/CVE scaffolded |
| queue.json, dispatcher, worker (branch, bump, clean, build, validate) | Updater | Implemented (Factory); live executor is the agent/CI step |
| SR filing to devel | Submitter | Filing moves to the submitter queue; insertion position open |
| [#15](https://github.com/scarabeusiv/freshcrab/issues/15) Leap maintenance-request filing | Submitter | In flight, geectl-only |
| [#21](https://github.com/scarabeusiv/freshcrab/issues/21) review queue | Reviewer | Step 1 (state file + discovery); step 2 (signal readers) in flight |
| [#22](https://github.com/scarabeusiv/freshcrab/issues/22) hygiene sweeps | Cleanup (planner-run) | In flight, report-only |
| [#24](https://github.com/scarabeusiv/freshcrab/issues/24) crates.io publish | — | Misfit: release tooling, not a queue item |
| [#26](https://github.com/scarabeusiv/freshcrab/issues/26) multi-forge (GitHub/GitLab) | Observer (forge assignment) | Scope open |

### Misfits

- [#24](https://github.com/scarabeusiv/freshcrab/issues/24) crates.io
  publish is release tooling, not a queue item. It is
  not owned by any queue; whether the planner owns it is not drawn.
- [#22](https://github.com/scarabeusiv/freshcrab/issues/22) hygiene is
  a CLI sweep. Whether the planner invokes it on a
  schedule or it stays manual is not drawn.

## Forge access rule

All forge interaction goes through geectl's library. freshcrab implements
no forge logic of its own: it has no forge client, no request/response
handling, no endpoint construction, no forge URL building. The Factory
reads (`src/factory.rs`: the spec via `cat`, the package list via
`list_packages`), the devel lookup, the open-SR check, and SR filing
all run through geectl. The reviewer queue's reads and acts run through
geectl's unified pull-request surface.

Any new forge need goes to geectl first and freshcrab picks it up from a
geectl release; local implementation stays out. Reviewers enforce
this: a freshcrab PR adding forge logic is refused.

## Updater queue

### Components

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

### Data flow

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
   project via geectl. The executor is the `UpdateExecutor` trait:
   only the `DryRunExecutor` is shipped (dry-run: logs the
   would-do steps and returns `Planned`; live: refuses, so an SR is filed
   only on a plan that was executed). The live executor — the agent/CI step
   that actually performs the branch, bump, spec-cleaner, OBS build,
   rpmcrab and audit steps, following `worker/brief.md` — is the
   remaining work. Escalates to a human on build
   failure, unfixable findings, a spec logic change, or a conflicting
   SR.

### Collectors (priority order)

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

### Confirmation rule

A candidate version is queued only when it is confirmed:

- the Repology candidate has status `newest` in at least two distinct
  repos (a single `newest` entry is a max, not a consensus, so it
  confirms only with another source), or
- at least two collectors agree on the same version (RPM version
  equality), or
- a direct upstream check confirms the version.

A Distrowatch-only candidate confirms only with another source. A pre-release
(`1.0~rc1`, `2.0~beta`) stays below the released version.

### Version comparison

Comparison is proper RPM version comparison (`rpmvercmp`), implemented
in pure Rust in `src/version.rs` — version-segment ordering:

- numeric segments compare numerically (`1.10` > `1.9`),
- `~` sorts before everything including the end (a tilde version is a
  pre-release),
- `^` sorts after the end but before any other character (a snapshot),
- alpha segments compare lexicographically, numeric beats alpha,
- separators (`.`, `-`, `_`, `+`, `%`, `{`, `}`) are skipped,
- epoch dominates version, version dominates release.

### Gate rules (for the worker phase)

- Branch from the devel project; Factory takes submissions from devel only.
- One `.changes` entry per package per SR, describing the net change.
- spec-cleaner in full mode as the final step; if its output is wrong,
  fix spec-cleaner and apply its diff whole.
- rpmcrab over the built RPMs: target 0 errors / 0 warnings. Findings
  are fixed at the cause. Info-severity findings stay informational.
- Pre-filing adversarial audit over the exact final diff, evaluated
  for every product the spec builds for (openSUSE / Leap / SLE /
  SL Micro).
- File the SR to the devel project via geectl.
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
  fixtures/            canned Repology / Anitya / PyPI / Distrowatch / spec
docs/
  architecture.md      this file
  leap-and-cve.md      Leap + CVE validation design (planned, scaffolded)
  review-queue.md      reviewer queue design
  runbook.md           run the container, configure the package set, pause, read the queue
  assets/logo.svg      project icon
```

(The opensuse-packaging-skill docs live outside this repo: they are
fetched at image build time from a tagged release, see the Dockerfile.)

## Open questions

Each item needs a decision or clarification. Nothing here is answered
by the design above.

### Planner

1. Wake-up: after the planner goes quiet, what wakes it for new work
   — a timer, an event, a poll interval? Decision: wake-up trigger.
2. Queue execution: does one planner run execute updater, reviewer,
   and submitter sequentially or in parallel, and in what order?
   Decision: execution order and parallelism.
3. Planner failure: if the planner dies mid-run, what resumes and
   what is lost? Does it re-spawn queues from state, or start fresh?
   Decision: planner recovery semantics.

### Observer — token budget and cost

4. Budget values: what are the numbers per client and forge? The
   values are per-lab config. Decision: budget values.
5. Clients in scope: which clients does the observer budget — the
   forges only (OBS, Gitea, GitHub, GitLab), or also the collectors
   (Repology, Anitya, PyPI, Distrowatch)? Decision: observer scope.
6. Pacing mechanism: how does the observer pace spending so the
   month's budget lasts the month — what does it throttle, and on
   what schedule? Decision: pacing mechanism.
7. Post-exhaustion state: after the daemon finishes on budget
   exhaustion, does it exit or idle waiting for the next budget
   period? Decision: post-exhaustion state.
8. Observer failure: if the observer dies or cannot read budget
   state, do the queues run unbounded (fail-open) or stop
   (fail-closed)? Decision: observer failure mode.

### Coherent queue

9. Reprioritisation mechanism: how does a human tell the daemon to
    prioritise CVEs or cleanups — a command, an API, a config file?
    Decision: reprioritisation mechanism.
10. Lock durations: what is the per-worker duration limit, and after
    how long does the daemon reclaim a long-running item back into
    the queue? Decision: lock durations.

### Forge assignment

11. Assignment rule: does the observer route an item to a forge, or
    does the item's own forge (its handle) decide? Does assignment
    account for per-forge capabilities (OBS decline is human-only,
    Gitea labels are Gitea-only)? Decision: assignment rule.
12. Forge down or unconfigured: does the item stay queued, get
    reassigned, or escalate to a human? Decision: forge-failure
    behaviour.
13. Adding a forge mid-run: is a newly configured forge picked up on
    the next run, or does the planner need a restart? Are existing
    items re-evaluated against the new forge? Decision: forge
    onboarding.

### Queue interaction

14. Cooldown duration: how long is the cooldown on a self-owned
    submission before the reviewer acts on it? Decision: cooldown
    duration.
15. Filing insertion position: filing items are inserted with
    priority, not tail-appended — where exactly: at the head, or at
    a high-priority position? Decision: filing insertion position.
16. Hotfix queue shape: what is the hotfix queue's exact shape,
    its priority ordering, and what counts as a concentrated nit?
    Decision: hotfix queue shape.

### State, guards, config

17. Planner state: does the planner keep spawn and cleanup state?
    Decision: planner state.
18. Kill switch scope: does the kill switch pause the planner (all
    queues) or one queue? Decision: kill-switch scope.
19. Dry-run scope: is dry-run global, or can one queue be live while
    another is dry-run? Decision: dry-run granularity.
20. Config placement: where do the planner schedule and the observer
    budgets live — `config.yaml`, the ruleset, or a separate file?
    Decision: config placement.

### Cleanups

21. Cleanup trigger: what triggers a cleanup — a planner schedule, a
    threshold, manual? Is
    [#22](https://github.com/scarabeusiv/freshcrab/issues/22) hygiene
    invoked by the planner, or run
    manually? Decision: cleanup trigger.
22. Cleanup safety: what guards an acting cleanup (dry-run, kill
    switch, human approval), and when does
    [#22](https://github.com/scarabeusiv/freshcrab/issues/22) move from
    report-only
    to acting? Decision: cleanup authorisation.

### Failure modes

23. Queue death: if one queue dies, does the planner restart it, mark
    it, or continue with the others? Does a dead queue block the
    run? Decision: queue-failure handling.
24. Partial act: an item is half-acted (comment posted, state not
    saved) — what resumes it? Decision: partial-act recovery.

### Scope

25. Planner boundary ("whatever"): is release tooling (
    [#24](https://github.com/scarabeusiv/freshcrab/issues/24) crates.io
    publish) planner-owned, or outside the architecture? Decision:
    planner boundary.
26. GitHub and GitLab (
    [#26](https://github.com/scarabeusiv/freshcrab/issues/26)): are
    they forges under the observer (with
    tokens and budgets), or out of scope? Decision: forge scope.
