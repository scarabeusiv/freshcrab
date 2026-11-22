<img src="https://raw.githubusercontent.com/scarabeusiv/freshcrab/main/docs/assets/logo.svg"
     align="right" width="130" alt="freshcrab logo">

# freshcrab

[![Freshness](https://github.com/scarabeusiv/freshcrab/actions/workflows/freshness.yml/badge.svg)](https://github.com/scarabeusiv/freshcrab/actions/workflows/freshness.yml)
[![CodeQL](https://github.com/scarabeusiv/freshcrab/actions/workflows/codeql.yml/badge.svg)](https://github.com/scarabeusiv/freshcrab/actions/workflows/codeql.yml)

Automatic updater and validator for openSUSE Tumbleweed/Factory — the
updater crab, paired with rpmcrab (the linter crab).

It watches upstream releases, queues updates for packages that are behind
on Factory, and — via an agent — branches the package from its devel
project, bumps the version, cleans the spec, builds it in OBS, validates
it, and submits the update to the devel project when no newer version is
already in flight.

## Status

Scaffolding: the watcher and the queue are implemented and tested, and
the dispatcher and the worker are implemented too: with `report_only:
false` the dispatcher picks pending entries (security first, within
the concurrency limit and the daily SR cap), the worker re-checks the
deduplication rules, builds the update plan (one `.changes` entry, the
SR description) and the exact SR payload, and files the submit request
to the devel project. Dry-run is the default: the plan and the exact
SR payload are logged and nothing is filed. What is NOT yet there is
the live update executor — the agent/CI step that actually performs
the branch, bump, spec-cleaner, OBS build, rpmcrab and audit steps.
Live mode refuses to file (the entries escalate
instead), so no SR is ever filed on a plan that was not executed.
`worker/` holds the agent brief for that step.

Leap and CVE validation are not implemented yet — see
`docs/leap-and-cve.md`. The scaffold exists (distribution targets with
Leap gated off, the CVE validation rule and validator interface,
security-first queue ordering), but the Leap watcher logic, the CVE
data-source integration, and Leap SR filing are not implemented.

## Collectors (priority order)

1. **Repology** (primary) — aggregates package versions across hundreds
   of distros and upstreams, JSON API.
2. **Anitya / release-monitoring.org** — tracks upstream releases
   (GitHub, GitLab, PyPI, ...), JSON API.
3. **PyPI JSON API** — for Python packages only.
4. **Distrowatch** — secondary signal only.

Freshmeat is defunct and is not used. A
candidate version is confirmed before queueing when it comes from
Repology with status `newest` in at least two distinct repos, when at
least two collectors agree, or when a direct upstream check confirms
it. See `docs/architecture.md`.

## Run it (container)

Build the image and run the watcher in report-only mode:

```sh
podman build -t freshcrab -f Dockerfile .
podman run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" freshcrab
```

That prints the queue: packages behind on Factory, and what would be
queued for each. Nothing is filed.

To run it against your own package set, copy `config.yaml`, edit the
`packages` section (list the packages you care about, or leave it empty
to watch all of Factory except the exclusions), and mount your copy
instead:

```sh
podman run --rm -v "$PWD/my-config.yaml:/app/config.yaml:ro" freshcrab
```

OBS credentials are never read from the repo. In CI they come from GitHub
Actions secrets; in the container they are injected via environment
variables or a mounted file (see `docs/runbook.md`). The Factory and
devel-project reads use the OBS public API and need no credentials. The
open-submit-request dedup check uses the OBS search API, which has no
public equivalent — without OBS credentials the check fails and the
package is skipped (fail-closed) instead of being queued on an
unchecked dedup. The credentials are read from the `OSC_USERNAME` /
`OSC_PASSWORD` environment variables; filing a submit request needs
them too (the OBS API accepts HTTP Basic auth with oscrc credentials).

## Tools in the container

All worker tools are the distro versions, installed with zypper from the
openSUSE repos — nothing is built from source:

- `rpmcrab` — the linter (`rpmcrab <rpm>`).
- `spec-cleaner` — the spec cleaner
  (`spec-cleaner -i --remove-groups --suse-copyright <spec>`).
- `osc` — the OBS client.
- `bugwarden` — the Bugzilla helper.
- opensuse-packaging-skill docs — at
  `/usr/share/doc/freshcrab/opensuse-packaging-skill/` (fetched at
  build time from tag v3.24.3 of openSUSE/openSUSE-packaging-skill,
  not in the repo; see `docs/runbook.md`).

The agent invokes them by name; see `worker/brief.md` and
`docs/runbook.md`.

## Dry-run

Dry-run is the default, and it is global: one mode
governs the watcher, the queue, the dispatcher, and the worker. In
dry-run nothing is written or filed — the watcher polls the collectors
and prints what it WOULD queue, the queue evaluates the dedup rules and
prints the decision for each candidate (would-enqueue / would-skip +
reason), the dispatcher logs the would-do plan for each entry, and the
worker prints the full plan and takes no action. The effective mode is
logged loudly at startup, so it is always obvious which mode is running.

```sh
# Dry-run (default): prints the would-do plan, writes nothing.
podman run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" freshcrab --packages foo bar

# Live: writes the queue state file; with a live executor the dispatcher files SRs
# (the shipped executor refuses live, so nothing is filed).
podman run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" freshcrab --live --packages foo bar
```

The mode resolves as CLI flag (`--dry-run` / `--live`) > env var
(`FRESHCRAB_DRY_RUN=true|false`) > config file (`dry_run:` in
`config.yaml`, default `true`). All plan output goes to stderr, so
stdout stays machine-readable JSON. See `docs/runbook.md`.

## Keeping dependencies fresh

Dependabot is on (`.github/dependabot.yml`), weekly, for three
ecosystems: Rust dependencies (`cargo`), GitHub Actions
(`github-actions`), and the container base image (`docker`). The setup
is strict:

- **No grouping** — each dependency update gets its own PR, so nothing
  hides in a group.
- **No PR limit that suppresses updates** — the open-PR limit is set
  high enough that every update is surfaced.
- Dependabot PRs go through the same branch protection as any other
  change (green CI + at least 1 approving review) and are **not**
  auto-merged.

A separate weekly workflow, `.github/workflows/freshness.yml`, keeps
the repo from rotting. It **fails** (not just reports) on:

- any outdated dependency (`cargo outdated`, failing exit code),
- any `cargo audit` advisory,
- any `cargo deny check` failure (licenses, advisories, sources —
  allowed licenses are in `deny.toml`),
- any unused dependency (`cargo machete`),
- a stale `Cargo.lock` (fails when the lockfile is not up to date with
  `Cargo.toml`).

The freshness workflow is separate from `test.yml`, so a freshness
failure does not block feature PRs — but it is visible (badge above)
and it stays red until the Dependabot PR is merged. The repo is kept
green by merging Dependabot PRs promptly, not by relaxing the checks.
If a check turns out too noisy in practice, it is relaxed
in a PR with a reason — never silently.

## Code scanning

CodeQL runs on every PR, on push to `main`, and weekly
(`.github/workflows/codeql.yml`), with the `security-and-quality`
query suite — security plus code quality, the strictest suite, not
security-only. Findings appear in the repo's Security tab, and the
workflow fails the PR when it finds issues (default behaviour — not
suppressed). No CodeQL rule is disabled or weakened.

Rust is extracted without a build (`build-mode: none`): CodeQL does
not support `autobuild` for Rust, so there is no
autobuild step.

## Repository protection

`main` is guarded:

- Pull requests only — no direct pushes, not even for the owner.
- At least 1 approving review before merge.
- The CI test workflow must pass, and branches must be up to date
  before merging.
- Linear history (rebase-only merges); no force pushes, no branch
  deletion.
- Conversation resolution required before merging.
- Enforced for admins too — the rule binds everyone.

Repo merge settings: rebase merges only (squash and merge commits
disabled), delete head branches on merge, auto-merge allowed.

`config.yaml` controls what is watched and how the pipeline behaves:

- `packages`: the set to monitor. Empty means all of Factory except
  `exclusions`.
- `exclusions`: packages never auto-updated (hand-maintained or special).
- `concurrency`: the per-run batch — how many queued entries one dispatch run handles.
- `daily_sr_cap`: maximum submit requests filed per day.
- `kill_switch`: when `true`, the pipeline pauses entirely.

See `docs/runbook.md` for the full reference.

## Layout

```
config.yaml            broad defaults; exclusions; concurrency; SR cap; kill switch
Dockerfile             multi-stage: build the static binary, then a minimal
                       image with the binary + distro worker tools
deny.toml              cargo-deny policy: allowed licenses, advisories, sources
.github/
  dependabot.yml       Dependabot: cargo + github-actions + docker, weekly,
                       no grouping, no suppressing PR limit
  workflows/
    test.yml           cargo test on every PR
    freshness.yml      weekly: cargo audit + deny + outdated + machete +
                       lockfile freshness (fails, does not just report)
    codeql.yml         CodeQL, security-and-quality, on PR / push / weekly
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
                       + the validator interface (not yet implemented)
  watcher.rs           collectors + confirmation + Factory compare
  queue.rs             queue state file, deduplication
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
  brief.md             agent brief for the update worker (the live executor step)
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
  architecture.md      component diagram + data flow + gate rules
  leap-and-cve.md      Leap + CVE validation design (planned, scaffolded)
  runbook.md           run the container, configure the package set, pause, read the queue
```

## Tests

```sh
cargo test
```

No live network is used in the tests; fixtures stand in for Repology,
Anitya, PyPI, Distrowatch, and the OBS API.

## License

Apache License 2.0 — see `LICENSE`.
