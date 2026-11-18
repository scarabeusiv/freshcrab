<img src="docs/assets/logo.svg" alt="freshcrab logo — a bright green crab molting out of a cracked old shell" width="128" height="128">

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

Scaffolding: the watcher and the queue are implemented and tested. The
dispatcher and the worker execution (invoking an agent from CI) are a
later phase; `worker/` currently holds only the agent brief. The watcher
runs in report-only mode by default: it queues and reports what it would
update, and files nothing.

## Collectors (priority order)

1. **Repology** (primary) — aggregates package versions across hundreds
   of distros and upstreams, JSON API.
2. **Anitya / release-monitoring.org** — tracks upstream releases
   (GitHub, GitLab, PyPI, ...), JSON API.
3. **PyPI JSON API** — for Python packages only.
4. **Distrowatch** — secondary signal only.

Freshmeat is defunct (shut down in 2014) and is deliberately not used. A
candidate version is confirmed before queueing when it comes from
Repology with status `newest`, when at least two collectors agree, or
when a direct upstream check confirms it. See `docs/architecture.md`.

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
public equivalent — without OBS credentials it warns and proceeds (the
worker re-checks before filing).

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

Dry-run is the default in this phase, and it is global: one mode
governs the watcher, the queue, and (later) the worker. In dry-run
nothing is written or filed — the watcher polls the collectors and
prints what it WOULD queue, the queue evaluates the dedup rules and
prints the decision for each candidate (would-enqueue / would-skip +
reason), and the worker prints the full plan and takes no action. The
effective mode is logged loudly at startup, so it is always obvious
which mode is running.

```sh
# Dry-run (default): prints the would-do plan, writes nothing.
podman run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" freshcrab --packages foo bar

# Live: writes the queue state file (still files no SR in this phase).
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
is deliberately strict:

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
If a check turns out too noisy in practice, it is relaxed deliberately
in a PR with a reason — never silently.

## Code scanning

CodeQL runs on every PR, on push to `main`, and weekly
(`.github/workflows/codeql.yml`), with the `security-and-quality`
query suite — security plus code quality, the strictest suite, not
security-only. Findings appear in the repo's Security tab, and the
workflow fails the PR when it finds issues (default behaviour — not
suppressed). No CodeQL rule is disabled or weakened.

Rust is extracted without a build (`build-mode: none`): CodeQL does
not support `autobuild` for Rust, so there is deliberately no
autobuild step. That is the correct CodeQL setup for Rust, not a
weakening.

## Repository protection

`main` is guarded from the start:

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
- `concurrency`: how many workers run at once (later phase).
- `daily_sr_cap`: maximum submit requests filed per day (later phase).
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
  architecture.md      component diagram + data flow + gate rules
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
