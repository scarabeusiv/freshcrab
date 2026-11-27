# Runbook

## Run the container

Build the image and run the watcher in report-only mode (it prints the
queue as JSON and files nothing):

```sh
podman build -t freshcrab -f Dockerfile .
podman run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" freshcrab
```

The default config watches all of Factory except the exclusions, so a
full run takes a while (one Repology/Anitya/Distrowatch query per
package, at the collectors' rate limits). For a quick smoke test, pass
a package list:

```sh
podman run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" freshcrab --packages foo bar
```

## Configure the package set

Copy `config.yaml` and edit it:

```yaml
# Distributions to watch. Only `factory` runs; a Leap target
# (e.g. `leap-16.0`) parses but the pipeline refuses to run it
# (see docs/leap-and-cve.md).
targets:
  - factory

# Watch only these packages (empty = all of Factory except exclusions).
packages:
  - curl
  - git

# Outside auto-update:
exclusions:
  - gcc
  - qemu
  - kernel

concurrency: 4
daily_sr_cap: 20
kill_switch: false
report_only: true
dry_run: true

# The OBS home project the worker branches into (empty = derive it
# from the OBS username, home:{OSC_USERNAME}).
home_project: ""
```

Mount your copy over the default:

```sh
podman run --rm -v "$PWD/my-config.yaml:/app/config.yaml:ro" freshcrab
```

An invalid config fails fast with an error naming the problem (unknown
key, wrong type, out-of-range value, tab indentation, inline flow
syntax).

## Dry-run

Dry-run is the default, and it is global: one mode governs the
watcher, the queue, the dispatcher, and the worker. In dry-run
nothing is written or filed anywhere — the watcher polls the collectors
and prints what it WOULD queue (package, Factory version, newest
upstream version, collector source), the queue evaluates the dedup
rules and prints the decision for each candidate (would-enqueue /
would-skip + reason), and the dispatcher and worker print the full
plan for each queued entry (the update steps, the SR description, the
one `.changes` entry, and the exact SR payload — source/target
project and package, the full request XML) and take no action. Every
mutating operation goes through the single dry-run guard
(`src/dry_run.rs`); every component consults it before mutating state.

The mode resolves as CLI flag > env var > config file:

| Source | How |
|---|---|
| CLI flag | `--dry-run` (force on) / `--live` (force off) |
| Env var | `FRESHCRAB_DRY_RUN=true|false` (also accepts `1`/`0`/`yes`/`no`; an empty value is unset) |
| Config | `dry_run:` in `config.yaml` (default `true`; only `true`/`false` — the config file does not accept `yes`/`no`) |

The effective mode is logged loudly at startup:

```
=== freshcrab DRY-RUN mode: no changes will be made ===
```

or, in live mode:

```
=== freshcrab LIVE mode: changes WILL be made ===
```

All plan output goes to stderr, so stdout stays machine-readable JSON.
To switch a run to live:

```sh
podman run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" freshcrab --live --packages foo bar
# or
FRESHCRAB_DRY_RUN=false podman run --rm -v "$PWD/config.yaml:/app/config.yaml:ro" freshcrab --packages foo bar
```

## The dispatcher (report_only: false)

With `report_only: true` (the default) the watcher prints the queue
and stops. Report-only gates the dispatcher only: the watcher still
enqueues, and in live mode `queue.json` is written (use `dry_run` to
prevent all writes). With `report_only: false` the dispatcher runs after the
watcher: it picks pending queue entries — security (CVE-driven) first,
then routine, at most `concurrency` per run, stopping when the daily
SR cap (`daily_sr_cap` SRs filed today) is reached — drives each
through the worker, and prints the dispatch report as JSON:

```json
{
  "dispatched": 2,
  "filed": 0,
  "planned": 2,
  "skipped": 0,
  "escalated": 0,
  "cap_remaining": 20,
  "outcomes": [
    {
      "package": "foo",
      "outcome": "planned",
      "reason": "dry-run: plan logged, nothing filed",
      "sr_id": null
    }
  ]
}
```

In dry-run (the default) every entry is `planned`: the plan and the
exact SR payload are logged to stderr, nothing is filed, and the queue
entry stays `pending`. In live mode the worker files the SR
(`POST /request?cmd=create`) and the entry is marked `done` with the
request id — once the live executor exists. The live executor is the
remaining work: live mode refuses to file (the update steps were not
performed) and the entry escalates instead. Set `home_project` in `config.yaml` (or
`OSC_USERNAME` in the environment) so the worker can resolve the
branch project; without it, live filing escalates and dry-run planning
notes the gap.

Durability: every run starts by resetting entries stranded in
`in_progress` by a crashed earlier run back to `pending`, and a filed
SR is saved to the queue file immediately (not only at the end of the
batch). An escalated entry is parked with its reason and timestamp in
`queue.json` — it stays parked until a newer upstream version arrives.
The daily SR cap counts SRs filed in the local queue file only;
filings from another host fall outside the cap.

## Pause via the kill switch

Set `kill_switch: true` in `config.yaml` and restart the container.
The watcher prints "kill switch is on: pipeline paused, nothing
queued." and exits without doing anything. Set it back to `false` to
resume.

## Project hygiene (report-only)

`freshcrab hygiene` sweeps a project for two kinds of staleness and
prints the findings as JSON. Report-only: the sweeps read only and
change nothing on OBS — there is no `--live` flag and nothing is
deleted or removed. The kill switch pauses the run like the pipeline.

```sh
cargo run -- hygiene --project devel:languages:python
```

With no `--project` flag the projects come from `hygiene_projects`
in `config.yaml`, else the home project (`home_project`, or
`home:{OSC_USERNAME}`). The sweeps need OBS credentials
(`OSC_USERNAME` / `OSC_PASSWORD`): the build results and the request
search are authenticated reads, and without them the run fails closed.

- **Obsolete repositories.** A repository whose build path targets
  a project or repository that no longer exists: the target project
  is gone (404), or the target project exists but carries no such
  repository. Each finding names the repository, the path, and the
  reason.
- **Long-broken packages.** A package that fails in every repository
  that counts for it, has not built successfully in 90 days, and was
  never integrated — no accepted submit request ever came from the
  project or a branch of it. A package in Factory counts Tumbleweed
  among its repositories; a package only in the devel project does
  not — failing on Tumbleweed is fine as long as it builds on the
  older releases. Each finding names the package, whether it is in
  Factory, the failing repositories with their codes, and the last
  successful build time (or none).

## Read the queue

The watcher prints the queue as JSON (one entry per package behind):

```json
[
  {
    "package": "foo",
    "factory_version": "1.9",
    "upstream_version": "2.0",
    "status": "pending",
    "target": "factory",
    "kind": "routine"
  }
]
```

`target` is the distribution (`factory`; Leap targets are planned —
see `docs/leap-and-cve.md`). `kind` is
`routine` (version bump) or `security` (CVE-driven); security
entries are dispatched before routine ones. The persistent queue
state file (`queue.json`, written by the queue module) holds the
same entries plus `created_at` / `updated_at` and the full status
set: `pending`, `in_progress`, `done`, `blocked`, `escalated`.
Filed entries also carry `sr_id` (the OBS request id) and security
entries carry `cves` (the CVE ids they fix); the dispatcher counts
`sr_id` entries filed today for the daily SR cap. `blocked` and
`escalated` entries need a human (see `worker/brief.md` for what
escalates).

Only one writer runs at a time: the queue takes an exclusive lock on
`<queue>.lock`, held until the process exits. A second writer (a
manual run racing the scheduled one, or the same process opening the
queue twice) fails fast with a lock error and exits 1 — that run is
skipped, not partial, and nothing is lost. Just re-run it; the next
scheduled run picks the packages up.

## Tools in the container

All worker tools are the distro versions, installed with zypper from
the openSUSE repos — nothing is built from source. The agent invokes
them by name:

| Tool | What it is | How the agent invokes it |
|---|---|---|
| `rpmcrab` | the linter | `rpmcrab <rpm>` — target 0 errors / 0 warnings |
| `spec-cleaner` | the spec cleaner | `spec-cleaner -i --remove-groups --suse-copyright <spec>` (full mode, final step) |
| `osc` | the OBS client | branch, build, commit, file SRs via the OBS API |
| `bugwarden` | the Bugzilla helper | read bugs, post comments |
| opensuse-packaging-skill docs | the packaging skill (fetched at build time, tag v3.27.0) | read at `/usr/share/doc/freshcrab/opensuse-packaging-skill/` — `SKILL.md` first, then the `references/` section for the block in progress |

The skill docs are NOT in this repo. They are fetched at image build
time from tag v3.27.0 of openSUSE/openSUSE-packaging-skill (see the
`ARG PACKAGING_SKILL_TAG` / `ARG PACKAGING_SKILL_SHA` in the Dockerfile —
the build verifies the clone matches the pinned SHA, so a tag that moves
fails the build) and copied into the image.
They are the only thing in the image that is not a distro package.
The tag is bumped by the weekly skill-tag-bump workflow
(`.github/workflows/skill-tag-bump.yml`), which opens a PR when a new
tag is released — Dependabot's docker ecosystem tracks FROM image
tags only.

## Credentials

Secrets stay outside the image. OBS credentials (oscrc) and the GitHub
token are injected at run time:

- **In the container:** mount a file or pass environment variables,
  e.g. `podman run --rm -v "$HOME/.config/osc:/root/.config/osc:ro"
  freshcrab ...`.
- **In CI:** GitHub Actions secrets.

The watcher and queue mostly need no credentials in report-only mode:
the Factory and devel-project reads use the OBS public API
(`/public/source/...`). The open-submit-request dedup check uses the
OBS search API, which has no public equivalent and returns 401 without
credentials — without OBS credentials the check fails and the package
is skipped (fail-closed) instead of being queued on an unchecked
dedup. Filing a submit request needs credentials too. The credentials
are read from the `OSC_USERNAME` / `OSC_PASSWORD` environment
variables (the OBS API accepts HTTP Basic auth with oscrc
credentials); pass them to the container with `-e`:

```sh
podman run --rm -e OSC_USERNAME=scarabeus_iv -e OSC_PASSWORD=... \
  -v "$PWD/config.yaml:/app/config.yaml:ro" freshcrab --packages foo
```

Logging excludes the values. Without them the dedup check fails
closed as above, and any live filing attempt fails loudly instead of
filing anonymously.

## Run the tests

```sh
cargo test
```

No live network is used in the tests; the fixtures in `tests/fixtures/`
stand in for Repology, Anitya, PyPI, Distrowatch, and the OBS API.
