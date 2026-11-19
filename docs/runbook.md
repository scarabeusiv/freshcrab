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
# Distributions to watch. Only `factory` is implemented; a Leap target
# (e.g. `leap-16.0`) parses but the pipeline refuses to run it until
# the Leap step lands (see docs/leap-and-cve.md).
targets:
  - factory

# Watch only these packages (empty = all of Factory except exclusions).
packages:
  - curl
  - git

# Never auto-update these.
exclusions:
  - gcc
  - qemu
  - kernel

concurrency: 4
daily_sr_cap: 20
kill_switch: false
report_only: true
```

Mount your copy over the default:

```sh
podman run --rm -v "$PWD/my-config.yaml:/app/config.yaml:ro" freshcrab
```

An invalid config fails fast with an error naming the problem (unknown
key, wrong type, out-of-range value, tab indentation, inline flow
syntax).

## Dry-run

Dry-run is the default in this phase, and it is global: one mode
governs the watcher, the queue, and (later) the worker. In dry-run
nothing is written or filed anywhere — the watcher polls the collectors
and prints what it WOULD queue (package, Factory version, newest
upstream version, collector source), the queue evaluates the dedup
rules and prints the decision for each candidate (would-enqueue /
would-skip + reason), and the worker prints the full plan and takes no
action. Every mutating operation goes through the single dry-run guard
(`src/dry_run.rs`); no component mutates state without consulting it.

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

## Pause via the kill switch

Set `kill_switch: true` in `config.yaml` and restart the container.
The watcher prints "kill switch is on: pipeline paused, nothing
queued." and exits without doing anything. Set it back to `false` to
resume.

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

`target` is the distribution (`factory` today; Leap targets are a
planned later step — see `docs/leap-and-cve.md`). `kind` is
`routine` (version bump) or `security` (CVE-driven); security
entries are dispatched before routine ones. The persistent queue
state file (`queue.json`, written by the queue module) holds the
same entries plus `created_at` / `updated_at` and the full status
set: `pending`, `in_progress`, `done`, `blocked`, `escalated`.
`blocked` and `escalated` entries need a human (see
`worker/brief.md` for what escalates).

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
| opensuse-packaging-skill docs | the packaging skill (fetched at build time, tag v3.24.3) | read at `/usr/share/doc/freshcrab/opensuse-packaging-skill/` — `SKILL.md` first, then the `references/` section for the block in progress |

The skill docs are NOT in this repo. They are fetched at image build
time from tag v3.24.3 of openSUSE/openSUSE-packaging-skill (see the
`ARG PACKAGING_SKILL_TAG` / `ARG PACKAGING_SKILL_SHA` in the Dockerfile —
the build verifies the clone matches the pinned SHA, so a tag that moves
fails the build instead of silently changing the image) and copied into the image.
They are the only thing in the image that is not a distro package.
The tag is bumped by the weekly skill-tag-bump workflow
(`.github/workflows/skill-tag-bump.yml`), which opens a PR when a new
tag is released — Dependabot's docker ecosystem only tracks FROM image
tags, so it cannot bump this one.

## Credentials

No secrets are in the image. OBS credentials (oscrc) and the GitHub
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
dedup; credential plumbing is the filing phase's work.

## Run the tests

```sh
cargo test
```

No live network is used in the tests; the fixtures in `tests/fixtures/`
stand in for Repology, Anitya, PyPI, Distrowatch, and the OBS API.
