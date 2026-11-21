# Leap and CVE validation (planned)

This is the design for extending freshcrab beyond Factory: validate
CVEs and submit updates to Leap. It is a **plan + scaffold**; the Leap
watcher logic and the CVE data-source integration are the remaining
work. Leap maintenance-incident filing is implemented in the worker
(see "Worker brief changes for Leap" below); the watcher that
produces Leap entries is the remaining step. The extension points are:
`src/target.rs` (distribution targets + the per-target update-policy
hook), `src/cve.rs` (the CVE validation rule + the validator
interface), the target/kind on queue entries with security-first
ordering, and the config `targets:` list with Leap gated off.

## Security first

Keeping stuff secure is of central importance, because automated
agents get exploited:

- **(a) Security fixes are the highest-priority work the system
  does.** The queue ranks CVE-driven (security) updates above routine
  version bumps, and the dispatcher drains security entries first.
  When a security fix and a routine bump are both pending, the
  security fix goes first — always. The happy-path rollover of all
  packages stays behind every security fix.
- **(b) CVE validation is the verification that a security fix
  actually landed.** A version number going up proves nothing — on Leap
  it usually stays put. The changelog check (below) is the verification:
  the package's own record says the CVE is fixed in this version, or the
  changelog names no CVE.
- **(c) The system itself must stay secure.** Credentials live outside
  the repo, the image, and the fixtures — OBS and GitHub credentials come
  only via environment variables / mounted secrets. The CVE
  sources are public reads and add no new credential surface. Every
  submit request still goes through the review gate (branch
  protection, required review, green CI), and the agent keeps the dedup
  and review checks in the path — CVE validation is an *additional*
  check on top of them.
  A compromised or tricked agent that can file submit requests to
  the distro is a supply-chain risk, so the checks stay in the path
  for every submission, security or not.

## Goal

Extend freshcrab to validate CVEs and submit updates to Leap (in
addition to Factory). Concretely, for a given Leap release and a
given package:

- know which CVEs affect that package on that Leap release,
- determine whether each CVE is already fixed in the Leap package,
- and where it is not, produce an update (a backported patch) and
  submit it through the Leap maintenance process.

## Why Leap is different: backports, not version bumps

Factory is rolling: when upstream releases 2.0, Factory moves to
2.0, and "is this fixed?" is answered by comparing versions. Leap
is stable: its packages stay on the version they shipped with, and
security fixes arrive as **backported patches** — the fix is applied
to the old version, the version number does not rise (only the
release number does), and the fix is recorded in the changelog.

So for Leap the version comparison is the wrong test. A CVE is
"fixed" when the backported patch is present, not when the version
number rises. The watcher/queue must therefore distinguish two
kinds of work:

- **Factory: "version bump available"** — upstream is newer than
  Factory (plain RPM version comparison).
- **Leap: "CVE fixed by backport"** — the CVE is fixed when the
  Leap package's changelog names it (below), regardless of the
  version number.

## CVE validation: the changelog carries the CVE

The validation rule is:

> **Every security-fix changelog (`.changes`) entry must carry the
> CVE reference it fixes.**

CVE validation works by comparing the package's changelog entries
against the CVE list:

- If the changelog for a given version names the CVE, the CVE is
  fixed in that version.
- Otherwise, the CVE is unfixed in that version.

The changelog is the package's own record of what it contains, so
it is the ground truth for "does this build contain the fix" —
stronger than the version number, which a backport leaves alone.
The check itself is implemented in `src/cve.rs` as
`changelog_names_cve` (case-insensitive on the CVE id, and a match
must not be a prefix of a longer number, so `CVE-2026-123`
skips a changelog naming `CVE-2026-1234`).

This also gives the worker a checkable rule: **a Leap backport
submission's `.changes` entry must name the CVE.** A submission
whose changelog names no CVE it claims to fix is rejected by the
validator — the fix is unverifiable, so it stays out.

## %check CVE regression tests: the proof, not just the claim

The changelog entry is the tracking layer (the CVE is *claimed*
fixed). The `%check` regression test is the correctness layer (the
CVE is *actually* fixed). The rule is:

> **For a Leap backport — and any CVE fix — the worker must add a
> `%check` regression test that exercises the CVE behaviour, where
> feasible. The test must FAIL on the unpatched code and PASS with
> the backport applied.**

Why it exists: a green build proves the code compiles, not that the
hole is closed. A regression test that fails
without the patch and passes with it is the proof the fix works.
It also guards against regressions: if the patch is later dropped,
or the code drifts so the fix stops applying, the test goes red
in `%check` instead of the vulnerability coming back unnoticed.

The test lives in the package (in `%check`, or in the package's
test suite run from `%check`), and it travels with the backport —
it is part of the submission, not an afterthought. The validator
exposes the hook for checking its presence
(`CveValidator::has_regression_test` in `src/cve.rs`); the trait requires
the implementation to report whether the package carries a `%check`
regression test exercising the CVE. A submission is complete only when
both halves hold: the changelog names the CVE **and** a regression test
is present (or a documented reason why none is feasible — below).

**Feasibility caveat ("where feasible").** Some CVEs have no
practical reproducer — timing and race conditions, ones needing a
specific environment or hardware, or ones whose trigger cannot be
constructed in a test. In those cases the worker **documents why
no test was added** (in the submission: the SR text and the
`.changes` entry note it). "No test" without a stated reason is a gap,
not a judgment call — the reviewer must be able to see that the
question was asked and answered.

## CVE sources (what to consult)

CVE validation needs two inputs per (Leap release, package):

- **The CVE list: which CVEs affect this package on this release.**
  The source is the **SUSE CVE database**
  (`suse.com/security/cve/CVE-YYYY-NNNN`): each CVE page carries the
  "Status of this issue by product and package" table (e.g. Already
  fixed / Released / Not affected), the SUSE Bugzilla entries, and
  the SUSE Security Advisories (`SUSE-SU-...`) that delivered the
  fix. That table is the per-product, per-package answer to "does
  this CVE affect us, and is it fixed". The exact machine-readable
  access to it (API vs the per-CVE pages) is still open — verify an
  endpoint before assuming it.
- **The package changelog: what the Leap package actually
  contains.** The `.changes` file from OBS for the package on the
  Leap project (public API, no credentials — same as the Factory
  spec reads). This is the text `changelog_names_cve` runs
  over.
- **OBS maintenance data (corroboration).** Leap updates are
  delivered through maintenance incidents (`openSUSE:Maintenance`):
  an incident references the CVEs it fixes, and the fixed packages
  land in the release's update project (e.g.
  `openSUSE:Leap:15.6:Update`, verified to exist). An open incident
  for a CVE is corroboration that a fix is in flight; the changelog
  check remains the deciding test.

One caveat: `openSUSE:Leap:16.0:Update` is absent (404) — Leap 16.0's
update delivery takes a different shape from 15.6's `:Update` project.
The exact Leap SR target per release (maintenance incident vs update
project) stays open here.

## Planned components

### Per-distribution target model

`src/target.rs`: a `Target` is `Factory` or `Leap { version }`
(`"factory"`, `"leap-16.0"`, `"leap-15.6"`), with `obs_project()`
(`openSUSE:Factory`, `openSUSE:Leap:16.0`) and `is_implemented()`.
Config gains a `targets:` list (default `[factory]`). Only Factory
is implemented; a Leap target parses but the pipeline refuses to
run it. The queue entry carries its
target, so Factory and Leap entries can coexist in one queue.

### CVE validation step in the pipeline

Where it sits: the watcher, per target.

```
watcher (per target)
  Factory: collectors -> confirm -> version compare -> queue entry
  Leap:    CVE list -> changelog check -> queue entry (security kind)
queue (dedup: devel already fixed? open SR? in flight?)
dispatcher (security first, then routine; SR cap consumed security-first)
worker (backport patch + .changes naming the CVE, or version bump)
```

For Factory, the version comparison alone decides and the CVE
validator stays out of the path (tested: a validator that panics if
called stays silent on the Factory path). For Leap, the CVE
validator decides: a CVE whose changelog already names it is fixed
and produces no entry; a CVE absent from the changelog produces
a security-kind queue entry. The validator interface is
`CveValidator` in `src/cve.rs`; the data-source-backed
implementation is the remaining work.

### Queue ordering: security first

Queue entries carry a kind — `Routine` (version bump) or `Security`
(CVE-driven). `Queue::pending()` returns security entries before
routine ones, keeping insertion order within a kind. The dispatcher
drains security entries first, and the daily SR cap is
consumed by security entries first. The Factory path is routine-only;
the ordering rule is in place, so CVE-driven
entries slot in above routine ones.

### Worker brief changes for Leap

The Leap worker differs from the Factory worker in the *kind* of
change, not in the gates:

- **Backport patch, not version bump.** The worker applies the
  upstream fix as a patch to the Leap version (or takes the patch
  from the upstream fix commit), bumps only the release number,
  and adds exactly one `.changes` entry **naming the CVE**.
- **Different SR target.** The SR goes to the Leap maintenance
  process (maintenance incident / update project for that release),
  not to the devel project — implemented in the worker
  (`Worker::run_maintenance`): the maintained instances are listed
  and the instance whose source project is the target's update
  project is selected (the listing's source project is the update
  project, e.g. `openSUSE:Leap:15.6:Update` — maintenance happens
  there, the release project is frozen), the incident files from
  the branch project the listing names (source package is the branch
  package name, e.g. `foo.openSUSE_Leap_15.6_Update`), the target is
  `openSUSE:Maintenance`, and the release project is the target's
  update project when known (`15.6` → `openSUSE:Leap:15.6:Update`)
  and otherwise omitted (geectl documents the server stores a
  filing-time-resolved value when none is filed; what it resolves
  from is unverified). No cleanup opt-in: the incident source is
  the maintenance working area, which the maintainer may reuse. The
  open-incident dedup is geectl's filing-time check; a duplicate
  found there maps to `Skipped` (already handled), and there is no
  worker-side open-incident check.
  - **Live verification caveat (2026-11-21).** The path is
  implemented against geectl's API contract and tested against
  it, but it is not verified end to end against
  api.opensuse.org: the maintained-instances listing returns no
  instances for real Leap packages there (verified live for
  `vim`, `curl`, `bash`, `nfs-utils`, `python3`, `openssl`,
  `git` — all 404 "no packages found by search criteria", and
  `osc maintained nfs-utils` fails the same way), because no
  `:Update` project carries the `OBS:Maintained` attribute. Only
  15.6 has a known update project; 16.0 and 16.1 have no `:Update`
  project at all (verified live), and Leap 16.x is Git-tracked
  (`scmsync`), so the OBS incident model here covers the 15.x
  line. Whether discovery should stay on the listing, move to an
  explicit `:Update` branch, or follow the Git-based maintenance
  flow is an open follow-up, not assumed here.
- **Same gates.** spec-cleaner full mode, rpmcrab 0E/0W,
  pre-filing adversarial audit evaluated for every product the spec
  builds for, one `.changes` entry per SR, and the CVE changelog
  rule as an additional check: the entry must name the CVE, or the
  submission stays out.
- **Escalation.** A CVE with no clean backport, a patch that does
  not apply, or a fix that changes behaviour escalates to a human
  — same as any other judgment call.

## Extension points in the code (this scaffold)

- `src/target.rs` — `Target` (Factory / Leap), `obs_project()`,
  `is_implemented()` gate, and the `UpdatePolicy` trait with
  `FactoryPolicy` (plain version comparison). The Leap policy will
  be backport-aware and will consult the CVE validator.
- `src/cve.rs` — `CveId` (validated `CVE-YYYY-NNNN`), the
  `changelog_names_cve` check (implemented + tested), the
  `CveValidation` outcome, the `CveValidator` trait (including the
  `has_regression_test` hook for the `%check` CVE regression test),
  and `NotImplementedValidator` (fails loudly; the Factory path
  skips it).
- `src/watcher.rs` — the watcher carries its `target`, a
  replaceable `policy` (`with_policy`), and an optional
  `cve_validator` (`with_cve_validator`, consulted only for
  non-Factory targets). A Leap target fails loudly.
- `src/queue.rs` — entries carry `target` and `kind`
  (`UpdateKind::Routine` / `UpdateKind::Security`); `pending()`
  orders security first. Queue files without target/kind fields
  load with Factory/Routine defaults.
- `src/config.rs` / `config.yaml` — the `targets:` list (default
  `[factory]`); `src/main.rs` fails fast on an unimplemented target.

## Not in this scaffold

- The Leap watcher logic (a Leap client reading the Leap project,
  the backport-aware policy implementation).
- The CVE data-source integration (fetching the CVE list from the
  SUSE CVE database and the changelog from OBS, and wiring them
  into the validator).
- The dispatcher (not part of this scaffold for Factory either).
- Live verification of the maintenance path end to end, and the
  maintenance-discovery question above (listing vs explicit
  `:Update` branch vs Git-based flow).

Those are the remaining work. The scaffold provides the named,
tested seams they plug into. Leap maintenance-incident filing itself
is already implemented in the worker (see above) — what is still
missing is the producer of Leap entries, the Leap watcher, so
`leap-*` targets remain refused at startup.
