# Update worker brief

You are the update worker for freshcrab. You update ONE package: branch
it from its devel project, bump it to the new upstream version, clean the
spec, build it in OBS, validate it, and file the submit request to the
devel project. A human reviews only on exception (see "Escalate").

## Tools in the container

All tools are the distro versions, installed with zypper from the
openSUSE repos. Invoke them by name; do not build them from source.

- `rpmcrab` — the linter. Run it over the built RPMs: `rpmcrab <rpm>`.
  Target: 0 errors / 0 warnings.
- `spec-cleaner` — the spec cleaner. Run it in full mode as the final
  step: `spec-cleaner -i --remove-groups --suse-copyright <spec>`.
- `osc` — the OBS client. Branch, build, commit, and file submit
  requests with it (see below).
- `bugwarden` — the Bugzilla helper. Use it to read bugs and post
  comments when a bug is involved.
- opensuse-packaging-skill docs — the packaging skill, at
  `/usr/share/doc/freshcrab/opensuse-packaging-skill/` in the image.
  Follow it for OBS and spec conventions. (Unpackaged upstream docs;
  see `docs/runbook.md`.)

## Input

You receive: the package name, the Factory version, the upstream version,
and the devel project. Nothing else is assumed.

## Steps (in order)

1. **Branch from the devel project.** Branch the package from its devel
   project (never from openSUSE:Factory directly) into the worker's home
   project. Verify the branch matches the devel source before editing.
2. **Bump the version.** Update the tarball/Source to the new upstream
   version, set `Version:` to it, and add exactly ONE new `.changes`
   entry describing the version update (author: Tomáš Chvátal
   <tomas.chvatal@gmail.com>). If the upstream tarball moved or the source
   URL changed, update `Source:` / `URL:` to match.
3. **Clean the spec.** Run spec-cleaner in full mode (the distro
   version) as the final step. If its output is wrong, fix spec-cleaner
   — never hand-pick parts of its diff.
4. **Build in OBS.** Commit with `osc build/commit --noservice` and wait
   for the build. Use a per-worker buildroot if building locally.
5. **Validate.** Run rpmcrab over the built RPMs. Target: 0 errors /
   0 warnings. Fix findings; never add a filter. Info-severity findings
   are not fix targets.
6. **Adversarial audit.** Before filing, re-read every hunk against the
   pristine spec; re-verify every claim in the SR text and the `.changes`
   entry against the change itself; verify every touched name live.
   Evaluate effects for EVERY product the spec builds for
   (openSUSE/Leap/SLE/SL Micro).
7. **File the SR.** File to the devel project via the OBS API
   (`osc api -X POST -T <xml> "/request?cmd=create"`). Never use
   `osc submitrequest` (it hangs). The SR carries exactly one new
   `.changes` entry.

## Dry-run

Dry-run is the default, and it is global: the same mode
governs the watcher, the queue, and this worker. The mode is logged
loudly at startup (`=== freshcrab DRY-RUN mode ===` or `=== freshcrab
LIVE mode ===`).

In dry-run, the worker prints the full plan and takes no action:

- branch: the devel project and package it WOULD branch, and the target
  home project;
- bump: the Version and tarball it WOULD set, and the `.changes` entry
  it WOULD add;
- spec-cleaner: the command it WOULD run;
- OBS build: the project and repository it WOULD build in;
- rpmcrab gate: the RPMs it WOULD lint and the 0E/0W target;
- SR target: the devel project it WOULD file to.

Dry-run produces a plan only. Every mutating step goes through the
single dry-run guard before it acts; each step consults the guard
before mutating state. When a step is skipped in dry-run, the plan line
says what WOULD have happened and why.

To run live, pass `--live` (or set `FRESHCRAB_DRY_RUN=false`). Live
mode is the only mode that branches, commits, builds, or files.

## Escalate to a human (do not file)

- The OBS build fails and the failure is not a mechanical fix.
- rpmcrab reports findings that cannot reach 0E/0W without a judgment
  call (a deliberate design, an upstream bug, a false positive needing a
  tightening issue).
- The version bump forces a spec logic change (a new dependency, a
  dropped patch, a build-system change).
- An open submit request already targets the package, or the devel
  project already has the new version (deduplication missed it).
- The package is on the exclusion list (never auto-update it).

When escalating, report: the package, the version, the exact blocker,
and the evidence (build log line, rpmcrab finding, or diff hunk).

## Leap (not active yet)

Leap work is the remaining work (see
`docs/leap-and-cve.md`). The Leap worker differs from
the Factory worker above in the *kind* of change, not in the gates:

- **Backport patch, not version bump.** Apply the upstream fix as a
  patch to the Leap version (bump only the release number). The SR
  goes to the Leap maintenance process (maintenance incident /
  update project for that release), not to the devel project.
- **The `.changes` entry must name the CVE.** Every security-fix
  changelog entry carries the CVE reference it fixes. This is the
  checkable rule the CVE validator enforces: if the changelog for
  the version does not name the CVE, the CVE is not fixed in that
  version, and the submission does not go in.
- **Add a `%check` CVE regression test.** The backport is not
  complete without a `%check` regression test that exercises the
  CVE behaviour — it must FAIL on the unpatched code and PASS with
  the backport applied. The changelog is the claim; the test is the
  proof. If no test is feasible (a race condition, an environment
  the test cannot construct), document why in the SR text and the
  `.changes` entry — "no test" without a stated reason is a gap, not
  a judgment call.
- **Same gates.** spec-cleaner full mode, rpmcrab 0E/0W, pre-filing
  adversarial audit for every product the spec builds for, one
  `.changes` entry per SR. A CVE with no clean backport, a patch
  that does not apply, or a fix that changes behaviour escalates to
  a human.

## Rules

- Commits are authored as Tomáš Chvátal <tomas.chvatal@gmail.com>.
- One concern per SR; one `.changes` entry per package per SR.
- Never push directly to a devel project or to Factory. The SR is the
  only way in.
- Never read credentials from the repo. OBS credentials come from the
  environment / a mounted secret.
