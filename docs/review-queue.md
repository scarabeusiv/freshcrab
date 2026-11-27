# Reviewer queue

Tracking: [#21](https://github.com/scarabeusiv/freshcrab/issues/21).

freshcrab triages submissions: OBS submit requests and Gitea pull
requests, read and acted on through geectl's unified pull-request
surface. A ruleset auto-comments or rejects the clear cases,
mid-confidence items sit in a maintained queue, and the rest go to a
human for review or decision. This is the reviewer queue's design; the
system overview is in `docs/architecture.md`.

## Scope

- The queue covers every submission the geectl pull-request surface
  exposes: OBS submit requests and Gitea pull requests, on the
  configured instances.
- It covers freshcrab's own filings and incoming submissions to
  watched packages. The two are the same queue: a submission is
  identified by its handle, not by who filed it.
- The queue triages only; it never files. Filing is the submitter
  queue's job; currently it is the worker's last step (SR filing)
  and, for Gitea, the working-copy layer (see the Submitter queue
  section in `docs/architecture.md`).
- Excluded explicitly: Leap `pool/` pull requests and maintenance
  (`:Update`) requests — they follow other rules.
- Machinery dependency: the geectl pull-request surface
  (https://github.com/scarabeusiv/geectl/issues/112) — search and show
  for discovery and detail, review-level act for comment and
  request-changes, PR-level act for decline, withdraw, and reopen.
  Labels are Gitea-only library operations and are not part of the
  queue surface.
- OBS and Gitea access rule: all reads and acts go through geectl's
  library. freshcrab implements no OBS or Gitea logic of its own: no
  client, no request/response handling, no endpoint construction. A
  new need goes to geectl first and arrives via a geectl release and a
  pin bump.

## Authority

- Act (comment, decline, accept, commit) only where the acting
  account maintains the target. Authority is the union of the OBS
  `_meta` and the git `_maintainership.json` indexes.
- Never accept or decline into openSUSE:Factory itself.
- An explicit reviewer role on the package or project means no accept
  and no direct commit: branch and submit instead. This qualifies the
  trivial-fix direct commit (see Trivial fixes).

## Safety

- Never parse a contributor's spec or run its `_service` on the host:
  `rpmspec` and `rpm -q --specfile` run `%(...)` and Lua at parse
  time, and services run locally. Read diffs as text. Anything that
  must parse goes in a sandbox with no network and no `$HOME`.

## Binding

- Record the request's source srcmd5 at a pinned rev (a `_link`'s
  numeric rev follows its target), the target's srcmd5, or the PR
  head and base, at classification. Re-check them right before
  acting: an accept must not copy content nobody looked at.

## Discovery

- Discovery is a pull-request search on both arms when no backend
  filter is given (OBS first, then Gitea), scoped to the watch scope:
  submissions whose target is a watched package (all of Factory
  except `exclusions`, per `config.yaml`) and submissions freshcrab
  filed (matched by the `sr_id` recorded on the queue entry).
- Discovery runs across ALL configured instances: every OBS instance
  and every Gitea instance in the config, not just the default. If
  more instances are defined, they are all scanned. A submission on
  any instance is a queue item.
- Scoped discovery, not a global search: the queue covers the
  packages freshcrab watches plus its own filings. A global OBS or
  Gitea search has no bounded result set and no per-package
  relevance.
- Discovery runs on every freshcrab run; there is no separate timer.
  Each run re-checks every open queue record against the server.
- One record per `PullRequestRef` (`obs:<id>` /
  `gitea:<owner>/<repo>#<number>`). Re-discovery of a known ref
  updates the record in place, never duplicates it. A ref that leaves
  the server (deleted, superseded) is marked terminal from the server
  state, never deleted locally.
- A multi-action OBS request reads only its first action's endpoints
  (geectl `PullRequest::from_obs`): a request whose first action
  targets an excluded or maintenance package but a later action
  targets a watched package is missed, and the recorded binding
  covers only the first action. A real fix needs a geectl surface
  change (all actions' endpoints), not freshcrab-side parsing.

## Confidence signals

All signals are read through geectl:

- Build status: green only from the request's current sources, on
  Tumbleweed and Leap 16, x86_64 and aarch64 (all green, any failed,
  still building, unknown). An older green build is no evidence. A
  Gitea PR that is not built is unknown, not green. A failure the
  devel project already has is not the submitter's. A failed build is
  the strongest negative signal.
- Review state: existing reviews on the submission (approved,
  changes-requested, asked-pending, none), per `ReviewOpinion`.
- Diff scope: what the submission changes — version-bump-only spec
  change, spec plus patch, new files, changelog entry present and
  naming the change (and naming the CVE on security updates, per the
  CVE rule in `docs/leap-and-cve.md`).
- Author trust: the submission author — freshcrab's own filings
  (known author, known pipeline), the package maintainer, a
  first-time submitter.
- Package risk: the target package — excluded or hand-maintained
  packages, core system packages, security (CVE-driven) updates.
- Server state: `PullRequestStatus` (Open, Merged, Declined,
  Withdrawn, Closed, Superseded, Deleted), draft flag, mergeable flag
  (Gitea; `None` on OBS).
- A signal read that fails (no credentials, malformed response,
  unknown state) is never read as green; the item goes to the human
  tier.

## Tiers

- Auto-actionable: every signal is green and a ruleset rule covers
  the case. The auto actions are comment and request-changes — plus
  accept with a follow-up fix after the grace period when the only
  findings are trivial (see Trivial fixes). OBS decline is
  human-only; in ruleset cases the queue comments instead of
  declining.
- Mid-confidence: signals are mixed, or the case is benign but not
  covered by a rule. The item stays in the maintained queue: it is
  re-checked on every run, its signal snapshot is updated, and it
  carries a triage comment stating what is unresolved. It is never
  auto-actioned.
- Human: conflicting signals, a high-risk package, a security update
  with unclear scope, a failed signal read, or anything the ruleset
  does not cover. The item is escalated with its full context and
  parked until its server state changes or a human acts.
- Merge is human-only, in every tier. Approve is human-only except
  the trivial-findings case, where the queue accepts and the agent
  fixes the trivial item as a follow-up, after the grace period. The ruleset never merges.

## Trivial fixes

- When the only findings on a submission are trivial, the queue
  accepts it. It never pushes back and iterates for a trivial fix:
  push-back churn on a trivial item costs more than the fix.
- The agent does not override the lower tier immediately. Permission
  tiers run package maintainer, then project maintainer, then factory
  maintainer: the queue notifies the lowest applicable tier and a
  grace period runs before the agent fixes the trivial item itself.
  The grace period is a per-tier value in the ruleset: package
  maintainer 7 days, project maintainer 3 days, factory maintainer
  1 day. Only after the grace period expires
  without the owner fixing it does the agent fix it directly. A fix
  by the owner inside the grace period stands the agent down.
- Push back and iterate (comment, request-changes) only for
  non-trivial findings: behavior, coverage, or a claim in the
  submission.
- Trivial means changelog wording and format only. Every other
  checklist finding changes what gets built or shipped and is
  non-trivial.
- Gitea: the agent fixes the trivial item directly, after the grace
  period — push to the PR branch where it has access, or a follow-up PR.
- OBS: a request cannot be rewritten by someone other than its
  author, so the trivial fix lands after accept and after the grace
  period: the agent commits it directly to the accepted package. Write
  permission for the post-accept direct commit already exists. Where
  the submission is freshcrab's own, it refiles with the fix. Hold the
  Factory forward until the follow-up is in devel, so one forward
  carries both: `osc accept` does not forward headlessly, and a second
  forward while one is open gets a 403. The follow-up commit passes the
  same gates as any update. Authority gates the direct commit: no
  accept and no direct commit where the acting account holds an
  explicit reviewer role on the package or project (see Authority).

## Ruleset

- Location and format: a separate declarative file in the repo,
  versioned with the code, so ruleset changes are reviewed like code.
  It is not a section of `config.yaml`: the ruleset is a policy
  artifact with its own version, the config is deployment settings.
- A rule names its signal pattern and its action (comment,
  request-changes, decline, escalate-human, hold). Rules are evaluated
  in file order; the first matching rule wins; no rule matching means
  the human tier. A rule whose findings are all trivial maps to accept
  with a follow-up fix after the grace period, never to request-changes.
- The ruleset carries a version. The queue record carries the ruleset
  version that produced it; a comment body never carries it.
- Fail-closed: anything the ruleset does not cover goes to the human
  tier. A ruleset that fails to load refuses the run, never falls back
  to a default-allow.
- Auto comments, including any quoted submission text, never carry a
  line starting with `merge ok` or `@group : approve`.

## Ruleset signals

Cheap text checks; each is something factory-auto or human Factory
reviewers decline.

### Cheap mechanical signals

- source_validator.
- Every added or removed patch named literally in `.changes`.
- `.changes` edits insertion-only.
- Tarball bytes equal to the Source URL.

### Risk flags

- Changed `_service` / `_link` / `_aggregate` / `*.macros` /
  `.gitmodules`, symlinks, new binaries in sources, vendor/obscpio
  archives, a new source host, bidi or zero-width characters.

### Coordination

- A newer SR from the same project supersedes it.
- The package was removed from Factory, which makes it a new package.
- A new mandatory dependency not yet in Factory, or a paired update
  that is needed.
- A version downgrade against Factory.
- A pre-release (`~rc`, beta) or a leading `v` in `Version:`.

### Build

- Every arch and flavor the devel project enables counts, i586 and
  `_multibuild` flavors included.
- No new rpmlint `E:` against the baseline.
- `setBadness` in an rpmlintrc is an automatic decline (human-only:
  the queue comments).
- `%check` changes: see Test suites.

### Spec

- A `Patch:` declared but not applied, or applied but not declared.
- A `Patch:` / `Source:` declared inside `%if`.
- A patch renamed only for the version bump.
- Both an obscpio and a tarball for one source.
- Unversioned `Obsoletes`; `Obsoletes` plus `Conflicts` on one name;
  a soname bump that doesn't obsolete the old library package.
- Static `.a` outside `-devel-static`.
- `update-alternatives` where Factory uses libalternatives.
- `%{?sle_version}` / `%{?sles_version}` guards.
- `%prep` or another section name inside a comment.
- A switch to a bundled library without a reason.
- A spec-cleaner diff (`--remove-groups --pkgconfig --perl --tex`).

### Sources

- `Version:` equals the tarball and the changelog header.
- The signature is checked when a keyring exists.
- No orphaned `Source` or leftover old tarball.
- Generated files match `pre_checkin.sh` when the package ships one.

### Changelog

- No bare "Update to X.Y".
- Every spec change named in the entry: dependency floors,
  subpackage or soname renames, license, a disabled `%check`. No
  claim without a matching hunk.
- Format: separators, header dates, bullets.
- CVE/boo ids only for what the diff actually fixes, cross-checked
  against the package's open VUL bugs.
- The SPDX license matches upstream's.
- Of these, only changelog wording and format count as trivial; the
  rest change what gets built or shipped.

### Test suites

- Any `%check` change is non-trivial in every tier. Triage signal,
  diff text only: a submission drops `%check`; wraps it in `%if 0`
  or a disabled bcond; masks it (`|| :`, `|| true`); adds skips
  (`--exclude`, `-k 'not …'`, `--skip`, `-j1`). The queue requests
  changes unless a spec comment and a changelog line give the
  reason. Fixes to suggest: a missing test dependency gets a
  `BuildRequires`; a test that cannot run on some arch gets
  `%ifarch` around that test or `ExclusiveArch`. Never a broad
  exclude.
- Freshcrab's own updates: the worker never files an update that
  disables or narrows `%check` without that reason. A bump that
  breaks the tests is a red build, not a reason to skip them.
- Report-only sweep, per run: "upstream ships tests but the spec
  has no `%check`". Detection needs the tarball: a `tests/` dir,
  pytest/tox config, `make check` / `ctest` / `cargo test`
  targets. The sweep lists candidates for a human. Enabling them
  is never an auto-fix: tests may need network, which OBS builds
  lack, or hours of runtime.

## Queue state

- Storage: a separate state file (`review_queue.json`), with the same
  shape and conventions as `queue.json` — one record per ref, JSON,
  statuses, `created_at` / `updated_at`, forward-compatible loading
  (unknown fields default). A separate file, not an extension of
  `queue.json`: review records are keyed by ref, not by package, and
  follow a different lifecycle from update entries.
- Record: ref, status (open, triaged, actioned, escalated, terminal),
  tier, signal snapshot, ruleset version, binding (source srcmd5 at a
  pinned rev, target srcmd5, or PR head and base — see Binding),
  last-checked, action history (each posted comment or review with its
  server-side id).
- Idempotency: an action is recorded with the server-side id it
  produced (comment id, review state). A re-run compares current
  server state with the recorded state and acts only on change, never
  double-posts.
- Re-check: every run re-checks every non-terminal record. A record
  with no server change is skipped without a re-post.
- Stale reset: the update queue's convention — a record stranded in an
  in-progress state by a crashed run is reset to open on the next run.
- Guards: `kill_switch` pauses the queue entirely; `report_only`
  gates filing (the queue files nothing); `dry_run` is the global
  guard — in dry-run the queue prints what it would do and writes
  nothing.

## Human handoff

- Escalation record: like the update queue's `escalation_reason` /
  `escalated_at`, persisted on the record so triage never depends on a
  captured run log. An escalated item stays parked until its server
  state changes or a human acts.
- Run report: each run lists the human-tier items with ref, tier,
  signal snapshot, ruleset version, and the exact question for the
  human. The report is the handoff; the human acts through the geectl
  `pull-request` CLI or the web UI.
- A human decision is recorded on the item (approved, declined,
  dismissed as not a queue item) so a re-run does not re-escalate the
  same submission.

## Rollout staging

- Stage 1, report-only: discover and classify; no posts, no
  review-state changes. Proves discovery, dedup, and signals.
- Stage 2, comment-only: post triage comments on auto-actionable and
  mid-confidence items; no review-state changes.
- Stage 3, reject: request-changes for ruleset-covered cases only.
  OBS decline is human-only; the queue comments in the ruleset cases
  instead of declining. Auto-reject does not go live unproven: it
  starts only after stage 2 has run with its comments verified against
  the ruleset.
- Stage 4, trivial-fix accept: accept plus follow-up fix, only for
  ruleset-covered trivial findings. It starts only after stage 3 has
  run with its actions verified against the ruleset.
- Each stage starts only on an explicit go-ahead, the same gate as the
  dry-run / live switch. The kill switch pauses every stage.

## Reviewer implementation order

One PR per step. Each step needs the geectl surface it uses to be in a
geectl release, with the freshcrab geectl pin bumped. Plusky's review
is required on the implementing PRs.

1. Review-record state file and discovery: search both arms, scoped,
   dedup, one record per ref — report-only. Depends on geectl
   pull-request step 3 (read surface).
2. Signal readers: build status, review state, diff scope, author,
   package risk — report-only. Depends on geectl pull-request step 3;
   build status is already in geectl.
3. Ruleset file and evaluator: fail-closed, first-match-wins, version
   recorded on every record — report-only.
4. Human handoff: escalation record and run report.
5. Comment action: post triage comments — comment-only stage. Depends
   on geectl pull-request step 4 (review-level act).
6. Request-changes action — reject stage. Depends on geectl
   pull-request step 4 (review-level act).
7. Trivial-fix accept path: accept plus follow-up fix (Gitea push to
   the PR branch or follow-up PR; OBS direct commit to the accepted
   package, or refile where the submission is freshcrab's own) —
   last stage. Depends on geectl pull-request steps 4 and 5; the
   Gitea push depends on the working-copy layer.

## Non-goals

- The reviewer queue never files submissions.
- The queue never auto-merges.
- The queue never bypasses the dedup or review checks.
