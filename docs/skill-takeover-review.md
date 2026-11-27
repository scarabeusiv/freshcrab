# Skill takeover review

Review of the packaging skill scripts for takeovers into the
planner/observer architecture. Review for #36; the adopted pieces
are proposed as edits below and tracked in #40–#45.

Method: every listed script read in full at
`openSUSE/openSUSE-packaging-skill` `a6b1841`. Each verdict is grounded
in what the script does, not in the issue summary. Where the issue
description is wrong or incomplete, the item says so with evidence.

The proposed `docs/architecture.md` edits quote against the design
PR's head (`d229b53`, 637 lines). They are proposals, not applied:
`architecture.md` is owned by #35. Proposed `docs/review-queue.md`
edits quote against the same head (446 lines).

General note, true for every ADAPT below: the skill scripts talk to
OBS and Gitea via `osc` / `git-obs` / `tea` directly. Freshcrab
implements no forge logic of its own — every ported behaviour reads
and acts through geectl's library. The per-user state files
(`~/.local/state`, per-task ledgers, baseline files) conflict with
the single queue store in every case; the store replaces them.

## Implementation rule — reimplement in Rust, carry no scripts over

Takeovers are reimplemented in Rust; no bash or Python script is
carried into the daemon. The daemon is Rust so freshcrab runs
anywhere. What transfers is the behaviour and the guard semantics;
what is dropped is the shell/Python harness, the per-user state
files, and the osc/git-obs/tea calls (forge access goes through
geectl's library, per the note above). Every script verdict below
reads "Adapt — reimplement in Rust" on this rule; the
`_obs_scope.py` "Adopt as-is" is the shared-scope design only,
reimplemented in Rust — the Python file does not transfer.

## Verdicts

| Item | Verdict |
|---|---|
| `references/token-budget.md` | Adapt |
| `SKILL.md` (three-block pipeline) | Adapt |
| `agents/` playbooks | Adapt |
| `scripts/incoming-requests.py` | Adapt — reimplement in Rust |
| `scripts/outdated.py` | Adapt — reimplement in Rust |
| `scripts/watch-submissions.sh` | Adapt — reimplement in Rust |
| `scripts/sr-status.py` | Adapt — reimplement in Rust |
| `scripts/preflight.sh` | Adapt — reimplement in Rust |
| `scripts/incoming-review.sh` | Adapt — reimplement in Rust |
| `scripts/pr-guard.py` | Adapt — reimplement in Rust (rule set only) |
| `scripts/bug-guard.py` | Adapt — reimplement in Rust (predicate only) |
| `scripts/obs-wait.py` + `scripts/build-wait.sh` | Adapt — reimplement in Rust |
| `scripts/gate.sh` | Adapt — reimplement in Rust |
| `scripts/target-gate.sh` + `scripts/pool-pr.sh` | Adapt — reimplement in Rust |
| `scripts/autoforward-gate.sh` + `scripts/forward-check.py` | Adapt — reimplement in Rust |
| `contrib/container/` | Adapt (deployment pattern) |
| `scripts/_obs_scope.py` | Adopt as-is (design) — reimplement in Rust |

16 adapt, 1 adopt as-is, 0 idea-only: every listed behaviour transfers
in some form. 12 of the adapts are reimplementations in Rust and the
adopt is the shared-scope design reimplemented in Rust; no script
file transfers.

## `references/token-budget.md` — Adapt

The orchestration rules check out against the file's "Briefing a
sub-agent" section: one package per child, dispatched only after
`preflight.sh` says proceed, never two children on one checkout;
parallel children below the provider's concurrency limit, counting
two sessions per child (worker plus reviewer); run children in the
background and take each as it returns; resume an aborted child
instead of starting over; keep a ledger of decisions and landed ids;
the review runs in a context of its own — a PASS the author wrote
for its own change is no review; a child that hands back after a
third BLOCK is reported as blocked with no further review round. The
budget is context economy, not money: context is a budget measured
on a 180-agent sweep where agents were 93% of the spend, with a
per-playbook cap of 48 KB.

What must change: the provider's concurrency limit becomes the
central observer's worker-concurrency control, with the reviewer
counts-as-2 rule becoming a reviewer-worker reservation; the
`/var/tmp/<task>/ledger.md` file becomes durable queue-store records
of decisions and landed ids; resume becomes the item-lock reclaim
and retry; background children are inherent to queue workers, with
file-each-once-green becoming submitter-queue behaviour; the
own-context review principle maps onto the re-discovery and cooldown
rule for self-owned submissions. The 48 KB playbook cap survives as
per-worker brief and context discipline feeding the observer's spend
pacing, not as a session budget.

Omissions in the issue, not errors: the REVIEW-PENDING fallback (only
for a child that hands back `REVIEW-PENDING` does the orchestrator
start the review itself, at once, once per tree); "Ask for a report,
not a transcript… at most ~1.5 KB, the full report in a file";
"Quote the user's request verbatim in the brief"; and the "Tool
output economy" section (build logs never enter context, gates in
one call, "Waiting is one bounded call, never a loop" — one 10-day
session spent ~430M tokens on ~900 sleep/osc-results rounds).

## `SKILL.md` (three-block pipeline) — Adapt

Confirmed: Block 1 Triage ("does the package need updating?"),
Block 2 Update/build/clean up, Block 3 Submit to Factory and watch;
"The three blocks form a loop: Block 3 feedback (a decline, a
staging FTBFS, a reviewer comment) routes back into Block 2, which
rebuilds… and re-gates before the next submit."

What must change: the pipeline is a single-session, human-in-the-loop
procedure with per-instance approval boundaries, while freshcrab is
a daemon whose equivalent boundaries are the guardrails (self-authored
submissions need an independent human accept bound to the exact
reviewed revision; the queue never auto-accepts third-party
substantive submissions; only a deterministic executor holds forge
credentials). Mapping: Block 1 → updater-queue discovery, Block 2 →
updater worker, Block 3 → submitter worker, with the Block 3 → Block
2 loop becoming re-queue to the updater with review state attached;
sequential per-package blocks become queue items under item locking.

Flags: (a) The issue's shorthand "triage → reviewer/discovery"
conflates two things. Block 1 triage is upstream-outdated discovery
(Repology/Anitya sweep, verify against forge/registry APIs, compare
by date not version string, filter pins/multi-track) — it feeds the
updater queue, not the reviewer queue. Submission triage is the
reviewer queue's job and has no counterpart in Block 1. (b) The
issue omits the pipeline's embedded fourth role: gate 6, the
adversarial change review, which must have COMPLETED and returned
`PASS` inside Block 2 before Block 3 may submit. (c) Omitted: the
"Bug-driven entry point" (`references/bugzilla-cve-triage.md`
feeding the same pipeline), which maps to the bugwarden source.

## `agents/` playbooks — Adapt

The issue's claim — `changes-review.md` and `incoming-review.md`
are the reviewer queue's two roles — is broadly right, but the two
roles have different trust postures the issue does not state, and
the other three playbooks map elsewhere.

- `triage.md` — Block 1 discovery, not a reviewer role. Enumerates
  maintained packages, finds candidates via `outdated.py`, verifies
  each against forge/registry APIs by date, outputs a six-bucket
  report (likely-real updates, pins/multi-track, Repology artifacts,
  devel already ahead, NOT CHECKED — source down, UNDETERMINED —
  packaged ahead of upstream). Maps to updater-queue discovery; the
  six-bucket output contract becomes queue-item states and outcomes.
- `update-build.md` — Block 2, one package: preflight, front-load
  upstream change extraction, clean, local/OBS-ONLY build, VUL-bug
  check before writing `.changes`, one-call `gate.sh`, then starts
  its own `changes-review` sub-agent and waits; after a third BLOCK
  on the package, hand back with the last review instead. Maps to
  the updater-queue worker; the nested-reviewer spawn becomes a
  separate reviewer-queue item.
- `submit-watch.md` — Block 3: pre-commit gate (show full diff,
  `gate.sh`, change review PASS), commit, file SR/PR (with
  `--cleanup` from `home:` branches, `forward-check.py` DUE before
  forwarding own devel requests), watch via `sr-status.py` /
  `watch-submissions.sh`, triage declines back to Block 2 (trivial
  fix → Block 2, rebuild, re-gate, resubmit with `--supersede`).
  Maps to the submitter-queue worker; the human-go gates become the
  human-accept guardrail and the watch loop becomes observer state.
- `changes-review.md` — adversarial review of the daemon's own
  change, pre-commit/pre-SR, whole change (spec, patches, sources,
  build, `.changes`), binary PASS/BLOCK (no FIXABLE), review-only,
  records verdict via `gate.sh --review`. This is the reviewer queue
  acting on self-owned items — but it runs synchronously inline
  before filing, while the design puts self-owned review after
  re-discovery and a cooldown. Keep the checklist (9 items, incl.
  "prove every security claim from the code, twice over") and the
  verdict-recording stamp as the audit trail, but re-time it to
  post-cooldown re-discovery with its own worker and context.
- `incoming-review.md` — text-only review of one contributor's
  SR/PR to a package the user maintains, three verdicts
  PASS/FIXABLE/BLOCK, never accepts/approves/declines/comments
  itself, records via `incoming-review.sh --record` with a key
  binding the reviewed content. Its HARD RULE text-only posture
  ("never run `rpmspec`, `rpmbuild`, `osc build`, `osc service`,
  `gate.sh`… on a submission") transfers directly as "submission
  content is untrusted data, never policy". Its FIXABLE verdict
  ("accepted with a follow-up fix from the maintainer") presumes a
  human maintainer accepts — the daemon never auto-accepts on
  FIXABLE; the grace periods and ruleset sit on top of this
  checklist, and the caller-posts-comment / user-go accept steps
  become the human-accept gate.

Flags: (a) The verdict asymmetry: changes-review is binary
PASS/BLOCK while incoming-review is ternary PASS/FIXABLE/BLOCK — a
daemon reviewer must not collapse them. (b) The issue omits both
reviewers' verdict-recording mechanisms (`gate.sh --review` keyed on
a tree hash; `incoming-review.sh --record` keyed on a sha256), which
are the audit-trail pattern the single store should carry. (c)
`SKILL.md` itself describes changes-review as "gate 6" inside Block
2 and incoming-review as "a contributor's submission to your package
reviewed as text" — supporting the two-roles claim but also showing
changes-review is the updater's own gate, not a standalone queue
role in the skill's framing.

## `scripts/incoming-requests.py` — Adapt, reimplemented in Rust

The discovery logic is the reviewer-discovery shape freshcrab needs:
buckets A (SR `new`, no reviewer, explicit person `role="maintainer"`
from OBS `_meta` UNION `osc maintainer -U` for git/scmsync packages),
B (SR `review`, pending `by_user==you` or `by_project`/`by_package`
you maintain, `by_group` skipped even as a member), C (Gitea PR
`open`, you in `requested_reviewers` by exact login, team-only
skipped and re-verified per PR). Own items are dropped in both legs
(`creator == user`, PR author == user). One global `/search/request`
call for A/B; every `osc`/`git-obs` call has a 60 s timeout and a
timeout counts as a failed query. OBS failure hard-fails with exit 2,
never "nothing pending"; a failed Gitea search leg prints a stderr
WARNING and the output says PRs are UNKNOWN.

What must change: it is a one-shot CLI printing a human table for
one user, covering only OBS and one Gitea instance
(`src.opensuse.org`), not GitHub/GitLab/bugwarden or all configured
instances. In the daemon this becomes reviewer discovery writing
queue items to the single store, with per-leg UNKNOWN as item/leg
state — not stderr text, since `main()` exits 0 even when the PR leg
is UNKNOWN, so an unattended caller keying on exit code cannot see
it. Reimplemented in Rust: keeps the three-bucket discovery, the
own-item drop and the fail-closed UNKNOWN legs; drops the one-shot
CLI, the printed table and the osc/git-obs subprocess calls.

Flags: a silent cap the issue omits — bucket C's search is
`limit=50` with no full-page warning, so a larger review-requested
set silently truncates. And "failed Gitea leg reads UNKNOWN" is
narrower than stated: only the initial search failing yields
UNKNOWN; a per-PR detail fetch failure appends a row with state
"?" and reason "detail fetch failed" while the leg still counts as
known.

## `scripts/outdated.py` — Adapt, reimplemented in Rust

The fail-closed contract is exactly the updater-discovery contract
freshcrab needs: Repology (paginated, 60 s timeout, retries
429/502/503/504 up to 4 attempts, keeps already-downloaded pages) +
Anitya over names Repology did not flag + a forge pass over
still-unmapped names (one `osc cat` for Version/URL/Source0, Anitya
homepage retry, then GitHub/GitLab/PyPI/npm/crates.io with the
registry-authority rule — a registry serving Source0 decides, a newer
git tag elsewhere is ignored). One WARNING per lost source as it
happens (deduped), the report ends in a `# COVERAGE:` verdict, and a
lost source exits 3. A 404 / "no releases" answer is a fact, not a
loss, and does not degrade the run. Also exit 3 when 0 of 10+ names
are found in `--project` (wrong input), and when the reference spec
can't be read.

What must change: it is a one-shot CLI over a piped/`--names` list
printing text. In the daemon the COVERAGE verdict and exit-3 contract
become per-source state on updater queue items, and the gaps below
must be closed so "partial" is always machine-visible rather than
text-only. Reimplemented in Rust: keeps the multi-source sweep, the
COVERAGE verdict and the exit-3 contract as per-source item state;
drops the one-shot CLI and the piped text output.

Flags: the issue's exit-3 claim is true but incomplete in two
directions. First, silent losses exist: Anitya homepage-retry
failures are swallowed with a bare `continue` (no warning, no down
entry), and Anitya failures for names Repology already flagged are
never warned or recorded ("its failure loses nothing"). Second,
UNDETERMINED names do not exit 3: `forge_behind` / `forge_nodata` /
`forge_unmapped` / `a_behind` names print as "NOT determined" but the
run still ends `# COVERAGE: complete …; N name(s) UNDETERMINED`
with exit 0 — so an exit-code-driven caller can read a partial sweep
as clean. Omitted: deliberate `--no-*` skips are named on the
complete line (`# COVERAGE: complete except, on purpose: …`) and exit
0; a run with no names at all also exits 3.

## `scripts/watch-submissions.sh` — Adapt, reimplemented in Rust

The delta semantics transfer: it diffs active OBS SRs
(`roles=creator`, `states=new,review`), incoming SRs
(`roles=maintainer,reviewer`, own creations removed), and open Gitea
PRs the user created against a saved baseline, printing
`BASELINE-INIT` / `NOCHANGE` / `CHANGED` with `NEW SR`,
`SR …: staging A -> B`, `RESOLVE SR`, `NEW INCOMING SR`,
`RESOLVE INCOMING SR`, `NEW PR`, `RESOLVE PR` lines. Failure rules
are good: the OBS leg hard-fails (`WATCH-ERROR`, exit 2, baseline
untouched; an empty OBS set without `--allow-empty` is also an
error), while incoming/Gitea legs fail soft (diff skipped, baseline
keeps that leg's previous set, `! <leg> unavailable` note — a leg
failure never fabricates RESOLVE lines). A full page (incoming 250,
PRs 50) likewise skips that leg's diff rather than reporting
unprovable RESOLVEs.

What must change: the mechanism is a shell + embedded-Python cron
one-shot with a per-user JSON baseline file — directly in conflict
with the decided single-store shape (the same conflict already
flagged for #33's `review_queue.json`). In the daemon the observer
diffs queue-item states in the store on its loop; the baseline file
and the cron entry point go away, keeping the delta vocabulary and
the fail-closed leg rules. Reimplemented in Rust on the rule above:
the delta vocabulary and fail-closed leg rules transfer as daemon
behaviour; the shell + embedded-Python cron one-shot and the
per-user JSON baseline file do not.

Flags: "RESOLVE lines → fetch final states" misdescribes the file.
Final states are fetched only with `--resolve`, only for outgoing
OBS SRs (one search call per 50 ids, yielding `accepted by X` /
`declined by X: "…"` / `superseded by #N` / `revoked by X`). Without
it, RESOLVE lines explicitly tell the caller to fetch. PR RESOLVE
lines never fetch even with `--resolve`, and NEW INCOMING lines never
fetch anything — the caller reviews via `osc request show --diff`.
"NOCHANGE → stay silent" is loose wording: the script prints the
`NOCHANGE` first line (the protocol's stable first line); "silent"
means no delta lines, not no output. No timeouts: the three
shell-level `osc api` / `tea api` calls have no `timeout` wrapper,
unlike the 60 s per-call timeouts in the Python scripts — a hung call
hangs the cron run. Omitted rules: `maintenance_incident` /
`maintenance_release` entries are aggregated into one counted
`INCOMING MAINTENANCE: <n> new/closed (…)` line, never per-request
review to-dos; and its "incoming" set is roles-based (includes group
reviews that `incoming-requests.py` deliberately excludes), while its
PR leg covers PRs the user created, not review-requested ones. Exit
codes are 0 (INIT/NOCHANGE/CHANGED) / 2 only.

## `scripts/sr-status.py` — Adapt, reimplemented in Rust

The status-view design is the observer view freshcrab needs: one
Markdown table of OBS SRs + src.opensuse.org PRs (two legs: created
and review-requested), declines first (where "bad" also covers STALE
and red/stale/unreadable PR builds), and STALE detection (compares
the SR's pinned `rev` against the source's current `rev`/`srcmd5`
plus link/service `xsrcmd5`/`lsrcmd5`, then an expanded file
comparison excluding `_scmsync.obsinfo`; a changed source yields
`STALE — source changed after the pinned revision` with a refile
command, with `forward-check.py` advised for a devel-project source
instead of a refile). Per-call timeout is 60 s, cut to the time left
before the deadline (minimum 5 s).

What must change: it is a one-shot human-facing renderer over
`osc`/`git-obs`, and its states live in printed text (including a
header scope string saying PRs are UNKNOWN when a leg fails). In the
daemon this becomes the observer's status view over the store, with
UNKNOWN/STALE as item state, and the caps below either removed or
kept as explicit, disclosed policy. Reimplemented in Rust: keeps the
unified status view, the declines-first ordering and STALE detection
as item state; drops the one-shot renderer and the osc/git-obs calls.

Flags: "No silent cap" is wrong — there is a cap. `--limit`
defaults to 40 SR rows: excess non-decline rows are dropped (all
declines kept, then the newest of the rest), and the header announces
it (`N of M shown — --limit 0 for all`). The cut is disclosed, not
silent — but capped-out rows vanish rather than printing UNKNOWN.
`--brief`/`--summary` remove the cap; `--limit 0` removes it.
Separately, each PR leg asks `limit=50`; a full page is flagged
"more may exist" in the header/summary, but the extra PRs are simply
not shown. "Past the deadline everything prints UNKNOWN" is wrong
for the default table view. `--deadline` defaults to 80 and gates
only starting per-item lookups (comments and closed-since return
SKIPPED past it). Discovery (the `/request` search, PR-leg fetch) is
not deadline-gated. In the table, past-deadline rows print `(not
fetched: --deadline reached)` for comments and `; STALE not checked
(--deadline reached)` — the literal `UNKNOWN (not looked up:
--deadline reached)` wording appears only in `--summary` sections.
Declines' reasons need no call and are unaffected by the deadline.
Discovery failure still hard-exits 2. Omitted: the table mode exits 0
even when a PR leg failed or comment fetches failed (warnings only);
the exit-code verdicts (green/merged 0, red/closed 1, lookup 2,
pending 3, stale 4) exist only in `--pr` single-PR mode. STALE
caveats the issue omits: multi-action requests yield `STALE not
checked (N actions)`, and a request pinning no revision is not
checked at all.

## `scripts/preflight.sh` — Adapt, reimplemented in Rust

The dispatch-gate lattice is the right gate logic and is genuinely
fail-closed: 7 checks (devel spec Version + `.changes` header;
incoming SRs; outgoing devel→Factory SRs; Gitea PRs on a scmsync
devel repo; other-`reviewer`-role notice; target-agnostic
`/search/request` sweep; contributors' submissions via
`_incoming.py` maintains/stamp), submit-actions only (a
`set_bugowner`/`add_role`/`delete` request is not an update in
flight), and `fail()` prints `VERDICT: CHECK-FAILED` and exits 2 —
including for empty/malformed collections ("OBS answers an empty
`<collection/>`, never nothing") and for a failed review-stamp read.
Declined SRs are surfaced because `osc sr` still prompts over them.
Per-call timeouts are 30 s for `osc`/`git-obs` (with 404-as-fact
distinguished from failure), 120 s for `devel-of.sh`.

What must change: it is a per-package shell one-shot whose interface
is exit codes plus printed text, using `osc`/`git-obs` and
`_incoming.py` review stamps on disk. In the daemon this becomes the
dispatch gate over queue items in the single store (verdicts as
item-state transitions, stamps as store state, geectl library for
forge reads). Reimplemented in Rust: keeps the dispatch-gate lattice
and the exact STOP/INCOMING precedence; drops the shell one-shot,
the exit-code interface and the on-disk review stamps.

Flags — the issue misstates the precedence, which is the thing to
get exactly right: "INCOMING beats FORWARD and STOP" is wrong about
STOP. The verdict block checks in-flight STOP first (outgoing /
own-incoming / own-PRs / sweep-blocking → `VERDICT: STOP`, exit 3)
before the INCOMING check (contributors non-empty → `VERDICT:
INCOMING`, exit 5). True precedence: in-flight STOP (3) > INCOMING
(5) > landed-STOP (3, devel and target already at the same version)
> FORWARD (4, stranded devel update) > PROCEED (0). INCOMING beats
FORWARD and beats the landed-STOP only. The header confirms the
STOP-first half: "your own request in flight still wins (3)" — when
contributors' items exist, the stop checks narrow to your own, so
your own SR still STOPs rather than yielding INCOMING. Exit 2 is
omitted from the issue's mapping and conflates two things: usage
errors and CHECK-FAILED both exit 2; only the printed `VERDICT:
CHECK-FAILED` line distinguishes them. "Never 'nothing incoming' or
'not yours'" overstates the rule. The script does print
`contributors' submissions: in flight, not yours to review` when
`_incoming.py maintains` returns 3 — that is a legitimate fact
outcome, and those items then count as in-flight (→ STOP). What is
fail-closed is a maintains-lookup failure (rc 2 or crash →
CHECK-FAILED, never "not yours"). Omitted scoping: the Gitea PR leg
runs only when the devel project has `<scmsync>`; a non-scmsync
devel project gets no PR check at all. The reviewer-role notice
(check 5) prints a branch-don't-commit-directly instruction but does
not change the verdict.

## `scripts/incoming-review.sh` — Adapt, reimplemented in Rust

The record/key/hold semantics the issue describes are real, but the
mechanism is a one-shot human/agent CLI writing sidecar JSON files,
not a daemon component. `--show` prints the facts, sanitized diff,
build (shown, never required) and a final `key <sha256>`; `--record
FILE` (first line `PASS|FIXABLE|BLOCK <ID> key <sha256>`, rest =
comment) re-derives everything from scratch and compares. The stamp
is `~/.local/state/opensuse-packaging/incoming/obs/<ID>.json` or
`gitea/<owner>_<repo>_<N>.json` (owner/repo lowercased, `%`→`%25`,
`_`→`%5F`), mode 0600, atomic replace, fields `v=1, kind, id,
creator, verdict, key, recorded (UTC), scan, build, findings,
comment_sha256, comment` plus OBS or Gitea detail. PASS/FIXABLE are
refused while any finding stands, while the comment breaks a rule, or
until the installed pr-guard contains the foreign-accept rule; BLOCK
always records but stores no comment if the comment breaks a rule.
The FIXABLE hold is real: `prune` keeps a FIXABLE stamp while it may
hold the Factory forward, and the guard asks before any forward to
Factory while devel's files still equal the stamp's source files
(unless Factory already holds them) — a per-package ask-gate at
forward time, not a queue.

What must change: move the stamp into the single store (#33's
separate `review_queue.json` is already flagged as conflicting;
per-submission files under `~/.local/state` are the same violation),
reimplement re-derivation as a daemon-side re-check (no `osc` /
`git-obs` CLI subprocesses, no `$TMPDIR` scratch, no 60 s timeouts),
and turn prune into store GC plus queue-item hold state. The
1,900-line spec parse-surface scanner does not transfer — only the
verdict/key/hold shape does. Reimplemented in Rust: keeps the
verdict/key/hold semantics (re-derivation, key-moved refusal,
FIXABLE hold); drops the one-shot CLI, the sidecar JSON files and
the osc/git-obs subprocesses.

Flags: stamp key contents are incomplete as stated, and PR keys are
a different shape. The OBS key is a sha256 over canonical JSON of
kind, id, creator, actions, source (srcmd5, files with md5s) and
target (exists, files with md5s) — `actions` carries full
type/source/target attributes (incl. `rev` and options), and the key
also covers the creator and the target's files, which the issue
omits. It does not cover build, findings, description or diff. The
Gitea key has no `actions`/`srcmd5` at all: kind, id, creator, head,
base, base ref, merge base, files (path to sha and mode), base files.
`--record` really does refuse a moved key — confirmed: on a key
mismatch it prints `KEY MOVED`, exits 3, and deletes any earlier
stamp for that request. (A lookup failure instead exits 5 and leaves
the old stamp alone.) `--prune` does not simply "remove stamps of
final submissions". An OBS FIXABLE stamp stays while the target's
files (minus `_link`) still equal its source's; a PR FIXABLE stamp
always stays, even merged/closed ("a FIXABLE PR's hold reads the
commit OBS synced, which this does not"). A failed lookup removes
nothing and makes `--prune` exit 5.

## `scripts/pr-guard.py` — Adapt (rule set only, not the hook), reimplemented in Rust

`pr-guard.py` (372 lines) is a thin harness wrapper, not a second
implementation. It holds only a prefilter regex, a 50 s deadline,
and a rule loader, which compiles and executes the sibling
`_pr_guard.py` (8,166 lines) and calls its judge function. All rules
live in `_pr_guard.py`. Input is a Claude Code `PreToolUse` JSON
event (opencode plugins map into the same shape); exit 0 = allowed
(an "ask" prints hook JSON), exit 2 = refused. Fail-closed: a
matched call the guard cannot decide, or a missing `_pr_guard.py`,
is refused; unmatched calls are allowed without loading the rules.
The opencode plugins carry a verbatim copy of the prefilter.

The issue's rule summary is broadly accurate: merges refused
universally ("agents never merge a PR, not even their own" — tea
merge, git-obs merge, API merge URL/payload; `gh` on GitHub is
explicitly not judged); pool-PR creation and head pushes outside
`pool-pr.sh` refused; contributor accept/approve refused without a
PASS/FIXABLE stamp (the foreign-accept rule re-checks creator, one
submit action, source/target srcmd5 still as reviewed, Factory devel
project, maintained + ELIGIBLE — and even with a stamp the outcome
is ask, never allow); credential-file reads (other than listing),
secret printers, credentials on command lines, and raw API calls via
curl/wget/HTTPie instead of `osc`/`git-obs` refused; comments,
declines, closes, non-ELIGIBLE accepts/forwards ask (with
exceptions, e.g. a comment on one's own request runs, and a comment
whose sha256 matches the recorded review runs).

What must change: the hook shape cannot transfer — tool-call events,
agent type, 50 s alarm, ask/refuse JSON are Claude Code/opencode
harness concepts. The daemon needs the rules re-expressed as an
evaluator over queue actions (file/accept/approve/comment/forward),
with ask mapped to escalate-to-human queue state, not a harness
prompt. Harness-only rules (sleep limits, script pinning to a git
ref, PATH/BASH_ENV bans, credential-file reads by the agent's own
shell) have no daemon equivalent and must be dropped, not ported.
Reimplemented in Rust: keeps the rule set as an evaluator over queue
actions, with ask mapped to escalate-to-human queue state; drops the
harness hook, the tool-call events and the 50 s alarm.

Flags: "Refuse fixed sleeps" is overbroad. The sleep rule refuses
only when a call's sleeps total 60 s or more (operands summed, GNU
`sleep` units parsed); shorter sleeps pass, as do sleeps in the
Monitor tool, background calls, or scripts the call runs. The
refusal text itself points at `obs-wait.py`/`build-wait.sh` as the
replacement. "Refuse self-review" is wrong as stated. The self-review
rule is an ask, not a refuse: only the changes-review agent that ran
the review may record it. Outright refuses in this area are narrower:
approving one's own PR is refused, and the incoming-review agent is
refused any accept/approve/comment/decline/close. Also, the
foreign-accept function itself has no explicit creator≠user check —
routing sends own requests to the eligible-accept path instead; the
"someone else's" property comes from the caller, not the function.
Important rules the issue omits: bot-directive refusal (no `merge
ok` / approve line in any comment, review or request message);
request/PR message rules (prose ≤160 chars, list lines ≤100, ≤1000
total, no work notes, no "only says it forwards"); scmsync-checkout
`osc commit` refusal; filing against scmsync'd
`openSUSE:Backports:SLE-16.x` refused; devel-project/target rules
for submits; stamp/state-directory write protection (only pinned
`gate.sh`/`target-gate.sh` write the state dir); skill scripts run
unread only when byte-identical to the pinned ref; and the
incoming-review agent's parse/build bans (rpm family, quilt, `osc
build`, services, `gate.sh` — the review reads the submission as
text only).

## `scripts/bug-guard.py` — Adapt (the predicate, not the hook), reimplemented in Rust

The claim is essentially accurate: a harness `PreToolUse` hook for
the Bugzilla MCP server; reads get no decision, every write except
one gets "ask" (a refusal in a sub-agent), and exactly one write
passes unprompted — `assign_bug` to `security-team@suse.de` with a
1–600-char comment citing exactly one request (`SR 123` / `SR#123` /
`request 123`, ≥4 digits, distinct numbers counted), where that
request was created by the caller, every action is a submit to
`openSUSE:Factory`, state is `new`/`review`/`accepted`, and
`factory-auto` has accepted it (or the request is `accepted`), and an
added `.changes` line (over the target's previous lines, via
`acceptinfo` `osrcmd5`) cites the bug id. Any failed/unreadable
lookup or the 40 s deadline answers "ask", never "allow". The tie
the issue names is the point: the write is anchored to a submission
only the maintainer can file, so bug text cannot redirect the
hand-back.

What must change: the hook (stdin event, allow/ask JSON, `osc`
subprocesses) does not transfer. What transfers is the predicate,
reimplemented as a daemon-side, stored and re-verifiable
admission/authorization check for bug items admitted via bugwarden —
a bug item is actionable unattended only when the SR proof above
holds at action time, with the SR number, `.changes` evidence and
factory-auto state recorded on the item, not re-derived from a live
hook call. Reimplemented in Rust: keeps the SR-proof predicate as a
stored, re-verifiable admission check; drops the hook, the stdin
event and the osc subprocesses.

Flags: "security bug" is not verified. The code never checks the
bug's product, component, classification or security flag — any
positive integer bug id passes if the SR proof holds. The "security"
property comes only from the assignee being the security team. The
`.changes` comparison is against the target as the request saw it
(`osrcmd5` from `acceptinfo`; empty old text for an accepted-as-new
package), not against current Factory — a nuance the issue omits.

## `scripts/obs-wait.py` + `scripts/build-wait.sh` — Adapt, reimplemented in Rust

Both are one-shot bounded waits whose exit code is the verdict, as
claimed. `obs-wait.py` (read-only; opens OBS's public SSE event
stream first, `osc` second, rechecks on an interval, default timeout
80 s): build mode judges only the current `srcmd5` on the gate's
scope (Tumbleweed + Leap 16, x86_64/aarch64); exit 0 green, 1 pending
(repeat the same call), 2 settled failure / request
declined-revoked-superseded-deleted, 3 no answer/lookup failure, 4
QUEUED-STUCK, 5 BLOCKED-UPSTREAM. `build-wait.sh` waits on one local
`osc build` process group (default max 540 s, repeat until it stops
exiting 4): exit 0 green (via `build-summary.sh`), 1 failed, 2 no
log, 3 no verdict, 4 still running, 5 usage / PGID is not a group id.

QUEUED-STUCK and BLOCKED-UPSTREAM are exactly as claimed in
substance: only `scheduled` arches left, the rest green, 30+ minutes
since both the last commit and the last finished job in each such
repo/arch (exit 4); only `blocked` arches left, blocked in the link
origin at the same repo/arch too, the rest green (exit 5). Both print
"not green: report it and check back later".

What must change: a daemon cannot block a worker on an 80 s / 540 s
synchronous wait with repeat-the-call semantics. These become
queue-item retry state: record the verdict (PENDING / QUEUED-STUCK /
BLOCKED-UPSTREAM) with a next-check time on the item and release the
worker; the SSE-feed + poll loop is replaced by the daemon's own
scheduler/observer pacing. `build-wait.sh` is a different domain
(local process groups on a build host) and only its exit-code-verdict
shape transfers. Reimplemented in Rust: keeps the exit-code-verdict
shape as queue-item retry state with next-check times; drops the
synchronous blocking waits and the local process-group waiting.

Flags: "never file" is caller policy, not something in the code.
`obs-wait.py` files nothing — it is read-only. The "never file"
follows from exits 4/5 being non-green, i.e. a caller gating on exit
0 will not file; the tool itself enforces nothing. The issue omits
`obs-wait.py` request mode (exit 0 accepted, 1 pending with open
reviews listed, 2 declined/revoked/superseded/deleted) — the wait
primitive covers requests as well as builds. `build-wait.sh
--no-summary` exit 0 does not mean green — it means the job merely
ended; "its outcome is in LOG". Only the default path (via
`build-summary.sh`) yields a green verdict.

## `scripts/gate.sh` — Adapt, reimplemented in Rust

A 2,303-line one-shot commit/SR gate for a local osc checkout,
ending in one `VERDICT: GREEN/RED` line, and its check list transfers
well — but as a shell script driving `osc`, `bwrap`, and per-user
state files, not as daemon code. The stamp mechanism is real: a GREEN
run writes `$HOME/.local/state/opensuse-packaging/gate/obs/<pkg>/<prj>.json`;
the key is a sha256 over `"md5  name\n"` lines (per-file md5, sorted,
excluding `_link` and `_service:*`); a red run deletes the stamp. The
stamp also carries separable `review`/`build`/`rpms` sub-records: a
rerun of the same tree keeps all three, a `.changes`-only diff keeps
build+rpms but never the review.

What must change: port the check list and the stamp semantics
(verdict bound to an exact tree hash; review/build/RPM-check as
separable sub-records; changelog-only carry rules) into daemon
pre-submit checks recorded in the single store; drop the shell /
`osc`-CLI / bwrap / local-state execution shape. Reimplemented in
Rust: keeps the check list and the stamp semantics (exact-tree
binding, separable sub-records, changelog-only carry rules) as
daemon pre-submit checks.

Flags — the issue misdescribes the gate count badly. It is not "six
gates": the header and the check calls enumerate 18 red-able checks
— `target`, `tracked`, `skill-scripts`, `source_validator`,
`download_files`, `rpmspec`, `prep`, `spec-cleaner`, `changes-lint`,
`changes-guard`, `changes-patches`, `build-summary` (only with
`--build-log`), `spec-notices`, `spec-header`, `spec-comments`,
`patch-tags`, `changes-entry`, `source-binaries` — plus
`parse-surface` (always rc 0) and `changes-range` (note, never red).
Also: the stamp exists only for osc checkouts (git checkouts have no
stamp file, so nothing is stamped or deleted); `--review` /
`--obs-build` are separate modes with their own `VERDICT` lines and
exit codes 0/1/2/3/4, not part of the main run; and several gates can
end UNKNOWN-not-red (rpmspec/%prep host limits), surfacing as "not
proven on this host" on the verdict line — a daemon must not treat
that GREEN as fully proven.

## `scripts/target-gate.sh` + `scripts/pool-pr.sh` — Adapt, reimplemented in Rust

The claimed mechanism is essentially accurate. `pool-pr.sh` runs
`target-gate.sh` in check mode first and exits 7 with nothing pushed
unless HEAD's exact tree has a GREEN build + PASS review for that
base; it re-verifies HEAD is unchanged after the gate, then only
opens (POST) or updates (PATCH) a Gitea PR — it force-pushes the head
branch and never merges (final line: "never merge a pool PR"). The
stamp is `<git-common-dir>/target-gate/<tree>-<base>.json`, keyed on
the full git tree hash plus base — a different stamp scheme from
gate.sh's sha256-over-md5s, not the same store.

What must change: the pattern (exact-tree+base stamp,
check-before-open, never-merge, single route) maps onto the
submitter queue, but the Leap/Gitea/pool specifics, local-build
mechanics, and git-dir file stamps must become daemon-side pre-submit
checks in the single store, with the "only route" enforced by the
queue owning the sole forge write path (via geectl's library).
Reimplemented in Rust: keeps the exact-tree+base stamp,
check-before-open and never-merge pattern as daemon-side pre-submit
checks; drops the shell scripts, the git-dir stamp files and the
local-build mechanics.

Flags: (a) Scope is Leap-only — bases `leap-16.x`, repos
`pool/<pkg>` on src.opensuse.org, builds against
`openSUSE:Backports:SLE-16.x` standard / the PR project — not a
general pool-PR gate. (b) "GREEN build" has three routes: native
`--build`, `--remote` (build in `home:<you>:leapgate`,
branch+package deleted once GREEN), or carried for a
`.changes`-only tree (build carries, review never does). (c) The
issue omits the refusal set: dirty worktree, detached HEAD,
unsmudged LFS, clone under `/tmp`, HEAD not on top of
`origin/<base>`, HEAD stacked on more than one of your open PRs,
host arch the PR project doesn't build. (d) "Only route" is a policy
statement in the header, enforced by convention, not technically —
nothing stops a hand-opened pool PR. `pool-pr.sh` also enforces
no-double-filing (someone else's open PR on the base refuses; two of
yours refuses; one head branch per base) and pushes LFS objects
before the ref.

## `scripts/autoforward-gate.sh` + `scripts/forward-check.py` — Adapt, reimplemented in Rust

This pair is the closest to queue-ready logic: `forward-check.py`
decides per package (FORWARDED / MINE-OPEN / IN-FACTORY / declined
variants / NOT-LANDED / DEVEL-DECLINED / GONE / WRONG-DEVEL /
NEW-IN-FACTORY / DUE / MAINTAINERS / UNKNOWN), calls
`autoforward-gate.sh --batch` only for the undecided ones, and DUE
requires no blocking forward state and gate ELIGIBLE and no older
foreign-declined forward. The gate's exits are 0 ELIGIBLE, 3 BLOCKED,
4 NOT_YOURS, 5 UNREADABLE, 6 WRONG-DEVEL, 2 usage.

What must change: adopt the verdict taxonomy and DUE conditions as
queue item states, but reimplement the decision logic over the single
store (with re-discovery and cooldown) and geectl-library reads
instead of shell + `osc` CLI + batch files + exit-code signalling.
Note the gate decides unattended accept+forward of your own request;
it does not itself accept or forward anything. Reimplemented in Rust:
keeps the verdict taxonomy and DUE conditions as queue item states.

Flags — the issue's three-clause summary is wrong/incomplete in five
places: (1) "Only an own accepted request" is overstated.
`autoforward-gate.sh` takes only project/package/user — it checks no
request ownership at all; the own-request rule is a header comment
about the caller (incoming-review), not enforced by the script. And
`forward-check.py`'s DUE does not require an accepted own request in
all cases: when Factory already holds the package (older files), DUE
is reachable on gate-ELIGIBLE alone. The own-accepted-request
requirement bites only for new-to-Factory packages, via the
first-revision check (first revision created by an accepted request
of yours → DUE with a note; otherwise NEW-IN-FACTORY, "ask before
submitting"). `--mine` is scoped to your accepted requests; direct
`forward-check.py prj pkg` is not. (2) "No reviewer role set and the
caller holds maintainer" omits the second eligibility leg: a package
with no maintainer at all + you holding maintainer on the project is
ELIGIBLE. Reviewer also blocks at project level and as a group, and
for scmsync projects `workflow.config` Reviewers count too. (3)
Omits WRONG-DEVEL entirely: the project must be Factory's devel
project for the package (with a `_link` exception and a spelling
check), else accept nothing there. Both scripts check it. (4) Omits
scmsync/git-kept projects: roles come from `_maintainership.json` +
`workflow.config` read via git-obs, not OBS `_meta`. (5) "File only
on DUE" omits the documented second case: "File a forward only on
DUE, or on MINE-DECLINED once the decline is fixed." A
FOREIGN-DECLINED older forward means ask, never supersede.

## `contrib/container/` — Adapt (deployment pattern, not a daemon)

Every claimed property checks out in the Quadlet files — with two
caveats below. (`contrib/` lives at the skill repo root, not under
`skills/opensuse-packaging/`.) The container unit is a user unit
(`WantedBy=default.target`, `UserNS=keep-id`; README: "rootless
podman"), with `ReadOnly=true`, `DropCapability=all`,
`NoNewPrivileges=true`; six `Secret=` lines (podman secrets); four
named volumes exactly as claimed — state → `.local/share/opencode`,
memory → `.local/share/mcp-memory`, toolstate → `.local/state`,
scratch → `/var/tmp` — plus a `Tmpfs` for `.cache` and a read-only
config volume; `Restart=on-failure` (plus `StartLimitBurst=5`,
`SuccessExitStatus=143`, `TimeoutStartSec=300`); and a nightly timer
(`OnCalendar=*-*-* 03:17`, `Persistent=true`,
`RandomizedDelaySec=1200`) driving the update service.

What must change: reuse the Quadlet skeleton (user unit, read-only
rootfs, secrets, named volumes, on-failure, timer) for the freshcrab
daemon, but replace `opencode serve` + relay + workdir mount with the
daemon binary, and design daemon-appropriate secret provisioning (the
design says only a deterministic executor holds forge credentials —
the skill's human-run secrets flow does not fit); enable the update
timer deliberately.

Flags: (a) The timer is not enabled by install: "enable it after one
watched run." The timer file exists; nightly updates are opt-in, not
default. (b) The shape is a per-instance interactive agent server,
not a daemon: it runs `opencode serve` on 127.0.0.1:4096 behind a
socat relay service, with a host workdir mount in the example
drop-in and drop-ins for the relay and container teardown. Secrets
are created by a human-run `secrets` subcommand ("run it yourself,
never from an agent"), and podman keeps secrets unencrypted under
the home dir (mode 0600).

## `scripts/_obs_scope.py` — Adopt as-is (design), reimplemented in Rust

The claim is accurate, including the docstring's own statement:
"shared by gate.sh --obs-build and obs-wait.py so the gate and the
wait cannot drift." The 55-line module defines `FACTORY_REPO`
(`openSUSE_(Factory(_\w+)?|Tumbleweed)`, plus `standard` in
`openSUSE:Factory*` projects), `LEAP16_REPO`
(`(openSUSE_Leap_)?16.\d+`), `ARCHES = {x86_64, aarch64}`, `OFF =
{"disabled"}`, and `judged(prj, repo, arch, leap=True, repos=None,
arches=None)` plus `factory()`, `origin()`, `codes()` (multibuild
flavors). Verified live: imported by `gate.sh` and `obs-wait.py`,
referenced by `incoming-review.sh`.

Flags: none material — one nuance the issue omits, worth carrying
over: `OFF` is `{"disabled"}` only; an `excluded` repo/arch still
counts as judged, because exclusion follows the spec the change may
edit. `judged()` also accepts optional extra repos/arches regexes for
widening. Adopt as-is as the pattern — one scope module shared by the
observer and the queues — with the literal regexes being the
Factory/Leap scope; any further freshcrab targets get added in that
one place, never per-consumer. The "adopt as-is" is the design only:
one scope module shared by the observer and the queues, with the
literal regexes as data. It is reimplemented in Rust; the Python file
is not carried into the daemon.

## Proposed `docs/architecture.md` edits

Quoted insertions against the #35 head. Anchors are the existing
section text; insertions go after the anchor.

### 1. Central queue planner — concurrency and ledger

Anchor: "The planner runs items in parallel, as defined in
configuration. Default concurrency: 1 worker per 4 cores or 1 worker
per 4 GB of RAM — whichever is the binding constraint."

```markdown
- One package per worker; parallel workers stay below the configured
  concurrency limit, and a worker plus its reviewer counts as two
  against it. An interrupted worker resumes its item instead of
  starting over. Decisions and landed ids are durable records in the
  queue store, never a per-task file.
```

### 2. Central observer — spend pacing counts briefs

Anchor: "The budget values are per-lab config; the pacing mechanism
is open."

```markdown
- The observer's pacing counts the worker's brief and tool output as
  spend: a worker's brief is bounded and a worker hands back a short
  report, not a transcript.
```

### 3. Central observer — discovery never reports clean from a partial read

Anchor: "Fail-closed throughout: a failed signal read is never read
as green; a malformed forge response bails out with a wrong-response
error carrying the trace; a missing credential fails the dedup check
and the package is skipped, never queued on an unchecked dedup."

```markdown
- Discovery never reports "nothing pending" from a partial read: a
  failed forge leg reads UNKNOWN, a lost updater source degrades to
  the remaining sources with a WARNING and a coverage verdict, and a
  dispatch gate that cannot read its inputs fails closed. A cap on
  listed rows is disclosed, never silent.
```

### 4. Central observer — one scope module

Anchor: "Forge assignment: an item's forge is where it was
discovered — an OBS SR is OBS, a bug is bugwarden, and so on."

```markdown
- One scope module defines which repo and arch counts, shared by the
  observer and the queues: Factory and Leap 16 repos on x86_64 and
  aarch64; `disabled` is the only off state — an `excluded` repo or
  arch still counts, because exclusion follows the spec the change
  may edit. A further target is added in that one module, never
  per-consumer.
```

### 5. Reviewer queue — two roles, two verdict shapes

Anchor: the Reviewer queue section, after the re-discovery and
cooldown paragraph.

```markdown
- Two reviewer roles: the own-change review (binary PASS/BLOCK) and
  the contributor-submission review (ternary PASS/FIXABLE/BLOCK,
  text-only — the submission is never parsed or executed). The
  verdicts are not collapsed. The own-change review is re-timed to
  post-cooldown re-discovery: it does not run inline before filing.
- A FIXABLE verdict holds the Factory forward while the target still
  equals the reviewed source. The hold is the hotfix queue's record:
  a concentrated nit, quick-fixed and forwarded as priority. This
  narrows open question 11 (hotfix queue shape); it does not close
  it.
```

### 6. Reviewer queue — dispatch gate precedence

Anchor: the Reviewer queue section, after the ruleset paragraph.

```markdown
- The dispatch gate decides whether a package takes a new worker:
  in-flight STOP beats INCOMING beats landed-STOP beats FORWARD
  beats PROCEED. A gate that cannot read its inputs fails closed
  instead of reporting proceed.
```

### 7. Submitter queue — forward rules

Anchor: "Filing is the submitter queue's job: the worker builds the
SR payload and hands filing to the submitter queue, which works in
the one queue."

```markdown
- Forwarding follows the forward taxonomy: a forward files only on
  DUE (no blocking forward state, gate ELIGIBLE, no older
  foreign-declined forward), or on MINE-DECLINED once the decline is
  fixed. WRONG-DEVEL (the project is not Factory's devel project
  for the package) files nothing. FOREIGN-DECLINED means ask, never
  supersede.
```

### 8. Updater queue — pre-submit checks

Anchor: "### Gate rules" under the Updater queue section, after the
rpmcrab bullet ("rpmcrab over the built RPMs: target 0 errors / 0
warnings. Findings are fixed at the cause. Info-severity findings
stay informational.").

```markdown
- Pre-submit checks, one call, one verdict: target, tracked,
  skill-scripts, source_validator, download_files, rpmspec, prep,
  spec-cleaner, changes-lint, changes-guard, changes-patches,
  build-summary, spec-notices, spec-header, spec-comments, patch-tags,
  changes-entry, source-binaries. A check that ends UNKNOWN (host
  limits) is "not proven on this host", never green.
- A GREEN pre-submit check stamps the exact tree; a red run deletes
  the stamp. Review, build and RPM-check are separable records; a
  `.changes`-only diff keeps build and RPM-check but never the
  review.
```

### 9. Deployment — new section after Secrets

Anchor: after the Secrets section, before Layout.

```markdown
## Deployment

- The daemon ships as a rootless podman unit: read-only rootfs, no
  new privileges, all capabilities dropped, secrets via podman
  secrets, separate volumes for state, memory, toolstate and scratch,
  restart on failure, and a nightly update timer the operator enables
  deliberately.
```

## Proposed `docs/review-queue.md` edits

### 10. Discovery — caps disclose, truncation reads UNKNOWN

Anchor: "Discovery runs across ALL configured instances: every OBS
instance and every Gitea instance in the config, not just the
default. If more instances are defined, they are all scanned."

```markdown
- Discovery lists are uncapped, or their cap is disclosed: a
  truncated leg reads UNKNOWN, never a complete list.
```

### 11. Binding — stamp key shapes

Anchor: the Binding section, after "Decisions, grace, builds,
authority, and the ruleset hash bind to the complete reviewed
snapshot; any mismatch on re-check reclassifies the item, it never
proceeds on the old binding."

```markdown
- The binding key covers the reviewed actions, source and target file
  hashes, and creator; the Gitea key covers head, base, merge base
  and files. A record whose key moved on re-check is refused, never
  updated in place.
```

### 12. Ruleset signals — guard rules the list does not yet name

Anchor: the Ruleset signals section, as additions to the existing
signal lists.

```markdown
- Bot-directive refusal: no merge-ok / approve line in any comment,
  review or request message.
- Message rules: prose ≤160 chars, list lines ≤100, ≤1000 total, no
  work notes, no "only says it forwards".
- Scmsync rules: no commit on a scmsync checkout; no filing against
  a scmsync'd Backports project.
```

### 13. Scope — the replacement gate for Leap pool PRs

Anchor: "Excluded explicitly: Leap `pool/` pull requests and
maintenance (`:Update`) requests — they follow other rules. Until a
replacement gate is named, they stay human-reviewed: the queue never
auto-acts on them."

```markdown
- The replacement gate for Leap `pool/` pull requests is the
  exact-tree gate: a pool PR opens only with a GREEN build + PASS
  review for HEAD's exact tree and base, and never merges.
```

### 14. Trivial fixes — the FIXABLE hold

Anchor: the Trivial fixes section, after "Hold the Factory forward
until the follow-up is in devel, so one forward carries both".

```markdown
- A FIXABLE verdict holds the Factory forward while the target still
  equals the reviewed source; a PR FIXABLE hold always stays.
```

## Not relevant — confirmed

Spot-checked against the same skill head; the list holds.

- `factory-report.py` is contributor analytics (SHAPE/RHYTHM axes
  over accepted SRs), not queue state.
- `changes-prepend.sh`, `changes-*.sh`, `quilt-*.sh`,
  `soname-check.sh`, `scm-snapshot.sh`, `gpg-verify.sh`,
  `source-binaries.py`, `vendor-strip.py`, `rdeps.sh`,
  `distro-survey.sh`, `wiki-drift.sh`, `leap-status.sh`,
  `leap-sync.sh`, `devel-of.sh`, `devel-packages.sh`,
  `my-packages.sh`, `my-requests.sh`, `build-summary.sh` are
  per-package tooling, not orchestration.
- `_parse_scan.py`, `_anitya.py`, `_forges.py`, `_sanitize.py`,
  `refsection.py` are shared helpers for per-package commands, not
  queue behaviour. Note: `_forges.py` carries the same "one home so
  two commands cannot drift" pattern as `_obs_scope.py`, at probe
  level — the file stays out, the pattern is the same idea.
- `contrib/harness/` (repo root) is per-agent permission snippets
  for interactive harnesses, not daemon architecture.

## Gaps — as they stand

- No hotfix queue exists in the skill's scripts — the closest is the
  FIXABLE stamp + hold, now specified above as the hotfix record
  (edit 5, issue #41). The hotfix queue is freshcrab's to build.
- No monetary token-budget enforcement anywhere. The skill's budget
  is context economy; the money budget, pacing and enforcement are
  freshcrab's to build (open questions 2–5).
- Bugwarden is a Rust MCP server for Bugzilla — a queue source (bugs
  in), not a planner. The bug-guard predicate feeds the bugwarden
  integration shape (open question 21, #21); it is not a separate
  issue.

## Follow-up issues

| Issue | Piece |
|---|---|
| #40 | Observer discovery, coverage and dispatch gate |
| #41 | Review records live in the single queue store |
| #42 | Daemon pre-submit gates |
| #43 | Submitter forward rules |
| #44 | Daemon deployment: Quadlet unit from the skill container shape |
| #45 | Shared scope module for observer and queues |

Mapped to existing work, no new issue: the ruleset file + evaluator
is #21 steps 3–7 (the pr-guard rule set is its reference); the
`review_queue.json` conflict is #41 reconciling the flag on #33.
