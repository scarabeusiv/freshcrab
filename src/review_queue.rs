//! Review queue: triage state for OBS submit requests and Gitea pull
//! requests, read through geectl's unified pull-request surface.
//!
//! Step 1 (this module): the review-record state file
//! (`review_queue.json`, one record per pull-request ref) and
//! discovery — a pull-request search on both arms, scoped to the
//! watch scope, deduplicated, one record per ref. Report-only:
//! discovery reads and records; it posts nothing, changes no
//! review state, files nothing, and merges nothing. The ruleset
//! (step 3), the human handoff (step 4) and the actions (steps 5-7)
//! are not built here.
//!
//! Step 2 (this module): the signal readers — build status, review
//! state, diff scope, author trust, package risk, server state —
//! read for every non-terminal record on every run and recorded on
//! the record as its signal snapshot. Report-only, like discovery:
//! the readers read and record; they post nothing, change no
//! review state, file nothing, and merge nothing. The tier stays
//! empty until the ruleset (step 3) classifies the snapshot.
//!
//! Step 3 (this module): the ruleset file (`review_ruleset.json`,
//! a separate declarative file in the repo, versioned with the
//! code — not a section of `config.yaml`) and the evaluator.
//! A rule names its signal pattern (`when`: conditions over the
//! step-2 signal snapshot) and its action (`comment`,
//! `request-changes`, `decline`, `escalate-human`, `hold`,
//! `accept-trivial`). Rules are evaluated in file order; the first
//! matching rule wins; no rule matching means the human tier.
//! The tier and the decided action are recorded on the record
//! together with the ruleset version that produced them; a comment
//! body never carries the version. Fail-closed: anything the
//! ruleset does not cover goes to the human tier, and a ruleset
//! that fails to load refuses the run (classify returns the error;
//! the run classifies nothing). `decline` is normalized to
//! `comment` at evaluation: OBS decline is human-only, so the
//! queue comments in the ruleset cases instead of declining.
//! Report-only, like steps 1-2: classification records the
//! tier and action; it posts nothing. The human handoff (step 4)
//! and the actions (steps 5-7) are not built here.
//!
//! The initial rule set encodes only the clear cases the step-2
//! snapshot supports: signal statuses (build, review, server),
//! file names from the diff (risk-flag files), and the bumped
//! version string (pre-release markers). The rest of #21's
//! ruleset signals needs diff text the snapshot does not carry
//! (changelog wording and format, `%check` changes, spec findings,
//! patch-to-changelog naming, tarball equality, `setBadness`);
//! those cases match no rule and fall through to the human tier
//! until diff-text signals land. No rule in the initial set yields
//! `request-changes` or `accept-trivial`: both need a diff-text
//! finding, so steps 6-7 stay live-inert until then.
//!
//! Step 4 (this module): the human handoff. A human-tier verdict
//! escalates the record in place: `escalation_reason` /
//! `escalated_at` / `escalation_question` are persisted on the
//! record (like the update queue's escalation), with the
//! fingerprint of the snapshot that produced them, so triage never
//! depends on a captured run log. An escalated item stays parked:
//! classification skips it while the fingerprint is unchanged,
//! and re-classifies it only when its server state changes (a
//! different fingerprint clears the escalation and re-opens the
//! record). A human decision (`approved` | `declined` |
//! `dismissed`) is recorded on the item and moves it to
//! `terminal`, so a re-run never re-escalates the same
//! submission. The run report lists the human-tier items with
//! ref, tier, signal snapshot, ruleset version, and the exact
//! question for the human; the human acts through the geectl
//! `pull-request` CLI or the web UI.
//!
//! Step 5 (this module): the comment action (comment-only stage).
//! Triage comments post on auto-actionable and mid-confidence
//! items (records whose decided action is `comment`), via
//! geectl's `PullRequestClient::comment` library call; no
//! review-state changes. Idempotency: each posted comment is
//! recorded with the server-side comment id and the fingerprint
//! of the snapshot it was raised on; a re-run acts only on
//! change, never double-posts, and adopts a comment already on
//! the server instead of posting it again. Stage-gated: the
//! comment-only stage is off by default and starts only on an
//! explicit go-ahead (`review_comment_stage` in the config); the
//! kill switch pauses every stage; dry-run prints what it would
//! do and writes nothing; `report_only` gates filing (the queue
//! files nothing). A comment body never carries the ruleset
//! version, and never carries a line starting with `merge ok` or
//! `@group : approve` (checked before posting, including any
//! quoted submission text — the body quotes no submission text,
//! so the check covers the composed lines; a future step that
//! quotes text must indent the quote so no quoted line starts
//! with a trigger).
//!
//! Discovery runs across ALL configured instances: every OBS
//! instance and every Gitea instance in the geectl config, not just
//! the default. Instances come from geectl's config file
//! (`[instances]` plus the effective `obs_url` / `gitea_url`); an
//! instance is scannable on a backend when credentials resolve for
//! it on that backend (OBS username/password or token, Gitea
//! Bearer <redacted> — see `geectl::auth`). An instance with no usable
//! credentials on either backend is skipped and named in the report,
//! never silently dropped. A failed search on one instance is
//! recorded on that instance and the run continues with the rest.
//!
//! All OBS and Gitea reads go through the geectl library
//! (`PullRequestClient` — search and show). freshcrab implements no
//! OBS or Gitea logic of its own here: no client, no endpoint
//! construction, no wire parsing. A new need goes to geectl first.
//!
//! Credentials for the review queue come from geectl's own model
//! (`GEECTL_OBS_*` / `GEECTL_GITEA_TOKEN*` variables, resolved
//! per instance from the geectl config), not from freshcrab's
//! `OSC_*` variables: the instances themselves are defined in
//! geectl's config, so the credentials that address them are
//! geectl's. The update pipeline keeps its own `OSC_*` credentials.
//!
//! Fail-closed: a search or show that fails is never read as green
//! and never drops a record. A record the search did not return is
//! re-checked with `show` before it is marked terminal, and a
//! failed re-check leaves the record as it is.

use crate::config::Config;
use crate::dry_run::DryRun;
use crate::queue::QueueEntry;
use fs2::FileExt;
use geectl::auth::{same_api_url, Credentials, EnvGiteaAuth, EnvObsAuth};
use geectl::config as geectl_config;
use geectl::error::{ErrorKind, GeectlError};
use geectl::gitea::GiteaClient;
use geectl::obs::{BuildResults, CveId, NamedRole, ObsClient, ResultsQuery, OBS_API_BASE};
use geectl::pull_request::{
    OpinionState, PullRequest, PullRequestBackend, PullRequestClient, PullRequestRef,
    PullRequestSearch, PullRequestStatus, PullRequestSummary, ReviewComment,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Seconds since the epoch, as a plain string. The queue files are
/// machine-read first, so an epoch timestamp is enough for ordering
/// (same convention as `crate::queue`).
fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

/// Grace periods for the trivial-fix tiers, decided 2026-11-27:
/// package maintainer 7 days, project maintainer 3 days, factory
/// maintainer 1 day. Carried on the record so the state names the
/// values the ruleset (step 3) enforces; this step does not enforce
/// them — it is report-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GracePeriods {
    pub package_maintainer_days: u64,
    pub project_maintainer_days: u64,
    pub factory_maintainer_days: u64,
}

impl Default for GracePeriods {
    fn default() -> Self {
        GracePeriods {
            package_maintainer_days: 7,
            project_maintainer_days: 3,
            factory_maintainer_days: 1,
        }
    }
}

/// The binding recorded at classification: the source and target
/// endpoints (the OBS source srcmd5 at a pinned rev and the target
/// srcmd5, or the Gitea PR head and base SHAs). Re-checked right
/// before acting, so an accept never copies content nobody looked at.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReviewBinding {
    #[serde(default)]
    pub source_repository: String,
    #[serde(default)]
    pub source_commit: Option<String>,
    #[serde(default)]
    pub target_repository: String,
    #[serde(default)]
    pub target_commit: Option<String>,
}

/// One recorded action on a review item (a posted comment or a
/// review-state change), with the server-side id it produced, so a
/// re-run never double-posts. Empty until step 5 acts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewAction {
    pub action: String,
    pub id: String,
    /// When the action was recorded (epoch seconds, like `updated_at`).
    pub at: String,
    /// The fingerprint of the snapshot (and ruleset version) the
    /// action was raised on (step 5): a re-run posts again only
    /// when the fingerprint changed. Empty for actions recorded
    /// before fingerprints existed.
    #[serde(default)]
    pub fingerprint: String,
}

/// The review-record statuses (see the design's Queue state).
pub const REVIEW_STATUSES: &[&str] = &["open", "triaged", "actioned", "escalated", "terminal"];

/// The human decisions recordable on a review item (step 4):
/// `approved` (the human approved the submission), `declined`
/// (the human declined it), `dismissed` (dismissed as not a
/// queue item).
pub const HUMAN_DECISIONS: &[&str] = &["approved", "declined", "dismissed"];

/// One triaged submission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewRecord {
    /// The pull-request handle: `obs:<id>` or
    /// `gitea:<owner>/<repo>#<number>`.
    pub reference: String,
    /// The instance the handle lives on: the geectl config alias, or
    /// `default`. The handle carries no host, so the instance is part
    /// of the record key — the same ref on two instances is two
    /// records.
    pub instance: String,
    /// `obs` or `gitea` (the backend the handle came from).
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub author: String,
    /// `open` | `triaged` | `actioned` | `escalated` | `terminal`.
    pub status: String,
    /// The triage tier: empty means unclassified (steps 2-3 set it);
    /// `auto` | `mid` | `human` once classified.
    #[serde(default)]
    pub tier: String,
    /// The signal snapshot (step 2). None until signals are read.
    #[serde(default)]
    pub signal_snapshot: Option<serde_json::Value>,
    /// The ruleset version that produced the tier (step 3). None
    /// until a ruleset exists.
    #[serde(default)]
    pub ruleset_version: Option<String>,
    /// The rule that classified this record (step 3). None until
    /// a rule matches; a record that matched no rule (human tier
    /// by fail-closed default) carries None.
    #[serde(default)]
    pub matched_rule: Option<String>,
    /// The action the ruleset decided for this record (step 3):
    /// `comment` | `request-changes` | `escalate-human` | `hold` |
    /// `accept-trivial`. None until classified. This is the decided
    /// next action, not a posted one — posted actions live in
    /// `action_history` (steps 5-7).
    #[serde(default)]
    pub action: Option<String>,
    /// Why this record was escalated to a human, if it was (step
    /// 4). Persisted on the record, like the update queue's
    /// `escalation_reason`, so triage never depends on a captured
    /// run log. Records without an escalation carry None.
    #[serde(default)]
    pub escalation_reason: Option<String>,
    /// When the record was escalated (epoch seconds, like
    /// `updated_at`). None when never escalated.
    #[serde(default)]
    pub escalated_at: Option<String>,
    /// The exact question for the human (step 4), from the
    /// matching rule. None when never escalated, or when the rule
    /// carries no question.
    #[serde(default)]
    pub escalation_question: Option<String>,
    /// The fingerprint of the snapshot (and ruleset version) the
    /// escalation was raised on (step 4). Classification skips an
    /// escalated record while this still matches the current
    /// snapshot, and re-opens it when the snapshot changes.
    #[serde(default)]
    pub escalation_fingerprint: Option<String>,
    /// The human decision on this item, if a human acted (step
    /// 4): `approved` | `declined` | `dismissed` (dismissed as
    /// not a queue item). A decision moves the record to
    /// `terminal`, so a re-run never re-escalates it.
    #[serde(default)]
    pub human_decision: Option<String>,
    /// When the human decision was recorded (epoch seconds, like
    /// `updated_at`). None when no human has acted.
    #[serde(default)]
    pub human_decision_at: Option<String>,
    #[serde(default)]
    pub binding: Option<ReviewBinding>,
    /// The grace periods for the trivial-fix tiers (decided
    /// 2026-11-27). Carried on the record; enforced by step 7.
    #[serde(default)]
    pub grace_periods: GracePeriods,
    /// When the record was last checked against the server (epoch
    /// seconds, like `updated_at`). Empty when never checked.
    #[serde(default)]
    pub last_checked: String,
    #[serde(default)]
    pub action_history: Vec<ReviewAction>,
    pub created_at: String,
    pub updated_at: String,
}

impl ReviewRecord {
    pub fn new(
        reference: &str,
        instance: &str,
        backend: &str,
        title: &str,
        author: &str,
        binding: Option<ReviewBinding>,
    ) -> Self {
        let now = now_iso();
        ReviewRecord {
            reference: reference.to_string(),
            instance: instance.to_string(),
            backend: backend.to_string(),
            title: title.to_string(),
            author: author.to_string(),
            status: "open".to_string(),
            tier: String::new(),
            signal_snapshot: None,
            ruleset_version: None,
            matched_rule: None,
            action: None,
            escalation_reason: None,
            escalated_at: None,
            escalation_question: None,
            escalation_fingerprint: None,
            human_decision: None,
            human_decision_at: None,
            binding,
            grace_periods: GracePeriods::default(),
            last_checked: now.clone(),
            action_history: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

/// The signal snapshot (step 2): the confidence signals read for one
/// review record, stored as JSON on the record. Report-only: the
/// snapshot describes the submission; it changes no review state and
/// files nothing. A failed read is never green: the failing signal
/// reads `unknown` and the failure is named in `read_errors`, so the
/// item goes to the human tier (step 3) instead of being silently
/// skipped. Unknown fields default on load, like the record itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalSnapshot {
    /// When the signals were read (epoch seconds, like `updated_at`).
    #[serde(default)]
    pub read_at: String,
    #[serde(default)]
    pub build: BuildSignal,
    #[serde(default)]
    pub review: ReviewSignal,
    #[serde(default)]
    pub diff: DiffSignal,
    #[serde(default)]
    pub author: AuthorSignal,
    #[serde(default)]
    pub package: PackageSignal,
    #[serde(default)]
    pub server: ServerSignal,
    /// Signal reads that failed, in the form `signal: error`.
    #[serde(default)]
    pub read_errors: Vec<String>,
}

impl SignalSnapshot {
    /// A snapshot where every signal is unknown: used when the
    /// record cannot be read at all (its ref does not parse, or the
    /// `show` fails). The failures are named, never silent.
    pub fn unknown(read_errors: Vec<String>) -> Self {
        SignalSnapshot {
            read_at: now_iso(),
            build: BuildSignal::unknown(None),
            review: ReviewSignal::unknown(None),
            diff: DiffSignal::unknown(None),
            author: AuthorSignal {
                author: String::new(),
                is_own_filing: None,
                is_package_maintainer: None,
                first_time_submitter: None,
            },
            package: PackageSignal {
                package: String::new(),
                is_excluded: None,
                is_core: None,
                is_security: None,
                cve_ids: Vec::new(),
            },
            server: ServerSignal::unknown(),
            read_errors,
        }
    }
}

/// The build-status signal: the build of the request's current
/// sources, on Tumbleweed and Leap 16, x86_64 and aarch64. `status`
/// is `all_green` | `any_failed` | `building` | `unknown`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSignal {
    #[serde(default = "default_unknown")]
    pub status: String,
    /// The per-cell build codes behind `status`, one per
    /// (repository, arch) cell the signal read.
    #[serde(default)]
    pub cells: Vec<BuildCell>,
    /// The target (devel) package's build status, same vocabulary
    /// as `status`: a failure the devel project already has is not
    /// the submitter's.
    #[serde(default = "default_unknown")]
    pub target_status: String,
    /// Why the target status is `unknown`, when it is: a failed
    /// target read is named here, never silent.
    #[serde(default)]
    pub target_reason: Option<String>,
    /// Why the status is `unknown`, when it is.
    #[serde(default)]
    pub reason: Option<String>,
}

impl BuildSignal {
    pub fn unknown(reason: Option<String>) -> Self {
        BuildSignal {
            status: "unknown".to_string(),
            cells: Vec::new(),
            target_status: "unknown".to_string(),
            target_reason: None,
            reason,
        }
    }
}

impl Default for BuildSignal {
    fn default() -> Self {
        Self::unknown(None)
    }
}

fn default_unknown() -> String {
    "unknown".to_string()
}

/// One (repository, arch) cell of the build-status signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildCell {
    pub repository: String,
    pub arch: String,
    pub code: String,
}

/// The review-state signal: the reviews on the submission.
/// `state` is `approved` | `changes_requested` | `asked_pending` |
/// `none` | `unknown`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSignal {
    #[serde(default = "default_unknown")]
    pub state: String,
    /// One entry per review, in server order.
    #[serde(default)]
    pub reviews: Vec<ReviewEntry>,
    /// Why the state is `unknown`, when it is.
    #[serde(default)]
    pub reason: Option<String>,
}

impl ReviewSignal {
    pub fn unknown(reason: Option<String>) -> Self {
        ReviewSignal {
            state: "unknown".to_string(),
            reviews: Vec::new(),
            reason,
        }
    }
}

impl Default for ReviewSignal {
    fn default() -> Self {
        Self::unknown(None)
    }
}

/// One review on the submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewEntry {
    pub reviewer: String,
    pub state: String,
}

/// The diff-scope signal: what the submission changes, parsed from
/// the diff text (git-style or OBS plain text). `version_bump_only`
/// is true only when the diff touches nothing but the spec
/// (version/release lines) and the changelog (a new entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSignal {
    /// The files the diff touches, in diff order.
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub spec_changed: bool,
    #[serde(default)]
    pub version_bump_only: bool,
    #[serde(default)]
    pub patches_changed: bool,
    /// Files the diff adds.
    #[serde(default)]
    pub new_files: Vec<String>,
    #[serde(default)]
    pub changelog_changed: bool,
    /// The new version, when the diff bumps the spec's `Version:`.
    #[serde(default)]
    pub new_version: Option<String>,
    /// The CVE ids the added changelog lines name.
    #[serde(default)]
    pub cve_ids: Vec<String>,
    /// Why the diff is empty, when it is (the diff could not be read).
    #[serde(default)]
    pub reason: Option<String>,
}

impl DiffSignal {
    pub fn unknown(reason: Option<String>) -> Self {
        DiffSignal {
            files: Vec::new(),
            spec_changed: false,
            version_bump_only: false,
            patches_changed: false,
            new_files: Vec::new(),
            changelog_changed: false,
            new_version: None,
            cve_ids: Vec::new(),
            reason,
        }
    }
}

impl Default for DiffSignal {
    fn default() -> Self {
        Self::unknown(None)
    }
}

/// The author-trust signal: the submission author. `is_own_filing`
/// is true for freshcrab's own filings (matched by `sr_id`).
/// `is_package_maintainer` is `Some` on the OBS arm (read via
/// geectl's `ObsClient::maintainers` for the target package) and
/// `None` on Gitea or when the read fails. `first_time_submitter`
/// is `None` (unknown): it needs the author's submission history,
/// which step 2 does not read. The bools are `Option` so a failed
/// read is unknown, never a false claim.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorSignal {
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub is_own_filing: Option<bool>,
    #[serde(default)]
    pub is_package_maintainer: Option<bool>,
    #[serde(default)]
    pub first_time_submitter: Option<bool>,
}

/// The package-risk signal: the target package. `is_excluded` is
/// true for the config's exclusions (hand-maintained or special
/// packages). `is_core` is `None` (unknown): no core-package list
/// lives in the config. `is_security` is true when the submission
/// names CVE ids. The bools are `Option` so a failed read is
/// unknown, never a false claim.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageSignal {
    #[serde(default)]
    pub package: String,
    #[serde(default)]
    pub is_excluded: Option<bool>,
    #[serde(default)]
    pub is_core: Option<bool>,
    #[serde(default)]
    pub is_security: Option<bool>,
    #[serde(default)]
    pub cve_ids: Vec<String>,
}

/// The server-state signal: the submission's state on the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSignal {
    #[serde(default = "default_unknown")]
    pub status: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub mergeable: Option<bool>,
}

impl ServerSignal {
    pub fn unknown() -> Self {
        ServerSignal {
            status: "unknown".to_string(),
            draft: false,
            mergeable: None,
        }
    }
}

impl Default for ServerSignal {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Error from review-queue operations.
#[derive(Debug)]
pub struct ReviewQueueError(pub String);

impl std::fmt::Display for ReviewQueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "review queue error: {}", self.0)
    }
}

impl std::error::Error for ReviewQueueError {}

/// One record per (instance, ref): keep the most recently updated
/// record for each key (latest `updated_at`, later position wins
/// ties). Order follows first appearance, so a compacted file stays
/// stable. Same convention as `crate::queue::compact`.
fn compact(records: Vec<ReviewRecord>) -> Vec<ReviewRecord> {
    use std::collections::HashMap;
    let mut best: HashMap<(String, String), usize> = HashMap::new();
    let mut order: Vec<(String, String)> = Vec::new();
    for (i, r) in records.iter().enumerate() {
        let key = (r.instance.clone(), r.reference.clone());
        let ts = r.updated_at.parse::<u64>().unwrap_or(0);
        match best.get(&key) {
            Some(&j) => {
                let prev = records[j].updated_at.parse::<u64>().unwrap_or(0);
                if ts >= prev {
                    best.insert(key, i);
                }
            }
            None => {
                best.insert(key.clone(), i);
                order.push(key);
            }
        }
    }
    order.iter().map(|key| records[best[key]].clone()).collect()
}

/// The review queue, backed by a JSON state file (`review_queue.json`).
///
/// Same shape and conventions as `crate::queue::Queue`: a JSON array
/// of records, writers serialized with an exclusive flock on a lock
/// file next to the state file (`<path>.lock`), held from `open`
/// until the queue is dropped, atomic save through a unique tmp file
/// (fsync, rename, fsync the parent directory). A missing file is an
/// empty queue; a corrupt file is an error, never an empty queue.
pub struct ReviewQueue {
    path: String,
    records: Vec<ReviewRecord>,
    /// The lock file, held open for the queue's lifetime. It is never
    /// read — it exists only to hold the flock — so the dead-code lint
    /// is silenced.
    #[allow(dead_code)]
    lock_file: Option<std::fs::File>,
}

impl ReviewQueue {
    /// Open the review queue at `path`. A missing file is an empty
    /// queue. The exclusive lock is held until the returned queue is
    /// dropped, and flock is per file descriptor: opening the same
    /// path twice in one process fails on the second open, so drop
    /// the first queue before reopening (the tests pin this).
    pub fn open(path: &str) -> Result<Self, ReviewQueueError> {
        let lock_path = format!("{path}.lock");
        let lock_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                ReviewQueueError(format!(
                    "cannot open review queue lock file {lock_path}: {e}"
                ))
            })?;
        lock_file.try_lock_exclusive().map_err(|e| {
            ReviewQueueError(format!(
                "cannot lock review queue file {path} (another writer holds it?): {e}"
            ))
        })?;
        let mut queue = ReviewQueue {
            path: path.to_string(),
            records: Vec::new(),
            lock_file: Some(lock_file),
        };
        if Path::new(path).exists() {
            queue.load()?;
        }
        Ok(queue)
    }

    /// Load the review queue state file.
    pub fn load(&mut self) -> Result<(), ReviewQueueError> {
        let text = fs::read_to_string(&self.path).map_err(|e| {
            ReviewQueueError(format!("cannot read review queue file {}: {e}", self.path))
        })?;
        let records: Vec<ReviewRecord> = serde_json::from_str(&text).map_err(|e| {
            ReviewQueueError(format!("invalid review queue file {}: {e}", self.path))
        })?;
        // Compact duplicates: a file can hold several records for one
        // (instance, ref). Keep the most recently updated record per
        // key and drop the rest, so the file converges to one record
        // per ref on the next save.
        self.records = compact(records);
        Ok(())
    }

    /// Write the review queue state file atomically. In dry-run,
    /// prints what it WOULD write and writes nothing.
    pub fn save(&self, dry_run: &DryRun) -> Result<(), ReviewQueueError> {
        if !dry_run.allow(&format!("write review queue state file {}", self.path)) {
            return Ok(());
        }
        let text = serde_json::to_string_pretty(&self.records)
            .map_err(|e| ReviewQueueError(format!("cannot serialize review queue: {e}")))?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let mut tmp = String::new();
        let mut file = None;
        for attempt in 0..10 {
            tmp = format!(
                "{path}.{pid}.{nanos}.{attempt}.tmp",
                path = self.path,
                pid = pid,
                nanos = nanos,
                attempt = attempt
            );
            match OpenOptions::new().write(true).create_new(true).open(&tmp) {
                Ok(f) => {
                    file = Some(f);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(ReviewQueueError(format!(
                        "cannot write review queue file {tmp}: {e}"
                    )));
                }
            }
        }
        let file = match file {
            Some(f) => f,
            None => {
                return Err(ReviewQueueError(format!(
                    "cannot allocate a unique tmp review queue file for {}",
                    self.path
                )));
            }
        };
        // Write, fsync, rename, then fsync the parent directory so
        // the rename itself is durable. Any failure removes the tmp
        // file instead of leaving an orphan behind.
        if let Err(e) = Self::persist(&self.path, &text, &tmp, file) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(())
    }

    /// Write `text` to `tmp`, fsync it, atomically rename it over
    /// `path`, then fsync the parent directory so the rename itself
    /// survives a crash. Owns the tmp file handle; the caller removes
    /// `tmp` when this returns an error.
    fn persist(
        path: &str,
        text: &str,
        tmp: &str,
        mut file: std::fs::File,
    ) -> Result<(), ReviewQueueError> {
        file.write_all(format!("{text}\n").as_bytes())
            .map_err(|e| ReviewQueueError(format!("cannot write review queue file {tmp}: {e}")))?;
        file.sync_all()
            .map_err(|e| ReviewQueueError(format!("cannot fsync review queue file {tmp}: {e}")))?;
        drop(file);
        fs::rename(tmp, path).map_err(|e| {
            ReviewQueueError(format!("cannot replace review queue file {path}: {e}"))
        })?;
        let parent = Path::new(path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| {
                ReviewQueueError(format!(
                    "cannot fsync review queue directory {}: {e}",
                    parent.display()
                ))
            })?;
        Ok(())
    }

    /// Return the record for (`instance`, `reference`), or None.
    pub fn find(&self, instance: &str, reference: &str) -> Option<&ReviewRecord> {
        self.records
            .iter()
            .find(|r| r.instance == instance && r.reference == reference)
    }

    /// Insert a record, or refresh the existing one in place.
    /// Returns true when the record is new.
    ///
    /// Discovery never resets triage work: a record that was
    /// triaged, actioned, or escalated keeps its status; only a
    /// terminal record whose ref is open again returns to `open`.
    /// A record handed in with status `terminal` marks the existing
    /// record terminal (the ref left the server). Server-derived
    /// fields (title, author, binding, last_checked) refresh on
    /// every sighting.
    pub fn upsert(&mut self, record: ReviewRecord) -> bool {
        let now = now_iso();
        match self
            .records
            .iter_mut()
            .find(|r| r.instance == record.instance && r.reference == record.reference)
        {
            Some(existing) => {
                existing.title = record.title;
                existing.author = record.author;
                existing.binding = record.binding;
                existing.last_checked = now.clone();
                existing.updated_at = now;
                if record.status == "terminal" {
                    existing.status = "terminal".to_string();
                } else if existing.status == "terminal" {
                    existing.status = "open".to_string();
                }
                false
            }
            None => {
                self.records.push(record);
                true
            }
        }
    }

    /// Mark the record for (`instance`, `reference`) terminal: the
    /// ref left the server. Only the status and the check
    /// timestamps change; the title, author, and binding are kept
    /// (the server no longer serves them). Returns false when no
    /// such record exists.
    pub fn mark_terminal(&mut self, instance: &str, reference: &str) -> bool {
        let now = now_iso();
        match self
            .records
            .iter_mut()
            .find(|r| r.instance == instance && r.reference == reference)
        {
            Some(existing) => {
                existing.status = "terminal".to_string();
                existing.last_checked = now.clone();
                existing.updated_at = now;
                true
            }
            None => false,
        }
    }

    /// Record a fresh signal snapshot on the record for
    /// (`instance`, `reference`): only the snapshot and the check
    /// timestamps change; the status, tier, binding, and action
    /// history are kept. Returns false when no such record exists.
    pub fn set_signal_snapshot(
        &mut self,
        instance: &str,
        reference: &str,
        snapshot: serde_json::Value,
    ) -> bool {
        let now = now_iso();
        match self
            .records
            .iter_mut()
            .find(|r| r.instance == instance && r.reference == reference)
        {
            Some(existing) => {
                existing.signal_snapshot = Some(snapshot);
                existing.last_checked = now.clone();
                existing.updated_at = now;
                true
            }
            None => false,
        }
    }

    /// Record a classification on the record for (`instance`,
    /// `reference`): the tier, the decided action, the matching
    /// rule, and the ruleset version that produced them. An `open`
    /// record becomes `triaged`; any other status is kept (an
    /// escalated record is re-classified only after step 4
    /// re-opens it on a server-state change).
    /// Returns false when no such record exists.
    pub fn set_classification(
        &mut self,
        instance: &str,
        reference: &str,
        tier: &str,
        action: &str,
        rule: Option<&str>,
        ruleset_version: &str,
    ) -> bool {
        let now = now_iso();
        match self
            .records
            .iter_mut()
            .find(|r| r.instance == instance && r.reference == reference)
        {
            Some(existing) => {
                existing.tier = tier.to_string();
                existing.action = Some(action.to_string());
                existing.matched_rule = rule.map(str::to_string);
                existing.ruleset_version = Some(ruleset_version.to_string());
                if existing.status == "open" {
                    existing.status = "triaged".to_string();
                }
                existing.last_checked = now.clone();
                existing.updated_at = now;
                true
            }
            None => false,
        }
    }

    /// Escalate the record for (`instance`, `reference`) to a
    /// human (step 4): status `escalated`, with the reason, the
    /// exact question, and the fingerprint of the snapshot the
    /// escalation was raised on. Returns false when no such
    /// record exists.
    pub fn escalate(
        &mut self,
        instance: &str,
        reference: &str,
        reason: &str,
        question: Option<&str>,
        fingerprint: &str,
    ) -> bool {
        let now = now_iso();
        match self
            .records
            .iter_mut()
            .find(|r| r.instance == instance && r.reference == reference)
        {
            Some(existing) => {
                existing.status = "escalated".to_string();
                existing.escalation_reason = Some(reason.to_string());
                existing.escalated_at = Some(now.clone());
                existing.escalation_question = question.map(str::to_string);
                existing.escalation_fingerprint = Some(fingerprint.to_string());
                existing.last_checked = now.clone();
                existing.updated_at = now;
                true
            }
            None => false,
        }
    }

    /// Clear the escalation on the record for (`instance`,
    /// `reference`) and re-open it (step 4): the server state
    /// changed, so the old escalation no longer describes the
    /// item. The human decision, if one was recorded, is kept.
    /// Returns false when no such record exists.
    pub fn clear_escalation(&mut self, instance: &str, reference: &str) -> bool {
        let now = now_iso();
        match self
            .records
            .iter_mut()
            .find(|r| r.instance == instance && r.reference == reference)
        {
            Some(existing) => {
                if existing.status == "escalated" {
                    existing.status = "open".to_string();
                }
                existing.escalation_reason = None;
                existing.escalated_at = None;
                existing.escalation_question = None;
                existing.escalation_fingerprint = None;
                existing.last_checked = now.clone();
                existing.updated_at = now;
                true
            }
            None => false,
        }
    }

    /// Record a human decision on the record for (`instance`,
    /// `reference`) (step 4): `approved` | `declined` |
    /// `dismissed` (dismissed as not a queue item). A decision
    /// moves the record to `terminal`, so a re-run never
    /// re-escalates the same submission. Returns Ok(false) when
    /// no such record exists, and an error for any other
    /// decision string.
    pub fn record_human_decision(
        &mut self,
        instance: &str,
        reference: &str,
        decision: &str,
    ) -> Result<bool, ReviewQueueError> {
        if !HUMAN_DECISIONS.contains(&decision) {
            return Err(ReviewQueueError(format!(
                "invalid human decision {decision:?} (expected one of {})",
                HUMAN_DECISIONS.join(", ")
            )));
        }
        let now = now_iso();
        match self
            .records
            .iter_mut()
            .find(|r| r.instance == instance && r.reference == reference)
        {
            Some(existing) => {
                existing.human_decision = Some(decision.to_string());
                existing.human_decision_at = Some(now.clone());
                existing.status = "terminal".to_string();
                existing.last_checked = now.clone();
                existing.updated_at = now;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Record a posted action on the record for (`instance`,
    /// `reference`) (step 5): the action name (`comment`,
    /// `request-changes`), the server-side id it produced, and
    /// the fingerprint of the snapshot it was raised on. The
    /// record becomes `actioned`. Returns false when no such
    /// record exists.
    pub fn record_action(
        &mut self,
        instance: &str,
        reference: &str,
        action: &str,
        id: &str,
        fingerprint: &str,
    ) -> bool {
        let now = now_iso();
        match self
            .records
            .iter_mut()
            .find(|r| r.instance == instance && r.reference == reference)
        {
            Some(existing) => {
                existing.action_history.push(ReviewAction {
                    action: action.to_string(),
                    id: id.to_string(),
                    at: now.clone(),
                    fingerprint: fingerprint.to_string(),
                });
                existing.status = "actioned".to_string();
                existing.last_checked = now.clone();
                existing.updated_at = now;
                true
            }
            None => false,
        }
    }

    /// True when the record for (`instance`, `reference`) already
    /// carries an action named `action` raised on `fingerprint`
    /// (step 5): a re-run skips it instead of acting again.
    /// False when no such record exists.
    pub fn action_recorded(
        &self,
        instance: &str,
        reference: &str,
        action: &str,
        fingerprint: &str,
    ) -> bool {
        self.find(instance, reference).is_some_and(|record| {
            record
                .action_history
                .iter()
                .any(|a| a.action == action && a.fingerprint == fingerprint)
        })
    }

    /// The records, in file order.
    pub fn entries(&self) -> &[ReviewRecord] {
        &self.records
    }
}

/// The OBS submit-request ids freshcrab filed, from the update queue
/// entries (their `sr_id`). Discovery treats those requests as in
/// scope even when their target is not a watched package. An `sr_id`
/// that does not parse as a request id is not an OBS id and is
/// ignored.
pub fn own_sr_ids(entries: &[QueueEntry]) -> Vec<u64> {
    entries
        .iter()
        .filter_map(|e| e.sr_id.as_deref())
        .filter_map(|s| s.parse::<u64>().ok())
        .collect()
}

/// One scannable instance: a geectl config instance (alias + URL)
/// with the credentials that resolved for it, per backend. An
/// instance is scannable on a backend when credentials resolve for
/// it there; the backends are independent — one instance can be an
/// OBS instance, a Gitea instance, or (when both credential sets
/// resolve) both, and each arm fails closed on its own when it hits
/// the wrong service. A backend whose credential set is
/// misconfigured carries its error here so the skipped arm is
/// named in the report, never silently dropped.
#[derive(Debug, Clone)]
pub struct Instance {
    /// The geectl config alias, or `default` for the effective
    /// `obs_url` / `gitea_url`.
    pub alias: String,
    /// The API base (OBS) or host (Gitea).
    pub url: String,
    pub obs_credentials: Option<Credentials>,
    pub gitea_credentials: Option<Credentials>,
    /// A real credential misconfiguration for the OBS arm (a
    /// half-configured pair, both credential types set, an
    /// unreadable file). None when the arm has no credentials, or
    /// when the resolver refused only because the default
    /// instance's credentials are never forwarded here.
    pub obs_error: Option<String>,
    /// The same, for the Gitea arm.
    pub gitea_error: Option<String>,
}

/// The outcome of enumerating instances: the scannable ones plus
/// the ones that could not be scanned, each with its reason. An
/// unscannable instance is skipped, never silently dropped: it is
/// named in the discovery report.
#[derive(Debug, Default)]
pub struct InstanceScan {
    pub instances: Vec<Instance>,
    /// (alias, reason) for each instance with no usable credentials
    /// on either backend, or a misconfigured credential set.
    pub unscannable: Vec<(String, String)>,
}

/// Enumerate the configured instances from the geectl config file
/// (`[instances]` plus the effective `obs_url` / `gitea_url`).
/// A missing config file is an empty config: only the two defaults.
pub fn enumerate_instances() -> Result<InstanceScan, GeectlError> {
    let file_config = geectl_config::load_config()?;
    let effective = geectl_config::effective_config(&file_config)?;
    let obs_default = effective.config.obs_url.as_deref().unwrap_or(OBS_API_BASE);
    let gitea_default = effective
        .config
        .gitea_url
        .as_deref()
        .unwrap_or(geectl_config::DEFAULT_GITEA_URL);
    Ok(enumerate_instances_with(
        &file_config,
        obs_default,
        gitea_default,
        &|url| EnvObsAuth::credentials_for_url(url, obs_default, &file_config.instances),
        &|url| EnvGiteaAuth::credentials_for_url(url, gitea_default, &file_config.instances),
    ))
}

/// Enumerate instances with injectable credential resolvers, so
/// tests control the environment without touching process env vars.
/// `resolve_obs` / `resolve_gitea` resolve credentials for a URL
/// the way `EnvObsAuth::credentials_for_url` /
/// `EnvGiteaAuth::credentials_for_url` do: `Ok(Credentials::None)`
/// when nothing is configured, `Ok` with real credentials when the
/// instance is scannable on that backend, `Err` when the credential
/// set is misconfigured.
/// True when a credential error is a real misconfiguration worth
/// surfacing. Geectl refuses to forward the default instance's
/// credentials to another URL ("never forwarded to another
/// instance") — that is expected safety behaviour for the other
/// backend on every URL, not a misconfiguration, so it stays
/// silent. Any other credential error (a half-configured pair,
/// both credential types set, an unreadable token file) names
/// something to fix.
fn is_credential_misconfiguration(message: &str) -> bool {
    !message.contains("never forwarded to another instance")
}

pub fn enumerate_instances_with(
    file_config: &geectl_config::Config,
    obs_default: &str,
    gitea_default: &str,
    resolve_obs: &dyn Fn(&str) -> Result<Credentials, GeectlError>,
    resolve_gitea: &dyn Fn(&str) -> Result<Credentials, GeectlError>,
) -> InstanceScan {
    // Candidates: every named alias, then the two effective
    // defaults. Aliases come first so a named alias wins the
    // dedup when its URL is also a default.
    let mut candidates: Vec<(String, String)> = file_config
        .instances
        .iter()
        .map(|(alias, url)| (alias.clone(), url.clone()))
        .collect();
    candidates.push(("default".to_string(), obs_default.to_string()));
    candidates.push(("default".to_string(), gitea_default.to_string()));
    // Dedup by URL: one URL is one instance, whatever alias names
    // it. A URL that cannot be compared is kept as its own entry;
    // the client construction fails closed on it later.
    let mut unique: Vec<(String, String)> = Vec::new();
    for (alias, url) in candidates {
        let duplicate = unique
            .iter()
            .any(|(_, kept)| same_api_url(&url, kept).unwrap_or(false));
        if !duplicate {
            unique.push((alias, url));
        }
    }
    let mut scan = InstanceScan::default();
    for (alias, url) in unique {
        let mut reasons: Vec<String> = Vec::new();
        let mut obs_error: Option<String> = None;
        let obs_credentials = match resolve_obs(&url) {
            Ok(Credentials::None) => None,
            Ok(creds) => Some(creds),
            Err(e) => {
                let message = e.to_string();
                // A never-forwarded refusal is expected safety
                // behaviour, not a reason the instance is
                // unscannable: it stays out of the reasons so the
                // fallback "no credentials configured" message is
                // used instead.
                if is_credential_misconfiguration(&message) {
                    reasons.push(format!("OBS credentials unusable: {message}"));
                    obs_error = Some(message);
                }
                None
            }
        };
        let mut gitea_error: Option<String> = None;
        let gitea_credentials = match resolve_gitea(&url) {
            Ok(Credentials::None) => None,
            Ok(creds) => Some(creds),
            Err(e) => {
                let message = e.to_string();
                if is_credential_misconfiguration(&message) {
                    reasons.push(format!("Gitea token unusable: {message}"));
                    gitea_error = Some(message);
                }
                None
            }
        };
        if obs_credentials.is_none() && gitea_credentials.is_none() {
            if reasons.is_empty() {
                reasons.push(
                    "no OBS credentials and no Gitea token configured for this instance"
                        .to_string(),
                );
            }
            scan.unscannable.push((alias, reasons.join("; ")));
        } else {
            scan.instances.push(Instance {
                alias,
                url,
                obs_credentials,
                gitea_credentials,
                obs_error,
                gitea_error,
            });
        }
    }
    scan
}

/// The pull-request reads discovery and the signal readers need, as
/// a trait so tests inject a fake. Production passes
/// `PullRequestClient`.
pub trait PullRequestSource {
    fn search(&self, query: &PullRequestSearch) -> Result<Vec<PullRequestSummary>, GeectlError>;
    fn show(&self, reference: &PullRequestRef) -> Result<PullRequest, GeectlError>;
    /// The unified diff of the pull request (plain text, not XML).
    fn diff(&self, reference: &PullRequestRef) -> Result<String, GeectlError>;
    /// The build-results matrix for `package` in `project`
    /// (all repositories and architectures). The caller filters to
    /// the repositories and architectures the signal needs.
    fn build_results(&self, project: &str, package: &str) -> Result<BuildResults, GeectlError>;
    /// The maintainers of `package` in `project`, as `(name, role)`
    /// pairs (persons and groups flattened).
    fn maintainers(&self, project: &str, package: &str) -> Result<Vec<NamedRole>, GeectlError>;
    /// Post a comment on the pull request (step 5), through
    /// geectl's `PullRequestClient::comment`. Returns the created
    /// comment, or `None` in dry-run.
    fn comment(
        &self,
        reference: &PullRequestRef,
        body: &str,
        dry_run: &geectl::obs::DryRun,
    ) -> Result<Option<ReviewComment>, GeectlError>;
    /// List the comments on the pull request, oldest first (step
    /// 5), through geectl's `PullRequestClient::comments`.
    fn comments(&self, reference: &PullRequestRef) -> Result<Vec<ReviewComment>, GeectlError>;
}

impl<'a> PullRequestSource for PullRequestClient<'a> {
    fn search(&self, query: &PullRequestSearch) -> Result<Vec<PullRequestSummary>, GeectlError> {
        PullRequestClient::search(self, query)
    }

    fn show(&self, reference: &PullRequestRef) -> Result<PullRequest, GeectlError> {
        PullRequestClient::show(self, reference)
    }

    fn diff(&self, reference: &PullRequestRef) -> Result<String, GeectlError> {
        PullRequestClient::diff(self, reference, false)
    }

    fn build_results(&self, project: &str, package: &str) -> Result<BuildResults, GeectlError> {
        let obs = self.obs().ok_or_else(|| {
            GeectlError::new(
                ErrorKind::InvalidInput,
                "build results need the OBS arm: this client has no OBS backend",
            )
        })?;
        obs.results(
            project,
            &ResultsQuery {
                package: Some(package.to_string()),
                ..ResultsQuery::default()
            },
        )
    }

    fn maintainers(&self, project: &str, package: &str) -> Result<Vec<NamedRole>, GeectlError> {
        let obs = self.obs().ok_or_else(|| {
            GeectlError::new(
                ErrorKind::InvalidInput,
                "maintainers need the OBS arm: this client has no OBS backend",
            )
        })?;
        obs.maintainers(project, package)
    }

    fn comment(
        &self,
        reference: &PullRequestRef,
        body: &str,
        dry_run: &geectl::obs::DryRun,
    ) -> Result<Option<ReviewComment>, GeectlError> {
        PullRequestClient::comment(self, reference, body, None, dry_run)
    }

    fn comments(&self, reference: &PullRequestRef) -> Result<Vec<ReviewComment>, GeectlError> {
        PullRequestClient::comments(self, reference)
    }
}

/// The outcome of scanning one instance on one backend.
#[derive(Debug, Default)]
pub struct InstanceReport {
    pub alias: String,
    pub url: String,
    pub backend: String,
    /// Summaries the search returned.
    pub searched: usize,
    /// Summaries that passed the watch-scope filter.
    pub in_scope: usize,
    pub new_records: usize,
    pub updated_records: usize,
    pub terminal_marked: usize,
    /// Results whose target could not be read (a Gitea `show`
    /// failed), so scope could not be decided: skipped, fail-closed.
    pub unresolved: usize,
    /// The search itself failed: no records from this arm.
    pub error: Option<String>,
    /// The arm was skipped before any search ran (a misconfigured
    /// credential set): the error names the skipped arm, not a
    /// search failure.
    pub skipped: bool,
}

/// The outcome of a discovery run across all instances.
#[derive(Debug, Default)]
pub struct DiscoveryReport {
    pub instances: Vec<InstanceReport>,
    pub unscannable: Vec<(String, String)>,
    pub discovered: usize,
    pub new_records: usize,
    pub updated_records: usize,
    pub terminal_marked: usize,
    pub unresolved: usize,
}

/// The target package of a pull request, if the target names one:
/// the part after the last `/` in the target repository
/// (`project/package` on OBS, `owner/repo` on Gitea). None when the
/// target names no package (a project-only OBS action).
fn target_package(repository: &str) -> Option<&str> {
    repository
        .rsplit_once('/')
        .map(|(_, package)| package)
        .filter(|package| !package.is_empty())
}

/// True when the target is a maintenance request: the OBS target
/// project carries `:Update` or `:Maintenance` as a full segment
/// (`openSUSE:Leap:15.6:Update`, `openSUSE:Maintenance:1234`).
/// A segment that merely starts with those words
/// (`home:alice:UpdateTools`) is not a maintenance request.
/// Maintenance requests follow other rules and are never queue
/// items.
fn is_maintenance_target(repository: &str) -> bool {
    let project = repository.split('/').next().unwrap_or(repository);
    project
        .split(':')
        .any(|segment| segment == "Update" || segment == "Maintenance")
}

/// True when the target is a Leap pool pull request: the Gitea
/// target branch starts with `pool/`. Pool PRs follow other rules.
fn is_pool_target(branch: &Option<String>) -> bool {
    branch.as_deref().is_some_and(|b| b.starts_with("pool/"))
}

/// True when a submission is in the watch scope: its target package
/// is watched, or it is one of freshcrab's own filings (OBS, by
/// `sr_id`). The maintenance and pool exclusions always win.
fn in_scope(
    target_repository: &str,
    target_branch: &Option<String>,
    backend: PullRequestBackend,
    reference: &PullRequestRef,
    config: &Config,
    own_sr_ids: &[u64],
) -> bool {
    if is_pool_target(target_branch) {
        return false;
    }
    if is_maintenance_target(target_repository) {
        return false;
    }
    if let Some(package) = target_package(target_repository) {
        if config.watched(package) {
            return true;
        }
    }
    if backend == PullRequestBackend::Obs {
        if let PullRequestRef::Obs(id) = reference {
            if own_sr_ids.contains(id) {
                return true;
            }
        }
    }
    false
}

/// A discovered submission, with its endpoints resolved: the OBS
/// summary carries them; a Gitea global-search summary does not, so
/// the endpoints come from a `show`.
struct DiscoveredItem {
    reference: PullRequestRef,
    title: String,
    author: String,
    source_repository: String,
    source_commit: Option<String>,
    target_repository: String,
    target_commit: Option<String>,
    target_branch: Option<String>,
}

/// Scan one instance on one backend: search open submissions,
/// resolve each result's target, filter to the watch scope, upsert
/// the records, and re-check the records this search did not
/// return. Returns the per-instance report.
pub fn discover_on(
    source: &dyn PullRequestSource,
    backend: PullRequestBackend,
    instance_alias: &str,
    config: &Config,
    own_sr_ids: &[u64],
    queue: &mut ReviewQueue,
    _dry_run: &DryRun,
) -> InstanceReport {
    let mut report = InstanceReport {
        alias: instance_alias.to_string(),
        backend: backend.as_str().to_string(),
        ..InstanceReport::default()
    };
    let query = PullRequestSearch {
        backend: Some(backend),
        states: vec![PullRequestStatus::Open],
        ..PullRequestSearch::default()
    };
    let summaries = match source.search(&query) {
        Ok(summaries) => summaries,
        Err(e) => {
            report.error = Some(e.to_string());
            return report;
        }
    };
    report.searched = summaries.len();
    let mut seen: HashSet<String> = HashSet::new();
    // Refs the search returned but that are out of scope: they are
    // not upserted, but they are still live refs, so the re-check
    // below still asks the server about them — a ref that later
    // merges or declines is marked terminal instead of staying open
    // forever because it stopped being in scope.
    let mut out_of_scope_seen: HashSet<String> = HashSet::new();
    for summary in &summaries {
        // Resolve the endpoints. The OBS summary carries them; the
        // Gitea global search does not, so read the PR.
        let item = match backend {
            PullRequestBackend::Obs => DiscoveredItem {
                reference: summary.reference.clone(),
                title: summary.title.clone(),
                author: summary.author.clone(),
                source_repository: summary.source.repository.clone(),
                source_commit: summary.source.commit.clone(),
                target_repository: summary.target.repository.clone(),
                target_commit: summary.target.commit.clone(),
                target_branch: summary.target.branch.clone(),
            },
            PullRequestBackend::Gitea => match source.show(&summary.reference) {
                Ok(pr) => DiscoveredItem {
                    reference: pr.reference.clone(),
                    title: pr.title.clone(),
                    author: pr.author.clone(),
                    source_repository: pr.source.repository.clone(),
                    source_commit: pr.source.commit.clone(),
                    target_repository: pr.target.repository.clone(),
                    target_commit: pr.target.commit.clone(),
                    target_branch: pr.target.branch.clone(),
                },
                Err(e) => {
                    // The target cannot be read, so scope cannot be
                    // decided: skip the item, fail-closed, and say so.
                    report.unresolved += 1;
                    eprintln!(
                        "warning: cannot read {} on {}: {e}; skipping (scope undecidable)",
                        summary.reference, instance_alias
                    );
                    continue;
                }
            },
        };
        seen.insert(item.reference.to_string());
        if !in_scope(
            &item.target_repository,
            &item.target_branch,
            backend,
            &item.reference,
            config,
            own_sr_ids,
        ) {
            out_of_scope_seen.insert(item.reference.to_string());
            continue;
        }
        report.in_scope += 1;
        let record = ReviewRecord::new(
            &item.reference.to_string(),
            instance_alias,
            backend.as_str(),
            &item.title,
            &item.author,
            Some(ReviewBinding {
                source_repository: item.source_repository,
                source_commit: item.source_commit,
                target_repository: item.target_repository,
                target_commit: item.target_commit,
            }),
        );
        if queue.upsert(record) {
            report.new_records += 1;
        } else {
            report.updated_records += 1;
        }
    }
    // Re-check the records this search did not return, plus the
    // records it returned out of scope: a record whose ref left the
    // server (merged, declined, superseded, deleted) is marked
    // terminal from the server state, never deleted locally. A
    // failed re-check leaves the record as it is — a failed read
    // never marks anything terminal. An out-of-scope ref is only
    // ever terminal-marked, never refreshed: its title and binding
    // are not rewritten, whether the search returned it or omitted
    // it.
    let recheck: Vec<(String, String)> = queue
        .entries()
        .iter()
        .filter(|r| {
            r.instance == instance_alias
                && r.backend == backend.as_str()
                && r.status != "terminal"
                && (!seen.contains(&r.reference) || out_of_scope_seen.contains(&r.reference))
        })
        .map(|r| (r.reference.clone(), r.title.clone()))
        .collect();
    for (reference, _title) in recheck {
        let parsed: PullRequestRef = match reference.parse() {
            Ok(parsed) => parsed,
            Err(e) => {
                eprintln!(
                    "warning: cannot parse stored review ref {reference:?} on {instance_alias}: {e}; leaving it as is"
                );
                continue;
            }
        };
        match source.show(&parsed) {
            Ok(pr) => {
                if pr.status == PullRequestStatus::Open {
                    // Still open. Refresh it in place only when it
                    // is in scope — an out-of-scope ref (whether
                    // the search returned it or omitted it) is left
                    // untouched; only its terminal state is tracked.
                    if !in_scope(
                        &pr.target.repository,
                        &pr.target.branch,
                        backend,
                        &pr.reference,
                        config,
                        own_sr_ids,
                    ) {
                        continue;
                    }
                    let record = ReviewRecord::new(
                        &pr.reference.to_string(),
                        instance_alias,
                        backend.as_str(),
                        &pr.title,
                        &pr.author,
                        Some(ReviewBinding {
                            source_repository: pr.source.repository.clone(),
                            source_commit: pr.source.commit.clone(),
                            target_repository: pr.target.repository.clone(),
                            target_commit: pr.target.commit.clone(),
                        }),
                    );
                    if !queue.upsert(record) {
                        report.updated_records += 1;
                    }
                } else {
                    // Merged, declined, or otherwise no longer open:
                    // mark terminal, keeping the stored title and
                    // binding (the same as the NotFound arm below).
                    if queue.mark_terminal(instance_alias, &reference) {
                        report.terminal_marked += 1;
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // The ref left the server: mark terminal, keeping
                // the stored title and binding (the server no
                // longer serves them).
                if queue.mark_terminal(instance_alias, &reference) {
                    report.terminal_marked += 1;
                }
            }
            Err(e) => {
                eprintln!(
                    "warning: cannot re-check {reference} on {instance_alias}: {e}; leaving it as is"
                );
            }
        }
    }
    report
}

/// Run discovery across all configured instances: enumerate, search
/// each scannable instance on each backend it has credentials for,
/// filter to the watch scope, upsert records, re-check records the
/// searches did not return, and save the review queue
/// (DryRun-guarded). Report-only: no posts, no review-state
/// changes, no filings. A failed search on one instance is recorded
/// on that instance and the run continues with the rest; a failure
/// to enumerate instances or to open/save the queue is returned to
/// the caller (main logs it and continues — the review queue is
/// sidecar state and must not break the update pipeline).
pub fn discover(
    config: &Config,
    own_sr_ids: &[u64],
    http: &dyn geectl::http::HttpClient,
    path: &str,
    dry_run: &DryRun,
) -> Result<DiscoveryReport, ReviewQueueError> {
    let mut queue = ReviewQueue::open(path)?;
    let scan = enumerate_instances()
        .map_err(|e| ReviewQueueError(format!("cannot enumerate geectl instances: {e}")))?;
    discover_with_scan(config, own_sr_ids, http, &mut queue, dry_run, scan)
}

/// Run discovery over an already-enumerated scan, so tests drive
/// the per-arm report construction (including skipped arms) without
/// touching the real geectl config or environment. The queue is
/// opened by the caller, before enumeration, so the lock is held
/// and the error precedence match `discover`'s original order.
/// A per-arm report: the fields discovery and refresh share, so
/// one driver runs the instance/arm loop for both.
trait ArmReport: Default {
    /// A report for an arm that could not run: the client build
    /// failed, or the arm was skipped (a misconfigured credential
    /// set). `error` names the failure; `skipped` marks the arm
    /// skipped before any work ran.
    fn failed(alias: String, url: String, backend: String, error: String, skipped: bool) -> Self;
    /// The API base the arm ran against (set by the driver after
    /// the per-arm work returns, which does not know it).
    fn set_url(&mut self, url: String);
}

impl ArmReport for InstanceReport {
    fn failed(alias: String, url: String, backend: String, error: String, skipped: bool) -> Self {
        InstanceReport {
            alias,
            url,
            backend,
            error: Some(error),
            skipped,
            ..InstanceReport::default()
        }
    }

    fn set_url(&mut self, url: String) {
        self.url = url;
    }
}

impl ArmReport for SignalInstanceReport {
    fn failed(alias: String, url: String, backend: String, error: String, skipped: bool) -> Self {
        SignalInstanceReport {
            alias,
            url,
            backend,
            error: Some(error),
            skipped,
            ..SignalInstanceReport::default()
        }
    }

    fn set_url(&mut self, url: String) {
        self.url = url;
    }
}

/// The summary a driver run produces: the per-arm reports plus
/// the per-arm totals.
trait ArmSummary<R: ArmReport>: Default {
    fn set_unscannable(&mut self, unscannable: Vec<(String, String)>);
    fn push_instance(&mut self, report: R);
    fn accumulate(&mut self, report: &R);
}

impl ArmSummary<InstanceReport> for DiscoveryReport {
    fn set_unscannable(&mut self, unscannable: Vec<(String, String)>) {
        self.unscannable = unscannable;
    }

    fn push_instance(&mut self, report: InstanceReport) {
        self.instances.push(report);
    }

    fn accumulate(&mut self, report: &InstanceReport) {
        self.discovered += report.in_scope;
        self.new_records += report.new_records;
        self.updated_records += report.updated_records;
        self.terminal_marked += report.terminal_marked;
        self.unresolved += report.unresolved;
    }
}

impl ArmSummary<SignalInstanceReport> for SignalReport {
    fn set_unscannable(&mut self, unscannable: Vec<(String, String)>) {
        self.unscannable = unscannable;
    }

    fn push_instance(&mut self, report: SignalInstanceReport) {
        self.instances.push(report);
    }

    fn accumulate(&mut self, report: &SignalInstanceReport) {
        self.refreshed += report.refreshed;
        self.failed += report.failed;
    }
}

/// Run one per-arm function over every instance arm: build the
/// client for the arm (or record the arm skipped/failed), run the
/// work, and fold the per-arm report into the summary. Shared by
/// discovery and signal refresh so the instance/arm loop lives in
/// one place.
fn run_arms<R, S>(
    http: &dyn geectl::http::HttpClient,
    scan: InstanceScan,
    config: &Config,
    own_sr_ids: &[u64],
    queue: &mut ReviewQueue,
    dry_run: &DryRun,
    work: impl Fn(
        &dyn PullRequestSource,
        PullRequestBackend,
        &str,
        &Config,
        &[u64],
        &mut ReviewQueue,
        &DryRun,
    ) -> R,
) -> Result<S, ReviewQueueError>
where
    R: ArmReport,
    S: ArmSummary<R>,
{
    let InstanceScan {
        instances,
        unscannable,
    } = scan;
    let mut summary = S::default();
    summary.set_unscannable(unscannable);
    for instance in &instances {
        for backend in [PullRequestBackend::Obs, PullRequestBackend::Gitea] {
            let (credentials, credential_error) = match backend {
                PullRequestBackend::Obs => {
                    (instance.obs_credentials.clone(), instance.obs_error.clone())
                }
                PullRequestBackend::Gitea => (
                    instance.gitea_credentials.clone(),
                    instance.gitea_error.clone(),
                ),
            };
            let Some(creds) = credentials else {
                // No credentials for this arm. A real
                // misconfiguration is named in the report so the
                // skipped arm is never silent; the expected
                // "never forwarded" refusal carries no error and
                // stays silent.
                if let Some(error) = credential_error {
                    summary.push_instance(R::failed(
                        instance.alias.clone(),
                        instance.url.clone(),
                        backend.as_str().to_string(),
                        error,
                        true,
                    ));
                }
                continue;
            };
            let mut instance_report = match backend {
                PullRequestBackend::Obs => {
                    match ObsClient::with_base_and_credentials(http, &instance.url, creds) {
                        Ok(obs) => {
                            let client = PullRequestClient::new(Some(&obs), None);
                            work(
                                &client,
                                backend,
                                &instance.alias,
                                config,
                                own_sr_ids,
                                queue,
                                dry_run,
                            )
                        }
                        Err(e) => R::failed(
                            instance.alias.clone(),
                            instance.url.clone(),
                            backend.as_str().to_string(),
                            e.to_string(),
                            false,
                        ),
                    }
                }
                PullRequestBackend::Gitea => {
                    match GiteaClient::with_base(http, &instance.url, creds) {
                        Ok(gitea) => {
                            let client = PullRequestClient::new(None, Some(&gitea));
                            work(
                                &client,
                                backend,
                                &instance.alias,
                                config,
                                own_sr_ids,
                                queue,
                                dry_run,
                            )
                        }
                        Err(e) => R::failed(
                            instance.alias.clone(),
                            instance.url.clone(),
                            backend.as_str().to_string(),
                            e.to_string(),
                            false,
                        ),
                    }
                }
            };
            instance_report.set_url(instance.url.clone());
            summary.accumulate(&instance_report);
            summary.push_instance(instance_report);
        }
    }
    queue.save(dry_run)?;
    Ok(summary)
}

fn discover_with_scan(
    config: &Config,
    own_sr_ids: &[u64],
    http: &dyn geectl::http::HttpClient,
    queue: &mut ReviewQueue,
    dry_run: &DryRun,
    scan: InstanceScan,
) -> Result<DiscoveryReport, ReviewQueueError> {
    run_arms(http, scan, config, own_sr_ids, queue, dry_run, discover_on)
}

/// The outcome of a signal-refresh run across all instances.
#[derive(Debug, Default)]
pub struct SignalReport {
    pub instances: Vec<SignalInstanceReport>,
    pub unscannable: Vec<(String, String)>,
    /// Records whose snapshot was refreshed (including ones whose
    /// reads failed and were recorded as unknown).
    pub refreshed: usize,
    /// Records whose snapshot carries a failed read.
    pub failed: usize,
}

/// The outcome of refreshing one instance on one backend.
#[derive(Debug, Default)]
pub struct SignalInstanceReport {
    pub alias: String,
    pub url: String,
    pub backend: String,
    pub refreshed: usize,
    pub failed: usize,
    /// The refresh itself failed (no records refreshed on this arm).
    pub error: Option<String>,
    /// The arm was skipped before any refresh ran (a misconfigured
    /// credential set).
    pub skipped: bool,
}

/// Read the signal snapshot for one record through `source`.
/// Never fails the run: every failed read is recorded as `unknown`
/// with the failure named in `read_errors`, so the item goes to the
/// human tier (step 3) instead of being silently skipped. The
/// snapshot is the record's state at read time; a re-run re-reads
/// it.
pub fn read_signals(
    source: &dyn PullRequestSource,
    record: &ReviewRecord,
    config: &Config,
    own_sr_ids: &[u64],
) -> SignalSnapshot {
    let reference: PullRequestRef = match record.reference.parse() {
        Ok(reference) => reference,
        Err(e) => {
            return SignalSnapshot::unknown(vec![format!(
                "show: cannot parse stored review ref {:?}: {e}",
                record.reference
            )]);
        }
    };
    let pr = match source.show(&reference) {
        Ok(pr) => pr,
        Err(e) => {
            return SignalSnapshot::unknown(vec![format!("show: {e}")]);
        }
    };
    let mut read_errors: Vec<String> = Vec::new();

    let review = review_state(&pr);
    if let Some(reason) = &review.reason {
        read_errors.push(format!("review: {reason}"));
    }

    let diff = match source.diff(&reference) {
        Ok(text) => parse_diff(&text),
        Err(e) => {
            read_errors.push(format!("diff: {e}"));
            DiffSignal::unknown(Some(e.to_string()))
        }
    };
    // CVE ids named by the title and description as well as the diff.
    let mut cve_ids = diff.cve_ids.clone();
    for found in cve_ids_in(&pr.title)
        .into_iter()
        .chain(cve_ids_in(&pr.description))
    {
        if !cve_ids.contains(&found) {
            cve_ids.push(found);
        }
    }
    cve_ids.sort();

    let build = match record.backend.as_str() {
        "obs" => build_signal(source, &pr),
        _ => BuildSignal::unknown(Some("Gitea pull requests are not built".to_string())),
    };
    // A failed OBS build read is named; the Gitea "not built" is
    // expected, not a failed read, so it is not counted as one.
    if record.backend == "obs" {
        if let Some(reason) = &build.reason {
            read_errors.push(format!("build: {reason}"));
        }
        if let Some(target_reason) = &build.target_reason {
            read_errors.push(format!("target_build: {target_reason}"));
        }
    }

    let is_own = match &reference {
        PullRequestRef::Obs(id) => own_sr_ids.contains(id),
        _ => false,
    };
    // The author maintains the target package when their login is
    // among its maintainers (OBS arm, via geectl's
    // `ObsClient::maintainers`). Membership can only be proven,
    // never disproven: the list flattens persons and groups with
    // no discriminator, so a group-member author who matches no
    // name reads as unknown, not as a non-maintainer. An empty
    // list proves no maintainer in the package/project ancestry
    // the owner search walks. Gitea has no such read here.
    let is_package_maintainer = match record.backend.as_str() {
        "obs" => match split_project_package(&pr.target.repository) {
            Some((target_project, target_package)) => {
                match source.maintainers(target_project, target_package) {
                    Ok(maintainers) => {
                        if maintainers.iter().any(|m| m.name == pr.author) {
                            Some(true)
                        } else if maintainers.is_empty() {
                            Some(false)
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        read_errors.push(format!("maintainers: {e}"));
                        None
                    }
                }
            }
            None => None,
        },
        _ => None,
    };
    let author = AuthorSignal {
        author: pr.author.clone(),
        is_own_filing: Some(is_own),
        is_package_maintainer,
        first_time_submitter: None,
    };

    let package_name = target_package(&pr.target.repository).unwrap_or("");
    let package = PackageSignal {
        package: package_name.to_string(),
        is_excluded: Some(config.exclusions.iter().any(|e| e == package_name)),
        is_core: None,
        is_security: Some(!cve_ids.is_empty()),
        cve_ids,
    };

    let server = ServerSignal {
        status: pr.status.as_str().to_string(),
        draft: pr.draft,
        mergeable: pr.mergeable,
    };

    SignalSnapshot {
        read_at: now_iso(),
        build,
        review,
        diff,
        author,
        package,
        server,
        read_errors,
    }
}

/// The review-state signal from a read pull request. A review that
/// requests changes dominates: one `changes_requested` is the state
/// even beside approvals. `asked_pending` is an outstanding ask.
/// `reviews_error` (the Gitea arm's reviews failed to fetch) is
/// `unknown`, never `none`.
fn review_state(pr: &PullRequest) -> ReviewSignal {
    if let Some(error) = &pr.reviews_error {
        return ReviewSignal::unknown(Some(error.clone()));
    }
    let reviews: Vec<ReviewEntry> = pr
        .reviews
        .iter()
        .map(|r| ReviewEntry {
            reviewer: r.reviewer.clone(),
            state: r.state.as_str().to_string(),
        })
        .collect();
    let state = if reviews
        .iter()
        .any(|r| r.state == OpinionState::ChangesRequested.as_str())
    {
        "changes_requested"
    } else if reviews
        .iter()
        .any(|r| r.state == OpinionState::Approved.as_str())
    {
        "approved"
    } else if reviews
        .iter()
        .any(|r| r.state == OpinionState::Asked.as_str())
    {
        "asked_pending"
    } else {
        "none"
    };
    ReviewSignal {
        state: state.to_string(),
        reviews,
        reason: None,
    }
}

/// The build-status signal for an OBS pull request: the build of
/// the request's current sources (the source package in its source
/// project), on Tumbleweed and Leap 16, x86_64 and aarch64, plus
/// the target (devel) package's build in the target project. A
/// failure the devel project already has is not the submitter's.
/// A read failure is `unknown`, never green.
fn build_signal(source: &dyn PullRequestSource, pr: &PullRequest) -> BuildSignal {
    let (source_project, source_package) = match split_project_package(&pr.source.repository) {
        Some((project, package)) => (project, package),
        None => {
            return BuildSignal::unknown(Some(
                "source names no project/package to build".to_string(),
            ));
        }
    };
    let (status, cells, reason) = match build_status_for(source, source_project, source_package) {
        Ok((status, cells)) => (status, cells, None),
        Err(e) => ("unknown".to_string(), Vec::new(), Some(e.to_string())),
    };
    let (target_status, target_reason) = match split_project_package(&pr.target.repository) {
        Some((target_project, target_package)) => {
            match build_status_for(source, target_project, target_package) {
                Ok((target_status, _)) => (target_status, None),
                Err(e) => ("unknown".to_string(), Some(e.to_string())),
            }
        }
        None => ("unknown".to_string(), None),
    };
    BuildSignal {
        status,
        cells,
        target_status,
        target_reason,
        reason,
    }
}

/// The build status of one package in one project, restricted to
/// the Tumbleweed and Leap 16 repositories and the x86_64 and
/// aarch64 architectures. Returns the aggregate status and the
/// per-cell codes behind it. The build is the package's current
/// status in the project: geectl 0.2.3's read surface does not tie
/// a build to the request's exact source revision, so an older
/// green build cannot be told from a current one here — that needs
/// the build-test flow, not this read.
fn build_status_for(
    source: &dyn PullRequestSource,
    project: &str,
    package: &str,
) -> Result<(String, Vec<BuildCell>), GeectlError> {
    let matrix = source.build_results(project, package)?;
    let mut cells: Vec<BuildCell> = Vec::new();
    for cell in &matrix.results {
        if !is_signal_repo(&cell.repository) {
            continue;
        }
        if cell.arch != "x86_64" && cell.arch != "aarch64" {
            continue;
        }
        for status in &cell.statuses {
            if status.package == package {
                cells.push(BuildCell {
                    repository: cell.repository.clone(),
                    arch: cell.arch.clone(),
                    code: status.code.clone(),
                });
            }
        }
    }
    Ok((classify_build(&cells), cells))
}

/// The aggregate build status over the cells the signal read:
/// any failure dominates, then any in-progress build, then all
/// green; no evidence at all is `unknown`. All green needs a green
/// cell on Tumbleweed and on Leap 16: the design requires green on
/// both, so a matrix with no evidence from one of them is unknown,
/// not green.
fn classify_build(cells: &[BuildCell]) -> String {
    let mut tw_green = false;
    let mut leap_green = false;
    let mut any_building = false;
    for cell in cells {
        match build_code_kind(&cell.code) {
            BuildCodeKind::Failed => return "any_failed".to_string(),
            BuildCodeKind::Building => any_building = true,
            BuildCodeKind::Green => {
                if is_tumbleweed_repo(&cell.repository) {
                    tw_green = true;
                } else if is_leap16_repo(&cell.repository) {
                    leap_green = true;
                }
            }
            BuildCodeKind::NoEvidence => {}
        }
    }
    if any_building {
        return "building".to_string();
    }
    if tw_green && leap_green {
        return "all_green".to_string();
    }
    "unknown".to_string()
}

enum BuildCodeKind {
    Green,
    Failed,
    Building,
    NoEvidence,
}

/// The kind of one OBS package build code. `disabled`, `excluded`,
/// and `locked` carry no evidence either way: the package is not
/// built in that cell, which is neither green nor failed.
fn build_code_kind(code: &str) -> BuildCodeKind {
    match code {
        "succeeded" => BuildCodeKind::Green,
        "failed" | "unresolvable" | "broken" => BuildCodeKind::Failed,
        "building" | "scheduled" | "dispatching" | "signing" | "finishing" | "blocked" => {
            BuildCodeKind::Building
        }
        _ => BuildCodeKind::NoEvidence,
    }
}

/// True for a repository the build signal reads: Tumbleweed or
/// Leap 16, matched by name. A home or devel project that builds
/// against other repositories contributes no cells, so the signal
/// reads `unknown` there.
fn is_signal_repo(name: &str) -> bool {
    is_tumbleweed_repo(name) || is_leap16_repo(name)
}

fn is_tumbleweed_repo(name: &str) -> bool {
    name.to_lowercase().contains("tumbleweed")
}

fn is_leap16_repo(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("leap_16") || lower.contains("leap-16") || lower.contains("leap16")
}

/// Split a `project/package` repository into its project and
/// package. None when there is no `/` or the package is empty.
fn split_project_package(repository: &str) -> Option<(&str, &str)> {
    repository
        .rsplit_once('/')
        .filter(|(_, package)| !package.is_empty())
}

/// The CVE ids named in `text`, normalized and deduplicated.
/// Uses geectl's `CveId::parse` as the validator, so the format
/// is geectl's, not a copy of it here.
fn cve_ids_in(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &text[i..];
        let lower = rest.to_lowercase();
        let Some(pos) = lower.find("cve-") else {
            break;
        };
        let start = i + pos;
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'-') {
            end += 1;
        }
        let candidate = &text[start..end];
        // A token may carry a dash suffix (`CVE-2026-12345-fixed`):
        // retry the longest dash-truncated prefix that parses, so
        // the embedded CVE is not missed entirely.
        let mut candidate = candidate;
        while !candidate.is_empty() {
            if let Ok(parsed) = CveId::parse(candidate) {
                let id = parsed.to_string();
                if !found.contains(&id) {
                    found.push(id);
                }
                break;
            }
            match candidate.rfind('-') {
                Some(idx) => candidate = &candidate[..idx],
                None => break,
            }
        }
        i = end.max(start + 1);
    }
    found
}

/// Parse a diff into the diff-scope signal. The diff is
/// caller-consumed text (geectl returns it unparsed); the parsing
/// here is freshcrab's own read of the text, not an OBS or Gitea
/// API call. Two formats arrive: git-style (Gitea; `diff --git`,
/// `a/`/`b/` prefixes) and OBS plain text (sectioned:
/// `changes files:`, `spec files:`, `other changes:`, with bare
/// `---`/`+++` lines and `++++++ new ... file:` markers). Under
/// `other changes:` a `++++++` marker decides what follows: an
/// archive (or an `old -> new` tarball change) means tarball
/// contents to skip, while a plain file (`_patchinfo`, a service
/// file) is a package file to parse — the section label alone
/// cannot tell them apart. `version_bump_only` is a heuristic:
/// every file is a spec or a changelog, every changed spec line
/// is a version or release line (or a changelog entry line), and
/// the changelog only gains lines.
fn parse_diff(text: &str) -> DiffSignal {
    let mut files: Vec<String> = Vec::new();
    let mut new_files: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    // True once a `diff --git` header set `current`: the `---`/`+++`
    // lines then carry `a/`/`b/` prefixes to strip. OBS plain-text
    // diffs have no `diff --git` lines and bare paths.
    let mut current_git_style = false;
    // Set by a `++++++ new ... file:` marker or `--- /dev/null`:
    // the next file header is a new file.
    let mut pending_new = false;
    // True while the hunks after a `++++++` marker are tarball
    // contents: an archive (or an `old -> new` tarball change)
    // names tarball contents to skip; a plain file names a package
    // file to parse. Reset by every section header, so a new
    // section starts with package files.
    let mut in_tarball_contents = false;
    // True inside a spec `%changelog` section (per file): only
    // there is a `- ` bullet a changelog entry line.
    let mut in_changelog = false;
    let mut spec_changed = false;
    let mut patches_changed = false;
    let mut changelog_changed = false;
    let mut new_version: Option<String> = None;
    let mut cve_ids: Vec<String> = Vec::new();
    // (file, added, content, changelog line) for the changed
    // lines, so the version-bump check runs after the whole diff
    // is read.
    let mut changed: Vec<(String, bool, String, bool)> = Vec::new();

    for line in text.lines() {
        // OBS section headers reset the tarball-contents state: a
        // new section starts with package files. A bare `other
        // changes:` line can only be a section header: hunk lines
        // carry a `+`, `-`, ` `, or `@@` prefix.
        match line {
            "changes files:" | "spec files:" | "dsc files:" | "old:" | "new:"
            | "other changes:" => {
                in_tarball_contents = false;
            }
            _ => {}
        }
        // A `++++++` marker names what follows: an archive (or an
        // `old -> new` tarball change) means tarball contents to
        // skip; a plain file means a package file to parse, and a
        // ` (new)` suffix (or a `new ... file:` marker) marks it
        // new.
        if let Some(marker) = line.strip_prefix("++++++ ") {
            if is_tarball_marker(marker) {
                in_tarball_contents = true;
            } else {
                in_tarball_contents = false;
                if marker.ends_with(" (new)") || marker.starts_with("new ") {
                    pending_new = true;
                }
            }
            continue;
        }
        if in_tarball_contents {
            continue;
        }
        if let Some(rest) = line.strip_prefix("diff --git ") {
            let path = rest
                .rsplit_once(" b/")
                .map(|(_, path)| path)
                .unwrap_or(rest);
            current = Some(path.to_string());
            current_git_style = true;
            in_changelog = false;
            pending_new = false;
            if !files.contains(&path.to_string()) {
                files.push(path.to_string());
            }
            continue;
        }
        if line.starts_with("new file mode") {
            if let Some(path) = &current {
                if !new_files.contains(path) {
                    new_files.push(path.clone());
                }
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("--- ") {
            let path = header_path(rest, if current_git_style { Some("a/") } else { None });
            if path == "/dev/null" {
                pending_new = true;
            } else {
                current = Some(path.clone());
                in_changelog = false;
                if !files.contains(&path) {
                    files.push(path);
                }
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("+++ ") {
            let path = header_path(rest, if current_git_style { Some("b/") } else { None });
            if path != "/dev/null" {
                current = Some(path.clone());
                in_changelog = false;
                if !files.contains(&path) {
                    files.push(path.clone());
                }
                if pending_new {
                    if !new_files.contains(&path) {
                        new_files.push(path);
                    }
                    pending_new = false;
                }
            }
            // `+++ /dev/null`: a deleted file; `current` stays
            // from the `---` line.
            continue;
        }
        if line.starts_with("@@ ") {
            continue;
        }
        let Some(path) = &current else {
            continue;
        };
        // Context lines carry the spec section state.
        if let Some(context) = line.strip_prefix(' ') {
            if let Some(is_changelog) = section_header(context) {
                in_changelog = is_changelog;
            }
            continue;
        }
        if let Some(added) = line.strip_prefix('+') {
            if line.starts_with("+++") {
                continue;
            }
            if let Some(is_changelog) = section_header(added) {
                in_changelog = is_changelog;
            }
            let is_changelog_line = path.ends_with(".changes") || in_changelog;
            changed.push((path.clone(), true, added.to_string(), is_changelog_line));
        } else if let Some(removed) = line.strip_prefix('-') {
            if line.starts_with("---") {
                continue;
            }
            if let Some(is_changelog) = section_header(removed) {
                in_changelog = is_changelog;
            }
            let is_changelog_line = path.ends_with(".changes") || in_changelog;
            changed.push((path.clone(), false, removed.to_string(), is_changelog_line));
        }
    }

    for (path, added, content, _) in &changed {
        if path.ends_with(".spec") {
            spec_changed = true;
            if *added && new_version.is_none() {
                new_version = version_line(content);
            }
        } else if path.ends_with(".changes") {
            changelog_changed = true;
        }
        if path.ends_with(".patch") || path.ends_with(".diff") {
            patches_changed = true;
        }
        if *added {
            for found in cve_ids_in(content) {
                if !cve_ids.contains(&found) {
                    cve_ids.push(found);
                }
            }
        }
    }
    cve_ids.sort();

    // A bump touches the spec (the Version: line) and the changelog
    // (a new entry); a changelog-only change is not a bump.
    let version_bump_only = !files.is_empty()
        && spec_changed
        && files
            .iter()
            .all(|f| f.ends_with(".spec") || f.ends_with(".changes"))
        && changed.iter().all(|(path, added, content, is_changelog)| {
            if path.ends_with(".changes") {
                // A bump only adds changelog entries.
                *added
            } else {
                // .spec: only version, release, and changelog lines.
                is_version_line(content, *is_changelog)
            }
        });

    DiffSignal {
        files,
        spec_changed,
        version_bump_only,
        patches_changed,
        new_files,
        changelog_changed,
        new_version,
        cve_ids,
        reason: None,
    }
}

/// True for a `++++++` marker naming tarball contents. OBS's
/// diff generator (`BSSrcServer::Srcdiff::srcdiff`, the `doarchive`
/// regex) tardiffs exactly `.tar`, `.tgz`, `.tar.gz`,
/// `.tar.bz2`, `.tbz`, `.tar.xz`, `.tar.zst`, `.tar.zstd`,
/// `.gem`, `.obscpio`, `.livebuild`, `.zip`; everything else gets
/// a plain filediff — including bare `.gz`/`.bz2`/`.xz`/`.zst`
/// (decompressed and diffed) and `.tbz2`/`.txz`/`.tzst`/`.7z`/`.rar`.
/// A `old -> new` rename marker is a tardiff only when the new
/// side is an archive; a renamed plain file gets a plain filediff.
fn is_tarball_marker(marker: &str) -> bool {
    // A rename names tarball contents only when the new side is
    // an archive.
    let name = match marker.split_once(" -> ") {
        Some((_, new)) => new,
        None => marker,
    };
    // A new archive is still an archive. No lowercasing: OBS's
    // regex is case-sensitive, so an uppercase extension is a
    // plain filediff there too.
    let name = name.strip_suffix(" (new)").unwrap_or(name);
    name.ends_with(".tar")
        || name.ends_with(".tgz")
        || name.ends_with(".tar.gz")
        || name.ends_with(".tar.bz2")
        || name.ends_with(".tbz")
        || name.ends_with(".tar.xz")
        || name.ends_with(".tar.zst")
        || name.ends_with(".tar.zstd")
        || name.ends_with(".gem")
        || name.ends_with(".obscpio")
        || name.ends_with(".livebuild")
        || name.ends_with(".zip")
}

/// The file path from a `---`/`+++` header line: strip a trailing
/// tab + revision/timestamp, and the `a/`/`b/` prefix of a
/// git-style diff (OBS plain-text diffs carry bare paths).
fn header_path(raw: &str, prefix: Option<&str>) -> String {
    let path = raw.split('\t').next().unwrap_or(raw).trim_end();
    match prefix {
        Some(prefix) => path.strip_prefix(prefix).unwrap_or(path).to_string(),
        None => path.to_string(),
    }
}

/// A spec section header line (`%description`, `%changelog`,
/// ...): `Some(true)` for `%changelog`, `Some(false)` for any
/// other section, `None` when the line is not a section header.
/// Section headers reset the `%changelog` tracking in
/// `parse_diff`, so a `%description` bullet is not read as a
/// changelog entry.
fn section_header(content: &str) -> Option<bool> {
    let trimmed = content.trim();
    if !trimmed.starts_with('%') || trimmed.starts_with("%{") {
        return None;
    }
    let name = trimmed[1..].split_whitespace().next().unwrap_or("");
    match name {
        "changelog" => Some(true),
        "description"
        | "prep"
        | "build"
        | "install"
        | "check"
        | "files"
        | "post"
        | "pre"
        | "preun"
        | "postun"
        | "pretrans"
        | "posttrans"
        | "package"
        | "triggerin"
        | "triggerun"
        | "triggerpostun"
        | "verifyscript"
        | "clean"
        | "generate_buildrequires" => Some(false),
        _ => None,
    }
}

/// The `Version:` of an added spec line, when the line sets it.
/// A trailing comment is not part of the version.
fn version_line(content: &str) -> Option<String> {
    let trimmed = content.trim_start();
    let rest = trimmed.strip_prefix("Version:")?;
    let version = rest.split('#').next().unwrap_or(rest).trim();
    let version = version.split_whitespace().next().unwrap_or("");
    if version.is_empty() {
        return None;
    }
    Some(version.to_string())
}

/// True for a changed spec line a version bump may touch: a
/// `Version:` or `Release:` tag, a version macro definition, or a
/// changelog entry line (`* date ...` header or `- ...` bullet).
/// Anything else (a dependency, a patch line, a build flag) makes
/// the change more than a bump. The `- ` bullet only counts inside
/// a changelog: a `%description` bullet is not one. The `* date`
/// header is distinctive enough (it needs a weekday) to count on
/// its own, even when the `%changelog` header sits outside the
/// hunk.
fn is_version_line(content: &str, is_changelog: bool) -> bool {
    let trimmed = content.trim_start();
    // A blank separator line carries no change.
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.starts_with("Version:") || trimmed.starts_with("Release:") {
        return true;
    }
    let lower = trimmed.to_lowercase();
    if (lower.starts_with("%define") || lower.starts_with("%global")) && lower.contains("version") {
        return true;
    }
    if is_changelog_header(trimmed) {
        return true;
    }
    if is_changelog && trimmed.starts_with("- ") {
        return true;
    }
    false
}

/// True for a `%changelog` entry header: `* <weekday> <month>
/// <day> <year> ...`. The weekday pins it to a changelog header
/// rather than any other `*` line in the spec.
fn is_changelog_header(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("* ") else {
        return false;
    };
    let mut words = rest.split_whitespace();
    matches!(
        words.next(),
        Some("Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun")
    )
}

/// Refresh the signal snapshots for every non-terminal record, on
/// every run: read the signals for each record through the
/// per-instance client, record the snapshot on the record, and
/// save the review queue (DryRun-guarded). Report-only: no posts,
/// no review-state changes, no filings. A failed read on one
/// record is recorded as `unknown` on that record and the run
/// continues with the rest; a failure to enumerate instances or to
/// open/save the queue is returned to the caller (main logs it and
/// continues — the review queue is sidecar state and must not
/// break the update pipeline).
pub fn refresh_signals(
    config: &Config,
    own_sr_ids: &[u64],
    http: &dyn geectl::http::HttpClient,
    path: &str,
    dry_run: &DryRun,
) -> Result<SignalReport, ReviewQueueError> {
    let mut queue = ReviewQueue::open(path)?;
    let scan = enumerate_instances()
        .map_err(|e| ReviewQueueError(format!("cannot enumerate geectl instances: {e}")))?;
    refresh_with_scan(config, own_sr_ids, http, &mut queue, dry_run, scan)
}

/// Run the refresh over an already-enumerated scan, so tests drive
/// the per-arm report construction without touching the real geectl
/// config or environment.
fn refresh_with_scan(
    config: &Config,
    own_sr_ids: &[u64],
    http: &dyn geectl::http::HttpClient,
    queue: &mut ReviewQueue,
    dry_run: &DryRun,
    scan: InstanceScan,
) -> Result<SignalReport, ReviewQueueError> {
    run_arms(http, scan, config, own_sr_ids, queue, dry_run, refresh_on)
}

/// Refresh the snapshots for the non-terminal records on one
/// instance arm. Terminal records are skipped: their refs left the
/// server, so there is nothing to read. A failed read is recorded
/// as `unknown` on the record (never green) and counted, and the
/// refresh continues with the next record.
fn refresh_on(
    source: &dyn PullRequestSource,
    backend: PullRequestBackend,
    instance_alias: &str,
    config: &Config,
    own_sr_ids: &[u64],
    queue: &mut ReviewQueue,
    _dry_run: &DryRun,
) -> SignalInstanceReport {
    let mut report = SignalInstanceReport {
        alias: instance_alias.to_string(),
        backend: backend.as_str().to_string(),
        ..SignalInstanceReport::default()
    };
    let targets: Vec<ReviewRecord> = queue
        .entries()
        .iter()
        .filter(|r| {
            r.instance == instance_alias && r.backend == backend.as_str() && r.status != "terminal"
        })
        .cloned()
        .collect();
    for record in &targets {
        let snapshot = read_signals(source, record, config, own_sr_ids);
        let failed = !snapshot.read_errors.is_empty();
        let json = match serde_json::to_value(&snapshot) {
            Ok(json) => json,
            Err(e) => {
                eprintln!(
                    "warning: cannot serialize signal snapshot for {} on {instance_alias}: {e}; leaving it as is",
                    record.reference
                );
                report.failed += 1;
                continue;
            }
        };
        if queue.set_signal_snapshot(instance_alias, &record.reference, json) {
            report.refreshed += 1;
            if failed {
                report.failed += 1;
            }
        }
    }
    report
}

/// The actions a ruleset rule can decide. `decline` is normalized
/// to `comment` by the evaluator: OBS decline is human-only, so
/// the queue comments in the ruleset cases instead of declining.
pub const RULESET_ACTIONS: &[&str] = &[
    "comment",
    "request-changes",
    "decline",
    "escalate-human",
    "hold",
    "accept-trivial",
];

/// The signal-snapshot paths a rule condition may name. A path
/// outside this set is a load error, never a silent never-match:
/// a typo'd path must refuse the run, not misclassify every item.
const RULESET_PATHS: &[&str] = &[
    "read_errors",
    "build.status",
    "build.target_status",
    "review.state",
    "diff.files",
    "diff.spec_changed",
    "diff.version_bump_only",
    "diff.patches_changed",
    "diff.new_files",
    "diff.changelog_changed",
    "diff.new_version",
    "diff.cve_ids",
    "author.is_own_filing",
    "author.is_package_maintainer",
    "author.first_time_submitter",
    "package.package",
    "package.is_excluded",
    "package.is_core",
    "package.is_security",
    "package.cve_ids",
    "server.status",
    "server.draft",
    "server.mergeable",
];

/// The condition operators. `eq` / `ne` compare a scalar;
/// `in` tests membership in an array of scalars; `contains`
/// is a string substring (or an array element, exact);
/// `contains_any` is a string substring against any of an array
/// of strings; `starts_with` is a string prefix;
/// `any_basename_in` matches when any file in an array has a
/// basename in the array of names; `any_ends_with` matches when
/// any string in an array ends with any of an array of suffixes;
/// `is_empty` / `is_non_empty` match an absent, null, empty
/// string, or empty array (and its negation).
const RULESET_OPS: &[&str] = &[
    "eq",
    "ne",
    "in",
    "contains",
    "contains_any",
    "starts_with",
    "any_basename_in",
    "any_ends_with",
    "is_empty",
    "is_non_empty",
];

/// One condition in a ruleset rule's signal pattern: all of a
/// rule's conditions must match for the rule to match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCondition {
    pub path: String,
    pub op: String,
    /// The compared value. Absent for `is_empty` /
    /// `is_non_empty`; anything else is a load error.
    #[serde(default)]
    pub value: Option<serde_json::Value>,
}

/// One rule in the ruleset file: its signal pattern, its action,
/// the finding text, and — for human-tier rules — the exact
/// question for the human (step 4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesetRule {
    pub name: String,
    #[serde(default)]
    pub when: Vec<RuleCondition>,
    pub action: String,
    pub message: String,
    #[serde(default)]
    pub question: Option<String>,
}

/// The ruleset file shape (`review_ruleset.json`): a version
/// plus the rules in evaluation order. Unknown fields are
/// rejected, like the config file's unknown keys: a typo'd field
/// must refuse the run, not be silently ignored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesetFile {
    pub version: String,
    pub rules: Vec<RulesetRule>,
}

/// A loaded, validated ruleset.
#[derive(Debug, Clone, PartialEq)]
pub struct Ruleset {
    pub version: String,
    pub rules: Vec<RulesetRule>,
}

impl Ruleset {
    /// Load and validate the ruleset file at `path`. Any failure
    /// (missing file, invalid JSON, unknown field, unknown action,
    /// unknown path or operator, bad condition value) refuses the
    /// run: the caller gets the error and classifies nothing,
    /// never a default-allow fallback.
    pub fn load(path: &str) -> Result<Self, ReviewQueueError> {
        let text = fs::read_to_string(path)
            .map_err(|e| ReviewQueueError(format!("cannot read ruleset file {path}: {e}")))?;
        Self::load_text(&text)
    }

    /// Load and validate a ruleset from its JSON text (used by the
    /// tests; `load` is the file entry point).
    pub fn load_text(text: &str) -> Result<Self, ReviewQueueError> {
        let file: RulesetFile = serde_json::from_str(text)
            .map_err(|e| ReviewQueueError(format!("invalid ruleset file: {e}")))?;
        Self::validate(file)
    }

    /// Validate a parsed ruleset file: a non-empty version, unique
    /// non-empty rule names, non-empty messages, known actions,
    /// and well-formed conditions (known path and operator, a
    /// value of the shape the operator needs).
    fn validate(file: RulesetFile) -> Result<Self, ReviewQueueError> {
        if file.version.trim().is_empty() {
            return Err(ReviewQueueError(
                "invalid ruleset file: version must be a non-empty string".to_string(),
            ));
        }
        let mut names: HashSet<&str> = HashSet::new();
        for rule in &file.rules {
            if rule.name.trim().is_empty() {
                return Err(ReviewQueueError(
                    "invalid ruleset file: every rule needs a non-empty name".to_string(),
                ));
            }
            if !names.insert(rule.name.as_str()) {
                return Err(ReviewQueueError(format!(
                    "invalid ruleset file: duplicate rule name {:?}",
                    rule.name
                )));
            }
            if !RULESET_ACTIONS.contains(&rule.action.as_str()) {
                return Err(ReviewQueueError(format!(
                    "invalid ruleset file: rule {:?} has unknown action {:?} (expected one of {})",
                    rule.name,
                    rule.action,
                    RULESET_ACTIONS.join(", ")
                )));
            }
            if rule.message.trim().is_empty() {
                return Err(ReviewQueueError(format!(
                    "invalid ruleset file: rule {:?} needs a non-empty message",
                    rule.name
                )));
            }
            for condition in &rule.when {
                Self::validate_condition(&rule.name, condition)?;
            }
        }
        Ok(Ruleset {
            version: file.version,
            rules: file.rules,
        })
    }

    /// Validate one condition: a known path, a known operator,
    /// and a value of the shape the operator needs (absent for
    /// `is_empty` / `is_non_empty`, a scalar for `eq` / `ne`, a
    /// non-empty string for `contains` / `starts_with`, a
    /// non-empty array of strings for the rest).
    fn validate_condition(rule: &str, condition: &RuleCondition) -> Result<(), ReviewQueueError> {
        let invalid = |what: &str| {
            ReviewQueueError(format!(
                "invalid ruleset file: rule {rule:?} condition {:?} {}: {what}",
                condition.path, condition.op
            ))
        };
        if !RULESET_PATHS.contains(&condition.path.as_str()) {
            return Err(invalid(&format!(
                "unknown signal path (expected one of {})",
                RULESET_PATHS.join(", ")
            )));
        }
        if !RULESET_OPS.contains(&condition.op.as_str()) {
            return Err(invalid(&format!(
                "unknown operator (expected one of {})",
                RULESET_OPS.join(", ")
            )));
        }
        match condition.op.as_str() {
            "is_empty" | "is_non_empty" => {
                if condition.value.is_some() {
                    return Err(invalid("takes no value"));
                }
            }
            "eq" | "ne" => match &condition.value {
                Some(value) if value.is_string() || value.is_boolean() || value.is_number() => {}
                _ => return Err(invalid("needs a string, boolean, or number value")),
            },
            "contains" | "starts_with" => match &condition.value {
                Some(serde_json::Value::String(s)) if !s.is_empty() => {}
                _ => return Err(invalid("needs a non-empty string value")),
            },
            "in" => match &condition.value {
                Some(serde_json::Value::Array(items))
                    if !items.is_empty()
                        && items.iter().all(|item| {
                            item.is_boolean()
                                || item.is_number()
                                || item.as_str().is_some_and(|s| !s.is_empty())
                        }) => {}
                _ => {
                    return Err(invalid(
                        "needs a non-empty array of scalars (strings must be non-empty)",
                    ));
                }
            },
            "contains_any" | "any_basename_in" | "any_ends_with" => match &condition.value {
                Some(serde_json::Value::Array(items))
                    if !items.is_empty()
                        && items
                            .iter()
                            .all(|item| item.as_str().is_some_and(|s| !s.is_empty())) => {}
                _ => {
                    return Err(invalid("needs a non-empty array of non-empty strings"));
                }
            },
            _ => unreachable!("operator validated above"),
        }
        Ok(())
    }
}

/// The evaluator's verdict for one record: the tier, the decided
/// action, the matching rule (None when no rule matched), the
/// finding text, and — for human-tier verdicts — the exact
/// question for the human (step 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub tier: String,
    pub action: String,
    pub rule: Option<String>,
    pub reason: String,
    pub question: Option<String>,
}

/// Classify one signal snapshot against the ruleset, in file
/// order: the first matching rule wins. No rule matching means
/// the human tier (fail-closed). A `decline` rule is normalized
/// to `comment`: OBS decline is human-only, so the queue comments
/// in the ruleset cases instead of declining.
pub fn classify(ruleset: &Ruleset, snapshot: &SignalSnapshot) -> Classification {
    let json = match serde_json::to_value(snapshot) {
        Ok(json) => json,
        Err(_) => {
            // The snapshot is freshcrab's own serialization, so
            // this is unreachable in practice; fail closed to the
            // human tier rather than guessing a verdict.
            return Classification {
                tier: "human".to_string(),
                action: "escalate-human".to_string(),
                rule: None,
                reason: "The signal snapshot cannot be read; fail-closed to the human tier."
                    .to_string(),
                question: Some(
                    "The signal snapshot cannot be read — what does the server actually say for this submission?"
                        .to_string(),
                ),
            };
        }
    };
    for rule in &ruleset.rules {
        if rule
            .when
            .iter()
            .all(|condition| condition_matches(condition, &json))
        {
            return classification_for(rule);
        }
    }
    Classification {
        tier: "human".to_string(),
        action: "escalate-human".to_string(),
        rule: None,
        reason: "No ruleset rule covers this item; fail-closed to the human tier.".to_string(),
        question: Some("No ruleset rule covers this item — what should happen to it?".to_string()),
    }
}

/// The verdict for one matching rule: the tier follows the
/// action (`comment` / `request-changes` / `accept-trivial` are
/// auto; `hold` is mid; `escalate-human` is human).
fn classification_for(rule: &RulesetRule) -> Classification {
    match rule.action.as_str() {
        "comment" | "request-changes" | "accept-trivial" => Classification {
            tier: "auto".to_string(),
            action: rule.action.clone(),
            rule: Some(rule.name.clone()),
            reason: rule.message.clone(),
            question: rule.question.clone(),
        },
        "hold" => Classification {
            tier: "mid".to_string(),
            action: "hold".to_string(),
            rule: Some(rule.name.clone()),
            reason: rule.message.clone(),
            question: rule.question.clone(),
        },
        "decline" => Classification {
            tier: "auto".to_string(),
            action: "comment".to_string(),
            rule: Some(rule.name.clone()),
            reason: format!(
                "{} (Rule {:?} says decline; OBS decline is human-only, so the queue comments instead.)",
                rule.message, rule.name
            ),
            question: rule.question.clone(),
        },
        "escalate-human" => Classification {
            tier: "human".to_string(),
            action: "escalate-human".to_string(),
            rule: Some(rule.name.clone()),
            reason: rule.message.clone(),
            question: rule.question.clone(),
        },
        _ => unreachable!("rule actions are validated at load"),
    }
}

/// True when one condition matches the snapshot (as JSON): the
/// condition's path resolves into the snapshot, and the operator
/// holds. A null or missing value matches only `is_empty`
/// (absence is empty); every other operator needs a real value.
fn condition_matches(condition: &RuleCondition, snapshot: &serde_json::Value) -> bool {
    let resolved = snapshot_value(snapshot, &condition.path);
    match condition.op.as_str() {
        "is_empty" => is_empty_value(resolved),
        "is_non_empty" => !is_empty_value(resolved),
        "eq" => {
            matches!(resolved, Some(value) if !value.is_null() && Some(value) == condition.value.as_ref())
        }
        "ne" => {
            matches!(resolved, Some(value) if !value.is_null() && Some(value) != condition.value.as_ref())
        }
        "in" => match (resolved, &condition.value) {
            (Some(value), Some(serde_json::Value::Array(items)))
                if !value.is_null() && !value.is_array() && !value.is_object() =>
            {
                items.iter().any(|item| item == value)
            }
            _ => false,
        },
        "contains" => match (resolved, &condition.value) {
            (
                Some(serde_json::Value::String(haystack)),
                Some(serde_json::Value::String(needle)),
            ) => haystack.contains(needle.as_str()),
            (Some(serde_json::Value::Array(items)), Some(needle)) => {
                items.iter().any(|item| item == needle)
            }
            _ => false,
        },
        "contains_any" => match (resolved, &condition.value) {
            (
                Some(serde_json::Value::String(haystack)),
                Some(serde_json::Value::Array(needles)),
            ) => needles.iter().any(|needle| {
                needle
                    .as_str()
                    .is_some_and(|needle| haystack.contains(needle))
            }),
            _ => false,
        },
        "starts_with" => match (resolved, &condition.value) {
            (
                Some(serde_json::Value::String(haystack)),
                Some(serde_json::Value::String(prefix)),
            ) => haystack.starts_with(prefix.as_str()),
            _ => false,
        },
        "any_basename_in" => match (resolved, &condition.value) {
            (Some(serde_json::Value::Array(files)), Some(serde_json::Value::Array(names))) => {
                files.iter().any(|file| {
                    file.as_str().is_some_and(|file| {
                        let basename = file.rsplit('/').next().unwrap_or(file);
                        names
                            .iter()
                            .any(|name| name.as_str().is_some_and(|name| name == basename))
                    })
                })
            }
            _ => false,
        },
        "any_ends_with" => match (resolved, &condition.value) {
            (Some(serde_json::Value::Array(items)), Some(serde_json::Value::Array(suffixes))) => {
                items.iter().any(|item| {
                    item.as_str().is_some_and(|item| {
                        suffixes.iter().any(|suffix| {
                            suffix.as_str().is_some_and(|suffix| item.ends_with(suffix))
                        })
                    })
                })
            }
            _ => false,
        },
        _ => unreachable!("operators are validated at load"),
    }
}

/// True for an absent, null, empty-string, or empty-array value.
fn is_empty_value(value: Option<&serde_json::Value>) -> bool {
    match value {
        None => true,
        Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::String(s)) => s.is_empty(),
        Some(serde_json::Value::Array(items)) => items.is_empty(),
        Some(_) => false,
    }
}

/// Resolve a dotted path (`build.status`, `read_errors`) into the
/// snapshot JSON. None when any step is missing.
fn snapshot_value<'a>(
    snapshot: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = snapshot;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

/// The outcome of a classification run over the queue file.
#[derive(Debug, Default)]
pub struct ClassifyReport {
    pub classified: usize,
    pub auto: usize,
    pub mid: usize,
    pub human: usize,
    /// Terminal records: classified never; the ref left the server.
    pub skipped_terminal: usize,
    /// Escalated records whose server state is unchanged:
    /// classification leaves them parked (step 4 re-opens them
    /// only when the state changes).
    pub skipped_escalated: usize,
    /// Records with no signal snapshot yet (an unscannable
    /// instance, or a record discovery just wrote): nothing to
    /// classify.
    pub skipped_no_snapshot: usize,
    /// Records whose snapshot says the ref is no longer open
    /// (merged, declined): discovery marks them terminal on its
    /// next pass; classification leaves them alone.
    pub skipped_not_open: usize,
}

/// Classify every classifiable record in the queue file against
/// the ruleset at `ruleset_path`, record the tier, the decided
/// action, the matching rule, and the ruleset version, and save
/// the queue (DryRun-guarded). Report-only: it records the
/// verdict; it posts nothing. A ruleset that fails to load
/// refuses the run: the error is returned and nothing is
/// classified. Terminal records are skipped. An escalated record
/// is skipped while its server state is unchanged (step 4 parks
/// it); when the state changes, the escalation is cleared and
/// the record is re-classified, and a human verdict escalates it
/// again with the new fingerprint. Records with no snapshot yet
/// and records whose snapshot says the ref is no longer open are
/// skipped. A snapshot that cannot be parsed is classified from
/// an unknown snapshot, so the `failed-read` rule escalates it
/// instead of dropping it.
pub fn classify_records(
    ruleset_path: &str,
    queue_path: &str,
    dry_run: &DryRun,
) -> Result<ClassifyReport, ReviewQueueError> {
    let ruleset = Ruleset::load(ruleset_path)?;
    let mut queue = ReviewQueue::open(queue_path)?;
    let mut report = ClassifyReport::default();
    let targets: Vec<ReviewRecord> = queue.entries().to_vec();
    for record in &targets {
        if record.status == "terminal" {
            report.skipped_terminal += 1;
            continue;
        }
        if record.status == "escalated" {
            // Parked (step 4): re-classify only when the server
            // state changed. The fingerprint is over the current
            // snapshot and the ruleset version that produced the
            // escalation, so a new ruleset re-opens the record
            // too. No snapshot cannot prove a change, so the
            // record stays parked; an unparsable snapshot cannot
            // prove the state is unchanged, so it re-opens.
            let parked = match &record.signal_snapshot {
                None => true,
                Some(stored) => match serde_json::from_value::<SignalSnapshot>(stored.clone()) {
                    Ok(snapshot) => {
                        let fingerprint = classification_fingerprint(
                            record.ruleset_version.as_deref().unwrap_or(""),
                            &snapshot,
                            &record.binding,
                        );
                        record.escalation_fingerprint.as_deref() == Some(fingerprint.as_str())
                    }
                    Err(_) => false,
                },
            };
            if parked {
                report.skipped_escalated += 1;
                continue;
            }
            // The server state changed: clear the escalation and
            // fall through to classify the new state.
            queue.clear_escalation(&record.instance, &record.reference);
        }
        let Some(stored) = &record.signal_snapshot else {
            report.skipped_no_snapshot += 1;
            continue;
        };
        let snapshot: SignalSnapshot = match serde_json::from_value(stored.clone()) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                SignalSnapshot::unknown(vec![format!("cannot parse stored signal snapshot: {e}")])
            }
        };
        if snapshot.server.status != "open" && snapshot.server.status != "unknown" {
            report.skipped_not_open += 1;
            continue;
        }
        let verdict = classify(&ruleset, &snapshot);
        match verdict.tier.as_str() {
            "auto" => report.auto += 1,
            "mid" => report.mid += 1,
            _ => report.human += 1,
        }
        if queue.set_classification(
            &record.instance,
            &record.reference,
            &verdict.tier,
            &verdict.action,
            verdict.rule.as_deref(),
            &ruleset.version,
        ) {
            report.classified += 1;
        }
        if verdict.tier == "human" {
            // Escalate in place (step 4): the reason, the
            // question, and the fingerprint of the snapshot this
            // verdict was raised on, so the next run can tell a
            // changed item from an unchanged one.
            let fingerprint =
                classification_fingerprint(&ruleset.version, &snapshot, &record.binding);
            queue.escalate(
                &record.instance,
                &record.reference,
                &verdict.reason,
                verdict.question.as_deref(),
                &fingerprint,
            );
        }
    }
    queue.save(dry_run)?;
    Ok(report)
}

/// The fingerprint of the snapshot a verdict was raised on: the
/// ruleset version, the snapshot with its read time blanked (the
/// read time changes on every run and is not server state), and
/// the binding. Two runs over unchanged server state produce the
/// same fingerprint; any server change — or a new ruleset
/// version — produces a different one. Step 4 parks escalated
/// records on it; steps 5-6 use it to tell a changed item (act
/// again) from an unchanged one (skip).
pub fn classification_fingerprint(
    ruleset_version: &str,
    snapshot: &SignalSnapshot,
    binding: &Option<ReviewBinding>,
) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut snapshot = snapshot.clone();
    snapshot.read_at = String::new();
    // The snapshot and binding are freshcrab's own serialization,
    // so this cannot fail in practice; a failure hashes the empty
    // string instead of refusing the run.
    let text = serde_json::to_string(&(ruleset_version, snapshot, binding)).unwrap_or_default();
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// One human-tier item in the run report (step 4): the ref, the
/// tier, the signal snapshot, the ruleset version, and the exact
/// question for the human.
#[derive(Debug, Clone, PartialEq)]
pub struct HumanHandoffItem {
    pub instance: String,
    pub reference: String,
    pub tier: String,
    pub ruleset_version: Option<String>,
    pub signal_snapshot: Option<serde_json::Value>,
    pub question: String,
}

/// The human-tier items in the queue file at `queue_path` (step
/// 4): every escalated record, with its snapshot and question.
/// The report is the handoff; the human acts through the geectl
/// `pull-request` CLI or the web UI.
pub fn human_handoff_report(queue_path: &str) -> Result<Vec<HumanHandoffItem>, ReviewQueueError> {
    let queue = ReviewQueue::open(queue_path)?;
    Ok(queue
        .entries()
        .iter()
        .filter(|r| r.status == "escalated")
        .map(|r| HumanHandoffItem {
            instance: r.instance.clone(),
            reference: r.reference.clone(),
            tier: r.tier.clone(),
            ruleset_version: r.ruleset_version.clone(),
            signal_snapshot: r.signal_snapshot.clone(),
            question: r
                .escalation_question
                .clone()
                .or_else(|| r.escalation_reason.clone())
                .unwrap_or_else(|| "No ruleset rule covers this item.".to_string()),
        })
        .collect())
}

/// A review-queue action stage (steps 5-7): comment-only, then
/// request-changes, then trivial-fix accept. Each stage starts
/// only on an explicit go-ahead, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewStage {
    Comment,
    RequestChanges,
    Accept,
}

impl ReviewStage {
    /// The stage's name, as the config key spells it.
    pub fn name(&self) -> &'static str {
        match self {
            ReviewStage::Comment => "comment",
            ReviewStage::RequestChanges => "request-changes",
            ReviewStage::Accept => "accept",
        }
    }
}

/// True when a review stage is ready to run: its config flag is
/// on, and the stage before it is on too (stages start in order:
/// comment, then request-changes, then accept). Off is the
/// normal state, not an error: it returns `Ok(false)` and the
/// caller runs nothing. A later stage on while an earlier one is
/// off is a misconfiguration: it refuses the run with an error.
/// The kill switch is the caller's gate (main returns before the
/// stages); the stage flags are the per-stage go-ahead.
pub fn review_stage_ready(config: &Config, stage: ReviewStage) -> Result<bool, ReviewQueueError> {
    let (on, earlier_on, earlier) = match stage {
        ReviewStage::Comment => (config.review_comment_stage, true, ""),
        ReviewStage::RequestChanges => (
            config.review_request_changes_stage,
            config.review_comment_stage,
            "comment",
        ),
        ReviewStage::Accept => (
            config.review_accept_stage,
            config.review_request_changes_stage,
            "request-changes",
        ),
    };
    if !on {
        return Ok(false);
    }
    if !earlier_on {
        return Err(ReviewQueueError(format!(
            "review {} stage is on but the {earlier} stage is off: stages start in order (comment, then request-changes, then accept); switch the {earlier} stage on first",
            stage.name()
        )));
    }
    Ok(true)
}

/// The triage comment body for one snapshot (step 5): the tier,
/// the matching rule, the finding, and one line per signal. The
/// body never carries the ruleset version, and it quotes no
/// submission text — the signals are summarized, never pasted —
/// so no quoted line can start with an approval trigger;
/// `check_comment_body` still verifies the composed lines before
/// posting.
pub fn triage_comment_body(snapshot: &SignalSnapshot, verdict: &Classification) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "freshcrab triage: {} — {}: {}",
        verdict.tier,
        verdict.rule.as_deref().unwrap_or("unclassified"),
        verdict.reason
    ));
    lines.push(format!(
        "build: {} (target: {})",
        snapshot.build.status, snapshot.build.target_status
    ));
    lines.push(format!("review: {}", snapshot.review.state));
    let diff = if snapshot.diff.version_bump_only {
        "version bump only".to_string()
    } else if snapshot.diff.spec_changed {
        format!("spec changed, {} file(s)", snapshot.diff.files.len())
    } else {
        format!("{} file(s)", snapshot.diff.files.len())
    };
    let changelog = if snapshot.diff.changelog_changed {
        ", changelog updated"
    } else {
        ""
    };
    let version = snapshot
        .diff
        .new_version
        .as_deref()
        .map_or_else(String::new, |v| format!(", version {v}"));
    lines.push(format!("diff: {diff}{changelog}{version}"));
    let author = match (
        snapshot.author.is_own_filing,
        snapshot.author.is_package_maintainer,
    ) {
        (Some(true), _) => format!("{} (freshcrab's own filing)", snapshot.author.author),
        (_, Some(true)) => format!("{} (package maintainer)", snapshot.author.author),
        _ => snapshot.author.author.clone(),
    };
    lines.push(format!("author: {author}"));
    let package = if snapshot.package.is_security == Some(true) {
        format!("{} (security update)", snapshot.package.package)
    } else if snapshot.package.is_excluded == Some(true) {
        format!("{} (excluded)", snapshot.package.package)
    } else {
        snapshot.package.package.clone()
    };
    lines.push(format!("package: {package}"));
    let server = if snapshot.server.draft {
        "draft".to_string()
    } else {
        snapshot.server.status.clone()
    };
    lines.push(format!("server: {server}"));
    lines.join("\n")
}

/// Refuse a comment body carrying a line that would read as an
/// approval on the server: a line starting with `merge ok` or
/// `@group : approve` (case-insensitive, after leading
/// whitespace — the server may trim the line before matching).
/// The check runs before posting, on the composed body.
pub fn check_comment_body(body: &str) -> Result<(), ReviewQueueError> {
    for line in body.lines() {
        let trimmed = line.trim_start().to_lowercase();
        if trimmed.starts_with("merge ok") || trimmed.starts_with("@group : approve") {
            return Err(ReviewQueueError(format!(
                "refusing to post a comment carrying a line starting with {line:?}: it would read as an approval"
            )));
        }
    }
    Ok(())
}

/// The outcome of a comment run across all instances.
#[derive(Debug, Default)]
pub struct CommentReport {
    pub instances: Vec<CommentInstanceReport>,
    pub unscannable: Vec<(String, String)>,
    /// Comments posted.
    pub posted: usize,
    /// Items whose comment was already recorded for the current
    /// fingerprint: skipped, never double-posted.
    pub skipped_unchanged: usize,
    /// Items whose comment was already on the server: adopted
    /// into the action history, not posted again.
    pub skipped_adopted: usize,
    /// Items that would post in dry-run: planned, nothing written.
    pub planned: usize,
    /// Items skipped for another reason (not actionable, a stale
    /// verdict, a body the guard refused, a failed server read):
    /// counted, never posted.
    pub skipped: usize,
    /// Items whose post failed.
    pub failed: usize,
}

/// The outcome of commenting on one instance on one backend.
#[derive(Debug, Default)]
pub struct CommentInstanceReport {
    pub alias: String,
    pub url: String,
    pub backend: String,
    pub posted: usize,
    pub skipped_unchanged: usize,
    pub skipped_adopted: usize,
    pub planned: usize,
    /// Items skipped for another reason (not actionable, a stale
    /// verdict, a body the guard refused, a failed server read):
    /// counted, never posted.
    pub skipped_other: usize,
    pub failed: usize,
    /// The comment run itself failed (no records commented on
    /// this arm).
    pub error: Option<String>,
    /// The arm was skipped before any comment ran (a misconfigured
    /// credential set).
    pub skipped: bool,
}

impl ArmReport for CommentInstanceReport {
    fn failed(alias: String, url: String, backend: String, error: String, skipped: bool) -> Self {
        CommentInstanceReport {
            alias,
            url,
            backend,
            error: Some(error),
            skipped,
            ..CommentInstanceReport::default()
        }
    }

    fn set_url(&mut self, url: String) {
        self.url = url;
    }
}

impl ArmSummary<CommentInstanceReport> for CommentReport {
    fn set_unscannable(&mut self, unscannable: Vec<(String, String)>) {
        self.unscannable = unscannable;
    }

    fn push_instance(&mut self, report: CommentInstanceReport) {
        self.instances.push(report);
    }

    fn accumulate(&mut self, report: &CommentInstanceReport) {
        self.posted += report.posted;
        self.skipped_unchanged += report.skipped_unchanged;
        self.skipped_adopted += report.skipped_adopted;
        self.planned += report.planned;
        self.skipped += report.skipped_other;
        self.failed += report.failed;
    }
}

/// Post triage comments (step 5, comment-only stage): records
/// whose decided action is `comment`, on every scannable
/// instance arm, through geectl's `PullRequestClient::comment`.
/// No review-state changes. The stage must be ready
/// (`review_stage_ready`): off runs nothing, a misordered stage
/// refuses the run. A ruleset that fails to load refuses the run.
/// In dry-run the run prints what it would do and writes nothing
/// (no posts, no state file). A failure on one arm is recorded on
/// that arm and the run continues with the rest; a failure to
/// enumerate instances or to open/save the queue is returned to
/// the caller.
pub fn post_comments(
    config: &Config,
    own_sr_ids: &[u64],
    http: &dyn geectl::http::HttpClient,
    path: &str,
    ruleset_path: &str,
    dry_run: &DryRun,
) -> Result<CommentReport, ReviewQueueError> {
    if !review_stage_ready(config, ReviewStage::Comment)? {
        return Ok(CommentReport::default());
    }
    let ruleset = Ruleset::load(ruleset_path)?;
    let mut queue = ReviewQueue::open(path)?;
    let scan = enumerate_instances()
        .map_err(|e| ReviewQueueError(format!("cannot enumerate geectl instances: {e}")))?;
    post_comments_with_scan(
        config, own_sr_ids, http, &mut queue, dry_run, scan, &ruleset,
    )
}

/// Run the comment stage over an already-enumerated scan, so
/// tests drive the per-arm report construction without touching
/// the real geectl config or environment.
fn post_comments_with_scan(
    config: &Config,
    own_sr_ids: &[u64],
    http: &dyn geectl::http::HttpClient,
    queue: &mut ReviewQueue,
    dry_run: &DryRun,
    scan: InstanceScan,
    ruleset: &Ruleset,
) -> Result<CommentReport, ReviewQueueError> {
    run_arms(
        http,
        scan,
        config,
        own_sr_ids,
        queue,
        dry_run,
        |source, backend, alias, _config, _own_sr_ids, queue, dry_run| {
            comment_on(source, backend, alias, queue, dry_run, ruleset)
        },
    )
}

/// Post triage comments for the records on one instance arm whose
/// decided action is `comment`. Each record's verdict is
/// re-derived from its snapshot and the ruleset: a record whose
/// stored verdict no longer matches the re-derived one is stale
/// (the ruleset changed since classification) and is skipped,
/// never acted on. A re-run acts only on change: a comment
/// already recorded for the current fingerprint is skipped, and
/// a comment already on the server is adopted into the action
/// history instead of posted again. A failed server read fails
/// closed: the item is skipped, never posted blind.
pub fn comment_on(
    source: &dyn PullRequestSource,
    backend: PullRequestBackend,
    instance_alias: &str,
    queue: &mut ReviewQueue,
    dry_run: &DryRun,
    ruleset: &Ruleset,
) -> CommentInstanceReport {
    let mut report = CommentInstanceReport {
        alias: instance_alias.to_string(),
        backend: backend.as_str().to_string(),
        ..CommentInstanceReport::default()
    };
    let geectl_dry = geectl::obs::DryRun::new(dry_run.enabled());
    let targets: Vec<ReviewRecord> = queue
        .entries()
        .iter()
        .filter(|r| {
            r.instance == instance_alias
                && r.backend == backend.as_str()
                && r.status != "terminal"
                && r.status != "escalated"
                && r.action.as_deref() == Some("comment")
        })
        .cloned()
        .collect();
    for record in &targets {
        let Some(stored) = &record.signal_snapshot else {
            report.skipped_other += 1;
            continue;
        };
        let snapshot: SignalSnapshot = match serde_json::from_value(stored.clone()) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                eprintln!(
                    "warning: cannot parse stored signal snapshot for {} on {instance_alias}: {e}; skipping",
                    record.reference
                );
                report.skipped_other += 1;
                continue;
            }
        };
        let reference: PullRequestRef = match record.reference.parse() {
            Ok(reference) => reference,
            Err(e) => {
                eprintln!(
                    "warning: cannot parse stored review ref {:?} on {instance_alias}: {e}; skipping",
                    record.reference
                );
                report.skipped_other += 1;
                continue;
            }
        };
        // Re-derive the verdict: the stored one may be stale.
        let verdict = classify(ruleset, &snapshot);
        if verdict.action != "comment"
            || verdict.tier != record.tier
            || verdict.rule.as_deref() != record.matched_rule.as_deref()
        {
            eprintln!(
                "warning: stored verdict for {} on {instance_alias} no longer matches the ruleset; skipping",
                record.reference
            );
            report.skipped_other += 1;
            continue;
        }
        let body = triage_comment_body(&snapshot, &verdict);
        if let Err(e) = check_comment_body(&body) {
            eprintln!(
                "warning: refusing to comment on {} on {instance_alias}: {e}",
                record.reference
            );
            report.skipped_other += 1;
            continue;
        }
        let fingerprint = classification_fingerprint(&ruleset.version, &snapshot, &record.binding);
        if queue.action_recorded(instance_alias, &record.reference, "comment", &fingerprint) {
            report.skipped_unchanged += 1;
            continue;
        }
        let server_comments = match source.comments(&reference) {
            Ok(comments) => comments,
            Err(e) => {
                eprintln!(
                    "warning: cannot list comments on {} on {instance_alias}: {e}; skipping (never post blind)",
                    record.reference
                );
                report.skipped_other += 1;
                continue;
            }
        };
        if let Some(existing) = server_comments.iter().find(|c| c.body == body) {
            // Already on the server: adopt it into the action
            // history with its server-side id, never post again.
            queue.record_action(
                instance_alias,
                &record.reference,
                "comment",
                &existing.id.to_string(),
                &fingerprint,
            );
            report.skipped_adopted += 1;
            continue;
        }
        if !dry_run.allow(&format!(
            "comment on {} on {instance_alias}",
            record.reference
        )) {
            report.planned += 1;
            continue;
        }
        match source.comment(&reference, &body, &geectl_dry) {
            Ok(Some(comment)) => {
                queue.record_action(
                    instance_alias,
                    &record.reference,
                    "comment",
                    &comment.id.to_string(),
                    &fingerprint,
                );
                report.posted += 1;
            }
            Ok(None) => {
                eprintln!(
                    "warning: comment on {} on {instance_alias} returned no comment in live mode; skipping",
                    record.reference
                );
                report.failed += 1;
            }
            Err(e) => {
                eprintln!(
                    "warning: cannot comment on {} on {instance_alias}: {e}",
                    record.reference
                );
                report.failed += 1;
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::{QueueEntry, UpdateKind};
    use crate::target::Target;
    use geectl::obs::{BuildResult, PackageBuildStatus};
    use geectl::pull_request::{PullRequestEndpoint, ReviewOpinion};
    use std::env;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_path(suffix: &str) -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!(
            "{}/freshcrab-test-review-{}-{}-{n}-{nanos}.json",
            env::temp_dir().display(),
            std::process::id(),
            suffix
        )
    }

    fn live() -> DryRun {
        DryRun::new(false)
    }

    fn dry() -> DryRun {
        DryRun::new(true)
    }

    fn test_config() -> Config {
        Config {
            packages: Vec::new(),
            exclusions: vec!["gcc".to_string(), "kernel".to_string()],
            ..Config::default()
        }
    }

    fn summary(
        reference: PullRequestRef,
        title: &str,
        target_repository: &str,
    ) -> PullRequestSummary {
        PullRequestSummary {
            reference,
            title: title.to_string(),
            author: "someone".to_string(),
            status: PullRequestStatus::Open,
            source: PullRequestEndpoint {
                repository: "home:alice/foo".to_string(),
                ..PullRequestEndpoint::default()
            },
            target: PullRequestEndpoint {
                repository: target_repository.to_string(),
                ..PullRequestEndpoint::default()
            },
        }
    }

    fn fake_pr(
        reference: PullRequestRef,
        status: PullRequestStatus,
        target_repository: &str,
        target_branch: Option<&str>,
    ) -> PullRequest {
        PullRequest {
            reference,
            title: "bump foo".to_string(),
            description: String::new(),
            author: "someone".to_string(),
            status,
            draft: false,
            merged: status == PullRequestStatus::Merged,
            mergeable: None,
            merge_base: None,
            source: PullRequestEndpoint {
                repository: "home:alice/foo".to_string(),
                commit: Some("srcmd5".to_string()),
                ..PullRequestEndpoint::default()
            },
            target: PullRequestEndpoint {
                repository: target_repository.to_string(),
                branch: target_branch.map(str::to_string),
                commit: Some("targetmd5".to_string()),
            },
            reviews: Vec::new(),
            reviews_error: None,
            labels: Vec::new(),
        }
    }

    /// A fake pull-request source: canned search results and canned
    /// show, diff, build, and maintainer answers (an error is canned
    /// by listing the ref in the matching answers with its kind),
    /// plus a recording comment store for the act methods (step 5):
    /// posted comments land in `posted_comments` with fresh ids,
    /// and `comments_answers` seeds the server-side comments a
    /// `comments` read returns.
    struct FakeSource {
        search_results: Vec<PullRequestSummary>,
        search_error: Option<GeectlError>,
        show_answers: Vec<(String, Result<PullRequest, GeectlError>)>,
        diff_answers: Vec<(String, Result<String, GeectlError>)>,
        build_answers: Vec<(String, Result<BuildResults, GeectlError>)>,
        maintainers_answers: Vec<(String, Result<Vec<NamedRole>, GeectlError>)>,
        comments_answers: Vec<(String, Vec<ReviewComment>)>,
        posted_comments: std::cell::RefCell<Vec<(String, ReviewComment)>>,
        next_comment_id: std::cell::Cell<u64>,
    }

    impl FakeSource {
        fn new(search_results: Vec<PullRequestSummary>) -> Self {
            FakeSource {
                search_results,
                search_error: None,
                show_answers: Vec::new(),
                diff_answers: Vec::new(),
                build_answers: Vec::new(),
                maintainers_answers: Vec::new(),
                comments_answers: Vec::new(),
                posted_comments: std::cell::RefCell::new(Vec::new()),
                next_comment_id: std::cell::Cell::new(0),
            }
        }

        fn with_show(mut self, reference: &str, answer: Result<PullRequest, GeectlError>) -> Self {
            self.show_answers.push((reference.to_string(), answer));
            self
        }

        fn with_diff(mut self, reference: &str, answer: Result<String, GeectlError>) -> Self {
            self.diff_answers.push((reference.to_string(), answer));
            self
        }

        fn with_build(
            mut self,
            project: &str,
            package: &str,
            answer: Result<BuildResults, GeectlError>,
        ) -> Self {
            self.build_answers
                .push((format!("{project}/{package}"), answer));
            self
        }

        fn with_maintainers(
            mut self,
            project: &str,
            package: &str,
            answer: Result<Vec<NamedRole>, GeectlError>,
        ) -> Self {
            self.maintainers_answers
                .push((format!("{project}/{package}"), answer));
            self
        }

        fn with_comments(mut self, reference: &str, comments: Vec<ReviewComment>) -> Self {
            self.comments_answers
                .push((reference.to_string(), comments));
            self
        }

        /// The comments this fake posted, as (ref, comment) pairs,
        /// in posting order.
        fn posted(&self) -> Vec<(String, ReviewComment)> {
            self.posted_comments.borrow().clone()
        }
    }

    impl PullRequestSource for FakeSource {
        fn search(
            &self,
            _query: &PullRequestSearch,
        ) -> Result<Vec<PullRequestSummary>, GeectlError> {
            match &self.search_error {
                Some(e) => Err(GeectlError::new(e.kind(), e.to_string())),
                None => Ok(self.search_results.clone()),
            }
        }

        fn show(&self, reference: &PullRequestRef) -> Result<PullRequest, GeectlError> {
            let key = reference.to_string();
            for (stored, answer) in &self.show_answers {
                if *stored == key {
                    return match answer {
                        Ok(pr) => Ok(pr.clone()),
                        Err(e) => Err(GeectlError::new(e.kind(), e.to_string())),
                    };
                }
            }
            Err(GeectlError::new(
                ErrorKind::NotFound,
                format!("fake source has no show answer for {key}"),
            ))
        }

        fn diff(&self, reference: &PullRequestRef) -> Result<String, GeectlError> {
            let key = reference.to_string();
            for (stored, answer) in &self.diff_answers {
                if *stored == key {
                    return match answer {
                        Ok(text) => Ok(text.clone()),
                        Err(e) => Err(GeectlError::new(e.kind(), e.to_string())),
                    };
                }
            }
            Err(GeectlError::new(
                ErrorKind::NotFound,
                format!("fake source has no diff answer for {key}"),
            ))
        }

        fn build_results(&self, project: &str, package: &str) -> Result<BuildResults, GeectlError> {
            let key = format!("{project}/{package}");
            for (stored, answer) in &self.build_answers {
                if *stored == key {
                    return match answer {
                        Ok(matrix) => Ok(matrix.clone()),
                        Err(e) => Err(GeectlError::new(e.kind(), e.to_string())),
                    };
                }
            }
            Err(GeectlError::new(
                ErrorKind::NotFound,
                format!("fake source has no build answer for {key}"),
            ))
        }

        fn maintainers(&self, project: &str, package: &str) -> Result<Vec<NamedRole>, GeectlError> {
            let key = format!("{project}/{package}");
            for (stored, answer) in &self.maintainers_answers {
                if *stored == key {
                    return match answer {
                        Ok(maintainers) => Ok(maintainers.clone()),
                        Err(e) => Err(GeectlError::new(e.kind(), e.to_string())),
                    };
                }
            }
            Err(GeectlError::new(
                ErrorKind::NotFound,
                format!("fake source has no maintainers answer for {key}"),
            ))
        }

        fn comment(
            &self,
            reference: &PullRequestRef,
            body: &str,
            dry_run: &geectl::obs::DryRun,
        ) -> Result<Option<ReviewComment>, GeectlError> {
            if dry_run.enabled() {
                return Ok(None);
            }
            let id = self.next_comment_id.get() + 1;
            self.next_comment_id.set(id);
            let comment = ReviewComment {
                id,
                author: "freshcrab".to_string(),
                created: "0".to_string(),
                body: body.to_string(),
                parent_id: None,
                diff_target: None,
                diff_file: None,
                diff_line: None,
            };
            self.posted_comments
                .borrow_mut()
                .push((reference.to_string(), comment.clone()));
            Ok(Some(comment))
        }

        fn comments(&self, reference: &PullRequestRef) -> Result<Vec<ReviewComment>, GeectlError> {
            let key = reference.to_string();
            let mut comments: Vec<ReviewComment> = self
                .comments_answers
                .iter()
                .find(|(stored, _)| *stored == key)
                .map(|(_, comments)| comments.clone())
                .unwrap_or_default();
            comments.extend(
                self.posted_comments
                    .borrow()
                    .iter()
                    .filter(|(stored, _)| *stored == key)
                    .map(|(_, comment)| comment.clone()),
            );
            Ok(comments)
        }
    }

    fn err(kind: ErrorKind, message: &str) -> GeectlError {
        GeectlError::new(kind, message.to_string())
    }

    #[test]
    fn record_serde_roundtrip() {
        let record = ReviewRecord::new(
            "obs:123",
            "api_opensuse_org",
            "obs",
            "bump foo",
            "someone",
            Some(ReviewBinding {
                source_repository: "home:alice/foo".to_string(),
                source_commit: Some("srcmd5".to_string()),
                target_repository: "devel:foo/foo".to_string(),
                target_commit: Some("targetmd5".to_string()),
            }),
        );
        let json = serde_json::to_string(&record).unwrap();
        let back: ReviewRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn record_loads_without_newer_fields() {
        // A record written before the grace periods, binding, and
        // tier fields existed loads with the defaults.
        let old = r#"{
            "reference": "obs:123", "instance": "default",
            "status": "open", "created_at": "1", "updated_at": "1"
        }"#;
        let record: ReviewRecord = serde_json::from_str(old).unwrap();
        assert_eq!(record.backend, "");
        assert_eq!(record.tier, "");
        assert_eq!(record.grace_periods.package_maintainer_days, 7);
        assert_eq!(record.grace_periods.project_maintainer_days, 3);
        assert_eq!(record.grace_periods.factory_maintainer_days, 1);
        assert!(record.binding.is_none());
        assert!(record.action_history.is_empty());
    }

    #[test]
    fn grace_periods_are_the_decided_values() {
        let periods = GracePeriods::default();
        assert_eq!(periods.package_maintainer_days, 7);
        assert_eq!(periods.project_maintainer_days, 3);
        assert_eq!(periods.factory_maintainer_days, 1);
    }

    #[test]
    fn queue_save_and_load_roundtrip() {
        let path = tmp_path("roundtrip");
        let live_run = live();
        {
            let mut q = ReviewQueue::open(&path).unwrap();
            q.upsert(ReviewRecord::new(
                "obs:123", "default", "obs", "bump foo", "someone", None,
            ));
            q.save(&live_run).unwrap();
        }
        let q = ReviewQueue::open(&path).unwrap();
        assert_eq!(q.entries().len(), 1);
        assert_eq!(q.entries()[0].reference, "obs:123");
        assert_eq!(q.entries()[0].status, "open");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn queue_load_compacts_duplicates_by_instance_and_ref() {
        let path = tmp_path("compact");
        let old = ReviewRecord {
            reference: "obs:123".to_string(),
            instance: "default".to_string(),
            status: "open".to_string(),
            created_at: "1".to_string(),
            updated_at: "1".to_string(),
            ..ReviewRecord::new("obs:123", "default", "obs", "old", "someone", None)
        };
        let new = ReviewRecord {
            title: "new".to_string(),
            updated_at: "2".to_string(),
            ..old.clone()
        };
        // The same ref on another instance is a different record.
        let other = ReviewRecord::new("obs:123", "staging", "obs", "other", "someone", None);
        let text = serde_json::to_string_pretty(&vec![old, new, other]).unwrap();
        fs::write(&path, format!("{text}\n")).unwrap();
        let q = ReviewQueue::open(&path).unwrap();
        assert_eq!(q.entries().len(), 2);
        let kept = q.find("default", "obs:123").unwrap();
        assert_eq!(kept.title, "new");
        assert!(q.find("staging", "obs:123").is_some());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn queue_second_open_fails_while_first_is_held() {
        let path = tmp_path("lock");
        let _first = ReviewQueue::open(&path).unwrap();
        assert!(ReviewQueue::open(&path).is_err());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn queue_save_in_dry_run_writes_nothing() {
        let path = tmp_path("dryrun");
        let dry_run = dry();
        let mut q = ReviewQueue::open(&path).unwrap();
        q.upsert(ReviewRecord::new(
            "obs:123", "default", "obs", "bump foo", "someone", None,
        ));
        q.save(&dry_run).unwrap();
        assert!(!Path::new(&path).exists());
        assert!(!dry_run.plan().is_empty());
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn upsert_keeps_triage_status_and_reopens_terminal() {
        let path = tmp_path("upsert");
        let mut q = ReviewQueue::open(&path).unwrap();
        // A record inserted already triaged keeps its status.
        let mut record = ReviewRecord::new("obs:123", "default", "obs", "t", "a", None);
        record.status = "triaged".to_string();
        assert!(q.upsert(record));
        assert_eq!(q.find("default", "obs:123").unwrap().status, "triaged");
        // Discovery refreshes with "open": the triaged status stands.
        let fresh = ReviewRecord::new("obs:123", "default", "obs", "t2", "a", None);
        assert!(!q.upsert(fresh));
        assert_eq!(q.find("default", "obs:123").unwrap().status, "triaged");
        assert_eq!(q.find("default", "obs:123").unwrap().title, "t2");
        // A terminal record whose ref is open again returns to open.
        let mut terminal = ReviewRecord::new("obs:123", "default", "obs", "t3", "a", None);
        terminal.status = "terminal".to_string();
        q.upsert(terminal);
        assert_eq!(q.find("default", "obs:123").unwrap().status, "terminal");
        let reopened = ReviewRecord::new("obs:123", "default", "obs", "t4", "a", None);
        q.upsert(reopened);
        assert_eq!(q.find("default", "obs:123").unwrap().status, "open");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn target_package_parsing() {
        assert_eq!(target_package("devel:foo/foo"), Some("foo"));
        assert_eq!(target_package("openSUSE:Factory"), None);
        assert_eq!(target_package("owner/repo"), Some("repo"));
        assert_eq!(target_package(""), None);
        assert_eq!(target_package("a:b:c/pkg"), Some("pkg"));
    }

    #[test]
    fn maintenance_and_pool_exclusions() {
        assert!(is_maintenance_target("openSUSE:Maintenance:1234/foo"));
        assert!(is_maintenance_target("openSUSE:Leap:15.6:Update/foo"));
        assert!(!is_maintenance_target("devel:foo/foo"));
        // A segment that merely starts with Update/Maintenance is
        // not a maintenance request.
        assert!(!is_maintenance_target("home:alice:UpdateTools/foo"));
        assert!(!is_maintenance_target("home:alice:MaintenanceHelper/foo"));
        assert!(is_pool_target(&Some("pool/foo".to_string())));
        assert!(!is_pool_target(&Some("factory".to_string())));
        assert!(!is_pool_target(&None));
    }

    #[test]
    fn own_sr_ids_parse() {
        let entries = vec![
            QueueEntry::new(
                "foo",
                "1.0",
                "2.0",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            )
            .with_sr_id("123"),
            QueueEntry::new(
                "bar",
                "1.0",
                "2.0",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
        ];
        assert_eq!(own_sr_ids(&entries), vec![123]);
    }

    // QueueEntry has no with_sr_id helper; set the field directly.
    trait WithSrId {
        fn with_sr_id(self, sr_id: &str) -> Self;
    }

    impl WithSrId for QueueEntry {
        fn with_sr_id(mut self, sr_id: &str) -> Self {
            self.sr_id = Some(sr_id.to_string());
            self
        }
    }

    #[test]
    fn enumerate_defaults_only_when_no_aliases() {
        let file_config = geectl_config::Config::default();
        // The fakes model the real resolvers: credentials resolve
        // only for their own default URL, and the OBS resolver
        // errors with the never-forwarded refusal on the other
        // backend's URL when plain credentials exist (the real
        // resolvers never forward plain credentials to a
        // non-default, non-alias URL).
        let scan = enumerate_instances_with(
            &file_config,
            "https://api.opensuse.org",
            "https://src.opensuse.org",
            &|url| {
                if url == "https://api.opensuse.org" {
                    Ok(Credentials::Basic {
                        username: "u".to_string(),
                        password: "p".to_string(),
                    })
                } else {
                    Err(err(
                        ErrorKind::ConfigError,
                        "no credentials configured for https://src.opensuse.org; the credentials configured for the default instance are never forwarded to another instance",
                    ))
                }
            },
            &|url| {
                if url == "https://src.opensuse.org" {
                    Ok(Credentials::Bearer {
                        token: "t".to_string(),
                    })
                } else {
                    Err(err(
                        ErrorKind::ConfigError,
                        "no credentials configured for https://api.opensuse.org; the credentials configured for the default instance are never forwarded to another instance",
                    ))
                }
            },
        );
        // Each default is one instance carrying only its own
        // backend's credentials.
        assert_eq!(scan.instances.len(), 2);
        assert!(scan.unscannable.is_empty());
        let obs = scan
            .instances
            .iter()
            .find(|i| i.url == "https://api.opensuse.org")
            .unwrap();
        assert!(obs.obs_credentials.is_some());
        assert!(obs.gitea_credentials.is_none());
        assert!(obs.gitea_error.is_none());
        let gitea = scan
            .instances
            .iter()
            .find(|i| i.url == "https://src.opensuse.org")
            .unwrap();
        assert!(gitea.obs_credentials.is_none());
        assert!(gitea.obs_error.is_none());
        assert!(gitea.gitea_credentials.is_some());
    }

    #[test]
    fn enumerate_dedups_alias_matching_a_default() {
        let file_config = geectl_config::Config {
            instances: vec![(
                "api_opensuse_org".to_string(),
                "https://api.opensuse.org".to_string(),
            )],
            ..geectl_config::Config::default()
        };
        let scan = enumerate_instances_with(
            &file_config,
            "https://api.opensuse.org",
            "https://src.opensuse.org",
            &|url| {
                if url == "https://api.opensuse.org" {
                    Ok(Credentials::Basic {
                        username: "u".to_string(),
                        password: "p".to_string(),
                    })
                } else {
                    Ok(Credentials::None)
                }
            },
            &|url| {
                if url == "https://src.opensuse.org" {
                    Ok(Credentials::Bearer {
                        token: "t".to_string(),
                    })
                } else {
                    Ok(Credentials::None)
                }
            },
        );
        // The alias URL and the OBS default are the same instance:
        // the alias wins the dedup, so the record carries its name.
        assert_eq!(scan.instances.len(), 2);
        let obs = scan
            .instances
            .iter()
            .find(|i| i.url == "https://api.opensuse.org")
            .unwrap();
        assert_eq!(obs.alias, "api_opensuse_org");
    }

    #[test]
    fn enumerate_marks_instances_without_credentials_unscannable() {
        let file_config = geectl_config::Config {
            instances: vec![(
                "staging".to_string(),
                "https://api.staging.example.org".to_string(),
            )],
            ..geectl_config::Config::default()
        };
        let scan = enumerate_instances_with(
            &file_config,
            "https://api.opensuse.org",
            "https://src.opensuse.org",
            &|_| Ok(Credentials::None),
            &|_| Ok(Credentials::None),
        );
        assert!(scan.instances.is_empty());
        assert_eq!(scan.unscannable.len(), 3);
        assert!(scan.unscannable.iter().any(|(alias, _)| alias == "staging"));
    }

    #[test]
    fn enumerate_records_a_misconfigured_credential_set() {
        let file_config = geectl_config::Config::default();
        let scan = enumerate_instances_with(
            &file_config,
            "https://api.opensuse.org",
            "https://src.opensuse.org",
            &|url| {
                if url == "https://api.opensuse.org" {
                    Err(err(ErrorKind::ConfigError, "half-configured OBS pair"))
                } else {
                    Ok(Credentials::None)
                }
            },
            &|_| Ok(Credentials::None),
        );
        assert!(scan.instances.is_empty());
        assert_eq!(scan.unscannable.len(), 2);
        let obs = scan
            .unscannable
            .iter()
            .find(|(alias, _)| alias == "default")
            .unwrap();
        assert!(obs.1.contains("half-configured"));
    }

    #[test]
    fn enumerate_records_a_misconfigured_arm_on_a_scannable_instance() {
        let file_config = geectl_config::Config {
            instances: vec![("both".to_string(), "https://both.example.org".to_string())],
            ..geectl_config::Config::default()
        };
        // The instance resolves OBS credentials but its Gitea token
        // is misconfigured: it stays scannable on OBS, and the
        // skipped Gitea arm is named on the instance instead of
        // being silently dropped.
        let scan = enumerate_instances_with(
            &file_config,
            "https://api.opensuse.org",
            "https://src.opensuse.org",
            &|url| {
                if url == "https://both.example.org" {
                    Ok(Credentials::Basic {
                        username: "u".to_string(),
                        password: "p".to_string(),
                    })
                } else {
                    Ok(Credentials::None)
                }
            },
            &|url| {
                if url == "https://both.example.org" {
                    Err(err(
                        ErrorKind::ConfigError,
                        "Gitea token file is unreadable",
                    ))
                } else {
                    Ok(Credentials::None)
                }
            },
        );
        let instance = scan.instances.iter().find(|i| i.alias == "both").unwrap();
        assert!(instance.obs_credentials.is_some());
        assert!(instance.gitea_credentials.is_none());
        assert!(instance.gitea_error.is_some());
        assert!(instance
            .gitea_error
            .as_ref()
            .unwrap()
            .contains("unreadable"));
    }

    #[test]
    fn enumerate_does_not_surface_the_never_forwarded_refusal() {
        let file_config = geectl_config::Config::default();
        // Each resolver refuses the other backend's default URL
        // because the default instance's credentials are never
        // forwarded there. That is expected safety behaviour, not a
        // misconfiguration, so it carries no error on either
        // instance — in both directions.
        let scan = enumerate_instances_with(
            &file_config,
            "https://api.opensuse.org",
            "https://src.opensuse.org",
            &|url| {
                if url == "https://api.opensuse.org" {
                    Ok(Credentials::Basic {
                        username: "u".to_string(),
                        password: "p".to_string(),
                    })
                } else {
                    Err(err(
                        ErrorKind::ConfigError,
                        "no credentials configured for https://src.opensuse.org; the credentials configured for the default instance are never forwarded to another instance",
                    ))
                }
            },
            &|url| {
                if url == "https://src.opensuse.org" {
                    Ok(Credentials::Bearer {
                        token: "t".to_string(),
                    })
                } else {
                    Err(err(
                        ErrorKind::ConfigError,
                        "no credentials configured for https://api.opensuse.org; the credentials configured for the default instance are never forwarded to another instance",
                    ))
                }
            },
        );
        let obs = scan
            .instances
            .iter()
            .find(|i| i.url == "https://api.opensuse.org")
            .unwrap();
        assert!(obs.obs_credentials.is_some());
        assert!(obs.gitea_credentials.is_none());
        assert!(obs.gitea_error.is_none());
        let gitea = scan
            .instances
            .iter()
            .find(|i| i.url == "https://src.opensuse.org")
            .unwrap();
        assert!(gitea.gitea_credentials.is_some());
        assert!(gitea.obs_credentials.is_none());
        assert!(gitea.obs_error.is_none());
    }

    #[test]
    fn enumerate_unscannable_reason_hides_the_never_forwarded_refusal() {
        let file_config = geectl_config::Config::default();
        // Single-backend setup: OBS credentials exist, no Gitea
        // token at all. The Gitea default is unscannable, but its
        // reason must not name the never-forwarded refusal — that
        // is expected safety behaviour, not why it cannot be
        // scanned. The fallback message names the real state.
        let scan = enumerate_instances_with(
            &file_config,
            "https://api.opensuse.org",
            "https://src.opensuse.org",
            &|url| {
                if url == "https://api.opensuse.org" {
                    Ok(Credentials::Basic {
                        username: "u".to_string(),
                        password: "p".to_string(),
                    })
                } else {
                    Err(err(
                        ErrorKind::ConfigError,
                        "no credentials configured for https://src.opensuse.org; the credentials configured for the default instance are never forwarded to another instance",
                    ))
                }
            },
            &|_| Ok(Credentials::None),
        );
        assert_eq!(scan.instances.len(), 1);
        assert_eq!(scan.unscannable.len(), 1);
        let (_, reason) = &scan.unscannable[0];
        assert!(!reason.contains("never forwarded"));
        assert!(reason.contains("no OBS credentials and no Gitea token configured"));
    }

    fn open_queue(path: &str) -> ReviewQueue {
        ReviewQueue::open(path).unwrap()
    }

    #[test]
    fn discover_on_obs_filters_to_watch_scope() {
        let path = tmp_path("obs-scope");
        let mut queue = open_queue(&path);
        let config = test_config();
        let source = FakeSource::new(vec![
            summary(PullRequestRef::Obs(1), "bump foo", "devel:foo/foo"),
            summary(PullRequestRef::Obs(2), "bump gcc", "devel:gcc/gcc"),
            summary(
                PullRequestRef::Obs(3),
                "maintenance",
                "openSUSE:Leap:15.6:Update/foo",
            ),
            summary(PullRequestRef::Obs(4), "no package", "openSUSE:Factory"),
        ]);
        let report = discover_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &config,
            &[],
            &mut queue,
            &dry(),
        );
        assert_eq!(report.searched, 4);
        // Only the watched package is in scope: gcc is excluded,
        // the :Update target is maintenance, the project-only target
        // names no package.
        assert_eq!(report.in_scope, 1);
        assert_eq!(report.new_records, 1);
        assert!(queue.find("default", "obs:1").is_some());
        assert!(queue.find("default", "obs:2").is_none());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn discover_on_obs_keeps_own_filings_by_sr_id() {
        let path = tmp_path("obs-own");
        let mut queue = open_queue(&path);
        let config = test_config();
        let source = FakeSource::new(vec![summary(
            PullRequestRef::Obs(99),
            "our filing",
            "devel:gcc/gcc",
        )]);
        let report = discover_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &config,
            &[99],
            &mut queue,
            &dry(),
        );
        // gcc is excluded, but the request is freshcrab's own filing.
        assert_eq!(report.in_scope, 1);
        assert!(queue.find("default", "obs:99").is_some());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn discover_on_gitea_resolves_targets_with_show() {
        let path = tmp_path("gitea-scope");
        let mut queue = open_queue(&path);
        let config = test_config();
        let source = FakeSource::new(vec![
            summary(
                PullRequestRef::Gitea {
                    owner: "openSUSE".to_string(),
                    repo: "foo".to_string(),
                    number: 7,
                },
                "bump foo",
                "",
            ),
            summary(
                PullRequestRef::Gitea {
                    owner: "openSUSE".to_string(),
                    repo: "bar".to_string(),
                    number: 8,
                },
                "pool work",
                "",
            ),
        ])
        .with_show(
            "gitea:openSUSE/foo#7",
            Ok(fake_pr(
                PullRequestRef::Gitea {
                    owner: "openSUSE".to_string(),
                    repo: "foo".to_string(),
                    number: 7,
                },
                PullRequestStatus::Open,
                "openSUSE/foo",
                Some("factory"),
            )),
        )
        .with_show(
            "gitea:openSUSE/bar#8",
            Ok(fake_pr(
                PullRequestRef::Gitea {
                    owner: "openSUSE".to_string(),
                    repo: "bar".to_string(),
                    number: 8,
                },
                PullRequestStatus::Open,
                "openSUSE/bar",
                Some("pool/foo"),
            )),
        );
        let report = discover_on(
            &source,
            PullRequestBackend::Gitea,
            "default",
            &config,
            &[],
            &mut queue,
            &dry(),
        );
        assert_eq!(report.searched, 2);
        // foo is watched; bar targets a pool/ branch and is excluded.
        assert_eq!(report.in_scope, 1);
        assert!(queue.find("default", "gitea:openSUSE/foo#7").is_some());
        assert!(queue.find("default", "gitea:openSUSE/bar#8").is_none());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn discover_on_gitea_show_failure_is_unresolved_not_queued() {
        let path = tmp_path("gitea-unresolved");
        let mut queue = open_queue(&path);
        let config = test_config();
        let source = FakeSource::new(vec![summary(
            PullRequestRef::Gitea {
                owner: "openSUSE".to_string(),
                repo: "foo".to_string(),
                number: 9,
            },
            "bump foo",
            "",
        )])
        .with_show(
            "gitea:openSUSE/foo#9",
            Err(err(ErrorKind::ServerError, "boom")),
        );
        let report = discover_on(
            &source,
            PullRequestBackend::Gitea,
            "default",
            &config,
            &[],
            &mut queue,
            &dry(),
        );
        assert_eq!(report.unresolved, 1);
        assert_eq!(report.in_scope, 0);
        assert!(queue.find("default", "gitea:openSUSE/foo#9").is_none());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn discover_on_search_failure_records_the_error() {
        let path = tmp_path("search-fail");
        let mut queue = open_queue(&path);
        let config = test_config();
        let mut source = FakeSource::new(vec![]);
        source.search_error = Some(err(ErrorKind::AuthFailed, "bad token"));
        let report = discover_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &config,
            &[],
            &mut queue,
            &dry(),
        );
        assert!(report.error.is_some());
        assert_eq!(report.searched, 0);
        // A genuine search failure is not a skipped arm.
        assert!(!report.skipped);
        assert!(queue.entries().is_empty());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    /// The Gitea arm of discovery searches the instance globally
    /// and must return every open pull request, past geectl's
    /// 500-entry bound (10 pages of 50). Against geectl 0.2.3 the
    /// search fails on page 11 ("the list of pull requests on the
    /// instance has more than 500 entries"); the unbounded read
    /// (geectl #492) returns them all. The search runs through the
    /// real geectl client over a canned HTTP transport — the
    /// transport is the fake, the search code is real — and drives
    /// it with the same query discovery builds (Gitea backend, open
    /// states, no repo scope).
    #[test]
    fn gitea_search_returns_more_than_500_open_pull_requests() {
        // 501 open pull requests: 10 full pages of 50, plus 1 on
        // page 11. Page 11 is the probe: a list of exactly 500
        // answers an empty page 11 and is returned, so the extra
        // item is what makes the bound fail.
        let mut http = crate::http::FakeHttpClient::new();
        for page in 1..=11 {
            let count = if page == 11 { 1 } else { 50 };
            let start = (page - 1) * 50;
            let issues: Vec<String> = (0..count)
                .map(|i| {
                    let number = start + i + 1;
                    format!(
                        r#"{{"number": {number}, "user": {{"login": "someone"}}, "title": "change {number}", "body": "A test PR body.", "labels": [], "state": "open", "pull_request": {{"merged": false, "draft": false}}, "repository": {{"full_name": "openSUSE/factory"}}}}"#
                    )
                })
                .collect();
            http = http.with(
                &format!(
                    "https://src.opensuse.org/api/v1/repos/issues/search?type=pulls&state=open&page={page}&limit=50"
                ),
                &format!("[{}]", issues.join(",")),
            );
        }
        let gitea = GiteaClient::with_base(
            &http,
            "https://src.opensuse.org",
            Credentials::Bearer {
                token: "test-token".to_string(),
            },
        )
        .unwrap();
        let client = PullRequestClient::new(None, Some(&gitea));
        let query = PullRequestSearch {
            backend: Some(PullRequestBackend::Gitea),
            states: vec![PullRequestStatus::Open],
            ..PullRequestSearch::default()
        };
        let summaries = PullRequestSource::search(&client, &query).unwrap();
        assert_eq!(summaries.len(), 501);
        assert_eq!(
            summaries[500].reference.to_string(),
            "gitea:openSUSE/factory#501"
        );
    }

    /// An HTTP client that fails every request. The skipped-arm
    /// test never reaches it (the arm is skipped before any client
    /// is built), so its methods are never called.
    struct FailingHttp;

    impl geectl::http::HttpClient for FailingHttp {
        fn get(&self, _url: &str) -> Result<String, GeectlError> {
            Err(err(ErrorKind::NetworkError, "failing http client"))
        }

        fn get_with(&self, _url: &str, _credentials: &Credentials) -> Result<String, GeectlError> {
            Err(err(ErrorKind::NetworkError, "failing http client"))
        }

        fn post(
            &self,
            _url: &str,
            _body: &str,
            _credentials: &Credentials,
        ) -> Result<String, GeectlError> {
            Err(err(ErrorKind::NetworkError, "failing http client"))
        }

        fn post_json(&self, _url: &str, _body: &str) -> Result<String, GeectlError> {
            Err(err(ErrorKind::NetworkError, "failing http client"))
        }

        fn post_json_with(
            &self,
            _url: &str,
            _body: &str,
            _credentials: &Credentials,
        ) -> Result<String, GeectlError> {
            Err(err(ErrorKind::NetworkError, "failing http client"))
        }

        fn put_json_with(
            &self,
            _url: &str,
            _body: &str,
            _credentials: &Credentials,
        ) -> Result<String, GeectlError> {
            Err(err(ErrorKind::NetworkError, "failing http client"))
        }

        fn patch_json_with(
            &self,
            _url: &str,
            _body: &str,
            _credentials: &Credentials,
        ) -> Result<String, GeectlError> {
            Err(err(ErrorKind::NetworkError, "failing http client"))
        }

        fn post_text(
            &self,
            _url: &str,
            _body: &str,
            _credentials: &Credentials,
        ) -> Result<String, GeectlError> {
            Err(err(ErrorKind::NetworkError, "failing http client"))
        }

        fn put(
            &self,
            _url: &str,
            _body: &str,
            _credentials: &Credentials,
        ) -> Result<String, GeectlError> {
            Err(err(ErrorKind::NetworkError, "failing http client"))
        }

        fn put_file(
            &self,
            _url: &str,
            _body: &str,
            _credentials: &Credentials,
        ) -> Result<String, GeectlError> {
            Err(err(ErrorKind::NetworkError, "failing http client"))
        }

        fn delete(&self, _url: &str, _credentials: &Credentials) -> Result<String, GeectlError> {
            Err(err(ErrorKind::NetworkError, "failing http client"))
        }

        fn delete_json_with(
            &self,
            _url: &str,
            _body: &str,
            _credentials: &Credentials,
        ) -> Result<String, GeectlError> {
            Err(err(ErrorKind::NetworkError, "failing http client"))
        }
    }

    #[test]
    fn discover_marks_a_misconfigured_arm_skipped() {
        let path = tmp_path("discover-skipped");
        let config = test_config();
        let http = FailingHttp;
        let mut queue = open_queue(&path);
        // One instance whose OBS arm is misconfigured (credentials
        // unusable) and whose Gitea arm has nothing at all: the OBS
        // arm is reported skipped, the Gitea arm stays silent, and
        // no search runs.
        let scan = InstanceScan {
            instances: vec![Instance {
                alias: "staging".to_string(),
                url: "https://api.staging.example.org".to_string(),
                obs_credentials: None,
                gitea_credentials: None,
                obs_error: Some("half-configured OBS pair".to_string()),
                gitea_error: None,
            }],
            unscannable: Vec::new(),
        };
        let report = discover_with_scan(&config, &[], &http, &mut queue, &dry(), scan).unwrap();
        assert_eq!(report.instances.len(), 1);
        let arm = &report.instances[0];
        assert_eq!(arm.alias, "staging");
        assert_eq!(arm.backend, "obs");
        assert!(arm.error.is_some());
        assert!(arm.error.as_ref().unwrap().contains("half-configured"));
        assert!(arm.skipped);
        assert_eq!(arm.searched, 0);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn discover_on_recheck_marks_gone_refs_terminal() {
        let path = tmp_path("recheck");
        let mut queue = open_queue(&path);
        let config = test_config();
        // Seed a record whose ref the search will not return.
        queue.upsert(ReviewRecord::new(
            "obs:55", "default", "obs", "old", "someone", None,
        ));
        queue.upsert(ReviewRecord::new(
            "obs:56", "default", "obs", "old", "someone", None,
        ));
        let source = FakeSource::new(vec![]).with_show(
            "obs:55",
            Ok(fake_pr(
                PullRequestRef::Obs(55),
                PullRequestStatus::Merged,
                "devel:foo/foo",
                None,
            )),
        );
        // obs:56 has no show answer: the fake returns NotFound,
        // which also marks it terminal.
        let report = discover_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &config,
            &[],
            &mut queue,
            &dry(),
        );
        assert_eq!(report.terminal_marked, 2);
        assert_eq!(queue.find("default", "obs:55").unwrap().status, "terminal");
        assert_eq!(queue.find("default", "obs:56").unwrap().status, "terminal");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn discover_on_recheck_leaves_records_alone_on_show_error() {
        let path = tmp_path("recheck-error");
        let mut queue = open_queue(&path);
        let config = test_config();
        queue.upsert(ReviewRecord::new(
            "obs:57", "default", "obs", "old", "someone", None,
        ));
        let source =
            FakeSource::new(vec![]).with_show("obs:57", Err(err(ErrorKind::ServerError, "boom")));
        let report = discover_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &config,
            &[],
            &mut queue,
            &dry(),
        );
        assert_eq!(report.terminal_marked, 0);
        assert_eq!(queue.find("default", "obs:57").unwrap().status, "open");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn discover_on_recheck_refreshes_a_still_open_miss() {
        let path = tmp_path("recheck-open");
        let mut queue = open_queue(&path);
        let config = test_config();
        queue.upsert(ReviewRecord::new(
            "obs:58",
            "default",
            "obs",
            "old title",
            "someone",
            None,
        ));
        let source = FakeSource::new(vec![]).with_show(
            "obs:58",
            Ok(fake_pr(
                PullRequestRef::Obs(58),
                PullRequestStatus::Open,
                "devel:foo/foo",
                None,
            )),
        );
        let report = discover_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &config,
            &[],
            &mut queue,
            &dry(),
        );
        assert_eq!(report.terminal_marked, 0);
        let record = queue.find("default", "obs:58").unwrap();
        assert_eq!(record.status, "open");
        assert_eq!(record.title, "bump foo");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn discover_on_recheck_marks_an_out_of_scope_ref_terminal_when_it_merges() {
        let path = tmp_path("recheck-out-of-scope");
        let mut queue = open_queue(&path);
        let config = test_config();
        // The stored title and binding deliberately differ from the
        // shown PR's ("bump foo" / srcmd5), so the test pins that
        // terminal-marking keeps the stored values instead of
        // rewriting them from the shown PR.
        let stored_binding = ReviewBinding {
            source_repository: "home:alice/foo".to_string(),
            source_commit: Some("old-src".to_string()),
            target_repository: "devel:foo/foo".to_string(),
            target_commit: Some("old-target".to_string()),
        };
        queue.upsert(ReviewRecord::new(
            "obs:60",
            "default",
            "obs",
            "original title",
            "someone",
            Some(stored_binding.clone()),
        ));
        // The search still returns the ref, but it now targets an
        // excluded package, so it is out of scope. Its show says
        // merged: the re-check still marks it terminal instead of
        // leaving it open forever.
        let source = FakeSource::new(vec![summary(
            PullRequestRef::Obs(60),
            "bump gcc",
            "devel:gcc/gcc",
        )])
        .with_show(
            "obs:60",
            Ok(fake_pr(
                PullRequestRef::Obs(60),
                PullRequestStatus::Merged,
                "devel:gcc/gcc",
                None,
            )),
        );
        let report = discover_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &config,
            &[],
            &mut queue,
            &dry(),
        );
        assert_eq!(report.terminal_marked, 1);
        let record = queue.find("default", "obs:60").unwrap();
        assert_eq!(record.status, "terminal");
        // Terminal-marking keeps the stored title and binding; only
        // the status changes.
        assert_eq!(record.title, "original title");
        assert_eq!(record.binding, Some(stored_binding));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn discover_on_leaves_a_still_open_out_of_scope_ref_untouched() {
        let path = tmp_path("recheck-out-of-scope-open");
        let mut queue = open_queue(&path);
        let config = test_config();
        queue.upsert(ReviewRecord::new(
            "obs:61",
            "default",
            "obs",
            "old title",
            "someone",
            None,
        ));
        // The search returns the ref out of scope and its show says
        // still open: the record is left untouched — its title and
        // binding are not refreshed, and it is not counted updated.
        let source = FakeSource::new(vec![summary(
            PullRequestRef::Obs(61),
            "bump gcc",
            "devel:gcc/gcc",
        )])
        .with_show(
            "obs:61",
            Ok(fake_pr(
                PullRequestRef::Obs(61),
                PullRequestStatus::Open,
                "devel:gcc/gcc",
                None,
            )),
        );
        let report = discover_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &config,
            &[],
            &mut queue,
            &dry(),
        );
        assert_eq!(report.terminal_marked, 0);
        assert_eq!(report.updated_records, 0);
        let record = queue.find("default", "obs:61").unwrap();
        assert_eq!(record.status, "open");
        assert_eq!(record.title, "old title");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn discover_on_leaves_an_omitted_out_of_scope_ref_untouched() {
        let path = tmp_path("recheck-omitted-out-of-scope");
        let mut queue = open_queue(&path);
        let config = test_config();
        queue.upsert(ReviewRecord::new(
            "obs:62",
            "default",
            "obs",
            "old title",
            "someone",
            None,
        ));
        // The search omits the ref entirely and its show says still
        // open but targeting an excluded package: the record is
        // left untouched, not refreshed as if it were in scope.
        let source = FakeSource::new(vec![]).with_show(
            "obs:62",
            Ok(fake_pr(
                PullRequestRef::Obs(62),
                PullRequestStatus::Open,
                "devel:gcc/gcc",
                None,
            )),
        );
        let report = discover_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &config,
            &[],
            &mut queue,
            &dry(),
        );
        assert_eq!(report.terminal_marked, 0);
        assert_eq!(report.updated_records, 0);
        let record = queue.find("default", "obs:62").unwrap();
        assert_eq!(record.status, "open");
        assert_eq!(record.title, "old title");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    // ---- Step 2: signal readers ----

    fn build_matrix(cells: Vec<(&str, &str, &str)>) -> BuildResults {
        BuildResults {
            state: None,
            results: cells
                .into_iter()
                .map(|(repository, arch, code)| BuildResult {
                    project: "home:alice".to_string(),
                    repository: repository.to_string(),
                    arch: arch.to_string(),
                    code: "published".to_string(),
                    state: "published".to_string(),
                    dirty: false,
                    details: None,
                    statuses: vec![PackageBuildStatus {
                        package: "foo".to_string(),
                        code: code.to_string(),
                        details: None,
                    }],
                })
                .collect(),
        }
    }

    fn signal_record(reference: &str, backend: &str) -> ReviewRecord {
        ReviewRecord::new(reference, "default", backend, "bump foo", "someone", None)
    }

    fn obs_pr_with_reviews(reviews: Vec<ReviewOpinion>) -> PullRequest {
        let mut pr = fake_pr(
            PullRequestRef::Obs(123),
            PullRequestStatus::Open,
            "devel:foo/foo",
            None,
        );
        pr.reviews = reviews;
        pr
    }

    fn review_opinion(reviewer: &str, state: OpinionState) -> ReviewOpinion {
        ReviewOpinion {
            reviewer: reviewer.to_string(),
            state,
            comment: String::new(),
            when: None,
        }
    }

    const BUMP_DIFF: &str = "diff --git a/foo.spec b/foo.spec\nindex 111..222 100644\n--- a/foo.spec\n+++ b/foo.spec\n@@ -1,4 +1,4 @@\n Name:           foo\n-Version:        1.0\n+Version:        1.1\n Release:        0\n %description\n Some text\ndiff --git a/foo.changes b/foo.changes\nindex 333..444 100644\n--- a/foo.changes\n+++ b/foo.changes\n@@ -1,3 +1,6 @@\n+-------------------------------------------------------------------\n+Tue Nov 24 2026 someone@example.com\n+\n+- Update to 1.1\n+\n -------------------------------------------------------------------\n Tue Nov 17 2026 someone@example.com\n";

    const PATCH_DIFF: &str = "diff --git a/foo.spec b/foo.spec\nindex 111..222 100644\n--- a/foo.spec\n+++ b/foo.spec\n@@ -1,5 +1,6 @@\n Name:           foo\n Version:        1.1\n Release:        0\n+Patch0:         fix-thing.patch\n %description\n Some text\ndiff --git a/fix-thing.patch b/fix-thing.patch\nnew file mode 100644\nindex 000..555\n--- /dev/null\n+++ b/fix-thing.patch\n@@ -0,0 +1,3 @@\n+--- a/foo.c\n++++ b/foo.c\n+@@ -1 +1 @@\n";

    const CVE_DIFF: &str = "diff --git a/foo.changes b/foo.changes\nindex 333..444 100644\n--- a/foo.changes\n+++ b/foo.changes\n@@ -1,3 +1,6 @@\n+-------------------------------------------------------------------\n+Tue Nov 24 2026 someone@example.com\n+\n+- Fix CVE-2026-12345: heap overflow\n+\n -------------------------------------------------------------------\n Tue Nov 17 2026 someone@example.com\n";

    // OBS plain-text diff (obs:1379722, trimmed): sectioned, bare
    // `---`/`+++`, no `diff --git`. The tarball change under
    // `other changes:` is not a package file, so README.md is not
    // in `files` and does not break the scope.
    const OBS_MODIFY_DIFF: &str = "changes files:\n--------------\n--- shadowsocks-v2ray-plugin.changes\n+++ shadowsocks-v2ray-plugin.changes\n@@ -1,0 +2,19 @@\n+Fri May 29 13:26:53 UTC 2026 - Hillwood Yang <hillwoodroc@gmail.com>\n+\n+- Update version to 5.49.0\n+  * Update v2ray-core to 5.49.0\n+  * Update vendor (boo#1260328 and CVE-2026-33186)\n+\n+-------------------------------------------------------------------\n+Thu Feb 12 12:51:31 UTC 2026 - Hillwood Yang <hillwood@opensuse.org>\n+\n+- Update version to 5.44.1\n\nold:\n----\n  v2ray-plugin-5.37.0.tar.gz\n\nnew:\n----\n  v2ray-plugin-5.49.0.tar.gz\n\nspec files:\n-----------\n--- shadowsocks-v2ray-plugin.spec\n+++ shadowsocks-v2ray-plugin.spec\n@@ -1,7 +1,7 @@\n #\n # spec file for package shadowsocks-v2ray-plugin\n #\n-# Copyright (c) 2025 SUSE LLC and contributors\n+# Copyright (c) 2026 SUSE LLC and contributors\n #\n # All modifications and additions to the file contributed by third parties\n # remain the property of their copyright owners, unless otherwise agreed\n@@ -27,7 +27,7 @@\n %define   import_path     %{provider_prefix}\n \n Name:           shadowsocks-v2ray-plugin\n-Version:        5.37.0\n+Version:        5.49.0\n Release:        0\n Summary:        SIP003 plugin for shadowsocks\n License:        MIT\n@@ -36,7 +36,9 @@\n Source0:        https://github.com/teddysun/v2ray-plugin/archive/v%{version}/%{repo}-%{version}.tar.gz\n Source1:        vendor.tar.gz\n BuildRequires:  fdupes\n+# BuildRequires:  golang-github-v2fly-v2ray-core >= 5.44.1\n BuildRequires:  golang-packaging\n+BuildRequires:  golang(API) >= 1.25\n AutoReqProv:    Off\n BuildRoot:      %{_tmppath}/%{name}-%{version}-build\n %{go_provides}\n\nother changes:\n--------------\n\n++++++ v2ray-plugin-5.37.0.tar.gz -> v2ray-plugin-5.49.0.tar.gz\n--- README.md\n+++ README.md\n@@ -2,7 +2,7 @@\n \n [![CircleCI](https://circleci.com/gh/shadowsocks/v2ray-plugin.svg?style=shield)](https://circleci.com/gh/shadowsocks/v2ray-plugin)\n [![Releases](https://img.shields.io/github/downloads/shadowsocks/v2ray-plugin/total.svg)](https://github.com/repo/releases)\n-[![Language: Go](https://img.shields.io/badge/go-1.20+-blue.svg)](https://github.com/repo/search?l=go)\n+[![Language: Go](https://img.shields.io/badge/go-1.25+-blue.svg)](https://github.com/repo/search?l=go)\n [![Go Report Card](https://goreportcard.com/badge/github.com/repo/report)](https://goreportcard.com/report/github.com/repo/report)\n\n++++++ vendor.tar.gz\n(207384 lines skipped)\n\nnew:\n----\n  _patchinfo\n\nother changes:\n--------------\n\n++++++ _patchinfo (new)\n--- _patchinfo\n+++ _patchinfo\n@@ -0,0 +1,20 @@\n+<patchinfo incident=\"19707\">\n+  <issue tracker=\"bnc\" id=\"1260328\">VUL-0: CVE-2026-33186: shadowsocks-v2ray-plugin: google.golang.org/grpc: authorization bypass due to improper validation of the HTTP/2 :path pseudo-header</issue>\n+  <issue tracker=\"cve\" id=\"2026-33186\"/>\n+  <packager>hillwood</packager>\n+  <rating>critical</rating>\n+  <category>security</category>\n+  <summary>Security update for shadowsocks-v2ray-plugin</summary>\n+  <description>This update for shadowsocks-v2ray-plugin fixes the following issues:\n+\n+- Update version to 5.49.0\n+  * Update v2ray-core to 5.49.0\n+  * Update vendor (boo#1260328 and CVE-2026-33186)\n+\n+- Update version to 5.44.1\n+  * Update v2ray-core to v5.44.1\n+\n+- Update version to 5.41.0\n+  * Update v2ray-core to v5.41.0\n+</description>\n+</patchinfo>\n";

    // OBS plain-text diff that is a pure version bump: only the
    // spec `Version:` and a new changelog entry.
    const OBS_BUMP_DIFF: &str = "changes files:\n--------------\n--- foo.changes\n+++ foo.changes\n@@ -1,0 +1,5 @@\n+-------------------------------------------------------------------\n+Tue Nov 24 2026 someone@example.com\n+\n+- Update to 1.1\n+\nspec files:\n-----------\n--- foo.spec\n+++ foo.spec\n@@ -1,4 +1,4 @@\n Name:           foo\n-Version:        1.0\n+Version:        1.1\n Release:        0\n";

    // OBS plain-text diff for a new package (obs:1274565, trimmed):
    // `++++++ new ... file:` markers, no `--- /dev/null`.
    const OBS_NEW_DIFF: &str = "changes files:\n--------------\n\n++++++ new changes file:\n--- python-pyproject-examples.changes\n+++ python-pyproject-examples.changes\n@@ -0,0 +1,9 @@\n+-------------------------------------------------------------------\n+Thu Feb 27 10:00:28 UTC 2025 - ecsos <ecsos@opensuse.org>\n+\n+- Add %{?sle15_python_module_pythons}\n+\n+-------------------------------------------------------------------\n+Fri Jul 26 07:14:39 UTC 2024 - Steve Kowalik <steven.kowalik@suse.com>\n+\n+- Initial release of 2023.6.30\n\nnew:\n----\n  pyproject_examples-2023.6.30.tar.gz\n  python-pyproject-examples.changes\n  python-pyproject-examples.spec\n\nspec files:\n-----------\n\n++++++ new spec file:\n--- python-pyproject-examples.spec\n+++ python-pyproject-examples.spec\n@@ -0,0 +1,61 @@\n+#\n+# spec file for package python-pyproject-examples\n+#\n+# Copyright (c) 2024 SUSE LLC\n+#\n+Name:           python-pyproject-examples\n+Version:        2023.6.30\n+Release:        0\n+Summary:        Example pyproject.toml configs for testing\n+License:        MIT\n";

    // OBS `other changes:` markers: a `.gem` is tarball contents
    // to skip; a `.txz` and a bare `.gz` are not in OBS's tardiff
    // list, so they are parsed as package files; a renamed patch
    // is a plain filediff, not a tardiff.
    const OBS_ARCHIVE_MARKERS_DIFF: &str = "other changes:\n--------------\n\n++++++ foo-1.0.gem\n--- data/foo.rb\n+++ data/foo.rb\n@@ -1 +1 @@\n-old\n+new\n\n++++++ bar-1.0.txz\n--- bar-1.0.txz\n+++ bar-1.0.txz\n@@ -1 +1 @@\n-old\n+new\n\n++++++ data.gz\n--- data.gz\n+++ data.gz\n@@ -1 +1 @@\n-old\n+new\n\n++++++ foo-1.0.patch -> foo-2.0.patch\n--- foo-1.0.patch\n+++ foo-2.0.patch\n@@ -1 +1 @@\n-old\n+new\n";

    // A spec-only `%description` bullet edit: not a version bump.
    // The `- ` bullet counts as a changelog line only inside a
    // `%changelog` section.
    const DESCRIPTION_BULLET_DIFF: &str = "diff --git a/foo.spec b/foo.spec\nindex 111..222 100644\n--- a/foo.spec\n+++ b/foo.spec\n@@ -1,4 +1,4 @@\n Name:           foo\n Version:        1.0\n %description\n-- old bullet\n+- new bullet\n";

    // A spec with an inline `%changelog` section: the version bump
    // plus a new changelog entry, in two hunks.
    const SPEC_CHANGELOG_DIFF: &str = "diff --git a/foo.spec b/foo.spec\nindex 111..222 100644\n--- a/foo.spec\n+++ b/foo.spec\n@@ -1,4 +1,4 @@\n Name:           foo\n-Version:        1.0\n+Version:        1.1\n Release:        0\n %description\n Some text\n@@ -10,3 +10,6 @@\n %changelog\n+* Tue Nov 24 2026 someone@example.com\n+\n+- Update to 1.1\n+\n -------------------------------------------------------------------\n Tue Nov 17 2026 someone@example.com\n";

    #[test]
    fn signal_snapshot_serde_roundtrip() {
        let snapshot = SignalSnapshot {
            read_at: "123".to_string(),
            build: BuildSignal {
                status: "all_green".to_string(),
                cells: vec![BuildCell {
                    repository: "openSUSE_Tumbleweed".to_string(),
                    arch: "x86_64".to_string(),
                    code: "succeeded".to_string(),
                }],
                target_status: "all_green".to_string(),
                target_reason: None,
                reason: None,
            },
            review: ReviewSignal {
                state: "approved".to_string(),
                reviews: vec![ReviewEntry {
                    reviewer: "alice".to_string(),
                    state: "approved".to_string(),
                }],
                reason: None,
            },
            diff: DiffSignal {
                files: vec!["foo.spec".to_string()],
                spec_changed: true,
                version_bump_only: true,
                patches_changed: false,
                new_files: Vec::new(),
                changelog_changed: true,
                new_version: Some("1.1".to_string()),
                cve_ids: Vec::new(),
                reason: None,
            },
            author: AuthorSignal {
                author: "someone".to_string(),
                is_own_filing: Some(false),
                is_package_maintainer: None,
                first_time_submitter: None,
            },
            package: PackageSignal {
                package: "foo".to_string(),
                is_excluded: Some(false),
                is_core: None,
                is_security: Some(false),
                cve_ids: Vec::new(),
            },
            server: ServerSignal {
                status: "open".to_string(),
                draft: false,
                mergeable: None,
            },
            read_errors: Vec::new(),
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let back: SignalSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snapshot, back);
    }

    #[test]
    fn signal_snapshot_loads_without_newer_fields() {
        let old = r#"{"read_at": "1"}"#;
        let snapshot: SignalSnapshot = serde_json::from_str(old).unwrap();
        assert_eq!(snapshot.build.status, "unknown");
        assert_eq!(snapshot.review.state, "unknown");
        assert_eq!(snapshot.server.status, "unknown");
        assert!(snapshot.read_errors.is_empty());
    }

    #[test]
    fn signal_snapshot_old_bool_fields_load() {
        // A snapshot written before the signal bools became
        // `Option<bool>` carries plain `false`: it loads as
        // `Some(false)`, and a snapshot without the fields loads
        // them as unknown.
        let old = r#"{
            "read_at": "1",
            "author": {"author": "someone", "is_own_filing": false},
            "package": {"package": "foo", "is_excluded": false, "is_security": false}
        }"#;
        let snapshot: SignalSnapshot = serde_json::from_str(old).unwrap();
        assert_eq!(snapshot.author.is_own_filing, Some(false));
        assert_eq!(snapshot.package.is_excluded, Some(false));
        assert_eq!(snapshot.package.is_security, Some(false));
        assert_eq!(snapshot.author.is_package_maintainer, None);
        assert_eq!(snapshot.package.is_core, None);
    }

    #[test]
    fn review_state_changes_requested_dominates() {
        let pr = obs_pr_with_reviews(vec![
            review_opinion("alice", OpinionState::Approved),
            review_opinion("bob", OpinionState::ChangesRequested),
        ]);
        let signal = review_state(&pr);
        assert_eq!(signal.state, "changes_requested");
        assert_eq!(signal.reviews.len(), 2);
    }

    #[test]
    fn review_state_approved_and_asked_and_none() {
        let approved = obs_pr_with_reviews(vec![review_opinion("alice", OpinionState::Approved)]);
        assert_eq!(review_state(&approved).state, "approved");
        let asked = obs_pr_with_reviews(vec![review_opinion("alice", OpinionState::Asked)]);
        assert_eq!(review_state(&asked).state, "asked_pending");
        let none = obs_pr_with_reviews(vec![]);
        assert_eq!(review_state(&none).state, "none");
    }

    #[test]
    fn review_state_reviews_error_is_unknown() {
        let mut pr = obs_pr_with_reviews(vec![]);
        pr.reviews_error = Some("reviews unavailable".to_string());
        let signal = review_state(&pr);
        assert_eq!(signal.state, "unknown");
        assert!(signal.reason.is_some());
    }

    #[test]
    fn parse_diff_version_bump_only() {
        let diff = parse_diff(BUMP_DIFF);
        assert_eq!(diff.files, vec!["foo.spec", "foo.changes"]);
        assert!(diff.spec_changed);
        assert!(diff.version_bump_only);
        assert!(!diff.patches_changed);
        assert!(diff.new_files.is_empty());
        assert!(diff.changelog_changed);
        assert_eq!(diff.new_version.as_deref(), Some("1.1"));
        assert!(diff.cve_ids.is_empty());
    }

    #[test]
    fn parse_diff_spec_plus_patch_is_not_a_bump() {
        let diff = parse_diff(PATCH_DIFF);
        assert!(diff.spec_changed);
        assert!(!diff.version_bump_only);
        assert!(diff.patches_changed);
        assert_eq!(diff.new_files, vec!["fix-thing.patch"]);
    }

    #[test]
    fn parse_diff_changelog_names_cve() {
        let diff = parse_diff(CVE_DIFF);
        assert!(diff.changelog_changed);
        assert_eq!(diff.cve_ids, vec!["CVE-2026-12345"]);
        assert!(!diff.version_bump_only);
    }

    #[test]
    fn parse_diff_obs_modify_format() {
        let diff = parse_diff(OBS_MODIFY_DIFF);
        assert_eq!(
            diff.files,
            vec![
                "shadowsocks-v2ray-plugin.changes",
                "shadowsocks-v2ray-plugin.spec",
                "_patchinfo",
            ]
        );
        assert!(diff.spec_changed);
        assert!(diff.changelog_changed);
        // The BuildRequires lines and the _patchinfo file make it
        // more than a bump.
        assert!(!diff.version_bump_only);
        assert_eq!(diff.new_version.as_deref(), Some("5.49.0"));
        assert_eq!(diff.cve_ids, vec!["CVE-2026-33186"]);
        // _patchinfo is a real package file under the second
        // `other changes:` section, not tarball contents.
        assert_eq!(diff.new_files, vec!["_patchinfo"]);
    }

    #[test]
    fn parse_diff_obs_bump_only() {
        let diff = parse_diff(OBS_BUMP_DIFF);
        assert_eq!(diff.files, vec!["foo.changes", "foo.spec"]);
        assert!(diff.spec_changed);
        assert!(diff.version_bump_only);
        assert!(diff.changelog_changed);
        assert_eq!(diff.new_version.as_deref(), Some("1.1"));
        assert!(diff.new_files.is_empty());
    }

    #[test]
    fn parse_diff_obs_new_package() {
        let diff = parse_diff(OBS_NEW_DIFF);
        assert_eq!(
            diff.files,
            vec![
                "python-pyproject-examples.changes",
                "python-pyproject-examples.spec",
            ]
        );
        assert_eq!(
            diff.new_files,
            vec![
                "python-pyproject-examples.changes",
                "python-pyproject-examples.spec",
            ]
        );
        assert!(diff.spec_changed);
        assert!(diff.changelog_changed);
        // A new package is not a version bump.
        assert!(!diff.version_bump_only);
        assert_eq!(diff.new_version.as_deref(), Some("2023.6.30"));
    }

    #[test]
    fn parse_diff_obs_archive_markers() {
        let diff = parse_diff(OBS_ARCHIVE_MARKERS_DIFF);
        // The gem's contents are tarball contents: skipped.
        // The .txz, the bare .gz, and the renamed patch are plain
        // filediffs: parsed.
        assert_eq!(
            diff.files,
            vec!["bar-1.0.txz", "data.gz", "foo-1.0.patch", "foo-2.0.patch"]
        );
        assert!(diff.patches_changed);
        assert!(!diff.version_bump_only);
    }

    #[test]
    fn parse_diff_description_bullet_is_not_a_bump() {
        let diff = parse_diff(DESCRIPTION_BULLET_DIFF);
        assert!(diff.spec_changed);
        assert!(!diff.version_bump_only);
    }

    #[test]
    fn parse_diff_spec_changelog_section_is_a_bump() {
        let diff = parse_diff(SPEC_CHANGELOG_DIFF);
        assert!(diff.spec_changed);
        assert!(diff.version_bump_only);
        assert_eq!(diff.new_version.as_deref(), Some("1.1"));
    }

    #[test]
    fn version_line_strips_trailing_comment() {
        assert_eq!(
            version_line("Version:        1.1 # comment").as_deref(),
            Some("1.1")
        );
        assert_eq!(version_line("Version:        1.1").as_deref(), Some("1.1"));
        assert_eq!(version_line("Version:").as_deref(), None);
    }

    #[test]
    fn cve_ids_scan_retries_dash_suffix() {
        assert_eq!(
            cve_ids_in("Fix CVE-2026-12345-fixed and CVE-2026-99999"),
            vec!["CVE-2026-12345", "CVE-2026-99999"]
        );
    }

    #[test]
    fn cve_ids_scan_validates_and_dedups() {
        let found =
            cve_ids_in("Fix CVE-2026-12345 and cve-2026-12345, not CVE-123 or CVE-2026-12.");
        assert_eq!(found, vec!["CVE-2026-12345"]);
    }

    #[test]
    fn build_classify_all_green_any_failed_building_unknown() {
        // All green needs a green cell on Tumbleweed and on Leap 16.
        assert_eq!(
            classify_build(&[
                BuildCell {
                    repository: "openSUSE_Tumbleweed".to_string(),
                    arch: "x86_64".to_string(),
                    code: "succeeded".to_string(),
                },
                BuildCell {
                    repository: "openSUSE_Leap_16.0".to_string(),
                    arch: "x86_64".to_string(),
                    code: "succeeded".to_string(),
                },
            ]),
            "all_green"
        );
        // Tumbleweed green alone is unknown, not all green.
        assert_eq!(
            classify_build(&[BuildCell {
                repository: "openSUSE_Tumbleweed".to_string(),
                arch: "x86_64".to_string(),
                code: "succeeded".to_string(),
            }]),
            "unknown"
        );
        assert_eq!(
            classify_build(&[
                BuildCell {
                    repository: "openSUSE_Tumbleweed".to_string(),
                    arch: "x86_64".to_string(),
                    code: "succeeded".to_string(),
                },
                BuildCell {
                    repository: "openSUSE_Leap_16.0".to_string(),
                    arch: "x86_64".to_string(),
                    code: "succeeded".to_string(),
                },
                BuildCell {
                    repository: "openSUSE_Tumbleweed".to_string(),
                    arch: "aarch64".to_string(),
                    code: "failed".to_string(),
                },
            ]),
            "any_failed"
        );
        assert_eq!(
            classify_build(&[BuildCell {
                repository: "openSUSE_Tumbleweed".to_string(),
                arch: "x86_64".to_string(),
                code: "building".to_string(),
            }]),
            "building"
        );
        assert_eq!(classify_build(&[]), "unknown");
        assert_eq!(
            classify_build(&[BuildCell {
                repository: "openSUSE_Tumbleweed".to_string(),
                arch: "x86_64".to_string(),
                code: "disabled".to_string(),
            }]),
            "unknown"
        );
    }

    #[test]
    fn signal_repo_matching() {
        assert!(is_signal_repo("openSUSE_Tumbleweed"));
        assert!(is_signal_repo("openSUSE_Leap_16.0"));
        assert!(is_signal_repo("openSUSE_Leap_16.1"));
        assert!(!is_signal_repo("openSUSE_Leap_15.6"));
        assert!(!is_signal_repo("SLE_15_SP6"));
        assert!(!is_signal_repo("openSUSE_Factory"));
    }

    #[test]
    fn build_status_for_filters_to_signal_repos_and_arches() {
        let matrix = build_matrix(vec![
            ("openSUSE_Tumbleweed", "x86_64", "succeeded"),
            ("openSUSE_Tumbleweed", "aarch64", "succeeded"),
            ("openSUSE_Leap_16.0", "x86_64", "succeeded"),
            ("openSUSE_Leap_15.6", "x86_64", "failed"),
            ("openSUSE_Tumbleweed", "ppc64le", "failed"),
        ]);
        let source = FakeSource::new(vec![]).with_build("home:alice", "foo", Ok(matrix));
        let (status, cells) = build_status_for(&source, "home:alice", "foo").unwrap();
        assert_eq!(status, "all_green");
        // The Leap 15.6 failure and the ppc64le failure are outside
        // the signal's repos/arches, so they do not count.
        assert_eq!(cells.len(), 3);
    }

    #[test]
    fn read_signals_obs_record() {
        let green = build_matrix(vec![
            ("openSUSE_Tumbleweed", "x86_64", "succeeded"),
            ("openSUSE_Tumbleweed", "aarch64", "succeeded"),
            ("openSUSE_Leap_16.0", "x86_64", "succeeded"),
        ]);
        let source = FakeSource::new(vec![])
            .with_show(
                "obs:123",
                Ok(obs_pr_with_reviews(vec![review_opinion(
                    "alice",
                    OpinionState::Approved,
                )])),
            )
            .with_diff("obs:123", Ok(BUMP_DIFF.to_string()))
            .with_build("home:alice", "foo", Ok(green))
            .with_build(
                "devel:foo",
                "foo",
                Ok(build_matrix(vec![
                    ("openSUSE_Tumbleweed", "x86_64", "succeeded"),
                    ("openSUSE_Leap_16.0", "x86_64", "succeeded"),
                ])),
            )
            .with_maintainers("devel:foo", "foo", Ok(vec![named_role("someone")]));
        let record = signal_record("obs:123", "obs");
        let snapshot = read_signals(&source, &record, &test_config(), &[123]);
        assert!(snapshot.read_errors.is_empty());
        assert_eq!(snapshot.build.status, "all_green");
        assert_eq!(snapshot.build.target_status, "all_green");
        assert_eq!(snapshot.review.state, "approved");
        assert!(snapshot.diff.version_bump_only);
        assert_eq!(snapshot.diff.new_version.as_deref(), Some("1.1"));
        assert_eq!(snapshot.author.is_own_filing, Some(true));
        assert_eq!(snapshot.author.is_package_maintainer, Some(true));
        assert_eq!(snapshot.author.first_time_submitter, None);
        assert_eq!(snapshot.package.package, "foo");
        assert_eq!(snapshot.package.is_excluded, Some(false));
        assert_eq!(snapshot.package.is_security, Some(false));
        assert_eq!(snapshot.server.status, "open");
    }

    fn named_role(name: &str) -> NamedRole {
        NamedRole {
            name: name.to_string(),
            role: "maintainer".to_string(),
            email: None,
            realname: None,
        }
    }

    #[test]
    fn read_signals_maintainer_check() {
        // The author is a maintainer of the target package.
        let maintainer = FakeSource::new(vec![])
            .with_show("obs:123", Ok(obs_pr_with_reviews(vec![])))
            .with_diff("obs:123", Ok(BUMP_DIFF.to_string()))
            .with_build(
                "home:alice",
                "foo",
                Ok(build_matrix(vec![(
                    "openSUSE_Tumbleweed",
                    "x86_64",
                    "succeeded",
                )])),
            )
            .with_build(
                "devel:foo",
                "foo",
                Ok(build_matrix(vec![(
                    "openSUSE_Tumbleweed",
                    "x86_64",
                    "succeeded",
                )])),
            )
            .with_maintainers("devel:foo", "foo", Ok(vec![named_role("someone")]));
        let record = signal_record("obs:123", "obs");
        let snapshot = read_signals(&maintainer, &record, &test_config(), &[]);
        assert_eq!(snapshot.author.is_package_maintainer, Some(true));
        // The author matches no name, but the list is non-empty:
        // a group in the list could hold them, so it is unknown,
        // not a false claim of non-maintainership.
        let not_maintainer = FakeSource::new(vec![])
            .with_show("obs:123", Ok(obs_pr_with_reviews(vec![])))
            .with_diff("obs:123", Ok(BUMP_DIFF.to_string()))
            .with_build(
                "home:alice",
                "foo",
                Ok(build_matrix(vec![(
                    "openSUSE_Tumbleweed",
                    "x86_64",
                    "succeeded",
                )])),
            )
            .with_build(
                "devel:foo",
                "foo",
                Ok(build_matrix(vec![(
                    "openSUSE_Tumbleweed",
                    "x86_64",
                    "succeeded",
                )])),
            )
            .with_maintainers("devel:foo", "foo", Ok(vec![named_role("alice")]));
        let snapshot = read_signals(&not_maintainer, &record, &test_config(), &[]);
        assert_eq!(snapshot.author.is_package_maintainer, None);
        // An empty maintainers list proves there is no maintainer.
        let nobody = FakeSource::new(vec![])
            .with_show("obs:123", Ok(obs_pr_with_reviews(vec![])))
            .with_diff("obs:123", Ok(BUMP_DIFF.to_string()))
            .with_build(
                "home:alice",
                "foo",
                Ok(build_matrix(vec![(
                    "openSUSE_Tumbleweed",
                    "x86_64",
                    "succeeded",
                )])),
            )
            .with_build(
                "devel:foo",
                "foo",
                Ok(build_matrix(vec![(
                    "openSUSE_Tumbleweed",
                    "x86_64",
                    "succeeded",
                )])),
            )
            .with_maintainers("devel:foo", "foo", Ok(vec![]));
        let snapshot = read_signals(&nobody, &record, &test_config(), &[]);
        assert_eq!(snapshot.author.is_package_maintainer, Some(false));
        // A failed maintainers read is unknown, never a false claim.
        let failed = FakeSource::new(vec![])
            .with_show("obs:123", Ok(obs_pr_with_reviews(vec![])))
            .with_diff("obs:123", Ok(BUMP_DIFF.to_string()))
            .with_build(
                "home:alice",
                "foo",
                Ok(build_matrix(vec![(
                    "openSUSE_Tumbleweed",
                    "x86_64",
                    "succeeded",
                )])),
            )
            .with_build(
                "devel:foo",
                "foo",
                Ok(build_matrix(vec![(
                    "openSUSE_Tumbleweed",
                    "x86_64",
                    "succeeded",
                )])),
            )
            .with_maintainers("devel:foo", "foo", Err(err(ErrorKind::ServerError, "boom")));
        let snapshot = read_signals(&failed, &record, &test_config(), &[]);
        assert_eq!(snapshot.author.is_package_maintainer, None);
        assert!(snapshot
            .read_errors
            .iter()
            .any(|e| e.starts_with("maintainers: ")));
    }

    #[test]
    fn read_signals_excluded_package_and_cve() {
        let source = FakeSource::new(vec![])
            .with_show(
                "obs:124",
                Ok({
                    let mut pr = fake_pr(
                        PullRequestRef::Obs(124),
                        PullRequestStatus::Open,
                        "devel:gcc/gcc",
                        None,
                    );
                    pr.title = "Fix CVE-2026-99999 in gcc".to_string();
                    pr
                }),
            )
            .with_diff("obs:124", Ok(CVE_DIFF.to_string()))
            .with_maintainers("devel:gcc", "gcc", Ok(vec![]));
        let record = signal_record("obs:124", "obs");
        let snapshot = read_signals(&source, &record, &test_config(), &[]);
        assert_eq!(snapshot.package.is_excluded, Some(true));
        assert_eq!(snapshot.package.is_security, Some(true));
        assert_eq!(snapshot.author.is_package_maintainer, Some(false));
        assert_eq!(
            snapshot.package.cve_ids,
            vec!["CVE-2026-12345", "CVE-2026-99999"]
        );
        // No build answers: the build reads unknown, never green.
        assert_eq!(snapshot.build.status, "unknown");
        assert!(!snapshot.read_errors.is_empty());
    }

    #[test]
    fn read_signals_show_failure_is_unknown() {
        let source =
            FakeSource::new(vec![]).with_show("obs:125", Err(err(ErrorKind::ServerError, "boom")));
        let record = signal_record("obs:125", "obs");
        let snapshot = read_signals(&source, &record, &test_config(), &[]);
        assert_eq!(snapshot.build.status, "unknown");
        assert_eq!(snapshot.review.state, "unknown");
        assert_eq!(snapshot.server.status, "unknown");
        assert_eq!(snapshot.author.is_own_filing, None);
        assert_eq!(snapshot.author.is_package_maintainer, None);
        assert_eq!(snapshot.package.is_excluded, None);
        assert_eq!(snapshot.package.is_security, None);
        assert!(!snapshot.read_errors.is_empty());
    }

    #[test]
    fn read_signals_gitea_build_is_unknown_not_green() {
        let source = FakeSource::new(vec![])
            .with_show(
                "gitea:alice/foo#7",
                Ok({
                    let mut pr = fake_pr(
                        PullRequestRef::Gitea {
                            owner: "alice".to_string(),
                            repo: "foo".to_string(),
                            number: 7,
                        },
                        PullRequestStatus::Open,
                        "alice/foo",
                        Some("main"),
                    );
                    pr.author = "alice".to_string();
                    pr
                }),
            )
            .with_diff("gitea:alice/foo#7", Ok(BUMP_DIFF.to_string()));
        let record = signal_record("gitea:alice/foo#7", "gitea");
        let snapshot = read_signals(&source, &record, &test_config(), &[]);
        assert_eq!(snapshot.build.status, "unknown");
        assert!(snapshot.build.reason.is_some());
        assert!(snapshot.diff.version_bump_only);
        // The Gitea "not built" is expected, not a failed read, so
        // no read error is recorded for it.
        assert!(snapshot.read_errors.is_empty());
        assert_eq!(snapshot.author.is_package_maintainer, None);
    }

    #[test]
    fn set_signal_snapshot_updates_only_snapshot() {
        let path = tmp_path("snapshot");
        let live_run = live();
        let mut queue = ReviewQueue::open(&path).unwrap();
        queue.upsert(ReviewRecord::new(
            "obs:123", "default", "obs", "bump foo", "someone", None,
        ));
        let snapshot = serde_json::to_value(SignalSnapshot::unknown(vec![])).unwrap();
        assert!(queue.set_signal_snapshot("default", "obs:123", snapshot));
        let record = queue.find("default", "obs:123").unwrap();
        assert!(record.signal_snapshot.is_some());
        assert_eq!(record.status, "open");
        assert_eq!(record.tier, "");
        assert!(!queue.set_signal_snapshot("default", "obs:999", serde_json::Value::Null));
        queue.save(&live_run).unwrap();
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn refresh_on_skips_terminal_records() {
        let source = FakeSource::new(vec![]).with_show("obs:123", Ok(obs_pr_with_reviews(vec![])));
        let path = tmp_path("refresh-skip");
        let live_run = live();
        let mut queue = ReviewQueue::open(&path).unwrap();
        queue.upsert(ReviewRecord::new(
            "obs:123", "default", "obs", "bump foo", "someone", None,
        ));
        queue.mark_terminal("default", "obs:123");
        let report = refresh_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &test_config(),
            &[],
            &mut queue,
            &live_run,
        );
        assert_eq!(report.refreshed, 0);
        let record = queue.find("default", "obs:123").unwrap();
        assert!(record.signal_snapshot.is_none());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn refresh_on_records_snapshot_and_failed_reads() {
        let source = FakeSource::new(vec![])
            .with_show(
                "obs:123",
                Ok(obs_pr_with_reviews(vec![review_opinion(
                    "alice",
                    OpinionState::Approved,
                )])),
            )
            .with_diff("obs:123", Ok(BUMP_DIFF.to_string()))
            .with_build(
                "home:alice",
                "foo",
                Ok(build_matrix(vec![
                    ("openSUSE_Tumbleweed", "x86_64", "succeeded"),
                    ("openSUSE_Leap_16.0", "x86_64", "succeeded"),
                ])),
            )
            .with_build(
                "devel:foo",
                "foo",
                Ok(build_matrix(vec![
                    ("openSUSE_Tumbleweed", "x86_64", "succeeded"),
                    ("openSUSE_Leap_16.0", "x86_64", "succeeded"),
                ])),
            )
            .with_maintainers("devel:foo", "foo", Ok(vec![named_role("someone")]));
        let path = tmp_path("refresh-ok");
        let live_run = live();
        let mut queue = ReviewQueue::open(&path).unwrap();
        queue.upsert(ReviewRecord::new(
            "obs:123", "default", "obs", "bump foo", "someone", None,
        ));
        let report = refresh_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &test_config(),
            &[],
            &mut queue,
            &live_run,
        );
        assert_eq!(report.refreshed, 1);
        assert_eq!(report.failed, 0);
        let record = queue.find("default", "obs:123").unwrap();
        let snapshot: SignalSnapshot =
            serde_json::from_value(record.signal_snapshot.clone().unwrap()).unwrap();
        assert_eq!(snapshot.build.status, "all_green");
        assert_eq!(snapshot.review.state, "approved");
        assert!(snapshot.diff.version_bump_only);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    // Step 3: ruleset and evaluator.

    /// A clean all-green version-bump snapshot: the baseline every
    /// classify test mutates.
    fn base_snapshot() -> SignalSnapshot {
        SignalSnapshot {
            read_at: "0".to_string(),
            build: BuildSignal {
                status: "all_green".to_string(),
                cells: Vec::new(),
                target_status: "all_green".to_string(),
                target_reason: None,
                reason: None,
            },
            review: ReviewSignal {
                state: "none".to_string(),
                reviews: Vec::new(),
                reason: None,
            },
            diff: DiffSignal {
                files: vec!["foo.spec".to_string(), "foo.changes".to_string()],
                spec_changed: true,
                version_bump_only: true,
                patches_changed: false,
                new_files: Vec::new(),
                changelog_changed: true,
                new_version: Some("2.0".to_string()),
                cve_ids: Vec::new(),
                reason: None,
            },
            author: AuthorSignal {
                author: "someone".to_string(),
                is_own_filing: Some(false),
                is_package_maintainer: Some(true),
                first_time_submitter: None,
            },
            package: PackageSignal {
                package: "foo".to_string(),
                is_excluded: Some(false),
                is_core: None,
                is_security: Some(false),
                cve_ids: Vec::new(),
            },
            server: ServerSignal {
                status: "open".to_string(),
                draft: false,
                mergeable: None,
            },
            read_errors: Vec::new(),
        }
    }

    fn shipped_ruleset() -> Ruleset {
        // The test runs with the crate root as the working
        // directory, like `repo_config_loads`.
        Ruleset::load("review_ruleset.json").unwrap()
    }

    #[test]
    fn ruleset_load_rejects_bad_files() {
        // No version.
        assert!(Ruleset::load_text(r#"{"rules": []}"#).is_err());
        // Empty version.
        assert!(Ruleset::load_text(r#"{"version": "", "rules": []}"#).is_err());
        // Unknown top-level key.
        assert!(Ruleset::load_text(r#"{"version": "1", "rules": [], "extra": 1}"#).is_err());
        // Unknown action.
        assert!(Ruleset::load_text(
            r#"{"version": "1", "rules": [{"name": "x", "when": [], "action": "merge", "message": "m"}]}"#
        )
        .is_err());
        // Unknown signal path.
        assert!(Ruleset::load_text(
            r#"{"version": "1", "rules": [{"name": "x", "when": [{"path": "build.colour", "op": "eq", "value": "green"}], "action": "hold", "message": "m"}]}"#
        )
        .is_err());
        // Unknown operator.
        assert!(Ruleset::load_text(
            r#"{"version": "1", "rules": [{"name": "x", "when": [{"path": "build.status", "op": "matches", "value": "green"}], "action": "hold", "message": "m"}]}"#
        )
        .is_err());
        // Duplicate rule name.
        assert!(Ruleset::load_text(
            r#"{"version": "1", "rules": [
                {"name": "x", "when": [], "action": "hold", "message": "m"},
                {"name": "x", "when": [], "action": "hold", "message": "m"}]}"#
        )
        .is_err());
        // `eq` with an array value.
        assert!(Ruleset::load_text(
            r#"{"version": "1", "rules": [{"name": "x", "when": [{"path": "build.status", "op": "eq", "value": ["green"]}], "action": "hold", "message": "m"}]}"#
        )
        .is_err());
        // `is_empty` with a value.
        assert!(Ruleset::load_text(
            r#"{"version": "1", "rules": [{"name": "x", "when": [{"path": "read_errors", "op": "is_empty", "value": true}], "action": "hold", "message": "m"}]}"#
        )
        .is_err());
        // Empty message.
        assert!(Ruleset::load_text(
            r#"{"version": "1", "rules": [{"name": "x", "when": [], "action": "hold", "message": "  "}]}"#
        )
        .is_err());
        // Not JSON at all.
        assert!(Ruleset::load_text("not json").is_err());
        // An empty rule list is a valid fail-closed ruleset:
        // everything falls through to the human tier.
        assert!(Ruleset::load_text(r#"{"version": "1", "rules": []}"#).is_ok());
        // `in` accepts booleans as well as strings.
        assert!(Ruleset::load_text(
            r#"{"version": "1", "rules": [{"name": "x", "when": [{"path": "package.is_excluded", "op": "in", "value": [true]}], "action": "hold", "message": "m"}]}"#
        )
        .is_ok());
    }

    #[test]
    fn ruleset_shipped_file_loads() {
        let ruleset = shipped_ruleset();
        assert_eq!(ruleset.version, "1");
        assert!(
            ruleset.rules.iter().any(|r| r.name == "clean-bump"),
            "shipped ruleset carries the clean-bump rule"
        );
        assert!(
            ruleset.rules.iter().any(|r| r.name == "failed-read"),
            "shipped ruleset carries the failed-read rule"
        );
    }

    #[test]
    fn classify_clean_bump_is_auto_comment() {
        let ruleset = shipped_ruleset();
        let verdict = classify(&ruleset, &base_snapshot());
        assert_eq!(verdict.tier, "auto");
        assert_eq!(verdict.action, "comment");
        assert_eq!(verdict.rule.as_deref(), Some("clean-bump"));
        // An approved review is green too.
        let mut approved = base_snapshot();
        approved.review.state = "approved".to_string();
        let verdict = classify(&ruleset, &approved);
        assert_eq!(verdict.tier, "auto");
        assert_eq!(verdict.rule.as_deref(), Some("clean-bump"));
    }

    #[test]
    fn classify_failed_read_is_human_and_wins_over_draft() {
        let ruleset = shipped_ruleset();
        let mut snapshot = base_snapshot();
        snapshot.read_errors = vec!["build: connection refused".to_string()];
        snapshot.server.draft = true;
        let verdict = classify(&ruleset, &snapshot);
        assert_eq!(verdict.tier, "human");
        assert_eq!(verdict.action, "escalate-human");
        assert_eq!(verdict.rule.as_deref(), Some("failed-read"));
        assert!(verdict.question.is_some());
    }

    #[test]
    fn classify_draft_is_mid_hold() {
        let ruleset = shipped_ruleset();
        let mut snapshot = base_snapshot();
        snapshot.server.draft = true;
        let verdict = classify(&ruleset, &snapshot);
        assert_eq!(verdict.tier, "mid");
        assert_eq!(verdict.action, "hold");
        assert_eq!(verdict.rule.as_deref(), Some("draft"));
    }

    #[test]
    fn classify_risk_flag_files_and_versions_are_human() {
        let ruleset = shipped_ruleset();
        // A changed _service, by basename, wherever it sits.
        let mut snapshot = base_snapshot();
        snapshot.diff.files = vec!["foo/_service".to_string()];
        snapshot.diff.version_bump_only = false;
        let verdict = classify(&ruleset, &snapshot);
        assert_eq!(verdict.rule.as_deref(), Some("risk-flag-service-files"));
        assert_eq!(verdict.tier, "human");
        // A pre-release version.
        let mut snapshot = base_snapshot();
        snapshot.diff.new_version = Some("1.0~rc1".to_string());
        let verdict = classify(&ruleset, &snapshot);
        assert_eq!(verdict.rule.as_deref(), Some("pre-release-version"));
        // A leading v.
        let mut snapshot = base_snapshot();
        snapshot.diff.new_version = Some("v2.0".to_string());
        let verdict = classify(&ruleset, &snapshot);
        assert_eq!(verdict.rule.as_deref(), Some("leading-v-version"));
        // No version at all: the version rules need a value, so
        // they do not match on null.
        let mut snapshot = base_snapshot();
        snapshot.diff.new_version = None;
        let verdict = classify(&ruleset, &snapshot);
        assert_eq!(verdict.rule.as_deref(), Some("clean-bump"));
    }

    #[test]
    fn classify_failed_build_depends_on_the_target() {
        let ruleset = shipped_ruleset();
        // The submitter's failure (the target builds): human.
        let mut snapshot = base_snapshot();
        snapshot.build.status = "any_failed".to_string();
        snapshot.build.target_status = "all_green".to_string();
        let verdict = classify(&ruleset, &snapshot);
        assert_eq!(verdict.rule.as_deref(), Some("failed-build-submit"));
        assert_eq!(verdict.tier, "human");
        // The target fails the same way: parked, not the
        // submitter's.
        let mut snapshot = base_snapshot();
        snapshot.build.status = "any_failed".to_string();
        snapshot.build.target_status = "any_failed".to_string();
        let verdict = classify(&ruleset, &snapshot);
        assert_eq!(verdict.rule.as_deref(), Some("failed-build-target"));
        assert_eq!(verdict.tier, "mid");
        assert_eq!(verdict.action, "hold");
    }

    #[test]
    fn classify_no_rule_match_is_human() {
        let ruleset = shipped_ruleset();
        // Green build and no outstanding review, but the diff is
        // more than a bump (a patch changed): no rule covers it.
        let mut snapshot = base_snapshot();
        snapshot.diff.version_bump_only = false;
        snapshot.diff.patches_changed = true;
        snapshot.diff.files.push("fix.patch".to_string());
        snapshot.diff.new_version = None;
        let verdict = classify(&ruleset, &snapshot);
        assert_eq!(verdict.tier, "human");
        assert_eq!(verdict.action, "escalate-human");
        assert_eq!(verdict.rule, None);
    }

    #[test]
    fn classify_decline_normalizes_to_comment() {
        let ruleset = Ruleset::load_text(
            r#"{"version": "1", "rules": [
                {"name": "would-decline", "when": [{"path": "build.status", "op": "eq", "value": "all_green"}], "action": "decline", "message": "Would decline this."}]}"#,
        )
        .unwrap();
        let verdict = classify(&ruleset, &base_snapshot());
        assert_eq!(verdict.tier, "auto");
        assert_eq!(verdict.action, "comment");
        assert_eq!(verdict.rule.as_deref(), Some("would-decline"));
        assert!(verdict.reason.contains("OBS decline is human-only"));
    }

    #[test]
    fn classify_first_match_wins() {
        let ruleset = Ruleset::load_text(
            r#"{"version": "1", "rules": [
                {"name": "first", "when": [{"path": "build.status", "op": "eq", "value": "all_green"}], "action": "escalate-human", "message": "First."},
                {"name": "second", "when": [{"path": "build.status", "op": "eq", "value": "all_green"}], "action": "comment", "message": "Second."}]}"#,
        )
        .unwrap();
        let verdict = classify(&ruleset, &base_snapshot());
        assert_eq!(verdict.rule.as_deref(), Some("first"));
        assert_eq!(verdict.tier, "human");
    }

    #[test]
    fn set_classification_opens_to_triaged() {
        let path = tmp_path("classify-set");
        let live_run = live();
        let mut queue = ReviewQueue::open(&path).unwrap();
        queue.upsert(ReviewRecord::new(
            "obs:123", "default", "obs", "bump foo", "someone", None,
        ));
        assert!(queue.set_classification(
            "default",
            "obs:123",
            "auto",
            "comment",
            Some("clean-bump"),
            "1"
        ));
        let record = queue.find("default", "obs:123").unwrap();
        assert_eq!(record.status, "triaged");
        assert_eq!(record.tier, "auto");
        assert_eq!(record.action.as_deref(), Some("comment"));
        assert_eq!(record.matched_rule.as_deref(), Some("clean-bump"));
        assert_eq!(record.ruleset_version.as_deref(), Some("1"));
        assert!(!queue.set_classification("default", "obs:999", "auto", "comment", None, "1"));
        queue.save(&live_run).unwrap();
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn classify_records_persists_verdicts() {
        let path = tmp_path("classify-run");
        let live_run = live();
        let mut queue = ReviewQueue::open(&path).unwrap();
        queue.upsert(ReviewRecord::new(
            "obs:123", "default", "obs", "bump foo", "someone", None,
        ));
        let clean = serde_json::to_value(base_snapshot()).unwrap();
        queue.set_signal_snapshot("default", "obs:123", clean);
        queue.upsert(ReviewRecord::new(
            "obs:124", "default", "obs", "bump bar", "someone", None,
        ));
        let mut failed = base_snapshot();
        failed.read_errors = vec!["build: connection refused".to_string()];
        queue.set_signal_snapshot("default", "obs:124", serde_json::to_value(failed).unwrap());
        // No snapshot: skipped.
        queue.upsert(ReviewRecord::new(
            "obs:125", "default", "obs", "bump baz", "someone", None,
        ));
        // Terminal: skipped.
        queue.upsert(ReviewRecord::new(
            "obs:126", "default", "obs", "bump qux", "someone", None,
        ));
        queue.mark_terminal("default", "obs:126");
        queue.save(&live_run).unwrap();
        drop(queue);

        let report = classify_records("review_ruleset.json", &path, &live_run).unwrap();
        assert_eq!(report.classified, 2);
        assert_eq!(report.auto, 1);
        assert_eq!(report.human, 1);
        assert_eq!(report.skipped_no_snapshot, 1);
        assert_eq!(report.skipped_terminal, 1);

        let queue = ReviewQueue::open(&path).unwrap();
        let clean_record = queue.find("default", "obs:123").unwrap();
        assert_eq!(clean_record.tier, "auto");
        assert_eq!(clean_record.action.as_deref(), Some("comment"));
        assert_eq!(clean_record.matched_rule.as_deref(), Some("clean-bump"));
        assert_eq!(clean_record.ruleset_version.as_deref(), Some("1"));
        assert_eq!(clean_record.status, "triaged");
        let failed_record = queue.find("default", "obs:124").unwrap();
        assert_eq!(failed_record.tier, "human");
        assert_eq!(failed_record.matched_rule.as_deref(), Some("failed-read"));
        let skipped = queue.find("default", "obs:125").unwrap();
        assert_eq!(skipped.tier, "");
        assert_eq!(skipped.ruleset_version, None);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn classify_records_refuses_a_bad_ruleset() {
        let ruleset_path = tmp_path("bad-ruleset");
        fs::write(&ruleset_path, "not json").unwrap();
        let queue_path = tmp_path("classify-refused");
        let live_run = live();
        {
            let mut queue = ReviewQueue::open(&queue_path).unwrap();
            queue.upsert(ReviewRecord::new(
                "obs:123", "default", "obs", "bump foo", "someone", None,
            ));
            queue.save(&live_run).unwrap();
        }
        assert!(classify_records(&ruleset_path, &queue_path, &live_run).is_err());
        let queue = ReviewQueue::open(&queue_path).unwrap();
        assert_eq!(queue.find("default", "obs:123").unwrap().tier, "");
        let _ = fs::remove_file(&ruleset_path);
        let _ = fs::remove_file(&queue_path);
        let _ = fs::remove_file(format!("{queue_path}.lock"));
    }

    // Step 4: human handoff.

    #[test]
    fn escalate_and_clear_escalation() {
        let path = tmp_path("escalate");
        let live_run = live();
        let mut queue = ReviewQueue::open(&path).unwrap();
        queue.upsert(ReviewRecord::new(
            "obs:123", "default", "obs", "bump foo", "someone", None,
        ));
        let fingerprint = "0123456789abcdef".to_string();
        assert!(queue.escalate(
            "default",
            "obs:123",
            "A signal read failed.",
            Some("What does the server say?"),
            &fingerprint,
        ));
        let record = queue.find("default", "obs:123").unwrap();
        assert_eq!(record.status, "escalated");
        assert_eq!(
            record.escalation_reason.as_deref(),
            Some("A signal read failed.")
        );
        assert_eq!(
            record.escalation_question.as_deref(),
            Some("What does the server say?")
        );
        assert_eq!(
            record.escalation_fingerprint.as_deref(),
            Some("0123456789abcdef")
        );
        assert!(record.escalated_at.is_some());
        assert!(!queue.escalate("default", "obs:999", "r", None, "f"));
        assert!(queue.clear_escalation("default", "obs:123"));
        let record = queue.find("default", "obs:123").unwrap();
        assert_eq!(record.status, "open");
        assert_eq!(record.escalation_reason, None);
        assert_eq!(record.escalated_at, None);
        assert_eq!(record.escalation_question, None);
        assert_eq!(record.escalation_fingerprint, None);
        assert!(!queue.clear_escalation("default", "obs:999"));
        queue.save(&live_run).unwrap();
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn record_human_decision_moves_to_terminal() {
        let path = tmp_path("decide");
        let live_run = live();
        let mut queue = ReviewQueue::open(&path).unwrap();
        queue.upsert(ReviewRecord::new(
            "obs:123", "default", "obs", "bump foo", "someone", None,
        ));
        queue.escalate("default", "obs:123", "No rule covers this.", None, "fp");
        assert!(queue
            .record_human_decision("default", "obs:123", "dismissed")
            .unwrap());
        let record = queue.find("default", "obs:123").unwrap();
        assert_eq!(record.status, "terminal");
        assert_eq!(record.human_decision.as_deref(), Some("dismissed"));
        assert!(record.human_decision_at.is_some());
        // The escalation stays recorded: the decision, not a
        // re-run, closed the item.
        assert_eq!(
            record.escalation_reason.as_deref(),
            Some("No rule covers this.")
        );
        assert!(!queue
            .record_human_decision("default", "obs:999", "approved")
            .unwrap());
        assert!(queue
            .record_human_decision("default", "obs:123", "maybe")
            .is_err());
        queue.save(&live_run).unwrap();
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn classification_fingerprint_ignores_read_time() {
        let mut first = base_snapshot();
        first.read_at = "111".to_string();
        let mut second = base_snapshot();
        second.read_at = "222".to_string();
        assert_eq!(
            classification_fingerprint("1", &first, &None),
            classification_fingerprint("1", &second, &None)
        );
        // A server change changes the fingerprint.
        second.build.status = "any_failed".to_string();
        assert_ne!(
            classification_fingerprint("1", &first, &None),
            classification_fingerprint("1", &second, &None)
        );
        // So does a new ruleset version.
        assert_ne!(
            classification_fingerprint("1", &first, &None),
            classification_fingerprint("2", &first, &None)
        );
    }

    /// A queue file with one clean record (obs:123) and one
    /// failed-read record (obs:124), snapshots recorded, for the
    /// step-4 classify tests.
    fn handoff_queue(path: &str) {
        let live_run = live();
        let mut queue = ReviewQueue::open(path).unwrap();
        queue.upsert(ReviewRecord::new(
            "obs:123", "default", "obs", "bump foo", "someone", None,
        ));
        queue.set_signal_snapshot(
            "default",
            "obs:123",
            serde_json::to_value(base_snapshot()).unwrap(),
        );
        queue.upsert(ReviewRecord::new(
            "obs:124", "default", "obs", "bump bar", "someone", None,
        ));
        let mut failed = base_snapshot();
        failed.read_errors = vec!["build: connection refused".to_string()];
        queue.set_signal_snapshot("default", "obs:124", serde_json::to_value(failed).unwrap());
        queue.save(&live_run).unwrap();
    }

    #[test]
    fn classify_records_escalates_human_verdicts_and_parks_them() {
        let path = tmp_path("handoff-park");
        let live_run = live();
        handoff_queue(&path);

        let report = classify_records("review_ruleset.json", &path, &live_run).unwrap();
        assert_eq!(report.classified, 2);
        assert_eq!(report.human, 1);
        let escalated_at = {
            let queue = ReviewQueue::open(&path).unwrap();
            let record = queue.find("default", "obs:124").unwrap();
            assert_eq!(record.status, "escalated");
            assert_eq!(record.tier, "human");
            assert_eq!(record.matched_rule.as_deref(), Some("failed-read"));
            assert!(record.escalation_reason.is_some());
            assert!(record.escalation_question.is_some());
            assert!(record.escalation_fingerprint.is_some());
            assert!(record.escalated_at.is_some());
            record.escalated_at.clone().unwrap()
        };

        // A second run over unchanged state parks the escalated
        // record: it is skipped, not re-escalated, and the
        // escalation timestamp does not move. The clean record
        // re-classifies as before.
        let report = classify_records("review_ruleset.json", &path, &live_run).unwrap();
        assert_eq!(report.skipped_escalated, 1);
        assert_eq!(report.classified, 1);
        assert_eq!(report.auto, 1);
        let queue = ReviewQueue::open(&path).unwrap();
        assert_eq!(
            queue
                .find("default", "obs:124")
                .unwrap()
                .escalated_at
                .as_deref(),
            Some(escalated_at.as_str())
        );
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn classify_records_reopens_escalated_on_state_change() {
        let path = tmp_path("handoff-reopen");
        let live_run = live();
        handoff_queue(&path);
        classify_records("review_ruleset.json", &path, &live_run).unwrap();
        {
            let queue = ReviewQueue::open(&path).unwrap();
            assert_eq!(
                queue.find("default", "obs:124").unwrap().status,
                "escalated"
            );
        }
        // The read now succeeds: the snapshot changes, so the
        // record re-opens and re-classifies as a clean bump.
        {
            let mut queue = ReviewQueue::open(&path).unwrap();
            queue.set_signal_snapshot(
                "default",
                "obs:124",
                serde_json::to_value(base_snapshot()).unwrap(),
            );
            queue.save(&live_run).unwrap();
        }
        let report = classify_records("review_ruleset.json", &path, &live_run).unwrap();
        assert_eq!(report.skipped_escalated, 0);
        // Both records classify: the re-opened one and the clean
        // one, which re-classifies as before.
        assert_eq!(report.classified, 2);
        assert_eq!(report.auto, 2);
        let queue = ReviewQueue::open(&path).unwrap();
        let record = queue.find("default", "obs:124").unwrap();
        assert_eq!(record.status, "triaged");
        assert_eq!(record.tier, "auto");
        assert_eq!(record.escalation_reason, None);
        assert_eq!(record.escalated_at, None);
        assert_eq!(record.escalation_fingerprint, None);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn human_handoff_report_lists_escalated_only() {
        let path = tmp_path("handoff-report");
        let live_run = live();
        handoff_queue(&path);
        classify_records("review_ruleset.json", &path, &live_run).unwrap();

        let items = human_handoff_report(&path).unwrap();
        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert_eq!(item.reference, "obs:124");
        assert_eq!(item.instance, "default");
        assert_eq!(item.tier, "human");
        assert_eq!(item.ruleset_version.as_deref(), Some("1"));
        assert!(item.signal_snapshot.is_some());
        assert!(item.question.contains("signal read failed"));

        // A recorded decision closes the item: the report empties
        // and a re-run never re-escalates it.
        {
            let mut queue = ReviewQueue::open(&path).unwrap();
            assert!(queue
                .record_human_decision("default", "obs:124", "approved")
                .unwrap());
            queue.save(&live_run).unwrap();
        }
        assert!(human_handoff_report(&path).unwrap().is_empty());
        let report = classify_records("review_ruleset.json", &path, &live_run).unwrap();
        assert_eq!(report.skipped_terminal, 1);
        // The clean record still classifies; the decided one stays
        // terminal and is never re-escalated.
        assert_eq!(report.classified, 1);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    // Step 5: comment action.

    #[test]
    fn review_stage_ready_off_on_misordered() {
        let mut config = Config::default();
        assert!(!review_stage_ready(&config, ReviewStage::Comment).unwrap());
        config.review_comment_stage = true;
        assert!(review_stage_ready(&config, ReviewStage::Comment).unwrap());
        assert!(!review_stage_ready(&config, ReviewStage::RequestChanges).unwrap());
        config.review_request_changes_stage = true;
        assert!(review_stage_ready(&config, ReviewStage::RequestChanges).unwrap());
        // Accept on while request-changes is off: refused.
        config.review_request_changes_stage = false;
        config.review_accept_stage = true;
        assert!(review_stage_ready(&config, ReviewStage::Accept).is_err());
        // Request-changes on while comment is off: refused the
        // other way (a later stage needs the earlier one on).
        config.review_request_changes_stage = true;
        config.review_comment_stage = false;
        assert!(review_stage_ready(&config, ReviewStage::RequestChanges).is_err());
    }

    #[test]
    fn triage_comment_body_has_no_ruleset_version() {
        let ruleset = shipped_ruleset();
        let snapshot = base_snapshot();
        let verdict = classify(&ruleset, &snapshot);
        let body = triage_comment_body(&snapshot, &verdict);
        assert!(body.contains("freshcrab triage: auto — clean-bump"));
        assert!(body.contains("Version bump only"));
        assert!(body.contains("build: all_green"));
        assert!(body.contains("review: none"));
        assert!(body.contains("diff: version bump only, changelog updated, version 2.0"));
        assert!(body.contains("author: someone (package maintainer)"));
        assert!(body.contains("package: foo"));
        assert!(body.contains("server: open"));
        assert!(!body.contains("ruleset"));
        assert!(check_comment_body(&body).is_ok());
    }

    #[test]
    fn check_comment_body_refuses_approval_lines() {
        assert!(check_comment_body("freshcrab triage: auto\nbuild: all_green").is_ok());
        // Only a line START carries the trigger: mid-line is fine.
        assert!(check_comment_body("the note says merge ok mid-line").is_ok());
        assert!(check_comment_body("merge ok, ship it").is_err());
        assert!(check_comment_body("  merge ok, ship it").is_err());
        assert!(check_comment_body("Merge OK, ship it").is_err());
        assert!(check_comment_body("@group : approve").is_err());
        assert!(check_comment_body("  @group : approve this").is_err());
        assert!(check_comment_body("first line\n@group : approve").is_err());
    }

    #[test]
    fn record_action_marks_actioned() {
        let path = tmp_path("record-action");
        let live_run = live();
        let mut queue = ReviewQueue::open(&path).unwrap();
        queue.upsert(ReviewRecord::new(
            "obs:123", "default", "obs", "bump foo", "someone", None,
        ));
        assert!(queue.record_action("default", "obs:123", "comment", "7", "fp1"));
        let record = queue.find("default", "obs:123").unwrap();
        assert_eq!(record.status, "actioned");
        assert_eq!(record.action_history.len(), 1);
        assert_eq!(record.action_history[0].action, "comment");
        assert_eq!(record.action_history[0].id, "7");
        assert_eq!(record.action_history[0].fingerprint, "fp1");
        assert!(queue.action_recorded("default", "obs:123", "comment", "fp1"));
        assert!(!queue.action_recorded("default", "obs:123", "comment", "fp2"));
        assert!(!queue.action_recorded("default", "obs:123", "request-changes", "fp1"));
        assert!(!queue.record_action("default", "obs:999", "comment", "7", "fp1"));
        assert!(!queue.action_recorded("default", "obs:999", "comment", "fp1"));
        queue.save(&live_run).unwrap();
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    /// A queue file with one clean record (obs:123), snapshot
    /// recorded and classified, for the step-5 comment tests.
    fn comment_queue(path: &str) {
        let live_run = live();
        {
            let mut queue = ReviewQueue::open(path).unwrap();
            queue.upsert(ReviewRecord::new(
                "obs:123", "default", "obs", "bump foo", "someone", None,
            ));
            queue.set_signal_snapshot(
                "default",
                "obs:123",
                serde_json::to_value(base_snapshot()).unwrap(),
            );
            queue.save(&live_run).unwrap();
        }
        classify_records("review_ruleset.json", path, &live_run).unwrap();
    }

    #[test]
    fn comment_on_posts_once_then_skips() {
        let path = tmp_path("comment-once");
        let live_run = live();
        comment_queue(&path);
        let ruleset = shipped_ruleset();
        let source = FakeSource::new(vec![]);
        let mut queue = ReviewQueue::open(&path).unwrap();
        let report = comment_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &mut queue,
            &live_run,
            &ruleset,
        );
        assert_eq!(report.posted, 1);
        assert_eq!(source.posted().len(), 1);
        let record = queue.find("default", "obs:123").unwrap();
        assert_eq!(record.status, "actioned");
        assert_eq!(record.action_history.len(), 1);
        assert_eq!(record.action_history[0].action, "comment");
        assert_eq!(record.action_history[0].id, "1");
        // A re-run over the unchanged snapshot posts nothing.
        let report = comment_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &mut queue,
            &live_run,
            &ruleset,
        );
        assert_eq!(report.posted, 0);
        assert_eq!(report.skipped_unchanged, 1);
        assert_eq!(source.posted().len(), 1);
        queue.save(&live_run).unwrap();
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn comment_on_adopts_server_comment() {
        let path = tmp_path("comment-adopt");
        let live_run = live();
        comment_queue(&path);
        let ruleset = shipped_ruleset();
        let snapshot = base_snapshot();
        let verdict = classify(&ruleset, &snapshot);
        let body = triage_comment_body(&snapshot, &verdict);
        let server_comment = ReviewComment {
            id: 99,
            author: "freshcrab".to_string(),
            created: "0".to_string(),
            body,
            parent_id: None,
            diff_target: None,
            diff_file: None,
            diff_line: None,
        };
        let source = FakeSource::new(vec![]).with_comments("obs:123", vec![server_comment]);
        let mut queue = ReviewQueue::open(&path).unwrap();
        let report = comment_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &mut queue,
            &live_run,
            &ruleset,
        );
        assert_eq!(report.posted, 0);
        assert_eq!(report.skipped_adopted, 1);
        assert!(source.posted().is_empty());
        let record = queue.find("default", "obs:123").unwrap();
        assert_eq!(record.action_history.len(), 1);
        assert_eq!(record.action_history[0].id, "99");
        queue.save(&live_run).unwrap();
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn comment_on_dry_run_plans_only() {
        let path = tmp_path("comment-dry");
        comment_queue(&path);
        let ruleset = shipped_ruleset();
        let source = FakeSource::new(vec![]);
        let mut queue = ReviewQueue::open(&path).unwrap();
        let report = comment_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &mut queue,
            &dry(),
            &ruleset,
        );
        assert_eq!(report.posted, 0);
        assert_eq!(report.planned, 1);
        assert!(source.posted().is_empty());
        let record = queue.find("default", "obs:123").unwrap();
        assert!(record.action_history.is_empty());
        assert_eq!(record.status, "triaged");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn comment_on_skips_stale_verdict() {
        let path = tmp_path("comment-stale");
        let live_run = live();
        comment_queue(&path);
        // A different ruleset re-derives a different verdict (an
        // empty ruleset: everything falls through to human), so
        // the stored `comment` verdict is stale and skipped.
        let ruleset = Ruleset::load_text(r#"{"version": "2", "rules": []}"#).unwrap();
        let source = FakeSource::new(vec![]);
        let mut queue = ReviewQueue::open(&path).unwrap();
        let report = comment_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &mut queue,
            &live_run,
            &ruleset,
        );
        assert_eq!(report.posted, 0);
        assert_eq!(report.skipped_other, 1);
        assert!(source.posted().is_empty());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn comment_on_reposts_on_change() {
        let path = tmp_path("comment-change");
        let live_run = live();
        comment_queue(&path);
        let ruleset = shipped_ruleset();
        let source = FakeSource::new(vec![]);
        let mut queue = ReviewQueue::open(&path).unwrap();
        let report = comment_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &mut queue,
            &live_run,
            &ruleset,
        );
        assert_eq!(report.posted, 1);
        // The review lands (approved): the verdict is still a
        // clean bump, but the snapshot — and the comment body —
        // changed, so the run posts again.
        let mut approved = base_snapshot();
        approved.review.state = "approved".to_string();
        queue.set_signal_snapshot(
            "default",
            "obs:123",
            serde_json::to_value(approved).unwrap(),
        );
        let report = comment_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &mut queue,
            &live_run,
            &ruleset,
        );
        assert_eq!(report.posted, 1);
        assert_eq!(source.posted().len(), 2);
        let record = queue.find("default", "obs:123").unwrap();
        assert_eq!(record.action_history.len(), 2);
        queue.save(&live_run).unwrap();
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }
}
