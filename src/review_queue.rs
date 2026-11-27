//! Review queue: triage state for OBS submit requests and Gitea pull
//! requests, read through geectl's unified pull-request surface.
//!
//! Step 1 (this module): the review-record state file
//! (`review_queue.json`, one record per pull-request ref) and
//! discovery — a pull-request search on both arms, scoped to the
//! watch scope, deduplicated, one record per ref. Report-only:
//! discovery reads and records; it posts nothing, changes no
//! review state, files nothing, and merges nothing. The ruleset
//! (step 3), the signal readers (step 2), the human handoff (step 4)
//! and the actions (steps 5-7) are not built here.
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
use geectl::obs::{ObsClient, OBS_API_BASE};
use geectl::pull_request::{
    PullRequest, PullRequestBackend, PullRequestClient, PullRequestRef, PullRequestSearch,
    PullRequestStatus, PullRequestSummary,
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
}

/// The review-record statuses (see the design's Queue state).
pub const REVIEW_STATUSES: &[&str] = &["open", "triaged", "actioned", "escalated", "terminal"];

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
            binding,
            grace_periods: GracePeriods::default(),
            last_checked: now.clone(),
            action_history: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
        }
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

/// The pull-request reads discovery needs, as a trait so tests
/// inject a fake. Production passes `PullRequestClient`.
pub trait PullRequestSource {
    fn search(&self, query: &PullRequestSearch) -> Result<Vec<PullRequestSummary>, GeectlError>;
    fn show(&self, reference: &PullRequestRef) -> Result<PullRequest, GeectlError>;
}

impl<'a> PullRequestSource for PullRequestClient<'a> {
    fn search(&self, query: &PullRequestSearch) -> Result<Vec<PullRequestSummary>, GeectlError> {
        PullRequestClient::search(self, query)
    }

    fn show(&self, reference: &PullRequestRef) -> Result<PullRequest, GeectlError> {
        PullRequestClient::show(self, reference)
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
fn discover_with_scan(
    config: &Config,
    own_sr_ids: &[u64],
    http: &dyn geectl::http::HttpClient,
    queue: &mut ReviewQueue,
    dry_run: &DryRun,
    scan: InstanceScan,
) -> Result<DiscoveryReport, ReviewQueueError> {
    let mut report = DiscoveryReport {
        unscannable: scan.unscannable,
        ..DiscoveryReport::default()
    };
    for instance in &scan.instances {
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
                    report.instances.push(InstanceReport {
                        alias: instance.alias.clone(),
                        url: instance.url.clone(),
                        backend: backend.as_str().to_string(),
                        error: Some(error),
                        skipped: true,
                        ..InstanceReport::default()
                    });
                }
                continue;
            };
            let instance_report = match backend {
                PullRequestBackend::Obs => {
                    match ObsClient::with_base_and_credentials(http, &instance.url, creds) {
                        Ok(obs) => {
                            let client = PullRequestClient::new(Some(&obs), None);
                            discover_on(
                                &client,
                                backend,
                                &instance.alias,
                                config,
                                own_sr_ids,
                                queue,
                                dry_run,
                            )
                        }
                        Err(e) => InstanceReport {
                            alias: instance.alias.clone(),
                            url: instance.url.clone(),
                            backend: backend.as_str().to_string(),
                            error: Some(e.to_string()),
                            ..InstanceReport::default()
                        },
                    }
                }
                PullRequestBackend::Gitea => {
                    match GiteaClient::with_base(http, &instance.url, creds) {
                        Ok(gitea) => {
                            let client = PullRequestClient::new(None, Some(&gitea));
                            discover_on(
                                &client,
                                backend,
                                &instance.alias,
                                config,
                                own_sr_ids,
                                queue,
                                dry_run,
                            )
                        }
                        Err(e) => InstanceReport {
                            alias: instance.alias.clone(),
                            url: instance.url.clone(),
                            backend: backend.as_str().to_string(),
                            error: Some(e.to_string()),
                            ..InstanceReport::default()
                        },
                    }
                }
            };
            let mut instance_report = instance_report;
            instance_report.url = instance.url.clone();
            report.discovered += instance_report.in_scope;
            report.new_records += instance_report.new_records;
            report.updated_records += instance_report.updated_records;
            report.terminal_marked += instance_report.terminal_marked;
            report.unresolved += instance_report.unresolved;
            report.instances.push(instance_report);
        }
    }
    queue.save(dry_run)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::{QueueEntry, UpdateKind};
    use crate::target::Target;
    use geectl::pull_request::PullRequestEndpoint;
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
    /// show answers (a show error is canned by listing the ref in
    /// `show_errors` with its kind).
    struct FakeSource {
        search_results: Vec<PullRequestSummary>,
        search_error: Option<GeectlError>,
        show_answers: Vec<(String, Result<PullRequest, GeectlError>)>,
    }

    impl FakeSource {
        fn new(search_results: Vec<PullRequestSummary>) -> Self {
            FakeSource {
                search_results,
                search_error: None,
                show_answers: Vec::new(),
            }
        }

        fn with_show(mut self, reference: &str, answer: Result<PullRequest, GeectlError>) -> Self {
            self.show_answers.push((reference.to_string(), answer));
            self
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
}
