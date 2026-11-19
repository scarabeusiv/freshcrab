//! Queue: persistent state for packages awaiting an update, with dedup.
//!
//! A queue entry is a package behind its upstream release. The queue is a
//! JSON file; each entry tracks its status (pending / in_progress / done /
//! blocked / escalated). Before an entry is added, the deduplication
//! checks run: skip the package when the devel project already has the
//! new version, when an open submit request already targets the package,
//! or when a task for the package is already in flight. When the
//! open-SR check itself fails, the package is skipped (fail-closed)
//! rather than queued on an unchecked dedup. The OBS-backed
//! checkers live in `obs.rs`; the queue takes closures so the tests can
//! inject fakes.
//!
//! In dry-run mode every mutation goes through the dry-run guard
//! (`crate::dry_run::DryRun`): the dedup rules are still evaluated (reads
//! are not gated) and the decision is printed (would-enqueue / would-skip
//! + reason), but nothing is added and nothing is persisted.

use crate::dry_run::DryRun;
use crate::target::Target;
use crate::version::is_newer;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub const STATUSES: &[&str] = &["pending", "in_progress", "done", "blocked", "escalated"];

/// What kind of update a queue entry is. Security (CVE-driven) updates
/// rank above routine version bumps: the dispatcher drains security
/// entries first (see `docs/leap-and-cve.md`). The Factory path is
/// routine-only for now; the kind is carried so the ordering rule is
/// already in place when CVE-driven entries arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateKind {
    #[default]
    Routine,
    Security,
}

impl UpdateKind {
    /// Ordering rank: security (0) before routine (1).
    fn rank(self) -> u8 {
        match self {
            UpdateKind::Security => 0,
            UpdateKind::Routine => 1,
        }
    }
}

/// One queued update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueEntry {
    pub package: String,
    pub factory_version: String,
    pub upstream_version: String,
    /// The collector that confirmed the upstream version.
    #[serde(default)]
    pub source: String,
    pub status: String,
    /// The distribution this update is for.
    #[serde(default)]
    pub target: Target,
    /// Routine version bump or security (CVE-driven) update.
    #[serde(default)]
    pub kind: UpdateKind,
    pub created_at: String,
    pub updated_at: String,
}

impl QueueEntry {
    pub fn new(
        package: &str,
        factory_version: &str,
        upstream_version: &str,
        source: &str,
        target: &Target,
        kind: UpdateKind,
    ) -> Self {
        let now = now_iso();
        QueueEntry {
            package: package.to_string(),
            factory_version: factory_version.to_string(),
            upstream_version: upstream_version.to_string(),
            source: source.to_string(),
            status: "pending".to_string(),
            target: target.clone(),
            kind,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

fn now_iso() -> String {
    // Seconds since the epoch. The queue is machine-read first, so a
    // plain epoch timestamp is enough for ordering.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

/// Maps a package to the devel project's version of it (or None when the
/// devel project is unknown). Used by `Queue::add` for deduplication.
pub type DevelVersionCheck<'a> = dyn Fn(&str) -> Option<String> + 'a;
/// Reports whether an open submit request targets a package. Used by
/// `Queue::add` for deduplication. Returns an error when the check
/// itself fails (e.g. the OBS search API 401s without credentials):
/// `Queue::add` treats that as fail-closed and skips the package
/// rather than queueing it on an unchecked dedup.
pub type OpenSrCheck<'a> = dyn Fn(&str) -> Result<bool, QueueError> + 'a;

/// The dedup checkers for `Queue::add`. Both are optional; a missing
/// checker skips that check.
pub struct DedupChecks<'a> {
    pub devel_version: Option<&'a DevelVersionCheck<'a>>,
    pub has_open_sr: Option<&'a OpenSrCheck<'a>>,
}

impl<'a> DedupChecks<'a> {
    /// No dedup checks (both skipped).
    pub fn none() -> Self {
        DedupChecks {
            devel_version: None,
            has_open_sr: None,
        }
    }
}

/// Error from queue operations.
#[derive(Debug)]
pub struct QueueError(pub String);

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "queue error: {}", self.0)
    }
}

impl std::error::Error for QueueError {}

/// The queue, backed by a JSON state file.
///
/// Writers are serialized with an exclusive flock on a lock file next
/// to the queue (`<path>.lock`), held from `open` until the Queue is
/// dropped. flock is released when the process exits, so a crashed
/// writer cannot leave a stale lock behind. Without it, two writers
/// (cron + manual) racing a read-modify-write would silently lose
/// entries (last rename wins).
pub struct Queue {
    path: String,
    entries: Vec<QueueEntry>,
    /// The lock file, held open for the Queue's lifetime. It is never
    /// read — it exists only to hold the flock — so the dead-code lint
    /// is silenced deliberately.
    #[allow(dead_code)]
    lock_file: Option<std::fs::File>,
}

impl Queue {
    /// Open the queue at `path`. A missing file is an empty queue.
    pub fn open(path: &str) -> Result<Self, QueueError> {
        // Take the exclusive lock before reading: the open → add →
        // save sequence is a read-modify-write, and the lock is what
        // makes it atomic against a second writer. The lock is taken
        // non-blocking (fail fast): a second writer errors out
        // immediately instead of hanging behind the first.
        let lock_path = format!("{path}.lock");
        // The lock file is never written to — it exists only to hold
        // the flock — so it is opened without truncation.
        let lock_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| QueueError(format!("cannot open queue lock file {lock_path}: {e}")))?;
        lock_file.try_lock_exclusive().map_err(|e| {
            QueueError(format!(
                "cannot lock queue file {path} (another writer holds it?): {e}"
            ))
        })?;
        let mut queue = Queue {
            path: path.to_string(),
            entries: Vec::new(),
            lock_file: Some(lock_file),
        };
        if Path::new(path).exists() {
            queue.load()?;
        }
        Ok(queue)
    }

    /// Load the queue state file.
    pub fn load(&mut self) -> Result<(), QueueError> {
        let text = fs::read_to_string(&self.path)
            .map_err(|e| QueueError(format!("cannot read queue file {}: {e}", self.path)))?;
        let entries: Vec<QueueEntry> = serde_json::from_str(&text)
            .map_err(|e| QueueError(format!("invalid queue file {}: {e}", self.path)))?;
        self.entries = entries;
        Ok(())
    }

    /// Write the queue state file atomically. In dry-run, prints what it
    /// WOULD write and writes nothing.
    pub fn save(&self, dry_run: &DryRun) -> Result<(), QueueError> {
        if !dry_run.allow(&format!("write queue state file {}", self.path)) {
            return Ok(());
        }
        let text = serde_json::to_string_pretty(&self.entries)
            .map_err(|e| QueueError(format!("cannot serialize queue: {e}")))?;
        // A unique tmp name (pid + nanoseconds, created with O_EXCL)
        // so two writers can never share a tmp file, and fsync before
        // the atomic rename so a crash cannot leave a torn queue file.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let mut tmp = String::new();
        let mut file = None;
        for attempt in 0..10 {
            tmp = format!("{path}.{pid}.{nanos}.{attempt}.tmp", path = self.path);
            match OpenOptions::new().write(true).create_new(true).open(&tmp) {
                Ok(f) => {
                    file = Some(f);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(QueueError(format!("cannot write queue file {tmp}: {e}")));
                }
            }
        }
        let mut file = match file {
            Some(f) => f,
            None => {
                return Err(QueueError(format!(
                    "cannot allocate a unique tmp queue file for {}",
                    self.path
                )));
            }
        };
        file.write_all(format!("{text}\n").as_bytes())
            .map_err(|e| QueueError(format!("cannot write queue file {tmp}: {e}")))?;
        file.sync_all()
            .map_err(|e| QueueError(format!("cannot fsync queue file {tmp}: {e}")))?;
        drop(file);
        fs::rename(&tmp, &self.path)
            .map_err(|e| QueueError(format!("cannot replace queue file {}: {e}", self.path)))?;
        Ok(())
    }

    /// Return the entry for `package`, or None.
    pub fn find(&self, package: &str) -> Option<&QueueEntry> {
        self.entries.iter().find(|e| e.package == package)
    }

    /// True when a task for `package` is already pending or running.
    /// Checks every entry, not just the first: once a non-pending
    /// entry (blocked / done) exists for a package, `find` would return
    /// that one and miss a later pending duplicate.
    pub fn in_flight(&self, package: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.package == package && (e.status == "pending" || e.status == "in_progress"))
    }

    /// Set the status of the entry for `package`. In dry-run, prints what
    /// it WOULD set and changes nothing.
    pub fn set_status(
        &mut self,
        package: &str,
        status: &str,
        dry_run: &DryRun,
    ) -> Result<(), QueueError> {
        // The dry-run guard comes first: in dry-run an invalid status
        // is a would-do, not an error (the guard records the plan and
        // returns Ok). Validation applies in live mode only.
        if !dry_run.allow(&format!("set {package} status to {status}")) {
            return Ok(());
        }
        if !STATUSES.contains(&status) {
            return Err(QueueError(format!("unknown queue status: {status:?}")));
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.package == package)
            .ok_or_else(|| QueueError(format!("no queue entry for package {package:?}")))?;
        entry.status = status.to_string();
        entry.updated_at = now_iso();
        Ok(())
    }

    /// Add an update, unless a deduplication check says to skip it.
    ///
    /// `dedup` carries the checkers: `devel_version` maps a package to
    /// the devel project's version (or None); `has_open_sr` reports
    /// whether an open submit request targets the package. Either may be
    /// None (that check is skipped). Returns the entry, or None when the
    /// package was skipped.
    ///
    /// When the open-SR check itself errors, the package is skipped
    /// (fail-closed) rather than queued on an unchecked dedup. When an
    /// entry for the package already exists (done, blocked, or
    /// escalated), it is refreshed in place instead of pushing a
    /// duplicate — one entry per package, always.
    ///
    /// In dry-run, the dedup rules are still evaluated and the decision is
    /// printed (would-enqueue / would-skip + reason), but nothing is
    /// added. Returns None in dry-run (nothing was enqueued).
    pub fn add(
        &mut self,
        entry: QueueEntry,
        dedup: DedupChecks<'_>,
        dry_run: &DryRun,
    ) -> Option<QueueEntry> {
        if self.in_flight(&entry.package) {
            dry_run.note(&format!(
                "would-skip {}: task already in flight",
                entry.package
            ));
            return None;
        }
        if let Some(check) = dedup.devel_version {
            if let Some(current) = check(&entry.package) {
                if !is_newer(&entry.upstream_version, &current) {
                    dry_run.note(&format!(
                        "would-skip {}: devel already has {current}",
                        entry.package
                    ));
                    return None;
                }
            }
        }
        if let Some(check) = dedup.has_open_sr {
            match check(&entry.package) {
                Ok(true) => {
                    dry_run.note(&format!(
                        "would-skip {}: open submit request already targets it",
                        entry.package
                    ));
                    return None;
                }
                Ok(false) => {}
                Err(e) => {
                    // Fail closed: the dedup check could not run (the
                    // OBS search API 401s without credentials, and no
                    // credentials are plumbed yet — that is the filing
                    // phase's work). Queueing anyway would file a
                    // duplicate submit request, so skip the package
                    // and say so loudly instead of treating the failed
                    // check as "no open SR".
                    eprintln!(
                        "warning: open-SR check failed for {}: {e}; skipping (fail-closed)",
                        entry.package
                    );
                    return None;
                }
            }
        }
        let kind_suffix = match entry.kind {
            UpdateKind::Security => " (security)",
            UpdateKind::Routine => "",
        };
        // One entry per package: when an entry already exists (done,
        // blocked, or escalated — not in flight, or `in_flight` above
        // would have skipped), refresh it in place instead of pushing
        // a duplicate. A duplicate pending entry would also make
        // `set_status` act on the wrong (first) entry.
        if let Some(existing) = self.entries.iter_mut().find(|e| e.package == entry.package) {
            if !dry_run.allow(&format!(
                "update {} {} -> {} (source: {}){kind_suffix}",
                entry.package, entry.factory_version, entry.upstream_version, entry.source
            )) {
                return None;
            }
            existing.factory_version = entry.factory_version;
            existing.upstream_version = entry.upstream_version;
            existing.source = entry.source;
            existing.target = entry.target;
            existing.kind = entry.kind;
            existing.status = "pending".to_string();
            existing.updated_at = now_iso();
            return Some(existing.clone());
        }
        if !dry_run.allow(&format!(
            "enqueue {} {} -> {} (source: {}){kind_suffix}",
            entry.package, entry.factory_version, entry.upstream_version, entry.source
        )) {
            return None;
        }
        self.entries.push(entry.clone());
        Some(entry)
    }

    /// Entries awaiting dispatch, in queue order — security (CVE-driven)
    /// entries first, then routine version bumps (see
    /// `docs/leap-and-cve.md`). Within a kind, insertion order is kept
    /// (the sort is stable).
    pub fn pending(&self) -> Vec<&QueueEntry> {
        let mut pending: Vec<&QueueEntry> = self
            .entries
            .iter()
            .filter(|e| e.status == "pending")
            .collect();
        pending.sort_by_key(|e| e.kind.rank());
        pending
    }

    /// All entries, in queue order.
    pub fn entries(&self) -> &[QueueEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn live() -> DryRun {
        DryRun::new(false)
    }

    fn dry() -> DryRun {
        DryRun::new(true)
    }

    fn tmp_path() -> String {
        // A process-wide counter (not just the clock) makes the path
        // unique: parallel tests can otherwise share a nanosecond and
        // collide on the same queue file.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!(
            "{}/freshcrab-test-queue-{}-{n}-{nanos}.json",
            env::temp_dir().display(),
            std::process::id()
        )
    }

    #[test]
    fn add_new_entry() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let entry = q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks::none(),
                &live(),
            )
            .unwrap();
        assert_eq!(entry.package, "foo");
        assert_eq!(entry.status, "pending");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn in_flight_is_skipped() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        q.add(
            QueueEntry::new(
                "foo",
                "1.9",
                "2.0",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        // A second add while the first is pending (in flight) is skipped.
        assert!(q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.1",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks::none(),
                &live()
            )
            .is_none());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn done_entry_does_not_block_requeue() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        q.add(
            QueueEntry::new(
                "foo",
                "1.9",
                "2.0",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        q.set_status("foo", "done", &live()).unwrap();
        assert!(q
            .add(
                QueueEntry::new(
                    "foo",
                    "2.0",
                    "2.1",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks::none(),
                &live()
            )
            .is_some());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn devel_already_new_is_skipped() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let devel = |_pkg: &str| Some("2.0".to_string());
        assert!(q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks {
                    devel_version: Some(&devel),
                    has_open_sr: None
                },
                &live()
            )
            .is_none());
        let devel_newer = |_pkg: &str| Some("2.1".to_string());
        assert!(q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks {
                    devel_version: Some(&devel_newer),
                    has_open_sr: None,
                },
                &live(),
            )
            .is_none());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn devel_behind_is_queued() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let devel = |_pkg: &str| Some("1.9".to_string());
        assert!(q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks {
                    devel_version: Some(&devel),
                    has_open_sr: None
                },
                &live()
            )
            .is_some());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn devel_version_unknown_is_queued() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let devel = |_pkg: &str| None;
        assert!(q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks {
                    devel_version: Some(&devel),
                    has_open_sr: None
                },
                &live()
            )
            .is_some());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn open_sr_is_skipped() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let has_sr = |_pkg: &str| Ok(true);
        assert!(q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks {
                    devel_version: None,
                    has_open_sr: Some(&has_sr)
                },
                &live()
            )
            .is_none());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn no_open_sr_is_queued() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let has_sr = |_pkg: &str| Ok(false);
        assert!(q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks {
                    devel_version: None,
                    has_open_sr: Some(&has_sr)
                },
                &live()
            )
            .is_some());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        q.add(
            QueueEntry::new(
                "foo",
                "1.9",
                "2.0",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        q.add(
            QueueEntry::new(
                "bar",
                "1.0",
                "1.1",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        q.set_status("bar", "blocked", &live()).unwrap();
        q.save(&live()).unwrap();

        // The first Queue holds the flock; drop it before reopening.
        drop(q);
        let q2 = Queue::open(&path).unwrap();
        assert_eq!(q2.entries().len(), 2);
        let foo = q2.find("foo").unwrap();
        assert_eq!(foo.status, "pending");
        assert_eq!(foo.factory_version, "1.9");
        assert_eq!(foo.upstream_version, "2.0");
        assert_eq!(q2.find("bar").unwrap().status, "blocked");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_empty_queue() {
        let path = tmp_path();
        let q = Queue::open(&path).unwrap();
        assert!(q.entries().is_empty());
    }

    #[test]
    fn pending_returns_only_pending() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        q.add(
            QueueEntry::new(
                "foo",
                "1.9",
                "2.0",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        q.add(
            QueueEntry::new(
                "bar",
                "1.0",
                "1.1",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        q.set_status("bar", "done", &live()).unwrap();
        let pending: Vec<&str> = q.pending().iter().map(|e| e.package.as_str()).collect();
        assert_eq!(pending, vec!["foo"]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn set_status_unknown_raises() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        q.add(
            QueueEntry::new(
                "foo",
                "1.9",
                "2.0",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        assert!(q.set_status("foo", "bogus", &live()).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn set_status_missing_package_raises() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        assert!(q.set_status("nope", "done", &live()).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn dry_run_add_evaluates_dedup_prints_decision_writes_nothing() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let dry_run = dry();
        // Would-enqueue: the decision is printed, nothing is added.
        assert!(q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks::none(),
                &dry_run
            )
            .is_none());
        assert!(q.entries().is_empty());
        assert_eq!(
            dry_run.plan(),
            vec!["[dry-run] would: enqueue foo 1.9 -> 2.0 (source: repology)"]
        );
        // Would-skip (devel already new): the reason is printed.
        let devel = |_pkg: &str| Some("2.0".to_string());
        assert!(q
            .add(
                QueueEntry::new(
                    "bar",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks {
                    devel_version: Some(&devel),
                    has_open_sr: None,
                },
                &dry_run
            )
            .is_none());
        assert_eq!(
            dry_run.plan()[1],
            "[dry-run] would-skip bar: devel already has 2.0"
        );
        // Would-skip (open SR): the reason is printed.
        let has_sr = |_pkg: &str| Ok(true);
        assert!(q
            .add(
                QueueEntry::new(
                    "baz",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks {
                    devel_version: None,
                    has_open_sr: Some(&has_sr),
                },
                &dry_run
            )
            .is_none());
        assert_eq!(
            dry_run.plan()[2],
            "[dry-run] would-skip baz: open submit request already targets it"
        );
        assert!(q.entries().is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn dry_run_save_writes_no_file() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let dry_run = dry();
        q.add(
            QueueEntry::new(
                "foo",
                "1.9",
                "2.0",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        q.save(&dry_run).unwrap();
        // The file was not created.
        assert!(!Path::new(&path).exists());
        assert_eq!(
            dry_run.plan(),
            vec![format!("[dry-run] would: write queue state file {path}")]
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn dry_run_set_status_changes_nothing() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let dry_run = dry();
        q.add(
            QueueEntry::new(
                "foo",
                "1.9",
                "2.0",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        q.set_status("foo", "done", &dry_run).unwrap();
        assert_eq!(q.find("foo").unwrap().status, "pending");
        assert_eq!(
            dry_run.plan(),
            vec!["[dry-run] would: set foo status to done"]
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn live_add_and_save_take_effect() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let live_run = live();
        let entry = q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks::none(),
                &live_run,
            )
            .unwrap();
        assert_eq!(entry.source, "repology");
        q.save(&live_run).unwrap();
        assert!(Path::new(&path).exists());
        assert!(live_run.plan().is_empty());
        // The first Queue holds the flock; drop it before reopening.
        drop(q);
        let q2 = Queue::open(&path).unwrap();
        assert_eq!(q2.find("foo").unwrap().source, "repology");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn entry_carries_target_and_kind() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let live_run = live();
        let entry = q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Security,
                ),
                DedupChecks::none(),
                &live_run,
            )
            .unwrap();
        assert_eq!(entry.target, Target::Factory);
        assert_eq!(entry.kind, UpdateKind::Security);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn pending_orders_security_before_routine() {
        // Security (CVE-driven) updates are dispatched before routine
        // version bumps; within a kind, insertion order is kept.
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let live_run = live();
        for (pkg, kind) in [
            ("routine-a", UpdateKind::Routine),
            ("routine-b", UpdateKind::Routine),
            ("security-a", UpdateKind::Security),
            ("security-b", UpdateKind::Security),
        ] {
            q.add(
                QueueEntry::new(pkg, "1.9", "2.0", "repology", &Target::Factory, kind),
                DedupChecks::none(),
                &live_run,
            )
            .unwrap();
        }
        let pending: Vec<&str> = q.pending().iter().map(|e| e.package.as_str()).collect();
        assert_eq!(
            pending,
            vec!["security-a", "security-b", "routine-a", "routine-b"]
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn old_queue_file_loads_with_factory_routine_defaults() {
        // Queue files written before target/kind existed (no such
        // fields) still load: the defaults are Factory / Routine.
        let path = tmp_path();
        let old_json = r#"[{"package": "foo", "factory_version": "1.9", "upstream_version": "2.0", "source": "repology", "status": "pending", "created_at": "1", "updated_at": "1"}]"#;
        fs::write(&path, old_json).unwrap();
        let q = Queue::open(&path).unwrap();
        let entry = q.find("foo").unwrap();
        assert_eq!(entry.target, Target::Factory);
        assert_eq!(entry.kind, UpdateKind::Routine);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn dry_run_security_plan_names_the_kind() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let dry_run = dry();
        assert!(q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Security,
                ),
                DedupChecks::none(),
                &dry_run
            )
            .is_none());
        assert_eq!(
            dry_run.plan(),
            vec!["[dry-run] would: enqueue foo 1.9 -> 2.0 (source: repology) (security)"]
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn blocked_then_requeue_twice_updates_in_place() {
        // A blocked entry re-queued twice stays a single entry: the
        // re-add refreshes it in place instead of pushing duplicates
        // (which also made `set_status` act on the wrong entry).
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let live_run = live();
        q.add(
            QueueEntry::new(
                "foo",
                "1.9",
                "2.0",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks::none(),
            &live_run,
        )
        .unwrap();
        q.set_status("foo", "blocked", &live_run).unwrap();
        // First re-queue: the blocked entry is refreshed, not duplicated.
        let entry = q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.1",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks::none(),
                &live_run,
            )
            .unwrap();
        assert_eq!(entry.upstream_version, "2.1");
        assert_eq!(entry.status, "pending");
        assert_eq!(q.entries().len(), 1);
        // Second re-queue after blocking again: still one entry.
        q.set_status("foo", "blocked", &live_run).unwrap();
        q.add(
            QueueEntry::new(
                "foo",
                "1.9",
                "2.2",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks::none(),
            &live_run,
        )
        .unwrap();
        assert_eq!(q.entries().len(), 1);
        assert_eq!(q.find("foo").unwrap().upstream_version, "2.2");
        assert_eq!(q.find("foo").unwrap().status, "pending");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn corrupt_queue_json_is_error() {
        let path = tmp_path();
        fs::write(&path, "not json").unwrap();
        assert!(Queue::open(&path).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn open_sr_check_error_is_fail_closed() {
        // When the open-SR dedup check itself fails (e.g. the OBS
        // search API 401s without credentials), the package is skipped
        // rather than queued on an unchecked dedup.
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let has_sr = |_pkg: &str| -> Result<bool, QueueError> {
            Err(QueueError("open-SR check failed".to_string()))
        };
        assert!(q
            .add(
                QueueEntry::new(
                    "foo",
                    "1.9",
                    "2.0",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks {
                    devel_version: None,
                    has_open_sr: Some(&has_sr)
                },
                &live()
            )
            .is_none());
        assert!(q.entries().is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn dry_run_update_in_place_prints_decision_writes_nothing() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let live_run = live();
        q.add(
            QueueEntry::new(
                "foo",
                "1.9",
                "2.0",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks::none(),
            &live_run,
        )
        .unwrap();
        q.set_status("foo", "done", &live_run).unwrap();
        let dry_run = dry();
        assert!(q
            .add(
                QueueEntry::new(
                    "foo",
                    "2.0",
                    "2.1",
                    "repology",
                    &Target::Factory,
                    UpdateKind::Routine,
                ),
                DedupChecks::none(),
                &dry_run
            )
            .is_none());
        assert_eq!(q.find("foo").unwrap().upstream_version, "2.0");
        assert_eq!(q.find("foo").unwrap().status, "done");
        assert_eq!(
            dry_run.plan(),
            vec!["[dry-run] would: update foo 2.0 -> 2.1 (source: repology)"]
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn dry_run_set_status_invalid_status_is_ok() {
        // In dry-run an invalid status is a would-do, not an error:
        // the guard records the plan and returns Ok.
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let dry_run = dry();
        q.add(
            QueueEntry::new(
                "foo",
                "1.9",
                "2.0",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        assert!(q.set_status("foo", "bogus", &dry_run).is_ok());
        assert_eq!(q.find("foo").unwrap().status, "pending");
        assert_eq!(
            dry_run.plan(),
            vec!["[dry-run] would: set foo status to bogus"]
        );
        let _ = fs::remove_file(&path);
    }
}
