//! Queue: persistent state for packages awaiting an update, with dedup.
//!
//! A queue entry is a package behind its upstream release. The queue is a
//! JSON file; each entry tracks its status (pending / in_progress / done /
//! blocked / escalated). Before an entry is added, the deduplication
//! checks run: skip the package when the devel project already has the
//! new version, when an open submit request already targets the package,
//! or when a task for the package is already in flight. The OBS-backed
//! checkers live in `obs.rs`; the queue takes closures so the tests can
//! inject fakes.
//!
//! In dry-run mode every mutation goes through the dry-run guard
//! (`crate::dry_run::DryRun`): the dedup rules are still evaluated (reads
//! are not gated) and the decision is printed (would-enqueue / would-skip
//! + reason), but nothing is added and nothing is persisted.

use crate::dry_run::DryRun;
use crate::version::is_newer;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const STATUSES: &[&str] = &["pending", "in_progress", "done", "blocked", "escalated"];

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
    pub created_at: String,
    pub updated_at: String,
}

impl QueueEntry {
    pub fn new(package: &str, factory_version: &str, upstream_version: &str, source: &str) -> Self {
        let now = now_iso();
        QueueEntry {
            package: package.to_string(),
            factory_version: factory_version.to_string(),
            upstream_version: upstream_version.to_string(),
            source: source.to_string(),
            status: "pending".to_string(),
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
/// `Queue::add` for deduplication.
pub type OpenSrCheck<'a> = dyn Fn(&str) -> bool + 'a;

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
pub struct Queue {
    path: String,
    entries: Vec<QueueEntry>,
}

impl Queue {
    /// Open the queue at `path`. A missing file is an empty queue.
    pub fn open(path: &str) -> Result<Self, QueueError> {
        let mut queue = Queue {
            path: path.to_string(),
            entries: Vec::new(),
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
        let tmp = format!("{}.tmp", self.path);
        fs::write(&tmp, format!("{text}\n"))
            .map_err(|e| QueueError(format!("cannot write queue file {}: {e}", tmp)))?;
        fs::rename(&tmp, &self.path)
            .map_err(|e| QueueError(format!("cannot replace queue file {}: {e}", self.path)))?;
        Ok(())
    }

    /// Return the entry for `package`, or None.
    pub fn find(&self, package: &str) -> Option<&QueueEntry> {
        self.entries.iter().find(|e| e.package == package)
    }

    /// True when a task for `package` is already pending or running.
    pub fn in_flight(&self, package: &str) -> bool {
        match self.find(package) {
            Some(entry) => entry.status == "pending" || entry.status == "in_progress",
            None => false,
        }
    }

    /// Set the status of the entry for `package`. In dry-run, prints what
    /// it WOULD set and changes nothing.
    pub fn set_status(
        &mut self,
        package: &str,
        status: &str,
        dry_run: &DryRun,
    ) -> Result<(), QueueError> {
        if !STATUSES.contains(&status) {
            return Err(QueueError(format!("unknown queue status: {status:?}")));
        }
        if !dry_run.allow(&format!("set {package} status to {status}")) {
            return Ok(());
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
    /// None (that check is skipped). Returns the new entry, or None when
    /// the package was skipped.
    ///
    /// In dry-run, the dedup rules are still evaluated and the decision is
    /// printed (would-enqueue / would-skip + reason), but nothing is
    /// added. Returns None in dry-run (nothing was enqueued).
    pub fn add(
        &mut self,
        package: &str,
        factory_version: &str,
        upstream_version: &str,
        source: &str,
        dedup: DedupChecks<'_>,
        dry_run: &DryRun,
    ) -> Option<QueueEntry> {
        if self.in_flight(package) {
            dry_run.note(&format!("would-skip {package}: task already in flight"));
            return None;
        }
        if let Some(check) = dedup.devel_version {
            if let Some(current) = check(package) {
                if !is_newer(upstream_version, &current) {
                    dry_run.note(&format!(
                        "would-skip {package}: devel already has {current}"
                    ));
                    return None;
                }
            }
        }
        if let Some(check) = dedup.has_open_sr {
            if check(package) {
                dry_run.note(&format!(
                    "would-skip {package}: open submit request already targets it"
                ));
                return None;
            }
        }
        let entry = QueueEntry::new(package, factory_version, upstream_version, source);
        if !dry_run.allow(&format!(
            "enqueue {package} {factory_version} -> {upstream_version} (source: {source})"
        )) {
            return None;
        }
        self.entries.push(entry.clone());
        Some(entry)
    }

    /// Entries awaiting dispatch, in queue order.
    pub fn pending(&self) -> Vec<&QueueEntry> {
        self.entries
            .iter()
            .filter(|e| e.status == "pending")
            .collect()
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
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!(
            "{}/freshcrab-test-queue-{nanos}.json",
            env::temp_dir().display()
        )
    }

    #[test]
    fn add_new_entry() {
        let path = tmp_path();
        let mut q = Queue::open(&path).unwrap();
        let entry = q
            .add(
                "foo",
                "1.9",
                "2.0",
                "repology",
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
            "foo",
            "1.9",
            "2.0",
            "repology",
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        // A second add while the first is pending (in flight) is skipped.
        assert!(q
            .add(
                "foo",
                "1.9",
                "2.1",
                "repology",
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
            "foo",
            "1.9",
            "2.0",
            "repology",
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        q.set_status("foo", "done", &live()).unwrap();
        assert!(q
            .add(
                "foo",
                "2.0",
                "2.1",
                "repology",
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
                "foo",
                "1.9",
                "2.0",
                "repology",
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
                "foo",
                "1.9",
                "2.0",
                "repology",
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
                "foo",
                "1.9",
                "2.0",
                "repology",
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
                "foo",
                "1.9",
                "2.0",
                "repology",
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
        let has_sr = |_pkg: &str| true;
        assert!(q
            .add(
                "foo",
                "1.9",
                "2.0",
                "repology",
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
        let has_sr = |_pkg: &str| false;
        assert!(q
            .add(
                "foo",
                "1.9",
                "2.0",
                "repology",
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
            "foo",
            "1.9",
            "2.0",
            "repology",
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        q.add(
            "bar",
            "1.0",
            "1.1",
            "repology",
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        q.set_status("bar", "blocked", &live()).unwrap();
        q.save(&live()).unwrap();

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
            "foo",
            "1.9",
            "2.0",
            "repology",
            DedupChecks::none(),
            &live(),
        )
        .unwrap();
        q.add(
            "bar",
            "1.0",
            "1.1",
            "repology",
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
            "foo",
            "1.9",
            "2.0",
            "repology",
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
                "foo",
                "1.9",
                "2.0",
                "repology",
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
                "bar",
                "1.9",
                "2.0",
                "repology",
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
        let has_sr = |_pkg: &str| true;
        assert!(q
            .add(
                "baz",
                "1.9",
                "2.0",
                "repology",
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
            "foo",
            "1.9",
            "2.0",
            "repology",
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
            "foo",
            "1.9",
            "2.0",
            "repology",
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
                "foo",
                "1.9",
                "2.0",
                "repology",
                DedupChecks::none(),
                &live_run,
            )
            .unwrap();
        assert_eq!(entry.source, "repology");
        q.save(&live_run).unwrap();
        assert!(Path::new(&path).exists());
        assert!(live_run.plan().is_empty());
        let q2 = Queue::open(&path).unwrap();
        assert_eq!(q2.find("foo").unwrap().source, "repology");
        let _ = fs::remove_file(&path);
    }
}
