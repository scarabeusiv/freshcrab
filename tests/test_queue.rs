//! Integration tests for the queue: deduplication, persistence, dry-run.

use freshcrab::dry_run::DryRun;
use freshcrab::queue::{DedupChecks, Queue, QueueEntry, UpdateKind};
use freshcrab::target::Target;
use std::env;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn tmp_path() -> String {
    // A process-wide counter alongside the clock makes the path
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

fn live() -> DryRun {
    DryRun::new(false)
}

#[test]
fn add_and_deduplicate() {
    let path = tmp_path();
    let mut q = Queue::open(&path).unwrap();
    let live_run = live();
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
            &live_run
        )
        .unwrap()
        .is_some());
    // In flight: a second add for the same package is skipped.
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
            &live_run
        )
        .unwrap()
        .is_none());
    // Devel already new: skipped.
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
            &live_run
        )
        .unwrap()
        .is_none());
    // Open SR: skipped.
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
            &live_run
        )
        .unwrap()
        .is_none());
    // Devel behind and no open SR: queued.
    let devel_behind = |_pkg: &str| Some("1.9".to_string());
    let no_sr = |_pkg: &str| Ok(false);
    assert!(q
        .add(
            QueueEntry::new(
                "qux",
                "1.9",
                "2.0",
                "repology",
                &Target::Factory,
                UpdateKind::Routine,
            ),
            DedupChecks {
                devel_version: Some(&devel_behind),
                has_open_sr: Some(&no_sr),
            },
            &live_run
        )
        .unwrap()
        .is_some());
    let _ = fs::remove_file(&path);
}

#[test]
fn save_and_load_roundtrip() {
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
        &live_run,
    )
    .unwrap();
    q.set_status("bar", "blocked", &live_run).unwrap();
    q.save(&live_run).unwrap();

    // The first Queue holds the flock; drop it before reopening.
    drop(q);
    let q2 = Queue::open(&path).unwrap();
    assert_eq!(q2.entries().len(), 2);
    assert_eq!(q2.find("foo").unwrap().status, "pending");
    assert_eq!(q2.find("foo").unwrap().source, "repology");
    assert_eq!(q2.find("bar").unwrap().status, "blocked");
    let _ = fs::remove_file(&path);
}

#[test]
fn dry_run_add_and_save_write_nothing() {
    let path = tmp_path();
    let mut q = Queue::open(&path).unwrap();
    let dry_run = DryRun::new(true);
    // The dedup decision is printed, nothing is added, nothing is saved.
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
        .unwrap()
        .is_none());
    assert!(q.entries().is_empty());
    q.save(&dry_run).unwrap();
    assert!(!Path::new(&path).exists());
    assert_eq!(
        dry_run.plan(),
        vec![
            "[dry-run] would: enqueue foo 1.9 -> 2.0 (source: repology)".to_string(),
            format!("[dry-run] would: write queue state file {path}"),
        ]
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn live_add_and_save_take_effect() {
    let path = tmp_path();
    let mut q = Queue::open(&path).unwrap();
    let live_run = live();
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
            &live_run
        )
        .unwrap()
        .is_some());
    q.save(&live_run).unwrap();
    assert!(Path::new(&path).exists());
    assert!(live_run.plan().is_empty());
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
        ("security-a", UpdateKind::Security),
        ("routine-b", UpdateKind::Routine),
    ] {
        q.add(
            QueueEntry::new(pkg, "1.9", "2.0", "repology", &Target::Factory, kind),
            DedupChecks::none(),
            &live_run,
        )
        .unwrap();
    }
    let pending: Vec<&str> = q.pending().iter().map(|e| e.package.as_str()).collect();
    assert_eq!(pending, vec!["security-a", "routine-a", "routine-b"]);
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
        .unwrap()
        .unwrap();
    assert_eq!(entry.target, Target::Factory);
    assert_eq!(entry.kind, UpdateKind::Security);
    // Persisted and reloaded, the target and kind survive.
    q.save(&live_run).unwrap();
    // The first Queue holds the flock; drop it before reopening.
    drop(q);
    let q2 = Queue::open(&path).unwrap();
    let reloaded = q2.find("foo").unwrap();
    assert_eq!(reloaded.target, Target::Factory);
    assert_eq!(reloaded.kind, UpdateKind::Security);
    let _ = fs::remove_file(&path);
}
