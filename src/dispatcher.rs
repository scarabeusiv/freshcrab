//! The dispatcher: pick queued updates and drive them through the
//! worker, respecting the concurrency limit, the daily SR cap, and the
//! security-first ordering.
//!
//! The dispatcher runs after the watcher has populated the queue. It:
//!
//! 1. takes the pending entries in queue order — security (CVE-driven)
//!    entries first, then routine version bumps
//!    (`Queue::pending()`; see `docs/leap-and-cve.md`),
//! 2. takes at most `concurrency` entries per run (the per-run batch;
//!    true parallel workers are a later step — the batch is processed
//!    sequentially here, and the limit bounds how much one run does),
//! 3. stops when the daily SR cap is reached (SRs filed today, counted
//!    from queue entries carrying a filed `sr_id` with today's
//!    `updated_at`; dry-run filings do not exist, so dry-run never
//!    consumes the cap),
//! 4. hands each entry to the [`Worker`](crate::worker::Worker), which
//!    re-checks the deduplication rules and drives the update, and
//! 5. applies the outcome to the queue status (`done` when the SR was
//!    filed or the update was already handled, `escalated` when a human
//!    must look, unchanged when the run was a dry-run plan) and saves
//!    the queue.
//!
//! The dispatcher itself files nothing: the SR filing happens inside
//! the worker, gated by the dry-run guard. In dry-run the dispatcher
//! logs the would-do plan for each entry and changes no queue state.
//!
//! Crash recovery: a run that died mid-dispatch used to strand entries
//! in `in_progress` (never retried — `Queue::pending` only matches
//! `pending`). Every run now starts by resetting stranded `in_progress`
//! entries to `pending`, and the dispatcher no longer pre-marks an entry
//! before the worker runs: a crash during the worker leaves the entry
//! `pending`, so the next run retries it, and the worker's dedup
//! re-check (open SR) is the backstop against filing twice. A filed SR
//! is saved to the queue file immediately after `mark_filed`, not only
//! at the end of the batch, so a crash cannot lose the filed id.
//!
//! TOCTOU: the dedup re-check and the filing POST are two separate OBS
//! calls — OBS has no conditional create — so a submit request filed by
//! someone else between the re-check and the POST can still produce a
//! duplicate. The re-check is a best-effort dedup, not a guarantee.
//!
//! Ordering is strict security-first with no aging: under a sustained
//! security backlog, routine entries can starve. That is the documented
//! tradeoff for now (security fixes always win).
//!
//! The daily SR cap counts SRs filed in the local queue file only.
//! Filings made from another host (or by hand) are not counted — the cap
//! is a local guard, not a global one.

use crate::config::Config;
use crate::dry_run::DryRun;
use crate::queue::{Queue, QueueError};
use crate::worker::{Worker, WorkerOutcome};
use serde::Serialize;

/// One entry's outcome in a dispatch run, for the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DispatchEntryOutcome {
    pub package: String,
    /// `filed`, `planned`, `skipped`, or `escalated`.
    pub outcome: String,
    /// Why (for skipped/escalated), or the SR id (for filed).
    pub reason: String,
    /// The OBS request id, when an SR was filed.
    pub sr_id: Option<String>,
}

/// The report for one dispatch run. Serialized as JSON to stdout by the
/// CLI, so `freshcrab | jq` stays machine-readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DispatchReport {
    /// Entries handed to the worker.
    pub dispatched: usize,
    /// Entries whose SR was filed.
    pub filed: usize,
    /// Entries planned in dry-run (nothing filed, nothing changed).
    pub planned: usize,
    /// Entries skipped (already handled: devel already new, open SR).
    pub skipped: usize,
    /// Entries escalated to a human.
    pub escalated: usize,
    /// Daily SR cap remaining after this run.
    pub cap_remaining: u32,
    pub outcomes: Vec<DispatchEntryOutcome>,
}

/// The dispatcher. Holds the worker (which carries the OBS client),
/// the config (concurrency, daily SR cap), and the dry-run mode.
pub struct Dispatcher<'a> {
    worker: &'a Worker<'a>,
    config: &'a Config,
    dry_run: &'a DryRun,
}

impl<'a> Dispatcher<'a> {
    pub fn new(worker: &'a Worker<'a>, config: &'a Config, dry_run: &'a DryRun) -> Self {
        Dispatcher {
            worker,
            config,
            dry_run,
        }
    }

    /// Dispatch the pending queue entries. Returns the report. Each run
    /// starts by resetting entries stranded in `in_progress` by a
    /// crashed earlier run (crash recovery), and every status change is
    /// propagated as an error — a failed `set_status`, `mark_filed`, or
    /// `escalate` fails the run loudly instead of recording a false
    /// success. A filed SR is saved to the queue file immediately
    /// (`mark_filed` + `save` per filing), and the queue is saved again
    /// at the end (through the dry-run guard, so a dry-run changes
    /// nothing on disk). A failed save is an error: after a live filing
    /// the filed SR id lives only in the queue file, so losing it would
    /// leave the entry pending — the next run would file again (the
    /// open-SR dedup re-check is the backstop, but a silent success here
    /// would hide the loss).
    pub fn dispatch(&self, queue: &mut Queue) -> Result<DispatchReport, QueueError> {
        // Crash recovery (see the module docs): entries stranded in
        // `in_progress` by a crashed earlier run go back to `pending`
        // before the batch is taken, so this run retries them.
        let recovered = queue.reset_stale_in_progress(self.dry_run)?;
        if recovered > 0 && self.dry_run.live() {
            eprintln!("recovered {recovered} stranded in_progress queue entries");
        }
        // Security-first order comes from Queue::pending(). Clone the
        // batch up front: pending() borrows the queue, and the outcomes
        // below mutate it.
        let batch: Vec<_> = queue
            .pending()
            .into_iter()
            .take(self.config.concurrency as usize)
            .cloned()
            .collect();
        let filed_today = queue.srs_filed_today() as u32;
        let mut remaining_cap = self.config.daily_sr_cap.saturating_sub(filed_today);
        let mut report = DispatchReport {
            dispatched: 0,
            filed: 0,
            planned: 0,
            skipped: 0,
            escalated: 0,
            cap_remaining: remaining_cap,
            outcomes: Vec::new(),
        };
        for entry in &batch {
            if remaining_cap == 0 {
                // Cap reached: stop, do not process further entries.
                // (The entry stays pending for the next run.) No outcome
                // is recorded for an entry that was never attempted.
                self.dry_run.note(&format!(
                    "daily SR cap reached ({} filed today); stopping dispatch",
                    filed_today
                ));
                break;
            }
            report.dispatched += 1;
            // No pre-mark: the entry stays `pending` while the worker
            // runs (see the module docs — a crash mid-run leaves it
            // pending, so the next run retries it).
            match self.worker.run(entry) {
                WorkerOutcome::Skipped { reason } => {
                    // Already handled (devel already new, or an open SR
                    // targets it): nothing to file, mark done. The cap
                    // is not consumed — no SR was filed.
                    queue.set_status(&entry.package, "done", self.dry_run)?;
                    report.skipped += 1;
                    report.outcomes.push(DispatchEntryOutcome {
                        package: entry.package.clone(),
                        outcome: "skipped".to_string(),
                        reason,
                        sr_id: None,
                    });
                }
                WorkerOutcome::NoDevelProject => {
                    queue.escalate(
                        &entry.package,
                        "no devel project for this package",
                        self.dry_run,
                    )?;
                    report.escalated += 1;
                    report.outcomes.push(DispatchEntryOutcome {
                        package: entry.package.clone(),
                        outcome: "escalated".to_string(),
                        reason: "no devel project for this package".to_string(),
                        sr_id: None,
                    });
                }
                WorkerOutcome::Planned { .. } => {
                    // Dry-run: the plan (and the SR payload, when
                    // built) was logged; the entry stays pending — a
                    // dry-run changes no queue state.
                    report.planned += 1;
                    report.outcomes.push(DispatchEntryOutcome {
                        package: entry.package.clone(),
                        outcome: "planned".to_string(),
                        reason: "dry-run: plan logged, nothing filed".to_string(),
                        sr_id: None,
                    });
                }
                WorkerOutcome::Escalated { reason } => {
                    queue.escalate(&entry.package, &reason, self.dry_run)?;
                    report.escalated += 1;
                    report.outcomes.push(DispatchEntryOutcome {
                        package: entry.package.clone(),
                        outcome: "escalated".to_string(),
                        reason,
                        sr_id: None,
                    });
                }
                WorkerOutcome::Filed { sr_id, .. } => {
                    // Record the filed SR on the entry (status done)
                    // and consume one cap. The save is immediate, not
                    // only at the end of the batch: a crash after the
                    // POST must not lose the filed id.
                    queue.mark_filed(&entry.package, &sr_id, self.dry_run)?;
                    queue.save(self.dry_run)?;
                    remaining_cap = remaining_cap.saturating_sub(1);
                    report.filed += 1;
                    report.outcomes.push(DispatchEntryOutcome {
                        package: entry.package.clone(),
                        outcome: "filed".to_string(),
                        reason: format!("submit request {sr_id} filed"),
                        sr_id: Some(sr_id),
                    });
                }
            }
        }
        report.cap_remaining = remaining_cap;
        // Save the queue (a no-op in dry-run); a failed save is an
        // error (see the doc comment above).
        queue.save(self.dry_run)?;
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dry_run::DryRun;
    use crate::http::FakeHttpClient;
    use crate::obs::{search_url, ObsClient, ObsCredentials};
    use crate::queue::{DedupChecks, QueueEntry, UpdateKind};
    use crate::target::Target;
    use crate::worker::{DryRunExecutor, Execution, UpdateExecutor, UpdatePlan};
    use std::env;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_path() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!(
            "{}/freshcrab-test-dispatch-{}-{n}-{nanos}.json",
            env::temp_dir().display(),
            std::process::id()
        )
    }

    fn entry(package: &str, kind: UpdateKind) -> QueueEntry {
        QueueEntry::new(package, "1.9", "2.0", "repology", &Target::Factory, kind)
    }

    /// A canned OBS backend for `package`: a devel project, a devel
    /// spec at the given version, and an open-SR search result.
    fn http_for(package: &str, devel_version: &str, open_sr_matches: u32) -> FakeHttpClient {
        FakeHttpClient::new()
            .with(
                &format!("https://api.opensuse.org/public/source/openSUSE:Factory/{package}"),
                &format!(
                    "<directory name=\"{package}\"><devel project=\"devel:languages:python\" package=\"{package}\"/></directory>"
                ),
            )
            .with(
                &format!(
                    "https://api.opensuse.org/public/source/devel:languages:python/{package}/{package}.spec"
                ),
                &format!("Name: {package}\nVersion: {devel_version}\n"),
            )
            .with(
                &search_url(package).unwrap(),
                &format!("<collection matches=\"{open_sr_matches}\"></collection>"),
            )
    }

    /// An executor that reports the update as completed (for live-mode
    /// filing tests with a fake HTTP POST).
    struct CompletedExecutor;
    impl UpdateExecutor for CompletedExecutor {
        fn execute(&self, _plan: &UpdatePlan, _dry_run: &DryRun) -> Result<Execution, String> {
            Ok(Execution::Completed)
        }
    }

    fn config(concurrency: u32, daily_sr_cap: u32) -> Config {
        Config {
            concurrency,
            daily_sr_cap,
            ..Config::default()
        }
    }

    #[test]
    fn dispatch_dry_run_plans_and_changes_nothing() {
        let path = tmp_path();
        let mut queue = Queue::open(&path).unwrap();
        let dry = DryRun::new(true);
        queue
            .add(
                entry("foo", UpdateKind::Routine),
                DedupChecks::none(),
                &DryRun::new(false),
            )
            .unwrap();
        queue.save(&DryRun::new(false)).unwrap();
        drop(queue);

        let mut queue = Queue::open(&path).unwrap();
        let http = http_for("foo", "1.9", 0);
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        let cfg = config(4, 20);
        let dispatcher = Dispatcher::new(&worker, &cfg, &dry);
        let report = dispatcher.dispatch(&mut queue).unwrap();
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.planned, 1);
        assert_eq!(report.filed, 0);
        assert_eq!(report.skipped, 0);
        assert_eq!(report.escalated, 0);
        // Dry-run changed no queue state: the entry is still pending.
        assert_eq!(queue.find("foo").unwrap().status, "pending");
        // And nothing was posted.
        assert!(http.posted().is_empty());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn dispatch_security_first() {
        let path = tmp_path();
        let mut queue = Queue::open(&path).unwrap();
        let live = DryRun::new(false);
        // Routine first, security second — the dispatcher must still
        // take the security entry first (Queue::pending orders it).
        queue
            .add(
                entry("routine-pkg", UpdateKind::Routine),
                DedupChecks::none(),
                &live,
            )
            .unwrap();
        let sec =
            entry("sec-pkg", UpdateKind::Security).with_cves(vec!["CVE-2026-12345".to_string()]);
        queue.add(sec, DedupChecks::none(), &live).unwrap();
        queue.save(&live).unwrap();
        drop(queue);

        let mut queue = Queue::open(&path).unwrap();
        let dry = DryRun::new(true);
        let http = http_for("routine-pkg", "1.9", 0)
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/sec-pkg",
                "<directory name=\"sec-pkg\"><devel project=\"devel:languages:python\" package=\"sec-pkg\"/></directory>",
            )
            .with(
                "https://api.opensuse.org/public/source/devel:languages:python/sec-pkg/sec-pkg.spec",
                "Name: sec-pkg\nVersion: 1.9\n",
            )
            .with(
                &search_url("sec-pkg").unwrap(),
                "<collection matches=\"0\"></collection>",
            );
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        let cfg = config(4, 20);
        let dispatcher = Dispatcher::new(&worker, &cfg, &dry);
        let report = dispatcher.dispatch(&mut queue).unwrap();
        assert_eq!(report.dispatched, 2);
        assert_eq!(report.planned, 2);
        // Security first.
        assert_eq!(report.outcomes[0].package, "sec-pkg");
        assert_eq!(report.outcomes[1].package, "routine-pkg");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn dispatch_respects_concurrency() {
        let path = tmp_path();
        let mut queue = Queue::open(&path).unwrap();
        let live = DryRun::new(false);
        for pkg in ["a", "b", "c"] {
            queue
                .add(entry(pkg, UpdateKind::Routine), DedupChecks::none(), &live)
                .unwrap();
        }
        queue.save(&live).unwrap();
        drop(queue);

        let mut queue = Queue::open(&path).unwrap();
        let dry = DryRun::new(true);
        let mut http = FakeHttpClient::new();
        for pkg in ["a", "b", "c"] {
            http = http
                .with(
                    &format!("https://api.opensuse.org/public/source/openSUSE:Factory/{pkg}"),
                    &format!(
                        "<directory name=\"{pkg}\"><devel project=\"devel:languages:python\" package=\"{pkg}\"/></directory>"
                    ),
                )
                .with(
                    &format!(
                        "https://api.opensuse.org/public/source/devel:languages:python/{pkg}/{pkg}.spec"
                    ),
                    &format!("Name: {pkg}\nVersion: 1.9\n"),
                )
                .with(
                    &search_url(pkg).unwrap(),
                    "<collection matches=\"0\"></collection>",
                );
        }
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        let cfg = config(2, 20);
        let dispatcher = Dispatcher::new(&worker, &cfg, &dry);
        let report = dispatcher.dispatch(&mut queue).unwrap();
        // Concurrency 2: only two of the three entries dispatched.
        assert_eq!(report.dispatched, 2);
        assert_eq!(report.planned, 2);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn dispatch_live_files_and_consumes_cap() {
        let path = tmp_path();
        let mut queue = Queue::open(&path).unwrap();
        let live = DryRun::new(false);
        queue
            .add(
                entry("foo", UpdateKind::Routine),
                DedupChecks::none(),
                &live,
            )
            .unwrap();
        queue
            .add(
                entry("bar", UpdateKind::Routine),
                DedupChecks::none(),
                &live,
            )
            .unwrap();
        queue.save(&live).unwrap();
        drop(queue);

        let mut queue = Queue::open(&path).unwrap();
        let http = http_for("foo", "1.9", 0)
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/bar",
                "<directory name=\"bar\"><devel project=\"devel:languages:python\" package=\"bar\"/></directory>",
            )
            .with(
                "https://api.opensuse.org/public/source/devel:languages:python/bar/bar.spec",
                "Name: bar\nVersion: 1.9\n",
            )
            .with(
                &search_url("bar").unwrap(),
                "<collection matches=\"0\"></collection>",
            )
            .with_post(
                "https://api.opensuse.org/request?cmd=create",
                "<request id=\"1400001\" creator=\"scarabeus_iv\"></request>",
            );
        let obs = ObsClient::with_credentials(
            &http,
            ObsCredentials {
                username: "scarabeus_iv".to_string(),
                password: "secret".to_string(),
            },
        );
        let executor = CompletedExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &live);
        // Daily cap 1: only the first entry files; the second is skipped
        // with the cap reason.
        let cfg = config(4, 1);
        let dispatcher = Dispatcher::new(&worker, &cfg, &live);
        let report = dispatcher.dispatch(&mut queue).unwrap();
        assert_eq!(report.filed, 1);
        // The cap-exhausted entry was never attempted, so it has no
        // outcome and is not counted as skipped.
        assert_eq!(report.skipped, 0);
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.cap_remaining, 0);
        assert_eq!(report.outcomes[0].outcome, "filed");
        assert_eq!(report.outcomes[0].sr_id.as_deref(), Some("1400001"));
        // The filed entry is done with the SR id recorded; the capped
        // one is still pending.
        assert_eq!(queue.find("foo").unwrap().status, "done");
        assert_eq!(queue.find("foo").unwrap().sr_id.as_deref(), Some("1400001"));
        assert_eq!(queue.find("bar").unwrap().status, "pending");
        // The cap counts the SR filed today.
        assert_eq!(queue.srs_filed_today(), 1);
        // Exactly one POST was made.
        assert_eq!(http.posted().len(), 1);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn dispatch_skips_when_devel_already_new() {
        let path = tmp_path();
        let mut queue = Queue::open(&path).unwrap();
        let live = DryRun::new(false);
        queue
            .add(
                entry("foo", UpdateKind::Routine),
                DedupChecks::none(),
                &live,
            )
            .unwrap();
        queue.save(&live).unwrap();
        drop(queue);

        let mut queue = Queue::open(&path).unwrap();
        // Devel already at 2.0: the worker skips, the dispatcher marks
        // the entry done, and the cap is not consumed.
        let http = http_for("foo", "2.0", 0);
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &live);
        let cfg = config(4, 20);
        let dispatcher = Dispatcher::new(&worker, &cfg, &live);
        let report = dispatcher.dispatch(&mut queue).unwrap();
        assert_eq!(report.skipped, 1);
        assert_eq!(report.filed, 0);
        assert_eq!(report.cap_remaining, 20);
        assert_eq!(queue.find("foo").unwrap().status, "done");
        assert!(http.posted().is_empty());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn dispatch_recovers_stale_in_progress_entries() {
        let path = tmp_path();
        let mut queue = Queue::open(&path).unwrap();
        let live = DryRun::new(false);
        queue
            .add(
                entry("foo", UpdateKind::Routine),
                DedupChecks::none(),
                &live,
            )
            .unwrap();
        // Simulate a crash mid-dispatch: the entry was marked
        // in_progress and the run never saved its outcome.
        queue.set_status("foo", "in_progress", &live).unwrap();
        queue.save(&live).unwrap();
        drop(queue);

        let mut queue = Queue::open(&path).unwrap();
        let http = http_for("foo", "1.9", 0).with_post(
            "https://api.opensuse.org/request?cmd=create",
            "<request id=\"1400001\" creator=\"scarabeus_iv\"></request>",
        );
        let obs = ObsClient::with_credentials(
            &http,
            ObsCredentials {
                username: "scarabeus_iv".to_string(),
                password: "secret".to_string(),
            },
        );
        let executor = CompletedExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &live);
        let cfg = config(4, 20);
        let dispatcher = Dispatcher::new(&worker, &cfg, &live);
        let report = dispatcher.dispatch(&mut queue).unwrap();
        // The stranded entry was reset to pending, dispatched, and
        // filed — not lost.
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.filed, 1);
        assert_eq!(queue.find("foo").unwrap().status, "done");
        assert_eq!(queue.find("foo").unwrap().sr_id.as_deref(), Some("1400001"));
        assert_eq!(http.posted().len(), 1);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn dispatch_dry_run_does_not_recover_stale_in_progress() {
        let path = tmp_path();
        let mut queue = Queue::open(&path).unwrap();
        let live = DryRun::new(false);
        queue
            .add(
                entry("foo", UpdateKind::Routine),
                DedupChecks::none(),
                &live,
            )
            .unwrap();
        queue.set_status("foo", "in_progress", &live).unwrap();
        queue.save(&live).unwrap();
        drop(queue);

        // Dry-run: the reset is a would-do only — the entry stays
        // in_progress in the file and is not dispatched.
        let mut queue = Queue::open(&path).unwrap();
        let dry = DryRun::new(true);
        let http = http_for("foo", "1.9", 0);
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        let cfg = config(4, 20);
        let dispatcher = Dispatcher::new(&worker, &cfg, &dry);
        let report = dispatcher.dispatch(&mut queue).unwrap();
        assert_eq!(report.dispatched, 0);
        assert_eq!(queue.find("foo").unwrap().status, "in_progress");
        assert!(dry
            .plan()
            .iter()
            .any(|l| l.contains("set foo status to pending")));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn dispatch_dedup_recheck_error_escalates_with_persisted_reason() {
        let path = tmp_path();
        let mut queue = Queue::open(&path).unwrap();
        let live = DryRun::new(false);
        queue
            .add(
                entry("foo", UpdateKind::Routine),
                DedupChecks::none(),
                &live,
            )
            .unwrap();
        queue.save(&live).unwrap();
        drop(queue);

        // Dispatch-time dedup re-check fails: the devel project
        // resolves, but the spec fetch has no canned response, so the
        // worker escalates fail-closed — and the dispatcher persists
        // the reason on the entry instead of only printing it.
        let mut queue = Queue::open(&path).unwrap();
        let http = FakeHttpClient::new().with(
            "https://api.opensuse.org/public/source/openSUSE:Factory/foo",
            "<directory name=\"foo\"><devel project=\"devel:languages:python\" package=\"foo\"/></directory>",
        );
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &live);
        let cfg = config(4, 20);
        let dispatcher = Dispatcher::new(&worker, &cfg, &live);
        let report = dispatcher.dispatch(&mut queue).unwrap();
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.escalated, 1);
        let found = queue.find("foo").unwrap();
        assert_eq!(found.status, "escalated");
        assert!(found
            .escalation_reason
            .as_deref()
            .unwrap_or_default()
            .contains("devel version check failed"));
        assert!(found.escalated_at.is_some());
        // The reason survives a save + reload.
        queue.save(&live).unwrap();
        drop(queue);
        let queue = Queue::open(&path).unwrap();
        let found = queue.find("foo").unwrap();
        assert_eq!(found.status, "escalated");
        assert!(found
            .escalation_reason
            .as_deref()
            .unwrap_or_default()
            .contains("devel version check failed"));
        drop(queue);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn dispatch_open_sr_recheck_error_escalates() {
        let path = tmp_path();
        let mut queue = Queue::open(&path).unwrap();
        let live = DryRun::new(false);
        queue
            .add(
                entry("foo", UpdateKind::Routine),
                DedupChecks::none(),
                &live,
            )
            .unwrap();
        queue.save(&live).unwrap();
        drop(queue);

        // The devel version check passes, but the open-SR search fails
        // (no canned response) — escalate fail-closed.
        let mut queue = Queue::open(&path).unwrap();
        let http = FakeHttpClient::new()
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo",
                "<directory name=\"foo\"><devel project=\"devel:languages:python\" package=\"foo\"/></directory>",
            )
            .with(
                "https://api.opensuse.org/public/source/devel:languages:python/foo/foo.spec",
                "Name: foo\nVersion: 1.9\n",
            );
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &live);
        let cfg = config(4, 20);
        let dispatcher = Dispatcher::new(&worker, &cfg, &live);
        let report = dispatcher.dispatch(&mut queue).unwrap();
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.escalated, 1);
        let found = queue.find("foo").unwrap();
        assert_eq!(found.status, "escalated");
        assert!(found
            .escalation_reason
            .as_deref()
            .unwrap_or_default()
            .contains("open-SR check failed"));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn dispatch_cap_zero_dispatches_nothing() {
        let path = tmp_path();
        let mut queue = Queue::open(&path).unwrap();
        let live = DryRun::new(false);
        queue
            .add(
                entry("foo", UpdateKind::Routine),
                DedupChecks::none(),
                &live,
            )
            .unwrap();
        queue.save(&live).unwrap();
        drop(queue);

        let mut queue = Queue::open(&path).unwrap();
        let dry = DryRun::new(true);
        let http = http_for("foo", "1.9", 0);
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        let cfg = config(4, 0);
        let dispatcher = Dispatcher::new(&worker, &cfg, &dry);
        let report = dispatcher.dispatch(&mut queue).unwrap();
        assert_eq!(report.dispatched, 0);
        assert_eq!(report.filed, 0);
        assert_eq!(report.outcomes.len(), 0);
        assert_eq!(report.cap_remaining, 0);
        assert_eq!(queue.find("foo").unwrap().status, "pending");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn dispatch_cap_already_reached_dispatches_nothing() {
        let path = tmp_path();
        let mut queue = Queue::open(&path).unwrap();
        let live = DryRun::new(false);
        queue
            .add(
                entry("foo", UpdateKind::Routine),
                DedupChecks::none(),
                &live,
            )
            .unwrap();
        queue
            .add(
                entry("bar", UpdateKind::Routine),
                DedupChecks::none(),
                &live,
            )
            .unwrap();
        // One SR already filed today: the cap (1) is exhausted before
        // this run starts.
        queue.mark_filed("foo", "1400001", &live).unwrap();
        queue.save(&live).unwrap();
        drop(queue);

        let mut queue = Queue::open(&path).unwrap();
        let dry = DryRun::new(true);
        let http = http_for("bar", "1.9", 0);
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        let cfg = config(4, 1);
        let dispatcher = Dispatcher::new(&worker, &cfg, &dry);
        let report = dispatcher.dispatch(&mut queue).unwrap();
        assert_eq!(report.dispatched, 0);
        assert_eq!(report.outcomes.len(), 0);
        assert_eq!(report.cap_remaining, 0);
        assert_eq!(queue.find("bar").unwrap().status, "pending");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn dispatch_live_filing_failure_escalates() {
        let path = tmp_path();
        let mut queue = Queue::open(&path).unwrap();
        let live = DryRun::new(false);
        queue
            .add(
                entry("foo", UpdateKind::Routine),
                DedupChecks::none(),
                &live,
            )
            .unwrap();
        queue.save(&live).unwrap();
        drop(queue);

        // Live mode, executor completes, but the filing POST fails (no
        // canned POST response = transport error): the worker escalates,
        // and the dispatcher persists the reason — the entry is not
        // marked done and carries no SR id.
        let mut queue = Queue::open(&path).unwrap();
        let http = http_for("foo", "1.9", 0);
        let obs = ObsClient::with_credentials(
            &http,
            ObsCredentials {
                username: "scarabeus_iv".to_string(),
                password: "secret".to_string(),
            },
        );
        let executor = CompletedExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &live);
        let cfg = config(4, 20);
        let dispatcher = Dispatcher::new(&worker, &cfg, &live);
        let report = dispatcher.dispatch(&mut queue).unwrap();
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.escalated, 1);
        assert_eq!(report.filed, 0);
        let found = queue.find("foo").unwrap();
        assert_eq!(found.status, "escalated");
        assert_eq!(found.sr_id, None);
        assert!(found
            .escalation_reason
            .as_deref()
            .unwrap_or_default()
            .contains("SR filing failed"));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn dispatch_unicode_package_name_escalates() {
        let path = tmp_path();
        let mut queue = Queue::open(&path).unwrap();
        let live = DryRun::new(false);
        queue
            .add(
                entry("föö", UpdateKind::Routine),
                DedupChecks::none(),
                &live,
            )
            .unwrap();
        queue.save(&live).unwrap();
        drop(queue);

        // A non-ASCII package name is not a valid OBS name: the
        // worker's devel lookup rejects it and the entry escalates
        // instead of reaching the network with a bad name.
        let mut queue = Queue::open(&path).unwrap();
        let http = FakeHttpClient::new();
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &live);
        let cfg = config(4, 20);
        let dispatcher = Dispatcher::new(&worker, &cfg, &live);
        let report = dispatcher.dispatch(&mut queue).unwrap();
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.escalated, 1);
        assert_eq!(queue.find("föö").unwrap().status, "escalated");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{path}.lock"));
    }
}
