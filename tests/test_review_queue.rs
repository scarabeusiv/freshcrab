//! Integration tests for the review queue: discovery end to end
//! against a fake pull-request source, persistence, dry-run.

use freshcrab::config::Config;
use freshcrab::dry_run::DryRun;
use freshcrab::queue::{QueueEntry, UpdateKind};
use freshcrab::review_queue::{discover_on, own_sr_ids, ReviewQueue, ReviewRecord};
use freshcrab::target::Target;
use geectl::error::{ErrorKind, GeectlError};
use geectl::pull_request::{
    PullRequest, PullRequestBackend, PullRequestEndpoint, PullRequestRef, PullRequestSearch,
    PullRequestStatus, PullRequestSummary,
};
use std::env;
use std::fs;
use std::path::Path;
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

fn dry() -> DryRun {
    DryRun::new(true)
}

fn live() -> DryRun {
    DryRun::new(false)
}

fn test_config() -> Config {
    Config {
        packages: Vec::new(),
        exclusions: vec!["gcc".to_string()],
        ..Config::default()
    }
}

struct FakeSource {
    search_results: Vec<PullRequestSummary>,
    show_answers: Vec<(String, Result<PullRequest, GeectlError>)>,
}

impl FakeSource {
    fn new(search_results: Vec<PullRequestSummary>) -> Self {
        FakeSource {
            search_results,
            show_answers: Vec::new(),
        }
    }

    fn with_show(mut self, reference: &str, answer: PullRequest) -> Self {
        self.show_answers.push((reference.to_string(), Ok(answer)));
        self
    }
}

impl freshcrab::review_queue::PullRequestSource for FakeSource {
    fn search(&self, _query: &PullRequestSearch) -> Result<Vec<PullRequestSummary>, GeectlError> {
        Ok(self.search_results.clone())
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
        Err(GeectlError::new(
            ErrorKind::NotFound,
            format!("fake source has no diff answer for {reference}"),
        ))
    }

    fn build_results(
        &self,
        project: &str,
        package: &str,
    ) -> Result<geectl::obs::BuildResults, GeectlError> {
        Err(GeectlError::new(
            ErrorKind::NotFound,
            format!("fake source has no build answer for {project}/{package}"),
        ))
    }
}

fn summary(reference: PullRequestRef, target_repository: &str) -> PullRequestSummary {
    PullRequestSummary {
        reference,
        title: "bump foo".to_string(),
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

fn fake_pr(reference: PullRequestRef, status: PullRequestStatus) -> PullRequest {
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
            repository: "devel:foo/foo".to_string(),
            commit: Some("targetmd5".to_string()),
            ..PullRequestEndpoint::default()
        },
        reviews: Vec::new(),
        reviews_error: None,
        labels: Vec::new(),
    }
}

#[test]
fn discovery_persists_and_reloads() {
    let path = tmp_path("persist");
    let live_run = live();
    {
        let mut queue = ReviewQueue::open(&path).unwrap();
        let config = test_config();
        let source = FakeSource::new(vec![summary(PullRequestRef::Obs(42), "devel:foo/foo")]);
        let report = discover_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &config,
            &[],
            &mut queue,
            &dry(),
        );
        assert_eq!(report.new_records, 1);
        queue.save(&live_run).unwrap();
    }
    let queue = ReviewQueue::open(&path).unwrap();
    let record = queue.find("default", "obs:42").unwrap();
    assert_eq!(record.status, "open");
    assert_eq!(record.title, "bump foo");
    assert_eq!(record.grace_periods.package_maintainer_days, 7);
    let binding = record.binding.as_ref().unwrap();
    assert_eq!(binding.target_repository, "devel:foo/foo");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(format!("{path}.lock"));
}

#[test]
fn discovery_in_dry_run_writes_nothing() {
    let path = tmp_path("dryrun");
    let dry_run = dry();
    let mut queue = ReviewQueue::open(&path).unwrap();
    let config = test_config();
    let source = FakeSource::new(vec![summary(PullRequestRef::Obs(43), "devel:foo/foo")]);
    let report = discover_on(
        &source,
        PullRequestBackend::Obs,
        "default",
        &config,
        &[],
        &mut queue,
        &dry_run,
    );
    assert_eq!(report.new_records, 1);
    queue.save(&dry_run).unwrap();
    assert!(!Path::new(&path).exists());
    let _ = fs::remove_file(format!("{path}.lock"));
}

#[test]
fn discovery_marks_merged_records_terminal_across_runs() {
    let path = tmp_path("terminal");
    let live_run = live();
    let config = test_config();
    {
        let mut queue = ReviewQueue::open(&path).unwrap();
        let source = FakeSource::new(vec![summary(PullRequestRef::Obs(44), "devel:foo/foo")]);
        discover_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &config,
            &[],
            &mut queue,
            &dry(),
        );
        queue.save(&live_run).unwrap();
    }
    {
        let mut queue = ReviewQueue::open(&path).unwrap();
        // The second run sees no open submissions; the re-check
        // shows the ref merged and marks it terminal.
        let source = FakeSource::new(vec![]).with_show(
            "obs:44",
            fake_pr(PullRequestRef::Obs(44), PullRequestStatus::Merged),
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
        queue.save(&live_run).unwrap();
    }
    let queue = ReviewQueue::open(&path).unwrap();
    assert_eq!(queue.find("default", "obs:44").unwrap().status, "terminal");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(format!("{path}.lock"));
}

#[test]
fn own_sr_ids_from_update_queue_entries() {
    let mut foo = QueueEntry::new(
        "foo",
        "1.0",
        "2.0",
        "repology",
        &Target::Factory,
        UpdateKind::Routine,
    );
    foo.sr_id = Some("123".to_string());
    let bar = QueueEntry::new(
        "bar",
        "1.0",
        "2.0",
        "repology",
        &Target::Factory,
        UpdateKind::Routine,
    );
    assert_eq!(own_sr_ids(&[foo, bar]), vec![123]);
}

#[test]
fn records_from_two_instances_do_not_collide() {
    let path = tmp_path("instances");
    let mut queue = ReviewQueue::open(&path).unwrap();
    assert!(queue.upsert(ReviewRecord::new(
        "obs:1", "default", "obs", "one", "a", None
    )));
    assert!(queue.upsert(ReviewRecord::new(
        "obs:1", "staging", "obs", "one", "a", None
    )));
    assert_eq!(queue.entries().len(), 2);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(format!("{path}.lock"));
}
