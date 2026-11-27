//! Integration tests for the review queue: discovery end to end
//! against a fake pull-request source, persistence, dry-run.

use freshcrab::config::Config;
use freshcrab::dry_run::DryRun;
use freshcrab::queue::{QueueEntry, UpdateKind};
use freshcrab::review_queue::{
    classify_records, comment_on, discover_on, own_sr_ids, request_changes_on, ReviewBinding,
    ReviewQueue, ReviewRecord, Ruleset,
};
use freshcrab::target::Target;
use geectl::error::{ErrorKind, GeectlError};
use geectl::pull_request::{
    PullRequest, PullRequestBackend, PullRequestEndpoint, PullRequestRef, PullRequestSearch,
    PullRequestStatus, PullRequestSummary, ReviewComment, ReviewOpinion,
};
use std::cell::{Cell, RefCell};
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

/// A recorded request-changes call: ref, message, commit pin.
type RequestedChange = (String, Option<String>, Option<String>);

struct FakeSource {
    search_results: Vec<PullRequestSummary>,
    show_answers: Vec<(String, Result<PullRequest, GeectlError>)>,
    posted_comments: RefCell<Vec<(String, ReviewComment)>>,
    next_comment_id: Cell<u64>,
    requested_changes: RefCell<Vec<RequestedChange>>,
}

impl FakeSource {
    fn new(search_results: Vec<PullRequestSummary>) -> Self {
        FakeSource {
            search_results,
            show_answers: Vec::new(),
            posted_comments: RefCell::new(Vec::new()),
            next_comment_id: Cell::new(0),
            requested_changes: RefCell::new(Vec::new()),
        }
    }

    fn with_show(mut self, reference: &str, answer: PullRequest) -> Self {
        self.show_answers.push((reference.to_string(), Ok(answer)));
        self
    }

    /// The comments this fake posted, as (ref, comment) pairs,
    /// in posting order.
    fn posted(&self) -> Vec<(String, ReviewComment)> {
        self.posted_comments.borrow().clone()
    }

    /// The request-changes calls this fake served, as (ref,
    /// message, commit) in call order.
    fn requested(&self) -> Vec<RequestedChange> {
        self.requested_changes.borrow().clone()
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

    fn maintainers(
        &self,
        project: &str,
        package: &str,
    ) -> Result<Vec<geectl::obs::NamedRole>, GeectlError> {
        Err(GeectlError::new(
            ErrorKind::NotFound,
            format!("fake source has no maintainers answer for {project}/{package}"),
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
        Ok(self
            .posted_comments
            .borrow()
            .iter()
            .filter(|(stored, _)| *stored == key)
            .map(|(_, comment)| comment.clone())
            .collect())
    }

    fn request_changes(
        &self,
        reference: &PullRequestRef,
        message: Option<&str>,
        commit: Option<&str>,
        dry_run: &geectl::obs::DryRun,
    ) -> Result<Option<ReviewOpinion>, GeectlError> {
        if dry_run.enabled() {
            return Ok(None);
        }
        self.requested_changes.borrow_mut().push((
            reference.to_string(),
            message.map(str::to_string),
            commit.map(str::to_string),
        ));
        Ok(Some(ReviewOpinion {
            reviewer: "freshcrab".to_string(),
            state: geectl::pull_request::OpinionState::ChangesRequested,
            comment: message.unwrap_or_default().to_string(),
            when: None,
        }))
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

#[test]
fn comment_stage_posts_once_across_runs() {
    let path = tmp_path("comment");
    let live_run = live();
    {
        let mut queue = ReviewQueue::open(&path).unwrap();
        queue.upsert(ReviewRecord::new(
            "obs:42", "default", "obs", "bump foo", "someone", None,
        ));
        // A clean all-green bump snapshot, as JSON: the readers
        // are covered by the unit tests; this test drives the
        // classify-then-comment path end to end.
        let snapshot = serde_json::json!({
            "read_at": "0",
            "build": {"status": "all_green", "cells": [], "target_status": "all_green"},
            "review": {"state": "none", "reviews": []},
            "diff": {
                "files": ["foo.spec", "foo.changes"],
                "spec_changed": true,
                "version_bump_only": true,
                "patches_changed": false,
                "new_files": [],
                "changelog_changed": true,
                "new_version": "2.0",
                "cve_ids": []
            },
            "author": {"author": "someone", "is_own_filing": false, "is_package_maintainer": true},
            "package": {"package": "foo", "is_excluded": false, "is_security": false, "cve_ids": []},
            "server": {"status": "open", "draft": false, "mergeable": null},
            "read_errors": []
        });
        queue.set_signal_snapshot("default", "obs:42", snapshot);
        queue.save(&live_run).unwrap();
    }
    classify_records("review_ruleset.json", &path, &live_run).unwrap();
    let ruleset = Ruleset::load("review_ruleset.json").unwrap();
    let source = FakeSource::new(vec![]);
    {
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
        assert_eq!(queue.find("default", "obs:42").unwrap().status, "actioned");
        queue.save(&live_run).unwrap();
    }
    {
        // A second run over the unchanged snapshot posts nothing.
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
        assert_eq!(report.skipped_unchanged, 1);
        assert_eq!(source.posted().len(), 1);
        queue.save(&live_run).unwrap();
    }
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(format!("{path}.lock"));
}

#[test]
fn request_changes_stage_posts_once_across_runs() {
    let path = tmp_path("request");
    let ruleset_path = tmp_path("reject-ruleset");
    let live_run = live();
    // A ruleset whose one rule matches the clean bump snapshot
    // and yields `request-changes`: the driver acts on the
    // decided action, and the rule exists only so the test can
    // drive it — no shipped rule yields `request-changes` yet.
    fs::write(
        &ruleset_path,
        r#"{"version": "9", "rules": [{"name": "test-reject", "when": [{"path": "diff.files", "op": "contains", "value": "foo.spec"}], "action": "request-changes", "message": "The test rule matches.", "question": "Why does the test rule match?"}]}"#,
    )
    .unwrap();
    {
        let mut queue = ReviewQueue::open(&path).unwrap();
        queue.upsert(ReviewRecord::new(
            "obs:42",
            "default",
            "obs",
            "bump foo",
            "someone",
            Some(ReviewBinding {
                source_repository: "home:alice/foo".to_string(),
                source_commit: Some("srcmd5".to_string()),
                target_repository: "devel:foo/foo".to_string(),
                target_commit: Some("targetmd5".to_string()),
            }),
        ));
        // A clean all-green bump snapshot, as JSON (the same
        // shape as the comment-stage test).
        let snapshot = serde_json::json!({
            "read_at": "0",
            "build": {"status": "all_green", "cells": [], "target_status": "all_green"},
            "review": {"state": "none", "reviews": []},
            "diff": {
                "files": ["foo.spec", "foo.changes"],
                "spec_changed": true,
                "version_bump_only": true,
                "patches_changed": false,
                "new_files": [],
                "changelog_changed": true,
                "new_version": "2.0",
                "cve_ids": []
            },
            "author": {"author": "someone", "is_own_filing": false, "is_package_maintainer": true},
            "package": {"package": "foo", "is_excluded": false, "is_security": false, "cve_ids": []},
            "server": {"status": "open", "draft": false, "mergeable": null},
            "read_errors": []
        });
        queue.set_signal_snapshot("default", "obs:42", snapshot);
        queue.save(&live_run).unwrap();
    }
    classify_records(&ruleset_path, &path, &live_run).unwrap();
    let ruleset = Ruleset::load(&ruleset_path).unwrap();
    let show = PullRequest {
        reference: PullRequestRef::Obs(42),
        title: "bump foo".to_string(),
        description: String::new(),
        author: "someone".to_string(),
        status: PullRequestStatus::Open,
        draft: false,
        merged: false,
        mergeable: None,
        merge_base: None,
        source: PullRequestEndpoint {
            repository: "home:alice/foo".to_string(),
            branch: None,
            commit: Some("srcmd5".to_string()),
        },
        target: PullRequestEndpoint {
            repository: "devel:foo/foo".to_string(),
            branch: None,
            commit: Some("targetmd5".to_string()),
        },
        reviews: Vec::new(),
        reviews_error: None,
        labels: Vec::new(),
    };
    let source = FakeSource::new(vec![]).with_show("obs:42", show);
    {
        let mut queue = ReviewQueue::open(&path).unwrap();
        assert_eq!(
            queue.find("default", "obs:42").unwrap().action.as_deref(),
            Some("request-changes")
        );
        let report = request_changes_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &mut queue,
            &live_run,
            &ruleset,
        );
        assert_eq!(report.requested, 1);
        assert_eq!(source.requested().len(), 1);
        assert_eq!(source.requested()[0].0, "obs:42");
        // OBS takes no commit pin.
        assert_eq!(source.requested()[0].2, None);
        assert_eq!(queue.find("default", "obs:42").unwrap().status, "actioned");
        queue.save(&live_run).unwrap();
    }
    {
        // A second run over the unchanged snapshot requests
        // nothing.
        let mut queue = ReviewQueue::open(&path).unwrap();
        let report = request_changes_on(
            &source,
            PullRequestBackend::Obs,
            "default",
            &mut queue,
            &live_run,
            &ruleset,
        );
        assert_eq!(report.requested, 0);
        assert_eq!(report.skipped_unchanged, 1);
        assert_eq!(source.requested().len(), 1);
        queue.save(&live_run).unwrap();
    }
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(format!("{path}.lock"));
    let _ = fs::remove_file(&ruleset_path);
}
