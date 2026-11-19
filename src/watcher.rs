//! Watcher: find Factory packages that are behind their upstream release.
//!
//! For each package in scope, the watcher queries the collectors in
//! priority order (Repology, Anitya, PyPI for Python packages,
//! Distrowatch), confirms the candidate version (see
//! `crate::collectors::confirmed_candidate`), compares it against the
//! Factory version with proper RPM version comparison, and emits a queue
//! entry when the upstream version is newer. Report-only by default: it
//! queues and reports, and files nothing.
//!
//! In dry-run mode the watcher still polls the collectors (reads are not
//! gated) and prints exactly what it WOULD queue — package, Factory
//! version, newest upstream version, collector source — and writes
//! nothing to the queue.

use crate::collectors::upstream::UpstreamChecker;
use crate::collectors::{confirmed_candidate, pypi_name, Candidate, Collector};
use crate::cve::CveValidator;
use crate::dry_run::DryRun;
use crate::factory::FactoryClient;
use crate::http::{HttpClient, HttpError};
use crate::queue::UpdateKind;
use crate::target::{FactoryPolicy, Target, UpdatePolicy};
use serde::Serialize;

/// A package that is behind its upstream release and needs an update.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct QueueEntry {
    pub package: String,
    pub factory_version: String,
    pub upstream_version: String,
    /// The collector that confirmed the upstream version.
    pub source: String,
    pub status: String,
    /// The distribution this update is for.
    pub target: Target,
    /// Routine version bump or security (CVE-driven) update.
    pub kind: UpdateKind,
}

impl QueueEntry {
    pub fn new(package: &str, factory_version: &str, upstream_version: &str, source: &str) -> Self {
        QueueEntry {
            package: package.to_string(),
            factory_version: factory_version.to_string(),
            upstream_version: upstream_version.to_string(),
            source: source.to_string(),
            status: "pending".to_string(),
            target: Target::Factory,
            kind: UpdateKind::Routine,
        }
    }
}

/// The watcher. It holds the HTTP client (collectors are built per
/// package, because PyPI needs the mapped PyPI name), the Factory client,
/// an optional upstream checker for direct confirmation, and the dry-run
/// mode (in dry-run it prints what it WOULD queue and writes nothing).
///
/// The target, the update policy, and the CVE validator are extension
/// points for the Leap step (see `docs/leap-and-cve.md`): the target
/// defaults to Factory, the policy defaults to the Factory version
/// comparison, and there is no CVE validator. A Leap watcher will be
/// built with `with_target` / `with_policy` / `with_cve_validator`.
pub struct Watcher<'a> {
    http: &'a dyn HttpClient,
    factory: FactoryClient<'a>,
    upstream: Option<Box<dyn UpstreamChecker + 'a>>,
    dry_run: &'a DryRun,
    target: Target,
    policy: Box<dyn UpdatePolicy + 'a>,
    /// The CVE validator, consulted only for non-Factory targets
    /// (Leap). The Factory path never calls it, so it is unread until
    /// the Leap step lands — the dead-code lint is silenced deliberately
    /// (it is the Leap extension point, not dead code).
    #[allow(dead_code)]
    cve_validator: Option<Box<dyn CveValidator + 'a>>,
}

impl<'a> Watcher<'a> {
    pub fn new(
        http: &'a dyn HttpClient,
        factory: FactoryClient<'a>,
        upstream: Option<Box<dyn UpstreamChecker + 'a>>,
        dry_run: &'a DryRun,
    ) -> Self {
        Watcher {
            http,
            factory,
            upstream,
            dry_run,
            target: Target::Factory,
            policy: Box::new(FactoryPolicy),
            cve_validator: None,
        }
    }

    /// Set the distribution target (Factory by default). Only Factory is
    /// implemented; a Leap target here is for the later Leap step.
    pub fn with_target(mut self, target: Target) -> Self {
        self.target = target;
        self
    }

    /// Replace the update policy (Factory version comparison by
    /// default). The Leap step plugs in a backport-aware policy here.
    pub fn with_policy(mut self, policy: Box<dyn UpdatePolicy + 'a>) -> Self {
        self.policy = policy;
        self
    }

    /// Attach a CVE validator. It is consulted only for non-Factory
    /// targets (Leap): for Factory the version comparison alone
    /// decides, so the Factory path never calls a validator.
    pub fn with_cve_validator(mut self, validator: Box<dyn CveValidator + 'a>) -> Self {
        self.cve_validator = Some(validator);
        self
    }

    /// Check one package. Returns a QueueEntry, or None when it is up to
    /// date, unconfirmed, or when a version is unavailable. In dry-run,
    /// prints what it WOULD queue and returns the entry (the caller
    /// decides whether to persist it; the queue also consults dry-run).
    pub fn check_package(&self, package: &str) -> Result<Option<QueueEntry>, HttpError> {
        // Leap targets are not implemented yet: fail loudly before any
        // network I/O, so no rate-limited collector requests are burned
        // (and no package names disclosed) for a target that will be
        // refused. The Leap step consults the CVE validator here (see
        // `docs/leap-and-cve.md`) to decide whether a CVE is already
        // fixed by a backport. The Factory path never reaches this
        // branch, so it never calls a validator.
        if self.target.is_leap() {
            return Err(HttpError(
                "Leap targets are not implemented yet (see docs/leap-and-cve.md)".to_string(),
            ));
        }

        // Fetch the Factory version first: when the spec is unavailable
        // (404), the collector calls below are wasted work.
        let factory_version = match self.factory.get_version(package)? {
            Some(version) => version,
            None => return Ok(None),
        };

        let collectors = collectors_for(self.http, package);
        let candidates = crate::collectors::collect(package, &collectors);
        let upstream_ref = self.upstream.as_deref();
        let candidate = match confirmed_candidate(&candidates, upstream_ref, package) {
            Some(candidate) => candidate,
            None => return Ok(None),
        };
        let upstream_version = candidate.version.clone();

        if self
            .policy
            .needs_update(&factory_version, &upstream_version)
        {
            let mut entry = QueueEntry::new(
                package,
                &factory_version,
                &upstream_version,
                candidate.collector,
            );
            entry.target = self.target.clone();
            let kind_suffix = match entry.kind {
                UpdateKind::Security => " (security)",
                UpdateKind::Routine => "",
            };
            self.dry_run.note(&format!(
                "would queue: {} {} -> {} (source: {}){}",
                entry.package,
                entry.factory_version,
                entry.upstream_version,
                entry.source,
                kind_suffix
            ));
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    /// Check a list of packages. Returns the queue entries found. A
    /// package whose check fails (e.g. the Factory spec 404s) is logged
    /// and skipped; one bad package no longer aborts the whole run.
    pub fn check_packages(&self, packages: &[&str]) -> Vec<QueueEntry> {
        let mut entries = Vec::new();
        for package in packages {
            match self.check_package(package) {
                Ok(Some(entry)) => entries.push(entry),
                Ok(None) => {}
                Err(e) => {
                    eprintln!("warning: check failed for {package}: {e}; skipping");
                }
            }
        }
        entries
    }
}

/// Build the collector list for one package, in priority order. The PyPI
/// collector is only included for Python packages, with the PyPI name.
pub fn collectors_for<'a>(http: &'a dyn HttpClient, package: &str) -> Vec<Box<dyn Collector + 'a>> {
    let mut collectors: Vec<Box<dyn Collector + 'a>> = vec![
        Box::new(crate::collectors::repology::RepologyCollector::new(http)),
        Box::new(crate::collectors::anitya::AnityaCollector::new(http)),
    ];
    if let Some(pypi) = pypi_name(package) {
        // The PyPI collector queries by PyPI name; bind it to the mapped
        // name (the OBS name differs).
        collectors.push(Box::new(PypiByName {
            http,
            pypi_name: pypi,
        }));
    }
    collectors.push(Box::new(
        crate::collectors::distrowatch::DistrowatchCollector::new(http),
    ));
    collectors
}

/// A PyPI collector bound to a fixed PyPI name (the OBS name differs).
struct PypiByName<'a> {
    http: &'a dyn HttpClient,
    pypi_name: String,
}

impl<'a> Collector for PypiByName<'a> {
    fn name(&self) -> &'static str {
        "pypi"
    }

    fn latest_version(&self, _package: &str) -> Result<Option<Candidate>, HttpError> {
        let inner = crate::collectors::pypi::PypiCollector::new(self.http);
        inner.latest_version(&self.pypi_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::FakeHttpClient;

    fn watcher_with_http(
        http: &'static dyn HttpClient,
        dry_run: &'static DryRun,
    ) -> Watcher<'static> {
        Watcher::new(http, FactoryClient::new(http), None, dry_run)
    }

    fn live() -> &'static DryRun {
        Box::leak(Box::new(DryRun::new(false)))
    }

    fn dry() -> &'static DryRun {
        Box::leak(Box::new(DryRun::new(true)))
    }

    #[test]
    fn check_package_behind_is_queued() {
        let http = FakeHttpClient::new()
            .with(
                "https://repology.org/api/v1/project/foo",
                r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}, {"repo": "debian_12", "version": "2.0", "status": "newest"}]"#,
            )
            .with(
                "https://release-monitoring.org/api/v2/projects/?name=foo",
                r#"{"items": []}"#,
            )
            .with(
                "https://distrowatch.com/table.php?distribution=opensuse",
                "<html></html>",
            )
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo/foo.spec",
                "Name: foo\nVersion: 1.9\n",
            );
        let http: &'static dyn HttpClient = Box::leak(Box::new(http));
        let watcher = watcher_with_http(http, live());
        let entry = watcher.check_package("foo").unwrap().unwrap();
        assert_eq!(entry.package, "foo");
        assert_eq!(entry.factory_version, "1.9");
        assert_eq!(entry.upstream_version, "2.0");
    }

    #[test]
    fn check_package_up_to_date_is_not_queued() {
        let http = FakeHttpClient::new()
            .with(
                "https://repology.org/api/v1/project/foo",
                r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}, {"repo": "debian_12", "version": "2.0", "status": "newest"}]"#,
            )
            .with(
                "https://release-monitoring.org/api/v2/projects/?name=foo",
                r#"{"items": []}"#,
            )
            .with(
                "https://distrowatch.com/table.php?distribution=opensuse",
                "<html></html>",
            )
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo/foo.spec",
                "Name: foo\nVersion: 2.0\n",
            );
        let http: &'static dyn HttpClient = Box::leak(Box::new(http));
        let watcher = watcher_with_http(http, live());
        assert!(watcher.check_package("foo").unwrap().is_none());
    }

    #[test]
    fn check_package_distrowatch_only_is_not_queued() {
        // Distrowatch alone (not multi-source, no second collector, no
        // upstream check) does not confirm.
        let http = FakeHttpClient::new()
            .with("https://repology.org/api/v1/project/foo", "[]")
            .with(
                "https://release-monitoring.org/api/v2/projects/?name=foo",
                r#"{"items": []}"#,
            )
            .with(
                "https://distrowatch.com/table.php?distribution=opensuse",
                "<table><tr><td>foo</td><td>2.0</td></tr></table>",
            )
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo/foo.spec",
                "Name: foo\nVersion: 1.9\n",
            );
        let http: &'static dyn HttpClient = Box::leak(Box::new(http));
        let watcher = watcher_with_http(http, live());
        assert!(watcher.check_package("foo").unwrap().is_none());
    }

    #[test]
    fn check_package_tilde_prerelease_is_not_newer() {
        let http = FakeHttpClient::new()
            .with(
                "https://repology.org/api/v1/project/foo",
                r#"[{"repo": "fedora_41", "version": "1.0~rc1", "status": "newest"}, {"repo": "debian_12", "version": "1.0~rc1", "status": "newest"}]"#,
            )
            .with(
                "https://release-monitoring.org/api/v2/projects/?name=foo",
                r#"{"items": []}"#,
            )
            .with(
                "https://distrowatch.com/table.php?distribution=opensuse",
                "<html></html>",
            )
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo/foo.spec",
                "Name: foo\nVersion: 1.0\n",
            );
        let http: &'static dyn HttpClient = Box::leak(Box::new(http));
        let watcher = watcher_with_http(http, live());
        assert!(watcher.check_package("foo").unwrap().is_none());
    }

    #[test]
    fn dry_run_prints_would_queue_plan_with_source() {
        // In dry-run the watcher still polls the collectors and prints
        // exactly what it WOULD queue (package, versions, source).
        let dry_run = dry();
        let http = FakeHttpClient::new()
            .with(
                "https://repology.org/api/v1/project/foo",
                r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}, {"repo": "debian_12", "version": "2.0", "status": "newest"}]"#,
            )
            .with(
                "https://release-monitoring.org/api/v2/projects/?name=foo",
                r#"{"items": []}"#,
            )
            .with(
                "https://distrowatch.com/table.php?distribution=opensuse",
                "<html></html>",
            )
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo/foo.spec",
                "Name: foo\nVersion: 1.9\n",
            );
        let http: &'static dyn HttpClient = Box::leak(Box::new(http));
        let watcher = watcher_with_http(http, dry_run);
        let entry = watcher.check_package("foo").unwrap().unwrap();
        assert_eq!(entry.source, "repology");
        assert_eq!(
            dry_run.plan(),
            vec!["[dry-run] would queue: foo 1.9 -> 2.0 (source: repology)"]
        );
    }

    #[test]
    fn live_mode_records_no_plan() {
        let dry_run = live();
        let http = FakeHttpClient::new()
            .with(
                "https://repology.org/api/v1/project/foo",
                r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}, {"repo": "debian_12", "version": "2.0", "status": "newest"}]"#,
            )
            .with(
                "https://release-monitoring.org/api/v2/projects/?name=foo",
                r#"{"items": []}"#,
            )
            .with(
                "https://distrowatch.com/table.php?distribution=opensuse",
                "<html></html>",
            )
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo/foo.spec",
                "Name: foo\nVersion: 1.9\n",
            );
        let http: &'static dyn HttpClient = Box::leak(Box::new(http));
        let watcher = watcher_with_http(http, dry_run);
        assert!(watcher.check_package("foo").unwrap().is_some());
        assert!(dry_run.plan().is_empty());
    }

    #[test]
    fn check_package_entry_carries_factory_target_and_routine_kind() {
        let http = FakeHttpClient::new()
            .with(
                "https://repology.org/api/v1/project/foo",
                r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}, {"repo": "debian_12", "version": "2.0", "status": "newest"}]"#,
            )
            .with(
                "https://release-monitoring.org/api/v2/projects/?name=foo",
                r#"{"items": []}"#,
            )
            .with(
                "https://distrowatch.com/table.php?distribution=opensuse",
                "<html></html>",
            )
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo/foo.spec",
                "Name: foo\nVersion: 1.9\n",
            );
        let http: &'static dyn HttpClient = Box::leak(Box::new(http));
        let watcher = watcher_with_http(http, live());
        let entry = watcher.check_package("foo").unwrap().unwrap();
        assert_eq!(entry.target, Target::Factory);
        assert_eq!(entry.kind, UpdateKind::Routine);
    }

    /// A policy that always says an update is needed.
    struct AlwaysUpdate;

    impl UpdatePolicy for AlwaysUpdate {
        fn needs_update(&self, _current: &str, _candidate: &str) -> bool {
            true
        }
    }

    /// A policy that never says an update is needed.
    struct NeverUpdate;

    impl UpdatePolicy for NeverUpdate {
        fn needs_update(&self, _current: &str, _candidate: &str) -> bool {
            false
        }
    }

    fn watcher_with_policy(
        http: &'static dyn HttpClient,
        dry_run: &'static DryRun,
        policy: Box<dyn UpdatePolicy + 'static>,
    ) -> Watcher<'static> {
        Watcher::new(http, FactoryClient::new(http), None, dry_run).with_policy(policy)
    }

    #[test]
    fn custom_policy_is_honoured() {
        // An up-to-date package is queued when the policy says so, and
        // a behind package is not queued when the policy says otherwise:
        // the version comparison is behind the policy hook.
        let http = FakeHttpClient::new()
            .with(
                "https://repology.org/api/v1/project/foo",
                r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}, {"repo": "debian_12", "version": "2.0", "status": "newest"}]"#,
            )
            .with(
                "https://release-monitoring.org/api/v2/projects/?name=foo",
                r#"{"items": []}"#,
            )
            .with(
                "https://distrowatch.com/table.php?distribution=opensuse",
                "<html></html>",
            )
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo/foo.spec",
                "Name: foo\nVersion: 2.0\n",
            );
        let http: &'static dyn HttpClient = Box::leak(Box::new(http));
        let watcher = watcher_with_policy(http, live(), Box::new(AlwaysUpdate));
        assert!(watcher.check_package("foo").unwrap().is_some());
        let watcher = watcher_with_policy(http, live(), Box::new(NeverUpdate));
        assert!(watcher.check_package("foo").unwrap().is_none());
    }

    /// A validator that panics if called: the Factory path must never
    /// call a CVE validator, so attaching one must not change the
    /// Factory outcome.
    struct PanickingValidator;

    impl CveValidator for PanickingValidator {
        fn validate(
            &self,
            _package: &str,
            _version: &str,
            _cve: &crate::cve::CveId,
        ) -> Result<crate::cve::CveValidation, crate::cve::CveError> {
            panic!("CVE validator must not be called on the Factory path")
        }

        fn has_regression_test(
            &self,
            _package: &str,
            _version: &str,
            _cve: &crate::cve::CveId,
        ) -> Result<bool, crate::cve::CveError> {
            panic!("CVE validator must not be called on the Factory path")
        }
    }

    #[test]
    fn factory_path_does_not_call_cve_validator() {
        let http = FakeHttpClient::new()
            .with(
                "https://repology.org/api/v1/project/foo",
                r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}, {"repo": "debian_12", "version": "2.0", "status": "newest"}]"#,
            )
            .with(
                "https://release-monitoring.org/api/v2/projects/?name=foo",
                r#"{"items": []}"#,
            )
            .with(
                "https://distrowatch.com/table.php?distribution=opensuse",
                "<html></html>",
            )
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo/foo.spec",
                "Name: foo\nVersion: 1.9\n",
            );
        let http: &'static dyn HttpClient = Box::leak(Box::new(http));
        let watcher =
            watcher_with_http(http, live()).with_cve_validator(Box::new(PanickingValidator));
        // Would panic if the Factory path consulted the validator.
        let entry = watcher.check_package("foo").unwrap().unwrap();
        assert_eq!(entry.package, "foo");
    }

    #[test]
    fn leap_target_fails_loudly() {
        let http = FakeHttpClient::new()
            .with(
                "https://repology.org/api/v1/project/foo",
                r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}, {"repo": "debian_12", "version": "2.0", "status": "newest"}]"#,
            )
            .with(
                "https://release-monitoring.org/api/v2/projects/?name=foo",
                r#"{"items": []}"#,
            )
            .with(
                "https://distrowatch.com/table.php?distribution=opensuse",
                "<html></html>",
            )
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo/foo.spec",
                "Name: foo\nVersion: 1.9\n",
            );
        let http: &'static dyn HttpClient = Box::leak(Box::new(http));
        let watcher = watcher_with_http(http, live()).with_target(Target::Leap {
            version: "16.0".to_string(),
        });
        let err = watcher.check_package("foo").unwrap_err();
        assert!(err.0.contains("not implemented"));
    }

    #[test]
    fn single_anitya_only_is_not_queued() {
        // A single non-multi-source collector (Anitya alone) does not
        // confirm: it needs a second collector agreeing or an upstream
        // check.
        let http = FakeHttpClient::new()
            .with("https://repology.org/api/v1/project/foo", "[]")
            .with(
                "https://release-monitoring.org/api/v2/projects/?name=foo",
                r#"{"items": [{"name": "foo", "version": "2.0"}]}"#,
            )
            .with(
                "https://distrowatch.com/table.php?distribution=opensuse",
                "<html></html>",
            )
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo/foo.spec",
                "Name: foo\nVersion: 1.9\n",
            );
        let http: &'static dyn HttpClient = Box::leak(Box::new(http));
        let watcher = watcher_with_http(http, live());
        assert!(watcher.check_package("foo").unwrap().is_none());
    }

    #[test]
    fn check_packages_skips_failed_package_and_continues() {
        // One bad package (its Factory spec is unavailable) is logged
        // and skipped; the good package behind it is still checked.
        // "bad" has no canned spec URL, so its check errors; "good"
        // has every URL canned.
        let http = FakeHttpClient::new()
            .with(
                "https://repology.org/api/v1/project/good",
                r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}, {"repo": "debian_12", "version": "2.0", "status": "newest"}]"#,
            )
            .with(
                "https://release-monitoring.org/api/v2/projects/?name=good",
                r#"{"items": []}"#,
            )
            .with(
                "https://distrowatch.com/table.php?distribution=opensuse",
                "<html></html>",
            )
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/good/good.spec",
                "Name: good\nVersion: 1.9\n",
            );
        let http: &'static dyn HttpClient = Box::leak(Box::new(http));
        let watcher = watcher_with_http(http, live());
        let entries = watcher.check_packages(&["bad", "good"]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].package, "good");
    }
}
