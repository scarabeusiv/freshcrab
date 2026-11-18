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
use crate::dry_run::DryRun;
use crate::factory::FactoryClient;
use crate::http::{HttpClient, HttpError};
use crate::version::is_newer;
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
}

impl QueueEntry {
    pub fn new(package: &str, factory_version: &str, upstream_version: &str, source: &str) -> Self {
        QueueEntry {
            package: package.to_string(),
            factory_version: factory_version.to_string(),
            upstream_version: upstream_version.to_string(),
            source: source.to_string(),
            status: "pending".to_string(),
        }
    }
}

/// The watcher. It holds the HTTP client (collectors are built per
/// package, because PyPI needs the mapped PyPI name), the Factory client,
/// an optional upstream checker for direct confirmation, and the dry-run
/// mode (in dry-run it prints what it WOULD queue and writes nothing).
pub struct Watcher<'a> {
    http: &'a dyn HttpClient,
    factory: FactoryClient<'a>,
    upstream: Option<Box<dyn UpstreamChecker + 'a>>,
    dry_run: &'a DryRun,
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
        }
    }

    /// Check one package. Returns a QueueEntry, or None when it is up to
    /// date, unconfirmed, or when a version is unavailable. In dry-run,
    /// prints what it WOULD queue and returns the entry (the caller
    /// decides whether to persist it; the queue also consults dry-run).
    pub fn check_package(&self, package: &str) -> Result<Option<QueueEntry>, HttpError> {
        let collectors = collectors_for(self.http, package);
        let candidates = crate::collectors::collect(package, &collectors);
        let upstream_ref = self.upstream.as_deref();
        let candidate = match confirmed_candidate(&candidates, upstream_ref, package) {
            Some(candidate) => candidate,
            None => return Ok(None),
        };
        let upstream_version = candidate.version.clone();

        let factory_version = match self.factory.get_version(package)? {
            Some(version) => version,
            None => return Ok(None),
        };

        if is_newer(&upstream_version, &factory_version) {
            let entry = QueueEntry::new(
                package,
                &factory_version,
                &upstream_version,
                candidate.collector,
            );
            self.dry_run.note(&format!(
                "would queue: {} {} -> {} (source: {})",
                entry.package, entry.factory_version, entry.upstream_version, entry.source
            ));
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    /// Check a list of packages. Returns the queue entries found.
    pub fn check_packages(&self, packages: &[&str]) -> Result<Vec<QueueEntry>, HttpError> {
        let mut entries = Vec::new();
        for package in packages {
            if let Some(entry) = self.check_package(package)? {
                entries.push(entry);
            }
        }
        Ok(entries)
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
                r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}]"#,
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
                r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}]"#,
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
                r#"[{"repo": "fedora_41", "version": "1.0~rc1", "status": "newest"}]"#,
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
                r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}]"#,
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
                r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}]"#,
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
}
