//! Integration tests for the watcher, using canned fixtures (no live
//! network). The fixtures live in tests/fixtures/.

use freshcrab::dry_run::DryRun;
use freshcrab::factory::FactoryClient;
use freshcrab::http::FakeHttpClient;
use freshcrab::watcher::Watcher;
use std::fs;

fn fixture(name: &str) -> String {
    fs::read_to_string(format!("tests/fixtures/{name}")).unwrap()
}

fn watcher_for(foo_spec_version: &str, distrowatch_html: &str) -> Watcher<'static> {
    let repology = r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}]"#;
    let http = FakeHttpClient::new()
        .with("https://repology.org/api/v1/project/foo", repology)
        .with(
            "https://release-monitoring.org/api/v2/projects/?name=foo",
            r#"{"items": []}"#,
        )
        .with(
            "https://distrowatch.com/table.php?distribution=opensuse",
            distrowatch_html,
        )
        .with(
            "https://api.opensuse.org/public/source/openSUSE:Factory/foo/foo.spec",
            &format!("Name: foo\nVersion: {foo_spec_version}\n"),
        );
    let http: &'static dyn freshcrab::http::HttpClient = Box::leak(Box::new(http));
    let dry_run: &'static DryRun = Box::leak(Box::new(DryRun::new(false)));
    Watcher::new(http, FactoryClient::new(http), None, dry_run)
}

#[test]
fn behind_on_factory_is_queued() {
    let distrowatch = fixture("distrowatch-opensuse.html");
    let watcher = watcher_for("1.9", &distrowatch);
    let entry = watcher.check_package("foo").unwrap().unwrap();
    assert_eq!(entry.package, "foo");
    assert_eq!(entry.factory_version, "1.9");
    assert_eq!(entry.upstream_version, "2.0");
    assert_eq!(entry.source, "repology");
}

#[test]
fn up_to_date_is_not_queued() {
    let distrowatch = fixture("distrowatch-opensuse.html");
    let watcher = watcher_for("2.0", &distrowatch);
    assert!(watcher.check_package("foo").unwrap().is_none());
}

#[test]
fn distrowatch_fixture_parses() {
    // The fixture lists foo 2.0, bar 1.0, baz 3.0~rc1.
    let html = fixture("distrowatch-opensuse.html");
    let candidate =
        freshcrab::collectors::distrowatch::parse_distrowatch_page(&html, "foo").unwrap();
    assert_eq!(candidate.version, "2.0");
    assert!(freshcrab::collectors::distrowatch::parse_distrowatch_page(&html, "qux").is_none());
}

#[test]
fn repology_fixture_newest_wins() {
    let body = fixture("repology-foo.json");
    let candidate = freshcrab::collectors::repology::parse_repology_response(&body).unwrap();
    assert_eq!(candidate.version, "2.0");
    assert!(candidate.multi_source);
}

#[test]
fn anitya_fixture_version() {
    let body = fixture("anitya-foo.json");
    let candidate = freshcrab::collectors::anitya::parse_anitya_response(&body).unwrap();
    assert_eq!(candidate.version, "2.0");
}

#[test]
fn pypi_fixture_version() {
    let body = fixture("pypi-requests.json");
    let candidate = freshcrab::collectors::pypi::parse_pypi_response(&body).unwrap();
    assert_eq!(candidate.version, "2.32.3");
}

#[test]
fn dry_run_watcher_prints_would_queue_and_writes_nothing() {
    // In dry-run the watcher still polls the collectors and prints what it
    // WOULD queue; the queue state is untouched (there is no queue file
    // here at all — the watcher never writes one).
    let dry_run = DryRun::new(true);
    let repology = r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}]"#;
    let http = FakeHttpClient::new()
        .with("https://repology.org/api/v1/project/foo", repology)
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
    let http: &'static dyn freshcrab::http::HttpClient = Box::leak(Box::new(http));
    let dry_run: &'static DryRun = Box::leak(Box::new(dry_run));
    let watcher = Watcher::new(http, FactoryClient::new(http), None, dry_run);
    let entry = watcher.check_package("foo").unwrap().unwrap();
    assert_eq!(entry.source, "repology");
    assert_eq!(
        dry_run.plan(),
        vec!["[dry-run] would queue: foo 1.9 -> 2.0 (source: repology)"]
    );
}
