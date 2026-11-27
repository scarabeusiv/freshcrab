//! Integration tests for the project-hygiene sweeps (issue #22):
//! the obsolete-platforms sweep and the long-broken sweep, both
//! report-only, over canned OBS responses through geectl's client.
//!
//! These tests pin freshcrab's side of the seam — the sweep logic
//! over geectl's parsed types — not geectl's parsers or URL building,
//! which geectl tests itself. The request-search URL is a literal
//! (geectl builds it; the test only needs the key to can a response
//! under), and the canned XML is fixture input, not a re-test of
//! geectl's parsing.

use freshcrab::http::FakeHttpClient;
use freshcrab::hygiene::{
    run_hygiene, sweep_long_broken, sweep_obsolete_repositories, BROKEN_DURATION_SECS,
};
use geectl::auth::Credentials;
use geectl::obs::ObsClient;

const PROJECT: &str = "devel:languages:python";
const FACTORY: &str = "openSUSE:Factory";
const NOW: u64 = 1_800_000_000;
const CUTOFF: u64 = NOW - BROKEN_DURATION_SECS;

fn obs_with_creds(http: &FakeHttpClient) -> ObsClient<'_> {
    ObsClient::with_credentials(
        http,
        Credentials::Basic {
            username: "scarabeus_iv".to_string(),
            password: "secret".to_string(),
        },
    )
    .unwrap()
}

fn meta_url(project: &str) -> String {
    format!("https://api.opensuse.org/source/{project}/_meta")
}

fn list_url(project: &str) -> String {
    format!("https://api.opensuse.org/public/source/{project}")
}

fn results_url(project: &str) -> String {
    format!("https://api.opensuse.org/build/{project}/_result")
}

fn jobhist_url(project: &str, repo: &str, arch: &str, package: &str) -> String {
    format!(
        "https://api.opensuse.org/build/{project}/{repo}/{arch}/_jobhistory?package={package}&limit=200"
    )
}

/// The OBS search URL for accepted submit requests with `package` as
/// a source. A literal: the query is
/// `source[@package='...'] and state[@name='accepted'] and
/// action[@type='submit']`, and the package names used here need no
/// percent-encoding. Geectl builds this URL; the test only needs the
/// key to can a response under.
fn search_url_for(package: &str) -> String {
    format!(
        "https://api.opensuse.org/search/request?match=source%5B%40package%3D%27{package}%27%5D%20and%20state%5B%40name%3D%27accepted%27%5D%20and%20action%5B%40type%3D%27submit%27%5D"
    )
}

/// A repository in a project meta document: (name, architectures,
/// paths as (project, repository) pairs).
type RepoSpec<'a> = (&'a str, &'a [&'a str], &'a [(&'a str, &'a str)]);

/// A project meta document: (repository, architectures, paths).
fn meta_xml(name: &str, repos: &[RepoSpec]) -> String {
    let mut out = format!("<project name=\"{name}\">");
    for (repo, arches, paths) in repos {
        out.push_str(&format!("<repository name=\"{repo}\">"));
        for (path_project, path_repo) in *paths {
            out.push_str(&format!(
                "<path project=\"{path_project}\" repository=\"{path_repo}\"/>"
            ));
        }
        for arch in *arches {
            out.push_str(&format!("<arch>{arch}</arch>"));
        }
        out.push_str("</repository>");
    }
    out.push_str("</project>");
    out
}

/// A build-results cell: (repository, arch, [(package, code)]).
type ResultCell<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)]);

/// A build-results document: (repository, arch, [(package, code)]).
fn results_xml(cells: &[ResultCell]) -> String {
    let mut out = String::from("<resultlist state=\"abc\">");
    for (repo, arch, statuses) in cells {
        out.push_str(&format!(
            "<result project=\"{PROJECT}\" repository=\"{repo}\" arch=\"{arch}\" code=\"published\" state=\"published\">"
        ));
        for (package, code) in *statuses {
            out.push_str(&format!("<status package=\"{package}\" code=\"{code}\"/>"));
        }
        out.push_str("</result>");
    }
    out.push_str("</resultlist>");
    out
}

/// A job-history document: (code, endtime) pairs, newest first.
fn jobhist_xml(jobs: &[(&str, u64)]) -> String {
    let mut out = String::from("<jobhistlist>");
    for (code, endtime) in jobs {
        out.push_str(&format!(
            "<jobhist repository=\"r\" arch=\"x86_64\" package=\"p\" endtime=\"{endtime}\" code=\"{code}\"/>"
        ));
    }
    out.push_str("</jobhistlist>");
    out
}

fn directory_xml(packages: &[&str]) -> String {
    let mut out = String::from("<directory>");
    for package in packages {
        out.push_str(&format!("<entry name=\"{package}\"/>"));
    }
    out.push_str("</directory>");
    out
}

/// An accepted submit request from `source_project` for `package`.
fn accepted_request_xml(id: u64, source_project: &str, package: &str) -> String {
    format!(
        "<collection matches=\"1\"><request id=\"{id}\" creator=\"scarabeus_iv\"><action type=\"submit\"><source project=\"{source_project}\" package=\"{package}\"/><target project=\"{PROJECT}\" package=\"{package}\"/></action><state name=\"accepted\" who=\"factory-auto\" when=\"2026-01-01T00:00:00\"/></request></collection>"
    )
}

fn empty_collection() -> String {
    "<collection matches=\"0\"></collection>".to_string()
}

fn project_meta() -> String {
    meta_xml(
        PROJECT,
        &[
            (
                "openSUSE_Tumbleweed",
                &["x86_64"],
                &[("openSUSE:Factory", "standard")],
            ),
            (
                "openSUSE_Leap_15.6",
                &["x86_64"],
                &[("openSUSE:Leap:15.6", "standard")],
            ),
        ],
    )
}

#[test]
fn obsolete_sweep_flags_missing_target_project_and_repository() {
    let http = FakeHttpClient::new()
        .with(
            &meta_url(PROJECT),
            &meta_xml(
                PROJECT,
                &[
                    (
                        "openSUSE_Tumbleweed",
                        &["x86_64"],
                        &[("openSUSE:Factory", "standard")],
                    ),
                    (
                        "openSUSE_Leap_15.6",
                        &["x86_64"],
                        &[("openSUSE:Leap:15.6", "standard")],
                    ),
                    (
                        "openSUSE_Leap_15.5",
                        &["x86_64"],
                        &[("openSUSE:Leap:15.5", "standard")],
                    ),
                    (
                        "SLE_15_SP5",
                        &["x86_64"],
                        &[("SUSE:SLE-15-SP5:Update", "standard")],
                    ),
                ],
            ),
        )
        .with(
            &meta_url("openSUSE:Factory"),
            &meta_xml("openSUSE:Factory", &[("standard", &["x86_64"], &[])]),
        )
        .with(
            &meta_url("openSUSE:Leap:15.6"),
            &meta_xml("openSUSE:Leap:15.6", &[("standard", &["x86_64"], &[])]),
        )
        .with_status(&meta_url("openSUSE:Leap:15.5"), 404, "")
        .with(
            &meta_url("SUSE:SLE-15-SP5:Update"),
            &meta_xml("SUSE:SLE-15-SP5:Update", &[("update", &["x86_64"], &[])]),
        );
    let obs = obs_with_creds(&http);
    let findings = sweep_obsolete_repositories(&obs, PROJECT).unwrap();
    assert_eq!(findings.len(), 2);
    let by_repo = |repo: &str| {
        findings
            .iter()
            .find(|f| f.repository == repo)
            .unwrap_or_else(|| panic!("no finding for repository {repo}"))
    };
    // The missing target project.
    let missing_project = by_repo("openSUSE_Leap_15.5");
    assert_eq!(missing_project.path_project, "openSUSE:Leap:15.5");
    assert_eq!(missing_project.reason, "target project does not exist");
    // The target project exists but carries no such repository.
    let missing_repo = by_repo("SLE_15_SP5");
    assert_eq!(missing_repo.path_project, "SUSE:SLE-15-SP5:Update");
    assert_eq!(
        missing_repo.reason,
        "target repository does not exist in target project"
    );
    // Report-only: nothing was posted.
    assert!(http.posted().is_empty());
}

#[test]
fn long_broken_lists_only_sustained_never_integrated() {
    // foo: devel-only, fails on Leap (counts) with no success in the
    // threshold, never integrated -> listed. Its Tumbleweed failure
    // does not count and is never history-checked: there is no canned
    // Tumbleweed job history for foo, so a call there would fail.
    // bar: fails on Tumbleweed but builds on Leap -> not listed.
    // baz: fails everywhere that counts but succeeded recently ->
    // not listed.
    let http = FakeHttpClient::new()
        .with(&list_url(FACTORY), &directory_xml(&["bar"]))
        .with(&list_url(PROJECT), &directory_xml(&["foo", "bar", "baz"]))
        .with(&meta_url(PROJECT), &project_meta())
        .with(
            &results_url(PROJECT),
            &results_xml(&[
                (
                    "openSUSE_Tumbleweed",
                    "x86_64",
                    &[("foo", "failed"), ("bar", "failed"), ("baz", "failed")],
                ),
                (
                    "openSUSE_Leap_15.6",
                    "x86_64",
                    &[("foo", "failed"), ("bar", "succeeded"), ("baz", "failed")],
                ),
            ]),
        )
        .with(
            &jobhist_url(PROJECT, "openSUSE_Leap_15.6", "x86_64", "foo"),
            &jobhist_xml(&[("failed", CUTOFF + 1000), ("failed", CUTOFF - 1000)]),
        )
        .with(
            &jobhist_url(PROJECT, "openSUSE_Leap_15.6", "x86_64", "baz"),
            &jobhist_xml(&[("succeeded", CUTOFF + 1000), ("failed", CUTOFF - 1000)]),
        )
        .with(&search_url_for("foo"), &empty_collection());
    let obs = obs_with_creds(&http);
    let broken = sweep_long_broken(&obs, PROJECT, NOW).unwrap();
    assert_eq!(broken.len(), 1);
    assert_eq!(broken[0].package, "foo");
    assert!(!broken[0].in_factory);
    assert_eq!(broken[0].failures.len(), 1);
    assert_eq!(broken[0].failures[0].repository, "openSUSE_Leap_15.6");
    assert_eq!(broken[0].failures[0].codes, vec!["failed"]);
    assert_eq!(broken[0].failures[0].last_success_unix, None);
    assert!(http.posted().is_empty());
}

#[test]
fn tumbleweed_counts_for_a_factory_package() {
    // qux is in Factory, so Tumbleweed counts: failing on both
    // repositories with no success in the threshold lists it with
    // both repositories as evidence.
    let http = FakeHttpClient::new()
        .with(&list_url(FACTORY), &directory_xml(&["qux"]))
        .with(&list_url(PROJECT), &directory_xml(&["qux"]))
        .with(&meta_url(PROJECT), &project_meta())
        .with(
            &results_url(PROJECT),
            &results_xml(&[
                ("openSUSE_Tumbleweed", "x86_64", &[("qux", "failed")]),
                ("openSUSE_Leap_15.6", "x86_64", &[("qux", "unresolvable")]),
            ]),
        )
        .with(
            &jobhist_url(PROJECT, "openSUSE_Tumbleweed", "x86_64", "qux"),
            &jobhist_xml(&[("failed", CUTOFF + 1000), ("failed", CUTOFF - 1000)]),
        )
        .with(
            &jobhist_url(PROJECT, "openSUSE_Leap_15.6", "x86_64", "qux"),
            &jobhist_xml(&[("failed", CUTOFF - 1000)]),
        )
        .with(&search_url_for("qux"), &empty_collection());
    let obs = obs_with_creds(&http);
    let broken = sweep_long_broken(&obs, PROJECT, NOW).unwrap();
    assert_eq!(broken.len(), 1);
    assert_eq!(broken[0].package, "qux");
    assert!(broken[0].in_factory);
    assert_eq!(broken[0].failures.len(), 2);
    assert_eq!(broken[0].failures[0].repository, "openSUSE_Tumbleweed");
    assert_eq!(broken[0].failures[1].repository, "openSUSE_Leap_15.6");
    assert_eq!(broken[0].failures[1].codes, vec!["unresolvable"]);
    assert!(http.posted().is_empty());
}

#[test]
fn accepted_request_from_the_project_excludes_but_another_project_does_not() {
    // quux: an accepted submit request from a branch of the project
    // integrated it -> not listed. corge: the only accepted request
    // comes from another project -> still never integrated -> listed.
    let http = FakeHttpClient::new()
        .with(&list_url(FACTORY), &directory_xml(&[]))
        .with(&list_url(PROJECT), &directory_xml(&["quux", "corge"]))
        .with(&meta_url(PROJECT), &project_meta())
        .with(
            &results_url(PROJECT),
            &results_xml(&[
                (
                    "openSUSE_Tumbleweed",
                    "x86_64",
                    &[("quux", "failed"), ("corge", "failed")],
                ),
                (
                    "openSUSE_Leap_15.6",
                    "x86_64",
                    &[("quux", "failed"), ("corge", "failed")],
                ),
            ]),
        )
        .with(
            &jobhist_url(PROJECT, "openSUSE_Leap_15.6", "x86_64", "quux"),
            &jobhist_xml(&[("failed", CUTOFF - 1000)]),
        )
        .with(
            &jobhist_url(PROJECT, "openSUSE_Leap_15.6", "x86_64", "corge"),
            &jobhist_xml(&[("failed", CUTOFF - 1000)]),
        )
        .with(
            &search_url_for("quux"),
            &accepted_request_xml(
                1400001,
                "home:scarabeus_iv:branches:devel:languages:python",
                "quux",
            ),
        )
        .with(
            &search_url_for("corge"),
            &accepted_request_xml(1400002, "devel:languages:ruby", "corge"),
        );
    let obs = obs_with_creds(&http);
    let broken = sweep_long_broken(&obs, PROJECT, NOW).unwrap();
    assert_eq!(broken.len(), 1);
    assert_eq!(broken[0].package, "corge");
    assert!(!broken[0].in_factory);
    assert!(http.posted().is_empty());
}

#[test]
fn sweeps_without_credentials_fail_closed() {
    let http = FakeHttpClient::new();
    let obs = ObsClient::new(&http);
    let err = sweep_obsolete_repositories(&obs, PROJECT).unwrap_err();
    assert_eq!(err.kind(), geectl::error::ErrorKind::ConfigError);
    let err = sweep_long_broken(&obs, PROJECT, NOW).unwrap_err();
    assert_eq!(err.kind(), geectl::error::ErrorKind::ConfigError);
}

#[test]
fn run_hygiene_reports_both_sweeps_per_project() {
    let http = FakeHttpClient::new()
        .with(
            &meta_url(PROJECT),
            &meta_xml(
                PROJECT,
                &[
                    (
                        "openSUSE_Tumbleweed",
                        &["x86_64"],
                        &[("openSUSE:Factory", "standard")],
                    ),
                    (
                        "openSUSE_Leap_15.5",
                        &["x86_64"],
                        &[("openSUSE:Leap:15.5", "standard")],
                    ),
                ],
            ),
        )
        .with(
            &meta_url("openSUSE:Factory"),
            &meta_xml("openSUSE:Factory", &[("standard", &["x86_64"], &[])]),
        )
        .with_status(&meta_url("openSUSE:Leap:15.5"), 404, "")
        .with(&list_url(FACTORY), &directory_xml(&[]))
        .with(&list_url(PROJECT), &directory_xml(&["foo"]))
        .with(
            &results_url(PROJECT),
            &results_xml(&[
                ("openSUSE_Tumbleweed", "x86_64", &[("foo", "failed")]),
                ("openSUSE_Leap_15.5", "x86_64", &[("foo", "failed")]),
            ]),
        )
        .with(
            &jobhist_url(PROJECT, "openSUSE_Leap_15.5", "x86_64", "foo"),
            &jobhist_xml(&[("failed", CUTOFF - 1000)]),
        )
        .with(&search_url_for("foo"), &empty_collection());
    let obs = obs_with_creds(&http);
    let report = run_hygiene(&obs, &[PROJECT.to_string()], NOW).unwrap();
    assert_eq!(report.projects.len(), 1);
    assert_eq!(report.projects[0].project, PROJECT);
    assert_eq!(report.projects[0].obsolete_repositories.len(), 1);
    assert_eq!(report.projects[0].long_broken_packages.len(), 1);
    assert_eq!(report.projects[0].long_broken_packages[0].package, "foo");
    assert!(http.posted().is_empty());
}
