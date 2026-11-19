//! Repology collector (primary).
//!
//! Repology aggregates package versions across hundreds of distros and
//! upstreams. Endpoint: `GET /api/v1/project/<name>` returns a JSON array
//! of packages with `repo`, `version`, and `status` (one of `newest`,
//! `devel`, `unique`, `outdated`, `legacy`, `rolling`, `noscheme`,
//! `incorrect`, `untrusted`, `ignored`).
//!
//! The collector takes the highest version (by RPM comparison) among
//! entries with status `newest`, but only when at least two distinct
//! repos report that version: `newest` is a max, not a consensus, so
//! one inflated repo entry must not confirm on its own. A single
//! `newest` repo returns the candidate as not-multi-source, so the
//! confirmation rule falls through to agreement with another collector
//! or to the direct upstream check. When no entry is `newest`, it falls
//! back to the highest version among release statuses (`unique`,
//! `outdated`, `legacy`, `rolling`). Development, incorrect, untrusted,
//! and ignored entries are never used.
//!
//! Rate limit: 1 request per second. Every request identifies itself with
//! a User-Agent linking to the project repository (see `crate::http`).

use crate::collectors::{encode_path, Candidate, Collector};
use crate::http::{HttpClient, HttpError};
use crate::version::rpmvercmp;
use serde::Deserialize;
use std::cell::Cell;
use std::time::{Duration, Instant};

/// The Repology rate limit: 1 request per second.
pub const MIN_INTERVAL: Duration = Duration::from_secs(1);

pub const REPOLOGY_API: &str = "https://repology.org/api/v1";

/// Statuses that denote a real release (used for the fallback max).
const RELEASE_STATUSES: &[&str] = &["newest", "unique", "outdated", "legacy", "rolling"];

#[derive(Debug, Deserialize)]
struct RepologyPackage {
    #[serde(default)]
    repo: String,
    version: String,
    #[serde(default)]
    status: String,
}

/// Parse a Repology `/api/v1/project/<name>` response. Returns the newest
/// version, or None when there is no usable release entry.
pub fn parse_repology_response(body: &str) -> Option<Candidate> {
    let packages: Vec<RepologyPackage> = serde_json::from_str(body).ok()?;
    if packages.is_empty() {
        return None;
    }

    // Prefer the highest version among `newest` entries — but only
    // when at least two distinct repos report that version. A single
    // `newest` entry is a max, not a consensus: one inflated repo entry
    // must not confirm on its own. With a single newest repo the
    // candidate is returned as not-multi-source, so the confirmation
    // rule falls through to agreement with another collector or to the
    // direct upstream check.
    let newest: Vec<&RepologyPackage> = packages.iter().filter(|p| p.status == "newest").collect();
    if let Some(best) = max_version(&newest) {
        let repos: std::collections::HashSet<&str> = newest
            .iter()
            .filter(|p| rpmvercmp(&p.version, &best) == std::cmp::Ordering::Equal)
            .map(|p| p.repo.as_str())
            .collect();
        return Some(Candidate {
            collector: "repology",
            version: best,
            multi_source: repos.len() >= 2,
        });
    }

    // Fallback: highest version among release statuses.
    let release: Vec<&RepologyPackage> = packages
        .iter()
        .filter(|p| RELEASE_STATUSES.contains(&p.status.as_str()))
        .collect();
    max_version(&release).map(|version| Candidate {
        collector: "repology",
        version,
        multi_source: false,
    })
}

/// The highest version (by RPM comparison) in the list, or None.
fn max_version(packages: &[&RepologyPackage]) -> Option<String> {
    packages
        .iter()
        .map(|p| p.version.clone())
        .max_by(|a, b| rpmvercmp(a, b))
}

pub struct RepologyCollector<'a> {
    http: &'a dyn HttpClient,
    min_interval: Duration,
    last_request: Cell<Option<Instant>>,
}

impl<'a> RepologyCollector<'a> {
    /// A collector that paces requests to the Repology rate limit
    /// (1 request per second).
    pub fn new(http: &'a dyn HttpClient) -> Self {
        RepologyCollector {
            http,
            min_interval: MIN_INTERVAL,
            last_request: Cell::new(None),
        }
    }

    /// A collector with a custom minimum interval between requests (used
    /// by the tests to disable pacing).
    pub fn with_interval(http: &'a dyn HttpClient, min_interval: Duration) -> Self {
        RepologyCollector {
            http,
            min_interval,
            last_request: Cell::new(None),
        }
    }

    /// Sleep until `min_interval` has passed since the last request.
    fn pace(&self) {
        if let Some(last) = self.last_request.get() {
            let elapsed = last.elapsed();
            if elapsed < self.min_interval {
                std::thread::sleep(self.min_interval - elapsed);
            }
        }
        self.last_request.set(Some(Instant::now()));
    }
}

impl<'a> Collector for RepologyCollector<'a> {
    fn name(&self) -> &'static str {
        "repology"
    }

    fn latest_version(&self, package: &str) -> Result<Option<Candidate>, HttpError> {
        self.pace();
        let url = format!("{REPOLOGY_API}/project/{}", encode_path(package));
        let body = self.http.get(&url)?;
        Ok(parse_repology_response(&body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"[
        {"repo": "opensuse_tumbleweed", "version": "1.9", "status": "outdated"},
        {"repo": "fedora_41", "version": "2.0", "status": "newest"},
        {"repo": "debian_12", "version": "2.0", "status": "newest"},
        {"repo": "arch", "version": "2.1", "status": "devel"},
        {"repo": "gentoo", "version": "0.5", "status": "incorrect"}
    ]"#;

    #[test]
    fn newest_wins_over_outdated() {
        let candidate = parse_repology_response(FIXTURE).unwrap();
        assert_eq!(candidate.version, "2.0");
        assert!(candidate.multi_source);
        assert_eq!(candidate.collector, "repology");
    }

    #[test]
    fn devel_and_incorrect_are_ignored() {
        // 2.1 is `devel` and 0.5 is `incorrect`; neither may win.
        let candidate = parse_repology_response(FIXTURE).unwrap();
        assert_ne!(candidate.version, "2.1");
        assert_ne!(candidate.version, "0.5");
    }

    #[test]
    fn fallback_to_release_max_when_no_newest() {
        let body = r#"[
            {"repo": "opensuse_tumbleweed", "version": "1.9", "status": "outdated"},
            {"repo": "debian_12", "version": "1.10", "status": "outdated"}
        ]"#;
        let candidate = parse_repology_response(body).unwrap();
        // 1.10 > 1.9 by RPM comparison (not lexicographic).
        assert_eq!(candidate.version, "1.10");
        assert!(!candidate.multi_source);
    }

    #[test]
    fn empty_response_is_none() {
        assert!(parse_repology_response("[]").is_none());
    }

    #[test]
    fn single_newest_repo_does_not_confirm() {
        // Hostile: one repo at `newest` is a max, not a consensus.
        // The candidate is returned, but not multi-source, so the
        // confirmation rule falls through to agreement / upstream.
        let body = r#"[
            {"repo": "opensuse_tumbleweed", "version": "1.9", "status": "outdated"},
            {"repo": "fedora_41", "version": "2.0", "status": "newest"}
        ]"#;
        let candidate = parse_repology_response(body).unwrap();
        assert_eq!(candidate.version, "2.0");
        assert!(!candidate.multi_source);
    }

    #[test]
    fn two_newest_repos_confirm() {
        // Two distinct repos at the same `newest` version: multi-source.
        let body = r#"[
            {"repo": "fedora_41", "version": "2.0", "status": "newest"},
            {"repo": "debian_12", "version": "2.0", "status": "newest"}
        ]"#;
        let candidate = parse_repology_response(body).unwrap();
        assert_eq!(candidate.version, "2.0");
        assert!(candidate.multi_source);
    }

    #[test]
    fn two_newest_repos_at_different_versions_do_not_confirm() {
        // Two `newest` entries, but only one repo at the max version:
        // still a single source for the max.
        let body = r#"[
            {"repo": "fedora_41", "version": "2.0", "status": "newest"},
            {"repo": "debian_12", "version": "1.9", "status": "newest"}
        ]"#;
        let candidate = parse_repology_response(body).unwrap();
        assert_eq!(candidate.version, "2.0");
        assert!(!candidate.multi_source);
    }

    #[test]
    fn invalid_json_is_none() {
        assert!(parse_repology_response("not json").is_none());
    }

    #[test]
    fn pacing_enforces_min_interval() {
        use crate::http::FakeHttpClient;
        let http = FakeHttpClient::new().with(
            "https://repology.org/api/v1/project/foo",
            r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}]"#,
        );
        let collector = RepologyCollector::with_interval(&http, Duration::from_millis(100));
        let start = Instant::now();
        collector.latest_version("foo").unwrap();
        collector.latest_version("foo").unwrap();
        // The second request waits for the interval (the first is free).
        assert!(start.elapsed() >= Duration::from_millis(90));
    }

    #[test]
    fn zero_interval_does_not_pace() {
        use crate::http::FakeHttpClient;
        let http = FakeHttpClient::new().with(
            "https://repology.org/api/v1/project/foo",
            r#"[{"repo": "fedora_41", "version": "2.0", "status": "newest"}]"#,
        );
        let collector = RepologyCollector::with_interval(&http, Duration::from_secs(0));
        let start = Instant::now();
        collector.latest_version("foo").unwrap();
        collector.latest_version("foo").unwrap();
        assert!(start.elapsed() < Duration::from_millis(50));
    }
}
