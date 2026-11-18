//! Direct upstream confirmation.
//!
//! A candidate version is confirmed against the upstream source itself,
//! not just an aggregator. The check is: does the upstream project have
//! a release (or tag) for exactly this version?
//!
//! [`GithubReleasesChecker`] implements the check for projects hosted on
//! GitHub: it lists the repository releases via the GitHub API and looks
//! for a tag whose version (leading `v` stripped) equals the candidate
//! (by RPM comparison). The repository (owner/repo) is supplied per
//! package by the caller; there is no guessing from the package name.

use crate::http::{HttpClient, HttpError};
use crate::version::rpmvercmp;
use serde::Deserialize;
use std::cmp::Ordering;

/// A direct upstream check. Returns true when the upstream project has a
/// release for exactly `version`.
pub trait UpstreamChecker {
    fn confirm(&self, package: &str, version: &str) -> Result<bool, HttpError>;
}

/// No upstream check configured: never confirms.
pub struct NoUpstreamChecker;

impl UpstreamChecker for NoUpstreamChecker {
    fn confirm(&self, _package: &str, _version: &str) -> Result<bool, HttpError> {
        Ok(false)
    }
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    #[serde(default)]
    tag_name: String,
}

/// Parse a GitHub releases list and check whether any tag matches
/// `version` (leading `v` stripped, compared with RPM comparison).
pub fn github_has_release(body: &str, version: &str) -> bool {
    let releases: Vec<GithubRelease> = match serde_json::from_str(body) {
        Ok(releases) => releases,
        Err(_) => return false,
    };
    releases.iter().any(|release| {
        let tag = release
            .tag_name
            .strip_prefix('v')
            .unwrap_or(&release.tag_name);
        rpmvercmp(tag, version) == Ordering::Equal
    })
}

pub struct GithubReleasesChecker<'a> {
    http: &'a dyn HttpClient,
    /// The repository, as `owner/repo`.
    repo: String,
}

impl<'a> GithubReleasesChecker<'a> {
    pub fn new(http: &'a dyn HttpClient, repo: &str) -> Self {
        GithubReleasesChecker {
            http,
            repo: repo.to_string(),
        }
    }
}

impl<'a> UpstreamChecker for GithubReleasesChecker<'a> {
    fn confirm(&self, _package: &str, version: &str) -> Result<bool, HttpError> {
        // The repo is caller-supplied config; validate its shape before
        // interpolating it into the URL (a `?` or `/` in it would rewrite
        // the request).
        let segments: Vec<&str> = self.repo.split('/').collect();
        let valid = segments.len() == 2
            && segments.iter().all(|seg| {
                !seg.is_empty()
                    && seg
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
            });
        if !valid {
            return Err(HttpError(format!(
                "invalid GitHub repository: {:?}",
                self.repo
            )));
        }
        let url = format!(
            "https://api.github.com/repos/{}/releases?per_page=100",
            self.repo
        );
        let body = self.http.get(&url)?;
        Ok(github_has_release(&body, version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"[
        {"tag_name": "v2.0"},
        {"tag_name": "v1.9"},
        {"tag_name": "2.0.1"}
    ]"#;

    #[test]
    fn tag_with_v_prefix_matches() {
        assert!(github_has_release(FIXTURE, "2.0"));
    }

    #[test]
    fn invalid_repo_is_an_error_not_a_request() {
        use crate::http::FakeHttpClient;
        let http = FakeHttpClient::new();
        let checker = GithubReleasesChecker::new(&http, "owner/repo?per_page=1");
        assert!(checker.confirm("foo", "2.0").is_err());
        let checker = GithubReleasesChecker::new(&http, "not-a-repo");
        assert!(checker.confirm("foo", "2.0").is_err());
        // A well-formed repo builds the expected URL and reaches the
        // HTTP client: a canned release list for that URL confirms.
        let http = FakeHttpClient::new().with(
            "https://api.github.com/repos/owner/repo/releases?per_page=100",
            FIXTURE,
        );
        let checker = GithubReleasesChecker::new(&http, "owner/repo");
        assert!(checker.confirm("foo", "2.0").unwrap());
    }

    #[test]
    fn tag_without_v_prefix_matches() {
        assert!(github_has_release(FIXTURE, "2.0.1"));
    }

    #[test]
    fn missing_version_does_not_match() {
        assert!(!github_has_release(FIXTURE, "3.0"));
    }

    #[test]
    fn invalid_json_does_not_match() {
        assert!(!github_has_release("not json", "2.0"));
    }
}
