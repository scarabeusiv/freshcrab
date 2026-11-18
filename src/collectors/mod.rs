//! Version collectors, in priority order.
//!
//! 1. Repology (primary) — aggregates package versions across hundreds of
//!    distros and upstreams, JSON API.
//! 2. Anitya / release-monitoring.org — tracks upstream releases (GitHub,
//!    GitLab, PyPI, ...), JSON API.
//! 3. PyPI JSON API — for Python packages only (name starts with
//!    `python3-` or `python-`; the prefix is stripped for the PyPI name).
//! 4. Distrowatch — secondary signal only (HTML table).
//!
//! Freshmeat is DEFUNCT (shut down in 2014) and is deliberately NOT used.
//!
//! A candidate version is confirmed before queueing when any of these
//! hold: it came from Repology with status `newest` (Repology already
//! aggregates across repos, so this is multi-source by construction), at
//! least two collectors agree on the same version, or the direct upstream
//! check confirms it. A Distrowatch-only candidate is never confirmed on
//! its own.

use crate::http::HttpError;
use crate::version::rpmvercmp;
use std::cmp::Ordering;

pub mod anitya;
pub mod distrowatch;
pub mod pypi;
pub mod repology;
pub mod upstream;

/// A candidate version from one collector.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// The collector that produced this candidate.
    pub collector: &'static str,
    /// The version string.
    pub version: String,
    /// True when the version is corroborated by multiple sources (e.g.
    /// Repology status `newest`, which aggregates across repositories).
    pub multi_source: bool,
}

/// Percent-encode a value interpolated into a URL (path segment or query
/// value). Keeps unreserved characters and `+` as-is; everything else
/// becomes `%XX`. Package names come from config / the CLI, so they are
/// never interpolated raw — a name containing `/`, `?`, `&` or `=` would
/// otherwise rewrite the request URL.
pub(crate) fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' || ch == '+' {
            out.push(ch);
        } else {
            for byte in ch.to_string().as_bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    out
}

/// A version collector. `latest_version` returns the newest version the
/// collector knows for `package`, or None when it has no record of it.
pub trait Collector {
    fn name(&self) -> &'static str;
    fn latest_version(&self, package: &str) -> Result<Option<Candidate>, HttpError>;
}

/// Query all collectors in priority order and return the candidates found.
/// A collector that errors is skipped (logged by the caller); it does not
/// fail the whole run.
pub fn collect(package: &str, collectors: &[Box<dyn Collector + '_>]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for collector in collectors {
        match collector.latest_version(package) {
            Ok(Some(candidate)) => out.push(candidate),
            Ok(None) => {}
            Err(_) => {}
        }
    }
    out
}

/// The confirmed candidate, if any. Returns the full candidate (with the
/// collector that produced it) so the caller can report the source.
///
/// `candidates` are in priority order (first = highest priority).
/// `upstream` is an optional direct upstream checker; when present and it
/// confirms the primary candidate, that also confirms it.
pub fn confirmed_candidate(
    candidates: &[Candidate],
    upstream: Option<&dyn upstream::UpstreamChecker>,
    package: &str,
) -> Option<Candidate> {
    let primary = candidates.first()?.clone();
    let version = primary.version.clone();

    // Repology `newest` is multi-source by construction.
    if primary.multi_source {
        return Some(primary);
    }

    // At least two collectors agree on the same version.
    let agreeing = candidates
        .iter()
        .skip(1)
        .any(|c| rpmvercmp(&c.version, &version) == Ordering::Equal);
    if agreeing {
        return Some(primary);
    }

    // Direct upstream check.
    if let Some(checker) = upstream {
        if checker.confirm(package, &version).unwrap_or(false) {
            return Some(primary);
        }
    }

    None
}

/// True when the package name denotes a Python package (for the PyPI
/// collector). The PyPI name is the OBS name with the `python3-` or
/// `python-` prefix stripped.
pub fn pypi_name(package: &str) -> Option<String> {
    package
        .strip_prefix("python3-")
        .or_else(|| package.strip_prefix("python-"))
        .map(|rest| rest.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(collector: &'static str, version: &str, multi_source: bool) -> Candidate {
        Candidate {
            collector,
            version: version.to_string(),
            multi_source,
        }
    }

    #[test]
    fn encode_keeps_safe_chars_and_escapes_the_rest() {
        assert_eq!(encode("curl"), "curl");
        assert_eq!(encode("python3-requests"), "python3-requests");
        assert_eq!(encode("foo/bar?x=1&y=2"), "foo%2Fbar%3Fx%3D1%26y%3D2");
    }

    #[test]
    fn repology_newest_confirms_on_its_own() {
        let candidates = vec![candidate("repology", "2.0", true)];
        let confirmed = confirmed_candidate(&candidates, None, "foo").unwrap();
        assert_eq!(confirmed.version, "2.0");
        assert_eq!(confirmed.collector, "repology");
    }

    #[test]
    fn two_collectors_agreeing_confirms() {
        let candidates = vec![
            candidate("anitya", "2.0", false),
            candidate("distrowatch", "2.0", false),
        ];
        let confirmed = confirmed_candidate(&candidates, None, "foo").unwrap();
        assert_eq!(confirmed.version, "2.0");
        // The primary (highest-priority) collector is the source.
        assert_eq!(confirmed.collector, "anitya");
    }

    #[test]
    fn single_non_multi_source_collector_does_not_confirm() {
        let candidates = vec![candidate("distrowatch", "2.0", false)];
        assert_eq!(confirmed_candidate(&candidates, None, "foo"), None);
    }

    #[test]
    fn no_candidates_means_none() {
        let candidates: Vec<Candidate> = vec![];
        assert_eq!(confirmed_candidate(&candidates, None, "foo"), None);
    }

    #[test]
    fn pypi_name_strips_prefix() {
        assert_eq!(pypi_name("python3-requests"), Some("requests".to_string()));
        assert_eq!(pypi_name("python-foo"), Some("foo".to_string()));
        assert_eq!(pypi_name("foo"), None);
        assert_eq!(pypi_name("python3"), None);
    }
}
