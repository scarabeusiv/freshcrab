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
//! hold: it came from Repology with status `newest` in at least two
//! distinct repos (a single `newest` entry is a max, not a consensus,
//! so it does not confirm on its own), at least two collectors agree on
//! the same version, or the direct upstream check confirms it. A
//! Distrowatch-only candidate is never confirmed on its own.

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
    /// Repology status `newest` in at least two distinct repos).
    pub multi_source: bool,
}

/// Percent-encode a value interpolated into a URL path segment. Keeps
/// unreserved characters, `+`, and `:` as-is; everything else becomes
/// `%XX`. `+` is a literal plus in a path segment, and `:` is legal
/// there (OBS project names are `openSUSE:Factory`-shaped). Package and
/// project names come from config / the CLI / the network, so they are
/// never interpolated raw — a name containing `/`, `?`, `&` or `=`
/// would otherwise rewrite the request URL.
pub(crate) fn encode_path(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '+' | ':') {
            out.push(ch);
        } else {
            for byte in ch.to_string().as_bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    out
}

/// Percent-encode a value interpolated into a URL query value. Unlike
/// a path segment, a query value decodes `+` as a space, so `+` (and
/// `:`) are encoded here too. Keeps unreserved characters and `~`.
pub(crate) fn encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            for byte in ch.to_string().as_bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    out
}

/// True when `name` is a valid OBS package or project name
/// (`[A-Za-z0-9_.+-:]`). Anything else is rejected rather than quoted
/// into a URL or an XPath literal, where a `/`, `?`, or quote would
/// rewrite the request.
pub(crate) fn valid_obs_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | ':'))
}

/// A version collector. `latest_version` returns the newest version the
/// collector knows for `package`, or None when it has no record of it.
pub trait Collector {
    fn name(&self) -> &'static str;
    fn latest_version(&self, package: &str) -> Result<Option<Candidate>, HttpError>;
}

/// Query all collectors in priority order and return the candidates found.
/// A collector that errors is skipped (its error is logged here, so an
/// outage does not look identical to "no updates"); it does not fail
/// the whole run.
pub fn collect(package: &str, collectors: &[Box<dyn Collector + '_>]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for collector in collectors {
        match collector.latest_version(package) {
            Ok(Some(candidate)) => out.push(candidate),
            Ok(None) => {}
            Err(e) => {
                eprintln!(
                    "warning: collector {} failed for {package}: {e}",
                    collector.name()
                );
            }
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

    // A multi-source candidate (e.g. Repology `newest` in at least two
    // distinct repos) confirms on its own.
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
    let rest = package
        .strip_prefix("python3-")
        .or_else(|| package.strip_prefix("python-"))?;
    // A bare `python-` / `python3-` prefix maps to an empty PyPI name,
    // which would query `/pypi//json`; treat it as "not a Python
    // package" instead.
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
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
    fn encode_path_keeps_safe_chars_and_escapes_the_rest() {
        assert_eq!(encode_path("curl"), "curl");
        assert_eq!(encode_path("python3-requests"), "python3-requests");
        assert_eq!(encode_path("openSUSE:Factory"), "openSUSE:Factory");
        assert_eq!(encode_path("gcc-c++"), "gcc-c++");
        assert_eq!(encode_path("foo/bar?x=1&y=2"), "foo%2Fbar%3Fx%3D1%26y%3D2");
    }

    #[test]
    fn encode_query_encodes_plus() {
        // A query value decodes `+` as a space, so `+` must be encoded
        // (a path segment keeps it raw).
        assert_eq!(encode_query("gcc-c++"), "gcc-c%2B%2B");
        assert_eq!(encode_query("foo bar"), "foo%20bar");
        assert_eq!(encode_query("curl"), "curl");
    }

    #[test]
    fn valid_obs_name_rejects_url_breaking_chars() {
        assert!(valid_obs_name("python3-requests"));
        assert!(valid_obs_name("foo:bar"));
        assert!(valid_obs_name("gcc-c++"));
        assert!(!valid_obs_name(""));
        assert!(!valid_obs_name("foo/bar"));
        assert!(!valid_obs_name("foo?x=1"));
        assert!(!valid_obs_name("foo' or '1'='1"));
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
        // A bare prefix is not a Python package (empty PyPI name).
        assert_eq!(pypi_name("python-"), None);
        assert_eq!(pypi_name("python3-"), None);
    }
}
