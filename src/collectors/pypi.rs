//! PyPI collector (Python packages only).
//!
//! Endpoint: `GET https://pypi.org/pypi/<name>/json` returns a JSON object
//! with `info.version`. Only used for packages whose OBS name starts with
//! `python3-` or `python-` (see `crate::collectors::pypi_name`); the
//! prefix is stripped for the PyPI name.

use crate::collectors::{encode, Candidate, Collector};
use crate::http::{HttpClient, HttpError};
use serde::Deserialize;

pub const PYPI_API: &str = "https://pypi.org/pypi";

#[derive(Debug, Deserialize)]
struct PypiResponse {
    info: PypiInfo,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    version: String,
}

/// Parse a PyPI JSON response. Returns the version, or None.
pub fn parse_pypi_response(body: &str) -> Option<Candidate> {
    let response: PypiResponse = serde_json::from_str(body).ok()?;
    let version = response.info.version;
    if version.is_empty() {
        return None;
    }
    Some(Candidate {
        collector: "pypi",
        version,
        multi_source: false,
    })
}

pub struct PypiCollector<'a> {
    http: &'a dyn HttpClient,
}

impl<'a> PypiCollector<'a> {
    pub fn new(http: &'a dyn HttpClient) -> Self {
        PypiCollector { http }
    }
}

impl<'a> Collector for PypiCollector<'a> {
    fn name(&self) -> &'static str {
        "pypi"
    }

    fn latest_version(&self, package: &str) -> Result<Option<Candidate>, HttpError> {
        // Only Python packages reach this collector; the caller maps the
        // OBS name to the PyPI name. Here the package is already the
        // PyPI name.
        let url = format!("{PYPI_API}/{}/json", encode(package));
        let body = self.http.get(&url)?;
        Ok(parse_pypi_response(&body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_extracted() {
        let body = r#"{"info": {"name": "requests", "version": "2.32.3"}}"#;
        let candidate = parse_pypi_response(body).unwrap();
        assert_eq!(candidate.version, "2.32.3");
        assert_eq!(candidate.collector, "pypi");
    }

    #[test]
    fn empty_version_is_none() {
        let body = r#"{"info": {"name": "requests", "version": ""}}"#;
        assert!(parse_pypi_response(body).is_none());
    }

    #[test]
    fn invalid_json_is_none() {
        assert!(parse_pypi_response("not json").is_none());
    }
}
