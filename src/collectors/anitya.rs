//! Anitya / release-monitoring.org collector (second).
//!
//! Anitya tracks upstream releases (GitHub, GitLab, PyPI, ...). Endpoint:
//! `GET /api/v2/projects/?name=<name>` returns a JSON object with an
//! `items` array; each item has a `version` field holding the latest known
//! version. No authentication is needed for these read-only queries.

use crate::collectors::{encode_query, Candidate, Collector};
use crate::http::{HttpClient, HttpError};
use serde::Deserialize;

pub const ANITYA_API: &str = "https://release-monitoring.org/api/v2";

#[derive(Debug, Deserialize)]
struct AnityaResponse {
    #[serde(default)]
    items: Vec<AnityaProject>,
}

#[derive(Debug, Deserialize)]
struct AnityaProject {
    #[serde(default)]
    version: Option<String>,
}

/// Parse an Anitya `/api/v2/projects/?name=<name>` response. Returns the
/// latest version of the first matching project, or None.
pub fn parse_anitya_response(body: &str) -> Option<Candidate> {
    let response: AnityaResponse = serde_json::from_str(body).ok()?;
    let version = response
        .items
        .first()
        .and_then(|project| project.version.clone())?;
    if version.is_empty() {
        return None;
    }
    Some(Candidate {
        collector: "anitya",
        version,
        multi_source: false,
    })
}

pub struct AnityaCollector<'a> {
    http: &'a dyn HttpClient,
}

impl<'a> AnityaCollector<'a> {
    pub fn new(http: &'a dyn HttpClient) -> Self {
        AnityaCollector { http }
    }
}

impl<'a> Collector for AnityaCollector<'a> {
    fn name(&self) -> &'static str {
        "anitya"
    }

    fn latest_version(&self, package: &str) -> Result<Option<Candidate>, HttpError> {
        // The name goes into a query value (`?name=`), where `+`
        // decodes as a space — so it uses the query encoder, not the
        // path encoder (which keeps `+` raw).
        let url = format!("{ANITYA_API}/projects/?name={}", encode_query(package));
        let body = self.http.get(&url)?;
        Ok(parse_anitya_response(&body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_item_version() {
        let body = r#"{
            "items": [
                {"name": "foo", "version": "2.0", "versions": ["2.0", "1.9"]},
                {"name": "foo", "version": "1.9", "versions": ["1.9"]}
            ],
            "items_per_page": 25, "page": 1, "total_items": 2
        }"#;
        let candidate = parse_anitya_response(body).unwrap();
        assert_eq!(candidate.version, "2.0");
        assert_eq!(candidate.collector, "anitya");
        assert!(!candidate.multi_source);
    }

    #[test]
    fn no_items_is_none() {
        let body = r#"{"items": [], "items_per_page": 25, "page": 1, "total_items": 0}"#;
        assert!(parse_anitya_response(body).is_none());
    }

    #[test]
    fn missing_version_is_none() {
        let body = r#"{"items": [{"name": "foo"}]}"#;
        assert!(parse_anitya_response(body).is_none());
    }

    #[test]
    fn invalid_json_is_none() {
        assert!(parse_anitya_response("not json").is_none());
    }

    #[test]
    fn plus_in_name_is_query_encoded() {
        // `gcc-c++` must reach Anitya as `gcc-c%2B%2B`: a raw `+` in a
        // query value decodes as a space and mis-queries.
        use crate::http::FakeHttpClient;
        let http = FakeHttpClient::new().with(
            "https://release-monitoring.org/api/v2/projects/?name=gcc-c%2B%2B",
            r#"{"items": [{"name": "gcc-c++", "version": "14.2"}]}"#,
        );
        let collector = AnityaCollector::new(&http);
        let candidate = collector.latest_version("gcc-c++").unwrap().unwrap();
        assert_eq!(candidate.version, "14.2");
    }
}
