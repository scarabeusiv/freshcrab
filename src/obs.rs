//! OBS client for the queue deduplication checks.
//!
//! Two checks need OBS, and both are read-only:
//! - the devel project's current version of a package (skip when the devel
//!   project already has the new version);
//! - whether an open submit request already targets the package.
//!
//! The devel project for a package is resolved via the OBS *public* API
//! (`/public/source/<project>/<package>` carries a `devel` attribute).
//! Those reads need no credentials. The open-SR check uses the OBS search
//! API, which has no public equivalent and returns 401 without
//! credentials — so it needs OBS credentials (injected via environment
//! variables / a mounted file, never from the repo), and the queue
//! treats a failed check as fail-closed (skip the package) rather than
//! as "no open SR".

use crate::collectors::{encode_path, encode_query, valid_obs_name};
use crate::factory::{parse_spec_version, FACTORY_PROJECT, OBS_API};
use crate::http::{HttpClient, HttpError};

pub struct ObsClient<'a> {
    http: &'a dyn HttpClient,
}

impl<'a> ObsClient<'a> {
    pub fn new(http: &'a dyn HttpClient) -> Self {
        ObsClient { http }
    }

    /// Return the devel project for `package` on Factory, or None.
    pub fn devel_project(&self, package: &str) -> Result<Option<String>, HttpError> {
        if !valid_obs_name(package) {
            return Err(HttpError(format!("invalid OBS package name: {package:?}")));
        }
        let url = format!(
            "{OBS_API}/public/source/{FACTORY_PROJECT}/{}",
            encode_path(package)
        );
        let body = self.http.get(&url)?;
        // The directory listing carries <devel project="..."/> when set.
        // This assumes the attribute order and lowercase spelling OBS
        // emits (`<devel project="..." package="..."/>`); a listing
        // that spells it differently is missed (fail-safe: None).
        let marker = "<devel project=\"";
        if let Some(pos) = body.find(marker) {
            let start = pos + marker.len();
            if let Some(end) = body[start..].find('"') {
                return Ok(Some(body[start..start + end].to_string()));
            }
        }
        Ok(None)
    }

    /// Return the devel project's Version of `package`, or None.
    pub fn devel_version(&self, package: &str) -> Result<Option<String>, HttpError> {
        let project = match self.devel_project(package)? {
            Some(project) => project,
            None => return Ok(None),
        };
        // The project comes from network XML (`<devel project>`), so it
        // is validated and encoded like any other interpolated value
        // before it goes into a URL.
        if !valid_obs_name(&project) {
            return Err(HttpError(format!("invalid OBS project name: {project:?}")));
        }
        let url = format!(
            "{OBS_API}/public/source/{}/{}/{}.spec",
            encode_path(&project),
            encode_path(package),
            encode_path(package)
        );
        let spec = self.http.get(&url)?;
        Ok(parse_spec_version(&spec))
    }

    /// True when an open submit request targets `package`.
    ///
    /// Uses the OBS search API. The plain `/request` endpoint ignores the
    /// `target_package` filter (verified live: it returns the same
    /// paginated directory listing regardless of the package) and returns
    /// request IDs, not `<request>` elements — so neither the filter nor a
    /// `<request ` substring test works there. The search matches on
    /// `action/target/@package` and the `new`/`review` states.
    pub fn has_open_sr(&self, package: &str) -> Result<bool, HttpError> {
        let url = search_url(package)?;
        let body = self.http.get(&url)?;
        match parse_search_matches(&body) {
            Some(n) => Ok(n > 0),
            None => Err(HttpError(format!(
                "unexpected OBS search response for package {package:?}"
            ))),
        }
    }
}

/// Build the OBS search URL for open submit requests targeting `package`.
/// The match expression is XPath over the request XML. The package name
/// goes into a single-quoted XPath string literal, so it must be a valid
/// OBS package name (`[A-Za-z0-9_.+-:]`); anything else is rejected rather
/// than quoted, because XPath has no string escape and a quote in the name
/// would break out of the literal.
pub fn search_url(package: &str) -> Result<String, HttpError> {
    if !valid_obs_name(package) {
        return Err(HttpError(format!("invalid OBS package name: {package:?}")));
    }
    let match_expr = format!(
        "action/target/@package='{package}' and (state/@name='new' or state/@name='review')"
    );
    Ok(format!(
        "{OBS_API}/search/request?match={}",
        encode_query(&match_expr)
    ))
}

/// Extract the `matches` count from an OBS search response
/// (`<collection matches="N">...</collection>`). None when the response
/// does not carry a count.
pub fn parse_search_matches(body: &str) -> Option<u32> {
    let marker = "matches=\"";
    let pos = body.find(marker)?;
    let start = pos + marker.len();
    let end = body[start..].find('"')?;
    body[start..start + end].parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::FakeHttpClient;

    #[test]
    fn devel_project_extracted() {
        let http = FakeHttpClient::new().with(
            "https://api.opensuse.org/public/source/openSUSE:Factory/foo",
            "<directory name=\"foo\"><devel project=\"devel:languages:python\" package=\"foo\"/></directory>",
        );
        let client = ObsClient::new(&http);
        assert_eq!(
            client.devel_project("foo").unwrap(),
            Some("devel:languages:python".to_string())
        );
    }

    #[test]
    fn devel_project_missing_is_none() {
        let http = FakeHttpClient::new().with(
            "https://api.opensuse.org/public/source/openSUSE:Factory/foo",
            "<directory name=\"foo\"></directory>",
        );
        let client = ObsClient::new(&http);
        assert_eq!(client.devel_project("foo").unwrap(), None);
    }

    #[test]
    fn has_open_sr_detects_request() {
        let http = FakeHttpClient::new().with(
            &search_url("foo").unwrap(),
            "<collection matches=\"1\"><request id=\"1398492\"/></collection>",
        );
        let client = ObsClient::new(&http);
        assert!(client.has_open_sr("foo").unwrap());
    }

    #[test]
    fn has_open_sr_empty_is_false() {
        let http = FakeHttpClient::new().with(
            &search_url("foo").unwrap(),
            "<collection matches=\"0\"></collection>",
        );
        let client = ObsClient::new(&http);
        assert!(!client.has_open_sr("foo").unwrap());
    }

    #[test]
    fn has_open_sr_unexpected_response_is_error() {
        let http =
            FakeHttpClient::new().with(&search_url("foo").unwrap(), "<collection></collection>");
        let client = ObsClient::new(&http);
        assert!(client.has_open_sr("foo").is_err());
    }

    #[test]
    fn parse_search_matches_counts() {
        assert_eq!(
            parse_search_matches("<collection matches=\"3\"></collection>"),
            Some(3)
        );
        assert_eq!(
            parse_search_matches("<collection matches=\"0\"></collection>"),
            Some(0)
        );
        assert_eq!(parse_search_matches("<collection></collection>"), None);
    }

    #[test]
    fn search_url_rejects_invalid_package_name() {
        // A quote in the name would break out of the XPath string literal.
        assert!(search_url("foo' or '1'='1").is_err());
        assert!(search_url("").is_err());
        assert!(search_url("foo bar").is_err());
        // Valid OBS names pass.
        assert!(search_url("python3-requests").is_ok());
        assert!(search_url("foo:bar").is_ok());
    }

    #[test]
    fn devel_project_rejects_invalid_package_name_without_http() {
        // An invalid name is rejected before any request: no canned
        // response exists, so reaching the HTTP client would error
        // differently (FakeHttpClient: "no canned response").
        let http = FakeHttpClient::new();
        let client = ObsClient::new(&http);
        let err = client.devel_project("foo/bar").unwrap_err();
        assert!(err.0.contains("invalid OBS package name"));
    }

    #[test]
    fn devel_version_rejects_invalid_project_from_xml() {
        // A project name from network XML is validated too: a value
        // that cannot be a project name errors rather than being
        // interpolated into a URL.
        let http = FakeHttpClient::new().with(
            "https://api.opensuse.org/public/source/openSUSE:Factory/foo",
            "<directory name=\"foo\"><devel project=\"weird/project\" package=\"foo\"/></directory>",
        );
        let client = ObsClient::new(&http);
        let err = client.devel_version("foo").unwrap_err();
        assert!(err.0.contains("invalid OBS project name"));
    }
}
