//! OBS client for the queue deduplication checks and for filing submit
//! requests.
//!
//! The deduplication checks are read-only:
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
//! as "no open SR". When credentials are present, the search uses them
//! (HTTP Basic auth); without them it stays unauthenticated and fails
//! closed as before.
//!
//! Filing a submit request (`create_request`) is the write side: it
//! POSTs the request XML to `POST /request?cmd=create` (the same call
//! `osc api -X POST -T <xml> "/request?cmd=create"` makes) and returns
//! the new request id. It requires credentials and fails loudly without
//! them. The dry-run guard lives in `crate::sr::SrFiling`, not here —
//! do not call `create_request` in dry-run.

use crate::collectors::{encode_path, encode_query, valid_obs_name};
use crate::factory::{parse_spec_version, FACTORY_PROJECT, OBS_API};
use crate::http::{HttpClient, HttpError};

/// OBS credentials (username + password) for the authenticated API.
/// Read from the environment (`OSC_USERNAME` / `OSC_PASSWORD`) — never
/// from the repo. The OBS API accepts HTTP Basic auth with these. The
/// values are never logged.
///
/// `Debug` is hand-written: the password is redacted, so a future
/// `{:?}` on a client or an error can never leak it into a log.
#[derive(Clone, PartialEq, Eq)]
pub struct ObsCredentials {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for ObsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObsCredentials")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish()
    }
}

impl ObsCredentials {
    /// Read credentials from the environment. None when either variable
    /// is unset or empty.
    pub fn from_env() -> Option<Self> {
        let username = std::env::var("OSC_USERNAME")
            .ok()
            .filter(|v| !v.trim().is_empty())?;
        let password = std::env::var("OSC_PASSWORD")
            .ok()
            .filter(|v| !v.trim().is_empty())?;
        Some(ObsCredentials { username, password })
    }
}

pub struct ObsClient<'a> {
    http: &'a dyn HttpClient,
    credentials: Option<ObsCredentials>,
}

impl<'a> ObsClient<'a> {
    pub fn new(http: &'a dyn HttpClient) -> Self {
        ObsClient {
            http,
            credentials: None,
        }
    }

    /// An OBS client with credentials (for the authenticated endpoints:
    /// the open-SR search and filing a submit request).
    pub fn with_credentials(http: &'a dyn HttpClient, credentials: ObsCredentials) -> Self {
        ObsClient {
            http,
            credentials: Some(credentials),
        }
    }

    /// The credentials, if any.
    pub fn credentials(&self) -> Option<&ObsCredentials> {
        self.credentials.as_ref()
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
    ///
    /// When this client has credentials, the search uses them (HTTP
    /// Basic auth); without them the request is unauthenticated and the
    /// API 401s, which the caller treats as fail-closed.
    pub fn has_open_sr(&self, package: &str) -> Result<bool, HttpError> {
        let url = search_url(package)?;
        let body = match &self.credentials {
            Some(creds) => self.http.get_auth(&url, &creds.username, &creds.password)?,
            None => self.http.get(&url)?,
        };
        match parse_search_matches(&body) {
            Some(n) => Ok(n > 0),
            None => Err(HttpError(format!(
                "unexpected OBS search response for package {package:?}"
            ))),
        }
    }

    /// File a submit request: POST the request XML to the OBS API
    /// (`POST /request?cmd=create`) and return the new request id.
    /// Requires credentials (the API 401s without them). The caller
    /// builds the XML (see `crate::sr`); this only sends it. The
    /// dry-run guard lives in `SrFiling`, not here — do not call this
    /// in dry-run.
    ///
    /// Convention, not compiler-enforced: `SrFiling` (`crate::sr`) is
    /// the single permitted caller in this crate. A direct call bypasses
    /// the dry-run guard, so do not add another one; enforcing it would
    /// need a capability/token design, which is a follow-up.
    pub fn create_request(&self, xml: &str) -> Result<String, HttpError> {
        let creds = self.credentials.as_ref().ok_or_else(|| {
            HttpError(
                "cannot file a submit request without OBS credentials \
                 (set OSC_USERNAME/OSC_PASSWORD)"
                    .to_string(),
            )
        })?;
        let url = format!("{OBS_API}/request?cmd=create");
        let body = self
            .http
            .post(&url, xml, Some((&creds.username, &creds.password)))?;
        parse_request_id(&body)
            .ok_or_else(|| HttpError(format!("unexpected OBS create-request response: {body:?}")))
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

/// Extract the request id from an OBS create-request response
/// (`<request id="1234567" ...>`). None when the response carries no
/// numeric id.
pub fn parse_request_id(body: &str) -> Option<String> {
    let marker = "<request id=\"";
    let pos = body.find(marker)?;
    let start = pos + marker.len();
    let end = body[start..].find('"')?;
    let id = &body[start..start + end];
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(id.to_string())
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

    #[test]
    fn parse_request_id_extracts_numeric_id() {
        assert_eq!(
            parse_request_id("<request id=\"1400001\" creator=\"scarabeus_iv\"></request>"),
            Some("1400001".to_string())
        );
        assert_eq!(parse_request_id("<request></request>"), None);
        assert_eq!(parse_request_id("<request id=\"abc\"></request>"), None);
        assert_eq!(parse_request_id(""), None);
    }

    #[test]
    fn create_request_posts_xml_and_returns_id() {
        let http = FakeHttpClient::new().with_post(
            "https://api.opensuse.org/request?cmd=create",
            "<request id=\"1400001\" creator=\"scarabeus_iv\"></request>",
        );
        let client = ObsClient::with_credentials(
            &http,
            ObsCredentials {
                username: "scarabeus_iv".to_string(),
                password: "secret".to_string(),
            },
        );
        let id = client
            .create_request("<request><action type=\"submit\"/></request>")
            .unwrap();
        assert_eq!(id, "1400001");
        let posted = http.posted();
        assert_eq!(posted.len(), 1);
        assert_eq!(posted[0].0, "https://api.opensuse.org/request?cmd=create");
        // The filing POST carried the credentials.
        assert_eq!(http.posted_auth(), vec![true]);
    }

    #[test]
    fn create_request_without_credentials_fails_closed() {
        let http = FakeHttpClient::new().with_post(
            "https://api.opensuse.org/request?cmd=create",
            "<request id=\"1400001\"></request>",
        );
        let client = ObsClient::new(&http);
        assert!(client
            .create_request("<request><action type=\"submit\"/></request>")
            .is_err());
        assert!(http.posted().is_empty());
    }

    #[test]
    fn has_open_sr_uses_auth_when_credentials_present() {
        let http = FakeHttpClient::new().with(
            &search_url("foo").unwrap(),
            "<collection matches=\"0\"></collection>",
        );
        let client = ObsClient::with_credentials(
            &http,
            ObsCredentials {
                username: "scarabeus_iv".to_string(),
                password: "secret".to_string(),
            },
        );
        assert!(!client.has_open_sr("foo").unwrap());
        assert_eq!(http.authed_gets(), vec![search_url("foo").unwrap()]);
    }

    #[test]
    fn debug_redacts_password() {
        let creds = ObsCredentials {
            username: "scarabeus_iv".to_string(),
            password: "s3cr3t".to_string(),
        };
        let debug = format!("{creds:?}");
        assert!(debug.contains("scarabeus_iv"));
        assert!(!debug.contains("s3cr3t"));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn create_request_transport_error_fails() {
        // No canned POST response: the transport fails, so filing fails
        // instead of silently reporting success.
        let http = FakeHttpClient::new();
        let client = ObsClient::with_credentials(
            &http,
            ObsCredentials {
                username: "scarabeus_iv".to_string(),
                password: "secret".to_string(),
            },
        );
        assert!(client
            .create_request("<request><action type=\"submit\"/></request>")
            .is_err());
    }
}
