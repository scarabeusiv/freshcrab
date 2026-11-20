//! HTTP client abstraction.
//!
//! All network access goes through the [`HttpClient`] trait so the unit
//! tests can inject a fake that returns canned responses instead of
//! hitting the live network. The real implementation uses ureq (a small
//! synchronous HTTP client). Every request identifies itself with a
//! User-Agent that links to the project repository, as Repology requires
//! for bulk clients.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

pub const USER_AGENT: &str = "freshcrab/0.1 (https://github.com/scarabeusiv/freshcrab)";

/// Error from an HTTP request.
///
/// A 401/403 on a credentialed call (bad or rotated credentials) is
/// a distinct variant: the caller can tell an auth rejection apart
/// from a 500 or a transport failure, so credential rotation fails
/// the run loudly instead of yielding per-package skips. A 401/403
/// on an unauthenticated read is [`HttpError::Other`] — there are no
/// credentials to reject, so a proxy 401 on a public read must not
/// fail the whole run. Any other failure is [`HttpError::Other`].
#[derive(Debug)]
pub enum HttpError {
    /// The server rejected the credentials (HTTP 401/403). Carries
    /// the underlying error text (e.g. `http status: 401`).
    AuthRejected(String),
    /// Any other HTTP or transport failure (other statuses, timeouts,
    /// DNS, unreadable bodies). Carries the underlying error text.
    Other(String),
}

impl HttpError {
    /// True when the server rejected the credentials (401/403).
    pub fn is_auth_rejected(&self) -> bool {
        matches!(self, HttpError::AuthRejected(_))
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::AuthRejected(msg) => write!(f, "http error (auth rejected): {msg}"),
            HttpError::Other(msg) => write!(f, "http error: {msg}"),
        }
    }
}

impl std::error::Error for HttpError {}

/// Map a ureq error to [`HttpError`] for an unauthenticated read:
/// every failure is a plain failure. A 401/403 here is not an auth
/// rejection — there are no credentials to reject.
fn map_ureq_error(e: ureq::Error) -> HttpError {
    HttpError::Other(e.to_string())
}

/// Map a ureq error to [`HttpError`] for a credentialed call
/// (`get_auth`, `post` with credentials): 401/403 is an auth rejection, everything
/// else is a plain failure. ureq reports non-2xx statuses as
/// `Error::StatusCode` (its `http_status_as_error` default is on),
/// so the status is available here without inspecting a response.
fn map_ureq_auth_error(e: ureq::Error) -> HttpError {
    match e {
        ureq::Error::StatusCode(401) | ureq::Error::StatusCode(403) => {
            HttpError::AuthRejected(e.to_string())
        }
        other => HttpError::Other(other.to_string()),
    }
}

/// The value for an HTTP `Authorization: Basic ...` header. Uses the
/// `base64` crate (already a transitive dependency via ureq), not a
/// hand-rolled encoder.
pub fn basic_auth_header(username: &str, password: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    format!(
        "Basic {}",
        STANDARD.encode(format!("{username}:{password}"))
    )
}

/// A synchronous HTTP client. Returns response bodies as strings.
///
/// `get` is the unauthenticated read (collectors, the OBS public API).
/// The authenticated calls are for the OBS API endpoints that 401
/// without credentials: `get_auth` (the open-submit-request search) and
/// `post` (filing a submit request). Credentials are passed per call,
/// never stored in the client, so a collector request can never carry
/// OBS credentials to a third party.
pub trait HttpClient {
    fn get(&self, url: &str) -> Result<String, HttpError>;

    /// A GET with HTTP Basic auth. The default implementation ignores
    /// the credentials and calls `get` (for fakes that do not model
    /// auth); real clients apply the `Authorization` header.
    fn get_auth(&self, url: &str, username: &str, password: &str) -> Result<String, HttpError> {
        let _ = (username, password);
        self.get(url)
    }

    /// A POST with a body. `auth` is an optional (username, password)
    /// for HTTP Basic auth; None sends no `Authorization` header.
    /// Returns the response body as a string.
    fn post(&self, url: &str, body: &str, auth: Option<(&str, &str)>) -> Result<String, HttpError>;
}

/// The real client, backed by ureq. Holds one agent (built once, with a
/// 30s global timeout) so connections are reused across requests.
pub struct UreqClient {
    agent: ureq::Agent,
}

impl UreqClient {
    pub fn new() -> Self {
        UreqClient {
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(std::time::Duration::from_secs(30)))
                .build()
                .into(),
        }
    }
}

impl Default for UreqClient {
    fn default() -> Self {
        UreqClient::new()
    }
}

impl HttpClient for UreqClient {
    fn get(&self, url: &str) -> Result<String, HttpError> {
        let mut resp = self
            .agent
            .get(url)
            .header("User-Agent", USER_AGENT)
            .call()
            .map_err(map_ureq_error)?;
        resp.body_mut()
            .read_to_string()
            .map_err(|e| HttpError::Other(e.to_string()))
    }

    fn get_auth(&self, url: &str, username: &str, password: &str) -> Result<String, HttpError> {
        let mut resp = self
            .agent
            .get(url)
            .header("User-Agent", USER_AGENT)
            .header("Authorization", basic_auth_header(username, password))
            .call()
            .map_err(map_ureq_auth_error)?;
        resp.body_mut()
            .read_to_string()
            .map_err(|e| HttpError::Other(e.to_string()))
    }

    fn post(&self, url: &str, body: &str, auth: Option<(&str, &str)>) -> Result<String, HttpError> {
        let mut req = self
            .agent
            .post(url)
            .header("User-Agent", USER_AGENT)
            .header("Content-Type", "application/xml");
        if let Some((username, password)) = auth {
            req = req.header("Authorization", basic_auth_header(username, password));
        }
        // Only a credentialed POST can be an auth rejection: with no
        // credentials there is nothing to reject, so a 401/403 is a
        // plain failure (the same split as `get` vs `get_auth`).
        let map_err = if auth.is_some() {
            map_ureq_auth_error
        } else {
            map_ureq_error
        };
        let mut resp = req.send(body).map_err(map_err)?;
        resp.body_mut()
            .read_to_string()
            .map_err(|e| HttpError::Other(e.to_string()))
    }
}

/// A fake client for tests: maps URLs to canned (status, body)
/// responses, and records the POSTs made (url + body) so tests can
/// assert on them. `with` / `with_post` mean a 200; `with_status` /
/// `with_post_status` can any status, so 401/403 (auth rejection),
/// 404, 429 and 500 are representable instead of only bodies.
#[derive(Default)]
pub struct FakeHttpClient {
    responses: HashMap<String, (u16, String)>,
    post_responses: HashMap<String, (u16, String)>,
    posted: RefCell<Vec<(String, String)>>,
    posted_auth: RefCell<Vec<bool>>,
    authed_gets: RefCell<Vec<String>>,
}

impl FakeHttpClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(self, url: &str, body: &str) -> Self {
        self.with_status(url, 200, body)
    }

    /// Add a canned response with an explicit status for a GET to `url`.
    pub fn with_status(mut self, url: &str, status: u16, body: &str) -> Self {
        self.responses
            .insert(url.to_string(), (status, body.to_string()));
        self
    }

    /// Add a canned response for a POST to `url`.
    pub fn with_post(self, url: &str, body: &str) -> Self {
        self.with_post_status(url, 200, body)
    }

    /// Add a canned response with an explicit status for a POST to `url`.
    pub fn with_post_status(mut self, url: &str, status: u16, body: &str) -> Self {
        self.post_responses
            .insert(url.to_string(), (status, body.to_string()));
        self
    }

    /// The POSTs made through this client, as (url, body) pairs, in
    /// order. Tests assert on this; production never calls it.
    pub fn posted(&self) -> Vec<(String, String)> {
        self.posted.borrow().clone()
    }

    /// Whether each recorded POST carried HTTP Basic auth, in order
    /// (parallel to `posted()`). Tests assert the filing POST was
    /// authenticated; production never calls it.
    pub fn posted_auth(&self) -> Vec<bool> {
        self.posted_auth.borrow().clone()
    }

    /// The URLs fetched with Basic auth, in order.
    pub fn authed_gets(&self) -> Vec<String> {
        self.authed_gets.borrow().clone()
    }
}

/// Turn a canned (status, body) pair into the `HttpClient` result:
/// 2xx is the body, any other status is a plain failure — except on a
/// credentialed call (`auth` true), where 401/403 is an auth
/// rejection. A missing canned response is a plain failure (the old
/// "no canned response" error), never a silent success.
fn canned(
    responses: &HashMap<String, (u16, String)>,
    url: &str,
    missing: &str,
    auth: bool,
) -> Result<String, HttpError> {
    let Some((status, body)) = responses.get(url) else {
        return Err(HttpError::Other(format!("{missing} for {url}")));
    };
    match *status {
        200..=299 => Ok(body.clone()),
        401 | 403 if auth => Err(HttpError::AuthRejected(format!(
            "http status: {status} for {url}"
        ))),
        _ => Err(HttpError::Other(format!("http status: {status} for {url}"))),
    }
}

impl HttpClient for FakeHttpClient {
    fn get(&self, url: &str) -> Result<String, HttpError> {
        canned(&self.responses, url, "no canned response", false)
    }

    fn get_auth(&self, url: &str, username: &str, password: &str) -> Result<String, HttpError> {
        let _ = (username, password);
        self.authed_gets.borrow_mut().push(url.to_string());
        canned(&self.responses, url, "no canned response", true)
    }

    fn post(&self, url: &str, body: &str, auth: Option<(&str, &str)>) -> Result<String, HttpError> {
        self.posted_auth.borrow_mut().push(auth.is_some());
        self.posted
            .borrow_mut()
            .push((url.to_string(), body.to_string()));
        canned(
            &self.post_responses,
            url,
            "no canned POST response",
            auth.is_some(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_header_format() {
        assert_eq!(
            basic_auth_header("martin", "secret"),
            "Basic bWFydGluOnNlY3JldA=="
        );
    }

    #[test]
    fn auth_rejected_variant_displays_and_detects() {
        let err = HttpError::AuthRejected("http status: 401".to_string());
        assert!(err.is_auth_rejected());
        assert!(format!("{err}").contains("auth rejected"));
        assert!(format!("{err}").contains("401"));
        let other = HttpError::Other("http status: 500".to_string());
        assert!(!other.is_auth_rejected());
        assert_eq!(format!("{other}"), "http error: http status: 500");
    }

    #[test]
    fn fake_status_model_maps_statuses() {
        let http = FakeHttpClient::new()
            .with_status("https://example.invalid/ok", 200, "body")
            .with_status("https://example.invalid/denied", 401, "unauthorized")
            .with_status("https://example.invalid/forbidden", 403, "forbidden")
            .with_status("https://example.invalid/missing", 404, "not found")
            .with_status("https://example.invalid/broken", 500, "boom");
        assert_eq!(
            http.get("https://example.invalid/ok").unwrap(),
            "body".to_string()
        );
        // A 401/403 on an unauthenticated read is a plain failure,
        // not an auth rejection: there are no credentials to reject.
        let denied = http.get("https://example.invalid/denied").unwrap_err();
        assert!(!denied.is_auth_rejected());
        assert!(!http
            .get("https://example.invalid/forbidden")
            .unwrap_err()
            .is_auth_rejected());
        // The same statuses on a credentialed call are auth rejections.
        assert!(http
            .get_auth("https://example.invalid/denied", "u", "p")
            .unwrap_err()
            .is_auth_rejected());
        assert!(http
            .get_auth("https://example.invalid/forbidden", "u", "p")
            .unwrap_err()
            .is_auth_rejected());
        // A 500 on a credentialed call is still a plain failure.
        assert!(!http
            .get_auth("https://example.invalid/broken", "u", "p")
            .unwrap_err()
            .is_auth_rejected());
        let missing = http.get("https://example.invalid/missing").unwrap_err();
        assert!(!missing.is_auth_rejected());
        let broken = http.get("https://example.invalid/broken").unwrap_err();
        assert!(!broken.is_auth_rejected());
        // No canned response at all is still a plain failure.
        assert!(!http
            .get("https://example.invalid/unknown")
            .unwrap_err()
            .is_auth_rejected());
    }

    #[test]
    fn fake_post_status_model_maps_auth_rejection() {
        let http = FakeHttpClient::new().with_post_status(
            "https://example.invalid/create",
            401,
            "unauthorized",
        );
        let err = http
            .post(
                "https://example.invalid/create",
                "<request/>",
                Some(("u", "p")),
            )
            .unwrap_err();
        assert!(err.is_auth_rejected());
        // Without credentials a 401 on a POST is a plain failure, not
        // an auth rejection: there are no credentials to reject.
        let err = http
            .post("https://example.invalid/create", "<request/>", None)
            .unwrap_err();
        assert!(!err.is_auth_rejected());
    }
}
