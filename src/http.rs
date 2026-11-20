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
/// NOTE (dispatcher review round): this is deliberately a plain string
/// for now, so a 401/403 (bad or rotated OBS credentials) is
/// indistinguishable from a 500 or a transport failure — the caller
/// escalates per package instead of failing the run loudly. A typed
/// `AuthRejected` variant is the intended direction, but it needs the
/// error type to change across the whole crate (collectors, factory,
/// obs, fakes, tests) plus a fail-loud outcome in the worker/
/// dispatcher contract, so it is a follow-up, not this round.
#[derive(Debug)]
pub struct HttpError(pub String);

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "http error: {}", self.0)
    }
}

impl std::error::Error for HttpError {}

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
            .map_err(|e| HttpError(e.to_string()))?;
        resp.body_mut()
            .read_to_string()
            .map_err(|e| HttpError(e.to_string()))
    }

    fn get_auth(&self, url: &str, username: &str, password: &str) -> Result<String, HttpError> {
        let mut resp = self
            .agent
            .get(url)
            .header("User-Agent", USER_AGENT)
            .header("Authorization", basic_auth_header(username, password))
            .call()
            .map_err(|e| HttpError(e.to_string()))?;
        resp.body_mut()
            .read_to_string()
            .map_err(|e| HttpError(e.to_string()))
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
        let mut resp = req.send(body).map_err(|e| HttpError(e.to_string()))?;
        resp.body_mut()
            .read_to_string()
            .map_err(|e| HttpError(e.to_string()))
    }
}

/// A fake client for tests: maps URLs to canned response bodies, and
/// records the POSTs made (url + body) so tests can assert on them.
#[derive(Default)]
pub struct FakeHttpClient {
    responses: HashMap<String, String>,
    post_responses: HashMap<String, String>,
    posted: RefCell<Vec<(String, String)>>,
    posted_auth: RefCell<Vec<bool>>,
    authed_gets: RefCell<Vec<String>>,
}

impl FakeHttpClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, url: &str, body: &str) -> Self {
        self.responses.insert(url.to_string(), body.to_string());
        self
    }

    /// Add a canned response for a POST to `url`.
    pub fn with_post(mut self, url: &str, body: &str) -> Self {
        self.post_responses
            .insert(url.to_string(), body.to_string());
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

impl HttpClient for FakeHttpClient {
    fn get(&self, url: &str) -> Result<String, HttpError> {
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| HttpError(format!("no canned response for {url}")))
    }

    fn get_auth(&self, url: &str, username: &str, password: &str) -> Result<String, HttpError> {
        let _ = (username, password);
        self.authed_gets.borrow_mut().push(url.to_string());
        self.get(url)
    }

    fn post(&self, url: &str, body: &str, auth: Option<(&str, &str)>) -> Result<String, HttpError> {
        self.posted_auth.borrow_mut().push(auth.is_some());
        self.posted
            .borrow_mut()
            .push((url.to_string(), body.to_string()));
        self.post_responses
            .get(url)
            .cloned()
            .ok_or_else(|| HttpError(format!("no canned POST response for {url}")))
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
}
