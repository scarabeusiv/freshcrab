//! HTTP client abstraction.
//!
//! All network access goes through the [`HttpClient`] trait so the unit
//! tests can inject a fake that returns canned responses instead of
//! hitting the live network. The real implementation uses ureq (a small
//! synchronous HTTP client). Every request identifies itself with a
//! User-Agent that links to the project repository, as Repology requires
//! for bulk clients.

use std::collections::HashMap;
use std::fmt;

pub const USER_AGENT: &str = "freshcrab/0.1 (https://github.com/scarabeusiv/freshcrab)";

/// Error from an HTTP request.
#[derive(Debug)]
pub struct HttpError(pub String);

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "http error: {}", self.0)
    }
}

impl std::error::Error for HttpError {}

/// A synchronous HTTP GET client. Returns the response body as a string.
pub trait HttpClient {
    fn get(&self, url: &str) -> Result<String, HttpError>;
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
}

/// A fake client for tests: maps URLs to canned response bodies.
#[derive(Default)]
pub struct FakeHttpClient {
    responses: HashMap<String, String>,
}

impl FakeHttpClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, url: &str, body: &str) -> Self {
        self.responses.insert(url.to_string(), body.to_string());
        self
    }
}

impl HttpClient for FakeHttpClient {
    fn get(&self, url: &str) -> Result<String, HttpError> {
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| HttpError(format!("no canned response for {url}")))
    }
}
