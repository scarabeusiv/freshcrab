//! Factory client: the current version of a package on openSUSE Factory.
//!
//! Reads the package spec from the OBS *public* API (`/public/source/...`)
//! and extracts the Version field. These reads need no credentials — the
//! plain `/source/...` endpoint returns 401 without them (verified live),
//! which is why the public namespace is used here.

use crate::collectors::{encode_path, valid_obs_name};
use crate::http::{HttpClient, HttpError};

// The OBS API base and the Factory project, shared with `obs.rs`
// (which imports them from here so there is exactly one definition).
pub const OBS_API: &str = "https://api.opensuse.org";
pub const FACTORY_PROJECT: &str = "openSUSE:Factory";

/// Extract the Version field from a spec file. Returns None if absent.
pub fn parse_spec_version(spec_text: &str) -> Option<String> {
    for line in spec_text.lines() {
        if let Some(rest) = line.strip_prefix("Version:") {
            let version = rest.trim().to_string();
            if !version.is_empty() {
                return Some(version);
            }
        }
    }
    None
}

#[derive(Clone, Copy)]
pub struct FactoryClient<'a> {
    http: &'a dyn HttpClient,
}

impl<'a> FactoryClient<'a> {
    pub fn new(http: &'a dyn HttpClient) -> Self {
        FactoryClient { http }
    }

    /// Return the raw spec text for `package` on Factory.
    pub fn get_spec(&self, package: &str) -> Result<String, HttpError> {
        if !valid_obs_name(package) {
            return Err(HttpError(format!("invalid OBS package name: {package:?}")));
        }
        let encoded = encode_path(package);
        let url = format!("{OBS_API}/public/source/{FACTORY_PROJECT}/{encoded}/{encoded}.spec");
        self.http.get(&url)
    }

    /// Return the Factory Version of `package`, or None.
    pub fn get_version(&self, package: &str) -> Result<Option<String>, HttpError> {
        Ok(parse_spec_version(&self.get_spec(package)?))
    }

    /// Return the list of package names on Factory.
    pub fn list_packages(&self) -> Result<Vec<String>, HttpError> {
        let url = format!("{OBS_API}/public/source/{FACTORY_PROJECT}");
        let body = self.http.get(&url)?;
        // The directory listing is XML: <directory><entry name="foo"/>...</directory>.
        // Extract entry names without an XML parser (the shape is fixed).
        let mut names = Vec::new();
        let mut rest = body.as_str();
        while let Some(pos) = rest.find("<entry") {
            let after = &rest[pos..];
            if let Some(name_pos) = after.find("name=\"") {
                let start = name_pos + "name=\"".len();
                if let Some(end) = after[start..].find('"') {
                    names.push(after[start..start + end].to_string());
                }
            }
            rest = &rest[pos + "<entry".len()..];
        }
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_found() {
        let spec = "Name: foo\nVersion: 1.2.3\nRelease: 1\n";
        assert_eq!(parse_spec_version(spec), Some("1.2.3".to_string()));
    }

    #[test]
    fn version_missing() {
        let spec = "Name: foo\nRelease: 1\n";
        assert_eq!(parse_spec_version(spec), None);
    }

    #[test]
    fn version_with_tilde() {
        let spec = "Version: 2.0~rc1\n";
        assert_eq!(parse_spec_version(spec), Some("2.0~rc1".to_string()));
    }
}
