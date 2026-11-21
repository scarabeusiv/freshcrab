//! Factory client: the current version of a package on openSUSE Factory.
//!
//! The Factory reads are geectl's public reads: `ObsClient::cat` for the
//! spec and `ObsClient::list_packages` for the package list, both over
//! `/public/source/...`, which needs no credentials. freshcrab implements
//! no OBS logic of its own here — no endpoint construction, no URL
//! building, no directory XML parsing (see docs/architecture.md for the
//! rule). The spec Version field is still parsed locally: it is a
//! package-file field, not OBS wire XML.

use geectl::error::GeectlError;
use geectl::obs::ObsClient;

/// The Factory project. The geectl OBS client carries its own copy of
/// the API base.
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
    obs: &'a ObsClient<'a>,
}

impl<'a> FactoryClient<'a> {
    pub fn new(obs: &'a ObsClient<'a>) -> Self {
        FactoryClient { obs }
    }

    /// Return the raw spec text for `package` on Factory.
    pub fn get_spec(&self, package: &str) -> Result<String, GeectlError> {
        let file = format!("{package}.spec");
        self.obs.cat(FACTORY_PROJECT, package, &file, None)
    }

    /// Return the Factory Version of `package`, or None.
    pub fn get_version(&self, package: &str) -> Result<Option<String>, GeectlError> {
        Ok(parse_spec_version(&self.get_spec(package)?))
    }

    /// Return the list of package names on Factory.
    pub fn list_packages(&self) -> Result<Vec<String>, GeectlError> {
        self.obs.list_packages(FACTORY_PROJECT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::FakeHttpClient;

    const SPEC_URL: &str = "https://api.opensuse.org/public/source/openSUSE:Factory/foo/foo.spec";
    const LIST_URL: &str = "https://api.opensuse.org/public/source/openSUSE:Factory";

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

    #[test]
    fn get_spec_reads_through_geectl_cat() {
        let http = FakeHttpClient::new().with(SPEC_URL, "Name: foo\nVersion: 1.2.3\nRelease: 1\n");
        let obs = ObsClient::new(&http);
        let factory = FactoryClient::new(&obs);
        assert_eq!(
            factory.get_spec("foo").unwrap(),
            "Name: foo\nVersion: 1.2.3\nRelease: 1\n"
        );
        assert_eq!(
            factory.get_version("foo").unwrap(),
            Some("1.2.3".to_string())
        );
    }

    #[test]
    fn list_packages_reads_through_geectl() {
        let http = FakeHttpClient::new().with(
            LIST_URL,
            "<directory><entry name=\"bar\"/><entry name=\"foo\"/></directory>",
        );
        let obs = ObsClient::new(&http);
        let factory = FactoryClient::new(&obs);
        assert_eq!(
            factory.list_packages().unwrap(),
            vec!["bar".to_string(), "foo".to_string()]
        );
    }

    #[test]
    fn get_spec_encodes_plus_in_package_name() {
        // Geectl percent-encodes `+` in path segments where the old
        // code passed it raw; the server decodes both to the same
        // segment, so the canned URL carries the encoded form.
        let url = "https://api.opensuse.org/public/source/openSUSE:Factory/libdbus-c%2B%2B/libdbus-c%2B%2B.spec";
        let http = FakeHttpClient::new().with(url, "Name: libdbus-c++\nVersion: 0.9.0\n");
        let obs = ObsClient::new(&http);
        let factory = FactoryClient::new(&obs);
        assert_eq!(
            factory.get_version("libdbus-c++").unwrap(),
            Some("0.9.0".to_string())
        );
    }

    #[test]
    fn dot_leading_package_is_rejected() {
        let http = FakeHttpClient::new();
        let obs = ObsClient::new(&http);
        let factory = FactoryClient::new(&obs);
        let err = factory.get_spec(".foo").unwrap_err();
        assert_eq!(err.kind(), geectl::error::ErrorKind::InvalidInput);
    }

    #[test]
    fn list_packages_parses_live_shaped_listing() {
        // Shaped like the real Factory listing: entries carry extra
        // attributes (multibuild flavors carry `originpackage`), and
        // the document ends with a trailing newline.
        let http = FakeHttpClient::new().with(
            LIST_URL,
            "<directory>\n<entry name=\"bar\" originpackage=\"bar\"/>\n<entry name=\"foo:flavor\"/>\n</directory>\n",
        );
        let obs = ObsClient::new(&http);
        let factory = FactoryClient::new(&obs);
        assert_eq!(
            factory.list_packages().unwrap(),
            vec!["bar".to_string(), "foo:flavor".to_string()]
        );
    }

    #[test]
    fn list_packages_rejects_malformed_listing() {
        let http = FakeHttpClient::new().with(LIST_URL, "<directory><entry /></directory>");
        let obs = ObsClient::new(&http);
        let factory = FactoryClient::new(&obs);
        assert!(factory.list_packages().is_err());
    }
}
