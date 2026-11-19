//! CVE validation: is a given CVE fixed in a given package version?
//!
//! The validation rule (see `docs/leap-and-cve.md`): a security fix's
//! changelog (`.changes`) entry must carry the CVE reference. Validation
//! compares the package's changelog entries against the CVE list — if
//! the changelog for a version names the CVE, the CVE is fixed in that
//! version; if it does not, it is not. This module holds the rule and
//! the validator interface. The data-source integration (fetching the
//! CVE list and the changelog from OBS) is the later Leap step and is
//! NOT implemented here.
//!
//! Security is the reason this exists: automated agents get exploited,
//! so the highest-priority work this system does is security fixes, and
//! the changelog check is the verification that a security fix actually
//! landed — not a version number going up, which a backport does not do.

use std::fmt;

/// A CVE identifier, e.g. `CVE-2026-12345`. Stored in canonical
/// uppercase form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CveId(String);

impl CveId {
    /// Parse and validate a CVE id: `CVE-<year>-<number>`, year 1999 or
    /// later, number at least 4 digits. Accepts lowercase input and
    /// normalizes it to uppercase.
    pub fn parse(s: &str) -> Result<Self, CveError> {
        let upper = s.to_ascii_uppercase();
        let parts: Vec<&str> = upper.split('-').collect();
        if parts.len() != 3 || parts[0] != "CVE" {
            return Err(CveError(format!("invalid CVE id: {s:?}")));
        }
        let year = parts[1];
        let number = parts[2];
        let year_ok = year.len() == 4
            && year.chars().all(|c| c.is_ascii_digit())
            && year.parse::<u32>().map(|y| y >= 1999).unwrap_or(false);
        let number_ok = number.len() >= 4 && number.chars().all(|c| c.is_ascii_digit());
        if !year_ok || !number_ok {
            return Err(CveError(format!("invalid CVE id: {s:?}")));
        }
        Ok(CveId(upper))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error from CVE validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveError(pub String);

impl fmt::Display for CveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cve error: {}", self.0)
    }
}

impl std::error::Error for CveError {}

/// The outcome of validating one CVE against one package version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CveValidation {
    /// The changelog for this version names the CVE: the fix is present.
    Fixed,
    /// The changelog for this version does not name the CVE: not fixed.
    NotFixed,
    /// Could not determine (changelog or CVE data unavailable).
    Unknown,
}

/// The primary check: does the changelog text reference this CVE?
///
/// Case-insensitive on the id. The match must not be a prefix of a
/// longer number, so `CVE-2026-123` does not match a changelog that
/// names `CVE-2026-1234`. Returns false for an empty changelog.
pub fn changelog_names_cve(changelog: &str, cve: &CveId) -> bool {
    let haystack = changelog.to_ascii_lowercase();
    let needle = cve.as_str().to_ascii_lowercase();
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(&needle) {
        let after = start + pos + needle.len();
        // A digit right after the match means the changelog names a
        // longer CVE number that merely starts with this id.
        if after >= haystack.len() || !haystack.as_bytes()[after].is_ascii_digit() {
            return true;
        }
        start = after;
    }
    false
}

/// Validates whether CVEs are fixed in a package version.
///
/// The later Leap step implements this against the CVE data source and
/// the package changelog from OBS; the check it applies is
/// `changelog_names_cve`. The Factory path never calls a validator:
/// for Factory, the version comparison alone decides.
///
/// `has_regression_test` is the second half of the evidence: the
/// `%check` regression test that proves the fix (see
/// `docs/leap-and-cve.md`). The changelog entry is the tracking layer
/// (the CVE is claimed fixed); the regression test is the correctness
/// layer (the CVE is actually fixed, and stays fixed). The later step
/// implements it by inspecting the spec's `%check` section for a test
/// exercising the CVE.
pub trait CveValidator {
    /// Validate one CVE against one version of a package.
    fn validate(
        &self,
        package: &str,
        version: &str,
        cve: &CveId,
    ) -> Result<CveValidation, CveError>;

    /// True when the package version carries a `%check` regression test
    /// exercising this CVE — a test that fails on the unpatched code
    /// and passes with the fix applied. Err when it cannot be
    /// determined (e.g. the spec is unavailable).
    fn has_regression_test(
        &self,
        package: &str,
        version: &str,
        cve: &CveId,
    ) -> Result<bool, CveError>;
}

/// A validator that is explicitly not implemented. It exists so the
/// Factory path (and tests) can prove the seam: calling it is always an
/// error, never a silent pass. The real implementation is the later
/// Leap step.
pub struct NotImplementedValidator;

impl CveValidator for NotImplementedValidator {
    fn validate(
        &self,
        _package: &str,
        _version: &str,
        _cve: &CveId,
    ) -> Result<CveValidation, CveError> {
        Err(CveError(
            "CVE validation is not implemented yet (see docs/leap-and-cve.md)".to_string(),
        ))
    }

    fn has_regression_test(
        &self,
        _package: &str,
        _version: &str,
        _cve: &CveId,
    ) -> Result<bool, CveError> {
        Err(CveError(
            "CVE validation is not implemented yet (see docs/leap-and-cve.md)".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid() {
        assert_eq!(
            CveId::parse("CVE-2026-12345").unwrap().as_str(),
            "CVE-2026-12345"
        );
        // Lowercase input normalizes to canonical uppercase.
        assert_eq!(
            CveId::parse("cve-2024-1234").unwrap().as_str(),
            "CVE-2024-1234"
        );
    }

    #[test]
    fn parse_invalid() {
        assert!(CveId::parse("").is_err());
        assert!(CveId::parse("CVE-2026").is_err());
        assert!(CveId::parse("CVE-2026-123").is_err());
        assert!(CveId::parse("CVE-1998-1234").is_err());
        assert!(CveId::parse("CVE-2026-12ab").is_err());
        assert!(CveId::parse("BUG-2026-1234").is_err());
        assert!(CveId::parse("CVE-2026-1234-extra").is_err());
    }

    #[test]
    fn changelog_names_cve_present() {
        let cve = CveId::parse("CVE-2026-12345").unwrap();
        let changelog = "- Fix a heap overflow (CVE-2026-12345, boo#1234567).\n";
        assert!(changelog_names_cve(changelog, &cve));
    }

    #[test]
    fn changelog_names_cve_absent() {
        let cve = CveId::parse("CVE-2026-12345").unwrap();
        let changelog = "- Update to 2.0.\n- Fix a crash on empty input.\n";
        assert!(!changelog_names_cve(changelog, &cve));
        assert!(!changelog_names_cve("", &cve));
    }

    #[test]
    fn changelog_names_cve_case_insensitive() {
        let cve = CveId::parse("CVE-2026-12345").unwrap();
        assert!(changelog_names_cve("fixed cve-2026-12345\n", &cve));
    }

    #[test]
    fn changelog_names_cve_no_prefix_collision() {
        // CVE-2026-123 must not match a changelog naming CVE-2026-1234.
        let short = CveId::parse("CVE-2026-0123").unwrap();
        let changelog = "- Fix CVE-2026-01234.\n";
        assert!(!changelog_names_cve(changelog, &short));
        // But the full id does match.
        let full = CveId::parse("CVE-2026-01234").unwrap();
        assert!(changelog_names_cve(changelog, &full));
    }

    #[test]
    fn not_implemented_validator_fails_loudly() {
        let validator = NotImplementedValidator;
        let cve = CveId::parse("CVE-2026-12345").unwrap();
        let err = validator.validate("foo", "1.9", &cve).unwrap_err();
        assert!(err.0.contains("not implemented"));
        // The regression-test hook fails loudly too, never silently
        // reporting "no test" or "test present".
        let err = validator
            .has_regression_test("foo", "1.9", &cve)
            .unwrap_err();
        assert!(err.0.contains("not implemented"));
    }
}
