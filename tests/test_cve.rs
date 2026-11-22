//! Integration tests for CVE validation: the changelog rule and the
//! unimplemented validator stub.

use freshcrab::cve::{
    changelog_names_cve, CveId, CveValidation, CveValidator, NotImplementedValidator,
};

#[test]
fn cve_id_parses_and_normalizes() {
    assert_eq!(
        CveId::parse("CVE-2026-12345").unwrap().as_str(),
        "CVE-2026-12345"
    );
    assert_eq!(
        CveId::parse("cve-2024-1234").unwrap().as_str(),
        "CVE-2024-1234"
    );
    assert!(CveId::parse("CVE-2026-123").is_err());
    assert!(CveId::parse("not-a-cve").is_err());
}

#[test]
fn changelog_rule_is_the_validation() {
    // The validation rule: a CVE is fixed in a version when the
    // changelog for that version names the CVE.
    let cve = CveId::parse("CVE-2026-12345").unwrap();
    let fixed = "- Fix a heap overflow (CVE-2026-12345).\n";
    assert!(changelog_names_cve(fixed, &cve));
    let not_fixed = "- Update to 2.0.\n";
    assert!(!changelog_names_cve(not_fixed, &cve));
}

#[test]
fn stub_validator_fails_loudly() {
    let validator = NotImplementedValidator;
    let cve = CveId::parse("CVE-2026-12345").unwrap();
    let err = validator.validate("foo", "1.9", &cve).unwrap_err();
    assert!(err.0.contains("not implemented"));
    // The regression-test hook fails loudly too.
    let err = validator
        .has_regression_test("foo", "1.9", &cve)
        .unwrap_err();
    assert!(err.0.contains("not implemented"));
    // The validation outcome type exists for the Leap step.
    assert_ne!(CveValidation::Fixed, CveValidation::NotFixed);
}
