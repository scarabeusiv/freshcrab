//! Integration tests for RPM version comparison (via the library).
//! The fine-grained edge cases live in the unit tests in src/version.rs;
//! these cover the comparison contract the watcher relies on.

use freshcrab::version::{compare_evr, is_newer, rpmvercmp};
use std::cmp::Ordering;

#[test]
fn numeric_comparison_not_lexicographic() {
    // 1.10 > 1.9 numerically; a naive string compare gets this wrong.
    assert_eq!(rpmvercmp("1.10", "1.9"), Ordering::Greater);
    assert_eq!(rpmvercmp("2.0", "10.0"), Ordering::Less);
}

#[test]
fn tilde_prerelease_sorts_before_release() {
    assert_eq!(rpmvercmp("1.0~rc1", "1.0"), Ordering::Less);
    assert_eq!(rpmvercmp("1.0", "1.0~rc1"), Ordering::Greater);
}

#[test]
fn caret_snapshot_sorts_between_release_and_next() {
    assert_eq!(rpmvercmp("1.0^git1", "1.0"), Ordering::Greater);
    assert_eq!(rpmvercmp("1.0^git1", "1.0.1"), Ordering::Less);
}

#[test]
fn epoch_dominates_version() {
    assert_eq!(compare_evr("2:1.0", "1:9.9"), Ordering::Greater);
}

#[test]
fn is_newer_contract() {
    assert!(is_newer("2.0", "1.9"));
    assert!(!is_newer("1.0~rc1", "1.0"));
    assert!(!is_newer("1.0", "1.0"));
}
