//! Which OBS repo/arch counts, shared by the observer and the queues.
//!
//! One module defines the scope, so the gate and the wait cannot drift:
//! Factory repos (`openSUSE_(Factory|Tumbleweed)`, plus `standard` in
//! `openSUSE:Factory*` projects) and Leap 16 repos, on x86_64 and
//! aarch64. Widening takes optional extra repo/arch patterns in this one
//! place; any further freshcrab target is added here, never per-consumer.
//!
//! Rust reimplementation of the skill's `_obs_scope.py` (pure scope
//! logic only). The script's `origin` and `codes` helpers are not
//! ported: they parse osc XML listings/results, and freshcrab's OBS data
//! comes via geectl, never osc XML parsing.
//!
//! Semantics, preserved exactly from the source:
//!
//! * The repo patterns are full matches; the widening `repos`/`arches`
//!   patterns are searches, not full matches.
//! * `OFF` is `{"disabled"}` only: an `excluded` repo/arch still counts
//!   as judged, because exclusion follows the spec the change may edit.

use regex::Regex;
use std::sync::LazyLock;

/// Factory repos: `openSUSE_Factory`, `openSUSE_Factory_<word>`,
/// `openSUSE_Tumbleweed`. Full match.
static FACTORY_REPO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\AopenSUSE_(?:Factory(?:_\w+)?|Tumbleweed)\z")
        .expect("literal Factory repo pattern")
});

/// Leap 16 repos: `16.<digits>`, with optional `openSUSE_Leap_` prefix.
/// Full match.
static LEAP16_REPO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A(?:openSUSE_Leap_)?16\.\d+\z").expect("literal Leap 16 repo pattern")
});

/// Architectures that count by default.
const DEFAULT_ARCHES: &[&str] = &["x86_64", "aarch64"];

/// Build codes that mean a repo/arch is off: `disabled` only. An
/// `excluded` repo/arch still counts as judged, because exclusion
/// follows the spec the change may edit.
pub const OFF: &[&str] = &["disabled"];

/// Whether repo `repo` of project `project` is a Tumbleweed/Factory
/// repository: a Factory repo name, or repo `standard` in an
/// `openSUSE:Factory` project (including `openSUSE:Factory:*`).
pub fn factory(project: &str, repo: &str) -> bool {
    FACTORY_REPO.is_match(repo)
        || (repo == "standard"
            && (project == "openSUSE:Factory" || project.starts_with("openSUSE:Factory:")))
}

/// Whether repo `repo` is a Leap 16 repository.
pub fn is_leap16_repo(repo: &str) -> bool {
    LEAP16_REPO.is_match(repo)
}

/// Whether arch `arch` counts by default: x86_64 or aarch64.
pub fn is_default_arch(arch: &str) -> bool {
    DEFAULT_ARCHES.contains(&arch)
}

/// Whether build code `code` means the repo/arch is off: `disabled`
/// only. `excluded` still counts as judged.
pub fn is_off(code: &str) -> bool {
    OFF.contains(&code)
}

/// Whether repo/arch of a build in `project` counts under the default
/// scope: a Tumbleweed/Factory or Leap 16 repo on x86_64 or aarch64.
/// See [`Scope::judged`] for the widened form.
pub fn judged(project: &str, repo: &str, arch: &str) -> bool {
    Scope::default().judged(project, repo, arch)
}

/// The OBS scope: which repo/arch counts, with optional widening.
///
/// The default scope is the literal Factory/Leap scope: Factory repos
/// and Leap 16 repos on x86_64 and aarch64. Widening adds optional
/// extra repo/arch patterns, matched by search (not full match), in
/// this one place.
#[derive(Debug, Clone)]
pub struct Scope {
    /// Whether the Leap 16 arm counts. True by default; false disables
    /// it while the Factory arm and any widening still apply.
    leap: bool,
    /// Optional extra repo pattern, matched by search.
    extra_repos: Option<Regex>,
    /// Optional extra arch pattern, matched by search.
    extra_arches: Option<Regex>,
}

impl Default for Scope {
    /// The default scope: Leap on, no widening.
    fn default() -> Self {
        Self {
            leap: true,
            extra_repos: None,
            extra_arches: None,
        }
    }
}

impl Scope {
    /// The default scope: Leap on, no widening.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether the Leap 16 arm counts.
    pub fn with_leap(mut self, leap: bool) -> Self {
        self.leap = leap;
        self
    }

    /// Add an extra repo pattern, matched by search against the repo
    /// name. Fails on an invalid pattern.
    pub fn with_extra_repos(mut self, pattern: &str) -> Result<Self, regex::Error> {
        self.extra_repos = Some(Regex::new(pattern)?);
        Ok(self)
    }

    /// Add an extra arch pattern, matched by search against the arch
    /// name. Fails on an invalid pattern.
    pub fn with_extra_arches(mut self, pattern: &str) -> Result<Self, regex::Error> {
        self.extra_arches = Some(Regex::new(pattern)?);
        Ok(self)
    }

    /// Whether repo/arch of a build in `project` counts: a Tumbleweed
    /// or (with Leap on) Leap 16 repo, or one the extra repo pattern
    /// matches, on x86_64, aarch64 or an arch the extra arch pattern
    /// matches.
    pub fn judged(&self, project: &str, repo: &str, arch: &str) -> bool {
        let wanted = factory(project, repo)
            || (self.leap && is_leap16_repo(repo))
            || self
                .extra_repos
                .as_ref()
                .is_some_and(|repos| repos.is_match(repo));
        wanted
            && (is_default_arch(arch)
                || self
                    .extra_arches
                    .as_ref()
                    .is_some_and(|arches| arches.is_match(arch)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_repo_names() {
        assert!(factory("openSUSE:Factory", "openSUSE_Factory"));
        assert!(factory("openSUSE:Factory", "openSUSE_Factory_ARM"));
        assert!(factory("openSUSE:Factory", "openSUSE_Tumbleweed"));
    }

    #[test]
    fn factory_repo_name_negatives() {
        // Trailing underscore with no word after it, a hyphenated
        // suffix, and Slowroll are not Factory repos.
        assert!(!factory("openSUSE:Factory", "openSUSE_Factory_"));
        assert!(!factory("openSUSE:Factory", "openSUSE_Factory_ARM-extra"));
        assert!(!factory("openSUSE:Factory", "openSUSE_FactoryX"));
        assert!(!factory("openSUSE:Slowroll", "openSUSE_Slowroll"));
    }

    #[test]
    fn standard_repo_counts_in_factory_projects() {
        assert!(factory("openSUSE:Factory", "standard"));
        assert!(factory("openSUSE:Factory:Staging:A", "standard"));
        assert!(factory("openSUSE:Factory:ARM", "standard"));
    }

    #[test]
    fn standard_repo_does_not_count_outside_factory_projects() {
        assert!(!factory("openSUSE:Leap:16.0", "standard"));
        assert!(!factory("home:foo", "standard"));
        // No colon: not `openSUSE:Factory` and not under it.
        assert!(!factory("openSUSE:FactoryX", "standard"));
    }

    #[test]
    fn leap16_repo_names() {
        assert!(is_leap16_repo("16.0"));
        assert!(is_leap16_repo("16.1"));
        assert!(is_leap16_repo("openSUSE_Leap_16.0"));
        assert!(is_leap16_repo("openSUSE_Leap_16.10"));
    }

    #[test]
    fn leap16_repo_name_negatives() {
        assert!(!is_leap16_repo("15.6"));
        assert!(!is_leap16_repo("openSUSE_Leap_15.6"));
        assert!(!is_leap16_repo("16"));
        assert!(!is_leap16_repo("16.0.1"));
        assert!(!is_leap16_repo("openSUSE_Leap_16"));
        assert!(!is_leap16_repo("openSUSE_Slowroll"));
    }

    #[test]
    fn default_arches() {
        assert!(is_default_arch("x86_64"));
        assert!(is_default_arch("aarch64"));
        assert!(!is_default_arch("ppc64le"));
        assert!(!is_default_arch("s390x"));
        assert!(!is_default_arch("riscv64"));
    }

    #[test]
    fn judged_default_scope() {
        assert!(judged("openSUSE:Factory", "openSUSE_Tumbleweed", "x86_64"));
        assert!(judged("openSUSE:Factory", "openSUSE_Factory", "aarch64"));
        assert!(judged("openSUSE:Leap:16.0", "openSUSE_Leap_16.0", "x86_64"));
        assert!(judged("openSUSE:Factory", "standard", "aarch64"));
        // Right repo, wrong arch; right arch, wrong repo.
        assert!(!judged(
            "openSUSE:Factory",
            "openSUSE_Tumbleweed",
            "ppc64le"
        ));
        assert!(!judged("openSUSE:Factory", "openSUSE_Slowroll", "x86_64"));
    }

    #[test]
    fn leap_false_disables_the_leap_arm_only() {
        let scope = Scope::new().with_leap(false);
        assert!(!scope.judged("openSUSE:Leap:16.0", "openSUSE_Leap_16.0", "x86_64"));
        assert!(!scope.judged("openSUSE:Leap:16.0", "16.0", "x86_64"));
        assert!(scope.judged("openSUSE:Factory", "openSUSE_Tumbleweed", "x86_64"));
    }

    #[test]
    fn widening_extra_repos_match_by_search() {
        let scope = Scope::new()
            .with_leap(false)
            .with_extra_repos("Slowroll")
            .unwrap();
        assert!(scope.judged("openSUSE:Slowroll", "openSUSE_Slowroll", "x86_64"));
        // Search, not full match: a substring pattern counts.
        let scope = Scope::new()
            .with_leap(false)
            .with_extra_repos("15")
            .unwrap();
        assert!(scope.judged("openSUSE:Leap:15.6", "openSUSE_Leap_15.6", "x86_64"));
        assert!(!scope.judged("openSUSE:Leap:16.0", "openSUSE_Leap_16.0", "x86_64"));
    }

    #[test]
    fn widening_extra_arches_match_by_search() {
        let scope = Scope::new().with_extra_arches("ppc64").unwrap();
        assert!(scope.judged("openSUSE:Factory", "openSUSE_Tumbleweed", "ppc64le"));
        assert!(!scope.judged("openSUSE:Factory", "openSUSE_Tumbleweed", "s390x"));
        // Search, not full match: a substring pattern counts.
        let scope = Scope::new().with_extra_arches("riscv").unwrap();
        assert!(scope.judged("openSUSE:Factory", "openSUSE_Tumbleweed", "riscv64"));
    }

    #[test]
    fn widening_invalid_pattern_is_an_error() {
        assert!(Scope::new().with_extra_repos("[").is_err());
        assert!(Scope::new().with_extra_arches("(").is_err());
    }

    #[test]
    fn off_is_disabled_only() {
        assert_eq!(OFF, &["disabled"]);
        assert!(is_off("disabled"));
        // Excluded still counts as judged: exclusion follows the spec
        // the change may edit.
        assert!(!is_off("excluded"));
        assert!(!is_off("succeeded"));
        assert!(!is_off(""));
    }
}
