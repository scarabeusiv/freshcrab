//! Project hygiene sweeps (issue #22): report-only detection of
//! obsolete platforms and long-broken never-integrated packages in
//! OBS devel and home projects.
//!
//! Two sweeps, both report-only: they list findings with the evidence
//! for each entry and change nothing. Automatic enforcement (removing
//! a repository from a project meta, deleting a package) comes later,
//! only once detection is trusted, and only for entries the maintainer
//! was notified about that stayed qualifying through the grace period.
//!
//! Policy (decided 2026-11-27, documented on issue #22):
//! - Duration threshold: 90 days.
//! - Broken means not building anywhere: the package fails in every
//!   repository that counts for it. For a package in Factory, that
//!   includes Tumbleweed. For a package only in devel, failing on
//!   Tumbleweed is fine as long as it builds on the older releases —
//!   Tumbleweed does not count toward broken for devel-only packages.
//! - Never-integrated means no accepted submit request ever: the
//!   update queue tries to integrate every package it watches, so a
//!   package that never got in was never meant to be in our projects,
//!   which points to deletion.
//! - Scope: both own devel projects and home projects.
//!
//! All OBS reads go through geectl's library (see
//! docs/architecture.md for the rule): project meta, build results,
//! job history, and the request search. A missing geectl surface is
//! a geectl gap, not new OBS logic here. Both sweeps need OBS
//! credentials: without them the calls fail closed instead of
//! reading anonymously or reporting an unchecked result.

use crate::factory::FACTORY_PROJECT;
use crate::http::map_obs_credentials_error;
use geectl::auth::Credentials;
use geectl::error::{ErrorKind, GeectlError};
use geectl::obs::{
    JobHistoryEntry, ObsClient, PackageBuildStatus, ProjectMeta, Repository, Request,
    RequestAction, RequestSearch, RequestState, ResultsQuery,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

/// Days a package must fail everywhere that counts before it is
/// long-broken.
pub const BROKEN_DURATION_DAYS: u64 = 90;

/// The same threshold in seconds, for comparing unix timestamps.
pub const BROKEN_DURATION_SECS: u64 = BROKEN_DURATION_DAYS * 24 * 60 * 60;

/// The project a repository builds against when it targets
/// Tumbleweed.
pub const TUMBLEWEED_PATH_PROJECT: &str = "openSUSE:Factory";

/// How many job-history entries to read per repository when dating
/// the last success. The entries come newest first, so a window that
/// reaches back past the threshold with no success proves no success
/// in the threshold.
const JOB_HISTORY_LIMIT: u32 = 200;

/// A build code that means the package failed to build.
pub fn is_failure_code(code: &str) -> bool {
    matches!(code, "failed" | "unresolvable" | "broken")
}

/// A build code that means the package built.
pub fn is_success_code(code: &str) -> bool {
    code == "succeeded"
}

/// A repository's build state for one package, across its
/// architectures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoBuild {
    /// The package succeeded on at least one architecture.
    Building,
    /// The package failed on at least one architecture and succeeded
    /// on none; the failure codes seen.
    Broken(Vec<String>),
    /// No success and no failure: disabled, in flight, or unknown.
    Neutral,
}

/// Classify one package's statuses in one repository: a success on
/// any architecture means the package builds there; otherwise the
/// failure codes seen, if any.
pub fn classify_repo(statuses: &[PackageBuildStatus]) -> RepoBuild {
    let mut failures: Vec<String> = Vec::new();
    for status in statuses {
        if is_success_code(&status.code) {
            return RepoBuild::Building;
        }
        if is_failure_code(&status.code) && !failures.contains(&status.code) {
            failures.push(status.code.clone());
        }
    }
    if failures.is_empty() {
        RepoBuild::Neutral
    } else {
        RepoBuild::Broken(failures)
    }
}

/// True when the repository targets Tumbleweed: one of its build
/// paths points at the Factory project.
pub fn repo_is_tumbleweed(repo: &Repository) -> bool {
    repo.paths
        .iter()
        .any(|(project, _)| project == TUMBLEWEED_PATH_PROJECT)
}

/// True when `source_project` is `project` itself or a branch of it.
/// A branch carries `:branches:<project>` after the branching user's
/// home (a branch of a branch nests the marker, which the suffix
/// form still matches).
pub fn is_branch_of(source_project: &str, project: &str) -> bool {
    source_project == project
        || source_project.ends_with(&format!(":branches:{project}"))
}

/// True when the request integrated `package` out of `project`: a
/// submit action whose source is the project or a branch of it.
pub fn request_integrated_package(req: &Request, project: &str, package: &str) -> bool {
    req.actions.iter().any(|action| match action {
        RequestAction::Submit {
            source_project,
            source_package,
            ..
        } => source_package == package && is_branch_of(source_project, project),
        _ => false,
    })
}

/// True when the job history proves no success in the threshold
/// before `now_unix`: the last success (when there is one) predates
/// the threshold, or the window reaches back past the threshold with
/// no success at all. An empty history, a success with no usable
/// time, or a window that does not reach back past the threshold
/// proves nothing: false (fail-closed).
pub fn sustained_broken(entries: &[JobHistoryEntry], now_unix: u64) -> bool {
    let cutoff = now_unix.saturating_sub(BROKEN_DURATION_SECS);
    let mut last_success: Option<u64> = None;
    for entry in entries.iter().filter(|e| is_success_code(&e.code)) {
        let Some(t) = entry.endtime.or(entry.starttime).or(entry.readytime) else {
            // A success with no usable time cannot be dated: the
            // duration is unproven.
            return false;
        };
        last_success = Some(last_success.map_or(t, |m| m.max(t)));
    }
    match last_success {
        Some(t) => t < cutoff,
        None => {
            // No success in the window: sustained only when the
            // window reaches back past the cutoff.
            match entries
                .iter()
                .filter_map(|e| e.endtime.or(e.starttime).or(e.readytime))
                .min()
            {
                Some(oldest) => oldest < cutoff,
                None => false,
            }
        }
    }
}

/// One obsolete repository path: a repository in the swept project
/// whose build path targets a project or repository that no longer
/// exists upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObsoleteRepository {
    /// The swept project.
    pub project: String,
    /// The repository in the swept project carrying the obsolete path.
    pub repository: String,
    /// The path's target project.
    pub path_project: String,
    /// The path's target repository.
    pub path_repository: String,
    /// Why the path is obsolete.
    pub reason: String,
}

/// One repository's failure evidence for a long-broken package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepoFailure {
    /// The repository.
    pub repository: String,
    /// The failure codes seen across the repository's architectures.
    pub codes: Vec<String>,
    /// The last successful build's unix time, when the package ever
    /// succeeded in this repository.
    pub last_success_unix: Option<u64>,
}

/// One long-broken never-integrated package: failing in every
/// repository that counts for it, with no success in the threshold,
/// and no accepted submit request ever out of the project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LongBrokenPackage {
    /// The swept project.
    pub project: String,
    /// The package.
    pub package: String,
    /// Whether the package is in Factory (so Tumbleweed counts for
    /// it); false for a devel-only package.
    pub in_factory: bool,
    /// The failure evidence, one entry per repository that counts.
    pub failures: Vec<RepoFailure>,
}

/// The hygiene findings for one project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectHygiene {
    /// The swept project.
    pub project: String,
    /// Obsolete repository paths in the project meta.
    pub obsolete_repositories: Vec<ObsoleteRepository>,
    /// Long-broken never-integrated packages in the project.
    pub long_broken_packages: Vec<LongBrokenPackage>,
}

/// The hygiene report: one entry per swept project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HygieneReport {
    /// The swept projects, in the order they were given.
    pub projects: Vec<ProjectHygiene>,
}

/// Require OBS credentials on the client, naming the variables
/// freshcrab users set. The sweeps read authenticated endpoints
/// (build results, request search) and an anonymous read of a hidden
/// project would 404, which the obsolete sweep would misread as a
/// missing target — so the check runs before any read.
fn require_credentials(obs: &ObsClient) -> Result<(), GeectlError> {
    match obs.credentials() {
        Credentials::Basic { .. } | Credentials::Bearer { .. } => Ok(()),
        _ => Err(GeectlError::new(
            ErrorKind::ConfigError,
            "project hygiene needs OBS credentials (OSC_USERNAME + OSC_PASSWORD)",
        )),
    }
}

/// Map a geectl credentials error at the seam, so it names the
/// `OSC_*` variables freshcrab users set instead of geectl's
/// `GEECTL_OBS_*` ones. Other errors pass through untouched.
fn map_credentials_error(e: GeectlError) -> GeectlError {
    if e.kind() == ErrorKind::ConfigError {
        map_obs_credentials_error(&e)
    } else {
        e
    }
}

/// The obsolete-platforms sweep for one project: every repository
/// path in the project meta whose target project does not exist, or
/// whose target repository is not in the target project. Target
/// metas are cached: many repositories share path targets. A
/// non-NotFound failure reading a target fails the sweep loudly
/// instead of listing a live path as obsolete.
pub fn sweep_obsolete_repositories(
    obs: &ObsClient,
    project: &str,
) -> Result<Vec<ObsoleteRepository>, GeectlError> {
    require_credentials(obs)?;
    let meta = obs
        .project_meta_authenticated(project)
        .map_err(map_credentials_error)?;
    let mut target_metas: HashMap<String, Option<ProjectMeta>> = HashMap::new();
    let mut findings: Vec<ObsoleteRepository> = Vec::new();
    for repo in &meta.repositories {
        for (path_project, path_repository) in &repo.paths {
            if !target_metas.contains_key(path_project) {
                match obs.project_meta_authenticated(path_project) {
                    Ok(target) => {
                        target_metas.insert(path_project.clone(), Some(target));
                    }
                    Err(e) if e.kind() == ErrorKind::NotFound => {
                        target_metas.insert(path_project.clone(), None);
                    }
                    Err(e) => return Err(map_credentials_error(e)),
                }
            }
            match &target_metas[path_project] {
                Some(target) => {
                    if !target
                        .repositories
                        .iter()
                        .any(|r| &r.name == path_repository)
                    {
                        findings.push(ObsoleteRepository {
                            project: project.to_string(),
                            repository: repo.name.clone(),
                            path_project: path_project.clone(),
                            path_repository: path_repository.clone(),
                            reason: "target repository does not exist in target project"
                                .to_string(),
                        });
                    }
                }
                None => {
                    findings.push(ObsoleteRepository {
                        project: project.to_string(),
                        repository: repo.name.clone(),
                        path_project: path_project.clone(),
                        path_repository: path_repository.clone(),
                        reason: "target project does not exist".to_string(),
                    });
                }
            }
        }
    }
    findings.sort_by(|a, b| {
        (
            a.repository.clone(),
            a.path_project.clone(),
            a.path_repository.clone(),
        )
            .cmp(&(
                b.repository.clone(),
                b.path_project.clone(),
                b.path_repository.clone(),
            ))
    });
    findings.dedup();
    Ok(findings)
}

/// Whether the package ever had an accepted submit request out of
/// `project`: an accepted submit action whose source is the project
/// or a branch of it. The search filters to accepted submit requests
/// with the package as a source; the project/branch filter runs here
/// because a same-named package in another project, or a request
/// whose submit action covers another package, must not count.
fn ever_integrated(
    obs: &ObsClient,
    project: &str,
    package: &str,
) -> Result<bool, GeectlError> {
    let search = RequestSearch::new()
        .source_packages(vec![package.to_string()])
        .states(vec![RequestState::Accepted])
        .types(vec!["submit".to_string()]);
    let requests = obs
        .search_requests(&search)
        .map_err(map_credentials_error)?;
    Ok(requests
        .iter()
        .any(|req| request_integrated_package(req, project, package)))
}

/// The long-broken sweep for one project: packages failing in every
/// repository that counts for them, with no success in the threshold
/// in any of those repositories, and no accepted submit request ever
/// out of the project. A package that builds in any counting
/// repository, or whose duration is unproven, is not listed.
pub fn sweep_long_broken(
    obs: &ObsClient,
    project: &str,
    now_unix: u64,
) -> Result<Vec<LongBrokenPackage>, GeectlError> {
    require_credentials(obs)?;
    let factory_packages: HashSet<String> = obs
        .list_packages(FACTORY_PROJECT)
        .map_err(map_credentials_error)?
        .into_iter()
        .collect();
    let packages = obs
        .list_packages(project)
        .map_err(map_credentials_error)?;
    let meta = obs
        .project_meta_authenticated(project)
        .map_err(map_credentials_error)?;
    let results = obs
        .results(project, &ResultsQuery::default())
        .map_err(map_credentials_error)?;

    // The build matrix, keyed by (repository, package): the statuses
    // with the architecture each came from.
    let mut by_repo_package: HashMap<(String, String), Vec<(String, PackageBuildStatus)>> =
        HashMap::new();
    for cell in &results.results {
        for status in &cell.statuses {
            by_repo_package
                .entry((cell.repository.clone(), status.package.clone()))
                .or_default()
                .push((cell.arch.clone(), status.clone()));
        }
    }

    let mut broken: Vec<LongBrokenPackage> = Vec::new();
    for package in &packages {
        let in_factory = factory_packages.contains(package);
        // The repositories that count for this package: the
        // project's repositories with build evidence, excluding
        // Tumbleweed for a devel-only package.
        let mut failures: Vec<RepoFailure> = Vec::new();
        let mut builds_somewhere = false;
        for repo in &meta.repositories {
            if in_factory || !repo_is_tumbleweed(repo) {
                let statuses: Vec<PackageBuildStatus> = by_repo_package
                    .get(&(repo.name.clone(), package.clone()))
                    .map(|entries| entries.iter().map(|(_, s)| s.clone()).collect())
                    .unwrap_or_default();
                match classify_repo(&statuses) {
                    RepoBuild::Building => {
                        builds_somewhere = true;
                    }
                    RepoBuild::Broken(codes) => {
                        failures.push(RepoFailure {
                            repository: repo.name.clone(),
                            codes,
                            last_success_unix: None,
                        });
                    }
                    RepoBuild::Neutral => {}
                }
            }
        }
        if builds_somewhere || failures.is_empty() {
            continue;
        }
        // Sustained: no success in the threshold in any counting
        // repository. The history runs on an architecture where the
        // package fails, so the jobs it returns are this package's.
        let mut sustained = true;
        for failure in &mut failures {
            let Some(failing_arch) = by_repo_package
                .get(&(failure.repository.clone(), package.clone()))
                .and_then(|entries| {
                    entries
                        .iter()
                        .find(|(_, s)| is_failure_code(&s.code))
                        .map(|(arch, _)| arch.clone())
                })
            else {
                sustained = false;
                break;
            };
            let history = match obs.job_history(
                project,
                &failure.repository,
                &failing_arch,
                Some(package),
                Some(JOB_HISTORY_LIMIT),
                None,
            ) {
                Ok(history) => history,
                Err(e) => return Err(map_credentials_error(e)),
            };
            failure.last_success_unix = history
                .iter()
                .filter(|e| is_success_code(&e.code))
                .filter_map(|e| e.endtime.or(e.starttime).or(e.readytime))
                .max();
            if !sustained_broken(&history, now_unix) {
                sustained = false;
                break;
            }
        }
        if !sustained {
            continue;
        }
        if ever_integrated(obs, project, package)? {
            continue;
        }
        broken.push(LongBrokenPackage {
            project: project.to_string(),
            package: package.clone(),
            in_factory,
            failures,
        });
    }
    broken.sort_by(|a, b| a.package.cmp(&b.package));
    Ok(broken)
}

/// Both sweeps for one project.
pub fn sweep_project(
    obs: &ObsClient,
    project: &str,
    now_unix: u64,
) -> Result<ProjectHygiene, GeectlError> {
    Ok(ProjectHygiene {
        project: project.to_string(),
        obsolete_repositories: sweep_obsolete_repositories(obs, project)?,
        long_broken_packages: sweep_long_broken(obs, project, now_unix)?,
    })
}

/// Both sweeps for each project, in the order given.
pub fn run_hygiene(
    obs: &ObsClient,
    projects: &[String],
    now_unix: u64,
) -> Result<HygieneReport, GeectlError> {
    let mut report = HygieneReport {
        projects: Vec::new(),
    };
    for project in projects {
        report.projects.push(sweep_project(obs, project, now_unix)?);
    }
    Ok(report)
}

/// The current unix time, for stamping a run.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use geectl::obs::{JobHistoryEntry, PackageBuildStatus, Repository};

    fn repo_named(name: &str, paths: Vec<(String, String)>) -> Repository {
        Repository {
            name: name.to_string(),
            arch: vec!["x86_64".to_string()],
            paths,
            rebuild: None,
            block: None,
            linkedbuild: None,
            downloads: vec![],
            release_targets: vec![],
            hostsystem: vec![],
        }
    }

    fn status(package: &str, code: &str) -> PackageBuildStatus {
        PackageBuildStatus {
            package: package.to_string(),
            code: code.to_string(),
            details: None,
        }
    }

    fn job(code: &str, endtime: Option<u64>) -> JobHistoryEntry {
        JobHistoryEntry {
            repository: None,
            arch: None,
            package: "foo".to_string(),
            rev: None,
            srcmd5: None,
            versrel: None,
            bcnt: None,
            readytime: None,
            starttime: None,
            endtime,
            code: code.to_string(),
            uri: None,
            workerid: None,
            hostarch: None,
            reason: None,
            verifymd5: None,
        }
    }

    #[test]
    fn failure_codes_are_exact() {
        assert!(is_failure_code("failed"));
        assert!(is_failure_code("unresolvable"));
        assert!(is_failure_code("broken"));
        assert!(!is_failure_code("succeeded"));
        assert!(!is_failure_code("disabled"));
        assert!(!is_failure_code("blocked"));
        assert!(is_success_code("succeeded"));
        assert!(!is_success_code("failed"));
    }

    #[test]
    fn classify_repo_success_beats_failure() {
        assert_eq!(
            classify_repo(&[status("foo", "failed"), status("foo", "succeeded")]),
            RepoBuild::Building
        );
        assert_eq!(
            classify_repo(&[status("foo", "failed"), status("foo", "unresolvable")]),
            RepoBuild::Broken(vec!["failed".to_string(), "unresolvable".to_string()])
        );
        assert_eq!(
            classify_repo(&[status("foo", "disabled"), status("foo", "blocked")]),
            RepoBuild::Neutral
        );
        assert_eq!(classify_repo(&[]), RepoBuild::Neutral);
    }

    #[test]
    fn tumbleweed_is_the_factory_path() {
        assert!(repo_is_tumbleweed(&repo_named(
            "openSUSE_Tumbleweed",
            vec![(
                "openSUSE:Factory".to_string(),
                "standard".to_string()
            )]
        )));
        assert!(!repo_is_tumbleweed(&repo_named(
            "openSUSE_Leap_15.6",
            vec![(
                "openSUSE:Leap:15.6".to_string(),
                "standard".to_string()
            )]
        )));
        assert!(!repo_is_tumbleweed(&repo_named("standard", vec![])));
    }

    #[test]
    fn branch_detection_is_exact() {
        assert!(is_branch_of("devel:languages:python", "devel:languages:python"));
        assert!(is_branch_of(
            "home:scarabeus_iv:branches:devel:languages:python",
            "devel:languages:python"
        ));
        assert!(is_branch_of(
            "home:scarabeus_iv:branches:home:scarabeus_iv:branches:devel:languages:python",
            "devel:languages:python"
        ));
        assert!(!is_branch_of("devel:languages:ruby", "devel:languages:python"));
        // A subproject of another project is not a branch of this one.
        assert!(!is_branch_of("bar:foo", "foo"));
        assert!(!is_branch_of(
            "home:other:branches:devel:languages:ruby",
            "devel:languages:python"
        ));
    }

    #[test]
    fn sustained_needs_no_success_in_threshold() {
        let now = 1_800_000_000u64;
        let cutoff = now - BROKEN_DURATION_SECS;
        // Last success just inside the threshold: not sustained.
        assert!(!sustained_broken(&[job("succeeded", Some(cutoff + 1))], now));
        // Last success just outside: sustained.
        assert!(sustained_broken(&[job("succeeded", Some(cutoff - 1))], now));
        // Failures only, window reaching past the cutoff: sustained.
        assert!(sustained_broken(
            &[
                job("failed", Some(cutoff + 100)),
                job("failed", Some(cutoff - 100)),
            ],
            now
        ));
        // Failures only, window not reaching the cutoff: unproven.
        assert!(!sustained_broken(&[job("failed", Some(cutoff + 100))], now));
        // No jobs at all: unproven.
        assert!(!sustained_broken(&[], now));
        // An undated success: unproven.
        assert!(!sustained_broken(&[job("succeeded", None)], now));
    }
}
