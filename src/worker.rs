//! The update worker: drive one queued package through the update
//! pipeline (branch, bump, clean, build, validate, audit, file).
//!
//! The worker follows `worker/brief.md`. For one queue entry it:
//!
//! 1. resolves the devel project (via the OBS public API),
//! 2. re-checks the deduplication rules (devel already has the version?
//!    open SR already targets the package?) — the queue entry may be
//!    stale, so the checks run again at dispatch time, fail-closed,
//! 3. resolves the branch project (the OBS home project the branch
//!    lives in: config `home_project`, else `home:{OBS username}`),
//! 4. builds the [`UpdatePlan`] — the structured, validated plan for
//!    the update, including the one `.changes` entry and the SR
//!    description — and enforces the changelog rules (a security entry
//!    must name its CVE; see `docs/leap-and-cve.md`),
//! 5. builds the [`SrPayload`](geectl::obs::SrPayload) for the submission,
//! 6. executes the update steps through the [`UpdateExecutor`], and
//! 7. files the SR through [`SrFiling`](geectl::obs::SrFiling).
//!
//! The update steps themselves (branch, bump, spec-cleaner, OBS build,
//! rpmcrab, adversarial audit) are performed by the executor. Only the
//! [`DryRunExecutor`] is shipped: in dry-run it logs the would-do steps
//! and returns `Planned`; in live mode it refuses, so no SR is ever filed
//! on a plan that was not actually executed. The live executor (the
//! agent/CI step, per `worker/brief.md`) is not implemented yet. Filing a
//! live SR for an update that never happened would file a bogus request,
//! so the pipeline stops and escalates instead.
//!
//! Dry-run / live boundary: every mutating step goes through the single
//! dry-run guard (`DryRun::allow`). In dry-run the worker logs the full
//! plan and the exact SR payload and files nothing; the queue entry
//! stays `pending`. In live mode (only reachable with a live executor)
//! the SR is filed and the entry is marked done with the request id.

use crate::cve::{changelog_names_cve, CveId};
use crate::dry_run::DryRun;
use crate::http::map_obs_credentials_error;
use crate::queue::{QueueEntry, UpdateKind};
use crate::target::Target;
use crate::version::is_newer;
use geectl::auth::Credentials;
use geectl::error::{ErrorKind, GeectlError};
use geectl::obs::{ObsClient, SrFiling, SrPayload};
use std::fmt;

/// The packager identity used for `.changes` entries (see
/// `worker/brief.md`).
pub const CHANGELOG_AUTHOR: &str = "Tomáš Chvátal <tomas.chvatal@gmail.com>";

/// The structured plan for updating one package: the steps from
/// `worker/brief.md`, as data. Built purely from the queue entry, the
/// devel project, and the branch project; executing it is the
/// executor's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlan {
    pub package: String,
    pub factory_version: String,
    pub upstream_version: String,
    /// The collector that confirmed the upstream version.
    pub source: String,
    /// The devel project the SR targets.
    pub devel_project: String,
    /// The OBS home project the branch lives in. None when it could not
    /// be resolved (no `home_project` in config, no OBS credentials):
    /// the plan is still built and logged, but no SR payload can be
    /// built from it — an unresolved branch project is an error, not a
    /// placeholder (see `payload_from_plan`): a payload with a made-up
    /// source project would file to the wrong place.
    pub branch_project: Option<String>,
    pub kind: UpdateKind,
    pub target: Target,
    /// The one `.changes` entry for this submission.
    pub changes_entry: String,
    /// The SR description text.
    pub description: String,
    /// The CVEs this submission claims to fix (empty for routine
    /// bumps). Carried so the SR payload can enforce the
    /// changelog-CVE rule at build time (see `payload_from_plan`).
    pub cves: Vec<CveId>,
    /// The `%check` CVE regression-test requirement, for security
    /// entries: add a test that fails on the unpatched code and passes
    /// with the fix, or document why none is feasible. None for routine
    /// bumps (no CVE, no regression test required).
    pub cve_regression_test: Option<String>,
}

/// What the executor did with the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Execution {
    /// Dry-run: the steps were logged as would-do; nothing was executed.
    Planned,
    /// Live: the update steps were performed and the SR may be filed.
    Completed,
}

/// Executes the update steps for a plan (branch, bump, spec-cleaner,
/// OBS build, rpmcrab, adversarial audit). The SR is filed only after
/// the executor reports [`Execution::Completed`] — never on a plan
/// alone.
pub trait UpdateExecutor {
    /// Execute the update steps for `plan`. Returns [`Execution::Planned`]
    /// in dry-run (steps logged, nothing executed) or
    /// [`Execution::Completed`] in live mode when the update is really
    /// done. Err when the update cannot be performed (with the reason).
    fn execute(&self, plan: &UpdatePlan, dry_run: &DryRun) -> Result<Execution, String>;
}

/// The shipped executor: in dry-run it logs the would-do
/// steps (branch, bump, spec-cleaner, build, rpmcrab, audit) and returns
/// [`Execution::Planned`]; in live mode it refuses, because the live
/// executor is the agent/CI step and does not exist yet. Refusing is
/// the safe answer: a live SR must never be filed for an update that
/// was not actually performed.
pub struct DryRunExecutor;

impl UpdateExecutor for DryRunExecutor {
    fn execute(&self, plan: &UpdatePlan, dry_run: &DryRun) -> Result<Execution, String> {
        if dry_run.live() {
            return Err(
                "live update executor is not configured yet (the agent/CI step); \
                 refusing to file a submit request on an unexecuted plan"
                    .to_string(),
            );
        }
        let branch = plan
            .branch_project
            .clone()
            .unwrap_or_else(|| "<unresolved home project>".to_string());
        dry_run.note(&format!(
            "would branch {} from {} into {}",
            plan.package, plan.devel_project, branch
        ));
        dry_run.note(&format!(
            "would bump {} to {} (tarball + Version + one .changes entry)",
            plan.package, plan.upstream_version
        ));
        dry_run.note(&format!(
            "would run spec-cleaner -i --remove-groups --suse-copyright on {}",
            plan.package
        ));
        dry_run.note(&format!("would build {} in OBS ({})", plan.package, branch));
        dry_run.note(&format!(
            "would run rpmcrab over the built RPMs for {} (target 0E/0W)",
            plan.package
        ));
        if let Some(note) = &plan.cve_regression_test {
            dry_run.note(&format!("would {note}"));
        }
        dry_run.note(&format!(
            "would run the pre-filing adversarial audit for {}",
            plan.package
        ));
        Ok(Execution::Planned)
    }
}

/// Map an OBS-call failure to the outcome: an auth failure is a
/// run-level failure ([`WorkerOutcome::AuthRejected`]), anything else
/// escalates the package. Geectl's no-credentials error names its own
/// `GEECTL_OBS_*` variables; the error is mapped first so the reason
/// names freshcrab's `OSC_*` variables instead (see
/// [`map_obs_credentials_error`]). The kind is preserved, so the
/// auth/escalate decision is unaffected.
fn obs_failure(e: &GeectlError, what: &str) -> WorkerOutcome {
    let mapped = map_obs_credentials_error(e);
    let reason = format!("{what}: {mapped}");
    if mapped.kind() == ErrorKind::AuthFailed {
        WorkerOutcome::AuthRejected { reason }
    } else {
        WorkerOutcome::Escalated { reason }
    }
}

/// Map a filing failure to the outcome. Preserve the variant: an auth
/// failure at filing time must stay distinguishable so the dispatcher
/// fails the run loudly instead of escalating the package. The error
/// is mapped first so the reason names freshcrab's `OSC_*` variables
/// instead of geectl's `GEECTL_OBS_*` (see
/// [`map_obs_credentials_error`]); the kind is preserved.
fn filing_failure(e: &GeectlError) -> WorkerOutcome {
    let mapped = map_obs_credentials_error(e);
    if mapped.kind() == ErrorKind::AuthFailed {
        WorkerOutcome::AuthRejected {
            reason: format!("SR filing failed: {mapped}"),
        }
    } else {
        WorkerOutcome::Escalated {
            reason: format!("SR filing failed: {mapped}"),
        }
    }
}

/// The outcome of driving one queue entry through the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerOutcome {
    /// The dedup re-check says the update is already handled (the devel
    /// project already has the version, or an open SR targets the
    /// package). No SR is filed.
    Skipped { reason: String },
    /// No devel project could be resolved for the package. The entry
    /// escalates; the worker cannot file without a target.
    NoDevelProject,
    /// Dry-run: the full plan and (when the branch project resolved)
    /// the exact SR payload were logged and verified; nothing was filed
    /// and nothing changed. `payload` is None when the branch project
    /// could not be resolved (see `UpdatePlan::branch_project`).
    Planned {
        plan: UpdatePlan,
        payload: Option<SrPayload>,
    },
    /// The update could not be completed (a check failed, the plan was
    /// invalid, or live mode has no live executor). Escalate with the
    /// reason.
    Escalated { reason: String },
    /// The OBS API rejected the credentials (401/403) on a check or on
    /// filing. This is a run-level failure — bad or rotated
    /// credentials — not a per-package problem: the dispatcher stops
    /// the batch and fails the run loudly instead of escalating
    /// package by package. The entry stays pending for the next run.
    AuthRejected { reason: String },
    /// Live: the SR was filed. Carries the OBS request id.
    Filed { sr_id: String, plan: UpdatePlan },
}

/// Error from worker operations (kept as a plain String in
/// [`WorkerOutcome::Escalated`]; this type is for the plan builder).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerError(pub String);

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "worker error: {}", self.0)
    }
}

impl std::error::Error for WorkerError {}

/// The worker: one queue entry, one update.
pub struct Worker<'a> {
    obs: &'a ObsClient<'a>,
    executor: &'a dyn UpdateExecutor,
    credentials: Option<&'a Credentials>,
    /// The OBS home project from config (empty = unset; see
    /// `resolve_branch_project`).
    home_project: String,
    dry_run: &'a DryRun,
}

impl<'a> Worker<'a> {
    pub fn new(
        obs: &'a ObsClient<'a>,
        executor: &'a dyn UpdateExecutor,
        credentials: Option<&'a Credentials>,
        home_project: &str,
        dry_run: &'a DryRun,
    ) -> Self {
        Worker {
            obs,
            executor,
            credentials,
            home_project: home_project.to_string(),
            dry_run,
        }
    }

    /// Drive one queue entry through the pipeline. See the module docs
    /// for the steps and the dry-run / live boundary.
    pub fn run(&self, entry: &QueueEntry) -> WorkerOutcome {
        // 1. Resolve the devel project (public API read).
        let devel_project = match self.obs.devel_project(&entry.package) {
            Ok(Some(project)) => project,
            Ok(None) => return WorkerOutcome::NoDevelProject,
            Err(e) => {
                return obs_failure(
                    &e,
                    &format!("devel project lookup failed for {}", entry.package),
                );
            }
        };
        // 2. Dedup re-check: the devel project may already have the new
        // version (the queue entry may be stale). A failed check
        // escalates (fail-closed): filing on an unchecked dedup would
        // file a duplicate.
        match self.obs.devel_version(&entry.package) {
            Ok(Some(current)) => {
                if !is_newer(&entry.upstream_version, &current) {
                    return WorkerOutcome::Skipped {
                        reason: format!("devel already has {current}"),
                    };
                }
            }
            Ok(None) => {}
            Err(e) => {
                return obs_failure(
                    &e,
                    &format!("devel version check failed for {}", entry.package),
                );
            }
        }
        // 3. Dedup re-check: an open SR may already target the package.
        match self.obs.has_open_sr(&entry.package) {
            Ok(true) => {
                return WorkerOutcome::Skipped {
                    reason: "open submit request already targets it".to_string(),
                };
            }
            Ok(false) => {}
            Err(e) => {
                return obs_failure(&e, &format!("open-SR check failed for {}", entry.package));
            }
        }
        // 4. Resolve the branch project (may be None; see the field docs).
        let branch_project = self.resolve_branch_project();
        // 5. Build the plan (validates the CVE changelog rule for
        // security entries).
        let plan = match self.build_plan(entry, &devel_project, branch_project) {
            Ok(plan) => plan,
            Err(e) => {
                return WorkerOutcome::Escalated { reason: e.0 };
            }
        };
        // 6. Build the SR payload. When the branch project is
        // unresolved, there is no payload to build: in dry-run that is
        // a planned outcome with a clear note (the plan is still
        // logged); in live mode it is an escalation (nothing may be
        // filed without a source project).
        let payload = match payload_from_plan(&plan) {
            Ok(payload) => Some(payload),
            Err(e) => {
                if self.dry_run.live() {
                    return WorkerOutcome::Escalated {
                        reason: e.to_string(),
                    };
                }
                self.dry_run
                    .note(&format!("SR payload not built for {}: {e}", entry.package));
                None
            }
        };
        // 7. Execute the update steps.
        let execution = match self.executor.execute(&plan, self.dry_run) {
            Ok(execution) => execution,
            Err(reason) => {
                return WorkerOutcome::Escalated { reason };
            }
        };
        match execution {
            Execution::Planned => WorkerOutcome::Planned { plan, payload },
            Execution::Completed => {
                // Live: file the SR. The filing is gated by the dry-run
                // guard inside SrFiling::file, so this path only files
                // when the mode is really live.
                let Some(payload) = payload else {
                    // Completed implies live, and live requires a
                    // resolved branch project (step 6 escalates
                    // otherwise), so this is unreachable — but never
                    // file on a missing payload.
                    return WorkerOutcome::Escalated {
                        reason: "cannot file: no SR payload was built".to_string(),
                    };
                };
                // The filing runs through geectl's own DryRun (built
                // from the worker's mode). Its dry-run lines are merged
                // back into freshcrab's plan below, so `DryRun::plan()`
                // consumers see the filing detail alongside the
                // executor/queue notes (in live mode the geectl plan
                // is empty: the merge is a no-op).
                let geectl_dry = geectl::obs::DryRun::new(self.dry_run.enabled());
                let filing = SrFiling::new(self.obs, &geectl_dry);
                let result = filing.file(&payload);
                self.dry_run.merge_plan(&geectl_dry.plan());
                match result {
                    Ok(Some(sr_id)) => WorkerOutcome::Filed { sr_id, plan },
                    Ok(None) => WorkerOutcome::Planned {
                        plan,
                        payload: Some(payload),
                    },
                    Err(e) => filing_failure(&e),
                }
            }
        }
    }

    /// Resolve the branch project (the OBS home project the branch lives
    /// in): config `home_project` first, else `home:{OBS username}`
    /// from the credentials. None when neither is available.
    pub fn resolve_branch_project(&self) -> Option<String> {
        if !self.home_project.trim().is_empty() {
            return Some(self.home_project.trim().to_string());
        }
        match self.credentials {
            Some(Credentials::Basic { username, .. }) => Some(format!("home:{username}")),
            _ => None,
        }
    }

    /// Build the update plan for `entry`. Enforces the changelog rules:
    /// a security entry must carry its CVE ids, and the generated
    /// `.changes` entry must name each of them (see
    /// `docs/leap-and-cve.md`).
    pub fn build_plan(
        &self,
        entry: &QueueEntry,
        devel_project: &str,
        branch_project: Option<String>,
    ) -> Result<UpdatePlan, WorkerError> {
        let cves: Vec<CveId> = entry
            .cves
            .iter()
            .map(|s| {
                CveId::parse(s).map_err(|e| {
                    WorkerError(format!(
                        "invalid CVE id {s:?} on entry {}: {e}",
                        entry.package
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if entry.kind == UpdateKind::Security && cves.is_empty() {
            return Err(WorkerError(format!(
                "security entry for {} names no CVE: a security fix must name its CVE \
                 (see docs/leap-and-cve.md)",
                entry.package
            )));
        }
        let changes_entry = changes_entry_for(&entry.upstream_version, &cves);
        // The generated entry must name every CVE it claims to fix
        // (defense in depth: the generator above names them, this
        // re-checks the text that would actually be filed).
        for cve in &cves {
            if !changelog_names_cve(&changes_entry, cve) {
                return Err(WorkerError(format!(
                    "generated .changes entry for {} does not name {cve}",
                    entry.package
                )));
            }
        }
        let description = description_for(
            &entry.package,
            &entry.factory_version,
            &entry.upstream_version,
            &entry.source,
            &cves,
        );
        let cve_regression_test = if cves.is_empty() {
            None
        } else {
            Some(format!(
                "add a %check regression test for {} that fails on the unpatched code and passes with the fix, or document why none is feasible",
                cves
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        };
        Ok(UpdatePlan {
            package: entry.package.clone(),
            factory_version: entry.factory_version.clone(),
            upstream_version: entry.upstream_version.clone(),
            source: entry.source.clone(),
            devel_project: devel_project.to_string(),
            branch_project,
            kind: entry.kind,
            target: entry.target.clone(),
            changes_entry,
            description,
            cves,
            cve_regression_test,
        })
    }
}

/// Build a geectl SR payload from an update plan. The branch project
/// must be resolved (see `UpdatePlan::branch_project`); an unresolved
/// branch project is an error, not a placeholder — a payload with a
/// made-up source project would file to the wrong place. The CVEs are
/// converted to geectl's `CveId` (already validated by `build_plan`,
/// so the conversion cannot fail in practice) and the payload
/// enforces the changelog-CVE rule and the never-Factory target rule
/// itself.
fn payload_from_plan(plan: &UpdatePlan) -> Result<SrPayload, GeectlError> {
    let source_project = plan.branch_project.clone().ok_or_else(|| {
        GeectlError::new(
            ErrorKind::InvalidInput,
            "cannot build an SR payload: the branch project is unresolved \
             (set home_project in config.yaml or OSC_USERNAME/OSC_PASSWORD)",
        )
    })?;
    let cves: Vec<geectl::obs::CveId> = plan
        .cves
        .iter()
        .map(|c| geectl::obs::CveId::parse(c.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    SrPayload::new(
        &source_project,
        &plan.package,
        &plan.devel_project,
        &plan.package,
        &plan.description,
        &plan.changes_entry,
        &cves,
    )
}

/// Build the one `.changes` entry for a submission. The entry is dated
/// now (UTC) and authored with the packager identity. A security entry
/// names each CVE it fixes; a routine entry is a plain version bump.
fn changes_entry_for(upstream_version: &str, cves: &[CveId]) -> String {
    let date = format_changes_date(now_epoch_secs());
    let body = if cves.is_empty() {
        format!("- Update to version {upstream_version}.")
    } else {
        let list = cves
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        format!("- Update to version {upstream_version} (fixes {list}).")
    };
    format!(
        "-------------------------------------------------------------------\n{date} - {CHANGELOG_AUTHOR}\n\n{body}\n"
    )
}

/// Build the SR description text: what the submission does, in a few
/// lines, current status only.
fn description_for(
    package: &str,
    factory_version: &str,
    upstream_version: &str,
    source: &str,
    cves: &[CveId],
) -> String {
    let mut text = format!(
        "Update {package} to {upstream_version}\n\nUpstream {upstream_version} is available (confirmed by {source}); Factory ships {factory_version}. Bumps Version and the tarball, one .changes entry."
    );
    if !cves.is_empty() {
        let list = cves
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        text.push_str(&format!("\n\nSecurity fix for {list}."));
    }
    text
}

/// Current time as epoch seconds.
fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format an epoch-seconds timestamp as an OBS `.changes` date:
/// "Fri Nov 20 07:00:00 UTC 2026" (UTC, English abbreviations, the day
/// not zero-padded). Pure function (no I/O) so tests can pin it.
fn format_changes_date(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let secs_of_day = epoch_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let weekday =
        ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][((days + 4).rem_euclid(7)) as usize];
    let month_name = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(month - 1) as usize];
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;
    format!("{weekday} {month_name} {day} {hh:02}:{mm:02}:{ss:02} UTC {year}")
}

/// Days since the Unix epoch -> (year, month, day). The civil_from_days
/// algorithm (public domain).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::FakeHttpClient;
    use geectl::auth::Credentials;
    use geectl::obs::ObsClient;

    fn entry(package: &str) -> QueueEntry {
        QueueEntry::new(
            package,
            "1.9",
            "2.0",
            "repology",
            &Target::Factory,
            UpdateKind::Routine,
        )
    }

    /// The OBS search URL for `package`, from a throwaway geectl
    /// client (the URL is a pure function of the package, so no canned
    /// response is needed to build it).
    fn search_url_for(package: &str) -> String {
        let probe = FakeHttpClient::new();
        let obs = ObsClient::new(&probe);
        obs.search_url(package).unwrap()
    }

    /// An OBS client with credentials, for tests that need the
    /// authenticated endpoints (the open-SR search, filing).
    fn obs_with_creds(http: &FakeHttpClient) -> ObsClient<'_> {
        ObsClient::with_credentials(
            http,
            Credentials::Basic {
                username: "scarabeus_iv".to_string(),
                password: "secret".to_string(),
            },
        )
        .unwrap()
    }

    /// A canned OBS backend for one package: a devel project, a devel
    /// spec at the given version, and an open-SR search result.
    fn http_for_foo(devel_version: &str, open_sr_matches: u32) -> FakeHttpClient {
        let search_body = if open_sr_matches == 0 {
            "<collection matches=\"0\"></collection>".to_string()
        } else {
            // A full request element with a submit action: geectl's
            // open-SR check counts only requests that carry one, so a
            // bare self-closing `<request id="..."/>` would read as
            // empty and the skip would silently stop happening.
            format!(
                "<collection matches=\"{open_sr_matches}\"><request id=\"1398492\"><action type=\"submit\"><source project=\"home:scarabeus_iv\" package=\"foo\"/><target project=\"devel:languages:python\" package=\"foo\"/></action></request></collection>"
            )
        };
        FakeHttpClient::new()
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo",
                "<directory name=\"foo\"><devel project=\"devel:languages:python\" package=\"foo\"/></directory>",
            )
            .with(
                "https://api.opensuse.org/public/source/devel:languages:python/foo/foo.spec",
                &format!("Name: foo\nVersion: {devel_version}\n"),
            )
            .with(&search_url_for("foo"), &search_body)
    }

    #[test]
    fn format_changes_date_epoch_zero() {
        assert_eq!(format_changes_date(0), "Thu Jan 1 00:00:00 UTC 1970");
    }

    #[test]
    fn format_changes_date_known_day() {
        assert_eq!(
            format_changes_date(1_795_089_600),
            "Thu Nov 19 12:00:00 UTC 2026"
        );
    }

    #[test]
    fn civil_from_days_roundtrip() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_000), (2024, 10, 4));
    }

    #[test]
    fn build_plan_routine() {
        let dry = DryRun::new(true);
        let http = FakeHttpClient::new();
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        let plan = worker
            .build_plan(
                &entry("foo"),
                "devel:languages:python",
                Some("home:scarabeus_iv".to_string()),
            )
            .unwrap();
        assert_eq!(plan.package, "foo");
        assert_eq!(plan.devel_project, "devel:languages:python");
        assert_eq!(plan.branch_project.as_deref(), Some("home:scarabeus_iv"));
        assert!(plan.changes_entry.contains("Update to version 2.0."));
        assert!(plan.changes_entry.contains(CHANGELOG_AUTHOR));
        assert!(plan.description.contains("Update foo to 2.0"));
        assert!(plan.cve_regression_test.is_none());
    }

    #[test]
    fn build_plan_security_names_cve() {
        let dry = DryRun::new(true);
        let http = FakeHttpClient::new();
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        let mut e = entry("foo");
        e.kind = UpdateKind::Security;
        e.cves = vec!["CVE-2026-12345".to_string()];
        let plan = worker
            .build_plan(
                &e,
                "devel:languages:python",
                Some("home:scarabeus_iv".to_string()),
            )
            .unwrap();
        assert!(plan.changes_entry.contains("CVE-2026-12345"));
        assert!(plan.description.contains("CVE-2026-12345"));
        assert!(plan.cve_regression_test.is_some());
    }

    #[test]
    fn build_plan_security_without_cve_escalates() {
        let dry = DryRun::new(true);
        let http = FakeHttpClient::new();
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        let mut e = entry("foo");
        e.kind = UpdateKind::Security;
        let err = worker
            .build_plan(
                &e,
                "devel:languages:python",
                Some("home:scarabeus_iv".to_string()),
            )
            .unwrap_err();
        assert!(err.0.contains("names no CVE"));
    }

    #[test]
    fn resolve_branch_project_prefers_config() {
        let dry = DryRun::new(true);
        let http = FakeHttpClient::new();
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let creds = Credentials::Basic {
            username: "someone".to_string(),
            password: "secret".to_string(),
        };
        let worker = Worker::new(&obs, &executor, Some(&creds), "home:scarabeus_iv", &dry);
        assert_eq!(
            worker.resolve_branch_project().as_deref(),
            Some("home:scarabeus_iv")
        );
        let worker2 = Worker::new(&obs, &executor, Some(&creds), "", &dry);
        assert_eq!(
            worker2.resolve_branch_project().as_deref(),
            Some("home:someone")
        );
        let worker3 = Worker::new(&obs, &executor, None, "", &dry);
        assert_eq!(worker3.resolve_branch_project(), None);
    }

    #[test]
    fn run_skips_when_devel_already_new() {
        let dry = DryRun::new(true);
        let http = http_for_foo("2.0", 0);
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::Skipped { .. }
        ));
    }

    #[test]
    fn run_skips_when_open_sr_exists() {
        let dry = DryRun::new(true);
        let http = http_for_foo("1.9", 1);
        let obs = obs_with_creds(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::Skipped { .. }
        ));
    }

    #[test]
    fn run_auth_rejected_on_open_sr_check() {
        // The OBS search API 401s (rotated credentials): the worker
        // reports AuthRejected — a run-level failure — not an
        // escalation of the package.
        let dry = DryRun::new(true);
        let http = FakeHttpClient::new()
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo",
                "<directory name=\"foo\"><devel project=\"devel:languages:python\" package=\"foo\"/></directory>",
            )
            .with(
                "https://api.opensuse.org/public/source/devel:languages:python/foo/foo.spec",
                "Name: foo\nVersion: 1.9\n",
            )
            .with_status(&search_url_for("foo"), 401, "unauthorized");
        let obs = obs_with_creds(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::AuthRejected { .. }
        ));
    }

    #[test]
    fn run_transport_error_on_open_sr_check_escalates() {
        // A non-auth failure (no canned search response = transport
        // error) still escalates the package; only auth rejection is
        // run-level.
        let dry = DryRun::new(true);
        let http = FakeHttpClient::new()
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo",
                "<directory name=\"foo\"><devel project=\"devel:languages:python\" package=\"foo\"/></directory>",
            )
            .with(
                "https://api.opensuse.org/public/source/devel:languages:python/foo/foo.spec",
                "Name: foo\nVersion: 1.9\n",
            );
        let obs = obs_with_creds(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::Escalated { .. }
        ));
    }

    #[test]
    fn run_auth_rejected_on_filing() {
        // The filing POST 401s (rotated credentials): the worker
        // reports AuthRejected, not an escalation of the package.
        struct CompletedExecutor;
        impl UpdateExecutor for CompletedExecutor {
            fn execute(&self, _plan: &UpdatePlan, _dry_run: &DryRun) -> Result<Execution, String> {
                Ok(Execution::Completed)
            }
        }
        let dry = DryRun::new(false);
        let http = http_for_foo("1.9", 0).with_post_status(
            "https://api.opensuse.org/request?cmd=create",
            401,
            "unauthorized",
        );
        let obs = obs_with_creds(&http);
        let executor = CompletedExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::AuthRejected { .. }
        ));
        // The POST was attempted (and rejected); nothing was filed.
        assert_eq!(http.posted().len(), 1);
    }

    #[test]
    fn run_no_devel_project() {
        let dry = DryRun::new(true);
        let http = FakeHttpClient::new().with(
            "https://api.opensuse.org/public/source/openSUSE:Factory/foo",
            "<directory name=\"foo\"></directory>",
        );
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::NoDevelProject
        ));
    }

    #[test]
    fn run_dry_run_plans_with_payload() {
        let dry = DryRun::new(true);
        let http = http_for_foo("1.9", 0);
        let obs = obs_with_creds(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&entry("foo")) {
            WorkerOutcome::Planned { plan, payload } => {
                assert_eq!(plan.package, "foo");
                let payload = payload.expect("payload built in dry-run");
                assert_eq!(payload.target_project(), "devel:languages:python");
                assert_eq!(payload.source_project(), "home:scarabeus_iv");
                assert!(payload.validate_xml().is_ok());
                // The dry-run plan records the would-do steps.
                assert!(dry
                    .plan()
                    .iter()
                    .any(|l| l.contains("would branch foo from devel:languages:python")));
            }
            other => panic!("expected Planned, got {other:?}"),
        }
    }

    #[test]
    fn run_dry_run_with_completed_executor_merges_filing_plan() {
        struct CompletedExecutor;
        impl UpdateExecutor for CompletedExecutor {
            fn execute(&self, _plan: &UpdatePlan, _dry_run: &DryRun) -> Result<Execution, String> {
                Ok(Execution::Completed)
            }
        }
        let dry = DryRun::new(true);
        let http = http_for_foo("1.9", 0);
        let obs = obs_with_creds(&http);
        let executor = CompletedExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&entry("foo")) {
            WorkerOutcome::Planned { plan, .. } => {
                assert_eq!(plan.package, "foo");
            }
            other => panic!("expected Planned, got {other:?}"),
        }
        // The filing's dry-run lines live in freshcrab's plan, not
        // only in geectl's: the would-file line and the payload detail.
        let plan = dry.plan();
        assert!(
            plan.iter()
                .any(|l| l.contains("would: file submit request for foo")),
            "filing line missing from plan: {plan:?}"
        );
        assert!(
            plan.iter()
                .any(|l| l.contains("source: home:scarabeus_iv/foo")),
            "filing detail missing from plan: {plan:?}"
        );
        // And nothing was posted (dry-run files nothing).
        assert!(http.posted().is_empty());
    }

    #[test]
    fn run_live_without_live_executor_escalates() {
        let dry = DryRun::new(false);
        let http = http_for_foo("1.9", 0);
        let obs = obs_with_creds(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::Escalated { .. }
        ));
        // And nothing was posted (no live SR was filed).
        assert!(http.posted().is_empty());
    }

    #[test]
    fn run_live_with_completed_executor_files() {
        struct CompletedExecutor;
        impl UpdateExecutor for CompletedExecutor {
            fn execute(&self, _plan: &UpdatePlan, _dry_run: &DryRun) -> Result<Execution, String> {
                Ok(Execution::Completed)
            }
        }
        let dry = DryRun::new(false);
        let http = http_for_foo("1.9", 0).with_post(
            "https://api.opensuse.org/request?cmd=create",
            "<request id=\"1400001\" creator=\"scarabeus_iv\"></request>",
        );
        let obs = obs_with_creds(&http);
        let executor = CompletedExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&entry("foo")) {
            WorkerOutcome::Filed { sr_id, plan } => {
                assert_eq!(sr_id, "1400001");
                assert_eq!(plan.package, "foo");
            }
            other => panic!("expected Filed, got {other:?}"),
        }
        // Exactly one POST, to the create-request endpoint, with the SR XML,
        // and it carried the credentials.
        let posted = http.posted();
        assert_eq!(http.posted_auth(), vec![true]);
        assert_eq!(posted.len(), 1);
        assert_eq!(posted[0].0, "https://api.opensuse.org/request?cmd=create");
        assert!(posted[0].1.contains("<action type=\"submit\">"));
        assert!(posted[0].1.contains("devel:languages:python"));
        // The filed SR carries the cleanup default: the source branch
        // dies on accept.
        assert!(posted[0]
            .1
            .contains("<options><sourceupdate>cleanup</sourceupdate></options>"));
        // Filing runs its own dedup check in live mode: the open-SR
        // search was fetched with credentials too.
        assert!(http.authed_gets().contains(&search_url_for("foo")));
    }

    #[test]
    fn run_escalates_when_devel_version_recheck_fails() {
        // Dispatch-time dedup re-check: the devel project resolves,
        // but the spec fetch fails (no canned response) — the worker
        // escalates fail-closed instead of filing on an unchecked dedup.
        let dry = DryRun::new(true);
        let http = FakeHttpClient::new().with(
            "https://api.opensuse.org/public/source/openSUSE:Factory/foo",
            "<directory name=\"foo\"><devel project=\"devel:languages:python\" package=\"foo\"/></directory>",
        );
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&entry("foo")) {
            WorkerOutcome::Escalated { reason } => {
                assert!(reason.contains("devel version check failed"));
            }
            other => panic!("expected Escalated, got {other:?}"),
        }
    }

    #[test]
    fn run_escalates_when_open_sr_recheck_fails() {
        // The devel version check passes, but the open-SR search fails
        // (no canned response) — escalate fail-closed.
        let dry = DryRun::new(true);
        let http = FakeHttpClient::new()
            .with(
                "https://api.opensuse.org/public/source/openSUSE:Factory/foo",
                "<directory name=\"foo\"><devel project=\"devel:languages:python\" package=\"foo\"/></directory>",
            )
            .with(
                "https://api.opensuse.org/public/source/devel:languages:python/foo/foo.spec",
                "Name: foo\nVersion: 1.9\n",
            );
        let obs = obs_with_creds(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&entry("foo")) {
            WorkerOutcome::Escalated { reason } => {
                assert!(reason.contains("open-SR check failed"));
            }
            other => panic!("expected Escalated, got {other:?}"),
        }
    }

    #[test]
    fn run_live_without_credentials_escalates_at_open_sr_check() {
        // No credentials: the worker's own open-SR re-check refuses
        // before any request (geectl requires credentials up front),
        // so the run escalates fail-closed there and never reaches
        // filing — nothing is posted. The filing-level no-creds
        // fail-closed is covered by tests/test_sr.rs.
        struct CompletedExecutor;
        impl UpdateExecutor for CompletedExecutor {
            fn execute(&self, _plan: &UpdatePlan, _dry_run: &DryRun) -> Result<Execution, String> {
                Ok(Execution::Completed)
            }
        }
        let dry = DryRun::new(false);
        let http = http_for_foo("1.9", 0);
        let obs = ObsClient::new(&http);
        let executor = CompletedExecutor;
        let worker = Worker::new(&obs, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&entry("foo")) {
            WorkerOutcome::Escalated { reason } => {
                assert!(reason.contains("open-SR check failed"), "{reason}");
                // The geectl no-credentials error names GEECTL_OBS_*;
                // the worker reason must name freshcrab's OSC_*
                // variables instead.
                assert!(reason.contains("OSC_USERNAME"), "{reason}");
                assert!(reason.contains("OSC_PASSWORD"), "{reason}");
                assert!(!reason.contains("GEECTL_OBS"), "{reason}");
            }
            other => panic!("expected Escalated, got {other:?}"),
        }
        assert!(http.posted().is_empty());
    }

    #[test]
    fn obs_failure_maps_geectl_credential_names_and_preserves_kind() {
        // A fake geectl error naming GEECTL_OBS_* variables: the
        // outcome reason names freshcrab's OSC_* variables instead,
        // and the kind still decides auth-reject vs escalate.
        let err = GeectlError::new(
            ErrorKind::ConfigError,
            "checking for open submit requests requires OBS credentials (GEECTL_OBS_USERNAME + GEECTL_OBS_PASSWORD or GEECTL_OBS_PASSWORD_FILE)",
        );
        match obs_failure(&err, "open-SR check failed for foo") {
            WorkerOutcome::Escalated { reason } => {
                assert!(reason.contains("open-SR check failed for foo"), "{reason}");
                assert!(reason.contains("(OSC_USERNAME + OSC_PASSWORD)"), "{reason}");
                assert!(!reason.contains("GEECTL_OBS"), "{reason}");
            }
            other => panic!("expected Escalated, got {other:?}"),
        }
        let auth_err = GeectlError::new(
            ErrorKind::AuthFailed,
            "set GEECTL_OBS_USERNAME and GEECTL_OBS_PASSWORD",
        );
        match obs_failure(&auth_err, "open-SR check failed for foo") {
            WorkerOutcome::AuthRejected { reason } => {
                assert!(reason.contains("OSC_USERNAME"), "{reason}");
                assert!(reason.contains("OSC_PASSWORD"), "{reason}");
                assert!(!reason.contains("GEECTL_OBS"), "{reason}");
            }
            other => panic!("expected AuthRejected, got {other:?}"),
        }
    }

    #[test]
    fn filing_failure_maps_geectl_credential_names_and_preserves_kind() {
        // Same mapping at the filing arm, with the variant preserved:
        // an auth failure stays an auth rejection, anything else
        // escalates.
        let err = GeectlError::new(
            ErrorKind::ConfigError,
            "filing requires OBS credentials (GEECTL_OBS_USERNAME + GEECTL_OBS_PASSWORD or GEECTL_OBS_PASSWORD_FILE)",
        );
        match filing_failure(&err) {
            WorkerOutcome::Escalated { reason } => {
                assert!(reason.contains("SR filing failed"), "{reason}");
                assert!(reason.contains("(OSC_USERNAME + OSC_PASSWORD)"), "{reason}");
                assert!(!reason.contains("GEECTL_OBS"), "{reason}");
            }
            other => panic!("expected Escalated, got {other:?}"),
        }
        let auth_err = GeectlError::new(
            ErrorKind::AuthFailed,
            "set GEECTL_OBS_USERNAME and GEECTL_OBS_PASSWORD",
        );
        match filing_failure(&auth_err) {
            WorkerOutcome::AuthRejected { reason } => {
                assert!(reason.contains("OSC_USERNAME"), "{reason}");
                assert!(reason.contains("OSC_PASSWORD"), "{reason}");
                assert!(!reason.contains("GEECTL_OBS"), "{reason}");
            }
            other => panic!("expected AuthRejected, got {other:?}"),
        }
    }

    #[test]
    fn payload_from_plan_without_branch_project_errors() {
        let dry = DryRun::new(true);
        let http = FakeHttpClient::new();
        let obs = ObsClient::new(&http);
        let executor = DryRunExecutor;
        let worker = Worker::new(&obs, &executor, None, "", &dry);
        let plan = worker
            .build_plan(&entry("foo"), "devel:languages:python", None)
            .unwrap();
        let err = payload_from_plan(&plan).unwrap_err();
        assert!(
            format!("{err}").contains("branch project is unresolved"),
            "{err}"
        );
    }
}
