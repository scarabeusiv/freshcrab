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
//! 7. files the SR through the [`ObsGateway`](crate::obs_gateway::ObsGateway)
//!    (geectl's `SrFiling` behind it).
//!
//! A Leap entry takes a different path (`Worker::run_maintenance`):
//! the maintained instances are listed, the incident payload is
//! built from the matching instance, and the maintenance incident
//! is filed through the gateway (`SrFiling::file_maintenance_incident`
//! behind it) instead of a submit request. There is no devel project, no
//! devel-version check, and no open-SR check on that path — the
//! open-incident dedup lives in geectl's filing path.
//!
//! The update steps themselves (branch, bump, spec-cleaner, OBS build,
//! rpmcrab, adversarial audit) are performed by the executor. Only the
//! [`DryRunExecutor`] is shipped: in dry-run it logs the would-do steps
//! and returns `Planned`; in live mode it refuses, so an SR is filed
//! only on a plan that was actually executed. The live executor (the
//! agent/CI step, per `worker/brief.md`) is the remaining work. Filing a
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
use crate::obs_gateway::ObsGateway;
use crate::queue::{QueueEntry, UpdateKind};
use crate::target::Target;
use crate::version::is_newer;
use geectl::auth::Credentials;
use geectl::error::{ErrorKind, GeectlError};
use geectl::obs::{
    MaintainedInstance, MaintenanceBranchOptions, MaintenanceIncidentPayload, SrPayload,
};
use std::fmt;

/// The packager identity used for `.changes` entries (see
/// `worker/brief.md`).
pub const CHANGELOG_AUTHOR: &str = "Tomáš Chvátal <tomas.chvatal@gmail.com>";

/// The maintenance project a Leap incident targets on api.opensuse.org.
pub const MAINTENANCE_PROJECT: &str = "openSUSE:Maintenance";

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
    /// The devel project the SR targets (Factory only). None for a
    /// Leap plan: a maintenance incident has no devel project and no
    /// SR.
    pub devel_project: Option<String>,
    /// The OBS home project the branch lives in. None when it could not
    /// be resolved (no `home_project` in config, no OBS credentials):
    /// the plan is still built and logged, but no SR payload can be
    /// built from it — an unresolved branch project is an error (see
    /// `payload_from_plan`): a payload with a made-up
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
    /// with the fix, or document why none is feasible. Routine bumps
    /// carry None (no CVE, no regression test required).
    pub cve_regression_test: Option<String>,
}

/// The filing payload a plan carries: a submit request for Factory,
/// a maintenance incident for Leap. The dispatcher treats both the
/// same (a filed id marks the entry done); only the worker builds
/// and files them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilingPayload {
    Submit(SrPayload),
    Maintenance(MaintenanceIncidentPayload),
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
/// the executor reports [`Execution::Completed`]; a plan alone
/// files nothing.
pub trait UpdateExecutor {
    /// Execute the update steps for `plan`. Returns [`Execution::Planned`]
    /// in dry-run (steps logged, nothing executed) or
    /// [`Execution::Completed`] in live mode when the update is really
    /// done. Err when the update cannot be performed (with the reason).
    ///
    /// Branching is the first step, and it differs by target: a
    /// Factory plan branches from its devel project; a Leap plan
    /// branches with `ObsClient::maintenance_branch` into
    /// `plan.branch_project` (the server-derived maintenance branch)
    /// — never a plain branch, and never from a devel project, which
    /// a Leap plan does not have. Land it in `plan.branch_project`:
    /// pass `MaintenanceBranchOptions::with_target_project` for it,
    /// or verify `MaintenanceBranchResult.target_project` equals it.
    fn execute(&self, plan: &UpdatePlan, dry_run: &DryRun) -> Result<Execution, String>;
}

/// The shipped executor: in dry-run it logs the would-do
/// steps (branch, bump, spec-cleaner, build, rpmcrab, audit) and returns
/// [`Execution::Planned`]; in live mode it refuses, because the live
/// executor is the agent/CI step and is the remaining work. Refusing is
/// the safe answer: a live SR is filed only for an update that was
/// actually performed.
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
        match &plan.target {
            // A Leap update is a backport, not a version bump, and
            // its branch is the server-derived maintenance branch
            // (from the maintained project, not a devel project).
            Target::Leap { .. } => {
                // The branch source is the maintained project (the
                // update project), which the plan does not carry —
                // name the target, not a project, in the note.
                dry_run.note(&format!(
                    "would branch maintained {} for {} into {}",
                    plan.package, plan.target, branch
                ));
                dry_run.note(&format!(
                    "would apply the Leap update for {} (backport patch + Release bump + one .changes entry)",
                    plan.package
                ));
            }
            Target::Factory => {
                dry_run.note(&format!(
                    "would branch {} from {} into {}",
                    plan.package,
                    plan.devel_project
                        .as_deref()
                        .unwrap_or("<no devel project>"),
                    branch
                ));
                dry_run.note(&format!(
                    "would bump {} to {} (tarball + Version + one .changes entry)",
                    plan.package, plan.upstream_version
                ));
            }
        }
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

/// Map a filing failure to the outcome. `what` names the filing
/// ("SR filing failed", "maintenance incident filing failed").
/// Preserve the variant: an auth failure at filing time must stay
/// distinguishable so the dispatcher fails the run loudly instead
/// of escalating the package. The error is mapped first so the
/// reason names freshcrab's `OSC_*` variables instead of geectl's
/// `GEECTL_OBS_*` (see [`map_obs_credentials_error`]); the kind is
/// preserved.
fn filing_failure(e: &GeectlError, what: &str) -> WorkerOutcome {
    let mapped = map_obs_credentials_error(e);
    if mapped.kind() == ErrorKind::AuthFailed {
        WorkerOutcome::AuthRejected {
            reason: format!("{what}: {mapped}"),
        }
    } else {
        WorkerOutcome::Escalated {
            reason: format!("{what}: {mapped}"),
        }
    }
}

/// Whether `e` is geectl's open-maintenance-incident dedup refusal
/// (live filing only): an open incident already targets the same
/// source package and release project. The kind alone does not
/// identify it (`InvalidInput` also covers payload validation), so
/// the message is matched — geectl's wording for this refusal, pinned
/// by the duplicate test below.
fn is_open_maintenance_incident_duplicate(e: &GeectlError) -> bool {
    e.kind() == ErrorKind::InvalidInput
        && e.to_string()
            .contains("an open maintenance_incident request already targets")
}

/// The outcome of driving one queue entry through the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerOutcome {
    /// The dedup re-check says the update is already handled (the devel
    /// project already has the version, or an open SR targets the
    /// package). No SR is filed.
    Skipped { reason: String },
    /// No devel project could be resolved for the package. The entry
    /// escalates; filing needs a target.
    NoDevelProject,
    /// The package is not maintained on the entry's target (no
    /// maintained instance for it), so no maintenance incident can
    /// be filed. The entry escalates; the dispatcher handles it
    /// like `NoDevelProject`.
    NotMaintained { reason: String },
    /// Dry-run: the full plan and (when the branch project resolved)
    /// the exact filing payload (submit request or maintenance
    /// incident) were logged and verified; nothing was filed and
    /// nothing changed. `payload` is None when the branch project
    /// could not be resolved (see `UpdatePlan::branch_project`).
    Planned {
        plan: UpdatePlan,
        payload: Option<FilingPayload>,
    },
    /// The update could not be completed (a check failed, the plan was
    /// invalid, or live mode lacks its executor). Escalate with the
    /// reason.
    Escalated { reason: String },
    /// The OBS API rejected the credentials (401/403) on a check or on
    /// filing. This is a run-level failure — bad or rotated
    /// credentials: the dispatcher stops the batch and fails the run
    /// loudly. The entry stays pending for the next run.
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
    gateway: &'a dyn ObsGateway,
    executor: &'a dyn UpdateExecutor,
    credentials: Option<&'a Credentials>,
    /// The OBS home project from config (empty = unset; see
    /// `resolve_branch_project`).
    home_project: String,
    dry_run: &'a DryRun,
}

impl<'a> Worker<'a> {
    pub fn new(
        gateway: &'a dyn ObsGateway,
        executor: &'a dyn UpdateExecutor,
        credentials: Option<&'a Credentials>,
        home_project: &str,
        dry_run: &'a DryRun,
    ) -> Self {
        Worker {
            gateway,
            executor,
            credentials,
            home_project: home_project.to_string(),
            dry_run,
        }
    }

    /// Drive one queue entry through the pipeline. See the module docs
    /// for the steps and the dry-run / live boundary.
    pub fn run(&self, entry: &QueueEntry) -> WorkerOutcome {
        // Leap entries file maintenance incidents, not submit
        // requests: a different lookup, payload, and filing path.
        if entry.target.is_leap() {
            return self.run_maintenance(entry);
        }
        // 1. Resolve the devel project (public API read) against
        // Factory, the target the lookup reads.
        let devel_project = match self
            .gateway
            .devel_project(geectl::obs::FACTORY_PROJECT, &entry.package)
        {
            Ok(Some((project, _devel_package))) => project,
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
        match self.gateway.devel_version(&entry.package) {
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
        match self.gateway.has_open_sr(&entry.package) {
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
        let plan = match self.build_plan(entry, Some(&devel_project), branch_project) {
            Ok(plan) => plan,
            Err(e) => {
                return WorkerOutcome::Escalated { reason: e.0 };
            }
        };
        // 6. Build the SR payload. When the branch project is
        // unresolved, the payload stays unbuilt: in dry-run that is
        // a planned outcome with a clear note (the plan is still
        // logged); in live mode it is an escalation (filing needs a
        // source project).
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
            Execution::Planned => WorkerOutcome::Planned {
                plan,
                payload: payload.map(FilingPayload::Submit),
            },
            Execution::Completed => {
                // Live: file the SR. The filing is gated by the dry-run
                // guard inside the gateway, so this path only files
                // when the mode is really live.
                let Some(payload) = payload else {
                    // Completed implies live, and live requires a
                    // resolved branch project (step 6 escalates
                    // otherwise), so this is unreachable — and filing
                    // needs a payload.
                    return WorkerOutcome::Escalated {
                        reason: "cannot file: no SR payload was built".to_string(),
                    };
                };
                // The filing runs through the gateway (geectl's
                // `SrFiling` behind it); its dry-run lines are merged
                // back into freshcrab's plan by the gateway, so
                // `DryRun::plan()` consumers see the filing detail
                // alongside the executor/queue notes (in live mode
                // the geectl plan is empty: the merge is a no-op).
                let result = self.gateway.file_submit(&payload, self.dry_run);
                match result {
                    Ok(Some(filed)) => WorkerOutcome::Filed {
                        sr_id: filed.id,
                        plan,
                    },
                    Ok(None) => WorkerOutcome::Planned {
                        plan,
                        payload: Some(FilingPayload::Submit(payload)),
                    },
                    Err(e) => filing_failure(&e, "SR filing failed"),
                }
            }
        }
    }

    /// Drive one Leap queue entry through the maintenance pipeline:
    /// list the maintained instances (the read that proves the
    /// package is maintained on this target and names the branch
    /// project), build the plan and the incident payload, execute
    /// the update steps, and file the maintenance incident.
    ///
    /// The devel-project lookup, devel-version check, and open-SR
    /// check of the Factory path do not apply: a Leap update has no
    /// devel project, and an open maintenance incident is refused by
    /// geectl's filing-time dedup (the gateway's
    /// `file_maintenance_incident` in live mode), so there is no
    /// worker-side open-incident
    /// check — geectl exposes none. A duplicate found that way
    /// escalates with the blocking id for human triage, not
    /// `Skipped`: the dedup identity carries no fix/CVE identity,
    /// so the open incident may be another maintainer's or for a
    /// different CVE (see `is_open_maintenance_incident_duplicate`).
    /// The branch
    /// itself is an executor step, as on the Factory path: the plan
    /// names the branch project the listing reports, and the live
    /// executor creates it with geectl's `ObsClient::maintenance_branch`
    /// before executing the steps (see `UpdateExecutor`).
    fn run_maintenance(&self, entry: &QueueEntry) -> WorkerOutcome {
        // 1. The maintained project for this target — the update
        // project (`openSUSE:Leap:15.6:Update`), not the release
        // project (`openSUSE:Leap:15.6`): maintenance happens in the
        // update project, the release project is frozen. Only
        // releases with a known update project resolve (see
        // `Target::update_project`): 16.0/16.1 have no `:Update`
        // project (verified live), so they cannot resolve here.
        // Checked before the listing call: a release with no known
        // update project needs no network round-trip.
        let Some(maintained_project) = entry.target.update_project() else {
            return WorkerOutcome::NotMaintained {
                reason: format!(
                    "no maintained instance for {} on {}: {} has no known update project (only 15.6 is mapped; see docs/leap-and-cve.md)",
                    entry.package, entry.target, entry.target
                ),
            };
        };
        // 2. Maintained instances: the read that proves the package
        // is maintained on this target and names the branch project
        // the incident files from. The listing's source project is
        // the maintained project found above.
        let instances = match self
            .gateway
            .maintained_instances(&entry.package, &MaintenanceBranchOptions::new())
        {
            Ok(instances) => instances,
            Err(e) => {
                return obs_failure(
                    &e,
                    &format!("maintained-instances lookup failed for {}", entry.package),
                );
            }
        };
        let Some(instance) = instances
            .iter()
            .find(|i| i.source_project == maintained_project)
        else {
            return WorkerOutcome::NotMaintained {
                reason: format!(
                    "no maintained instance for {} on {}: the package is not maintained on this target",
                    entry.package, entry.target
                ),
            };
        };
        let branch_project = Some(instance.target_project.clone());
        // 3. Build the plan (validates the CVE changelog rule for
        // security entries). A Leap plan has no devel project.
        let plan = match self.build_plan(entry, None, branch_project) {
            Ok(plan) => plan,
            Err(e) => {
                return WorkerOutcome::Escalated { reason: e.0 };
            }
        };
        // 4. Build the incident payload from the plan and the
        // instance it was built from. Mirror the Factory path: in
        // dry-run a payload that cannot be built is a planned
        // outcome with a note, not an escalation; in live mode it
        // escalates (nothing may be filed without a payload).
        let payload = match maintenance_incident_payload_from_plan(&plan, instance) {
            Ok(payload) => Some(payload),
            Err(e) => {
                if self.dry_run.live() {
                    return WorkerOutcome::Escalated {
                        reason: e.to_string(),
                    };
                }
                self.dry_run.note(&format!(
                    "maintenance incident payload not built for {}: {e}",
                    entry.package
                ));
                None
            }
        };
        // 5. Execute the update steps.
        let execution = match self.executor.execute(&plan, self.dry_run) {
            Ok(execution) => execution,
            Err(reason) => {
                return WorkerOutcome::Escalated { reason };
            }
        };
        match execution {
            Execution::Planned => WorkerOutcome::Planned {
                plan,
                payload: payload.map(FilingPayload::Maintenance),
            },
            Execution::Completed => {
                // A payload failure escalates before execution in
                // live mode (see step 4), so this is unreachable
                // there; fail closed rather than filing nothing.
                let Some(payload) = payload else {
                    return WorkerOutcome::Escalated {
                        reason: format!(
                            "maintenance incident payload not built for {}",
                            entry.package
                        ),
                    };
                };
                // Live: file the maintenance incident. The filing is
                // gated by the dry-run guard inside the gateway, so
                // this path only files when the mode is really live.
                let result = self
                    .gateway
                    .file_maintenance_incident(&payload, self.dry_run);
                match result {
                    Ok(Some(sr_id)) => WorkerOutcome::Filed { sr_id, plan },
                    Ok(None) => WorkerOutcome::Planned {
                        plan,
                        payload: Some(FilingPayload::Maintenance(payload)),
                    },
                    Err(e) => {
                        // An open incident already targets this
                        // package — but the dedup identity carries
                        // no fix/CVE identity, so the open incident
                        // may be another maintainer's or for a
                        // different CVE. Escalate with the blocking
                        // id (it is in the error) for human triage
                        // instead of marking the entry done and
                        // silently dropping the fix. This is also
                        // the crash-recovery case: the incident we
                        // filed just before a crash is the open one,
                        // and the human verifies that from the id.
                        if is_open_maintenance_incident_duplicate(&e) {
                            WorkerOutcome::Escalated {
                                reason: format!(
                                    "maintenance incident already open for {}: {e}",
                                    entry.package
                                ),
                            }
                        } else {
                            filing_failure(&e, "maintenance incident filing failed")
                        }
                    }
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
    /// `docs/leap-and-cve.md`). The devel project is `None` for a
    /// Leap plan: a maintenance incident has no devel project and no
    /// SR.
    pub fn build_plan(
        &self,
        entry: &QueueEntry,
        devel_project: Option<&str>,
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
        let changes_entry = changes_entry_for(&entry.upstream_version, &cves, &entry.target);
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
            &entry.target,
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
            devel_project: devel_project.map(str::to_string),
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

/// Build a geectl SR payload from an update plan (Factory only).
/// The plan must carry a devel project and the branch project must
/// be resolved (see `UpdatePlan::branch_project`); an unresolved
/// branch project is an error, not a placeholder — a payload with a
/// made-up source project would file to the wrong place. A Leap plan
/// has no devel project, so this is never called for one (see
/// `maintenance_incident_payload_from_plan`). The CVEs are converted
/// to geectl's `CveId` (already validated by `build_plan`, so the
/// conversion cannot fail in practice) and the payload enforces the
/// changelog-CVE rule and the never-Factory target rule itself.
fn payload_from_plan(plan: &UpdatePlan) -> Result<SrPayload, GeectlError> {
    let source_project = plan.branch_project.clone().ok_or_else(|| {
        GeectlError::new(
            ErrorKind::InvalidInput,
            "cannot build an SR payload: the branch project is unresolved \
             (set home_project in config.yaml or OSC_USERNAME/OSC_PASSWORD)",
        )
    })?;
    let devel_project = plan.devel_project.clone().ok_or_else(|| {
        GeectlError::new(
            ErrorKind::InvalidInput,
            "cannot build an SR payload: the plan has no devel project \
             (a Leap plan carries a maintenance incident payload, not an SR payload)",
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
        &devel_project,
        &plan.package,
        &plan.description,
        &plan.changes_entry,
        &cves,
    )
}

/// Build a geectl maintenance-incident payload from a Leap plan and
/// the maintained instance it was built from. The source is the
/// branch the instance names: the branch project plus the branch
/// package name from the listing (`foo.openSUSE_Leap_15.6_Update`),
/// not the plain package — that dotted name is the package that
/// lands in the branch project. The target is the maintenance
/// project; the release project is the target's update project when
/// known (see `Target::update_project`), and otherwise omitted —
/// geectl documents the server stores a filing-time-resolved value
/// when none is filed. What it resolves from for a release with no
/// `:Update` project is unverified (see `docs/leap-and-cve.md`); the
/// omit is unreachable via `run_maintenance` today (unknown versions
/// are refused first) and exists for a future release mapping.
/// No cleanup opt-in: the
/// incident source is the maintenance working area, which the
/// maintainer may reuse for the next incident (geectl's default).
fn maintenance_incident_payload_from_plan(
    plan: &UpdatePlan,
    instance: &MaintainedInstance,
) -> Result<MaintenanceIncidentPayload, GeectlError> {
    let source_project = plan.branch_project.clone().ok_or_else(|| {
        GeectlError::new(
            ErrorKind::InvalidInput,
            "cannot build a maintenance incident payload: the branch project is unresolved",
        )
    })?;
    let mut payload = MaintenanceIncidentPayload::new(
        &source_project,
        &[instance.target_package.as_str()],
        MAINTENANCE_PROJECT,
        &plan.description,
    )?;
    if let Some(release_project) = plan.target.update_project() {
        payload = payload.with_release_project(&release_project)?;
    }
    Ok(payload)
}

/// Build the one `.changes` entry for a submission. The entry is dated
/// now (UTC) and authored with the packager identity. A security entry
/// names each CVE it fixes; a routine entry is a plain version bump.
/// A Leap entry is a backport, not a version bump: it says so
/// (Release bump, no version change) and never claims a version bump.
fn changes_entry_for(upstream_version: &str, cves: &[CveId], target: &Target) -> String {
    let date = format_changes_date(now_epoch_secs());
    let body = if cves.is_empty() {
        match target {
            Target::Factory => format!("- Update to version {upstream_version}."),
            Target::Leap { .. } => {
                "- Backport the upstream fix (Release bump, no version change).".to_string()
            }
        }
    } else {
        let list = cves
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        match target {
            Target::Factory => format!("- Update to version {upstream_version} (fixes {list})."),
            Target::Leap { .. } => {
                format!("- Backport the fix for {list} (Release bump, no version change).")
            }
        }
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
    target: &Target,
) -> String {
    // The shipped version belongs to the entry's target, not always
    // to Factory — and a Leap update is a backport, not a version
    // bump, so its description must not claim one.
    let mut text = match target {
        Target::Factory => format!(
            "Update {package} to {upstream_version}\n\nUpstream {upstream_version} is available (confirmed by {source}); Factory ships {factory_version}. Bumps Version and the tarball, one .changes entry."
        ),
        Target::Leap { version } => format!(
            "Backport the fix for {package} to Leap {version} (Release bump, no version change)\n\nUpstream {upstream_version} is available (confirmed by {source}); Leap {version} ships {factory_version}."
        ),
    };
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
    use crate::obs_gateway::FakeObsGateway;
    use geectl::auth::Credentials;

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

    /// A canned gateway for one Factory package: a devel project, a
    /// devel version, and an open-SR answer.
    fn gateway_for_foo(devel_version: &str, open_sr: bool) -> FakeObsGateway {
        let mut gateway = FakeObsGateway::new();
        gateway.devel_project = Ok(Some((
            "devel:languages:python".to_string(),
            "foo".to_string(),
        )));
        gateway.devel_version = Ok(Some(devel_version.to_string()));
        gateway.has_open_sr = Ok(open_sr);
        gateway
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
        let gateway = FakeObsGateway::new();
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        let plan = worker
            .build_plan(
                &entry("foo"),
                Some("devel:languages:python"),
                Some("home:scarabeus_iv".to_string()),
            )
            .unwrap();
        assert_eq!(plan.package, "foo");
        assert_eq!(
            plan.devel_project.as_deref(),
            Some("devel:languages:python")
        );
        assert_eq!(plan.branch_project.as_deref(), Some("home:scarabeus_iv"));
        assert!(plan.changes_entry.contains("Update to version 2.0."));
        assert!(plan.changes_entry.contains(CHANGELOG_AUTHOR));
        assert!(plan.description.contains("Update foo to 2.0"));
        assert!(plan.cve_regression_test.is_none());
    }

    #[test]
    fn build_plan_security_names_cve() {
        let dry = DryRun::new(true);
        let gateway = FakeObsGateway::new();
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        let mut e = entry("foo");
        e.kind = UpdateKind::Security;
        e.cves = vec!["CVE-2026-12345".to_string()];
        let plan = worker
            .build_plan(
                &e,
                Some("devel:languages:python"),
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
        let gateway = FakeObsGateway::new();
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        let mut e = entry("foo");
        e.kind = UpdateKind::Security;
        let err = worker
            .build_plan(
                &e,
                Some("devel:languages:python"),
                Some("home:scarabeus_iv".to_string()),
            )
            .unwrap_err();
        assert!(err.0.contains("names no CVE"));
    }

    #[test]
    fn resolve_branch_project_prefers_config() {
        let dry = DryRun::new(true);
        let gateway = FakeObsGateway::new();
        let executor = DryRunExecutor;
        let creds = Credentials::Basic {
            username: "someone".to_string(),
            password: "secret".to_string(),
        };
        let worker = Worker::new(&gateway, &executor, Some(&creds), "home:scarabeus_iv", &dry);
        assert_eq!(
            worker.resolve_branch_project().as_deref(),
            Some("home:scarabeus_iv")
        );
        let worker2 = Worker::new(&gateway, &executor, Some(&creds), "", &dry);
        assert_eq!(
            worker2.resolve_branch_project().as_deref(),
            Some("home:someone")
        );
        let worker3 = Worker::new(&gateway, &executor, None, "", &dry);
        assert_eq!(worker3.resolve_branch_project(), None);
    }

    #[test]
    fn run_skips_when_devel_already_new() {
        let dry = DryRun::new(true);
        let gateway = gateway_for_foo("2.0", false);
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::Skipped { .. }
        ));
    }

    #[test]
    fn run_skips_when_open_sr_exists() {
        let dry = DryRun::new(true);
        let gateway = gateway_for_foo("1.9", true);
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::Skipped { .. }
        ));
    }

    #[test]
    fn run_auth_rejected_on_open_sr_check() {
        // The open-SR check rejects the credentials (rotated
        // credentials): the worker reports AuthRejected — a run-level
        // failure — not an escalation of the package.
        let dry = DryRun::new(true);
        let mut gateway = gateway_for_foo("1.9", false);
        gateway.has_open_sr = Err(GeectlError::new(ErrorKind::AuthFailed, "unauthorized"));
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::AuthRejected { .. }
        ));
    }

    #[test]
    fn run_transport_error_on_open_sr_check_escalates() {
        // A non-auth failure of the open-SR check still escalates the
        // package; only auth rejection is run-level.
        let dry = DryRun::new(true);
        let mut gateway = gateway_for_foo("1.9", false);
        gateway.has_open_sr = Err(GeectlError::new(
            ErrorKind::NetworkError,
            "transport error",
        ));
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::Escalated { .. }
        ));
    }

    #[test]
    fn run_auth_rejected_on_filing() {
        // Filing rejects the credentials (rotated credentials): the
        // worker reports AuthRejected, not an escalation of the package.
        struct CompletedExecutor;
        impl UpdateExecutor for CompletedExecutor {
            fn execute(&self, _plan: &UpdatePlan, _dry_run: &DryRun) -> Result<Execution, String> {
                Ok(Execution::Completed)
            }
        }
        let dry = DryRun::new(false);
        let mut gateway = gateway_for_foo("1.9", false);
        gateway.file_submit = Err(GeectlError::new(ErrorKind::AuthFailed, "unauthorized"));
        let executor = CompletedExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::AuthRejected { .. }
        ));
    }

    #[test]
    fn run_no_devel_project() {
        let dry = DryRun::new(true);
        let gateway = FakeObsGateway::new();
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::NoDevelProject
        ));
    }

    #[test]
    fn run_dry_run_plans_with_payload() {
        let dry = DryRun::new(true);
        let gateway = gateway_for_foo("1.9", false);
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&entry("foo")) {
            WorkerOutcome::Planned { plan, payload } => {
                assert_eq!(plan.package, "foo");
                let payload = payload.expect("payload built in dry-run");
                match &payload {
                    FilingPayload::Submit(payload) => {
                        assert_eq!(payload.target_project(), "devel:languages:python");
                        assert_eq!(payload.source_project(), "home:scarabeus_iv");
                        assert!(payload.validate_xml().is_ok());
                    }
                    other => panic!("expected Submit payload, got {other:?}"),
                }
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
    fn run_dry_run_with_completed_executor_stays_planned() {
        struct CompletedExecutor;
        impl UpdateExecutor for CompletedExecutor {
            fn execute(&self, _plan: &UpdatePlan, _dry_run: &DryRun) -> Result<Execution, String> {
                Ok(Execution::Completed)
            }
        }
        // A completed executor in dry-run mode: the worker takes the
        // Completed arm, the gateway files nothing (Ok(None)), and the
        // outcome stays Planned — with the submit payload carried for
        // the plan record. (The would-file lines geectl's filing
        // produces live behind the gateway, so they are not asserted
        // here: geectl's behaviour is tested in geectl.)
        let dry = DryRun::new(true);
        let gateway = gateway_for_foo("1.9", false);
        let executor = CompletedExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&entry("foo")) {
            WorkerOutcome::Planned { plan, payload } => {
                assert_eq!(plan.package, "foo");
                assert!(matches!(payload, Some(FilingPayload::Submit(_))));
            }
            other => panic!("expected Planned, got {other:?}"),
        }
    }

    #[test]
    fn run_live_without_live_executor_escalates() {
        let dry = DryRun::new(false);
        let gateway = gateway_for_foo("1.9", false);
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&entry("foo")),
            WorkerOutcome::Escalated { .. }
        ));
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
        let mut gateway = gateway_for_foo("1.9", false);
        gateway.file_submit = Ok(Some(("1400001".to_string(), Vec::new())));
        let executor = CompletedExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&entry("foo")) {
            WorkerOutcome::Filed { sr_id, plan } => {
                assert_eq!(sr_id, "1400001");
                assert_eq!(plan.package, "foo");
            }
            other => panic!("expected Filed, got {other:?}"),
        }
    }

    #[test]
    fn run_escalates_when_devel_version_recheck_fails() {
        // Dispatch-time dedup re-check: the devel project resolves,
        // but the devel-version check fails — the worker escalates
        // fail-closed instead of filing on an unchecked dedup.
        let dry = DryRun::new(true);
        let mut gateway = gateway_for_foo("1.9", false);
        gateway.devel_version = Err(GeectlError::new(
            ErrorKind::NetworkError,
            "transport error",
        ));
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&entry("foo")) {
            WorkerOutcome::Escalated { reason } => {
                assert!(reason.contains("devel version check failed"));
            }
            other => panic!("expected Escalated, got {other:?}"),
        }
    }

    #[test]
    fn run_escalates_when_open_sr_recheck_fails() {
        // The devel version check passes, but the open-SR check fails
        // — escalate fail-closed.
        let dry = DryRun::new(true);
        let mut gateway = gateway_for_foo("1.9", false);
        gateway.has_open_sr = Err(GeectlError::new(
            ErrorKind::NetworkError,
            "transport error",
        ));
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&entry("foo")) {
            WorkerOutcome::Escalated { reason } => {
                assert!(reason.contains("open-SR check failed"));
            }
            other => panic!("expected Escalated, got {other:?}"),
        }
    }

    #[test]
    fn run_live_without_credentials_escalates_at_open_sr_check() {
        // No credentials: the open-SR re-check reports the missing
        // credentials, so the run escalates fail-closed there and
        // never reaches filing. The filing-level no-creds fail-closed
        // is covered by tests/test_sr.rs.
        struct CompletedExecutor;
        impl UpdateExecutor for CompletedExecutor {
            fn execute(&self, _plan: &UpdatePlan, _dry_run: &DryRun) -> Result<Execution, String> {
                Ok(Execution::Completed)
            }
        }
        let dry = DryRun::new(false);
        let mut gateway = gateway_for_foo("1.9", false);
        gateway.has_open_sr = Err(GeectlError::new(
            ErrorKind::ConfigError,
            "checking for open submit requests requires OBS credentials (GEECTL_OBS_USERNAME + GEECTL_OBS_PASSWORD or GEECTL_OBS_PASSWORD_FILE)",
        ));
        let executor = CompletedExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
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
        match filing_failure(&err, "SR filing failed") {
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
        match filing_failure(&auth_err, "SR filing failed") {
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
        let gateway = FakeObsGateway::new();
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "", &dry);
        let plan = worker
            .build_plan(&entry("foo"), Some("devel:languages:python"), None)
            .unwrap();
        let err = payload_from_plan(&plan).unwrap_err();
        assert!(
            format!("{err}").contains("branch project is unresolved"),
            "{err}"
        );
    }

    /// A Leap 15.6 security entry for `package` (CVE-driven, as the
    /// Leap watcher will produce; see docs/leap-and-cve.md).
    fn leap_entry(package: &str) -> QueueEntry {
        let mut e = QueueEntry::new(
            package,
            "1.9",
            "2.0",
            "repology",
            &Target::Leap {
                version: "15.6".to_string(),
            },
            UpdateKind::Security,
        );
        e.cves = vec!["CVE-2026-12345".to_string()];
        e
    }

    /// The 15.6 maintained instance for `foo`: the source project is
    /// the update project, and the branch project is the listing's
    /// target project.
    fn leap_15_6_instance() -> MaintainedInstance {
        MaintainedInstance {
            source_project: "openSUSE:Leap:15.6:Update".to_string(),
            source_package: "foo".to_string(),
            devel_project: Some("devel:languages:python".to_string()),
            devel_package: Some("foo".to_string()),
            target_project: "home:scarabeus_iv:branches:OBS_Maintained:foo".to_string(),
            target_package: "foo.openSUSE_Leap_15.6_Update".to_string(),
        }
    }

    /// The 15.5 maintained instance for `foo` (no devel project).
    fn leap_15_5_instance() -> MaintainedInstance {
        MaintainedInstance {
            source_project: "openSUSE:Leap:15.5:Update".to_string(),
            source_package: "foo".to_string(),
            devel_project: None,
            devel_package: None,
            target_project: "home:scarabeus_iv:branches:OBS_Maintained:foo".to_string(),
            target_package: "foo.openSUSE_Leap_15.5_Update".to_string(),
        }
    }

    /// A canned gateway for a Leap `foo`: the maintained-instances
    /// listing for 15.6 (plus the 15.5 instance the listing carries).
    fn gateway_for_leap_foo() -> FakeObsGateway {
        let mut gateway = FakeObsGateway::new();
        gateway.maintained_instances = Ok(vec![leap_15_6_instance(), leap_15_5_instance()]);
        gateway
    }

    #[test]
    fn build_plan_leap_has_no_devel_project() {
        let dry = DryRun::new(true);
        let gateway = FakeObsGateway::new();
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        let plan = worker
            .build_plan(
                &leap_entry("foo"),
                None,
                Some("home:scarabeus_iv:branches:OBS_Maintained:foo".to_string()),
            )
            .unwrap();
        assert_eq!(plan.devel_project, None);
        assert_eq!(
            plan.target,
            Target::Leap {
                version: "15.6".to_string()
            }
        );
        assert!(plan.description.contains("Leap 15.6 ships 1.9"));
        assert!(plan.description.contains("CVE-2026-12345"));
        // A Leap plan is a backport: its description and .changes
        // entry must not claim a version bump.
        assert!(plan
            .description
            .contains("Backport the fix for foo to Leap 15.6"));
        assert!(!plan.description.contains("Bumps Version"));
        assert!(plan
            .changes_entry
            .contains("Backport the fix for CVE-2026-12345"));
        assert!(!plan.changes_entry.contains("Update to version"));
    }

    #[test]
    fn run_maintenance_dry_run_plans_with_incident_payload() {
        let dry = DryRun::new(true);
        let gateway = gateway_for_leap_foo();
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&leap_entry("foo")) {
            WorkerOutcome::Planned { plan, payload } => {
                assert_eq!(plan.package, "foo");
                assert_eq!(plan.devel_project, None);
                let payload = payload.expect("payload built in dry-run");
                match &payload {
                    FilingPayload::Maintenance(payload) => {
                        assert_eq!(
                            payload.source_project(),
                            "home:scarabeus_iv:branches:OBS_Maintained:foo"
                        );
                        assert_eq!(payload.source_packages().len(), 1);
                        assert_eq!(
                            payload.source_packages()[0],
                            "foo.openSUSE_Leap_15.6_Update"
                        );
                        assert_eq!(payload.target_project(), "openSUSE:Maintenance");
                        assert_eq!(
                            payload.target_releaseproject(),
                            Some("openSUSE:Leap:15.6:Update")
                        );
                        // No cleanup opt-in: the incident source is the
                        // maintenance working area, which the maintainer
                        // may reuse (geectl's default).
                        assert!(payload.source_update().is_none());
                        assert!(payload.validate_xml().is_ok());
                        // The filed description is the backport text,
                        // not a version-bump claim.
                        assert!(payload
                            .description()
                            .contains("Backport the fix for foo to Leap 15.6"));
                        assert!(!payload.description().contains("Bumps Version"));
                    }
                    other => panic!("expected Maintenance payload, got {other:?}"),
                }
                // The dry-run plan records the maintenance branch step.
                assert!(dry
                    .plan()
                    .iter()
                    .any(|l| l.contains("would branch maintained foo for leap-15.6")));
            }
            other => panic!("expected Planned, got {other:?}"),
        }
    }

    #[test]
    fn run_maintenance_live_with_completed_executor_files() {
        struct CompletedExecutor;
        impl UpdateExecutor for CompletedExecutor {
            fn execute(&self, _plan: &UpdatePlan, _dry_run: &DryRun) -> Result<Execution, String> {
                Ok(Execution::Completed)
            }
        }
        let dry = DryRun::new(false);
        let mut gateway = gateway_for_leap_foo();
        gateway.file_maintenance_incident = Ok(Some("1400002".to_string()));
        let executor = CompletedExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&leap_entry("foo")) {
            WorkerOutcome::Filed { sr_id, plan } => {
                assert_eq!(sr_id, "1400002");
                assert_eq!(plan.package, "foo");
            }
            other => panic!("expected Filed, got {other:?}"),
        }
    }

    #[test]
    fn run_maintenance_not_maintained_escalates() {
        let dry = DryRun::new(true);
        let gateway = FakeObsGateway::new();
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&leap_entry("foo")) {
            WorkerOutcome::NotMaintained { reason } => {
                assert!(
                    reason.contains("no maintained instance for foo on leap-15.6"),
                    "{reason}"
                );
            }
            other => panic!("expected NotMaintained, got {other:?}"),
        }
    }

    #[test]
    fn run_maintenance_no_instance_for_target_escalates() {
        // The package is maintained, but only on another release
        // (15.5): no instance matches this entry's 15.6 target.
        let dry = DryRun::new(true);
        let mut gateway = FakeObsGateway::new();
        gateway.maintained_instances = Ok(vec![leap_15_5_instance()]);
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        assert!(matches!(
            worker.run(&leap_entry("foo")),
            WorkerOutcome::NotMaintained { .. }
        ));
    }

    #[test]
    fn maintenance_incident_payload_16_0_omits_release_project() {
        // 16.0 has no `:Update` project (verified live): the incident
        // omits the release project. This pins the payload layer
        // only — discovery never yields a 16.0 instance (see
        // `run_maintenance_16_0_has_no_known_update_project`), so
        // the omit path is hypothetical until a 16.x release project
        // exists; geectl documents the server stores a
        // filing-time-resolved value when none is filed.
        let dry = DryRun::new(true);
        let gateway = FakeObsGateway::new();
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        let mut e = leap_entry("foo");
        e.target = Target::Leap {
            version: "16.0".to_string(),
        };
        let plan = worker
            .build_plan(
                &e,
                None,
                Some("home:scarabeus_iv:branches:OBS_Maintained:foo".to_string()),
            )
            .unwrap();
        let instance = MaintainedInstance {
            source_project: "openSUSE:Leap:16.0:Update".to_string(),
            source_package: "foo".to_string(),
            devel_project: None,
            devel_package: None,
            target_project: "home:scarabeus_iv:branches:OBS_Maintained:foo".to_string(),
            target_package: "foo.openSUSE_Leap_16.0_Update".to_string(),
        };
        let payload = maintenance_incident_payload_from_plan(&plan, &instance).unwrap();
        assert_eq!(payload.target_releaseproject(), None);
        assert_eq!(
            payload.source_packages()[0],
            "foo.openSUSE_Leap_16.0_Update"
        );
    }

    #[test]
    fn run_maintenance_16_0_has_no_known_update_project() {
        // 16.0 has no `:Update` project, so the worker cannot match
        // a maintained instance for it — even when the listing
        // carries instances for other releases.
        let dry = DryRun::new(true);
        let gateway = gateway_for_leap_foo();
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        let mut e = leap_entry("foo");
        e.target = Target::Leap {
            version: "16.0".to_string(),
        };
        match worker.run(&e) {
            WorkerOutcome::NotMaintained { reason } => {
                assert!(reason.contains("has no known update project"), "{reason}");
            }
            other => panic!("expected NotMaintained, got {other:?}"),
        }
        // The unknown version is refused before the listing call (see
        // `run_maintenance`): no listing round-trip is spent on it.
    }

    #[test]
    fn run_maintenance_selects_update_project_instance() {
        // The worker selects the instance whose source project is
        // the update project, not the release project — even when
        // that instance branches from another maintainer's home.
        let dry = DryRun::new(true);
        let mut instance_15_6 = leap_15_6_instance();
        instance_15_6.target_project =
            "home:alice:branches:OBS_Maintained:foo".to_string();
        let mut gateway = FakeObsGateway::new();
        gateway.maintained_instances = Ok(vec![instance_15_6, leap_15_5_instance()]);
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&leap_entry("foo")) {
            WorkerOutcome::Planned { payload, .. } => {
                let payload = payload.expect("payload built in dry-run");
                match &payload {
                    FilingPayload::Maintenance(payload) => {
                        assert_eq!(
                            payload.source_project(),
                            "home:alice:branches:OBS_Maintained:foo"
                        );
                        assert_eq!(
                            payload.source_packages()[0],
                            "foo.openSUSE_Leap_15.6_Update"
                        );
                        assert_eq!(
                            payload.target_releaseproject(),
                            Some("openSUSE:Leap:15.6:Update")
                        );
                    }
                    other => panic!("expected Maintenance payload, got {other:?}"),
                }
            }
            other => panic!("expected Planned, got {other:?}"),
        }
    }

    #[test]
    fn run_maintenance_live_duplicate_incident_escalates() {
        // An open incident already targets this package: the filing
        // refuses at dedup time, and the worker escalates with the
        // blocking id for human triage — the dedup identity carries
        // no fix/CVE identity, so the open incident may be another
        // maintainer's or for a different CVE, and marking the entry
        // done would silently drop this fix.
        struct CompletedExecutor;
        impl UpdateExecutor for CompletedExecutor {
            fn execute(&self, _plan: &UpdatePlan, _dry_run: &DryRun) -> Result<Execution, String> {
                Ok(Execution::Completed)
            }
        }
        let dry = DryRun::new(false);
        let mut gateway = gateway_for_leap_foo();
        gateway.file_maintenance_incident = Err(GeectlError::new(
            ErrorKind::InvalidInput,
            "an open maintenance_incident request already targets foo.openSUSE_Leap_15.6_Update (request 1399001)",
        ));
        let executor = CompletedExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&leap_entry("foo")) {
            WorkerOutcome::Escalated { reason } => {
                assert!(reason.contains("already open"), "{reason}");
                assert!(reason.contains("1399001"), "{reason}");
            }
            other => panic!("expected Escalated, got {other:?}"),
        }
    }

    #[test]
    fn run_maintenance_dry_run_completed_executor_stays_planned() {
        // CompletedExecutor in dry-run mode (mirrors the Factory
        // test).
        struct CompletedExecutor;
        impl UpdateExecutor for CompletedExecutor {
            fn execute(&self, _plan: &UpdatePlan, _dry_run: &DryRun) -> Result<Execution, String> {
                Ok(Execution::Completed)
            }
        }
        // A completed executor in dry-run mode: the worker takes the
        // Completed arm, the gateway files nothing (Ok(None)), and the
        // outcome stays Planned — with the incident payload carried
        // for the plan record. (The would-file lines geectl's filing
        // produces live behind the gateway, so they are not asserted
        // here: geectl's behaviour is tested in geectl.)
        let dry = DryRun::new(true);
        let gateway = gateway_for_leap_foo();
        let executor = CompletedExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&leap_entry("foo")) {
            WorkerOutcome::Planned { payload, .. } => {
                assert!(matches!(payload, Some(FilingPayload::Maintenance(_))));
            }
            other => panic!("expected Planned, got {other:?}"),
        }
    }

    #[test]
    fn run_maintenance_listing_failure_escalates() {
        // The maintained-instances lookup fails: escalate fail-closed
        // instead of filing without a branch project.
        let dry = DryRun::new(true);
        let mut gateway = FakeObsGateway::new();
        gateway.maintained_instances = Err(GeectlError::new(
            ErrorKind::NetworkError,
            "transport error",
        ));
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&leap_entry("foo")) {
            WorkerOutcome::Escalated { reason } => {
                assert!(
                    reason.contains("maintained-instances lookup failed for foo"),
                    "{reason}"
                );
            }
            other => panic!("expected Escalated, got {other:?}"),
        }
    }

    #[test]
    fn run_maintenance_no_credentials_escalates_at_listing() {
        // No credentials: the maintained-instances lookup reports the
        // missing credentials, so the run escalates fail-closed there
        // and never reaches filing.
        let dry = DryRun::new(true);
        let mut gateway = gateway_for_leap_foo();
        gateway.maintained_instances = Err(GeectlError::new(
            ErrorKind::ConfigError,
            "listing maintained instances requires OBS credentials (GEECTL_OBS_USERNAME + GEECTL_OBS_PASSWORD or GEECTL_OBS_PASSWORD_FILE)",
        ));
        let executor = DryRunExecutor;
        let worker = Worker::new(&gateway, &executor, None, "home:scarabeus_iv", &dry);
        match worker.run(&leap_entry("foo")) {
            WorkerOutcome::Escalated { reason } => {
                assert!(
                    reason.contains("maintained-instances lookup failed for foo"),
                    "{reason}"
                );
                assert!(reason.contains("OSC_USERNAME"), "{reason}");
                assert!(reason.contains("OSC_PASSWORD"), "{reason}");
                assert!(!reason.contains("GEECTL_OBS"), "{reason}");
            }
            other => panic!("expected Escalated, got {other:?}"),
        }
    }
}
