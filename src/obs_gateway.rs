//! The OBS gateway: the seam between freshcrab and geectl.
//!
//! The worker drives OBS through this trait, never through geectl's
//! types directly and never through raw HTTP: every OBS operation the
//! worker needs is a typed method here. The shipped implementation
//! delegates to geectl's `ObsClient`/`SrFiling`; tests use a fake
//! that returns canned values, so no test pins geectl's HTTP shapes
//! (URLs, bodies) — geectl's behaviour is tested in geectl, and
//! freshcrab tests only its own logic.

use crate::dry_run::DryRun;
use geectl::error::GeectlError;
use geectl::obs::{
    FiledRequest, MaintainedInstance, MaintenanceBranchOptions, MaintenanceIncidentPayload,
    ObsClient, SrFiling, SrPayload,
};

/// The OBS operations the worker needs, as typed methods. The filing
/// methods take freshcrab's [`DryRun`]: in dry-run they record the
/// would-do plan (via geectl's own dry-run guard) and file nothing;
/// in live mode they file and return the new request id.
pub trait ObsGateway {
    fn devel_project(
        &self,
        project: &str,
        package: &str,
    ) -> Result<Option<(String, String)>, GeectlError>;
    fn devel_version(&self, package: &str) -> Result<Option<String>, GeectlError>;
    fn has_open_sr(&self, package: &str) -> Result<bool, GeectlError>;
    fn maintained_instances(
        &self,
        package: &str,
        options: &MaintenanceBranchOptions,
    ) -> Result<Vec<MaintainedInstance>, GeectlError>;
    fn file_submit(
        &self,
        payload: &SrPayload,
        dry_run: &DryRun,
    ) -> Result<Option<FiledRequest>, GeectlError>;
    fn file_maintenance_incident(
        &self,
        payload: &MaintenanceIncidentPayload,
        dry_run: &DryRun,
    ) -> Result<Option<String>, GeectlError>;
}

/// The shipped gateway: every operation delegates to geectl.
pub struct GeectlObsGateway<'a> {
    obs: &'a ObsClient<'a>,
}

impl<'a> GeectlObsGateway<'a> {
    pub fn new(obs: &'a ObsClient<'a>) -> Self {
        GeectlObsGateway { obs }
    }
}

impl ObsGateway for GeectlObsGateway<'_> {
    fn devel_project(
        &self,
        project: &str,
        package: &str,
    ) -> Result<Option<(String, String)>, GeectlError> {
        self.obs.devel_project(project, package)
    }

    fn devel_version(&self, package: &str) -> Result<Option<String>, GeectlError> {
        self.obs.devel_version(package)
    }

    fn has_open_sr(&self, package: &str) -> Result<bool, GeectlError> {
        self.obs.has_open_sr(package)
    }

    fn maintained_instances(
        &self,
        package: &str,
        options: &MaintenanceBranchOptions,
    ) -> Result<Vec<MaintainedInstance>, GeectlError> {
        self.obs.maintained_instances(package, options)
    }

    fn file_submit(
        &self,
        payload: &SrPayload,
        dry_run: &DryRun,
    ) -> Result<Option<FiledRequest>, GeectlError> {
        let geectl_dry = geectl::obs::DryRun::new(dry_run.enabled());
        let filing = SrFiling::new(self.obs, &geectl_dry);
        let result = filing.file(payload);
        dry_run.merge_plan(&geectl_dry.plan());
        result
    }

    fn file_maintenance_incident(
        &self,
        payload: &MaintenanceIncidentPayload,
        dry_run: &DryRun,
    ) -> Result<Option<String>, GeectlError> {
        let geectl_dry = geectl::obs::DryRun::new(dry_run.enabled());
        let filing = SrFiling::new(self.obs, &geectl_dry);
        let result = filing.file_maintenance_incident(payload);
        dry_run.merge_plan(&geectl_dry.plan());
        result
    }
}

/// A fake gateway for tests: canned results per operation, returned
/// on every call. The filed-submit result carries the request id and
/// the superseded ids (`FiledRequest` is not `Clone`, so the fake
/// stores the parts and builds it fresh per call). Tests set the
/// fields they need; unset operations return the empty default
/// (no devel project, no devel version, no open SR, no maintained
/// instances, nothing filed).
#[cfg(test)]
pub struct FakeObsGateway {
    pub devel_project: Result<Option<(String, String)>, GeectlError>,
    pub devel_version: Result<Option<String>, GeectlError>,
    pub has_open_sr: Result<bool, GeectlError>,
    pub maintained_instances: Result<Vec<MaintainedInstance>, GeectlError>,
    pub file_submit: Result<Option<(String, Vec<String>)>, GeectlError>,
    pub file_maintenance_incident: Result<Option<String>, GeectlError>,
    /// Packages `has_open_sr` was called for, in call order (test
    /// pin: the dispatcher must stop at the first auth rejection,
    /// so a later package is never checked).
    pub has_open_sr_calls: std::cell::RefCell<Vec<String>>,
}

#[cfg(test)]
impl FakeObsGateway {
    pub fn new() -> Self {
        FakeObsGateway {
            devel_project: Ok(None),
            devel_version: Ok(None),
            has_open_sr: Ok(false),
            maintained_instances: Ok(Vec::new()),
            file_submit: Ok(None),
            file_maintenance_incident: Ok(None),
            has_open_sr_calls: std::cell::RefCell::new(Vec::new()),
        }
    }
}

#[cfg(test)]
impl FakeObsGateway {
    /// Packages `has_open_sr` was called for, in call order.
    pub fn has_open_sr_calls(&self) -> Vec<String> {
        self.has_open_sr_calls.borrow().clone()
    }
}

#[cfg(test)]
impl Default for FakeObsGateway {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl ObsGateway for FakeObsGateway {
    fn devel_project(
        &self,
        _project: &str,
        _package: &str,
    ) -> Result<Option<(String, String)>, GeectlError> {
        self.devel_project.clone()
    }

    fn devel_version(&self, _package: &str) -> Result<Option<String>, GeectlError> {
        self.devel_version.clone()
    }

    fn has_open_sr(&self, package: &str) -> Result<bool, GeectlError> {
        self.has_open_sr_calls
            .borrow_mut()
            .push(package.to_string());
        self.has_open_sr.clone()
    }

    fn maintained_instances(
        &self,
        _package: &str,
        _options: &MaintenanceBranchOptions,
    ) -> Result<Vec<MaintainedInstance>, GeectlError> {
        self.maintained_instances.clone()
    }

    fn file_submit(
        &self,
        _payload: &SrPayload,
        _dry_run: &DryRun,
    ) -> Result<Option<FiledRequest>, GeectlError> {
        match &self.file_submit {
            Ok(Some((id, superseded))) => Ok(Some(FiledRequest {
                id: id.clone(),
                superseded: superseded.clone(),
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(e.clone()),
        }
    }

    fn file_maintenance_incident(
        &self,
        _payload: &MaintenanceIncidentPayload,
        _dry_run: &DryRun,
    ) -> Result<Option<String>, GeectlError> {
        self.file_maintenance_incident.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::FakeHttpClient;
    use geectl::obs::ObsClient;

    /// The gateway merges geectl's dry-run filing lines into
    /// freshcrab's plan: filing in dry-run returns None and the
    /// would-file lines land in `DryRun::plan()`. Deleting the merge
    /// in `file_submit` / `file_maintenance_incident` must fail this.
    /// The submit target is a devel project, not Factory, so no
    /// factory check (which needs the network) runs before the
    /// dry-run guard; the fake HTTP client carries no responses.
    #[test]
    fn dry_run_filing_lines_reach_freshcrab_plan() {
        let http = FakeHttpClient::new();
        let obs = ObsClient::new(&http);
        let gateway = GeectlObsGateway::new(&obs);
        let dry = DryRun::new(true);

        let payload = SrPayload::new(
            "home:scarabeus_iv",
            "foo",
            "devel:languages:python",
            "foo",
            "Update foo to 2.0",
            "- Update to version 2.0.",
            &[],
        )
        .unwrap();
        assert_eq!(gateway.file_submit(&payload, &dry).unwrap(), None);
        assert!(
            dry.plan()
                .iter()
                .any(|l| l.contains("file submit request for foo")),
            "submit filing line missing from plan: {:?}",
            dry.plan()
        );

        let incident = MaintenanceIncidentPayload::new(
            "home:scarabeus_iv",
            &["foo.openSUSE_Leap_15.6_Update"],
            "openSUSE:Maintenance",
            "Backport the fix for foo",
        )
        .unwrap();
        assert_eq!(
            gateway.file_maintenance_incident(&incident, &dry).unwrap(),
            None
        );
        assert!(
            dry.plan()
                .iter()
                .any(|l| l.contains("maintenance incident")),
            "incident filing line missing from plan: {:?}",
            dry.plan()
        );
    }
}
