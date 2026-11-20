//! Submit-request filing: build, validate, and file the OBS request.
//!
//! A submit request (SR) is the only way a package update enters a devel
//! project. This module owns the SR payload — the OBS request XML — and
//! the filing step:
//!
//! - [`SrPayload`] builds the payload from an update plan and validates
//!   it (valid OBS project/package names, non-empty description and
//!   `.changes` entry, well-formed XML). A payload that fails validation
//!   is never filed.
//! - [`SrFiling::file`] files it. The filing is gated by the single
//!   dry-run guard (`DryRun::allow`): in dry-run it logs exactly what
//!   would be filed — the SR text, the target project, the package, and
//!   the full XML — verifies the payload is well-formed, and files
//!   nothing. In live mode it POSTs the XML to the OBS API and returns
//!   the new request id. There is no other filing path.
//!
//! The OBS API call is `POST /request?cmd=create` with the request XML
//! as the body (the same call `osc api -X POST -T <xml>
//! "/request?cmd=create"` makes). It needs OBS credentials (HTTP Basic
//! auth); without them the filing fails loudly instead of filing
//! anonymously. Credentials come from the environment (`OSC_USERNAME` /
//! `OSC_PASSWORD`), never from the repo (see `crate::obs`).

use crate::collectors::valid_obs_name;
use crate::dry_run::DryRun;
use crate::obs::ObsClient;
use crate::worker::UpdatePlan;
use std::fmt;

/// Error from SR payload building or filing.
///
/// Mirrors [`crate::http::HttpError`]: an auth rejection (the OBS API
/// 401d the filing POST) is a distinct variant, so the worker can fail
/// the run loudly on bad or rotated credentials instead of escalating
/// the package like any other filing failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrError {
    /// The OBS API rejected the credentials when filing.
    AuthRejected(String),
    /// Any other payload or filing failure.
    Other(String),
}

impl SrError {
    /// The message without the `sr error: ` Display prefix (the
    /// escalation reason text the worker reports).
    pub fn message(&self) -> &str {
        match self {
            SrError::AuthRejected(msg) | SrError::Other(msg) => msg,
        }
    }
}

impl fmt::Display for SrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrError::AuthRejected(msg) => write!(f, "sr error (auth rejected): {msg}"),
            SrError::Other(msg) => write!(f, "sr error: {msg}"),
        }
    }
}

impl std::error::Error for SrError {}

/// The validated submit-request payload: where the change comes from,
/// where it goes, what it says, and the one `.changes` entry it carries.
///
/// The `.changes` entry is not part of the OBS request XML (it lives in
/// the package's `.changes` file, in the branch); it is carried here so
/// the filing step can log the complete submission and the worker can
/// validate the changelog rules (see `docs/leap-and-cve.md`) before
/// anything is filed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrPayload {
    /// The project the change comes from (the branch, e.g.
    /// `home:scarabeus_iv`).
    pub source_project: String,
    /// The package in the source project.
    pub source_package: String,
    /// The project the SR targets (the devel project).
    pub target_project: String,
    /// The package in the target project.
    pub target_package: String,
    /// The SR description text (the human-readable summary).
    pub description: String,
    /// The one `.changes` entry for this submission.
    pub changes_entry: String,
}

impl SrPayload {
    /// Build and validate a payload. Every name must be a valid OBS
    /// project/package name, and the description and `.changes` entry
    /// must be non-empty. Returns Err instead of building a payload
    /// that could not be filed.
    pub fn new(
        source_project: &str,
        source_package: &str,
        target_project: &str,
        target_package: &str,
        description: &str,
        changes_entry: &str,
    ) -> Result<Self, SrError> {
        for (label, value) in [
            ("source project", source_project),
            ("target project", target_project),
        ] {
            if !valid_obs_name(value) {
                return Err(SrError::Other(format!(
                    "invalid OBS project name for {label}: {value:?}"
                )));
            }
        }
        for (label, value) in [
            ("source package", source_package),
            ("target package", target_package),
        ] {
            if !valid_obs_name(value) {
                return Err(SrError::Other(format!(
                    "invalid OBS package name for {label}: {value:?}"
                )));
            }
        }
        if description.trim().is_empty() {
            return Err(SrError::Other(
                "SR description must not be empty".to_string(),
            ));
        }
        if changes_entry.trim().is_empty() {
            return Err(SrError::Other(
                "SR .changes entry must not be empty".to_string(),
            ));
        }
        let payload = SrPayload {
            source_project: source_project.to_string(),
            source_package: source_package.to_string(),
            target_project: target_project.to_string(),
            target_package: target_package.to_string(),
            description: description.to_string(),
            changes_entry: changes_entry.to_string(),
        };
        // The payload must render to well-formed XML, or it is not a
        // payload at all — check now, not at filing time.
        payload.validate_xml()?;
        Ok(payload)
    }

    /// Build a payload from an update plan. The branch project must be
    /// resolved (see `UpdatePlan::branch_project`); an unresolved branch
    /// project is an error, not a placeholder — a payload with a made-up
    /// source project would file to the wrong place.
    pub fn from_plan(plan: &UpdatePlan) -> Result<Self, SrError> {
        let source_project = plan.branch_project.clone().ok_or_else(|| {
            SrError::Other(
                "cannot build an SR payload: the branch project is unresolved \
                 (set home_project in config.yaml or OSC_USERNAME/OSC_PASSWORD)"
                    .to_string(),
            )
        })?;
        SrPayload::new(
            &source_project,
            &plan.package,
            &plan.devel_project,
            &plan.package,
            &plan.description,
            &plan.changes_entry,
        )
    }

    /// Render the OBS request XML for this payload. All text is
    /// XML-escaped, so a description containing `&` or `<` cannot break
    /// out of its element.
    pub fn to_xml(&self) -> String {
        format!(
            "<request>\n  <action type=\"submit\">\n    <source project=\"{}\" package=\"{}\" />\n    <target project=\"{}\" package=\"{}\" />\n  </action>\n  <description>{}</description>\n</request>",
            xml_escape(&self.source_project),
            xml_escape(&self.source_package),
            xml_escape(&self.target_project),
            xml_escape(&self.target_package),
            xml_escape(&self.description),
        )
    }

    /// Verify the rendered XML is well-formed: tags are balanced and
    /// properly nested, there is exactly one root element (`request`),
    /// and the required elements are present in the expected nesting
    /// (`request > action[type=submit] > source, target` and
    /// `request > description`). This is a structural check on the
    /// generated XML, not a re-derivation of the payload.
    pub fn validate_xml(&self) -> Result<(), SrError> {
        check_well_formed(&self.to_xml())
    }
}

/// Escape text for an XML element or attribute value.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Check that `xml` is well-formed: every tag is balanced and properly
/// nested, there is exactly one root element, and it is `request` with
/// the submit action, source, target, and description in the expected
/// nesting. Returns the first problem found.
fn check_well_formed(xml: &str) -> Result<(), SrError> {
    let mut stack: Vec<String> = Vec::new();
    // The element path of each element, for the required-structure check.
    let mut paths: Vec<String> = Vec::new();
    let bytes = xml.as_bytes();
    let mut i = 0;
    let mut root_seen = false;
    while i < bytes.len() {
        let Some(open) = xml[i..].find('<') else {
            break;
        };
        // `start` is the position of this tag; `i` (the scan position)
        // only advances at the end of the iteration, after the tag.
        let start = i + open;
        let Some(close_rel) = xml[start..].find('>') else {
            return Err(SrError::Other(
                "malformed XML: unterminated tag".to_string(),
            ));
        };
        let close = start + close_rel;
        let raw = &xml[start + 1..close];
        if raw.starts_with('?') || raw.starts_with('!') {
            // Declaration / comment / doctype: not generated here, but
            // tolerated so a strict checker does not reject a harmless
            // prefix.
            i = close + 1;
            continue;
        }
        if let Some(name) = raw.strip_prefix('/') {
            // Close tag: must match the innermost open tag.
            let name = name.trim();
            match stack.pop() {
                Some(open_name) if open_name == name => {}
                Some(open_name) => {
                    return Err(SrError::Other(format!(
                        "malformed XML: closing </{name}> does not match open <{open_name}>"
                    )));
                }
                None => {
                    return Err(SrError::Other(format!(
                        "malformed XML: closing </{name}> with nothing open"
                    )));
                }
            }
        } else if let Some(without_slash) = raw.strip_suffix('/') {
            // Self-closing tag: no stack change. It is a leaf; record
            // its path for the structure check.
            let name = without_slash.split_whitespace().next().unwrap_or("");
            if name.is_empty() {
                return Err(SrError::Other("malformed XML: empty tag".to_string()));
            }
            let mut path = stack.join("/");
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(name);
            paths.push(path);
        } else {
            // Open tag: push it. The tag name is the first word.
            let name = raw.split_whitespace().next().unwrap_or("");
            if name.is_empty() {
                return Err(SrError::Other("malformed XML: empty tag".to_string()));
            }
            if stack.is_empty() {
                if root_seen {
                    return Err(SrError::Other(
                        "malformed XML: more than one root element".to_string(),
                    ));
                }
                root_seen = true;
            }
            stack.push(name.to_string());
            let mut path = stack.join("/");
            paths.push(std::mem::take(&mut path));
        }
        i = close + 1;
    }
    if !stack.is_empty() {
        return Err(SrError::Other(format!(
            "malformed XML: unclosed tag(s): {}",
            stack.join(", ")
        )));
    }
    if !root_seen {
        return Err(SrError::Other("malformed XML: no root element".to_string()));
    }
    // Required structure: exactly one root `request`, containing an
    // `action` (which holds `source` and `target`) and a `description`.
    let has = |path: &str| paths.iter().any(|p| p == path);
    if !has("request") {
        return Err(SrError::Other(
            "malformed SR XML: root element is not <request>".to_string(),
        ));
    }
    if !has("request/action") {
        return Err(SrError::Other(
            "malformed SR XML: missing <action> in <request>".to_string(),
        ));
    }
    if !has("request/action/source") {
        return Err(SrError::Other(
            "malformed SR XML: missing <source> in <action>".to_string(),
        ));
    }
    if !has("request/action/target") {
        return Err(SrError::Other(
            "malformed SR XML: missing <target> in <action>".to_string(),
        ));
    }
    if !has("request/description") {
        return Err(SrError::Other(
            "malformed SR XML: missing <description> in <request>".to_string(),
        ));
    }
    Ok(())
}

/// Capability token proving the caller is [`SrFiling`]: the only way
/// to file a submit request is through [`SrFiling::file`], which
/// enforces the dry-run guard.
///
/// The token can only be minted here — its field is private and its
/// constructor is private, so no other module (in this crate or
/// outside it) can construct one. [`ObsClient::create_request`]
/// requires it, which makes the single-caller rule compiler-
/// enforced: a future direct caller cannot compile without a token
/// it cannot mint.
pub struct FilingPermit {
    _private: (),
}

impl FilingPermit {
    fn new() -> Self {
        FilingPermit { _private: () }
    }
}

/// Files a submit request through the OBS API.
///
/// The only filing path. In dry-run, [`SrFiling::file`] logs exactly
/// what would be filed and verifies the payload, and files nothing. In
/// live mode it POSTs the payload XML and returns the new request id.
pub struct SrFiling<'a> {
    obs: &'a ObsClient<'a>,
    dry_run: &'a DryRun,
}

impl<'a> SrFiling<'a> {
    pub fn new(obs: &'a ObsClient<'a>, dry_run: &'a DryRun) -> Self {
        SrFiling { obs, dry_run }
    }

    /// File `payload`. Returns the new OBS request id in live mode, or
    /// None in dry-run (nothing was filed). The payload is validated
    /// before either path is taken.
    pub fn file(&self, payload: &SrPayload) -> Result<Option<String>, SrError> {
        payload.validate_xml()?;
        if !self.dry_run.allow(&format!(
            "file submit request for {} to {}",
            payload.target_package, payload.target_project
        )) {
            // Dry-run: log exactly what would be filed, in full, so the
            // filing path is exercised end to end without filing.
            // (The `allow` call above already recorded the would-do line
            // in the plan.)
            eprintln!("--- would-be submit request (dry-run) ---");
            eprintln!(
                "source: {}/{}",
                payload.source_project, payload.source_package
            );
            eprintln!(
                "target: {}/{}",
                payload.target_project, payload.target_package
            );
            eprintln!("description: {}", payload.description);
            eprintln!("changes entry: {}", payload.changes_entry);
            eprintln!("{}", payload.to_xml());
            eprintln!("--- end of would-be submit request ---");
            return Ok(None);
        }
        let xml = payload.to_xml();
        let id = self
            .obs
            .create_request(&FilingPermit::new(), &xml)
            .map_err(|e| {
                // Preserve the variant: an auth rejection at filing time
                // must stay distinguishable so the worker fails the run
                // loudly instead of escalating the package.
                let msg = format!("OBS create-request failed: {e}");
                if e.is_auth_rejected() {
                    SrError::AuthRejected(msg)
                } else {
                    SrError::Other(msg)
                }
            })?;
        Ok(Some(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dry_run::DryRun;
    use crate::http::FakeHttpClient;
    use crate::obs::{ObsClient, ObsCredentials};
    use crate::queue::UpdateKind;
    use crate::target::Target;

    fn payload() -> SrPayload {
        SrPayload::new(
            "home:scarabeus_iv",
            "foo",
            "devel:languages:python",
            "foo",
            "Update foo to 2.0",
            "-------------------------------------------------------------------\nFri Nov 20 07:00:00 UTC 2026 - Tomáš Chvátal <tomas.chvatal@gmail.com>\n\n- Update to version 2.0.\n",
        )
        .unwrap()
    }

    #[test]
    fn to_xml_renders_submit_action() {
        let xml = payload().to_xml();
        assert!(xml.contains("<request>"));
        assert!(xml.contains("<action type=\"submit\">"));
        assert!(xml.contains("<source project=\"home:scarabeus_iv\" package=\"foo\" />"));
        assert!(xml.contains("<target project=\"devel:languages:python\" package=\"foo\" />"));
        assert!(xml.contains("<description>Update foo to 2.0</description>"));
        assert!(xml.contains("</request>"));
    }

    #[test]
    fn to_xml_escapes_description() {
        let p = SrPayload::new(
            "home:scarabeus_iv",
            "foo",
            "devel:languages:python",
            "foo",
            "Update foo to 2.0 & fix <bugs>",
            "- Update to version 2.0.\n",
        )
        .unwrap();
        let xml = p.to_xml();
        assert!(xml.contains("Update foo to 2.0 &amp; fix &lt;bugs&gt;"));
        assert!(!xml.contains("fix <bugs>"));
        // The escaped description still validates.
        assert!(p.validate_xml().is_ok());
    }

    #[test]
    fn new_rejects_invalid_names() {
        assert!(SrPayload::new(
            "home:scarabeus_iv",
            "foo/bar",
            "devel:languages:python",
            "foo",
            "Update foo to 2.0",
            "- Update to version 2.0.\n",
        )
        .is_err());
        assert!(SrPayload::new(
            "home:scarabeus_iv",
            "foo",
            "devel:languages:python",
            "foo",
            "   ",
            "- Update to version 2.0.\n",
        )
        .is_err());
        assert!(SrPayload::new(
            "home:scarabeus_iv",
            "foo",
            "devel:languages:python",
            "foo",
            "Update foo to 2.0",
            "  ",
        )
        .is_err());
    }

    #[test]
    fn check_well_formed_accepts_generated_xml() {
        assert!(check_well_formed(&payload().to_xml()).is_ok());
    }

    #[test]
    fn check_well_formed_rejects_mismatched_tags() {
        assert!(check_well_formed("<request><action></request>").is_err());
        assert!(check_well_formed("<request><action>").is_err());
        assert!(check_well_formed("<request></request><request></request>").is_err());
        assert!(check_well_formed("").is_err());
    }

    #[test]
    fn check_well_formed_rejects_missing_elements() {
        // Well-formed XML but not an SR: no action/source/target.
        assert!(check_well_formed("<request><description>x</description></request>").is_err());
        assert!(check_well_formed(
            "<request><action><source project=\"a\" package=\"b\" /></action></request>"
        )
        .is_err());
    }

    #[test]
    fn from_plan_needs_resolved_branch_project() {
        let plan = UpdatePlan {
            package: "foo".to_string(),
            factory_version: "1.9".to_string(),
            upstream_version: "2.0".to_string(),
            source: "repology".to_string(),
            devel_project: "devel:languages:python".to_string(),
            branch_project: None,
            kind: UpdateKind::Routine,
            target: Target::Factory,
            changes_entry: "- Update to version 2.0.\n".to_string(),
            description: "Update foo to 2.0".to_string(),
            cve_regression_test: None,
        };
        assert!(SrPayload::from_plan(&plan).is_err());
    }

    #[test]
    fn to_xml_escapes_all_five_specials_and_unicode() {
        // All five XML special characters, plus non-ASCII text: the
        // escaped form must carry the entities, the raw specials must
        // not leak into the description element, the unicode must pass
        // through, and the result must still validate.
        let p = SrPayload::new(
            "home:scarabeus_iv",
            "foo",
            "devel:languages:python",
            "foo",
            "Update foo to 2.0 & fix <bugs> \"quoted\" 'apos' — Tomáš",
            "- Update to version 2.0.\n",
        )
        .unwrap();
        let xml = p.to_xml();
        assert!(xml.contains(
            "Update foo to 2.0 &amp; fix &lt;bugs&gt; &quot;quoted&quot; &apos;apos&apos; — Tomáš"
        ));
        assert!(!xml.contains("fix <bugs>"));
        assert!(!xml.contains("\"quoted\""));
        assert!(xml.contains("Tomáš"));
        assert!(p.validate_xml().is_ok());
    }

    #[test]
    fn new_rejects_unicode_names() {
        // OBS names are ASCII-only; a unicode package name is rejected
        // at payload build time, not at the API.
        assert!(SrPayload::new(
            "home:scarabeus_iv",
            "föö",
            "devel:languages:python",
            "foo",
            "Update foo to 2.0",
            "- Update to version 2.0.\n",
        )
        .is_err());
    }

    #[test]
    fn file_returns_error_on_transport_failure() {
        // Live mode, credentials present, but the POST itself fails (no
        // canned response = transport error): filing returns Err, it
        // does not silently report a plan.
        let http = FakeHttpClient::new();
        let obs = ObsClient::with_credentials(
            &http,
            ObsCredentials {
                username: "scarabeus_iv".to_string(),
                password: "secret".to_string(),
            },
        );
        let dry = DryRun::new(false);
        let filing = SrFiling::new(&obs, &dry);
        assert!(filing.file(&payload()).is_err());
    }

    #[test]
    fn file_returns_auth_rejected_on_401() {
        // Live mode, credentials present, but the OBS API 401s the
        // filing POST: the auth rejection stays typed (AuthRejected)
        // so the worker can fail the run loudly instead of escalating
        // the package.
        let http = FakeHttpClient::new().with_post_status(
            "https://api.opensuse.org/request?cmd=create",
            401,
            "unauthorized",
        );
        let obs = ObsClient::with_credentials(
            &http,
            ObsCredentials {
                username: "scarabeus_iv".to_string(),
                password: "secret".to_string(),
            },
        );
        let dry = DryRun::new(false);
        let filing = SrFiling::new(&obs, &dry);
        assert!(matches!(
            filing.file(&payload()),
            Err(SrError::AuthRejected(_))
        ));
    }

    #[test]
    fn file_posts_xml_and_returns_id() {
        // Live mode: filing POSTs the payload XML and returns the new
        // request id; the POST carried the credentials.
        let http = FakeHttpClient::new().with_post(
            "https://api.opensuse.org/request?cmd=create",
            "<request id=\"1400001\" creator=\"scarabeus_iv\"></request>",
        );
        let obs = ObsClient::with_credentials(
            &http,
            ObsCredentials {
                username: "scarabeus_iv".to_string(),
                password: "secret".to_string(),
            },
        );
        let dry = DryRun::new(false);
        let filing = SrFiling::new(&obs, &dry);
        assert_eq!(
            filing.file(&payload()).unwrap(),
            Some("1400001".to_string())
        );
        let posted = http.posted();
        assert_eq!(posted.len(), 1);
        assert_eq!(posted[0].0, "https://api.opensuse.org/request?cmd=create");
        assert_eq!(http.posted_auth(), vec![true]);
    }

    #[test]
    fn file_without_credentials_fails_closed() {
        // No credentials: filing fails instead of posting anonymously,
        // and nothing is posted.
        let http = FakeHttpClient::new().with_post(
            "https://api.opensuse.org/request?cmd=create",
            "<request id=\"1400001\"></request>",
        );
        let obs = ObsClient::new(&http);
        let dry = DryRun::new(false);
        let filing = SrFiling::new(&obs, &dry);
        assert!(filing.file(&payload()).is_err());
        assert!(http.posted().is_empty());
    }
}
