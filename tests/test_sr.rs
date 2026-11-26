//! Integration tests for SR filing through geectl: the dry-run exercise
//! (logs the exact payload, files nothing) and the live path (POSTs the
//! XML, returns the request id), plus the credential requirement.
//!
//! The filing itself is geectl's (`geectl::obs::SrFiling`); these tests
//! pin freshcrab's side of the seam — the fake HTTP client behind
//! geectl's client, and the payload shape freshcrab files — not
//! geectl's parsers or XML rendering, which geectl tests itself.

use freshcrab::http::FakeHttpClient;
use geectl::auth::Credentials;
use geectl::obs::{DryRun, ObsClient, SrFiling, SrPayload};

fn payload() -> SrPayload {
    SrPayload::new(
        "home:scarabeus_iv",
        "foo",
        "devel:languages:python",
        "foo",
        "Update foo to 2.0",
        "- Update to version 2.0.\n",
        &[],
    )
    .unwrap()
}

/// The OBS search URL for `package`, from a throwaway geectl client.
fn search_url_for(package: &str) -> String {
    let probe = FakeHttpClient::new();
    let obs = ObsClient::new(&probe);
    obs.search_url(package).unwrap()
}

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

#[test]
fn dry_run_logs_payload_and_posts_nothing() {
    let dry = DryRun::new(true);
    let http = FakeHttpClient::new().with_post(
        "https://api.opensuse.org/request?cmd=create",
        "<request id=\"1400001\"></request>",
    );
    let obs = obs_with_creds(&http);
    let filing = SrFiling::new(&obs, &dry);
    let result = filing.file(&payload()).unwrap();
    assert_eq!(result, None);
    // The POST count is zero.
    assert!(http.posted().is_empty());
    // The dry-run plan records the would-file action. The filing runs
    // through geectl's DryRun, so the lines land in geectl's plan, not
    // freshcrab's.
    assert!(dry
        .plan()
        .iter()
        .any(|l| l.contains("would: file submit request for foo to devel:languages:python")));
    // And the would-be payload detail lines are there too.
    assert!(dry
        .plan()
        .iter()
        .any(|l| l.contains("source: home:scarabeus_iv/foo")));
}

#[test]
fn live_posts_xml_and_returns_request_id() {
    let live = DryRun::new(false);
    let http = FakeHttpClient::new()
        .with(
            &search_url_for("foo"),
            "<collection matches=\"0\"></collection>",
        )
        .with_post(
            "https://api.opensuse.org/request?cmd=create",
            "<request id=\"1400001\" creator=\"scarabeus_iv\"></request>",
        );
    let obs = obs_with_creds(&http);
    let filing = SrFiling::new(&obs, &live);
    let result = filing.file(&payload()).unwrap();
    assert_eq!(result.map(|filed| filed.id), Some("1400001".to_string()));
    let posted = http.posted();
    assert_eq!(http.posted_auth(), vec![true]);
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].0, "https://api.opensuse.org/request?cmd=create");
    assert!(posted[0].1.contains("<action type=\"submit\">"));
    assert!(posted[0]
        .1
        .contains("<source project=\"home:scarabeus_iv\" package=\"foo\" />"));
    assert!(posted[0]
        .1
        .contains("<target project=\"devel:languages:python\" package=\"foo\" />"));
    assert!(posted[0].1.contains("Update foo to 2.0"));
    // The filed SR carries the cleanup default: the source branch dies
    // on accept.
    assert!(posted[0]
        .1
        .contains("<options><sourceupdate>cleanup</sourceupdate></options>"));
}

#[test]
fn live_without_credentials_fails_closed() {
    let live = DryRun::new(false);
    let http = FakeHttpClient::new().with_post(
        "https://api.opensuse.org/request?cmd=create",
        "<request id=\"1400001\"></request>",
    );
    // No credentials on the OBS client.
    let obs = ObsClient::new(&http);
    let filing = SrFiling::new(&obs, &live);
    assert!(filing.file(&payload()).is_err());
    // The POST count is zero.
    assert!(http.posted().is_empty());
}

#[test]
fn create_request_rejects_unexpected_response() {
    let live = DryRun::new(false);
    let http = FakeHttpClient::new()
        .with(
            &search_url_for("foo"),
            "<collection matches=\"0\"></collection>",
        )
        .with_post(
            "https://api.opensuse.org/request?cmd=create",
            "<not-a-request></not-a-request>",
        );
    let obs = obs_with_creds(&http);
    let filing = SrFiling::new(&obs, &live);
    assert!(filing.file(&payload()).is_err());
}
