//! Integration tests for SR filing: the dry-run exercise (logs the exact
//! payload, files nothing) and the live path (POSTs the XML, returns the
//! request id), plus the credential requirement.

use freshcrab::dry_run::DryRun;
use freshcrab::http::FakeHttpClient;
use freshcrab::obs::{ObsClient, ObsCredentials};
use freshcrab::sr::{SrFiling, SrPayload};

fn payload() -> SrPayload {
    SrPayload::new(
        "home:scarabeus_iv",
        "foo",
        "devel:languages:python",
        "foo",
        "Update foo to 2.0",
        "- Update to version 2.0.\n",
    )
    .unwrap()
}

fn obs_with_creds(http: &FakeHttpClient) -> ObsClient<'_> {
    ObsClient::with_credentials(
        http,
        ObsCredentials {
            username: "scarabeus_iv".to_string(),
            password: "secret".to_string(),
        },
    )
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
    // No POST was made.
    assert!(http.posted().is_empty());
    // The dry-run plan records the would-file action.
    assert!(dry
        .plan()
        .iter()
        .any(|l| l.contains("would: file submit request for foo to devel:languages:python")));
}

#[test]
fn live_posts_xml_and_returns_request_id() {
    let live = DryRun::new(false);
    let http = FakeHttpClient::new().with_post(
        "https://api.opensuse.org/request?cmd=create",
        "<request id=\"1400001\" creator=\"scarabeus_iv\"></request>",
    );
    let obs = obs_with_creds(&http);
    let filing = SrFiling::new(&obs, &live);
    let result = filing.file(&payload()).unwrap();
    assert_eq!(result, Some("1400001".to_string()));
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
    // Nothing was posted.
    assert!(http.posted().is_empty());
}

#[test]
fn create_request_rejects_unexpected_response() {
    let live = DryRun::new(false);
    let http = FakeHttpClient::new().with_post(
        "https://api.opensuse.org/request?cmd=create",
        "<not-a-request></not-a-request>",
    );
    let obs = obs_with_creds(&http);
    let filing = SrFiling::new(&obs, &live);
    assert!(filing.file(&payload()).is_err());
}
