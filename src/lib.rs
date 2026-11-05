//! Blocking client for the [Eclipse hawkBit](https://eclipse.dev/hawkbit/) Direct Device
//! Integration (DDI) API, authenticating with a tenant-wide `GatewayToken` or a device-specific
//! `TargetToken`.
//!
//! ```no_run
//! use hawkbit_ddi::{Action, DdiClient, Execution, Finished, Token};
//!
//! let client = DdiClient::new(
//!     "https://hawkbit.example.com",
//!     "DEFAULT",
//!     Token::TargetToken("secret".into()),
//! );
//! let poll = client.poll("my-device")?;
//! match poll.action {
//!     Some(Action::Deploy(deployment)) => {
//!         println!("update to {:?} from {:?}", deployment.version(), deployment.bundle_url(".raucb"));
//!         client.feedback("my-device", &deployment.id, Execution::Closed, Finished::Success, &[])?;
//!     }
//!     Some(Action::Cancel(id)) => {
//!         client.cancel_feedback("my-device", &id, Execution::Closed, Finished::Success, &[])?;
//!     }
//!     None => {}
//! }
//! std::thread::sleep(poll.sleep.unwrap_or(std::time::Duration::from_secs(300)));
//! # Ok::<(), ureq::Error>(())
//! ```
#![deny(missing_docs)]
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;

/// Client for one hawkBit tenant's DDI API.
pub struct DdiClient {
    agent: ureq::Agent,
    base_url: String,
    tenant: String,
    token: Token,
    attributes: BTreeMap<String, String>,
    attributes_sent: AtomicBool,
}

/// DDI credentials, deserialized from `{"gateway_token": ...}` or `{"target_token": ...}`.
/// `Debug` hides the secret.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Token {
    /// Tenant-wide gateway security token.
    GatewayToken(String),
    /// Security token of a single target (device).
    TargetToken(String),
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Token::GatewayToken(_) => "GatewayToken(***)",
            Token::TargetToken(_) => "TargetToken(***)",
        })
    }
}

/// A HAL link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    /// Target URL of the link.
    pub href: String,
}

/// The `deploymentBase` resource of an action, keeping only the fields this crate uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentBase {
    /// Action id, used when reporting feedback.
    pub id: String,
    /// What to deploy.
    pub deployment: Deployment,
}

/// The software modules of a deployment, and how to handle them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    /// Whether to download the artifacts.
    pub download: Handling,
    /// Whether to install the artifacts. `Skip` means download only.
    pub update: Handling,
    /// Set when the action has a maintenance window: install only while it is `Available`.
    pub maintenance_window: Option<MaintenanceWindow>,
    /// One chunk per software module.
    pub chunks: Vec<Chunk>,
}

/// How a step of a deployment is to be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Handling {
    /// Do not perform the step.
    Skip,
    /// Perform the step if the device sees fit (soft update).
    Attempt,
    /// Perform the step now.
    Forced,
}

/// Whether the action's maintenance window is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MaintenanceWindow {
    /// The window is open; installing is allowed.
    Available,
    /// The window is closed; wait before installing.
    Unavailable,
}

/// A software module to deploy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    /// Version of the software module.
    pub version: String,
    /// Artifacts (files) of the software module.
    pub artifacts: Vec<Artifact>,
}

/// A downloadable file of a software module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// File name of the artifact.
    pub filename: String,
    /// Size in bytes.
    pub size: u64,
    /// Checksums, to verify the download.
    pub hashes: Hashes,
    /// Download links of the artifact.
    #[serde(rename = "_links")]
    pub links: ArtifactLinks,
}

/// Hex-encoded checksums of an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hashes {
    /// SHA-1 checksum.
    pub sha1: String,
    /// MD5 checksum.
    pub md5: String,
    /// SHA-256 checksum, sent by hawkBit 0.3 and later.
    pub sha256: Option<String>,
}

/// Download links of an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactLinks {
    /// HTTPS download link.
    pub download: Option<Link>,
    /// Plain HTTP download link.
    #[serde(rename = "download-http")]
    pub download_http: Option<Link>,
}

impl DeploymentBase {
    /// HTTPS download URL of the one artifact whose file name ends with `suffix`, such as
    /// `".raucb"`. Other files next to it, like signatures or notes, are ignored. `None` when no
    /// artifact or several match, the match has no https link, or there is more than one chunk;
    /// then read [`Deployment::chunks`] instead.
    #[must_use]
    pub fn bundle_url(&self, suffix: &str) -> Option<&str> {
        let artifacts = &self.only_chunk()?.artifacts;
        let mut matches = artifacts.iter().filter(|a| a.filename.ends_with(suffix));
        match (matches.next(), matches.next()) {
            (Some(artifact), None) => Some(&artifact.links.download.as_ref()?.href),
            _ => None,
        }
    }

    /// Version of the deployment's only chunk. `None` when there are several.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        Some(&self.only_chunk()?.version)
    }

    fn only_chunk(&self) -> Option<&Chunk> {
        match self.deployment.chunks.as_slice() {
            [chunk] => Some(chunk),
            _ => None,
        }
    }
}

/// Execution status of an action, as reported in feedback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Execution {
    /// The action is still running.
    Proceeding,
    /// The action is done.
    Closed,
    /// The action was cancelled.
    Canceled,
    /// The device rejected the action, for example a cancel it cannot honour.
    Rejected,
    /// The action is scheduled for later.
    Scheduled,
    /// The action resumed, for example after a reboot.
    Resumed,
    /// The artifacts are downloading.
    Download,
    /// The artifacts are downloaded; ends a download-only action.
    Downloaded,
}

/// Result of an action, as reported in feedback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Finished {
    /// The action succeeded.
    Success,
    /// The action failed.
    Failure,
    /// No result yet.
    None,
}

/// Result of polling a controller.
#[derive(Debug, Clone)]
pub struct Poll {
    /// How long hawkBit wants the device to wait before polling again, if it said.
    pub sleep: Option<Duration>,
    /// What hawkBit wants the device to do, if anything.
    pub action: Option<Action>,
}

/// An open action for the device.
#[derive(Debug, Clone)]
pub enum Action {
    /// Deploy this. Report with [`DdiClient::feedback`] and [`DdiClient::progress`].
    Deploy(DeploymentBase),
    /// Cancel the action with this id. Answer with [`DdiClient::cancel_feedback`]; hawkBit holds
    /// back newer actions until you do.
    Cancel(String),
}

#[derive(Deserialize)]
struct CancelAction {
    id: String,
}

/// Parses hawkBit's `HH:MM:SS` polling interval.
fn parse_sleep(s: &str) -> Option<Duration> {
    let mut parts = s.split(':').map(str::parse::<u64>);
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(Ok(h)), Some(Ok(m)), Some(Ok(s)), None) => {
            Some(Duration::from_secs(h * 3600 + m * 60 + s))
        }
        _ => None,
    }
}

impl DdiClient {
    /// Client for `tenant` on the hawkBit server at `base_url`, with a 30 s request timeout and
    /// the server certificate verified against the default roots.
    #[must_use]
    pub fn new(base_url: &str, tenant: &str, token: Token) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Self {
            agent,
            base_url: base_url.trim_end_matches('/').to_string(),
            tenant: tenant.to_string(),
            token,
            attributes: BTreeMap::new(),
            attributes_sent: AtomicBool::new(false),
        }
    }

    /// Sends requests through `agent` instead, for example to trust a private CA or change the
    /// timeout.
    #[must_use]
    pub fn with_agent(mut self, agent: ureq::Agent) -> Self {
        self.agent = agent;
        self
    }

    /// Target attributes to report, on the first successful poll and whenever hawkBit asks again.
    #[must_use]
    pub fn with_attributes(mut self, attributes: BTreeMap<String, String>) -> Self {
        self.attributes = attributes;
        self
    }

    /// `Authorization` header value, for example to let another tool download the artifact.
    #[must_use]
    pub fn auth_header(&self) -> String {
        match &self.token {
            Token::GatewayToken(t) => format!("GatewayToken {t}"),
            Token::TargetToken(t) => format!("TargetToken {t}"),
        }
    }

    fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T, ureq::Error> {
        self.agent
            .get(url)
            .header("Accept", "application/hal+json")
            .header("Authorization", self.auth_header())
            .call()?
            .body_mut()
            .read_json()
    }

    /// The path of `href` from the server on `base_url`'s scheme and host, so the token never
    /// goes to another host or over plain http, even when hawkBit spells its own address
    /// differently (a port, letter case, or `http` behind a TLS proxy).
    fn on_base(&self, href: &str) -> Result<String, ureq::Error> {
        let bad = || ureq::Error::BadUri(format!("hawkBit link {href} or {}", self.base_url));
        let href: ureq::http::Uri = href.parse().map_err(|_| bad())?;
        let base: ureq::http::Uri = self.base_url.parse().map_err(|_| bad())?;
        match (base.scheme_str(), base.authority(), href.path_and_query()) {
            (Some(scheme), Some(host), Some(path)) => Ok(format!("{scheme}://{host}{path}")),
            _ => Err(bad()),
        }
    }

    fn controller_url(&self, controller_id: &str, path: &str) -> String {
        format!(
            "{}/{}/controller/v1/{controller_id}{path}",
            self.base_url, self.tenant
        )
    }

    /// Polls this controller for its open action and the interval until the next poll. Also
    /// reports the target attributes when due.
    pub fn poll(&self, controller_id: &str) -> Result<Poll, ureq::Error> {
        let poll: serde_json::Value = self.get_json(&self.controller_url(controller_id, ""))?;
        self.report_attributes(controller_id, poll.pointer("/_links/configData").is_some());
        let sleep = poll
            .pointer("/config/polling/sleep")
            .and_then(serde_json::Value::as_str)
            .and_then(parse_sleep);
        let link = |name: &str| {
            poll.pointer(&format!("/_links/{name}/href"))
                .and_then(serde_json::Value::as_str)
        };
        let action = if let Some(href) = link("cancelAction") {
            Some(Action::Cancel(
                self.get_json::<CancelAction>(&self.on_base(href)?)?.id,
            ))
        } else if let Some(href) = link("deploymentBase") {
            Some(Action::Deploy(self.get_json(&self.on_base(href)?)?))
        } else {
            None
        };
        Ok(Poll { sleep, action })
    }

    /// Reports the progress of this controller's action `action_id`.
    pub fn feedback(
        &self,
        controller_id: &str,
        action_id: &str,
        execution: Execution,
        finished: Finished,
        details: &[&str],
    ) -> Result<(), ureq::Error> {
        let url = self.controller_url(
            controller_id,
            &format!("/deploymentBase/{action_id}/feedback"),
        );
        self.post_status(&url, execution, finished, details, None)
    }

    /// Answers the cancel request for action `action_id`: `Closed` with `Success` accepts it,
    /// `Rejected` refuses it, for example when the install is too far along to stop.
    pub fn cancel_feedback(
        &self,
        controller_id: &str,
        action_id: &str,
        execution: Execution,
        finished: Finished,
        details: &[&str],
    ) -> Result<(), ureq::Error> {
        let url = self.controller_url(
            controller_id,
            &format!("/cancelAction/{action_id}/feedback"),
        );
        self.post_status(&url, execution, finished, details, None)
    }

    /// Reports `percent` done on this controller's still-running action `action_id`.
    pub fn progress(
        &self,
        controller_id: &str,
        action_id: &str,
        percent: u32,
        detail: &str,
    ) -> Result<(), ureq::Error> {
        let url = self.controller_url(
            controller_id,
            &format!("/deploymentBase/{action_id}/feedback"),
        );
        self.post_status(
            &url,
            Execution::Proceeding,
            Finished::None,
            &[detail],
            Some(percent),
        )
    }

    /// Sends the target attributes unless they already went out, or again if hawkBit `asked` for
    /// them. A failure is only logged, leaving them unsent for the next call.
    pub fn report_attributes(&self, controller_id: &str, asked: bool) {
        if self.attributes.is_empty() || (self.attributes_sent.load(Ordering::Relaxed) && !asked) {
            return;
        }
        match self.put_attributes(&self.controller_url(controller_id, "/configData")) {
            Ok(()) => self.attributes_sent.store(true, Ordering::Relaxed),
            Err(e) => tracing::warn!(error = %e, "reporting attributes to hawkBit"),
        }
    }

    fn put_attributes(&self, url: &str) -> Result<(), ureq::Error> {
        self.agent
            .put(url)
            .header("Authorization", self.auth_header())
            .send_json(json!({ "mode": "merge", "data": self.attributes }))?;
        Ok(())
    }

    fn post_status(
        &self,
        url: &str,
        execution: Execution,
        finished: Finished,
        details: &[&str],
        percent: Option<u32>,
    ) -> Result<(), ureq::Error> {
        let mut result = json!({ "finished": finished });
        if let Some(percent) = percent {
            result["progress"] = json!({ "cnt": percent, "of": 100 });
        }
        self.agent
            .post(url)
            .header("Authorization", self.auth_header())
            .send_json(json!({
                "status": {
                    "execution": execution,
                    "result": result,
                    "details": details,
                }
            }))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{Matcher, Server};

    #[test]
    fn poll_follows_the_deployment_link() {
        let mut server = Server::new();
        let href = format!(
            "{}/t/controller/v1/u-jetson/deploymentBase/5?c=1",
            server.url()
        );
        let _p = server
            .mock("GET", "/t/controller/v1/u-jetson")
            .match_header("authorization", "GatewayToken tok")
            .with_body(format!(
                r#"{{"config":{{"polling":{{"sleep":"00:05:00"}}}},"_links":{{"deploymentBase":{{"href":"{href}"}}}}}}"#
            ))
            .create();
        let _d = server
            .mock("GET", "/t/controller/v1/u-jetson/deploymentBase/5")
            .match_query(Matcher::UrlEncoded("c".into(), "1".into()))
            .with_body(
                r#"{"id":"5","deployment":{"download":"forced","update":"skip",
                    "maintenanceWindow":"unavailable","chunks":[
                    {"part":"os","name":"jetson","version":"20261030-abc1234","artifacts":[
                        {"filename":"b.raucb","size":3,"hashes":{"sha1":"s","md5":"m","sha256":"x"},"_links":{
                            "download":{"href":"https://h/b.raucb"},
                            "download-http":{"href":"http://h/b.raucb"}}}]}]}}"#,
            )
            .create();
        let api = DdiClient::new(&server.url(), "t", Token::GatewayToken("tok".into()));
        let poll = api.poll("u-jetson").unwrap();
        assert_eq!(poll.sleep, Some(Duration::from_secs(300)));
        let Some(Action::Deploy(d)) = poll.action else {
            panic!("expected a deployment, got {:?}", poll.action)
        };
        assert_eq!(d.id, "5");
        assert_eq!(d.deployment.update, Handling::Skip);
        assert_eq!(
            d.deployment.maintenance_window,
            Some(MaintenanceWindow::Unavailable)
        );
        let artifact = &d.deployment.chunks[0].artifacts[0];
        assert_eq!((artifact.filename.as_str(), artifact.size), ("b.raucb", 3));
        assert_eq!(artifact.hashes.sha256.as_deref(), Some("x"));
        assert_eq!(d.deployment.chunks[0].version, "20261030-abc1234");
        assert_eq!(d.bundle_url(".raucb"), Some("https://h/b.raucb"));
    }

    #[test]
    fn poll_without_action_is_none() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/t/controller/v1/u-verdin")
            .with_body(r#"{"config":{"polling":{"sleep":"12:34:56"}},"_links":{}}"#)
            .create();
        let api = DdiClient::new(&server.url(), "t", Token::GatewayToken("tok".into()));
        let poll = api.poll("u-verdin").unwrap();
        assert!(poll.action.is_none());
        assert_eq!(
            poll.sleep,
            Some(Duration::from_secs(12 * 3600 + 34 * 60 + 56))
        );
    }

    #[test]
    fn poll_returns_a_cancel_and_cancel_feedback_answers_it() {
        let mut server = Server::new();
        let href = format!("{}/t/controller/v1/u-verdin/cancelAction/27", server.url());
        let _p = server
            .mock("GET", "/t/controller/v1/u-verdin")
            .with_body(format!(
                r#"{{"_links":{{"cancelAction":{{"href":"{href}"}}}}}}"#
            ))
            .create();
        let _c = server
            .mock("GET", "/t/controller/v1/u-verdin/cancelAction/27")
            .with_body(r#"{"id":"27","cancelAction":{"stopId":"27"}}"#)
            .create();
        let reject = server
            .mock("POST", "/t/controller/v1/u-verdin/cancelAction/27/feedback")
            .match_header("authorization", "TargetToken tok")
            .match_body(Matcher::PartialJson(serde_json::json!({
                "status": {"execution": "rejected", "result": {"finished": "none"}}
            })))
            .create();
        let api = DdiClient::new(&server.url(), "t", Token::TargetToken("tok".into()));
        let poll = api.poll("u-verdin").unwrap();
        assert!(poll.sleep.is_none());
        let Some(Action::Cancel(id)) = poll.action else {
            panic!("expected a cancel, got {:?}", poll.action)
        };
        assert_eq!(id, "27");
        api.cancel_feedback("u-verdin", &id, Execution::Rejected, Finished::None, &[])
            .unwrap();
        reject.assert();
    }

    #[test]
    fn poll_reports_attributes_once_until_asked_again() {
        let mut server = Server::new();
        let poll = |links: &str| format!(r#"{{"_links":{{{links}}}}}"#);
        let quiet = server
            .mock("GET", "/t/controller/v1/u-verdin")
            .with_body(poll(""))
            .expect(2)
            .create();
        let put = server
            .mock("PUT", "/t/controller/v1/u-verdin/configData")
            .match_header("authorization", "TargetToken tok")
            .match_body(Matcher::Json(serde_json::json!({
                "mode": "merge", "data": {"rauc.compatible": "c"}
            })))
            .expect(2)
            .create();
        let api = DdiClient::new(&server.url(), "t", Token::TargetToken("tok".into()))
            .with_attributes(BTreeMap::from([("rauc.compatible".into(), "c".into())]));
        api.poll("u-verdin").unwrap();
        api.poll("u-verdin").unwrap();
        quiet.assert();
        let href = format!("{}/t/controller/v1/u-verdin/configData", server.url());
        let _asking = server
            .mock("GET", "/t/controller/v1/u-verdin")
            .with_body(poll(&format!(r#""configData":{{"href":"{href}"}}"#)))
            .create();
        api.poll("u-verdin").unwrap();
        put.assert();
    }

    #[test]
    fn poll_follows_links_on_base_url_only() {
        let mut server = Server::new();
        let api = DdiClient::new(&server.url(), "t", Token::GatewayToken("tok".into()));
        for (rel, path, body) in [
            ("cancelAction", "cancelAction/27", r#"{"id":"27"}"#),
            (
                "deploymentBase",
                "deploymentBase/5",
                r#"{"id":"5","deployment":{"download":"forced","update":"forced","chunks":[]}}"#,
            ),
        ] {
            let path = format!("/t/controller/v1/u-verdin/{path}");
            let _p = server
                .mock("GET", "/t/controller/v1/u-verdin")
                .with_body(format!(
                    r#"{{"_links":{{"{rel}":{{"href":"https://evil.example:8443{path}"}}}}}}"#
                ))
                .create();
            let followed = server
                .mock("GET", path.as_str())
                .match_header("authorization", "GatewayToken tok")
                .with_body(body)
                .create();
            assert!(api.poll("u-verdin").unwrap().action.is_some());
            followed.assert();
        }
    }

    #[test]
    fn helpers_refuse_to_guess_between_chunks() {
        let chunk = |v: &str| Chunk {
            version: v.into(),
            artifacts: vec![],
        };
        let d = DeploymentBase {
            id: "5".into(),
            deployment: Deployment {
                download: Handling::Forced,
                update: Handling::Forced,
                maintenance_window: None,
                chunks: vec![chunk("os-1"), chunk("app-2")],
            },
        };
        assert_eq!((d.version(), d.bundle_url("")), (None, None));
    }

    #[test]
    fn bundle_url_picks_the_one_file_with_the_suffix() {
        let artifact = |name: &str| Artifact {
            filename: name.into(),
            size: 1,
            hashes: Hashes {
                sha1: "s".into(),
                md5: "m".into(),
                sha256: None,
            },
            links: ArtifactLinks {
                download: Some(Link {
                    href: format!("https://h/{name}"),
                }),
                download_http: None,
            },
        };
        let with = |names: &[&str]| DeploymentBase {
            id: "5".into(),
            deployment: Deployment {
                download: Handling::Forced,
                update: Handling::Forced,
                maintenance_window: None,
                chunks: vec![Chunk {
                    version: "1".into(),
                    artifacts: names.iter().map(|n| artifact(n)).collect(),
                }],
            },
        };
        let url = |names: &[&str]| with(names).bundle_url(".raucb").map(str::to_owned);
        assert_eq!(
            url(&["notes.txt", "b.raucb", "b.raucb.sig"]).as_deref(),
            Some("https://h/b.raucb")
        );
        assert_eq!(url(&["a.raucb", "b.raucb"]), None);
        assert_eq!(url(&["b.raucb.sig"]), None);
    }

    #[test]
    fn token_debug_hides_the_secret() {
        let debug = format!("{:?}", Token::TargetToken("tok".into()));
        assert_eq!(debug, "TargetToken(***)");
    }

    #[test]
    fn poll_maps_unauthorized() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/t/controller/v1/u-verdin")
            .with_status(401)
            .create();
        let api = DdiClient::new(&server.url(), "t", Token::GatewayToken("tok".into()));
        assert!(matches!(
            api.poll("u-verdin"),
            Err(ureq::Error::StatusCode(401))
        ));
    }

    #[test]
    fn feedback_posts_status() {
        let mut server = Server::new();
        let m = server
            .mock(
                "POST",
                "/t/controller/v1/u-jetson/deploymentBase/5/feedback",
            )
            .match_header("authorization", "TargetToken tok")
            .match_body(Matcher::Json(serde_json::json!({
                "status": {
                    "execution": "closed",
                    "result": { "finished": "failure" },
                    "details": ["rolled back"],
                }
            })))
            .with_status(200)
            .create();
        let api = DdiClient::new(&server.url(), "t", Token::TargetToken("tok".into()));
        api.feedback(
            "u-jetson",
            "5",
            Execution::Closed,
            Finished::Failure,
            &["rolled back"],
        )
        .unwrap();
        m.assert();
    }

    #[test]
    fn progress_posts_percent_on_a_proceeding_action() {
        let mut server = Server::new();
        let m = server
            .mock(
                "POST",
                "/t/controller/v1/u-jetson/deploymentBase/5/feedback",
            )
            .match_body(Matcher::Json(serde_json::json!({
                "status": {
                    "execution": "proceeding",
                    "result": { "finished": "none", "progress": { "cnt": 40, "of": 100 } },
                    "details": ["Copying image to rootfs.1"],
                }
            })))
            .create();
        let api = DdiClient::new(&server.url(), "t", Token::TargetToken("tok".into()));
        api.progress("u-jetson", "5", 40, "Copying image to rootfs.1")
            .unwrap();
        m.assert();
    }
}
