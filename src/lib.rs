//! Blocking client for the [Eclipse hawkBit](https://eclipse.dev/hawkbit/) Direct Device
//! Integration (DDI) API, authenticating with a tenant-wide `GatewayToken` or a device-specific
//! `TargetToken`.
//!
//! ```no_run
//! use hawkbit_ddi::{DdiClient, Execution, Finished, Token};
//!
//! let client = DdiClient::new(
//!     "https://hawkbit.example.com",
//!     "DEFAULT",
//!     Token::TargetToken("secret".into()),
//! );
//! if let Some(deployment) = client.pending("my-device")? {
//!     println!("update to {:?} from {:?}", deployment.version(), deployment.bundle_url());
//!     client.feedback("my-device", &deployment.id, Execution::Closed, Finished::Success, &[])?;
//! }
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

/// The software modules of a deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    /// One chunk per software module.
    pub chunks: Vec<Chunk>,
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
    /// Download links of the artifact.
    #[serde(rename = "_links")]
    pub links: ArtifactLinks,
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
    /// Download URL of the first artifact, preferring https.
    #[must_use]
    pub fn bundle_url(&self) -> Option<&str> {
        let links = &self.deployment.chunks.first()?.artifacts.first()?.links;
        links
            .download
            .as_ref()
            .or(links.download_http.as_ref())
            .map(|l| l.href.as_str())
    }

    /// Version of the first chunk.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        Some(&self.deployment.chunks.first()?.version)
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

    /// `href` from the server, if it points below `base_url`, so the token never goes to another
    /// host or over plain http.
    fn trusted<'a>(&self, href: &'a str) -> Result<&'a str, ureq::Error> {
        match href.strip_prefix(&self.base_url) {
            Some(rest) if rest.starts_with('/') => Ok(href),
            _ => Err(ureq::Error::BadUri(format!(
                "hawkBit link {href} is outside {}",
                self.base_url
            ))),
        }
    }

    fn feedback_url(&self, controller_id: &str, action_id: &str) -> String {
        format!(
            "{}/{}/controller/v1/{controller_id}/deploymentBase/{action_id}/feedback",
            self.base_url, self.tenant
        )
    }

    /// The pending deployment for this controller, if any. A cancel request is accepted first, since
    /// hawkBit holds back newer actions until it is; the next poll then sees them. Links from the
    /// server must point below `base_url`, or this returns [`ureq::Error::BadUri`].
    pub fn pending(&self, controller_id: &str) -> Result<Option<DeploymentBase>, ureq::Error> {
        let url = format!(
            "{}/{}/controller/v1/{controller_id}",
            self.base_url, self.tenant
        );
        let poll: serde_json::Value = self.get_json(&url)?;
        self.report_attributes(controller_id, poll.pointer("/_links/configData").is_some());
        if let Some(href) = poll
            .pointer("/_links/cancelAction/href")
            .and_then(serde_json::Value::as_str)
        {
            tracing::info!(href, "accepting hawkBit cancel");
            self.post_status(
                &format!("{}/feedback", self.trusted(href)?),
                Execution::Closed,
                Finished::Success,
                &["cancelled"],
                None,
            )?;
            return Ok(None);
        }
        poll.pointer("/_links/deploymentBase/href")
            .and_then(serde_json::Value::as_str)
            .map(|href| self.get_json(self.trusted(href)?))
            .transpose()
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
        self.post_status(
            &self.feedback_url(controller_id, action_id),
            execution,
            finished,
            details,
            None,
        )
    }

    /// Reports `percent` done on this controller's still-running action `action_id`.
    pub fn progress(
        &self,
        controller_id: &str,
        action_id: &str,
        percent: u32,
        detail: &str,
    ) -> Result<(), ureq::Error> {
        self.post_status(
            &self.feedback_url(controller_id, action_id),
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
        let url = format!(
            "{}/{}/controller/v1/{controller_id}/configData",
            self.base_url, self.tenant
        );
        match self.put_attributes(&url) {
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
    fn pending_follows_the_deployment_link() {
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
                r#"{"id":"5","deployment":{"download":"forced","update":"forced","chunks":[
                    {"part":"os","name":"jetson","version":"20261030-abc1234","artifacts":[
                        {"filename":"b.raucb","size":3,"hashes":{"sha256":"x"},"_links":{
                            "download":{"href":"https://h/b.raucb"},
                            "download-http":{"href":"http://h/b.raucb"}}}]}]}}"#,
            )
            .create();
        let api = DdiClient::new(&server.url(), "t", Token::GatewayToken("tok".into()));
        let d = api.pending("u-jetson").unwrap().unwrap();
        assert_eq!(d.id, "5");
        assert_eq!(d.deployment.chunks[0].version, "20261030-abc1234");
        assert_eq!(d.bundle_url(), Some("https://h/b.raucb"));
    }

    #[test]
    fn pending_without_action_is_none() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/t/controller/v1/u-verdin")
            .with_body(r#"{"config":{"polling":{"sleep":"00:05:00"}},"_links":{}}"#)
            .create();
        let api = DdiClient::new(&server.url(), "t", Token::GatewayToken("tok".into()));
        assert!(api.pending("u-verdin").unwrap().is_none());
    }

    #[test]
    fn pending_accepts_a_cancel() {
        let mut server = Server::new();
        let href = format!("{}/t/controller/v1/u-verdin/cancelAction/27", server.url());
        let _p = server
            .mock("GET", "/t/controller/v1/u-verdin")
            .with_body(format!(
                r#"{{"_links":{{"cancelAction":{{"href":"{href}"}}}}}}"#
            ))
            .create();
        let ack = server
            .mock("POST", "/t/controller/v1/u-verdin/cancelAction/27/feedback")
            .match_header("authorization", "TargetToken tok")
            .match_body(Matcher::PartialJson(serde_json::json!({
                "status": {"execution": "closed", "result": {"finished": "success"}}
            })))
            .create();
        let api = DdiClient::new(&server.url(), "t", Token::TargetToken("tok".into()));
        assert!(api.pending("u-verdin").unwrap().is_none());
        ack.assert();
    }

    #[test]
    fn pending_reports_attributes_once_until_asked_again() {
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
        api.pending("u-verdin").unwrap();
        api.pending("u-verdin").unwrap();
        quiet.assert();
        let href = format!("{}/t/controller/v1/u-verdin/configData", server.url());
        let _asking = server
            .mock("GET", "/t/controller/v1/u-verdin")
            .with_body(poll(&format!(r#""configData":{{"href":"{href}"}}"#)))
            .create();
        api.pending("u-verdin").unwrap();
        put.assert();
    }

    #[test]
    fn pending_refuses_links_outside_base_url() {
        let mut server = Server::new();
        let base = server.url();
        let plain = base.replacen("http://", "ftp://", 1);
        for href in [
            format!("{plain}/t/controller/v1/u-verdin/deploymentBase/5"),
            format!("{base}.evil.com/t/controller/v1/u-verdin/deploymentBase/5"),
        ] {
            let _p = server
                .mock("GET", "/t/controller/v1/u-verdin")
                .with_body(format!(
                    r#"{{"_links":{{"deploymentBase":{{"href":"{href}"}}}}}}"#
                ))
                .create();
            let api = DdiClient::new(&base, "t", Token::GatewayToken("tok".into()));
            assert!(matches!(
                api.pending("u-verdin"),
                Err(ureq::Error::BadUri(_))
            ));
        }
    }

    #[test]
    fn token_debug_hides_the_secret() {
        let debug = format!("{:?}", Token::TargetToken("tok".into()));
        assert_eq!(debug, "TargetToken(***)");
    }

    #[test]
    fn pending_maps_unauthorized() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/t/controller/v1/u-verdin")
            .with_status(401)
            .create();
        let api = DdiClient::new(&server.url(), "t", Token::GatewayToken("tok".into()));
        assert!(matches!(
            api.pending("u-verdin"),
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
