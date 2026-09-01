//! Minimal blocking HTTP/TLS client for the v1 Keyit relay API.

use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;

use keyit_protocol::ids::{DeviceId, EnvironmentId, ProjectId};
use keyit_protocol::primitives::Timestamp;
use keyit_protocol::signing::SigningKeyPair;
use keyit_relay::{
    AccessRecordKind, HttpMethod, RelayAuthorizationEnvelope, RelayRequestSigningInput,
    RelayRevisionEnvelope, RelaySignedRequestEnvelope,
};

use crate::error::CliError;

/// Result of checking the public relay health/readiness endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCheckOutcome {
    pub relay_url: String,
    pub health_status: u16,
    pub readiness_status: u16,
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHttpClient {
    endpoint: RelayEndpoint,
}

impl RelayHttpClient {
    pub fn new(url: &str) -> Result<Self, CliError> {
        Ok(Self {
            endpoint: RelayEndpoint::parse(url)?,
        })
    }

    pub fn check(&self) -> Result<RelayCheckOutcome, CliError> {
        let health = send_get(&self.endpoint.url_for_path("/healthz"))?;
        let readiness = send_get(&self.endpoint.url_for_path("/readyz"))?;
        Ok(RelayCheckOutcome {
            relay_url: self.endpoint.base_url(),
            health_status: health.status,
            readiness_status: readiness.status,
            ready: health.status == 200 && readiness.status == 200,
        })
    }

    pub fn publish_revision_checked(
        &self,
        envelope: RelayRevisionEnvelope,
        authorization: RelayAuthorizationEnvelope,
        device_id: DeviceId,
        signing_keypair: &SigningKeyPair,
        now: Timestamp,
    ) -> Result<(), CliError> {
        let path = format!(
            "/v1/projects/{}/environments/{}/revisions/{}",
            envelope.project_id, envelope.environment_id, envelope.revision_id
        );
        let response = self.send_signed(SignedHttpRequest {
            method: HttpMethod::Put,
            path: &path,
            payload: envelope.encode(),
            authorization,
            device_id,
            signing_keypair,
            now,
        })?;
        match response.status {
            201 => Ok(()),
            409 => Err(CliError::RevisionConflict {
                reason: String::from_utf8_lossy(&response.body).into_owned(),
            }),
            status => Err(CliError::RelayHttp {
                reason: format!(
                    "PUT {path} returned HTTP {status}: {}",
                    String::from_utf8_lossy(&response.body)
                ),
            }),
        }
    }

    pub fn fetch_latest_revision(
        &self,
        project_id: &ProjectId,
        environment_id: &EnvironmentId,
        authorization: RelayAuthorizationEnvelope,
        device_id: DeviceId,
        signing_keypair: &SigningKeyPair,
        now: Timestamp,
    ) -> Result<Option<RelayRevisionEnvelope>, CliError> {
        let path =
            format!("/v1/projects/{project_id}/environments/{environment_id}/revisions/latest");
        let response = self.send_signed(SignedHttpRequest {
            method: HttpMethod::Get,
            path: &path,
            payload: Vec::new(),
            authorization,
            device_id,
            signing_keypair,
            now,
        })?;
        match response.status {
            200 => RelayRevisionEnvelope::decode(&response.body)
                .map(Some)
                .map_err(|reason| CliError::RelayHttp { reason }),
            404 => Ok(None),
            status => Err(CliError::RelayHttp {
                reason: format!(
                    "GET {path} returned HTTP {status}: {}",
                    String::from_utf8_lossy(&response.body)
                ),
            }),
        }
    }

    pub fn publish_access_record(
        &self,
        project_id: &ProjectId,
        kind: AccessRecordKind,
        object_id: &str,
        record: &[u8],
    ) -> Result<(), CliError> {
        let path = format!(
            "/v1/projects/{}/access/{}/{}",
            project_id,
            kind.as_str(),
            object_id
        );
        let response = send_raw_request("PUT", &self.endpoint.url_for_path(&path), record)?;
        match response.status {
            201 => Ok(()),
            409 if kind == AccessRecordKind::JoinRequest => Err(CliError::InviteNotUsable {
                reason: String::from_utf8_lossy(&response.body).into_owned(),
            }),
            status => Err(CliError::RelayHttp {
                reason: format!(
                    "PUT {path} returned HTTP {status}: {}",
                    String::from_utf8_lossy(&response.body)
                ),
            }),
        }
    }

    pub fn fetch_access_record(
        &self,
        project_id: &ProjectId,
        kind: AccessRecordKind,
        object_id: &str,
    ) -> Result<Option<Vec<u8>>, CliError> {
        let path = format!(
            "/v1/projects/{}/access/{}/{}",
            project_id,
            kind.as_str(),
            object_id
        );
        let response = send_get(&self.endpoint.url_for_path(&path))?;
        match response.status {
            200 => Ok(Some(response.body)),
            404 => Ok(None),
            status => Err(CliError::RelayHttp {
                reason: format!(
                    "GET {path} returned HTTP {status}: {}",
                    String::from_utf8_lossy(&response.body)
                ),
            }),
        }
    }

    fn send_signed(&self, request: SignedHttpRequest<'_>) -> Result<HttpResponse, CliError> {
        let signed = RelaySignedRequestEnvelope::sign(RelayRequestSigningInput {
            method: request.method,
            path: request.path,
            payload: request.payload,
            authorization: request.authorization,
            device_id: request.device_id,
            signing_keypair: request.signing_keypair,
            created_at: request.now,
            nonce: random_nonce()?,
        });
        let body = signed.encode();
        send_request(
            method_string(request.method),
            &self.endpoint.url_for_path(request.path),
            &body,
        )
    }
}

#[derive(Debug)]
struct SignedHttpRequest<'a> {
    method: HttpMethod,
    path: &'a str,
    payload: Vec<u8>,
    authorization: RelayAuthorizationEnvelope,
    device_id: DeviceId,
    signing_keypair: &'a SigningKeyPair,
    now: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayEndpoint {
    scheme: RelayScheme,
    host: String,
    port: u16,
}

impl RelayEndpoint {
    fn parse(url: &str) -> Result<Self, CliError> {
        let (scheme, rest) = if let Some(rest) = url.strip_prefix("http://") {
            (RelayScheme::Http, rest)
        } else if let Some(rest) = url.strip_prefix("https://") {
            (RelayScheme::Https, rest)
        } else {
            return Err(CliError::RelayHttp {
                reason: format!("only http:// and https:// relay URLs are supported, got {url}"),
            });
        };
        let authority = rest.split('/').next().unwrap_or(rest);
        if authority.is_empty() {
            return Err(CliError::RelayHttp {
                reason: "relay URL is missing a host".to_string(),
            });
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (
                host.to_string(),
                port.parse::<u16>().map_err(|e| CliError::RelayHttp {
                    reason: format!("relay URL has an invalid port: {e}"),
                })?,
            ),
            None => (authority.to_string(), scheme.default_port()),
        };
        Ok(Self { scheme, host, port })
    }

    fn url_for_path(&self, path: &str) -> String {
        format!("{}{}", self.base_url(), path)
    }

    fn base_url(&self) -> String {
        if self.port == self.scheme.default_port() {
            format!("{}://{}", self.scheme.as_str(), self.host)
        } else {
            format!("{}://{}:{}", self.scheme.as_str(), self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayScheme {
    Http,
    Https,
}

impl RelayScheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

/// Shared HTTP agent for relay requests.
///
/// `ureq`'s bare `ureq::get`/`ureq::request` helpers use a default agent with
/// no request timeout, so a stalled relay connection can hang indefinitely.
/// This agent bounds connect and overall request time so relay calls (and
/// anything that shells out to them, such as
/// `scripts/verify-release-candidate.sh`) fail with a clear error instead of
/// appearing stuck.
fn relay_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
    })
}

fn send_get(url: &str) -> Result<HttpResponse, CliError> {
    let response = match relay_agent().get(url).set("Accept", "text/plain").call() {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(err) => {
            return Err(CliError::RelayHttp {
                reason: relay_request_failure_reason(url, &err),
            });
        }
    };
    let status = response.status();
    read_response_body(status, response.into_reader())
}

fn send_request(method: &str, url: &str, body: &[u8]) -> Result<HttpResponse, CliError> {
    let response = match relay_agent()
        .request(method, url)
        .set("Content-Type", "application/octet-stream")
        .set("Accept", "application/octet-stream")
        .send_bytes(body)
    {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(err) => {
            return Err(CliError::RelayHttp {
                reason: relay_request_failure_reason(url, &err),
            });
        }
    };
    let status = response.status();
    read_response_body(status, response.into_reader())
}

fn send_raw_request(method: &str, url: &str, body: &[u8]) -> Result<HttpResponse, CliError> {
    let response = match relay_agent()
        .request(method, url)
        .set("Content-Type", "application/octet-stream")
        .set("Accept", "application/octet-stream")
        .send_bytes(body)
    {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(err) => {
            return Err(CliError::RelayHttp {
                reason: relay_request_failure_reason(url, &err),
            });
        }
    };
    let status = response.status();
    read_response_body(status, response.into_reader())
}

fn relay_request_failure_reason(url: &str, err: impl std::fmt::Display) -> String {
    format!(
        "could not reach relay at {url}: {err}. Run `keyit relay check` to verify the hosted relay, or pass `--relay-url <url>` for another relay"
    )
}

fn read_response_body(status: u16, stream: impl Read) -> Result<HttpResponse, CliError> {
    let mut bytes = Vec::new();
    stream
        .take(10 * 1024 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|e| CliError::RelayHttp {
            reason: format!("could not read relay response: {e}"),
        })?;
    Ok(HttpResponse {
        status,
        body: bytes,
    })
}

fn random_nonce() -> Result<Vec<u8>, CliError> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|e| CliError::RelayHttp {
        reason: format!("could not generate relay request nonce: {e}"),
    })?;
    Ok(nonce.to_vec())
}

fn method_string(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Put => "PUT",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_local_relay_url() {
        let client = RelayHttpClient::new("http://127.0.0.1:3456").expect("client");
        assert_eq!(client.endpoint.scheme, RelayScheme::Http);
        assert_eq!(client.endpoint.host, "127.0.0.1");
        assert_eq!(client.endpoint.port, 3456);
    }

    #[test]
    fn parses_hosted_https_relay_url() {
        let client = RelayHttpClient::new("https://relay.keyit.sh").expect("client");
        assert_eq!(client.endpoint.scheme, RelayScheme::Https);
        assert_eq!(client.endpoint.host, "relay.keyit.sh");
        assert_eq!(client.endpoint.port, 443);
        assert_eq!(client.endpoint.base_url(), "https://relay.keyit.sh");
        assert_eq!(
            client.endpoint.url_for_path("/healthz"),
            "https://relay.keyit.sh/healthz"
        );
    }

    #[test]
    fn hosted_relay_with_explicit_default_port_has_canonical_base_url() {
        let client = RelayHttpClient::new("https://relay.keyit.sh:443").expect("client");
        assert_eq!(client.endpoint.base_url(), "https://relay.keyit.sh");
    }

    #[test]
    fn relay_request_failure_reason_includes_next_step() {
        let reason = relay_request_failure_reason(
            "https://relay.keyit.sh/readyz",
            "synthetic transport failure",
        );

        assert!(reason.contains("could not reach relay"));
        assert!(reason.contains("keyit relay check"));
        assert!(reason.contains("--relay-url <url>"));
    }
}
