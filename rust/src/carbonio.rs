use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Minimal JSON-SOAP client for Zextras Carbonio CE's `urn:zimbraAccount` /
/// `urn:zimbraMail` namespaces, reachable at `<base_url>/service/soap/`.
pub struct CarbonioClient {
    base_url: String,
    http: reqwest::Client,
    auth_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SoapEnvelope<T> {
    #[serde(rename = "Body")]
    body: T,
}

#[derive(Debug, Deserialize)]
struct AuthBody {
    #[serde(rename = "AuthResponse")]
    auth_response: Option<AuthResponse>,
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    #[serde(rename = "authToken")]
    auth_token: Vec<ContentField>,
}

#[derive(Debug, Deserialize)]
struct ContentField {
    #[serde(rename = "_content")]
    content: String,
}

#[derive(Debug, Deserialize)]
struct SoapFault {
    #[serde(rename = "Reason")]
    reason: FaultReason,
    #[serde(rename = "Detail")]
    detail: Option<FaultDetail>,
}

#[derive(Debug, Deserialize)]
struct FaultReason {
    #[serde(rename = "Text")]
    text: String,
}

#[derive(Debug, Deserialize)]
struct FaultDetail {
    #[serde(rename = "Error")]
    error: FaultError,
}

#[derive(Debug, Deserialize)]
struct FaultError {
    #[serde(rename = "Code")]
    code: String,
}

#[derive(Debug, Serialize)]
struct AccountByName<'a> {
    by: &'a str,
    #[serde(rename = "_content")]
    content: &'a str,
}

impl CarbonioClient {
    /// `base_url` example: "https://192.168.10.2". Uses the system trust
    /// store for TLS validation; use [`Self::new_with_ca`] when Carbonio's
    /// certificate is signed by a private/internal CA.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            base_url: base_url.into(),
            http,
            auth_token: None,
        })
    }

    /// Same as [`Self::new`] but additionally trusts `ca_pem_path` (PEM file)
    /// as a root CA. Carbonio CE ships a self-signed CA by default at
    /// `/opt/zextras/ssl/carbonio/ca/ca.pem` on the mailbox host; copy it
    /// somewhere this process can read and point this at it rather than
    /// disabling certificate validation.
    ///
    /// `dns_override`, if set, pins `(hostname, port)` from `base_url` to a
    /// specific IP for this client, like `curl --resolve`. Carbonio's cert
    /// is typically issued for a hostname (its configured mail server name)
    /// rather than an IP, so when that hostname has no real DNS record this
    /// lets TLS hostname validation still succeed instead of being bypassed.
    pub fn new_with_ca(
        base_url: impl Into<String>,
        ca_pem_path: &str,
        dns_override: Option<(&str, std::net::IpAddr)>,
    ) -> Result<Self> {
        let ca_pem = std::fs::read(ca_pem_path)
            .with_context(|| format!("failed to read CA cert at {ca_pem_path}"))?;
        let ca_cert = reqwest::Certificate::from_pem(&ca_pem)
            .context("CA file was not a valid PEM certificate")?;
        let mut builder = reqwest::Client::builder().add_root_certificate(ca_cert);
        if let Some((host, ip)) = dns_override {
            builder = builder.resolve(host, std::net::SocketAddr::new(ip, 443));
        }
        let http = builder
            .build()
            .context("failed to build HTTP client with custom CA")?;
        Ok(Self {
            base_url: base_url.into(),
            http,
            auth_token: None,
        })
    }

    /// Like [`Self::new_with_ca`], but validates the server's TLS cert by
    /// exact byte match against `pinned_cert_pem_path` instead of building a
    /// CA chain. Use this when Carbonio's self-signed cert has a validity
    /// period rustls/webpki (and macOS's Security.framework) reject as too
    /// long for normal chain validation -- see [`crate::tls_pinning`].
    pub fn new_with_pinned_cert(
        base_url: impl Into<String>,
        pinned_cert_pem_path: &str,
        dns_override: Option<(&str, std::net::IpAddr)>,
    ) -> Result<Self> {
        let verifier = crate::tls_pinning::PinnedCertVerifier::from_pem_file(pinned_cert_pem_path)?;
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        let mut builder = reqwest::Client::builder().use_preconfigured_tls(tls_config);
        if let Some((host, ip)) = dns_override {
            builder = builder.resolve(host, std::net::SocketAddr::new(ip, 443));
        }
        let http = builder
            .build()
            .context("failed to build HTTP client with pinned certificate")?;
        Ok(Self {
            base_url: base_url.into(),
            http,
            auth_token: None,
        })
    }

    fn soap_endpoint(&self) -> String {
        format!("{}/service/soap/", self.base_url.trim_end_matches('/'))
    }

    /// Authenticates against `AuthRequest` (`urn:zimbraAccount`) and stores
    /// the resulting auth token on the client for later requests.
    pub async fn authenticate(&mut self, username: &str, password: &str) -> Result<()> {
        let request_body = json!({
            "Body": {
                "AuthRequest": {
                    "_jsns": "urn:zimbraAccount",
                    "account": AccountByName { by: "name", content: username },
                    "password": { "_content": password },
                }
            },
            "_jsns": "urn:zimbraSoap"
        });

        let response = self
            .http
            .post(self.soap_endpoint())
            .json(&request_body)
            .send()
            .await
            .context("AuthRequest failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<AuthBody> = response
            .json()
            .await
            .context("AuthRequest response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio auth failed ({code}): {}", fault.reason.text);
        }

        let auth_response = envelope
            .body
            .auth_response
            .context("AuthResponse missing from a non-fault SOAP reply")?;

        let token = auth_response
            .auth_token
            .first()
            .context("authToken field was empty")?
            .content
            .clone();

        self.auth_token = Some(token);
        Ok(())
    }

    pub fn auth_token(&self) -> Option<&str> {
        self.auth_token.as_deref()
    }

    /// Flattens the user's mail folder tree via `GetFolderRequest`
    /// (`urn:zimbraMail`) into a flat list, dropping the synthetic root.
    pub async fn get_folders(&self) -> Result<Vec<CarbonioFolder>> {
        let token = self
            .auth_token
            .as_deref()
            .context("get_folders called before authenticate")?;

        let request_body = json!({
            "Body": {
                "GetFolderRequest": { "_jsns": "urn:zimbraMail" }
            },
            "Header": {
                "context": {
                    "_jsns": "urn:zimbra",
                    "authToken": { "_content": token }
                }
            },
            "_jsns": "urn:zimbraSoap"
        });

        let response = self
            .http
            .post(self.soap_endpoint())
            .json(&request_body)
            .send()
            .await
            .context("GetFolderRequest failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<GetFolderBody> = response
            .json()
            .await
            .context("GetFolderRequest response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio GetFolder failed ({code}): {}", fault.reason.text);
        }

        let root = envelope
            .body
            .get_folder_response
            .context("GetFolderResponse missing from a non-fault SOAP reply")?
            .folder
            .into_iter()
            .next()
            .context("GetFolderResponse had no root folder")?;

        let mut flat = Vec::new();
        flatten_folder(&root, None, &mut flat);
        Ok(flat)
    }
}

/// One Carbonio/Zimbra mail folder, flattened from the SOAP tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarbonioFolder {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub view: Option<String>,
}

fn flatten_folder(node: &RawFolder, parent_id: Option<String>, out: &mut Vec<CarbonioFolder>) {
    // The root folder itself ("USER_ROOT") has no meaningful name/view for
    // ActiveSync and is never shown to the device, only its children are.
    if parent_id.is_some() {
        out.push(CarbonioFolder {
            id: node.id.clone(),
            parent_id,
            name: node.name.clone(),
            view: node.view.clone(),
        });
    }
    for child in &node.folder {
        flatten_folder(child, Some(node.id.clone()), out);
    }
}

#[derive(Debug, Deserialize)]
struct GetFolderBody {
    #[serde(rename = "GetFolderResponse")]
    get_folder_response: Option<GetFolderResponse>,
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

#[derive(Debug, Deserialize)]
struct GetFolderResponse {
    folder: Vec<RawFolder>,
}

#[derive(Debug, Deserialize)]
struct RawFolder {
    id: String,
    name: String,
    view: Option<String>,
    #[serde(default)]
    folder: Vec<RawFolder>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soap_endpoint_strips_trailing_slash() {
        let client = CarbonioClient::new("https://192.168.10.2/").unwrap();
        assert_eq!(client.soap_endpoint(), "https://192.168.10.2/service/soap/");
    }

    #[test]
    fn account_by_name_serializes_with_zimbra_shape() {
        let account = AccountByName { by: "name", content: "user@example.com" };
        let value = serde_json::to_value(&account).unwrap();
        assert_eq!(value["by"], "name");
        assert_eq!(value["_content"], "user@example.com");
    }

    #[test]
    fn fault_envelope_parses_auth_required() {
        // Shape matches the live AUTH_REQUIRED fault we captured from
        // Carbonio CE (carbonio-core 4.5.14) at 192.168.10.2 during manual testing.
        let raw = r#"{
            "Body": {
                "Fault": {
                    "Reason": {"Text": "no valid authtoken present"},
                    "Detail": {"Error": {"Code": "service.AUTH_REQUIRED"}}
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<AuthBody> = serde_json::from_str(raw).unwrap();
        let fault = envelope.body.fault.expect("fault should be present");
        assert_eq!(fault.reason.text, "no valid authtoken present");
        assert_eq!(fault.detail.unwrap().error.code, "service.AUTH_REQUIRED");
    }

    #[test]
    fn get_folder_response_flattens_nested_tree_and_drops_root() {
        // Shape matches a real GetFolderResponse: synthetic root (id "1")
        // containing Inbox (id "2") with a "Drafts of Inbox" subfolder (id "6").
        let raw = r#"{
            "Body": {
                "GetFolderResponse": {
                    "folder": [{
                        "id": "1",
                        "name": "USER_ROOT",
                        "folder": [
                            {
                                "id": "2",
                                "name": "Inbox",
                                "view": "message",
                                "folder": [
                                    {"id": "6", "name": "Sub", "view": "message"}
                                ]
                            },
                            {"id": "10", "name": "Calendar", "view": "appointment"}
                        ]
                    }]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;

        let envelope: SoapEnvelope<GetFolderBody> = serde_json::from_str(raw).unwrap();
        let root = envelope.body.get_folder_response.unwrap().folder.into_iter().next().unwrap();
        let mut flat = Vec::new();
        flatten_folder(&root, None, &mut flat);

        assert_eq!(
            flat,
            vec![
                CarbonioFolder {
                    id: "2".into(),
                    parent_id: Some("1".into()),
                    name: "Inbox".into(),
                    view: Some("message".into()),
                },
                CarbonioFolder {
                    id: "6".into(),
                    parent_id: Some("2".into()),
                    name: "Sub".into(),
                    view: Some("message".into()),
                },
                CarbonioFolder {
                    id: "10".into(),
                    parent_id: Some("1".into()),
                    name: "Calendar".into(),
                    view: Some("appointment".into()),
                },
            ]
        );
    }
}
