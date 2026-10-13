use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

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
    /// Item count Carbonio reports for this folder (`n` in `GetFolderResponse`).
    pub item_count: u32,
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
            item_count: node.n,
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
    n: u32,
    #[serde(default)]
    folder: Vec<RawFolder>,
}

/// One email message, as returned by `SearchRequest` and trimmed to the
/// fields the `Sync` command's Email codepage currently emits.
#[derive(Debug, Clone, PartialEq)]
pub struct CarbonioMessage {
    pub id: String,
    pub subject: String,
    pub from: Option<String>,
    pub to: Vec<String>,
    /// Milliseconds since the Unix epoch, as Zimbra/Carbonio reports it.
    pub date_epoch_ms: i64,
    pub unread: bool,
}

impl CarbonioClient {
    /// Lists up to `limit` messages in `folder_id`, newest first, via
    /// `SearchRequest` (`urn:zimbraMail`) with query `inid:<folder_id>`.
    pub async fn search_messages(&self, folder_id: &str, limit: u32) -> Result<Vec<CarbonioMessage>> {
        let token = self
            .auth_token
            .as_deref()
            .context("search_messages called before authenticate")?;

        let request_body = json!({
            "Body": {
                "SearchRequest": {
                    "_jsns": "urn:zimbraMail",
                    "types": "message",
                    "query": { "_content": format!("inid:{folder_id}") },
                    "sortBy": "dateDesc",
                    "limit": limit
                }
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
            .context("SearchRequest failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<SearchBody> = response
            .json()
            .await
            .context("SearchRequest response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio SearchRequest failed ({code}): {}", fault.reason.text);
        }

        let raw_messages = envelope
            .body
            .search_response
            .context("SearchResponse missing from a non-fault SOAP reply")?
            .m;

        Ok(raw_messages.into_iter().map(RawMessage::into_carbonio_message).collect())
    }

    /// Sends a plain-text email via `SendMsgRequest` (`urn:zimbraMail`).
    /// Does not support HTML bodies or attachments yet; `to`/`cc` are the
    /// raw address strings as parsed from the device's RFC 822 headers.
    pub async fn send_message(&self, to: &[String], cc: &[String], subject: &str, body: &str) -> Result<()> {
        let token = self
            .auth_token
            .as_deref()
            .context("send_message called before authenticate")?;

        let mut participants: Vec<_> = to.iter().map(|addr| json!({ "t": "t", "a": addr })).collect();
        participants.extend(cc.iter().map(|addr| json!({ "t": "c", "a": addr })));

        let request_body = json!({
            "Body": {
                "SendMsgRequest": {
                    "_jsns": "urn:zimbraMail",
                    "m": {
                        "su": { "_content": subject },
                        "e": participants,
                        "mp": {
                            "ct": "text/plain",
                            "content": { "_content": body }
                        }
                    }
                }
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
            .context("SendMsgRequest failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<SendMsgBody> = response
            .json()
            .await
            .context("SendMsgRequest response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio SendMsgRequest failed ({code}): {}", fault.reason.text);
        }

        Ok(())
    }

    /// Lists up to `limit` contacts in `folder_id`, via `SearchRequest`
    /// (`urn:zimbraMail`) with `types=contact`. Only the fields a basic
    /// ActiveSync contact needs are extracted from `_attrs`; anything else
    /// Carbonio stores on the contact (addresses, notes, a photo, etc.) is
    /// dropped.
    pub async fn search_contacts(&self, folder_id: &str, limit: u32) -> Result<Vec<CarbonioContact>> {
        let token = self
            .auth_token
            .as_deref()
            .context("search_contacts called before authenticate")?;

        let request_body = json!({
            "Body": {
                "SearchRequest": {
                    "_jsns": "urn:zimbraMail",
                    "types": "contact",
                    "query": { "_content": format!("inid:{folder_id}") },
                    "limit": limit
                }
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
            .context("SearchRequest (contacts) failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<SearchContactsBody> = response
            .json()
            .await
            .context("SearchRequest (contacts) response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio SearchRequest (contacts) failed ({code}): {}", fault.reason.text);
        }

        let raw_contacts = envelope
            .body
            .search_response
            .context("SearchResponse missing from a non-fault SOAP reply")?
            .cn;

        Ok(raw_contacts.into_iter().map(RawContact::into_carbonio_contact).collect())
    }

    /// Lists up to `limit` calendar events in `folder_id`, via
    /// `SearchRequest` (`urn:zimbraMail`) with `types=appointment`. Only
    /// the first occurrence (`inst[0]`) of a recurring event is used;
    /// recurrence rules themselves are not synced (a recurring event shows
    /// up as a single one-off event on the first occurrence's date).
    pub async fn search_appointments(&self, folder_id: &str, limit: u32) -> Result<Vec<CarbonioAppointment>> {
        let token = self
            .auth_token
            .as_deref()
            .context("search_appointments called before authenticate")?;

        let request_body = json!({
            "Body": {
                "SearchRequest": {
                    "_jsns": "urn:zimbraMail",
                    "types": "appointment",
                    "query": { "_content": format!("inid:{folder_id}") },
                    "limit": limit
                }
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
            .context("SearchRequest (appointments) failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<SearchApptBody> = response
            .json()
            .await
            .context("SearchRequest (appointments) response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio SearchRequest (appointments) failed ({code}): {}", fault.reason.text);
        }

        let raw_appts = envelope
            .body
            .search_response
            .context("SearchResponse missing from a non-fault SOAP reply")?
            .appt;

        Ok(raw_appts.into_iter().map(RawAppointment::into_carbonio_appointment).collect())
    }

    /// Fetches a message's plain-text body via `GetMsgRequest`
    /// (`urn:zimbraMail`). Returns the first MIME part marked `body: true`
    /// with a `text/plain` content type; HTML-only messages and messages
    /// with no plain-text part return an empty string rather than an error.
    pub async fn get_message_body(&self, message_id: &str) -> Result<String> {
        let token = self
            .auth_token
            .as_deref()
            .context("get_message_body called before authenticate")?;

        let request_body = json!({
            "Body": {
                "GetMsgRequest": {
                    "_jsns": "urn:zimbraMail",
                    "m": { "id": message_id }
                }
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
            .context("GetMsgRequest failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<GetMsgBody> = response
            .json()
            .await
            .context("GetMsgRequest response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio GetMsgRequest failed ({code}): {}", fault.reason.text);
        }

        let message = envelope
            .body
            .get_msg_response
            .context("GetMsgResponse missing from a non-fault SOAP reply")?
            .m
            .into_iter()
            .next()
            .context("GetMsgResponse had no message")?;

        Ok(message
            .mp
            .into_iter()
            .find(|part| part.body && part.ct == "text/plain")
            .map(|part| part.content)
            .unwrap_or_default())
    }
}

#[derive(Debug, Deserialize)]
struct GetMsgBody {
    #[serde(rename = "GetMsgResponse")]
    get_msg_response: Option<GetMsgResponse>,
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

#[derive(Debug, Deserialize)]
struct GetMsgResponse {
    #[serde(default)]
    m: Vec<RawFullMessage>,
}

#[derive(Debug, Deserialize)]
struct RawFullMessage {
    #[serde(default)]
    mp: Vec<RawMimePart>,
}

#[derive(Debug, Deserialize)]
struct RawMimePart {
    ct: String,
    #[serde(default)]
    body: bool,
    #[serde(default)]
    content: String,
}

#[derive(Debug, Deserialize)]
struct SendMsgBody {
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

/// One calendar event, trimmed to the fields the Calendar codepage
/// currently emits. Does not carry attendees, recurrence, or reminders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarbonioAppointment {
    pub id: String,
    pub subject: String,
    pub location: String,
    pub start_epoch_ms: i64,
    pub end_epoch_ms: i64,
    pub all_day: bool,
}

#[derive(Debug, Deserialize)]
struct SearchApptBody {
    #[serde(rename = "SearchResponse")]
    search_response: Option<SearchApptResponse>,
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

#[derive(Debug, Deserialize)]
struct SearchApptResponse {
    #[serde(default)]
    appt: Vec<RawAppointment>,
}

#[derive(Debug, Deserialize)]
struct RawAppointment {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    loc: String,
    /// Duration in milliseconds.
    #[serde(default)]
    dur: i64,
    #[serde(default, rename = "allDay")]
    all_day: bool,
    #[serde(default)]
    inst: Vec<RawInstance>,
}

#[derive(Debug, Deserialize)]
struct RawInstance {
    /// Occurrence start time, milliseconds since the Unix epoch.
    s: i64,
}

impl RawAppointment {
    fn into_carbonio_appointment(self) -> CarbonioAppointment {
        let start_epoch_ms = self.inst.first().map(|i| i.s).unwrap_or(0);
        CarbonioAppointment {
            id: self.id,
            subject: self.name,
            location: self.loc,
            start_epoch_ms,
            end_epoch_ms: start_epoch_ms + self.dur,
            all_day: self.all_day,
        }
    }
}

/// One contact, trimmed to the fields the Contacts codepage currently emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarbonioContact {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub mobile_phone: String,
}

#[derive(Debug, Deserialize)]
struct SearchContactsBody {
    #[serde(rename = "SearchResponse")]
    search_response: Option<SearchContactsResponse>,
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

#[derive(Debug, Deserialize)]
struct SearchContactsResponse {
    #[serde(default)]
    cn: Vec<RawContact>,
}

#[derive(Debug, Deserialize)]
struct RawContact {
    id: String,
    #[serde(default)]
    _attrs: HashMap<String, String>,
}

impl RawContact {
    fn into_carbonio_contact(self) -> CarbonioContact {
        let get = |key: &str| self._attrs.get(key).cloned().unwrap_or_default();
        CarbonioContact {
            id: self.id,
            first_name: get("firstName"),
            last_name: get("lastName"),
            email: get("email"),
            mobile_phone: get("mobilePhone"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct SearchBody {
    #[serde(rename = "SearchResponse")]
    search_response: Option<SearchResponse>,
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    #[serde(default)]
    m: Vec<RawMessage>,
}

#[derive(Debug, Deserialize)]
struct RawMessage {
    id: String,
    su: Option<ContentField>,
    /// Date in milliseconds since the Unix epoch.
    d: Option<i64>,
    /// Flag string; Zimbra/Carbonio uses 'u' for unread among others.
    f: Option<String>,
    #[serde(default)]
    e: Vec<RawEmailAddr>,
}

#[derive(Debug, Deserialize)]
struct RawEmailAddr {
    a: String,
    t: Option<String>,
}

impl RawMessage {
    fn into_carbonio_message(self) -> CarbonioMessage {
        let from = self.e.iter().find(|addr| addr.t.as_deref() == Some("f")).map(|addr| addr.a.clone());
        let to = self
            .e
            .iter()
            .filter(|addr| addr.t.as_deref() == Some("t"))
            .map(|addr| addr.a.clone())
            .collect();
        CarbonioMessage {
            id: self.id,
            subject: self.su.map(|s| s.content).unwrap_or_default(),
            from,
            to,
            date_epoch_ms: self.d.unwrap_or(0),
            unread: self.f.as_deref().is_some_and(|flags| flags.contains('u')),
        }
    }
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
                                "n": 5,
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
                    item_count: 5,
                },
                CarbonioFolder {
                    id: "6".into(),
                    parent_id: Some("2".into()),
                    name: "Sub".into(),
                    view: Some("message".into()),
                    item_count: 0,
                },
                CarbonioFolder {
                    id: "10".into(),
                    parent_id: Some("1".into()),
                    name: "Calendar".into(),
                    view: Some("appointment".into()),
                    item_count: 0,
                },
            ]
        );
    }

    #[test]
    fn search_response_maps_sender_recipients_and_unread_flag() {
        // Shape matches a real SearchRequest hit: one unread message from
        // alice to bob and carol.
        let raw = r#"{
            "Body": {
                "SearchResponse": {
                    "m": [{
                        "id": "123",
                        "su": {"_content": "Weekly report"},
                        "d": 1760000000000,
                        "f": "u",
                        "e": [
                            {"a": "alice@afatyo.com", "t": "f"},
                            {"a": "bob@afatyo.com", "t": "t"},
                            {"a": "carol@afatyo.com", "t": "t"}
                        ]
                    }]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;

        let envelope: SoapEnvelope<SearchBody> = serde_json::from_str(raw).unwrap();
        let raw_messages = envelope.body.search_response.unwrap().m;
        let messages: Vec<CarbonioMessage> =
            raw_messages.into_iter().map(RawMessage::into_carbonio_message).collect();

        assert_eq!(
            messages,
            vec![CarbonioMessage {
                id: "123".into(),
                subject: "Weekly report".into(),
                from: Some("alice@afatyo.com".into()),
                to: vec!["bob@afatyo.com".into(), "carol@afatyo.com".into()],
                date_epoch_ms: 1760000000000,
                unread: true,
            }]
        );
    }

    #[test]
    fn search_response_without_flags_is_read() {
        let raw = r#"{
            "Body": {
                "SearchResponse": {
                    "m": [{"id": "1", "su": {"_content": "Hi"}, "d": 1, "e": []}]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SearchBody> = serde_json::from_str(raw).unwrap();
        let raw_messages = envelope.body.search_response.unwrap().m;
        let messages: Vec<CarbonioMessage> =
            raw_messages.into_iter().map(RawMessage::into_carbonio_message).collect();
        assert!(!messages[0].unread);
    }

    #[test]
    fn search_contacts_response_maps_known_attrs() {
        // Shape matches a real CreateContactRequest/SearchRequest hit,
        // captured live from Carbonio CE 4.5.14.
        let raw = r#"{
            "Body": {
                "SearchResponse": {
                    "cn": [{
                        "id": "262",
                        "l": "7",
                        "fileAsStr": "Santoso, Budi",
                        "_attrs": {
                            "firstName": "Budi",
                            "lastName": "Santoso",
                            "mobilePhone": "08123456789",
                            "email": "budi@afatyo.com"
                        }
                    }]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;

        let envelope: SoapEnvelope<SearchContactsBody> = serde_json::from_str(raw).unwrap();
        let raw_contacts = envelope.body.search_response.unwrap().cn;
        let contacts: Vec<CarbonioContact> =
            raw_contacts.into_iter().map(RawContact::into_carbonio_contact).collect();

        assert_eq!(
            contacts,
            vec![CarbonioContact {
                id: "262".into(),
                first_name: "Budi".into(),
                last_name: "Santoso".into(),
                email: "budi@afatyo.com".into(),
                mobile_phone: "08123456789".into(),
            }]
        );
    }

    #[test]
    fn contact_missing_attrs_defaults_to_empty_strings() {
        let raw = r#"{
            "Body": {
                "SearchResponse": { "cn": [{"id": "1", "l": "7"}] }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SearchContactsBody> = serde_json::from_str(raw).unwrap();
        let raw_contacts = envelope.body.search_response.unwrap().cn;
        let contacts: Vec<CarbonioContact> =
            raw_contacts.into_iter().map(RawContact::into_carbonio_contact).collect();
        assert_eq!(contacts[0].first_name, "");
    }

    #[test]
    fn search_appointments_response_maps_subject_location_and_computes_end_time() {
        // Shape matches a real CreateAppointmentRequest/SearchRequest hit,
        // captured live from Carbonio CE 4.5.14: a 1-hour meeting starting
        // at inst[0].s with duration `dur` in milliseconds.
        let raw = r#"{
            "Body": {
                "SearchResponse": {
                    "appt": [{
                        "id": "264",
                        "name": "Team Sync Meeting",
                        "loc": "Zoom",
                        "dur": 3600000,
                        "allDay": false,
                        "inst": [{"s": 1792512000000}]
                    }]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;

        let envelope: SoapEnvelope<SearchApptBody> = serde_json::from_str(raw).unwrap();
        let raw_appts = envelope.body.search_response.unwrap().appt;
        let appointments: Vec<CarbonioAppointment> =
            raw_appts.into_iter().map(RawAppointment::into_carbonio_appointment).collect();

        assert_eq!(
            appointments,
            vec![CarbonioAppointment {
                id: "264".into(),
                subject: "Team Sync Meeting".into(),
                location: "Zoom".into(),
                start_epoch_ms: 1792512000000,
                end_epoch_ms: 1792515600000,
                all_day: false,
            }]
        );
    }

    #[test]
    fn appointment_with_no_instances_defaults_start_to_zero() {
        let raw = r#"{
            "Body": {
                "SearchResponse": { "appt": [{"id": "1", "name": "X", "dur": 1000}] }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SearchApptBody> = serde_json::from_str(raw).unwrap();
        let raw_appts = envelope.body.search_response.unwrap().appt;
        let appointments: Vec<CarbonioAppointment> =
            raw_appts.into_iter().map(RawAppointment::into_carbonio_appointment).collect();
        assert_eq!(appointments[0].start_epoch_ms, 0);
        assert_eq!(appointments[0].end_epoch_ms, 1000);
    }

    #[test]
    fn get_msg_response_extracts_the_plain_text_body_part() {
        // Shape matches a real GetMsgRequest hit, captured live from
        // Carbonio CE 4.5.14 for a plain-text message.
        let raw = r#"{
            "Body": {
                "GetMsgResponse": {
                    "m": [{
                        "mp": [{
                            "part": "1",
                            "ct": "text/plain",
                            "body": true,
                            "content": "Hello body text"
                        }]
                    }]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<GetMsgBody> = serde_json::from_str(raw).unwrap();
        let message = envelope.body.get_msg_response.unwrap().m.into_iter().next().unwrap();
        let body = message.mp.into_iter().find(|p| p.body && p.ct == "text/plain").map(|p| p.content);
        assert_eq!(body, Some("Hello body text".to_string()));
    }

    #[test]
    fn get_msg_response_with_no_plain_text_part_has_no_body() {
        let raw = r#"{
            "Body": {
                "GetMsgResponse": {
                    "m": [{"mp": [{"part": "1", "ct": "text/html", "body": true, "content": "<p>hi</p>"}]}]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<GetMsgBody> = serde_json::from_str(raw).unwrap();
        let message = envelope.body.get_msg_response.unwrap().m.into_iter().next().unwrap();
        let body = message.mp.into_iter().find(|p| p.body && p.ct == "text/plain").map(|p| p.content);
        assert_eq!(body, None);
    }
}
