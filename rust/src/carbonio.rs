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

/// An email to send via [`CarbonioClient::send_message`]. `attachment_aids`
/// are upload ids obtained from [`CarbonioClient::upload_attachment`].
#[derive(Debug, Clone, Default)]
pub struct OutgoingMessage {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub plain_body: String,
    pub html_body: Option<String>,
    pub attachment_aids: Vec<String>,
}

/// Parses Carbonio's `/service/upload` REST response: a bare line shaped
/// like `200,'null','<aid>'` (status code, a quoted ignorable field, and
/// the quoted attachment id).
fn parse_upload_response(text: &str) -> Result<String> {
    let text = text.trim();
    let status_end = text.find(',').context("upload response missing status code")?;
    let status: u16 = text[..status_end].parse().context("upload response had a non-numeric status code")?;
    if status != 200 {
        bail!("attachment upload returned status {status}: {text}");
    }
    let aid_start = text.rfind('\'').context("upload response missing closing quote for aid")?;
    let before_aid = &text[..aid_start];
    let aid_quote_start = before_aid.rfind('\'').context("upload response missing opening quote for aid")?;
    Ok(text[aid_quote_start + 1..aid_start].to_string())
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
    /// Per-folder modification sequence (`i4ms` in `GetFolderResponse`):
    /// advances whenever an item inside this folder changes, confirmed live
    /// by sending a real message and seeing only the target folder's
    /// `i4ms` move. Backs `Ping`'s per-folder change detection, since
    /// Carbonio's `WaitSetRequest` itself can't say which folder changed.
    pub mod_seq: u64,
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
            mod_seq: node.i4ms,
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
    i4ms: u64,
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
    /// From the search result's own flag string (`f` contains `a`), so
    /// callers can decide whether a further `get_message_details` call is
    /// worth making to list the actual attachments.
    pub has_attachment: bool,
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

    /// Fetches the full search-result shape (subject, sender, read flag,
    /// etc.) for a specific, already-known set of message ids, via
    /// `SearchRequest` with Zimbra's `item:{id1,id2,...}` query operator.
    /// Backs real delta `Sync`: `sync_since` only returns bare ids, so this
    /// is the follow-up call that turns those ids into real `Add` nodes. An
    /// empty `ids` list skips the round trip entirely and returns an empty
    /// result, since `item:{}` is not a valid Carbonio query.
    pub async fn search_messages_by_ids(&self, ids: &[String]) -> Result<Vec<CarbonioMessage>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let token = self.auth_token.as_deref().context("search_messages_by_ids called before authenticate")?;

        let request_body = json!({
            "Body": {
                "SearchRequest": {
                    "_jsns": "urn:zimbraMail",
                    "types": "message",
                    "query": { "_content": format!("item:{{{}}}", ids.join(",")) },
                    "limit": ids.len()
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
            .context("SearchRequest (by id) failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<SearchBody> = response
            .json()
            .await
            .context("SearchRequest (by id) response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio SearchRequest (by id) failed ({code}): {}", fault.reason.text);
        }

        let raw_messages = envelope
            .body
            .search_response
            .context("SearchResponse missing from a non-fault SOAP reply")?
            .m;

        Ok(raw_messages.into_iter().map(RawMessage::into_carbonio_message).collect())
    }

    /// Lists up to `limit` messages matching `free_text`, newest first, via
    /// the same `SearchRequest` as `search_messages` but with the free text
    /// as the query. When `folder_id` is given, the query is scoped to that
    /// folder (`inid:<id> <text>`, since Zimbra's query language ANDs
    /// space-separated terms together); `None` searches the whole mailbox,
    /// matching MS-ASCMD's basic `Search` command (no per-folder scoping in
    /// the request). Backs the `Search` command.
    pub async fn search_messages_text(&self, folder_id: Option<&str>, free_text: &str, limit: u32) -> Result<Vec<CarbonioMessage>> {
        let token = self
            .auth_token
            .as_deref()
            .context("search_messages_text called before authenticate")?;

        let query = match folder_id {
            Some(id) => format!("inid:{id} {free_text}"),
            None => free_text.to_string(),
        };
        let request_body = json!({
            "Body": {
                "SearchRequest": {
                    "_jsns": "urn:zimbraMail",
                    "types": "message",
                    "query": { "_content": query },
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
            .context("SearchRequest (text) failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<SearchBody> = response
            .json()
            .await
            .context("SearchRequest (text) response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio SearchRequest (text) failed ({code}): {}", fault.reason.text);
        }

        let raw_messages = envelope
            .body
            .search_response
            .context("SearchResponse missing from a non-fault SOAP reply")?
            .m;

        Ok(raw_messages.into_iter().map(RawMessage::into_carbonio_message).collect())
    }

    /// Carbonio's own incremental-sync token, via `SyncRequest`
    /// (`urn:zimbraMail`). Verified live: `token` is the same number
    /// `GetInfoRequest`'s change token advances to on every mailbox change,
    /// and a later `SyncRequest` with an earlier `token` (and `l` to scope
    /// it to one folder) returns only the items that changed since then
    /// under `m` -- real delta sync, not a full resync. `token: None` seeds
    /// a fresh baseline (an empty `m`, since there's nothing "since" yet)
    /// and just returns the current token to store for next time.
    ///
    /// Carbonio expires old sync tombstones, so a `token` that's aged out
    /// comes back as a `mail.MUST_RESYNC` fault; that's a real, expected
    /// outcome (not every call that returns `Err` here is a failure), so
    /// this reports it as `Ok(SyncOutcome::MustResync)` instead of an
    /// error, and callers fall back to a full resync exactly like an
    /// unrecognized ActiveSync SyncKey already does.
    pub async fn sync_since(&self, token: Option<&str>, folder_id: &str) -> Result<SyncOutcome> {
        let auth_token = self.auth_token.as_deref().context("sync_since called before authenticate")?;

        let mut sync_request = serde_json::Map::new();
        sync_request.insert("_jsns".to_string(), json!("urn:zimbraMail"));
        sync_request.insert("l".to_string(), json!(folder_id));
        if let Some(t) = token {
            sync_request.insert("token".to_string(), json!(t));
        }
        let request_body = json!({
            "Body": { "SyncRequest": sync_request },
            "Header": {
                "context": {
                    "_jsns": "urn:zimbra",
                    "authToken": { "_content": auth_token }
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
            .context("SyncRequest failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<SyncRequestBody> = response
            .json()
            .await
            .context("SyncRequest response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault.detail.map(|d| d.error.code).unwrap_or_else(|| "UNKNOWN".to_string());
            if code == "mail.MUST_RESYNC" {
                return Ok(SyncOutcome::MustResync);
            }
            bail!("Carbonio SyncRequest failed ({code}): {}", fault.reason.text);
        }

        let resp = envelope.body.sync_response.context("SyncResponse missing from a non-fault SOAP reply")?;
        let token = sync_token_to_string(&resp.token)?;
        let changed_ids = resp
            .m
            .into_iter()
            .chain(resp.cn)
            .chain(resp.appt)
            .map(|item| item.id)
            .collect();
        Ok(SyncOutcome::Delta { token, changed_ids })
    }

    /// Same idea as [`Self::sync_since`], but account-wide (no `l`, so no
    /// single-folder scope) and reading `SyncResponse.folder` instead of
    /// `m`/`cn`/`appt`, for `FolderSync`'s own real delta sync. Verified
    /// live: a changed/new folder comes back as a flat entry (not nested
    /// under its parent) with an explicit `l` for its parent id, the same
    /// shape `GetFolderResponse` uses per folder, just without the tree
    /// nesting -- so this reuses `CarbonioFolder` for the result.
    pub async fn sync_folders_since(&self, token: Option<&str>) -> Result<FolderSyncOutcome> {
        let auth_token = self.auth_token.as_deref().context("sync_folders_since called before authenticate")?;

        let mut sync_request = serde_json::Map::new();
        sync_request.insert("_jsns".to_string(), json!("urn:zimbraMail"));
        if let Some(t) = token {
            sync_request.insert("token".to_string(), json!(t));
        }
        let request_body = json!({
            "Body": { "SyncRequest": sync_request },
            "Header": {
                "context": {
                    "_jsns": "urn:zimbra",
                    "authToken": { "_content": auth_token }
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
            .context("SyncRequest (folders) failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<SyncRequestBody> = response
            .json()
            .await
            .context("SyncRequest (folders) response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault.detail.map(|d| d.error.code).unwrap_or_else(|| "UNKNOWN".to_string());
            if code == "mail.MUST_RESYNC" {
                return Ok(FolderSyncOutcome::MustResync);
            }
            bail!("Carbonio SyncRequest (folders) failed ({code}): {}", fault.reason.text);
        }

        let resp = envelope.body.sync_response.context("SyncResponse missing from a non-fault SOAP reply")?;
        let token = sync_token_to_string(&resp.token)?;
        let changed_folders = resp.folder.into_iter().filter_map(RawSyncFolder::into_carbonio_folder).collect();
        Ok(FolderSyncOutcome::Delta { token, changed_folders })
    }

    /// Moves an item (any type: message, contact, appointment) to a
    /// different folder via `ItemActionRequest` (`urn:zimbraMail`) with
    /// `op=move`. Verified live: the item keeps its own id across the move
    /// (Carbonio does not renumber it), so this backs `MoveItems` by moving
    /// the item and reporting the same id back as both source and
    /// destination id.
    pub async fn move_item(&self, item_id: &str, dst_folder_id: &str) -> Result<()> {
        let token = self.auth_token.as_deref().context("move_item called before authenticate")?;

        let request_body = json!({
            "Body": {
                "ItemActionRequest": {
                    "_jsns": "urn:zimbraMail",
                    "action": { "op": "move", "id": item_id, "l": dst_folder_id }
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
            .context("ItemActionRequest failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<ItemActionBody> = response
            .json()
            .await
            .context("ItemActionRequest response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio ItemActionRequest failed ({code}): {}", fault.reason.text);
        }

        Ok(())
    }

    /// Looks up `address` in Carbonio's Global Address List via
    /// `SearchGalRequest` (`urn:zimbraAccount`), for `ResolveRecipients`.
    /// Returns every GAL match (display name, email), not just the first:
    /// cross-checked against the original PHP z-push's Zimbra backend,
    /// which does the same and reports a real `RecipientCount` for
    /// ambiguous matches. `type: "all"` (not `"account"`, which this
    /// project used before) also matches that backend, so a match can be
    /// a resource or distribution list, not only a user account.
    pub async fn resolve_recipients_gal(&self, address: &str) -> Result<Vec<(String, String)>> {
        let token = self.auth_token.as_deref().context("resolve_recipients_gal called before authenticate")?;

        let request_body = json!({
            "Body": {
                "SearchGalRequest": {
                    "_jsns": "urn:zimbraAccount",
                    "name": address,
                    "type": "all"
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
            .context("SearchGalRequest failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<SearchGalBody> = response
            .json()
            .await
            .context("SearchGalRequest response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio SearchGalRequest failed ({code}): {}", fault.reason.text);
        }

        let matches = envelope
            .body
            .search_gal_response
            .map(|r| r.cn)
            .unwrap_or_default()
            .into_iter()
            .map(|cn| (cn.file_as_str, gal_attr_as_string(&cn.attrs, "email").unwrap_or_default()))
            .collect();
        Ok(matches)
    }

    /// Sends an email via `SendMsgRequest` (`urn:zimbraMail`), with an
    /// optional HTML alternative body and optional attachments (already
    /// uploaded via [`Self::upload_attachment`]).
    pub async fn send_message(&self, msg: &OutgoingMessage) -> Result<()> {
        let token = self
            .auth_token
            .as_deref()
            .context("send_message called before authenticate")?;

        let mut participants: Vec<_> = msg.to.iter().map(|addr| json!({ "t": "t", "a": addr })).collect();
        participants.extend(msg.cc.iter().map(|addr| json!({ "t": "c", "a": addr })));

        // An HTML body and a plain-text body are sent as sibling
        // multipart/alternative parts when both are present (matches what
        // a real mail client sends); plain-text-only stays a single part.
        let mp = if let Some(html) = &msg.html_body {
            json!({
                "ct": "multipart/alternative",
                "mp": [
                    { "ct": "text/plain", "content": { "_content": msg.plain_body } },
                    { "ct": "text/html", "content": { "_content": html } }
                ]
            })
        } else {
            json!({ "ct": "text/plain", "content": { "_content": msg.plain_body } })
        };

        let mut m = json!({
            "su": { "_content": msg.subject },
            "e": participants,
            "mp": mp
        });
        if !msg.attachment_aids.is_empty() {
            m["attach"] = json!({ "aid": msg.attachment_aids.join(",") });
        }

        let request_body = json!({
            "Body": {
                "SendMsgRequest": {
                    "_jsns": "urn:zimbraMail",
                    "m": m
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

    /// Uploads `data` via the REST `/service/upload` endpoint (not SOAP;
    /// Carbonio's attachment upload is multipart/form-data over REST) and
    /// returns the resulting attachment id (`aid`), to reference from
    /// [`Self::send_message`]'s `attachment_aids`. Carbonio does not accept
    /// attachment bytes inlined directly in `SendMsgRequest`'s `mp` tree:
    /// doing that was tried live and silently became a second body part
    /// instead of a real downloadable attachment.
    pub async fn upload_attachment(&self, filename: &str, content_type: &str, data: Vec<u8>) -> Result<String> {
        let token = self.auth_token.as_deref().context("upload_attachment called before authenticate")?;
        let upload_url = format!("{}/service/upload?fmt=raw", self.base_url.trim_end_matches('/'));

        let part = reqwest::multipart::Part::bytes(data)
            .file_name(filename.to_string())
            .mime_str(content_type)
            .context("invalid attachment content type")?;
        let form = reqwest::multipart::Form::new().part("upload", part);

        let response = self
            .http
            .post(&upload_url)
            .header("Cookie", format!("ZM_AUTH_TOKEN={token}"))
            .multipart(form)
            .send()
            .await
            .context("attachment upload failed to reach Carbonio")?;

        let text = response.text().await.context("attachment upload response was not readable")?;
        // Response is a bare comma-separated line: `200,'null','<aid>'`
        // (not JSON, not SOAP) -- the one REST, non-SOAP call this client
        // makes, because Carbonio's attachment upload only exists as REST.
        parse_upload_response(&text)
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

    /// Looks up `query` across every personal Contacts folder (no `inid`
    /// scope), for `ResolveRecipients`. Cross-checked against the original
    /// PHP z-push's Zimbra backend, which searches personal Contacts in
    /// addition to the GAL for every recipient, not GAL alone.
    pub async fn search_contacts_text(&self, query: &str, limit: u32) -> Result<Vec<CarbonioContact>> {
        let token = self.auth_token.as_deref().context("search_contacts_text called before authenticate")?;

        let request_body = json!({
            "Body": {
                "SearchRequest": {
                    "_jsns": "urn:zimbraMail",
                    "types": "contact",
                    "query": { "_content": query },
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
            .context("SearchRequest (contacts text) failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<SearchContactsBody> = response
            .json()
            .await
            .context("SearchRequest (contacts text) response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio SearchRequest (contacts text) failed ({code}): {}", fault.reason.text);
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

    /// Fetches a single contact's full attribute set via `GetContactsRequest`
    /// (`urn:zimbraMail`), for `ItemOperations`/`Fetch` on a Contacts item.
    /// Verified live: `cn` comes back as a one-element array with the same
    /// `_attrs` shape `search_contacts` already parses, so this reuses
    /// `RawContact`.
    pub async fn get_contact(&self, contact_id: &str) -> Result<CarbonioContact> {
        let token = self.auth_token.as_deref().context("get_contact called before authenticate")?;

        let request_body = json!({
            "Body": {
                "GetContactsRequest": {
                    "_jsns": "urn:zimbraMail",
                    "cn": { "id": contact_id }
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
            .context("GetContactsRequest failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<GetContactsBody> = response
            .json()
            .await
            .context("GetContactsRequest response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio GetContactsRequest failed ({code}): {}", fault.reason.text);
        }

        let contact = envelope
            .body
            .get_contacts_response
            .context("GetContactsResponse missing from a non-fault SOAP reply")?
            .cn
            .into_iter()
            .next()
            .context("GetContactsResponse had no matching contact")?;

        Ok(contact.into_carbonio_contact())
    }

    /// Fetches a single calendar event's full detail via
    /// `GetAppointmentRequest` (`urn:zimbraMail`), for `ItemOperations`/
    /// `Fetch` on a Calendar item. Verified live: unlike `SearchRequest`'s
    /// flat `name`/`loc`/`dur`/`inst` fields, this response nests the usable
    /// fields under `appt[0].inv[0].comp[0]` (invite/component), which is
    /// why this needs its own raw struct instead of reusing `RawAppointment`.
    pub async fn get_appointment(&self, appointment_id: &str) -> Result<CarbonioAppointment> {
        let token = self.auth_token.as_deref().context("get_appointment called before authenticate")?;

        let request_body = json!({
            "Body": {
                "GetAppointmentRequest": {
                    "_jsns": "urn:zimbraMail",
                    "id": appointment_id
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
            .context("GetAppointmentRequest failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<GetAppointmentBody> = response
            .json()
            .await
            .context("GetAppointmentRequest response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault
                .detail
                .map(|d| d.error.code)
                .unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio GetAppointmentRequest failed ({code}): {}", fault.reason.text);
        }

        let raw = envelope
            .body
            .get_appointment_response
            .context("GetAppointmentResponse missing from a non-fault SOAP reply")?
            .appt
            .into_iter()
            .next()
            .context("GetAppointmentResponse had no matching appointment")?;

        raw.into_carbonio_appointment()
            .context("GetAppointmentResponse's appt had no invite/component data")
    }

    /// Fetches a message's plain-text body and attachment list via
    /// `GetMsgRequest` (`urn:zimbraMail`). The body is the first MIME part
    /// (searched recursively, since a `multipart/alternative` nests its
    /// parts one level deeper) marked `body: true` with a `text/plain`
    /// content type; HTML-only messages and messages with no plain-text
    /// part get an empty body string rather than an error.
    pub async fn get_message_details(&self, message_id: &str) -> Result<MessageDetails> {
        let token = self
            .auth_token
            .as_deref()
            .context("get_message_details called before authenticate")?;

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

        let mut attachments = Vec::new();
        collect_attachments(&message.mp, &mut attachments);

        let mut leaves = Vec::new();
        collect_leaf_parts(&message.mp, &mut leaves);
        let body = leaves
            .into_iter()
            .find(|part| part.body && part.ct == "text/plain")
            .map(|part| part.content)
            .unwrap_or_default();

        Ok(MessageDetails { body, attachments })
    }

    /// Downloads one attachment's raw bytes via the REST
    /// `/service/content/get` endpoint (not SOAP; like upload, Carbonio's
    /// attachment content retrieval only exists as REST). Returns the
    /// filename and content type Carbonio reports in the response headers.
    pub async fn download_attachment(&self, message_id: &str, part_id: &str) -> Result<(String, String, Vec<u8>)> {
        let token = self.auth_token.as_deref().context("download_attachment called before authenticate")?;
        let url = format!(
            "{}/service/content/get?id={message_id}&part={part_id}",
            self.base_url.trim_end_matches('/')
        );

        let response = self
            .http
            .get(&url)
            .header("Cookie", format!("ZM_AUTH_TOKEN={token}"))
            .send()
            .await
            .context("attachment download failed to reach Carbonio")?;

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .split(';')
            .next()
            .unwrap_or("application/octet-stream")
            .trim()
            .to_string();

        let filename = response
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split("filename=").nth(1))
            .map(|v| v.trim_matches('"').to_string())
            .unwrap_or_else(|| "attachment".to_string());

        let bytes = response.bytes().await.context("failed to read attachment download body")?;
        Ok((filename, content_type, bytes.to_vec()))
    }

    /// Fetches the authenticated account's own id via `GetInfoRequest`
    /// (`urn:zimbraAccount`). Needed to explicitly list the account in a
    /// WaitSet's `add` list (see [`Self::create_waitset`]).
    async fn get_account_id(&self) -> Result<String> {
        let token = self.auth_token.as_deref().context("get_account_id called before authenticate")?;

        let request_body = json!({
            "Body": { "GetInfoRequest": { "_jsns": "urn:zimbraAccount" } },
            "Header": {
                "context": { "_jsns": "urn:zimbra", "authToken": { "_content": token } }
            },
            "_jsns": "urn:zimbraSoap"
        });

        let response = self
            .http
            .post(self.soap_endpoint())
            .json(&request_body)
            .send()
            .await
            .context("GetInfoRequest failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<GetInfoBody> = response
            .json()
            .await
            .context("GetInfoRequest response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault.detail.map(|d| d.error.code).unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio GetInfoRequest failed ({code}): {}", fault.reason.text);
        }

        Ok(envelope.body.get_info_response.context("GetInfoResponse missing")?.id)
    }

    /// Creates a WaitSet (`CreateWaitSetRequest`, `urn:zimbraMail`) bound to
    /// the authenticated account's own mailbox (no explicit account `add`
    /// entry, which requires admin rights; omitting it binds to self).
    /// Returns the WaitSet id and its starting sequence number.
    pub async fn create_waitset(&self) -> Result<(String, String)> {
        let token = self.auth_token.as_deref().context("create_waitset called before authenticate")?;

        // An empty `add` list (binding "implicitly" to the caller's own
        // mailbox) creates a WaitSet successfully but never actually
        // reports a change -- verified live: the account's own change
        // token kept advancing on new mail while this WaitSet's `a` list
        // stayed empty across repeated calls. The account id must be
        // listed explicitly in `add.a` for change notifications to fire.
        let account_id = self.get_account_id().await?;

        let request_body = json!({
            "Body": {
                "CreateWaitSetRequest": {
                    "_jsns": "urn:zimbraMail",
                    "defTypes": "all",
                    "add": { "a": [{ "id": account_id, "types": "all" }] }
                }
            },
            "Header": {
                "context": { "_jsns": "urn:zimbra", "authToken": { "_content": token } }
            },
            "_jsns": "urn:zimbraSoap"
        });

        let response = self
            .http
            .post(self.soap_endpoint())
            .json(&request_body)
            .send()
            .await
            .context("CreateWaitSetRequest failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<CreateWaitSetBody> = response
            .json()
            .await
            .context("CreateWaitSetRequest response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault.detail.map(|d| d.error.code).unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio CreateWaitSetRequest failed ({code}): {}", fault.reason.text);
        }

        let resp = envelope.body.create_wait_set_response.context("CreateWaitSetResponse missing")?;
        let seq = match resp.seq {
            serde_json::Value::String(s) => s,
            serde_json::Value::Number(n) => n.to_string(),
            other => bail!("CreateWaitSetResponse.seq was neither a string nor a number: {other:?}"),
        };
        Ok((resp.wait_set, seq))
    }

    /// Blocks (per Carbonio's own WaitSet semantics -- it clamps the actual
    /// wait duration server-side, observed around 33s regardless of the
    /// `timeout_secs` requested) until a change occurs on the account or
    /// the server-side timeout elapses. Returns whether any change was
    /// reported and the sequence number to pass on the next call.
    ///
    /// Caution: Carbonio's own reverse proxy (nginx, in front of the SOAP
    /// endpoint) has its own upstream read timeout, observed to reject
    /// (`504`) a single HTTP call that blocks much longer than ~33-60s.
    /// Keep `timeout_secs` well under that, or loop multiple shorter calls
    /// for a longer overall wait instead of one long one.
    pub async fn wait_for_changes(&self, wait_set_id: &str, seq: &str, timeout_secs: u32) -> Result<(bool, String)> {
        let token = self.auth_token.as_deref().context("wait_for_changes called before authenticate")?;

        let request_body = json!({
            "Body": {
                "WaitSetRequest": {
                    "_jsns": "urn:zimbraMail",
                    "waitSet": wait_set_id,
                    "seq": seq,
                    "block": true,
                    "timeout": timeout_secs
                }
            },
            "Header": {
                "context": { "_jsns": "urn:zimbra", "authToken": { "_content": token } }
            },
            "_jsns": "urn:zimbraSoap"
        });

        let response = self
            .http
            .post(self.soap_endpoint())
            .json(&request_body)
            .send()
            .await
            .context("WaitSetRequest failed to reach Carbonio SOAP endpoint")?;

        let envelope: SoapEnvelope<WaitSetBody> = response
            .json()
            .await
            .context("WaitSetRequest response was not valid SOAP-JSON")?;

        if let Some(fault) = envelope.body.fault {
            let code = fault.detail.map(|d| d.error.code).unwrap_or_else(|| "UNKNOWN".to_string());
            bail!("Carbonio WaitSetRequest failed ({code}): {}", fault.reason.text);
        }

        let resp = envelope.body.wait_set_response.context("WaitSetResponse missing")?;
        let changed = !resp.a.is_empty();
        Ok((changed, resp.seq))
    }
}

#[derive(Debug, Deserialize)]
struct GetInfoBody {
    #[serde(rename = "GetInfoResponse")]
    get_info_response: Option<GetInfoResponse>,
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

#[derive(Debug, Deserialize)]
struct GetInfoResponse {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CreateWaitSetBody {
    #[serde(rename = "CreateWaitSetResponse")]
    create_wait_set_response: Option<CreateWaitSetResponse>,
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

#[derive(Debug, Deserialize)]
struct CreateWaitSetResponse {
    #[serde(rename = "waitSet")]
    wait_set: String,
    /// Observed as a bare JSON number (`0`) in practice, unlike
    /// `WaitSetResponse.seq` which comes back as a string; accept either.
    seq: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct WaitSetBody {
    #[serde(rename = "WaitSetResponse")]
    wait_set_response: Option<WaitSetResponse>,
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

#[derive(Debug, Deserialize)]
struct WaitSetResponse {
    seq: String,
    /// Accounts reporting a change; empty means the call timed out with no changes.
    #[serde(default)]
    a: Vec<serde_json::Value>,
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
    part: String,
    ct: String,
    #[serde(default)]
    body: bool,
    #[serde(default)]
    content: String,
    #[serde(default)]
    cd: String,
    #[serde(default)]
    filename: String,
    /// Part size in bytes, as Carbonio reports it (0 for container parts).
    #[serde(default)]
    s: u64,
    #[serde(default)]
    mp: Vec<RawMimePart>,
}

/// One attachment on a message, identified by its MIME part id (needed to
/// fetch its content later via [`CarbonioClient::download_attachment`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRef {
    pub part_id: String,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
}

/// Flattens a message's MIME part tree, collecting every part whose
/// content-disposition is `attachment`.
fn collect_attachments(parts: &[RawMimePart], out: &mut Vec<AttachmentRef>) {
    for part in parts {
        if part.cd == "attachment" {
            out.push(AttachmentRef {
                part_id: part.part.clone(),
                filename: part.filename.clone(),
                content_type: part.ct.clone(),
                size: part.s,
            });
        }
        collect_attachments(&part.mp, out);
    }
}

/// Flattens a message's MIME part tree into every leaf part (parts with no
/// children), regardless of disposition -- used to find the plain-text
/// body part wherever it's nested (e.g. inside `multipart/alternative`).
fn collect_leaf_parts(parts: &[RawMimePart], out: &mut Vec<RawMimePart>) {
    for part in parts {
        if part.mp.is_empty() {
            out.push(RawMimePart {
                part: part.part.clone(),
                ct: part.ct.clone(),
                body: part.body,
                content: part.content.clone(),
                cd: part.cd.clone(),
                filename: part.filename.clone(),
                s: part.s,
                mp: Vec::new(),
            });
        } else {
            collect_leaf_parts(&part.mp, out);
        }
    }
}

/// A message's plain-text body plus its attachment list, from
/// [`CarbonioClient::get_message_details`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDetails {
    pub body: String,
    pub attachments: Vec<AttachmentRef>,
}

/// Result of [`CarbonioClient::sync_since`]: either a real delta (possibly
/// empty, meaning "nothing changed") with a token to store for next time, or
/// a signal that the given token is too old for Carbonio to diff against
/// anymore, so the caller needs to fall back to a full resync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    Delta { token: String, changed_ids: Vec<String> },
    MustResync,
}

/// Result of [`CarbonioClient::sync_folders_since`]: the folder-hierarchy
/// equivalent of [`SyncOutcome`], carrying full `CarbonioFolder` values
/// (not just ids) since a changed folder's `SyncResponse` entry already has
/// everything `FolderSync` needs, with no need for a follow-up call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderSyncOutcome {
    Delta { token: String, changed_folders: Vec<CarbonioFolder> },
    MustResync,
}

#[derive(Debug, Deserialize)]
struct SyncRequestBody {
    #[serde(rename = "SyncResponse")]
    sync_response: Option<SyncResponseJson>,
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

#[derive(Debug, Deserialize)]
struct SyncResponseJson {
    /// Comes back as a bare JSON number on some calls and a quoted string
    /// on others, confirmed live against the same account in the same
    /// session; same inconsistency this project already works around for
    /// `CreateWaitSetResponse`/`WaitSetResponse`'s own `seq` field.
    token: serde_json::Value,
    /// Changed messages. Confirmed live: a `SyncRequest` scoped to one
    /// folder (`l`) puts a changed item under a different field by type --
    /// messages under `m`, contacts under `cn`, calendar events under
    /// `appt` -- not one unified list. `sync_since` reads whichever of
    /// these is relevant and merges them into one id list.
    #[serde(default)]
    m: Vec<RawSyncItem>,
    #[serde(default)]
    cn: Vec<RawSyncItem>,
    #[serde(default)]
    appt: Vec<RawSyncItem>,
    /// Changed/new folders, for `sync_folders_since`. Only populated on an
    /// account-wide (no `l`) call; an `l`-scoped item delta call just
    /// leaves this empty.
    #[serde(default)]
    folder: Vec<RawSyncFolder>,
}

/// One changed or newly created folder from a folder-hierarchy
/// `SyncResponse`. Unlike `GetFolderResponse`'s `RawFolder` (nested tree,
/// parent implicit from nesting), this is a flat entry with its parent
/// given explicitly via `l`, confirmed live against a real `CreateFolder`.
#[derive(Debug, Deserialize)]
struct RawSyncFolder {
    id: String,
    /// A baseline (no-token) account-wide call wraps everything under one
    /// synthetic root entry that has neither `name` nor `l` (confirmed
    /// live), unlike a real changed folder; both are `Option` so that
    /// entry parses instead of failing the whole response, and
    /// `into_carbonio_folder` filters it out.
    name: Option<String>,
    view: Option<String>,
    #[serde(default)]
    n: u32,
    #[serde(default)]
    i4ms: u64,
    l: Option<String>,
}

impl RawSyncFolder {
    fn into_carbonio_folder(self) -> Option<CarbonioFolder> {
        Some(CarbonioFolder {
            id: self.id,
            parent_id: Some(self.l?),
            name: self.name?,
            view: self.view,
            item_count: self.n,
            mod_seq: self.i4ms,
        })
    }
}

/// Renders a `SyncResponse.token` (string or number) as a plain string.
fn sync_token_to_string(token: &serde_json::Value) -> Result<String> {
    match token {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        other => bail!("SyncResponse.token was neither a string nor a number: {other:?}"),
    }
}

/// One changed item from `SyncResponse.m`. Only the id is used (the full
/// details come from a follow-up `search_messages_by_ids` call); `l`
/// (the item's folder) and the rest of the fields this carries aren't
/// needed since the request already scopes `SyncRequest` to one folder.
#[derive(Debug, Deserialize)]
struct RawSyncItem {
    id: String,
}

/// `ItemActionResponse`'s own `action` echo isn't used for anything (its
/// `id` is the same id we sent); only whether a `Fault` came back matters.
#[derive(Debug, Deserialize)]
struct ItemActionBody {
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

#[derive(Debug, Deserialize)]
struct SearchGalBody {
    #[serde(rename = "SearchGalResponse")]
    search_gal_response: Option<SearchGalResponse>,
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

#[derive(Debug, Deserialize)]
struct SearchGalResponse {
    #[serde(default)]
    cn: Vec<RawGalContact>,
}

/// A GAL entry, trimmed to the one field `resolve_recipient` needs.
#[derive(Debug, Deserialize)]
struct RawGalContact {
    #[serde(rename = "fileAsStr")]
    file_as_str: String,
    /// `serde_json::Value`, not `String`: confirmed live that `type: "all"`
    /// (needed to match non-account GAL entries, not just `"account"`)
    /// can return multi-valued attributes like `objectClass` as a JSON
    /// array, which broke deserializing the whole `_attrs` map when it
    /// was typed as `HashMap<String, String>`.
    #[serde(rename = "_attrs", default)]
    attrs: HashMap<String, serde_json::Value>,
}

/// Reads one `_attrs` value as a plain string, whether Carbonio sent it as
/// a bare string or (for a multi-valued attribute) the first element of a
/// JSON array.
fn gal_attr_as_string(attrs: &HashMap<String, serde_json::Value>, key: &str) -> Option<String> {
    match attrs.get(key)? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(arr) => arr.first().and_then(|v| v.as_str()).map(|s| s.to_string()),
        _ => None,
    }
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

#[derive(Debug, Deserialize)]
struct GetAppointmentBody {
    #[serde(rename = "GetAppointmentResponse")]
    get_appointment_response: Option<GetAppointmentResponse>,
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
}

#[derive(Debug, Deserialize)]
struct GetAppointmentResponse {
    #[serde(default)]
    appt: Vec<RawApptDetail>,
}

/// A single `GetAppointmentRequest` result. The fields a Calendar `Fetch`
/// needs (subject, location, start/end time, all-day flag) live under the
/// first invite's first component, not at this level.
#[derive(Debug, Deserialize)]
struct RawApptDetail {
    id: String,
    #[serde(default)]
    inv: Vec<RawInvite>,
}

#[derive(Debug, Deserialize)]
struct RawInvite {
    #[serde(default)]
    comp: Vec<RawComponent>,
}

#[derive(Debug, Deserialize)]
struct RawComponent {
    #[serde(default)]
    name: String,
    #[serde(default)]
    loc: String,
    #[serde(default, rename = "allDay")]
    all_day: bool,
    #[serde(default)]
    s: Vec<RawCompTime>,
    #[serde(default)]
    e: Vec<RawCompTime>,
}

/// A component's start/end time; `u` is milliseconds since the Unix epoch
/// (the same unit `inst[].s` uses for search results).
#[derive(Debug, Deserialize)]
struct RawCompTime {
    u: i64,
}

impl RawApptDetail {
    fn into_carbonio_appointment(self) -> Option<CarbonioAppointment> {
        let comp = self.inv.into_iter().next()?.comp.into_iter().next()?;
        let start_epoch_ms = comp.s.first().map(|t| t.u).unwrap_or(0);
        let end_epoch_ms = comp.e.first().map(|t| t.u).unwrap_or(start_epoch_ms);
        Some(CarbonioAppointment {
            id: self.id,
            subject: comp.name,
            location: comp.loc,
            start_epoch_ms,
            end_epoch_ms,
            all_day: comp.all_day,
        })
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
struct GetContactsBody {
    #[serde(rename = "GetContactsResponse")]
    get_contacts_response: Option<SearchContactsResponse>,
    #[serde(rename = "Fault")]
    fault: Option<SoapFault>,
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
    /// A bare string here (unlike `GetMsgRequest`'s structured fields),
    /// confirmed live: `SearchResponse.m[].su` is plain JSON text, not
    /// `{"_content": ...}`. This mismatch went unnoticed for a while
    /// because every earlier live Sync test happened to hit an empty
    /// Inbox, so `su` was never actually deserialized until a folder with
    /// real messages was synced.
    su: Option<String>,
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
            subject: self.su.unwrap_or_default(),
            from,
            to,
            date_epoch_ms: self.d.unwrap_or(0),
            unread: self.f.as_deref().is_some_and(|flags| flags.contains('u')),
            has_attachment: self.f.as_deref().is_some_and(|flags| flags.contains('a')),
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
                                "i4ms": 189,
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
                    mod_seq: 189,
                },
                CarbonioFolder {
                    id: "6".into(),
                    parent_id: Some("2".into()),
                    name: "Sub".into(),
                    view: Some("message".into()),
                    item_count: 0,
                    mod_seq: 0,
                },
                CarbonioFolder {
                    id: "10".into(),
                    parent_id: Some("1".into()),
                    name: "Calendar".into(),
                    view: Some("appointment".into()),
                    item_count: 0,
                    mod_seq: 0,
                },
            ]
        );
    }

    #[test]
    fn search_response_maps_sender_recipients_and_unread_flag() {
        // Shape matches a real SearchRequest hit: one unread message with
        // an attachment, from alice to bob and carol.
        let raw = r#"{
            "Body": {
                "SearchResponse": {
                    "m": [{
                        "id": "123",
                        "su": "Weekly report",
                        "d": 1760000000000,
                        "f": "ua",
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
                has_attachment: true,
            }]
        );
    }

    #[test]
    fn search_response_without_flags_is_read() {
        let raw = r#"{
            "Body": {
                "SearchResponse": {
                    "m": [{"id": "1", "su": "Hi", "d": 1, "e": []}]
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
    fn get_contacts_response_maps_known_attrs() {
        // Shape matches a real GetContactsRequest hit, captured live from
        // Carbonio CE (carbonio-core 4.5.14): `cn` is a one-element array
        // with the same `_attrs` shape SearchRequest uses.
        let raw = r#"{
            "Body": {
                "GetContactsResponse": {
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
        let envelope: SoapEnvelope<GetContactsBody> = serde_json::from_str(raw).unwrap();
        let contact = envelope.body.get_contacts_response.unwrap().cn.into_iter().next().unwrap();
        assert_eq!(
            contact.into_carbonio_contact(),
            CarbonioContact {
                id: "262".into(),
                first_name: "Budi".into(),
                last_name: "Santoso".into(),
                email: "budi@afatyo.com".into(),
                mobile_phone: "08123456789".into(),
            }
        );
    }

    #[test]
    fn get_appointment_response_extracts_subject_location_and_times_from_the_invite() {
        // Shape matches a real GetAppointmentRequest hit, captured live from
        // Carbonio CE (carbonio-core 4.5.14): unlike SearchRequest, the
        // usable fields are nested under appt[0].inv[0].comp[0], not at the
        // appt level.
        let raw = r#"{
            "Body": {
                "GetAppointmentResponse": {
                    "appt": [{
                        "id": "264",
                        "inv": [{
                            "comp": [{
                                "name": "Team Sync Meeting",
                                "loc": "Zoom",
                                "s": [{"d": "20261020T090000", "tz": "America/Los_Angeles", "u": 1792512000000}],
                                "e": [{"tz": "America/Los_Angeles", "u": 1792515600000, "d": "20261020T100000"}]
                            }]
                        }]
                    }]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<GetAppointmentBody> = serde_json::from_str(raw).unwrap();
        let raw_appt = envelope.body.get_appointment_response.unwrap().appt.into_iter().next().unwrap();
        let appt = raw_appt.into_carbonio_appointment().expect("invite/component data should be present");
        assert_eq!(appt.id, "264");
        assert_eq!(appt.subject, "Team Sync Meeting");
        assert_eq!(appt.location, "Zoom");
        assert_eq!(appt.start_epoch_ms, 1792512000000);
        assert_eq!(appt.end_epoch_ms, 1792515600000);
        assert!(!appt.all_day);
    }

    #[test]
    fn get_appointment_response_with_no_invite_returns_none() {
        let raw = r#"{
            "Body": {
                "GetAppointmentResponse": { "appt": [{"id": "264"}] }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<GetAppointmentBody> = serde_json::from_str(raw).unwrap();
        let raw_appt = envelope.body.get_appointment_response.unwrap().appt.into_iter().next().unwrap();
        assert!(raw_appt.into_carbonio_appointment().is_none());
    }

    #[test]
    fn item_action_response_with_no_fault_is_success() {
        // Shape matches a real move hit, captured live from Carbonio CE
        // (carbonio-core 4.5.14): moving a message doesn't renumber it.
        let raw = r#"{
            "Body": {
                "ItemActionResponse": { "action": {"id": "275", "op": "move"} }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<ItemActionBody> = serde_json::from_str(raw).unwrap();
        assert!(envelope.body.fault.is_none());
    }

    #[test]
    fn search_gal_response_extracts_the_display_name() {
        // Shape matches a real SearchGalRequest hit, captured live from
        // Carbonio CE (carbonio-core 4.5.14): `cn` uses the same `_attrs`
        // convention as contacts, but `resolve_recipient` only needs
        // `fileAsStr`.
        let raw = r#"{
            "Body": {
                "SearchGalResponse": {
                    "cn": [{
                        "id": "x:258",
                        "fileAsStr": "Carbonio Admin",
                        "_attrs": {"email": "zextras@afatyo.com"}
                    }]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SearchGalBody> = serde_json::from_str(raw).unwrap();
        let display_name = envelope.body.search_gal_response.and_then(|r| r.cn.into_iter().next()).map(|cn| cn.file_as_str);
        assert_eq!(display_name, Some("Carbonio Admin".to_string()));
    }

    #[test]
    fn search_gal_response_with_multivalued_attr_still_parses() {
        // Confirmed live: `type: "all"` (needed for non-account GAL
        // entries) can return a multi-valued attribute like `objectClass`
        // as a JSON array, which broke deserializing the whole `_attrs`
        // map when every value was assumed to be a plain string.
        let raw = r#"{
            "Body": {
                "SearchGalResponse": {
                    "cn": [{
                        "id": "x:258",
                        "fileAsStr": "Carbonio Admin",
                        "_attrs": {"email": "zextras@afatyo.com", "objectClass": ["inetOrgPerson", "zimbraAccount"]}
                    }]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SearchGalBody> = serde_json::from_str(raw).unwrap();
        let cn = envelope.body.search_gal_response.unwrap().cn.into_iter().next().unwrap();
        assert_eq!(gal_attr_as_string(&cn.attrs, "email"), Some("zextras@afatyo.com".to_string()));
        assert_eq!(gal_attr_as_string(&cn.attrs, "objectClass"), Some("inetOrgPerson".to_string()));
    }

    #[test]
    fn search_gal_response_with_no_matches_is_none() {
        let raw = r#"{
            "Body": { "SearchGalResponse": {} },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SearchGalBody> = serde_json::from_str(raw).unwrap();
        let display_name = envelope.body.search_gal_response.and_then(|r| r.cn.into_iter().next()).map(|cn| cn.file_as_str);
        assert_eq!(display_name, None);
    }

    #[test]
    fn sync_response_extracts_token_and_changed_ids() {
        // Shape matches a real SyncRequest hit, captured live from Carbonio
        // CE (carbonio-core 4.5.14): token comes back as a string here, and
        // `m` only needs `id` (the rest of the fields back a follow-up
        // search by id).
        let raw = r#"{
            "Body": {
                "SyncResponse": {
                    "md": 1791941834,
                    "m": [{"d": 1791941833000, "l": "5", "cid": "-295", "rev": 191, "md": 1791941833, "ms": 191, "id": "295"}],
                    "token": "192"
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SyncRequestBody> = serde_json::from_str(raw).unwrap();
        let resp = envelope.body.sync_response.unwrap();
        assert_eq!(sync_token_to_string(&resp.token).unwrap(), "192");
        assert_eq!(resp.m.into_iter().map(|m| m.id).collect::<Vec<_>>(), vec!["295".to_string()]);
    }

    #[test]
    fn sync_response_reads_changed_ids_from_cn_and_appt_too() {
        // Shape matches real SyncRequest hits, captured live from Carbonio
        // CE (carbonio-core 4.5.14): unlike `SearchResponse`'s unified `m`,
        // a folder-scoped `SyncRequest` puts a changed contact under `cn`
        // and a changed calendar event under `appt`, not `m`. Missing this
        // was a real bug: a changed contact/appointment silently produced
        // an empty id list (no error, serde just drops unknown fields),
        // caught live when a real contact edit never showed up as a delta.
        let cn_raw = r#"{
            "Body": {
                "SyncResponse": { "md": 1, "token": "204", "cn": [{"id": "304", "l": "7", "ms": 204}] }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SyncRequestBody> = serde_json::from_str(cn_raw).unwrap();
        let resp = envelope.body.sync_response.unwrap();
        let ids: Vec<String> = resp.m.into_iter().chain(resp.cn).chain(resp.appt).map(|i| i.id).collect();
        assert_eq!(ids, vec!["304".to_string()]);

        let appt_raw = r#"{
            "Body": {
                "SyncResponse": { "md": 1, "token": "205", "appt": [{"id": "306", "l": "10", "ms": 205}] }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SyncRequestBody> = serde_json::from_str(appt_raw).unwrap();
        let resp = envelope.body.sync_response.unwrap();
        let ids: Vec<String> = resp.m.into_iter().chain(resp.cn).chain(resp.appt).map(|i| i.id).collect();
        assert_eq!(ids, vec!["306".to_string()]);
    }

    #[test]
    fn sync_response_folder_extracts_a_flat_new_folder_with_its_parent() {
        // Shape matches a real CreateFolderRequest hit, captured live from
        // Carbonio CE (carbonio-core 4.5.14): a new folder's entry under an
        // account-wide SyncResponse.folder is flat (not nested under its
        // parent, unlike GetFolderResponse's tree) with an explicit `l`.
        let raw = r#"{
            "Body": {
                "SyncResponse": {
                    "md": 1,
                    "token": "211",
                    "folder": [{"id": "312", "name": "DeltaFolderTest", "l": "1", "view": "message", "n": 0, "i4ms": 211}]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SyncRequestBody> = serde_json::from_str(raw).unwrap();
        let resp = envelope.body.sync_response.unwrap();
        let folders: Vec<CarbonioFolder> = resp.folder.into_iter().filter_map(RawSyncFolder::into_carbonio_folder).collect();
        assert_eq!(
            folders,
            vec![CarbonioFolder {
                id: "312".into(),
                parent_id: Some("1".into()),
                name: "DeltaFolderTest".into(),
                view: Some("message".into()),
                item_count: 0,
                mod_seq: 211,
            }]
        );
    }

    #[test]
    fn sync_response_folder_skips_the_synthetic_root_on_a_baseline_call() {
        // Confirmed live: an account-wide SyncRequest with no token wraps
        // the whole folder tree under one synthetic root entry that has
        // neither `name` nor `l`. This used to be a hard deserialize
        // failure for the whole response (both fields were required),
        // which meant seeding a FolderSync delta token always silently
        // fell back to the plain counter.
        let raw = r#"{
            "Body": {
                "SyncResponse": { "md": 1, "token": "211", "folder": [{"id": "11", "n": 0, "i4ms": 1}] }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SyncRequestBody> = serde_json::from_str(raw).unwrap();
        let resp = envelope.body.sync_response.unwrap();
        let folders: Vec<CarbonioFolder> = resp.folder.into_iter().filter_map(RawSyncFolder::into_carbonio_folder).collect();
        assert!(folders.is_empty());
    }

    #[test]
    fn sync_response_with_empty_m_means_nothing_changed() {
        let raw = r#"{
            "Body": { "SyncResponse": { "md": 1, "token": "190" } },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SyncRequestBody> = serde_json::from_str(raw).unwrap();
        let resp = envelope.body.sync_response.unwrap();
        assert_eq!(sync_token_to_string(&resp.token).unwrap(), "190");
        assert!(resp.m.is_empty());
    }

    #[test]
    fn sync_response_token_as_a_bare_number_also_parses() {
        // Confirmed live: the same SyncRequest call can come back with
        // `token` as a bare JSON number instead of a quoted string,
        // depending on the call (e.g. a baseline call with no `token` in
        // the request). Both forms must parse.
        let raw = r#"{
            "Body": { "SyncResponse": { "md": 1, "token": 193 } },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SyncRequestBody> = serde_json::from_str(raw).unwrap();
        let resp = envelope.body.sync_response.unwrap();
        assert_eq!(sync_token_to_string(&resp.token).unwrap(), "193");
    }

    #[test]
    fn sync_request_fault_parses_must_resync() {
        // Shape matches a real fault, captured live: an aged-out sync token
        // comes back as this specific error code, not a generic failure.
        let raw = r#"{
            "Body": {
                "Fault": {
                    "Reason": {"Text": "sync token too old; tombstones have already been expired"},
                    "Detail": {"Error": {"Code": "mail.MUST_RESYNC"}}
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<SyncRequestBody> = serde_json::from_str(raw).unwrap();
        let fault = envelope.body.fault.expect("fault should be present");
        assert_eq!(fault.detail.unwrap().error.code, "mail.MUST_RESYNC");
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
        let mut leaves = Vec::new();
        collect_leaf_parts(&message.mp, &mut leaves);
        let body = leaves.into_iter().find(|p| p.body && p.ct == "text/plain").map(|p| p.content);
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
        let mut leaves = Vec::new();
        collect_leaf_parts(&message.mp, &mut leaves);
        let body = leaves.into_iter().find(|p| p.body && p.ct == "text/plain").map(|p| p.content);
        assert_eq!(body, None);
    }

    #[test]
    fn collect_leaf_parts_finds_body_nested_inside_multipart_alternative() {
        // Shape matches a real multipart/alternative message, captured
        // live: the plain-text body is nested one level under "1".
        let raw = r#"{
            "Body": {
                "GetMsgResponse": {
                    "m": [{
                        "mp": [{
                            "part": "1",
                            "ct": "multipart/alternative",
                            "mp": [
                                {"part": "1.1", "ct": "text/plain", "body": true, "content": "Plain fallback text"},
                                {"part": "1.2", "ct": "text/html", "content": "<p>HTML</p>"}
                            ]
                        }]
                    }]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<GetMsgBody> = serde_json::from_str(raw).unwrap();
        let message = envelope.body.get_msg_response.unwrap().m.into_iter().next().unwrap();
        let mut leaves = Vec::new();
        collect_leaf_parts(&message.mp, &mut leaves);
        let body = leaves.into_iter().find(|p| p.body && p.ct == "text/plain").map(|p| p.content);
        assert_eq!(body, Some("Plain fallback text".to_string()));
    }

    #[test]
    fn collect_attachments_finds_a_nested_attachment_part() {
        // Shape matches our own live multipart/mixed + alternative +
        // attachment test message (id 282).
        let raw = r#"{
            "Body": {
                "GetMsgResponse": {
                    "m": [{
                        "mp": [{
                            "part": "TEXT",
                            "ct": "multipart/mixed",
                            "mp": [
                                {
                                    "part": "1",
                                    "ct": "multipart/alternative",
                                    "mp": [
                                        {"part": "1.1", "ct": "text/plain", "body": true, "content": "Plain"},
                                        {"part": "1.2", "ct": "text/html"}
                                    ]
                                },
                                {
                                    "part": "2",
                                    "ct": "text/plain",
                                    "cd": "attachment",
                                    "filename": "rust-note.txt",
                                    "s": 25
                                }
                            ]
                        }]
                    }]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<GetMsgBody> = serde_json::from_str(raw).unwrap();
        let message = envelope.body.get_msg_response.unwrap().m.into_iter().next().unwrap();
        let mut attachments = Vec::new();
        collect_attachments(&message.mp, &mut attachments);
        assert_eq!(
            attachments,
            vec![AttachmentRef {
                part_id: "2".into(),
                filename: "rust-note.txt".into(),
                content_type: "text/plain".into(),
                size: 25,
            }]
        );
    }

    #[test]
    fn parses_a_real_upload_response() {
        // Captured live from Carbonio CE 4.5.14's /service/upload?fmt=raw.
        let raw = "200,'null','c6d61b68-cd2d-420a-bb0f-ff6edd48db7c:5824e249-83f0-4b7e-8b5a-3f155b64ee55'";
        let aid = parse_upload_response(raw).unwrap();
        assert_eq!(aid, "c6d61b68-cd2d-420a-bb0f-ff6edd48db7c:5824e249-83f0-4b7e-8b5a-3f155b64ee55");
    }

    #[test]
    fn upload_response_with_non_200_status_is_an_error() {
        let raw = "500,'null','error'";
        let err = parse_upload_response(raw).unwrap_err();
        assert!(err.to_string().contains("status 500"));
    }

    #[test]
    fn get_info_response_parses_account_id() {
        let raw = r#"{
            "Body": {
                "GetInfoResponse": {
                    "id": "788c414c-386c-4c6a-be83-03523f4ba5fe",
                    "name": "zpush-test@afatyo.com"
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<GetInfoBody> = serde_json::from_str(raw).unwrap();
        assert_eq!(envelope.body.get_info_response.unwrap().id, "788c414c-386c-4c6a-be83-03523f4ba5fe");
    }

    #[test]
    fn create_waitset_response_parses_id_and_numeric_seq() {
        // Shape matches a real CreateWaitSetRequest hit, captured live from
        // Carbonio CE 4.5.14: `seq` comes back as a bare JSON number here,
        // unlike WaitSetResponse's string `seq`.
        let raw = r#"{
            "Body": {
                "CreateWaitSetResponse": {
                    "waitSet": "WaitSet-77b6fda6-d862-4c83-b39f-d0679e10e6c3",
                    "defTypes": "f,m,c,a",
                    "seq": 0
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<CreateWaitSetBody> = serde_json::from_str(raw).unwrap();
        let resp = envelope.body.create_wait_set_response.unwrap();
        assert_eq!(resp.wait_set, "WaitSet-77b6fda6-d862-4c83-b39f-d0679e10e6c3");
        assert_eq!(resp.seq, serde_json::json!(0));
    }

    #[test]
    fn wait_set_response_with_no_accounts_means_no_changes() {
        let raw = r#"{
            "Body": {
                "WaitSetResponse": {
                    "waitSet": "WaitSet-77b6fda6-d862-4c83-b39f-d0679e10e6c3",
                    "seq": "0"
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<WaitSetBody> = serde_json::from_str(raw).unwrap();
        let resp = envelope.body.wait_set_response.unwrap();
        assert!(resp.a.is_empty());
        assert_eq!(resp.seq, "0");
    }

    #[test]
    fn wait_set_response_with_accounts_means_something_changed() {
        let raw = r#"{
            "Body": {
                "WaitSetResponse": {
                    "waitSet": "WaitSet-77b6fda6-d862-4c83-b39f-d0679e10e6c3",
                    "seq": "1",
                    "a": [{"id": "abc", "type": "m"}]
                }
            },
            "_jsns": "urn:zimbraSoap"
        }"#;
        let envelope: SoapEnvelope<WaitSetBody> = serde_json::from_str(raw).unwrap();
        let resp = envelope.body.wait_set_response.unwrap();
        assert!(!resp.a.is_empty());
    }
}
