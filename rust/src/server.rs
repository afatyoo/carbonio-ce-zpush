use crate::activesync_http::{ensure_supported_command, parse_activesync_query, parse_basic_auth, ActiveSyncRequest};
use crate::carbonio::CarbonioClient;
use crate::codepages::{
    activesync_folder_type, airsync_encode_table, airsync_item_page_of, calendar_encode_table,
    contacts_encode_table, email_encode_table, folderhierarchy_encode_table, itemestimate_decode_table,
    itemestimate_encode_table, itemoperations_decode_table, itemoperations_encode_table,
    merge_encode_tables, ping_encode_table, provision_encode_table, PAGE_CALENDAR, PAGE_CONTACTS,
    PAGE_EMAIL, PAGE_FOLDERHIERARCHY, PAGE_ITEMESTIMATE, PAGE_ITEMOPERATIONS, PAGE_PING, PAGE_PROVISION,
};
use crate::mime_lite::parse_rfc822;
use crate::sync_state::SyncStateStore;
use crate::wbxml::{find_text_child, WbxmlDecoder, WbxmlEncoder, WbxmlNode};
use axum::{
    body::Bytes,
    extract::OriginalUri,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use std::sync::Arc;

/// How to validate Carbonio's TLS certificate.
#[derive(Clone)]
pub enum CarbonioTls {
    /// Normal CA-chain validation against `ca_pem_path`.
    Ca { ca_pem_path: String },
    /// Exact-byte-match pinning against `pinned_cert_pem_path`; needed when
    /// Carbonio's self-signed cert has a validity period CA-chain validators
    /// reject outright (see [`crate::tls_pinning`]).
    Pinned { pinned_cert_pem_path: String },
    /// System trust store, no overrides.
    SystemDefault,
}

/// Shared server config: where Carbonio lives and how to trust its TLS cert.
/// Always accessed through the `Arc<AppState>` the router holds, never
/// cloned directly (it owns the non-`Clone` `SyncStateStore`).
pub struct AppState {
    pub carbonio_base_url: String,
    pub carbonio_tls: CarbonioTls,
    /// `(hostname_in_cert, ip_to_dial)`, for when Carbonio's TLS cert names a
    /// host with no real DNS record. See [`CarbonioClient::new_with_ca`].
    pub carbonio_dns_override: Option<(String, std::net::IpAddr)>,
    pub sync_state: SyncStateStore,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/Microsoft-Server-ActiveSync", post(handle_activesync))
        .with_state(Arc::new(state))
}

async fn handle_activesync(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let query = uri.query().unwrap_or("");
    let request = match parse_activesync_query(query) {
        Ok(req) => req,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    if let Err(e) = ensure_supported_command(&request.command) {
        return (StatusCode::NOT_IMPLEMENTED, e.to_string()).into_response();
    }

    let auth_header = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(v) => v,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Basic realm=\"carbonio-ce-zpush\"")],
            )
                .into_response()
        }
    };

    let creds = match parse_basic_auth(auth_header) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    tracing_stub_log(&request, &creds.username, body.len());

    let dns_override = state
        .carbonio_dns_override
        .as_ref()
        .map(|(host, ip)| (host.as_str(), *ip));
    let mut client = match &state.carbonio_tls {
        CarbonioTls::Ca { ca_pem_path } => {
            CarbonioClient::new_with_ca(state.carbonio_base_url.clone(), ca_pem_path, dns_override)
        }
        CarbonioTls::Pinned { pinned_cert_pem_path } => CarbonioClient::new_with_pinned_cert(
            state.carbonio_base_url.clone(),
            pinned_cert_pem_path,
            dns_override,
        ),
        CarbonioTls::SystemDefault => CarbonioClient::new(state.carbonio_base_url.clone()),
    };
    let mut client = match client.as_mut() {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    if let Err(e) = client.authenticate(&creds.username, &creds.password).await {
        eprintln!("[activesync] auth failed for {}: {e:?}", creds.username);
        return (
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Basic realm=\"carbonio-ce-zpush\"")],
        )
            .into_response();
    }

    match request.command.as_str() {
        "FolderSync" => handle_folder_sync(&mut client).await,
        "Sync" => handle_sync(&mut client, &state.sync_state, &request, &body).await,
        "Provision" => handle_provision(),
        "Ping" => handle_ping(&client).await,
        "SendMail" => handle_send_mail(&client, &body).await,
        "GetItemEstimate" => handle_get_item_estimate(&client, &body).await,
        "ItemOperations" => handle_item_operations(&client, &body).await,
        other => (
            StatusCode::NOT_IMPLEMENTED,
            format!("'{other}' is accepted but not yet wired to a Carbonio handler"),
        )
            .into_response(),
    }
}

/// Builds a minimal FolderSync response: every Carbonio folder as an `<Add>`
/// entry, SyncKey hardcoded to "1". Incremental sync (tracking a real
/// SyncKey across requests so only deltas are sent) lands in a later task.
async fn handle_folder_sync(client: &mut CarbonioClient) -> Response {
    let folders = match client.get_folders().await {
        Ok(f) => f,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("GetFolder from Carbonio failed: {e}")).into_response(),
    };

    let mut adds = Vec::with_capacity(folders.len());
    for folder in &folders {
        let parent_id = folder.parent_id.clone().unwrap_or_else(|| "0".to_string());
        adds.push(WbxmlNode::Tag {
            name: "Add".into(),
            children: vec![
                WbxmlNode::Tag {
                    name: "ServerId".into(),
                    children: vec![WbxmlNode::Text(folder.id.clone())],
                },
                WbxmlNode::Tag {
                    name: "ParentId".into(),
                    children: vec![WbxmlNode::Text(parent_id)],
                },
                WbxmlNode::Tag {
                    name: "DisplayName".into(),
                    children: vec![WbxmlNode::Text(folder.name.clone())],
                },
                WbxmlNode::Tag {
                    name: "Type".into(),
                    children: vec![WbxmlNode::Text(activesync_folder_type(folder.view.as_deref()).into())],
                },
            ],
        });
    }

    let mut changes_children = vec![WbxmlNode::Tag {
        name: "Count".into(),
        children: vec![WbxmlNode::Text(folders.len().to_string())],
    }];
    changes_children.extend(adds);

    let tree = vec![WbxmlNode::Tag {
        name: "FolderSync".into(),
        children: vec![
            WbxmlNode::Tag {
                name: "Status".into(),
                children: vec![WbxmlNode::Text("1".into())],
            },
            WbxmlNode::Tag {
                name: "SyncKey".into(),
                children: vec![WbxmlNode::Text("1".into())],
            },
            WbxmlNode::Tag {
                name: "Changes".into(),
                children: changes_children,
            },
        ],
    }];

    let encode_table = folderhierarchy_encode_table();
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &|_name| PAGE_FOLDERHIERARCHY) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };

    (
        StatusCode::OK,
        [("Content-Type", "application/vnd.ms-sync.wbxml")],
        encoded,
    )
        .into_response()
}

/// Handles the `Sync` command for a single email collection (multi-collection
/// requests, and Calendar/Contacts/Tasks item sync, are not implemented
/// yet). SyncKey handling:
/// - client sends "0": first sync, assign a new key and return the current
///   message list as `<Add>` entries.
/// - client sends the store's current key: already caught up, no known new
///   mail is tracked yet, so this returns zero changes (not true delta
///   sync; new mail since the last Sync is not detected until the device
///   issues another "0" or until real change-tracking lands).
/// - client sends anything else (stale/unknown key): Status 3 (invalid
///   sync key per MS-ASCMD 2.2.4), telling the device to FolderSync/Sync
///   again from scratch.
/// Which item type a collection holds, and how to sync it. Calendar/Tasks
/// folders exist (FolderSync lists them) but have no entry here yet, so
/// `Sync`-ing one returns an explicit "not implemented" instead of silently
/// returning an empty or wrong-shaped item list.
enum CollectionKind {
    Email,
    Contacts,
    Calendar,
}

fn collection_kind_for_view(view: Option<&str>) -> Option<CollectionKind> {
    match view {
        Some("contact") => Some(CollectionKind::Contacts),
        Some("appointment") => Some(CollectionKind::Calendar),
        Some("message") | None => Some(CollectionKind::Email),
        Some(_) => None,
    }
}

/// Formats a Unix epoch (milliseconds) as the compact UTC datetime string
/// ActiveSync uses for `StartTime`/`EndTime` (MS-ASCAL 2.2.2.1): "no dashes,
/// no colons, trailing Z", e.g. `20261020T160000Z`.
fn format_activesync_datetime(epoch_ms: i64) -> String {
    use chrono::{DateTime, Utc};
    let dt: DateTime<Utc> = DateTime::from_timestamp_millis(epoch_ms).unwrap_or_default();
    dt.format("%Y%m%dT%H%M%SZ").to_string()
}

async fn handle_sync(
    client: &mut CarbonioClient,
    sync_state: &SyncStateStore,
    request: &ActiveSyncRequest,
    body: &[u8],
) -> Response {
    let decode_table = crate::codepages::airsync_decode_table();
    let nodes = match WbxmlDecoder::new(body, &decode_table).decode() {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("failed to decode Sync body: {e}")).into_response(),
    };

    let client_sync_key = find_text_child(&nodes, "SyncKey").unwrap_or_else(|| "0".to_string());
    let collection_id = match find_text_child(&nodes, "CollectionId") {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, "Sync body missing CollectionId").into_response(),
    };

    let folders = match client.get_folders().await {
        Ok(f) => f,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("GetFolder from Carbonio failed: {e}")).into_response(),
    };
    let view = folders.iter().find(|f| f.id == collection_id).and_then(|f| f.view.as_deref());
    let kind = match collection_kind_for_view(view) {
        Some(k) => k,
        None => {
            return (
                StatusCode::NOT_IMPLEMENTED,
                format!("Sync for folder view '{}' is not implemented (only email and contacts)", view.unwrap_or("?")),
            )
                .into_response()
        }
    };

    let current_key = sync_state.current_key(&request.user, &request.device_id, &collection_id);

    let (new_key, adds) = if client_sync_key == "0" {
        let adds = match &kind {
            CollectionKind::Email => match client.search_messages(&collection_id, 25).await {
                Ok(messages) => messages.iter().map(email_to_add_node).collect(),
                Err(e) => return (StatusCode::BAD_GATEWAY, format!("SearchRequest from Carbonio failed: {e}")).into_response(),
            },
            CollectionKind::Contacts => match client.search_contacts(&collection_id, 100).await {
                Ok(contacts) => contacts.iter().map(contact_to_add_node).collect(),
                Err(e) => return (StatusCode::BAD_GATEWAY, format!("SearchRequest (contacts) from Carbonio failed: {e}")).into_response(),
            },
            CollectionKind::Calendar => match client.search_appointments(&collection_id, 50).await {
                Ok(appts) => appts.iter().map(appointment_to_add_node).collect(),
                Err(e) => return (StatusCode::BAD_GATEWAY, format!("SearchRequest (appointments) from Carbonio failed: {e}")).into_response(),
            },
        };
        let new_key = sync_state.advance_key(&request.user, &request.device_id, &collection_id);
        (new_key, adds)
    } else if client_sync_key == current_key {
        (current_key, Vec::new())
    } else {
        return build_sync_response(&collection_id, "3", &current_key, Vec::new(), &kind);
    };

    build_sync_response(&collection_id, "1", &new_key, adds, &kind)
}

fn email_to_add_node(m: &crate::carbonio::CarbonioMessage) -> WbxmlNode {
    WbxmlNode::Tag {
        name: "Add".into(),
        children: vec![
            WbxmlNode::Tag {
                name: "ServerId".into(),
                children: vec![WbxmlNode::Text(m.id.clone())],
            },
            WbxmlNode::Tag {
                name: "ApplicationData".into(),
                children: vec![
                    WbxmlNode::Tag {
                        name: "Subject".into(),
                        children: vec![WbxmlNode::Text(m.subject.clone())],
                    },
                    WbxmlNode::Tag {
                        name: "From".into(),
                        children: vec![WbxmlNode::Text(m.from.clone().unwrap_or_default())],
                    },
                    WbxmlNode::Tag {
                        name: "Read".into(),
                        children: vec![WbxmlNode::Text(if m.unread { "0" } else { "1" }.into())],
                    },
                ],
            },
        ],
    }
}

fn contact_to_add_node(c: &crate::carbonio::CarbonioContact) -> WbxmlNode {
    WbxmlNode::Tag {
        name: "Add".into(),
        children: vec![
            WbxmlNode::Tag {
                name: "ServerId".into(),
                children: vec![WbxmlNode::Text(c.id.clone())],
            },
            WbxmlNode::Tag {
                name: "ApplicationData".into(),
                children: vec![
                    WbxmlNode::Tag {
                        name: "FirstName".into(),
                        children: vec![WbxmlNode::Text(c.first_name.clone())],
                    },
                    WbxmlNode::Tag {
                        name: "LastName".into(),
                        children: vec![WbxmlNode::Text(c.last_name.clone())],
                    },
                    WbxmlNode::Tag {
                        name: "Email1Address".into(),
                        children: vec![WbxmlNode::Text(c.email.clone())],
                    },
                    WbxmlNode::Tag {
                        name: "MobilePhoneNumber".into(),
                        children: vec![WbxmlNode::Text(c.mobile_phone.clone())],
                    },
                ],
            },
        ],
    }
}

fn appointment_to_add_node(a: &crate::carbonio::CarbonioAppointment) -> WbxmlNode {
    WbxmlNode::Tag {
        name: "Add".into(),
        children: vec![
            WbxmlNode::Tag {
                name: "ServerId".into(),
                children: vec![WbxmlNode::Text(a.id.clone())],
            },
            WbxmlNode::Tag {
                name: "ApplicationData".into(),
                children: vec![
                    WbxmlNode::Tag {
                        name: "Subject".into(),
                        children: vec![WbxmlNode::Text(a.subject.clone())],
                    },
                    WbxmlNode::Tag {
                        name: "Location".into(),
                        children: vec![WbxmlNode::Text(a.location.clone())],
                    },
                    WbxmlNode::Tag {
                        name: "StartTime".into(),
                        children: vec![WbxmlNode::Text(format_activesync_datetime(a.start_epoch_ms))],
                    },
                    WbxmlNode::Tag {
                        name: "EndTime".into(),
                        children: vec![WbxmlNode::Text(format_activesync_datetime(a.end_epoch_ms))],
                    },
                    WbxmlNode::Tag {
                        name: "AllDayEvent".into(),
                        children: vec![WbxmlNode::Text(if a.all_day { "1" } else { "0" }.into())],
                    },
                ],
            },
        ],
    }
}

fn build_sync_response(
    collection_id: &str,
    status: &str,
    sync_key: &str,
    adds: Vec<WbxmlNode>,
    kind: &CollectionKind,
) -> Response {
    let (class_name, item_page, item_encode_table) = match kind {
        CollectionKind::Email => ("Email", PAGE_EMAIL, email_encode_table()),
        CollectionKind::Contacts => ("Contacts", PAGE_CONTACTS, contacts_encode_table()),
        CollectionKind::Calendar => ("Calendar", PAGE_CALENDAR, calendar_encode_table()),
    };

    let mut collection_children = vec![
        WbxmlNode::Tag {
            name: "Class".into(),
            children: vec![WbxmlNode::Text(class_name.into())],
        },
        WbxmlNode::Tag {
            name: "SyncKey".into(),
            children: vec![WbxmlNode::Text(sync_key.into())],
        },
        WbxmlNode::Tag {
            name: "CollectionId".into(),
            children: vec![WbxmlNode::Text(collection_id.into())],
        },
        WbxmlNode::Tag {
            name: "Status".into(),
            children: vec![WbxmlNode::Text(status.into())],
        },
    ];
    if !adds.is_empty() {
        collection_children.push(WbxmlNode::Tag { name: "Commands".into(), children: adds });
    }

    let tree = vec![WbxmlNode::Tag {
        name: "Sync".into(),
        children: vec![WbxmlNode::Tag {
            name: "Collections".into(),
            children: vec![WbxmlNode::Tag {
                name: "Collection".into(),
                children: collection_children,
            }],
        }],
    }];

    let encode_table = merge_encode_tables(vec![airsync_encode_table(), item_encode_table]);
    let page_of = airsync_item_page_of(item_page);
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &page_of) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };

    (StatusCode::OK, [("Content-Type", "application/vnd.ms-sync.wbxml")], encoded).into_response()
}

/// `Provision` accepts any device and does not enforce an EAS policy
/// payload: no remote wipe, no PIN/encryption requirements are checked.
/// This exists only so clients that refuse to sync without a successful
/// Provision handshake (most modern phones) get past it.
fn handle_provision() -> Response {
    let tree = vec![WbxmlNode::Tag {
        name: "Provision".into(),
        children: vec![
            WbxmlNode::Tag {
                name: "Status".into(),
                children: vec![WbxmlNode::Text("1".into())],
            },
            WbxmlNode::Tag {
                name: "Policies".into(),
                children: vec![WbxmlNode::Tag {
                    name: "Policy".into(),
                    children: vec![
                        WbxmlNode::Tag {
                            name: "PolicyType".into(),
                            children: vec![WbxmlNode::Text("MS-EAS-Provisioning-WBXML".into())],
                        },
                        WbxmlNode::Tag {
                            name: "Status".into(),
                            children: vec![WbxmlNode::Text("1".into())],
                        },
                        WbxmlNode::Tag {
                            name: "PolicyKey".into(),
                            children: vec![WbxmlNode::Text("1".into())],
                        },
                    ],
                }],
            },
        ],
    }];

    let encode_table = provision_encode_table();
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &|_name| PAGE_PROVISION) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };
    (StatusCode::OK, [("Content-Type", "application/vnd.ms-sync.wbxml")], encoded).into_response()
}

/// `Ping` is meant to long-poll until Carbonio reports a change or a
/// heartbeat timeout elapses (MS-ASCMD 2.2.2.11). This returns immediately
/// with Status 1 ("no changes, ping me again") instead of actually
/// watching Carbonio for new mail, so devices will poll in a tight loop
/// rather than holding a real long connection. Real push support needs a
/// Carbonio-side notification subscription, not implemented yet.
/// `Ping` now genuinely blocks on Carbonio's own `WaitSetRequest` instead
/// of replying instantly. One `WaitSetRequest` call is issued per `Ping`;
/// Carbonio itself clamps the actual wait to roughly 33 seconds regardless
/// of the timeout requested (observed live), and Carbonio's own nginx
/// front end rejects a single call that blocks much past that with a 504,
/// so this does not loop multiple waits in one HTTP response -- the device
/// will simply issue another `Ping` immediately after this one returns,
/// same as it would with any `Ping` implementation once this one's single
/// wait window elapses.
///
/// Status 2 ("changes found") is returned on any detected change without
/// identifying which folder changed (`Folders`/`Folder` is omitted): the
/// WaitSet response only reports that the account changed, not which
/// collection, so this is a real but incomplete signal -- a real device
/// reading status 2 with no folder list is outside what MS-ASCMD 2.2.3.3
/// documents, and has not been tested against a real client.
async fn handle_ping(client: &CarbonioClient) -> Response {
    let (wait_set_id, seq) = match client.create_waitset().await {
        Ok(ids) => ids,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("CreateWaitSetRequest to Carbonio failed: {e}")).into_response(),
    };

    let changed = match client.wait_for_changes(&wait_set_id, &seq, 20).await {
        Ok((changed, _new_seq)) => changed,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("WaitSetRequest to Carbonio failed: {e}")).into_response(),
    };

    let tree = vec![WbxmlNode::Tag {
        name: "Ping".into(),
        children: vec![WbxmlNode::Tag {
            name: "Status".into(),
            children: vec![WbxmlNode::Text(if changed { "2" } else { "1" }.into())],
        }],
    }];

    let encode_table = ping_encode_table();
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &|_name| PAGE_PING) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };
    (StatusCode::OK, [("Content-Type", "application/vnd.ms-sync.wbxml")], encoded).into_response()
}

/// Handles `GetItemEstimate`: reports how many items are in the requested
/// collection, from Carbonio's own per-folder count (`GetFolderRequest`'s
/// `n` field), without fetching the items themselves. WBXML token values
/// for this command's codepage are unverified against a real device (see
/// `codepages::ITEMESTIMATE_TAGS`); this has only been exercised with
/// hand-built WBXML in this project's own tests.
async fn handle_get_item_estimate(client: &CarbonioClient, body: &[u8]) -> Response {
    let decode_table = itemestimate_decode_table();
    let nodes = match WbxmlDecoder::new(body, &decode_table).decode() {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("failed to decode GetItemEstimate body: {e}")).into_response(),
    };
    let collection_id = match find_text_child(&nodes, "CollectionId") {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, "GetItemEstimate body missing CollectionId").into_response(),
    };

    let folders = match client.get_folders().await {
        Ok(f) => f,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("GetFolder from Carbonio failed: {e}")).into_response(),
    };
    let estimate = folders.iter().find(|f| f.id == collection_id).map(|f| f.item_count).unwrap_or(0);

    let tree = vec![WbxmlNode::Tag {
        name: "GetItemEstimate".into(),
        children: vec![WbxmlNode::Tag {
            name: "Response".into(),
            children: vec![
                WbxmlNode::Tag {
                    name: "Status".into(),
                    children: vec![WbxmlNode::Text("1".into())],
                },
                WbxmlNode::Tag {
                    name: "Collection".into(),
                    children: vec![
                        WbxmlNode::Tag {
                            name: "CollectionId".into(),
                            children: vec![WbxmlNode::Text(collection_id)],
                        },
                        WbxmlNode::Tag {
                            name: "Estimate".into(),
                            children: vec![WbxmlNode::Text(estimate.to_string())],
                        },
                    ],
                },
            ],
        }],
    }];

    let encode_table = itemestimate_encode_table();
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &|_name| PAGE_ITEMESTIMATE) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };
    (StatusCode::OK, [("Content-Type", "application/vnd.ms-sync.wbxml")], encoded).into_response()
}

/// Handles `ItemOperations`/`Fetch` for an email message: fetches the
/// plain-text body via `GetMsgRequest` and returns it under `Properties`.
/// Only email Fetch is implemented (no attachment download, no
/// Contacts/Calendar Fetch). WBXML token values for this command's
/// codepage are unverified against a real device, same caveat as
/// `GetItemEstimate` -- see `codepages::ITEMOPERATIONS_TAGS`.
async fn handle_item_operations(client: &CarbonioClient, body: &[u8]) -> Response {
    let decode_table = itemoperations_decode_table();
    let nodes = match WbxmlDecoder::new(body, &decode_table).decode() {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("failed to decode ItemOperations body: {e}")).into_response(),
    };
    let server_id = match find_text_child(&nodes, "ServerId") {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, "ItemOperations Fetch missing ServerId").into_response(),
    };

    let message_body = match client.get_message_body(&server_id).await {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("GetMsg from Carbonio failed: {e}")).into_response(),
    };

    let tree = vec![WbxmlNode::Tag {
        name: "ItemOperations".into(),
        children: vec![
            WbxmlNode::Tag {
                name: "Status".into(),
                children: vec![WbxmlNode::Text("1".into())],
            },
            WbxmlNode::Tag {
                name: "Response".into(),
                children: vec![WbxmlNode::Tag {
                    name: "Fetch".into(),
                    children: vec![
                        WbxmlNode::Tag {
                            name: "Status".into(),
                            children: vec![WbxmlNode::Text("1".into())],
                        },
                        WbxmlNode::Tag {
                            name: "ServerId".into(),
                            children: vec![WbxmlNode::Text(server_id)],
                        },
                        WbxmlNode::Tag {
                            name: "Properties".into(),
                            children: vec![WbxmlNode::Tag {
                                name: "Body".into(),
                                children: vec![WbxmlNode::Text(message_body)],
                            }],
                        },
                    ],
                }],
            },
        ],
    }];

    let encode_table = merge_encode_tables(vec![itemoperations_encode_table(), email_encode_table()]);
    let page_of = |name: &str| if name == "Body" { PAGE_EMAIL } else { PAGE_ITEMOPERATIONS };
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &page_of) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };
    (StatusCode::OK, [("Content-Type", "application/vnd.ms-sync.wbxml")], encoded).into_response()
}

/// Handles `SendMail`: the request body is a raw RFC 822 message (modern
/// ActiveSync sends plain MIME here, not WBXML), parsed just enough to
/// pull Subject/To/Cc/body and relay it through Carbonio's SendMsgRequest.
/// HTML bodies and attachments (multipart MIME) are not parsed out
/// separately yet; the raw body text is sent as-is as a text/plain part.
async fn handle_send_mail(client: &CarbonioClient, body: &[u8]) -> Response {
    let parsed = parse_rfc822(body);
    if parsed.to.is_empty() {
        return (StatusCode::BAD_REQUEST, "SendMail body had no To recipients").into_response();
    }

    match client.send_message(&parsed.to, &parsed.cc, &parsed.subject, &parsed.body).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("SendMsgRequest to Carbonio failed: {e}")).into_response(),
    }
}

/// Placeholder until a real logging crate (tracing) is wired in; keeps the
/// call site stable so swapping it out later touches one place.
fn tracing_stub_log(request: &crate::activesync_http::ActiveSyncRequest, username: &str, body_len: usize) {
    eprintln!(
        "[activesync] cmd={} user={} device={}/{} auth_user={} body_bytes={}",
        request.command, request.user, request.device_id, request.device_type, username, body_len
    );
}
