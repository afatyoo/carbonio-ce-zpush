use crate::activesync_http::{ensure_supported_command, parse_activesync_query, parse_basic_auth, ActiveSyncRequest};
use crate::carbonio::{CarbonioClient, SyncOutcome};
use crate::codepages::{
    activesync_folder_type, airsync_encode_table, airsync_item_page_of, calendar_encode_table,
    contacts_encode_table, email_encode_table, folderhierarchy_decode_table, folderhierarchy_encode_table,
    itemestimate_decode_table,
    itemestimate_encode_table, itemoperations_decode_table, itemoperations_encode_table,
    merge_encode_tables, move_decode_table, move_encode_table, ping_decode_table, ping_encode_table,
    provision_encode_table, resolverecipients_decode_table, resolverecipients_encode_table,
    search_decode_table, search_encode_table, settings_decode_table, settings_encode_table,
    PAGE_AIRSYNC, PAGE_CALENDAR, PAGE_CONTACTS, PAGE_EMAIL, PAGE_FOLDERHIERARCHY, PAGE_ITEMESTIMATE,
    PAGE_ITEMOPERATIONS, PAGE_MOVE, PAGE_PING, PAGE_PROVISION, PAGE_RESOLVERECIPIENTS, PAGE_SEARCH, PAGE_SETTINGS,
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
        "FolderSync" => handle_folder_sync(&mut client, &state.sync_state, &request, &body).await,
        "Sync" => handle_sync(&mut client, &state.sync_state, &request, &body).await,
        "Provision" => handle_provision(),
        "Ping" => handle_ping(&client, &body).await,
        "SendMail" => handle_send_mail(&client, &body).await,
        "GetItemEstimate" => handle_get_item_estimate(&client, &body).await,
        "ItemOperations" => handle_item_operations(&client, &body).await,
        "MoveItems" => handle_move_items(&client, &body).await,
        "ResolveRecipients" => handle_resolve_recipients(&client, &body).await,
        "Settings" => handle_settings(&body),
        "Search" => handle_search(&client, &body).await,
        other => (
            StatusCode::NOT_IMPLEMENTED,
            format!("'{other}' is accepted but not yet wired to a Carbonio handler"),
        )
            .into_response(),
    }
}

/// There is only one folder hierarchy per account, so its SyncKey is tracked
/// under this fixed sentinel "collection id" in the same per-(user, device)
/// `SyncStateStore` the `Sync` command uses for real collections.
const FOLDER_HIERARCHY_COLLECTION: &str = "__folder_hierarchy__";

/// Builds a FolderSync response: every Carbonio folder as an `<Add>` entry.
/// SyncKey handling mirrors the `Sync` command's own state machine:
/// - client sends "0": full folder list, assign and return a new key.
/// - client sends the store's current key: already caught up, so this
///   returns zero changes (not true delta sync; a folder added or renamed
///   since the last FolderSync is not detected until the device issues
///   another "0").
/// - client sends anything else (stale/unknown key): Status 9 (invalid sync
///   key per MS-ASCMD 2.2.3.165.3), telling the device to FolderSync again
///   from scratch.
async fn handle_folder_sync(
    client: &mut CarbonioClient,
    sync_state: &SyncStateStore,
    request: &ActiveSyncRequest,
    body: &[u8],
) -> Response {
    let decode_table = folderhierarchy_decode_table();
    let nodes = match WbxmlDecoder::new(body, &decode_table).decode() {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("failed to decode FolderSync body: {e}")).into_response(),
    };
    let client_sync_key = find_text_child(&nodes, "SyncKey").unwrap_or_else(|| "0".to_string());
    let current_key = sync_state.current_key(&request.user, &request.device_id, FOLDER_HIERARCHY_COLLECTION);

    if client_sync_key != "0" {
        if client_sync_key != current_key {
            return build_folder_sync_response("9", &current_key, Vec::new());
        }
        return build_folder_sync_response("1", &current_key, Vec::new());
    }

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

    let new_key = sync_state.advance_key(&request.user, &request.device_id, FOLDER_HIERARCHY_COLLECTION);
    build_folder_sync_response("1", &new_key, adds)
}

fn build_folder_sync_response(status: &str, sync_key: &str, adds: Vec<WbxmlNode>) -> Response {
    let mut changes_children = vec![WbxmlNode::Tag {
        name: "Count".into(),
        children: vec![WbxmlNode::Text(adds.len().to_string())],
    }];
    changes_children.extend(adds);

    let tree = vec![WbxmlNode::Tag {
        name: "FolderSync".into(),
        children: vec![
            WbxmlNode::Tag {
                name: "Status".into(),
                children: vec![WbxmlNode::Text(status.into())],
            },
            WbxmlNode::Tag {
                name: "SyncKey".into(),
                children: vec![WbxmlNode::Text(sync_key.into())],
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

    if client_sync_key == "0" {
        let adds = match &kind {
            CollectionKind::Email => match client.search_messages(&collection_id, 25).await {
                Ok(messages) => {
                    let mut nodes = Vec::with_capacity(messages.len());
                    for m in &messages {
                        nodes.push(email_to_add_node(client, m).await);
                    }
                    nodes
                }
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
        // Email also seeds a Carbonio-native sync token as its SyncKey (see
        // the long comment below), so the *next* Sync can do a real delta
        // instead of another full resync. A seed failure isn't fatal to
        // this response (the device already has its Add list either way),
        // it just means the next Sync falls back to the old full-resync
        // behavior via the plain counter.
        let new_key = match &kind {
            CollectionKind::Email => match client.sync_since(None, &collection_id).await {
                Ok(SyncOutcome::Delta { token, .. }) => match token.parse::<u64>() {
                    Ok(t) => sync_state.set_key(&request.user, &request.device_id, &collection_id, t),
                    Err(_) => sync_state.advance_key(&request.user, &request.device_id, &collection_id),
                },
                _ => sync_state.advance_key(&request.user, &request.device_id, &collection_id),
            },
            CollectionKind::Contacts | CollectionKind::Calendar => {
                sync_state.advance_key(&request.user, &request.device_id, &collection_id)
            }
        };
        return build_sync_response(&collection_id, "1", &new_key, adds, &kind);
    }

    if client_sync_key != current_key {
        return build_sync_response(&collection_id, "3", &current_key, Vec::new(), &kind);
    }

    // Email: the device is already caught up on *our* counter, but that
    // doesn't mean nothing changed -- it only meant that before real delta
    // sync existed. Now the "SyncKey" an email collection hands back is
    // really Carbonio's own `SyncRequest` token (seeded above, and
    // re-seeded below), so this calls `SyncRequest` again with that same
    // token to ask Carbonio directly whether anything changed since, and
    // fetches full details only for the ids that actually did. Contacts
    // and Calendar don't get this yet (see Known limitations in the
    // README): they still report zero changes here and only pick up new
    // data when the device resets to SyncKey "0".
    match &kind {
        CollectionKind::Email => match client.sync_since(Some(&current_key), &collection_id).await {
            Ok(SyncOutcome::MustResync) => build_sync_response(&collection_id, "3", &current_key, Vec::new(), &kind),
            Ok(SyncOutcome::Delta { token, changed_ids }) => {
                if changed_ids.is_empty() {
                    return build_sync_response(&collection_id, "1", &current_key, Vec::new(), &kind);
                }
                let messages = match client.search_messages_by_ids(&changed_ids).await {
                    Ok(m) => m,
                    Err(e) => {
                        return (StatusCode::BAD_GATEWAY, format!("SearchRequest (by id) from Carbonio failed: {e}")).into_response()
                    }
                };
                let mut adds = Vec::with_capacity(messages.len());
                for m in &messages {
                    adds.push(email_to_add_node(client, m).await);
                }
                let new_key = match token.parse::<u64>() {
                    Ok(t) => sync_state.set_key(&request.user, &request.device_id, &collection_id, t),
                    Err(_) => sync_state.advance_key(&request.user, &request.device_id, &collection_id),
                };
                build_sync_response(&collection_id, "1", &new_key, adds, &kind)
            }
            Err(e) => (StatusCode::BAD_GATEWAY, format!("SyncRequest from Carbonio failed: {e}")).into_response(),
        },
        CollectionKind::Contacts | CollectionKind::Calendar => build_sync_response(&collection_id, "1", &current_key, Vec::new(), &kind),
    }
}

/// Builds a Sync `<Add>` node for one email. When the message has an
/// attachment (per the search result's own flag), this makes one extra
/// `GetMsgRequest` round trip to list the attachment parts, so a device
/// has a `FileReference` to `Fetch` later -- only paid for messages that
/// actually have attachments, not every message in the folder.
async fn email_to_add_node(client: &CarbonioClient, m: &crate::carbonio::CarbonioMessage) -> WbxmlNode {
    let mut application_data = vec![
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
    ];

    if m.has_attachment {
        if let Ok(details) = client.get_message_details(&m.id).await {
            if !details.attachments.is_empty() {
                let attachment_nodes = details
                    .attachments
                    .iter()
                    .map(|a| WbxmlNode::Tag {
                        name: "Attachment".into(),
                        children: vec![
                            WbxmlNode::Tag {
                                name: "AttName".into(),
                                children: vec![WbxmlNode::Text(a.filename.clone())],
                            },
                            WbxmlNode::Tag {
                                name: "AttSize".into(),
                                children: vec![WbxmlNode::Text(a.size.to_string())],
                            },
                            WbxmlNode::Tag {
                                name: "Att0Id".into(),
                                children: vec![WbxmlNode::Text(format!("{}:{}", m.id, a.part_id))],
                            },
                            WbxmlNode::Tag {
                                name: "AttMethod".into(),
                                children: vec![WbxmlNode::Text("1".into())],
                            },
                        ],
                    })
                    .collect();
                application_data.push(WbxmlNode::Tag { name: "Attachments".into(), children: attachment_nodes });
            }
        }
        // A failed detail lookup here just means the device won't see an
        // attachment list for this one message; the message itself still
        // syncs normally rather than failing the whole Sync response.
    }

    WbxmlNode::Tag {
        name: "Add".into(),
        children: vec![
            WbxmlNode::Tag {
                name: "ServerId".into(),
                children: vec![WbxmlNode::Text(m.id.clone())],
            },
            WbxmlNode::Tag { name: "ApplicationData".into(), children: application_data },
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
/// Status 2 ("changes found") is returned on any detected change. Carbonio's
/// WaitSet only reports that the account changed, not which collection
/// (confirmed live: a `WaitSetResponse.a[]` entry is just `{id, changeid}`,
/// no folder breakdown), so this can't tell the device which of its watched
/// folders actually has new data. The practical compromise: the device's
/// own `Ping` request already lists which folders it's watching
/// (`Folders`/`Folder`/`Id`/`Class`), so on Status 2 this echoes that same
/// list back, same as every watched folder changed. That's the device's own
/// list, so it's always a safe superset to re-`Sync`, even though it isn't
/// Carbonio telling us which one really changed.
async fn handle_ping(client: &CarbonioClient, body: &[u8]) -> Response {
    let watched_folders = if body.is_empty() {
        Vec::new()
    } else {
        let decode_table = ping_decode_table();
        match WbxmlDecoder::new(body, &decode_table).decode() {
            Ok(nodes) => collect_ping_folders(&nodes),
            Err(_) => Vec::new(),
        }
    };

    let (wait_set_id, seq) = match client.create_waitset().await {
        Ok(ids) => ids,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("CreateWaitSetRequest to Carbonio failed: {e}")).into_response(),
    };

    let changed = match client.wait_for_changes(&wait_set_id, &seq, 20).await {
        Ok((changed, _new_seq)) => changed,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("WaitSetRequest to Carbonio failed: {e}")).into_response(),
    };

    let mut ping_children = vec![WbxmlNode::Tag {
        name: "Status".into(),
        children: vec![WbxmlNode::Text(if changed { "2" } else { "1" }.into())],
    }];
    if changed && !watched_folders.is_empty() {
        let folder_nodes = watched_folders
            .into_iter()
            .map(|(id, class)| WbxmlNode::Tag {
                name: "Folder".into(),
                children: vec![
                    WbxmlNode::Tag { name: "Id".into(), children: vec![WbxmlNode::Text(id)] },
                    WbxmlNode::Tag { name: "Class".into(), children: vec![WbxmlNode::Text(class)] },
                ],
            })
            .collect();
        ping_children.push(WbxmlNode::Tag { name: "Folders".into(), children: folder_nodes });
    }

    let tree = vec![WbxmlNode::Tag { name: "Ping".into(), children: ping_children }];

    let encode_table = ping_encode_table();
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &|_name| PAGE_PING) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };
    (StatusCode::OK, [("Content-Type", "application/vnd.ms-sync.wbxml")], encoded).into_response()
}

/// Finds the first `<tag_name>` node in a decoded WBXML tree and returns its
/// children, searching recursively (like `find_text_child`, but for a tag
/// whose content is more child tags, not plain text).
fn find_tag_children<'a>(nodes: &'a [WbxmlNode], tag_name: &str) -> Option<&'a [WbxmlNode]> {
    for node in nodes {
        if let WbxmlNode::Tag { name, children } = node {
            if name == tag_name {
                return Some(children);
            }
            if let Some(found) = find_tag_children(children, tag_name) {
                return Some(found);
            }
        }
    }
    None
}

/// Pulls the `(Id, Class)` pairs out of a `Ping` request's `Folders` list,
/// so `handle_ping` can echo them back on Status 2.
fn collect_ping_folders(nodes: &[WbxmlNode]) -> Vec<(String, String)> {
    let Some(folders) = find_tag_children(nodes, "Folders") else { return Vec::new() };
    folders
        .iter()
        .filter_map(|node| {
            let WbxmlNode::Tag { name, children } = node else { return None };
            if name != "Folder" {
                return None;
            }
            let id = find_text_child(children, "Id")?;
            let class = find_text_child(children, "Class").unwrap_or_else(|| "Email".to_string());
            Some((id, class))
        })
        .collect()
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
/// `FileReference` for an attachment is our own opaque scheme:
/// `"<message_id>:<part_id>"`, generated when listing attachments on a
/// Sync Add node (see `email_to_add_node`) and parsed back out here. Real
/// devices treat `FileReference` as opaque, so round-tripping our own
/// format through it is safe.
fn parse_attachment_file_reference(file_reference: &str) -> Option<(&str, &str)> {
    file_reference.split_once(':')
}

async fn handle_item_operations(client: &CarbonioClient, body: &[u8]) -> Response {
    let decode_table = itemoperations_decode_table();
    let nodes = match WbxmlDecoder::new(body, &decode_table).decode() {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("failed to decode ItemOperations body: {e}")).into_response(),
    };

    if let Some(file_reference) = find_text_child(&nodes, "FileReference") {
        return handle_fetch_attachment(client, file_reference).await;
    }

    let server_id = match find_text_child(&nodes, "ServerId") {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, "ItemOperations Fetch missing ServerId/FileReference").into_response(),
    };

    // `CollectionId` tells us which item type `ServerId` belongs to, the
    // same way `Sync` picks email vs. contacts vs. calendar per collection.
    // Without it (some clients omit it on a Fetch), this falls back to the
    // email body fetch below.
    let kind = match find_text_child(&nodes, "CollectionId") {
        Some(collection_id) => {
            let folders = match client.get_folders().await {
                Ok(f) => f,
                Err(e) => return (StatusCode::BAD_GATEWAY, format!("GetFolder from Carbonio failed: {e}")).into_response(),
            };
            folders
                .iter()
                .find(|f| f.id == collection_id)
                .and_then(|f| f.view.as_deref())
                .map(|v| v.to_string())
        }
        None => None,
    };

    match kind.as_deref() {
        Some("contact") => return handle_fetch_contact(client, server_id).await,
        Some("appointment") => return handle_fetch_appointment(client, server_id).await,
        _ => {}
    }

    let details = match client.get_message_details(&server_id).await {
        Ok(d) => d,
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
                                children: vec![WbxmlNode::Text(details.body)],
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

/// Handles an attachment `Fetch`: downloads the raw bytes via Carbonio's
/// REST content endpoint and returns them base64-encoded under
/// `Properties/Data`, per MS-ASCMD's ItemOperations response schema for
/// attachments (unlike a message body, which is returned as plain text).
async fn handle_fetch_attachment(client: &CarbonioClient, file_reference: String) -> Response {
    let Some((message_id, part_id)) = parse_attachment_file_reference(&file_reference) else {
        return (StatusCode::BAD_REQUEST, "FileReference was not in the expected 'message_id:part_id' form").into_response();
    };

    let (_, content_type, data) = match client.download_attachment(message_id, part_id).await {
        Ok(result) => result,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("attachment download from Carbonio failed: {e}")).into_response(),
    };
    let encoded_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data);

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
                            name: "FileReference".into(),
                            children: vec![WbxmlNode::Text(file_reference)],
                        },
                        WbxmlNode::Tag {
                            name: "Properties".into(),
                            children: vec![
                                WbxmlNode::Tag {
                                    name: "ContentType".into(),
                                    children: vec![WbxmlNode::Text(content_type)],
                                },
                                WbxmlNode::Tag {
                                    name: "Data".into(),
                                    children: vec![WbxmlNode::Text(encoded_data)],
                                },
                            ],
                        },
                    ],
                }],
            },
        ],
    }];

    let encode_table = itemoperations_encode_table();
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &|_name| PAGE_ITEMOPERATIONS) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };
    (StatusCode::OK, [("Content-Type", "application/vnd.ms-sync.wbxml")], encoded).into_response()
}

/// Handles a Contacts `Fetch`: returns the contact's full field set under
/// `Properties`, using the same field tags `Sync` already emits for
/// contacts (`contact_to_add_node`).
async fn handle_fetch_contact(client: &CarbonioClient, server_id: String) -> Response {
    let contact = match client.get_contact(&server_id).await {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("GetContacts from Carbonio failed: {e}")).into_response(),
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
                            children: vec![
                                WbxmlNode::Tag {
                                    name: "FirstName".into(),
                                    children: vec![WbxmlNode::Text(contact.first_name)],
                                },
                                WbxmlNode::Tag {
                                    name: "LastName".into(),
                                    children: vec![WbxmlNode::Text(contact.last_name)],
                                },
                                WbxmlNode::Tag {
                                    name: "Email1Address".into(),
                                    children: vec![WbxmlNode::Text(contact.email)],
                                },
                                WbxmlNode::Tag {
                                    name: "MobilePhoneNumber".into(),
                                    children: vec![WbxmlNode::Text(contact.mobile_phone)],
                                },
                            ],
                        },
                    ],
                }],
            },
        ],
    }];

    let encode_table = merge_encode_tables(vec![itemoperations_encode_table(), contacts_encode_table()]);
    let page_of = |name: &str| {
        if matches!(name, "ItemOperations" | "Status" | "Response" | "Fetch" | "ServerId" | "Properties") {
            PAGE_ITEMOPERATIONS
        } else {
            PAGE_CONTACTS
        }
    };
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &page_of) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };
    (StatusCode::OK, [("Content-Type", "application/vnd.ms-sync.wbxml")], encoded).into_response()
}

/// Handles a Calendar `Fetch`: returns the event's full field set under
/// `Properties`, using the same field tags `Sync` already emits for
/// calendar events (`appointment_to_add_node`).
async fn handle_fetch_appointment(client: &CarbonioClient, server_id: String) -> Response {
    let appt = match client.get_appointment(&server_id).await {
        Ok(a) => a,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("GetAppointment from Carbonio failed: {e}")).into_response(),
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
                            children: vec![
                                WbxmlNode::Tag {
                                    name: "Subject".into(),
                                    children: vec![WbxmlNode::Text(appt.subject)],
                                },
                                WbxmlNode::Tag {
                                    name: "Location".into(),
                                    children: vec![WbxmlNode::Text(appt.location)],
                                },
                                WbxmlNode::Tag {
                                    name: "StartTime".into(),
                                    children: vec![WbxmlNode::Text(format_activesync_datetime(appt.start_epoch_ms))],
                                },
                                WbxmlNode::Tag {
                                    name: "EndTime".into(),
                                    children: vec![WbxmlNode::Text(format_activesync_datetime(appt.end_epoch_ms))],
                                },
                                WbxmlNode::Tag {
                                    name: "AllDayEvent".into(),
                                    children: vec![WbxmlNode::Text(if appt.all_day { "1" } else { "0" }.into())],
                                },
                            ],
                        },
                    ],
                }],
            },
        ],
    }];

    let encode_table = merge_encode_tables(vec![itemoperations_encode_table(), calendar_encode_table()]);
    let page_of = |name: &str| {
        if matches!(name, "ItemOperations" | "Status" | "Response" | "Fetch" | "ServerId" | "Properties") {
            PAGE_ITEMOPERATIONS
        } else {
            PAGE_CALENDAR
        }
    };
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

    let mut attachment_aids = Vec::with_capacity(parsed.attachments.len());
    for attachment in &parsed.attachments {
        match client.upload_attachment(&attachment.filename, &attachment.content_type, attachment.data.clone()).await {
            Ok(aid) => attachment_aids.push(aid),
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("uploading attachment '{}' to Carbonio failed: {e}", attachment.filename),
                )
                    .into_response()
            }
        }
    }

    let outgoing = crate::carbonio::OutgoingMessage {
        to: parsed.to,
        cc: parsed.cc,
        subject: parsed.subject,
        plain_body: parsed.plain_body,
        html_body: parsed.html_body,
        attachment_aids,
    };

    match client.send_message(&outgoing).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("SendMsgRequest to Carbonio failed: {e}")).into_response(),
    }
}

/// Handles `MoveItems`: moves a single item to another folder via
/// Carbonio's own `ItemActionRequest`. Only one `<Move>` entry is handled
/// even if the request lists several (a real device rarely sends more than
/// one per request); later ones are ignored. Status codes are this
/// project's own simplified success/failure pair (`1`/`2`), not a full
/// mapping of MS-ASCMD's `Move` status table (invalid source, invalid
/// destination, already exists, etc.) -- same unverified-against-spec
/// caveat as `GetItemEstimate`'s codepage.
async fn handle_move_items(client: &CarbonioClient, body: &[u8]) -> Response {
    let decode_table = move_decode_table();
    let nodes = match WbxmlDecoder::new(body, &decode_table).decode() {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("failed to decode MoveItems body: {e}")).into_response(),
    };

    let src_msg_id = match find_text_child(&nodes, "SrcMsgId") {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, "MoveItems body missing SrcMsgId").into_response(),
    };
    let dst_fld_id = match find_text_child(&nodes, "DstFldId") {
        Some(id) => id,
        None => return (StatusCode::BAD_REQUEST, "MoveItems body missing DstFldId").into_response(),
    };

    let status = match client.move_item(&src_msg_id, &dst_fld_id).await {
        Ok(()) => "1",
        Err(e) => {
            eprintln!("[activesync] MoveItems failed: {e:?}");
            "2"
        }
    };

    let tree = vec![WbxmlNode::Tag {
        name: "MoveItems".into(),
        children: vec![WbxmlNode::Tag {
            name: "Response".into(),
            children: vec![
                WbxmlNode::Tag {
                    name: "Status".into(),
                    children: vec![WbxmlNode::Text(status.into())],
                },
                WbxmlNode::Tag {
                    name: "SrcMsgId".into(),
                    children: vec![WbxmlNode::Text(src_msg_id.clone())],
                },
                WbxmlNode::Tag {
                    name: "DstMsgId".into(),
                    children: vec![WbxmlNode::Text(src_msg_id)],
                },
            ],
        }],
    }];

    let encode_table = move_encode_table();
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &|_name| PAGE_MOVE) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };
    (StatusCode::OK, [("Content-Type", "application/vnd.ms-sync.wbxml")], encoded).into_response()
}

/// Handles `ResolveRecipients`: looks up the first requested address (only
/// one `<To>` is read, same simplification `MoveItems` makes for `<Move>`)
/// in Carbonio's GAL. A GAL hit's display name is returned; no hit still
/// returns Status 1 (resolved), just with the address echoed back as its
/// own display name -- any syntactically valid address is fine to send to,
/// GAL membership or not. No certificate or picture support.
async fn handle_resolve_recipients(client: &CarbonioClient, body: &[u8]) -> Response {
    let decode_table = resolverecipients_decode_table();
    let nodes = match WbxmlDecoder::new(body, &decode_table).decode() {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("failed to decode ResolveRecipients body: {e}")).into_response(),
    };

    let address = match find_text_child(&nodes, "To") {
        Some(a) => a,
        None => return (StatusCode::BAD_REQUEST, "ResolveRecipients body missing To").into_response(),
    };

    let display_name = match client.resolve_recipient(&address).await {
        Ok(Some(name)) => name,
        Ok(None) => address.clone(),
        Err(e) => {
            eprintln!("[activesync] ResolveRecipients GAL lookup failed: {e:?}");
            address.clone()
        }
    };

    let tree = vec![WbxmlNode::Tag {
        name: "ResolveRecipients".into(),
        children: vec![
            WbxmlNode::Tag {
                name: "Status".into(),
                children: vec![WbxmlNode::Text("1".into())],
            },
            WbxmlNode::Tag {
                name: "Response".into(),
                children: vec![WbxmlNode::Tag {
                    name: "Recipient".into(),
                    children: vec![
                        WbxmlNode::Tag {
                            name: "Status".into(),
                            children: vec![WbxmlNode::Text("1".into())],
                        },
                        WbxmlNode::Tag {
                            name: "DisplayName".into(),
                            children: vec![WbxmlNode::Text(display_name)],
                        },
                        WbxmlNode::Tag {
                            name: "EmailAddress".into(),
                            children: vec![WbxmlNode::Text(address)],
                        },
                    ],
                }],
            },
        ],
    }];

    let encode_table = resolverecipients_encode_table();
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &|_name| PAGE_RESOLVERECIPIENTS) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };
    (StatusCode::OK, [("Content-Type", "application/vnd.ms-sync.wbxml")], encoded).into_response()
}

/// Handles `Settings`: just enough to stop a device from refusing to sync
/// over an unanswered `Settings` request.
/// - A `DeviceInformation`/`Set` is acknowledged (Status 1); the device
///   info itself (model, OS, friendly name) isn't stored anywhere.
/// - An `Oof`/`Get` always answers "out of office is off" (`OofState` 0);
///   there's no real per-account Oof message storage or editing.
/// Does not call Carbonio at all; both of these are static acknowledgments.
fn handle_settings(body: &[u8]) -> Response {
    let decode_table = settings_decode_table();
    let wants_oof = match WbxmlDecoder::new(body, &decode_table).decode() {
        Ok(nodes) => find_tag_children(&nodes, "Oof").is_some(),
        Err(_) => false,
    };

    let mut settings_children = vec![WbxmlNode::Tag {
        name: "Status".into(),
        children: vec![WbxmlNode::Text("1".into())],
    }];
    if wants_oof {
        settings_children.push(WbxmlNode::Tag {
            name: "Oof".into(),
            children: vec![
                WbxmlNode::Tag {
                    name: "Status".into(),
                    children: vec![WbxmlNode::Text("1".into())],
                },
                WbxmlNode::Tag {
                    name: "OofState".into(),
                    children: vec![WbxmlNode::Text("0".into())],
                },
            ],
        });
    }

    let tree = vec![WbxmlNode::Tag { name: "Settings".into(), children: settings_children }];

    let encode_table = settings_encode_table();
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &|_name| PAGE_SETTINGS) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };
    (StatusCode::OK, [("Content-Type", "application/vnd.ms-sync.wbxml")], encoded).into_response()
}

/// Handles `Search`: a flat free-text search, no boolean query trees
/// (`And`/`Or`/`LessThan`/etc.), no GAL search -- Store must be "Mailbox".
/// Reuses the same email field tags `Sync` already emits
/// (`email_to_add_node`'s `Subject`/`From`), just under `Result` instead of
/// `Add`. `Range` from the request isn't honored; up to 25 results are
/// always returned.
async fn handle_search(client: &CarbonioClient, body: &[u8]) -> Response {
    let decode_table = search_decode_table();
    let nodes = match WbxmlDecoder::new(body, &decode_table).decode() {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("failed to decode Search body: {e}")).into_response(),
    };

    let store_name = find_text_child(&nodes, "Name").unwrap_or_else(|| "Mailbox".to_string());
    if store_name != "Mailbox" {
        return (StatusCode::NOT_IMPLEMENTED, format!("Search store '{store_name}' is not implemented (only Mailbox)"))
            .into_response();
    }
    let query = match find_text_child(&nodes, "Query") {
        Some(q) => q,
        None => return (StatusCode::BAD_REQUEST, "Search body missing Query").into_response(),
    };

    let messages = match client.search_messages_text(None, &query, 25).await {
        Ok(m) => m,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("SearchRequest from Carbonio failed: {e}")).into_response(),
    };

    let results: Vec<WbxmlNode> = messages
        .iter()
        .map(|m| WbxmlNode::Tag {
            name: "Result".into(),
            children: vec![
                WbxmlNode::Tag {
                    name: "Class".into(),
                    children: vec![WbxmlNode::Text("Email".into())],
                },
                WbxmlNode::Tag {
                    name: "ServerId".into(),
                    children: vec![WbxmlNode::Text(m.id.clone())],
                },
                WbxmlNode::Tag {
                    name: "Properties".into(),
                    children: vec![
                        WbxmlNode::Tag {
                            name: "Subject".into(),
                            children: vec![WbxmlNode::Text(m.subject.clone())],
                        },
                        WbxmlNode::Tag {
                            name: "From".into(),
                            children: vec![WbxmlNode::Text(m.from.clone().unwrap_or_default())],
                        },
                    ],
                },
            ],
        })
        .collect();

    let tree = vec![WbxmlNode::Tag {
        name: "Search".into(),
        children: vec![
            WbxmlNode::Tag {
                name: "Status".into(),
                children: vec![WbxmlNode::Text("1".into())],
            },
            WbxmlNode::Tag {
                name: "Response".into(),
                children: vec![WbxmlNode::Tag {
                    name: "Store".into(),
                    children: vec![
                        WbxmlNode::Tag {
                            name: "Total".into(),
                            children: vec![WbxmlNode::Text(results.len().to_string())],
                        },
                    ]
                    .into_iter()
                    .chain(results)
                    .collect(),
                }],
            },
        ],
    }];

    let encode_table = merge_encode_tables(vec![
        search_encode_table(),
        itemoperations_encode_table(),
        email_encode_table(),
        airsync_encode_table(),
    ]);
    let page_of = |name: &str| {
        if matches!(name, "Properties") {
            PAGE_ITEMOPERATIONS
        } else if matches!(name, "Subject" | "From") {
            PAGE_EMAIL
        } else if matches!(name, "ServerId" | "Class") {
            PAGE_AIRSYNC
        } else {
            PAGE_SEARCH
        }
    };
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &page_of) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };
    (StatusCode::OK, [("Content-Type", "application/vnd.ms-sync.wbxml")], encoded).into_response()
}

/// Placeholder until a real logging crate (tracing) is wired in; keeps the
/// call site stable so swapping it out later touches one place.
fn tracing_stub_log(request: &crate::activesync_http::ActiveSyncRequest, username: &str, body_len: usize) {
    eprintln!(
        "[activesync] cmd={} user={} device={}/{} auth_user={} body_bytes={}",
        request.command, request.user, request.device_id, request.device_type, username, body_len
    );
}
