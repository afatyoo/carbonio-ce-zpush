use crate::activesync_http::{ensure_supported_command, parse_activesync_query, parse_basic_auth, ActiveSyncRequest};
use crate::carbonio::{CarbonioClient, FolderSyncOutcome, SyncOutcome};
use crate::codepages::{
    activesync_folder_type, airsync_decode_table, airsync_encode_table, airsync_item_page_of,
    airsyncbase_decode_table, airsyncbase_encode_table, calendar_encode_table, composemail_decode_table,
    contacts_encode_table, email_decode_table, email_encode_table, folderhierarchy_decode_table,
    folderhierarchy_encode_table, itemestimate_decode_table,
    itemestimate_encode_table, itemoperations_decode_table, itemoperations_encode_table,
    merge_decode_tables, merge_encode_tables, move_decode_table, move_encode_table, ping_decode_table,
    ping_encode_table, provision_encode_table, resolverecipients_decode_table, resolverecipients_encode_table,
    search_decode_table, search_encode_table, settings_decode_table, settings_encode_table,
    PAGE_AIRSYNC, PAGE_AIRSYNCBASE, PAGE_CALENDAR, PAGE_CONTACTS, PAGE_EMAIL, PAGE_FOLDERHIERARCHY,
    PAGE_ITEMESTIMATE, PAGE_ITEMOPERATIONS, PAGE_MOVE, PAGE_PING, PAGE_PROVISION, PAGE_RESOLVERECIPIENTS,
    PAGE_SEARCH, PAGE_SETTINGS,
};
use crate::mime_lite::parse_rfc822;
use crate::sync_state::SyncStateStore;
use crate::wbxml::{find_opaque_child, find_text_child, WbxmlDecoder, WbxmlEncoder, WbxmlNode};
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
        .route(
            "/Microsoft-Server-ActiveSync",
            post(handle_activesync).options(handle_activesync_options),
        )
        .with_state(Arc::new(state))
}

/// Real ActiveSync clients (Outlook, iOS Mail, Android's built-in Exchange
/// support) send an `OPTIONS` request to this endpoint before ever
/// attempting a `POST`, to discover which protocol versions and commands
/// the server supports (MS-ASHTTP 3.1.5.1). Without a real `200` reply
/// carrying `MS-ASProtocolVersions`/`MS-ASProtocolCommands`, these clients
/// refuse to proceed to Provision/FolderSync at all -- confirmed live: a
/// real device's setup screen failed with no request ever reaching this
/// server's logs, while hand-built WBXML sent straight to `POST` (which
/// skips the `OPTIONS` probe real clients do first) worked the whole time,
/// masking this gap completely until a real client was tried. Advertises
/// protocol version 14.1 (the newest version every command this project
/// implements was written against) and the command list
/// `ensure_supported_command` actually accepts.
async fn handle_activesync_options() -> Response {
    (
        StatusCode::OK,
        [
            ("Allow", "OPTIONS, POST"),
            ("Public", "OPTIONS, POST"),
            ("MS-Server-ActiveSync", "14.1"),
            ("MS-ASProtocolVersions", "2.5,12.0,12.1,14.0,14.1"),
            (
                "MS-ASProtocolCommands",
                "FolderSync,Sync,Provision,Ping,SendMail,GetItemEstimate,ItemOperations,MoveItems,ResolveRecipients,Settings,Search",
            ),
        ],
    )
        .into_response()
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
/// SyncKey handling mirrors the `Sync` command's own real-delta state
/// machine: "0" seeds a Carbonio `SyncRequest` token (just like an email,
/// contacts, or calendar collection does) alongside the full folder list,
/// the current key asks Carbonio what changed since via that same token
/// and reports only the folders that did, and anything else is Status 9
/// (invalid sync key per MS-ASCMD 2.2.3.165.3).
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

    if client_sync_key == "0" {
        let folders = match client.get_folders().await {
            Ok(f) => f,
            Err(e) => return (StatusCode::BAD_GATEWAY, format!("GetFolder from Carbonio failed: {e}")).into_response(),
        };
        let adds = folders.iter().map(folder_to_add_node).collect();

        // A seed failure isn't fatal to this response (the device already
        // has its full Add list either way); it just means the next
        // FolderSync falls back to the old full-resync behavior via the
        // plain counter, same fallback `Sync` already uses.
        let new_key = match client.sync_folders_since(None).await {
            Ok(FolderSyncOutcome::Delta { token, .. }) => match token.parse::<u64>() {
                Ok(t) => sync_state.set_key(&request.user, &request.device_id, FOLDER_HIERARCHY_COLLECTION, t),
                Err(_) => sync_state.advance_key(&request.user, &request.device_id, FOLDER_HIERARCHY_COLLECTION),
            },
            _ => sync_state.advance_key(&request.user, &request.device_id, FOLDER_HIERARCHY_COLLECTION),
        };
        return build_folder_sync_response("1", &new_key, adds);
    }

    if client_sync_key != current_key {
        return build_folder_sync_response("9", &current_key, Vec::new());
    }

    match client.sync_folders_since(Some(&current_key)).await {
        Ok(FolderSyncOutcome::MustResync) => build_folder_sync_response("9", &current_key, Vec::new()),
        Ok(FolderSyncOutcome::Delta { token, changed_folders }) => {
            if changed_folders.is_empty() {
                return build_folder_sync_response("1", &current_key, Vec::new());
            }
            let adds = changed_folders.iter().map(folder_to_add_node).collect();
            let new_key = match token.parse::<u64>() {
                Ok(t) => sync_state.set_key(&request.user, &request.device_id, FOLDER_HIERARCHY_COLLECTION, t),
                Err(_) => sync_state.advance_key(&request.user, &request.device_id, FOLDER_HIERARCHY_COLLECTION),
            };
            build_folder_sync_response("1", &new_key, adds)
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("SyncRequest (folders) from Carbonio failed: {e}")).into_response(),
    }
}

fn folder_to_add_node(folder: &crate::carbonio::CarbonioFolder) -> WbxmlNode {
    let parent_id = folder.parent_id.clone().unwrap_or_else(|| "0".to_string());
    WbxmlNode::Tag {
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
                children: vec![WbxmlNode::Text(activesync_folder_type(&folder.id, folder.view.as_deref()).into())],
            },
        ],
    }
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
    // Merged with AirSyncBase (a real Sync request's Options/BodyPreference
    // block switches to that codepage) and Email (a real device's `Change`
    // command -- sent whenever the user reads/unreads a message on the
    // phone -- switches to the Email codepage for its `Read` flag). Both
    // confirmed live against a real Android Gmail client: without Email
    // merged in here, every such push 400'd outright (`unknown tag token
    // 0x15 on codepage 2`), which left the device stuck retrying the same
    // failed push instead of moving on to pull new mail.
    let decode_table =
        merge_decode_tables(vec![crate::codepages::airsync_decode_table(), airsyncbase_decode_table(), email_decode_table()]);
    let nodes = match WbxmlDecoder::new(body, &decode_table).decode() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[activesync] Sync decode failed: {e} -- raw body ({} bytes): {}", body.len(), hex_dump(body));
            return (StatusCode::BAD_REQUEST, format!("failed to decode Sync body: {e}")).into_response();
        }
    };

    let client_sync_key = find_text_child(&nodes, "SyncKey").unwrap_or_else(|| "0".to_string());
    let collection_id = match find_text_child(&nodes, "CollectionId") {
        Some(id) => id,
        None => {
            eprintln!("[activesync] Sync missing CollectionId -- raw body ({} bytes): {}", body.len(), hex_dump(body));
            eprintln!("[activesync] decoded nodes: {nodes:?}");
            return (StatusCode::BAD_REQUEST, "Sync body missing CollectionId").into_response();
        }
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

    // Apply any read/unread pushes from the device (its `Commands/Change`
    // entries) before anything else, regardless of which SyncKey branch
    // this request falls into: a real device sends these the moment the
    // user reads/unreads a message on the phone, not tied to a particular
    // delta cycle. Only meaningful for email; contacts/calendar don't have
    // a `Read` flag.
    if matches!(kind, CollectionKind::Email) {
        let mut changes = Vec::new();
        find_all_tag_occurrences(&nodes, "Change", &mut changes);
        for change in changes {
            let Some(server_id) = find_text_child(change, "ServerId") else { continue };
            let mut app_data_blocks = Vec::new();
            find_all_tag_occurrences(change, "ApplicationData", &mut app_data_blocks);
            let Some(app_data) = app_data_blocks.into_iter().next() else { continue };
            if let Some(read_flag) = find_text_child(app_data, "Read") {
                if let Err(e) = client.set_message_read(&server_id, read_flag == "1").await {
                    eprintln!("[activesync] Sync Change (mark read) for {server_id} failed: {e:?}");
                }
            }
        }
    }

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
        // Every collection kind also seeds a Carbonio-native `SyncRequest`
        // token as its SyncKey (see the long comment below), so the *next*
        // Sync can do a real delta instead of another full resync. A seed
        // failure isn't fatal to this response (the device already has its
        // Add list either way), it just means the next Sync falls back to
        // the old full-resync behavior via the plain counter.
        let new_key = match client.sync_since(None, &collection_id).await {
            Ok(SyncOutcome::Delta { token, .. }) => match token.parse::<u64>() {
                Ok(t) => sync_state.set_key(&request.user, &request.device_id, &collection_id, t),
                Err(_) => sync_state.advance_key(&request.user, &request.device_id, &collection_id),
            },
            _ => sync_state.advance_key(&request.user, &request.device_id, &collection_id),
        };
        return build_sync_response(&collection_id, "1", &new_key, adds, &kind);
    }

    if client_sync_key != current_key {
        return build_sync_response(&collection_id, "3", &current_key, Vec::new(), &kind);
    }

    // The device is already caught up on *our* counter, but that doesn't
    // mean nothing changed -- it only meant that before real delta sync
    // existed. Now the "SyncKey" this hands back is really Carbonio's own
    // `SyncRequest` token (seeded above, and re-seeded below), so this
    // calls `SyncRequest` again with that same token to ask Carbonio
    // directly whether anything changed since, and fetches full details
    // only for the ids that actually did (one request for email via
    // `item:{...}`, one `GetContactsRequest`/`GetAppointmentRequest` per id
    // for contacts/calendar, since there's no bulk-by-id call for those).
    match client.sync_since(Some(&current_key), &collection_id).await {
        Ok(SyncOutcome::MustResync) => build_sync_response(&collection_id, "3", &current_key, Vec::new(), &kind),
        Ok(SyncOutcome::Delta { token, changed_ids }) => {
            if changed_ids.is_empty() {
                return build_sync_response(&collection_id, "1", &current_key, Vec::new(), &kind);
            }
            let adds = match &kind {
                CollectionKind::Email => {
                    let messages = match client.search_messages_by_ids(&changed_ids).await {
                        Ok(m) => m,
                        Err(e) => {
                            return (StatusCode::BAD_GATEWAY, format!("SearchRequest (by id) from Carbonio failed: {e}"))
                                .into_response()
                        }
                    };
                    let mut adds = Vec::with_capacity(messages.len());
                    for m in &messages {
                        adds.push(email_to_add_node(client, m).await);
                    }
                    adds
                }
                CollectionKind::Contacts => {
                    let mut adds = Vec::with_capacity(changed_ids.len());
                    for id in &changed_ids {
                        match client.get_contact(id).await {
                            Ok(c) => adds.push(contact_to_add_node(&c)),
                            // A changed id Carbonio no longer has as a contact
                            // (e.g. it was deleted, or moved to a different
                            // item type) just isn't surfaced as an Add; this
                            // project doesn't model Sync deletes anywhere else
                            // either, so that's consistent, not a regression.
                            Err(e) => eprintln!("[activesync] Sync (contacts delta) get_contact {id} failed: {e:?}"),
                        }
                    }
                    adds
                }
                CollectionKind::Calendar => {
                    let mut adds = Vec::with_capacity(changed_ids.len());
                    for id in &changed_ids {
                        match client.get_appointment(id).await {
                            Ok(a) => adds.push(appointment_to_add_node(&a)),
                            Err(e) => eprintln!("[activesync] Sync (calendar delta) get_appointment {id} failed: {e:?}"),
                        }
                    }
                    adds
                }
            };
            let new_key = match token.parse::<u64>() {
                Ok(t) => sync_state.set_key(&request.user, &request.device_id, &collection_id, t),
                Err(_) => sync_state.advance_key(&request.user, &request.device_id, &collection_id),
            };
            build_sync_response(&collection_id, "1", &new_key, adds, &kind)
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("SyncRequest from Carbonio failed: {e}")).into_response(),
    }
}

/// Builds a Sync `<Add>` node for one email. When the message has an
/// attachment (per the search result's own flag), this makes one extra
/// `GetMsgRequest` round trip to list the attachment parts, so a device
/// has a `FileReference` to `Fetch` later -- only paid for messages that
/// actually have attachments, not every message in the folder.
///
/// Attachments are listed under the real AirSyncBase codepage
/// (`DisplayName`/`FileReference`/`Method`/`EstimatedDataSize`/
/// `ContentType`), cross-checked against the original PHP z-push's
/// `wbxmldefs.php`: the old Email-codepage `Attachment`/`AttName`/
/// `AttSize`/`AttOid`/`AttMethod` fields this project used before are
/// deprecated since EAS 12.0, and a real device built against a current
/// client version won't look for them there.
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

    // A real device (confirmed live with Android Gmail) never issues a
    // separate `ItemOperations`/`Fetch` to read a message it already has
    // from `Sync` -- it expects the body inline in the `Add` node's own
    // AirSyncBase `Body` block. This used to only fetch message details
    // (and therefore only ever send a body) for messages flagged as having
    // an attachment, so every message without one synced with no body at
    // all, confirmed live: the phone showed every email completely empty.
    // Now fetched unconditionally so `Body` is always present.
    if let Ok(details) = client.get_message_details(&m.id).await {
        application_data.push(WbxmlNode::Tag {
            name: "Body".into(),
            children: vec![
                WbxmlNode::Tag {
                    name: "Type".into(),
                    children: vec![WbxmlNode::Text(if details.is_html { "2" } else { "1" }.into())],
                },
                WbxmlNode::Tag {
                    name: "EstimatedDataSize".into(),
                    children: vec![WbxmlNode::Text(details.body.len().to_string())],
                },
                WbxmlNode::Tag {
                    name: "Truncated".into(),
                    children: vec![WbxmlNode::Text("0".into())],
                },
                WbxmlNode::Tag {
                    name: "Data".into(),
                    children: vec![WbxmlNode::Text(details.body.clone())],
                },
            ],
        });

        if !details.attachments.is_empty() {
            let attachment_nodes = details
                .attachments
                .iter()
                .map(|a| WbxmlNode::Tag {
                    name: "Attachment".into(),
                    children: vec![
                        WbxmlNode::Tag {
                            name: "DisplayName".into(),
                            children: vec![WbxmlNode::Text(a.filename.clone())],
                        },
                        WbxmlNode::Tag {
                            name: "FileReference".into(),
                            children: vec![WbxmlNode::Text(format!("{}:{}", m.id, a.part_id))],
                        },
                        WbxmlNode::Tag {
                            name: "Method".into(),
                            children: vec![WbxmlNode::Text("1".into())],
                        },
                        WbxmlNode::Tag {
                            name: "EstimatedDataSize".into(),
                            children: vec![WbxmlNode::Text(a.size.to_string())],
                        },
                        WbxmlNode::Tag {
                            name: "ContentType".into(),
                            children: vec![WbxmlNode::Text(a.content_type.clone())],
                        },
                    ],
                })
                .collect();
            application_data.push(WbxmlNode::Tag { name: "Attachments".into(), children: attachment_nodes });
        }
    }
    // A failed detail lookup here just means the device won't see a body
    // or attachment list for this one message; the message itself still
    // syncs normally rather than failing the whole Sync response.

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

    let mut encode_table = merge_encode_tables(vec![airsync_encode_table(), item_encode_table]);
    if matches!(kind, CollectionKind::Email) {
        encode_table = merge_encode_tables(vec![encode_table, airsyncbase_encode_table()]);
    }
    let base_page_of = airsync_item_page_of(item_page);
    // Email's attachment list lives under the real AirSyncBase codepage
    // (cross-checked against the original PHP z-push), not the deprecated
    // Email-codepage attachment fields this project used before.
    let page_of = |name: &str| {
        if matches!(kind, CollectionKind::Email)
            && matches!(
                name,
                "Attachments"
                    | "Attachment"
                    | "DisplayName"
                    | "FileReference"
                    | "Method"
                    | "EstimatedDataSize"
                    | "ContentType"
                    | "Body"
                    | "Type"
                    | "Data"
                    | "Truncated"
            )
        {
            PAGE_AIRSYNCBASE
        } else {
            base_page_of(name)
        }
    };
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
/// no folder breakdown), so on its own it can't tell the device which of
/// its watched folders actually has new data.
///
/// This narrows that down with a cheap trick instead: `GetFolderRequest`'s
/// `i4ms` field (this project's `CarbonioFolder::mod_seq`) is a per-folder
/// modification counter that only advances when something inside that
/// folder changes, confirmed live by sending a message and watching only
/// its target folder's `i4ms` move while every other folder's stayed put.
/// So this snapshots `mod_seq` for every watched folder before the wait,
/// and diffs it against a fresh snapshot after a change is detected --
/// whichever watched folders actually moved are the real answer. If that
/// diff ever comes back empty (a tight race between the two snapshots) or
/// the second `GetFolderRequest` fails, this falls back to the old,
/// strictly safe behavior: list every watched folder, since re-`Sync`-ing
/// one that didn't change is harmless but missing one that did isn't.
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

    let mod_seqs_before = if watched_folders.is_empty() { None } else { client.get_folders().await.ok() };

    let (wait_set_id, seq) = match client.create_waitset().await {
        Ok(ids) => ids,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("CreateWaitSetRequest to Carbonio failed: {e}")).into_response(),
    };

    let changed = match client.wait_for_changes(&wait_set_id, &seq, 20).await {
        Ok((changed, _new_seq)) => changed,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("WaitSetRequest to Carbonio failed: {e}")).into_response(),
    };

    let reported_folders = if changed {
        narrow_changed_folders(client, &watched_folders, mod_seqs_before).await
    } else {
        Vec::new()
    };

    let mut ping_children = vec![WbxmlNode::Tag {
        name: "Status".into(),
        children: vec![WbxmlNode::Text(if changed { "2" } else { "1" }.into())],
    }];
    if changed && !reported_folders.is_empty() {
        let folder_nodes = reported_folders
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

/// Narrows `watched_folders` down to the ones that actually changed, by
/// diffing their `mod_seq` against a fresh `GetFolderRequest`. Falls back
/// to the full `watched_folders` list (the old, always-safe behavior)
/// whenever the narrowing itself can't be trusted: no "before" snapshot
/// (`before` is `None`, e.g. the "before" call failed), the "after" call
/// failing now, or the diff coming back with nothing narrower than what
/// went in (a tight race, or `mod_seq` not actually distinguishing these
/// folders for some reason this project hasn't seen yet).
async fn narrow_changed_folders(
    client: &CarbonioClient,
    watched_folders: &[(String, String)],
    before: Option<Vec<crate::carbonio::CarbonioFolder>>,
) -> Vec<(String, String)> {
    let Some(before) = before else { return watched_folders.to_vec() };
    let Ok(after) = client.get_folders().await else { return watched_folders.to_vec() };

    let narrowed: Vec<(String, String)> = watched_folders
        .iter()
        .filter(|(id, _)| {
            let before_seq = before.iter().find(|f| &f.id == id).map(|f| f.mod_seq);
            let after_seq = after.iter().find(|f| &f.id == id).map(|f| f.mod_seq);
            match (before_seq, after_seq) {
                (Some(b), Some(a)) => a > b,
                _ => false,
            }
        })
        .cloned()
        .collect();

    if narrowed.is_empty() {
        watched_folders.to_vec()
    } else {
        narrowed
    }
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
/// `ServerId`/`CollectionId` here are the real AirSync-codepage tokens
/// (cross-checked against the original PHP z-push), not self-contained
/// `ItemOperations` ones, so this decodes with both codepages merged in
/// case a real device page-switches to send them.
/// `FileReference` for an attachment is our own opaque scheme:
/// `"<message_id>:<part_id>"`, generated when listing attachments on a
/// Sync Add node (see `email_to_add_node`) and parsed back out here. Real
/// devices treat `FileReference` as opaque, so round-tripping our own
/// format through it is safe.
fn parse_attachment_file_reference(file_reference: &str) -> Option<(&str, &str)> {
    file_reference.split_once(':')
}

async fn handle_item_operations(client: &CarbonioClient, body: &[u8]) -> Response {
    let decode_table = merge_decode_tables(vec![itemoperations_decode_table(), airsync_decode_table(), airsyncbase_decode_table()]);
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

    // `Body` lives under the real AirSyncBase codepage (cross-checked
    // against the original PHP z-push), not the deprecated Email-codepage
    // `Body` this project used before.
    let encode_table = merge_encode_tables(vec![itemoperations_encode_table(), airsyncbase_encode_table(), airsync_encode_table()]);
    let page_of = |name: &str| {
        if name == "Body" {
            PAGE_AIRSYNCBASE
        } else if name == "ServerId" {
            PAGE_AIRSYNC
        } else {
            PAGE_ITEMOPERATIONS
        }
    };
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

    // `FileReference`/`ContentType`/`Data` all live under the real
    // AirSyncBase codepage (cross-checked against the original PHP
    // z-push), not self-contained `ItemOperations` tokens this project
    // invented before.
    let encode_table = merge_encode_tables(vec![itemoperations_encode_table(), airsyncbase_encode_table()]);
    let page_of = |name: &str| {
        if matches!(name, "FileReference" | "ContentType" | "Data") {
            PAGE_AIRSYNCBASE
        } else {
            PAGE_ITEMOPERATIONS
        }
    };
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &page_of) {
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

    let encode_table = merge_encode_tables(vec![itemoperations_encode_table(), contacts_encode_table(), airsync_encode_table()]);
    let page_of = |name: &str| {
        if name == "ServerId" {
            PAGE_AIRSYNC
        } else if matches!(name, "ItemOperations" | "Status" | "Response" | "Fetch" | "Properties") {
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

    let encode_table = merge_encode_tables(vec![itemoperations_encode_table(), calendar_encode_table(), airsync_encode_table()]);
    let page_of = |name: &str| {
        if name == "ServerId" {
            PAGE_AIRSYNC
        } else if matches!(name, "ItemOperations" | "Status" | "Response" | "Fetch" | "Properties") {
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
/// A real EAS 14.0+ device wraps `SendMail`'s RFC 822 content in a WBXML
/// envelope on the `ComposeMail` codepage, with the actual message
/// embedded as `OPAQUE` binary content inside `MIME` -- confirmed live
/// capturing a real Android Gmail `SendMail` request, which starts with a
/// WBXML header (`03 01 6A 00...`) that's never valid RFC 822 text (real
/// email headers start with printable ASCII like `To:`/`Date:`). This
/// project's own hand-built test requests, and any client that still
/// posts raw RFC 822 directly (the simpler, older convention this project
/// originally assumed was universal), don't have that WBXML wrapper, so a
/// failed decode here just means "treat the whole body as the message
/// itself" rather than an error.
fn extract_sendmail_rfc822(body: &[u8]) -> Vec<u8> {
    let decode_table = composemail_decode_table();
    match WbxmlDecoder::new(body, &decode_table).decode() {
        Ok(nodes) => match find_opaque_child(&nodes, "MIME") {
            Some(mime) => mime,
            None => body.to_vec(),
        },
        Err(_) => body.to_vec(),
    }
}

async fn handle_send_mail(client: &CarbonioClient, body: &[u8]) -> Response {
    let rfc822_bytes = extract_sendmail_rfc822(body);
    let parsed = parse_rfc822(&rfc822_bytes);
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

/// Handles `MoveItems`: moves every `<Move>` entry in the request to its
/// own destination folder via Carbonio's `ItemActionRequest`, each getting
/// its own `<Response>`, cross-checked against the original PHP z-push's
/// `moveitems.php` (which loops the same way). Status codes use the real
/// MS-ASCMD `MOVEITEMSSTATUS` table (3 = success), confirmed against
/// `zpushdefs.php`; this project doesn't yet distinguish invalid-source
/// (1) from invalid-destination (2) on failure, since Carbonio's own
/// error doesn't cleanly map to one or the other, so both report the
/// generic cannot-move code (5).
async fn handle_move_items(client: &CarbonioClient, body: &[u8]) -> Response {
    let decode_table = move_decode_table();
    let nodes = match WbxmlDecoder::new(body, &decode_table).decode() {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("failed to decode MoveItems body: {e}")).into_response(),
    };

    let mut move_entries = Vec::new();
    find_all_tag_occurrences(&nodes, "Move", &mut move_entries);
    if move_entries.is_empty() {
        return (StatusCode::BAD_REQUEST, "MoveItems body had no Move entries").into_response();
    }

    let mut responses = Vec::with_capacity(move_entries.len());
    for move_children in move_entries {
        let src_msg_id = match find_text_child(move_children, "SrcMsgId") {
            Some(id) => id,
            None => continue,
        };
        let dst_fld_id = match find_text_child(move_children, "DstFldId") {
            Some(id) => id,
            None => continue,
        };

        // Real MS-ASCMD status table (MOVEITEMSSTATUS, cross-checked
        // against the original PHP z-push's zpushdefs.php): 3 = success,
        // 5 = cannot move (used here as the generic failure code; this
        // project doesn't distinguish invalid-source (1) from
        // invalid-destination (2), since Carbonio's own error doesn't
        // cleanly map to one or the other).
        let status = match client.move_item(&src_msg_id, &dst_fld_id).await {
            Ok(()) => "3",
            Err(e) => {
                eprintln!("[activesync] MoveItems failed: {e:?}");
                "5"
            }
        };

        responses.push(WbxmlNode::Tag {
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
        });
    }

    let tree = vec![WbxmlNode::Tag { name: "MoveItems".into(), children: responses }];

    let encode_table = move_encode_table();
    let encoded = match WbxmlEncoder::new(&encode_table).encode(&tree, &|_name| PAGE_MOVE) {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("WBXML encode failed: {e}")).into_response(),
    };
    (StatusCode::OK, [("Content-Type", "application/vnd.ms-sync.wbxml")], encoded).into_response()
}

/// Finds every occurrence of `<tag_name>` in a decoded WBXML tree,
/// recursively, and collects each one's children -- like
/// `find_tag_children`, but for a tag that can legitimately repeat
/// (`MoveItems`'s `Move`, `ResolveRecipients`'s `To`), where only the
/// first match isn't enough.
fn find_all_tag_occurrences<'a>(nodes: &'a [WbxmlNode], tag_name: &str, out: &mut Vec<&'a [WbxmlNode]>) {
    for node in nodes {
        if let WbxmlNode::Tag { name, children } = node {
            if name == tag_name {
                out.push(children);
            }
            find_all_tag_occurrences(children, tag_name, out);
        }
    }
}

/// Finds the text content of every occurrence of `<tag_name>` in a decoded
/// WBXML tree, recursively -- the text-returning counterpart of
/// `find_all_tag_occurrences`, for a repeatable tag whose content is plain
/// text (`ResolveRecipients`'s `To`) rather than more child tags.
fn find_all_text_occurrences(nodes: &[WbxmlNode], tag_name: &str, out: &mut Vec<String>) {
    for node in nodes {
        if let WbxmlNode::Tag { name, children } = node {
            if name == tag_name {
                if let Some(WbxmlNode::Text(text)) = children.first() {
                    out.push(text.clone());
                }
            }
            find_all_text_occurrences(children, tag_name, out);
        }
    }
}

fn recipient_node(kind: &str, display_name: &str, email: &str) -> WbxmlNode {
    WbxmlNode::Tag {
        name: "Recipient".into(),
        children: vec![
            WbxmlNode::Tag {
                name: "Type".into(),
                children: vec![WbxmlNode::Text(kind.into())],
            },
            WbxmlNode::Tag {
                name: "DisplayName".into(),
                children: vec![WbxmlNode::Text(display_name.into())],
            },
            WbxmlNode::Tag {
                name: "EmailAddress".into(),
                children: vec![WbxmlNode::Text(email.into())],
            },
        ],
    }
}

/// Handles `ResolveRecipients`: resolves every requested `<To>` address,
/// not just the first, cross-checked against the original PHP z-push's
/// Zimbra backend. Each address is looked up in both the GAL
/// (`SearchGalRequest`) and personal Contacts (`SearchRequest
/// types=contact`), matching that backend's own two-source lookup; all
/// matches from both go into one `RecipientCount`/`Recipient` list, typed
/// `1` (GAL) or `2` (Contact) per MS-ASCMD. An address with no match in
/// either source gets Status 4 (unresolved, MS-ASCMD's
/// `RESOLVERECIPSSTATUS_RESPONSE_UNRESOLVEDRECIP`) instead of being
/// treated as resolved to itself, since that's what the real backend
/// does. No certificate, availability, or picture support.
async fn handle_resolve_recipients(client: &CarbonioClient, body: &[u8]) -> Response {
    let decode_table = resolverecipients_decode_table();
    let nodes = match WbxmlDecoder::new(body, &decode_table).decode() {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("failed to decode ResolveRecipients body: {e}")).into_response(),
    };

    let mut addresses = Vec::new();
    find_all_text_occurrences(&nodes, "To", &mut addresses);
    if addresses.is_empty() {
        return (StatusCode::BAD_REQUEST, "ResolveRecipients body missing To").into_response();
    }

    let mut responses = Vec::with_capacity(addresses.len());
    for address in addresses {
        let gal_matches = client.resolve_recipients_gal(&address).await.unwrap_or_else(|e| {
            eprintln!("[activesync] ResolveRecipients GAL lookup for '{address}' failed: {e:?}");
            Vec::new()
        });
        let contact_matches = client.search_contacts_text(&address, 20).await.unwrap_or_else(|e| {
            eprintln!("[activesync] ResolveRecipients contacts lookup for '{address}' failed: {e:?}");
            Vec::new()
        });

        let mut recipients: Vec<WbxmlNode> = gal_matches
            .into_iter()
            .map(|(display_name, email)| {
                recipient_node("1", &display_name, if email.is_empty() { &address } else { &email })
            })
            .collect();
        recipients.extend(contact_matches.into_iter().map(|c| {
            let display_name = format!("{} {}", c.first_name, c.last_name).trim().to_string();
            let email = if c.email.is_empty() { address.clone() } else { c.email };
            recipient_node("2", &display_name, &email)
        }));

        let response_children = if recipients.is_empty() {
            vec![
                WbxmlNode::Tag {
                    name: "To".into(),
                    children: vec![WbxmlNode::Text(address.clone())],
                },
                WbxmlNode::Tag {
                    name: "Status".into(),
                    children: vec![WbxmlNode::Text("4".into())],
                },
            ]
        } else {
            vec![
                WbxmlNode::Tag {
                    name: "To".into(),
                    children: vec![WbxmlNode::Text(address.clone())],
                },
                WbxmlNode::Tag {
                    name: "Status".into(),
                    children: vec![WbxmlNode::Text("1".into())],
                },
                WbxmlNode::Tag {
                    name: "RecipientCount".into(),
                    children: vec![WbxmlNode::Text(recipients.len().to_string())],
                },
            ]
            .into_iter()
            .chain(recipients)
            .collect()
        };
        responses.push(WbxmlNode::Tag { name: "Response".into(), children: response_children });
    }

    let tree = vec![WbxmlNode::Tag {
        name: "ResolveRecipients".into(),
        children: vec![WbxmlNode::Tag {
            name: "Status".into(),
            children: vec![WbxmlNode::Text("1".into())],
        }]
        .into_iter()
        .chain(responses)
        .collect(),
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

    let encode_table = merge_encode_tables(vec![search_encode_table(), email_encode_table(), airsync_encode_table()]);
    let page_of = |name: &str| {
        if matches!(name, "Subject" | "From") {
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

/// Temporary debug helper for logging a raw WBXML body that failed to
/// decode as expected, to compare against a real device's actual bytes
/// instead of this project's own hand-built test WBXML.
fn hex_dump(body: &[u8]) -> String {
    body.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// Placeholder until a real logging crate (tracing) is wired in; keeps the
/// call site stable so swapping it out later touches one place.
fn tracing_stub_log(request: &crate::activesync_http::ActiveSyncRequest, username: &str, body_len: usize) {
    eprintln!(
        "[activesync] cmd={} user={} device={}/{} auth_user={} body_bytes={}",
        request.command, request.user, request.device_id, request.device_type, username, body_len
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mime_lite::parse_rfc822;

    /// Exact bytes captured from a real Android Gmail `SendMail` request
    /// against this project's live server (see README "Known limitations" /
    /// memory notes): a WBXML envelope on the ComposeMail codepage with the
    /// RFC 822 message embedded as OPAQUE binary content inside `MIME`.
    const REAL_GMAIL_SENDMAIL_WBXML: &[u8] = &[
        0x03, 0x01, 0x6a, 0x00, 0x00, 0x15, 0x45, 0x51, 0x03, 0x53, 0x65, 0x6e,
        0x64, 0x4d, 0x61, 0x69, 0x6c, 0x2d, 0x35, 0x35, 0x32, 0x30, 0x39, 0x37,
        0x33, 0x33, 0x36, 0x39, 0x32, 0x32, 0x37, 0x32, 0x31, 0x00, 0x01, 0x08,
        0x50, 0xc3, 0x83, 0x4b, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46, 0x72,
        0x69, 0x2c, 0x20, 0x31, 0x36, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x32, 0x30,
        0x32, 0x36, 0x20, 0x31, 0x39, 0x3a, 0x30, 0x37, 0x3a, 0x35, 0x33, 0x20,
        0x2b, 0x30, 0x37, 0x30, 0x30, 0x0d, 0x0a, 0x53, 0x75, 0x62, 0x6a, 0x65,
        0x63, 0x74, 0x3a, 0x20, 0x68, 0x61, 0x6c, 0x6c, 0x6f, 0x68, 0x0d, 0x0a,
        0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2d, 0x49, 0x44, 0x3a, 0x20,
        0x3c, 0x62, 0x39, 0x38, 0x30, 0x62, 0x32, 0x38, 0x32, 0x2d, 0x61, 0x65,
        0x37, 0x61, 0x2d, 0x34, 0x61, 0x33, 0x64, 0x2d, 0x61, 0x36, 0x31, 0x65,
        0x2d, 0x35, 0x64, 0x35, 0x35, 0x33, 0x33, 0x36, 0x64, 0x38, 0x37, 0x32,
        0x39, 0x40, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x61, 0x6e, 0x64, 0x72,
        0x6f, 0x69, 0x64, 0x2e, 0x63, 0x6f, 0x6d, 0x3e, 0x0d, 0x0a, 0x58, 0x2d,
        0x41, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2d, 0x4d, 0x65, 0x73, 0x73,
        0x61, 0x67, 0x65, 0x2d, 0x49, 0x44, 0x3a, 0x20, 0x3c, 0x62, 0x39, 0x38,
        0x30, 0x62, 0x32, 0x38, 0x32, 0x2d, 0x61, 0x65, 0x37, 0x61, 0x2d, 0x34,
        0x61, 0x33, 0x64, 0x2d, 0x61, 0x36, 0x31, 0x65, 0x2d, 0x35, 0x64, 0x35,
        0x35, 0x33, 0x33, 0x36, 0x64, 0x38, 0x37, 0x32, 0x39, 0x40, 0x65, 0x6d,
        0x61, 0x69, 0x6c, 0x2e, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e,
        0x63, 0x6f, 0x6d, 0x3e, 0x0d, 0x0a, 0x46, 0x72, 0x6f, 0x6d, 0x3a, 0x20,
        0x7a, 0x70, 0x75, 0x73, 0x68, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x40, 0x61,
        0x66, 0x61, 0x74, 0x79, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x54,
        0x6f, 0x3a, 0x20, 0x7a, 0x65, 0x78, 0x74, 0x72, 0x61, 0x73, 0x40, 0x61,
        0x66, 0x61, 0x74, 0x79, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x49,
        0x6d, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x3a, 0x20, 0x4e,
        0x6f, 0x72, 0x6d, 0x61, 0x6c, 0x0d, 0x0a, 0x58, 0x2d, 0x50, 0x72, 0x69,
        0x6f, 0x72, 0x69, 0x74, 0x79, 0x3a, 0x20, 0x33, 0x0d, 0x0a, 0x58, 0x2d,
        0x4d, 0x53, 0x4d, 0x61, 0x69, 0x6c, 0x2d, 0x50, 0x72, 0x69, 0x6f, 0x72,
        0x69, 0x74, 0x79, 0x3a, 0x20, 0x4e, 0x6f, 0x72, 0x6d, 0x61, 0x6c, 0x0d,
        0x0a, 0x4d, 0x49, 0x4d, 0x45, 0x2d, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
        0x6e, 0x3a, 0x20, 0x31, 0x2e, 0x30, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74,
        0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x74, 0x65,
        0x78, 0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3b, 0x20, 0x63, 0x68, 0x61,
        0x72, 0x73, 0x65, 0x74, 0x3d, 0x75, 0x74, 0x66, 0x2d, 0x38, 0x0d, 0x0a,
        0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x72, 0x61, 0x6e,
        0x73, 0x66, 0x65, 0x72, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e,
        0x67, 0x3a, 0x20, 0x62, 0x61, 0x73, 0x65, 0x36, 0x34, 0x0d, 0x0a, 0x0d,
        0x0a, 0x50, 0x47, 0x52, 0x70, 0x64, 0x69, 0x42, 0x6b, 0x61, 0x58, 0x49,
        0x39, 0x4a, 0x32, 0x46, 0x31, 0x64, 0x47, 0x38, 0x6e, 0x50, 0x6d, 0x68,
        0x68, 0x62, 0x47, 0x78, 0x76, 0x62, 0x32, 0x39, 0x76, 0x50, 0x43, 0x39,
        0x6b, 0x61, 0x58, 0x59, 0x2b, 0x0d, 0x0a, 0x01, 0x01,
    ];

    #[test]
    fn unwraps_real_gmail_sendmail_wbxml_envelope_and_recovers_the_body() {
        let rfc822_bytes = extract_sendmail_rfc822(REAL_GMAIL_SENDMAIL_WBXML);
        let parsed = parse_rfc822(&rfc822_bytes);
        assert_eq!(parsed.subject, "halloh");
        assert_eq!(parsed.to, vec!["zextras@afatyo.com".to_string()]);
        assert_eq!(
            parsed.html_body.as_deref(),
            Some("<div dir='auto'>halloooo</div>")
        );
    }

    #[test]
    fn falls_back_to_treating_the_whole_body_as_raw_rfc822_when_not_wbxml() {
        let raw = b"To: a@b.com\r\nSubject: hi\r\n\r\nplain body".to_vec();
        let rfc822_bytes = extract_sendmail_rfc822(&raw);
        assert_eq!(rfc822_bytes, raw);
    }

    /// Exact bytes captured from a real Android Gmail `Sync` push: the
    /// device marking message ServerId "487" read after the user opened it
    /// on the phone (`<Sync><Collections><Collection><SyncKey>487</SyncKey>
    /// <CollectionId>2</CollectionId><GetChanges>0</GetChanges><Commands>
    /// <Change><ServerId>284</ServerId><ApplicationData><Email:Read>1
    /// </Email:Read></ApplicationData></Change></Commands></Collection>
    /// </Collections></Sync>`). Used to 400 outright (`unknown tag token
    /// 0x15 on codepage 2`) because handle_sync's decode table never
    /// included the Email codepage.
    const REAL_GMAIL_MARK_READ_WBXML: &[u8] = &[
        0x03, 0x01, 0x6a, 0x00, 0x45, 0x5c, 0x4f, 0x4b, 0x03, 0x34, 0x38, 0x37,
        0x00, 0x01, 0x52, 0x03, 0x32, 0x00, 0x01, 0x53, 0x03, 0x30, 0x00, 0x01,
        0x56, 0x48, 0x4d, 0x03, 0x32, 0x38, 0x34, 0x00, 0x01, 0x5d, 0x00, 0x02,
        0x55, 0x03, 0x31, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    ];

    #[test]
    fn decodes_a_real_gmail_mark_as_read_sync_push() {
        let decode_table =
            merge_decode_tables(vec![crate::codepages::airsync_decode_table(), airsyncbase_decode_table(), email_decode_table()]);
        let nodes = WbxmlDecoder::new(REAL_GMAIL_MARK_READ_WBXML, &decode_table)
            .decode()
            .expect("a real device's mark-as-read Sync push must decode");

        assert_eq!(find_text_child(&nodes, "SyncKey"), Some("487".to_string()));
        assert_eq!(find_text_child(&nodes, "CollectionId"), Some("2".to_string()));

        let mut changes = Vec::new();
        find_all_tag_occurrences(&nodes, "Change", &mut changes);
        assert_eq!(changes.len(), 1);
        assert_eq!(find_text_child(changes[0], "ServerId"), Some("284".to_string()));

        let mut app_data_blocks = Vec::new();
        find_all_tag_occurrences(changes[0], "ApplicationData", &mut app_data_blocks);
        assert_eq!(find_text_child(app_data_blocks[0], "Read"), Some("1".to_string()));
    }
}
