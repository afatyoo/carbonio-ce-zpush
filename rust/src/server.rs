use crate::activesync_http::{ensure_supported_command, parse_activesync_query, parse_basic_auth};
use crate::carbonio::CarbonioClient;
use crate::codepages::{activesync_folder_type, folderhierarchy_encode_table, PAGE_FOLDERHIERARCHY};
use crate::wbxml::{WbxmlEncoder, WbxmlNode};
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
#[derive(Clone)]
pub struct AppState {
    pub carbonio_base_url: String,
    pub carbonio_tls: CarbonioTls,
    /// `(hostname_in_cert, ip_to_dial)`, for when Carbonio's TLS cert names a
    /// host with no real DNS record. See [`CarbonioClient::new_with_ca`].
    pub carbonio_dns_override: Option<(String, std::net::IpAddr)>,
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

/// Placeholder until a real logging crate (tracing) is wired in; keeps the
/// call site stable so swapping it out later touches one place.
fn tracing_stub_log(request: &crate::activesync_http::ActiveSyncRequest, username: &str, body_len: usize) {
    eprintln!(
        "[activesync] cmd={} user={} device={}/{} auth_user={} body_bytes={}",
        request.command, request.user, request.device_id, request.device_type, username, body_len
    );
}
