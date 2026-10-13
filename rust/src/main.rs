mod activesync_http;
mod carbonio;
mod codepages;
mod server;
mod tls_pinning;
mod wbxml;

use anyhow::Result;
use server::{AppState, CarbonioTls};

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls ring crypto provider (called once at startup)");

    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:7272".into());
    let carbonio_base_url =
        std::env::var("CARBONIO_URL").unwrap_or_else(|_| "https://192.168.10.2".into());

    let carbonio_tls = if let Ok(path) = std::env::var("CARBONIO_PINNED_CERT") {
        CarbonioTls::Pinned { pinned_cert_pem_path: path }
    } else if let Ok(path) = std::env::var("CARBONIO_CA_PEM") {
        CarbonioTls::Ca { ca_pem_path: path }
    } else {
        CarbonioTls::SystemDefault
    };

    let carbonio_dns_override = match (
        std::env::var("CARBONIO_TLS_HOSTNAME").ok(),
        std::env::var("CARBONIO_TLS_IP").ok(),
    ) {
        (Some(host), Some(ip)) => Some((host, ip.parse().expect("CARBONIO_TLS_IP must be a valid IP address"))),
        _ => None,
    };

    let state = AppState { carbonio_base_url, carbonio_tls, carbonio_dns_override };
    let router = server::build_router(state);
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    println!("carbonio-ce-zpush listening on {listen_addr}");
    axum::serve(listener, router).await?;
    Ok(())
}
