use anyhow::{bail, Context, Result};
use std::collections::HashMap;

/// A decoded ActiveSync request line: devices call
/// `POST /Microsoft-Server-ActiveSync?Cmd=FolderSync&User=alice&DeviceId=...&DeviceType=...`
/// with HTTP Basic auth and a WBXML body. See MS-ASHTTP 2.2.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSyncRequest {
    pub command: String,
    pub user: String,
    pub device_id: String,
    pub device_type: String,
}

/// Decoded HTTP Basic credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicCredentials {
    pub username: String,
    pub password: String,
}

/// Parses the `Authorization: Basic <base64>` header value (the full header
/// value, e.g. what `headers.get("authorization")` yields).
pub fn parse_basic_auth(header_value: &str) -> Result<BasicCredentials> {
    let encoded = header_value
        .strip_prefix("Basic ")
        .context("Authorization header is not HTTP Basic")?;
    let decoded_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .context("Basic auth payload was not valid base64")?;
    let decoded = String::from_utf8(decoded_bytes).context("Basic auth payload was not valid UTF-8")?;
    let (username, password) = decoded
        .split_once(':')
        .context("Basic auth payload missing ':' separator")?;
    Ok(BasicCredentials {
        username: username.to_string(),
        password: password.to_string(),
    })
}

/// Parses the required `Cmd`, `User`, `DeviceId`, `DeviceType` query
/// parameters out of an ActiveSync request's raw query string.
pub fn parse_activesync_query(query: &str) -> Result<ActiveSyncRequest> {
    let mut params: HashMap<String, String> = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let decoded_value = percent_decode(value);
        params.insert(key.to_string(), decoded_value);
    }

    let mut required = |name: &str| -> Result<String> {
        params
            .remove(name)
            .with_context(|| format!("missing required ActiveSync query param '{name}'"))
    };

    Ok(ActiveSyncRequest {
        command: required("Cmd")?,
        user: required("User")?,
        device_id: required("DeviceId")?,
        device_type: required("DeviceType")?,
    })
}

/// Minimal percent-decoding, sufficient for the ASCII query values
/// (device ids/types, usernames) ActiveSync clients send.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    out.push(value);
                    i += 3;
                    continue;
                }
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Validates that `command` is one of the ActiveSync commands this server
/// currently implements, surfacing an explicit error for anything else
/// rather than silently mis-dispatching.
pub fn ensure_supported_command(command: &str) -> Result<()> {
    const SUPPORTED: &[&str] = &["FolderSync", "Sync", "Provision", "Ping", "SendMail", "GetItemEstimate"];
    if !SUPPORTED.contains(&command) {
        bail!("ActiveSync command '{command}' is not yet implemented");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_basic_auth_header() {
        // "alice:s3cret" base64-encoded
        let header = "Basic YWxpY2U6czNjcmV0";
        let creds = parse_basic_auth(header).unwrap();
        assert_eq!(creds.username, "alice");
        assert_eq!(creds.password, "s3cret");
    }

    #[test]
    fn rejects_non_basic_auth_scheme() {
        let err = parse_basic_auth("Bearer abc123").unwrap_err();
        assert!(err.to_string().contains("not HTTP Basic"));
    }

    #[test]
    fn parses_activesync_query_params() {
        let query = "Cmd=FolderSync&User=alice%40example.com&DeviceId=ABCD1234&DeviceType=iPhone";
        let req = parse_activesync_query(query).unwrap();
        assert_eq!(
            req,
            ActiveSyncRequest {
                command: "FolderSync".into(),
                user: "alice@example.com".into(),
                device_id: "ABCD1234".into(),
                device_type: "iPhone".into(),
            }
        );
    }

    #[test]
    fn missing_query_param_is_reported() {
        let query = "Cmd=Sync&User=alice";
        let err = parse_activesync_query(query).unwrap_err();
        assert!(err.to_string().contains("DeviceId"));
    }

    #[test]
    fn unsupported_command_is_rejected() {
        let err = ensure_supported_command("ItemOperations").unwrap_err();
        assert!(err.to_string().contains("not yet implemented"));
    }

    #[test]
    fn supported_command_passes() {
        assert!(ensure_supported_command("FolderSync").is_ok());
        assert!(ensure_supported_command("SendMail").is_ok());
    }
}
