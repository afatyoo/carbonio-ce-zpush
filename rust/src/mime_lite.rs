/// Minimal RFC 822/2822 + MIME multipart parser, enough to read what
/// ActiveSync devices actually send for `SendMail`: a plain-text-only
/// compose, or a `multipart/alternative`/`multipart/mixed` message with an
/// HTML body and/or attachments. Not a general MIME parser: no nested
/// `message/rfc822` parts, no charset handling beyond UTF-8, and
/// quoted-printable decoding is a simplified pass (`=XX` hex escapes and
/// soft line breaks only).
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedMail {
    pub subject: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub plain_body: String,
    pub html_body: Option<String>,
    pub attachments: Vec<Attachment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// One MIME header, lowercase name plus the raw (unfolded) value.
struct Headers(Vec<(String, String)>);

impl Headers {
    fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

/// Splits `text` into its header block and remaining body, unfolding
/// continuation lines (RFC 2822 3.2.3: a line starting with whitespace
/// continues the previous header). The header/body boundary is the first
/// blank line (`\r\n\r\n` or `\n\n`); everything after it is the body
/// verbatim, with no further line-ending normalization.
fn parse_headers(text: &str) -> (Headers, &str) {
    // No headers at all: the message starts directly with the blank line
    // that would otherwise follow the last header.
    if let Some(rest) = text.strip_prefix("\r\n").or_else(|| text.strip_prefix('\n')) {
        return (Headers(Vec::new()), rest);
    }
    let split_at = find_blank_line(text).unwrap_or(text.len());
    let header_block = &text[..split_at];
    let body = text.get(split_at..).unwrap_or("");
    // Skip the blank line itself (either "\r\n\r\n" or "\n\n") so the body
    // doesn't start with a stray leading line break.
    let body = body
        .strip_prefix("\r\n\r\n")
        .or_else(|| body.strip_prefix("\n\n"))
        .or_else(|| body.strip_prefix("\r\n"))
        .or_else(|| body.strip_prefix('\n'))
        .unwrap_or(body);

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in header_block.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if (line.starts_with(' ') || line.starts_with('\t')) && !headers.is_empty() {
            let last = headers.last_mut().unwrap();
            last.1.push(' ');
            last.1.push_str(line.trim_start());
        } else if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }

    (Headers(headers), body)
}

/// Finds the byte offset of the first blank-line separator (`\r\n\r\n` or
/// `\n\n`), i.e. where the header block ends.
fn find_blank_line(text: &str) -> Option<usize> {
    text.find("\r\n\r\n").or_else(|| text.find("\n\n"))
}

/// Parses a `Content-Type`-style header into its main value and `key=value`
/// parameters (e.g. `multipart/mixed; boundary="abc"` -> `("multipart/mixed", {"boundary": "abc"})`).
fn parse_header_params(value: &str) -> (String, HashMap<String, String>) {
    let mut parts = value.split(';');
    let main = parts.next().unwrap_or("").trim().to_string();
    let mut params = HashMap::new();
    for part in parts {
        if let Some((k, v)) = part.split_once('=') {
            let v = v.trim().trim_matches('"').to_string();
            params.insert(k.trim().to_ascii_lowercase(), v);
        }
    }
    (main, params)
}

fn decode_quoted_printable(input: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'=' if i + 2 < bytes.len() && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' => {
                i += 3; // soft line break, drop it
            }
            b'=' if i + 1 < bytes.len() && bytes[i + 1] == b'\n' => {
                i += 2; // soft line break (bare LF variant)
            }
            b'=' if i + 2 < bytes.len() => {
                if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                    if let Ok(value) = u8::from_str_radix(hex, 16) {
                        out.push(value);
                        i += 3;
                        continue;
                    }
                }
                out.push(bytes[i]);
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    out
}

fn decode_body(encoding: Option<&str>, raw: &str) -> Vec<u8> {
    match encoding.map(|e| e.to_ascii_lowercase()) {
        Some(ref e) if e == "base64" => {
            let cleaned: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, cleaned).unwrap_or_default()
        }
        Some(ref e) if e == "quoted-printable" => decode_quoted_printable(raw),
        _ => raw.as_bytes().to_vec(),
    }
}

/// One decoded leaf part (not a `multipart/*` container).
struct LeafPart {
    content_type: String,
    filename: Option<String>,
    is_attachment: bool,
    data: Vec<u8>,
}

/// Recursively parses a MIME part's headers+body, flattening nested
/// `multipart/*` containers into their leaf parts.
fn parse_part(part_text: &str, out: &mut Vec<LeafPart>) {
    let (headers, body) = parse_headers(part_text);
    let content_type_header = headers.get("content-type").unwrap_or("text/plain");
    let (content_type, ct_params) = parse_header_params(content_type_header);

    if content_type.starts_with("multipart/") {
        let Some(boundary) = ct_params.get("boundary") else { return };
        for sub_part in split_on_boundary(body, boundary) {
            parse_part(sub_part, out);
        }
        return;
    }

    let (disposition, cd_params) = headers
        .get("content-disposition")
        .map(parse_header_params)
        .unwrap_or_else(|| (String::new(), HashMap::new()));
    let filename = cd_params
        .get("filename")
        .or_else(|| ct_params.get("name"))
        .cloned();
    let is_attachment = disposition.eq_ignore_ascii_case("attachment") || (filename.is_some() && !content_type.starts_with("text/"));

    let data = decode_body(headers.get("content-transfer-encoding"), body);
    out.push(LeafPart { content_type, filename, is_attachment, data });
}

/// Splits a multipart body on `--boundary` markers, returning each part's
/// raw text (headers+body, not yet parsed). Drops the preamble before the
/// first boundary and the epilogue after the closing `--boundary--`.
fn split_on_boundary<'a>(body: &'a str, boundary: &str) -> Vec<&'a str> {
    let marker = format!("--{boundary}");
    let mut parts = Vec::new();
    let mut rest = body;
    // Skip the preamble up to the first boundary marker.
    if let Some(idx) = rest.find(&marker) {
        rest = &rest[idx + marker.len()..];
    } else {
        return parts;
    }
    loop {
        match rest.find(&marker) {
            Some(idx) => {
                let part = &rest[..idx];
                let part = part.strip_prefix("\r\n").or_else(|| part.strip_prefix('\n')).unwrap_or(part);
                if !part.trim().is_empty() {
                    parts.push(part);
                }
                rest = &rest[idx + marker.len()..];
                // A closing boundary is immediately followed by "--".
                if rest.starts_with("--") {
                    break;
                }
            }
            None => break,
        }
    }
    parts
}

pub fn parse_rfc822(raw: &[u8]) -> ParsedMail {
    let text = String::from_utf8_lossy(raw);
    let (headers, body) = parse_headers(&text);

    let mut parsed = ParsedMail::default();
    if let Some(v) = headers.get("subject") {
        parsed.subject = v.to_string();
    }
    if let Some(v) = headers.get("to") {
        parsed.to = split_address_list(v);
    }
    if let Some(v) = headers.get("cc") {
        parsed.cc = split_address_list(v);
    }

    let content_type_header = headers.get("content-type").unwrap_or("text/plain");
    let (content_type, ct_params) = parse_header_params(content_type_header);

    let mut leaves = Vec::new();
    if content_type.starts_with("multipart/") {
        if let Some(boundary) = ct_params.get("boundary") {
            for sub_part in split_on_boundary(body, boundary) {
                parse_part(sub_part, &mut leaves);
            }
        }
    } else {
        let data = decode_body(headers.get("content-transfer-encoding"), body);
        leaves.push(LeafPart { content_type, filename: None, is_attachment: false, data });
    }

    for leaf in leaves {
        if leaf.is_attachment {
            parsed.attachments.push(Attachment {
                filename: leaf.filename.unwrap_or_else(|| "attachment".to_string()),
                content_type: leaf.content_type,
                data: leaf.data,
            });
        } else if leaf.content_type == "text/html" && parsed.html_body.is_none() {
            parsed.html_body = Some(String::from_utf8_lossy(&leaf.data).into_owned());
        } else if leaf.content_type == "text/plain" && parsed.plain_body.is_empty() {
            parsed.plain_body = String::from_utf8_lossy(&leaf.data).into_owned();
        }
    }

    parsed
}

fn split_address_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_simple_plain_text_message() {
        let raw = b"To: bob@afatyo.com\r\nSubject: Hello\r\n\r\nHi Bob,\r\nSee you tomorrow.";
        let parsed = parse_rfc822(raw);
        assert_eq!(parsed.subject, "Hello");
        assert_eq!(parsed.to, vec!["bob@afatyo.com".to_string()]);
        assert_eq!(parsed.plain_body, "Hi Bob,\r\nSee you tomorrow.");
        assert_eq!(parsed.html_body, None);
        assert!(parsed.attachments.is_empty());
    }

    #[test]
    fn splits_multiple_recipients_and_keeps_cc_separate() {
        let raw = b"To: bob@afatyo.com, carol@afatyo.com\r\nCc: dave@afatyo.com\r\nSubject: Team sync\r\n\r\nBody text";
        let parsed = parse_rfc822(raw);
        assert_eq!(parsed.to, vec!["bob@afatyo.com".to_string(), "carol@afatyo.com".to_string()]);
        assert_eq!(parsed.cc, vec!["dave@afatyo.com".to_string()]);
    }

    #[test]
    fn unfolds_a_continued_header_line() {
        let raw = b"Subject: This is a long subject\r\n that wraps onto a second line\r\n\r\nBody";
        let parsed = parse_rfc822(raw);
        assert_eq!(parsed.subject, "This is a long subject that wraps onto a second line");
    }

    #[test]
    fn missing_headers_default_to_empty() {
        let raw = b"\r\nJust a body, no headers";
        let parsed = parse_rfc822(raw);
        assert_eq!(parsed.subject, "");
        assert!(parsed.to.is_empty());
        assert_eq!(parsed.plain_body, "Just a body, no headers");
    }

    #[test]
    fn parses_multipart_alternative_with_plain_and_html() {
        let raw = concat!(
            "Subject: Alt test\r\n",
            "Content-Type: multipart/alternative; boundary=\"B1\"\r\n",
            "\r\n",
            "--B1\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "Plain version\r\n",
            "--B1\r\n",
            "Content-Type: text/html\r\n",
            "\r\n",
            "<p>HTML version</p>\r\n",
            "--B1--\r\n",
        )
        .as_bytes();

        let parsed = parse_rfc822(raw);
        assert_eq!(parsed.plain_body.trim_end(), "Plain version");
        assert_eq!(parsed.html_body.as_deref().map(|s| s.trim_end()), Some("<p>HTML version</p>"));
    }

    #[test]
    fn parses_multipart_mixed_with_html_and_base64_attachment() {
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"hello attachment content");
        let raw = format!(
            concat!(
                "Subject: Attach test\r\n",
                "Content-Type: multipart/mixed; boundary=\"B2\"\r\n",
                "\r\n",
                "--B2\r\n",
                "Content-Type: text/html\r\n",
                "\r\n",
                "<p>Hello HTML body</p>\r\n",
                "--B2\r\n",
                "Content-Type: text/plain; name=\"note.txt\"\r\n",
                "Content-Disposition: attachment; filename=\"note.txt\"\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "{b64}\r\n",
                "--B2--\r\n",
            ),
            b64 = b64
        );

        let parsed = parse_rfc822(raw.as_bytes());
        assert_eq!(parsed.html_body.as_deref().map(|s| s.trim_end()), Some("<p>Hello HTML body</p>"));
        assert_eq!(parsed.attachments.len(), 1);
        assert_eq!(parsed.attachments[0].filename, "note.txt");
        assert_eq!(parsed.attachments[0].data, b"hello attachment content");
    }

    #[test]
    fn decodes_quoted_printable_plain_body() {
        let raw = concat!(
            "Subject: QP test\r\n",
            "Content-Type: text/plain\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "Caf=C3=A9 and a soft break=\r\n continues here",
        )
        .as_bytes();
        let parsed = parse_rfc822(raw);
        assert_eq!(parsed.plain_body, "Café and a soft break continues here");
    }
}
