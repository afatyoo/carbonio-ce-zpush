/// Minimal RFC 822/2822 message parser, enough to read what `SendMail`
/// bodies ActiveSync devices actually send for a plain text compose: a
/// header block, a blank line, then the body. Does not handle
/// multipart/MIME (HTML + attachments), which real mail clients often add;
/// a multipart body currently comes through as raw text in `body`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedMail {
    pub subject: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub body: String,
}

pub fn parse_rfc822(raw: &[u8]) -> ParsedMail {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.lines();
    let mut headers: Vec<String> = Vec::new();

    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        // Unfold header continuation lines (RFC 2822 3.2.3: a line starting
        // with whitespace continues the previous header).
        if (line.starts_with(' ') || line.starts_with('\t')) && !headers.is_empty() {
            let last = headers.last_mut().unwrap();
            last.push(' ');
            last.push_str(line.trim_start());
        } else {
            headers.push(line.to_string());
        }
    }

    let body = lines.collect::<Vec<_>>().join("\n");

    let mut parsed = ParsedMail { body, ..Default::default() };
    for header in &headers {
        let Some((name, value)) = header.split_once(':') else { continue };
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "subject" => parsed.subject = value.to_string(),
            "to" => parsed.to = split_address_list(value),
            "cc" => parsed.cc = split_address_list(value),
            _ => {}
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
        assert_eq!(parsed.body, "Hi Bob,\nSee you tomorrow.");
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
        assert_eq!(parsed.body, "Just a body, no headers");
    }
}
