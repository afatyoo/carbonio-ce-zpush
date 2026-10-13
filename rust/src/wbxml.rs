use anyhow::{bail, Result};
use std::collections::HashMap;

/// WBXML global tokens we care about (WAP Binary XML, used to wrap every
/// ActiveSync command body). See [MS-ASWBXML].
const SWITCH_PAGE: u8 = 0x00;
const END: u8 = 0x01;
const STR_I: u8 = 0x03;
const LITERAL: u8 = 0x04;

/// Minimum WBXML version/header bytes z-push and real devices send:
/// version 1.3 (0x03), unknown public id (0x01), UTF-8 charset (0x6A),
/// zero-length string table (0x00).
const WBXML_VERSION: u8 = 0x03;
const PUBLIC_ID_UNKNOWN: u8 = 0x01;
const CHARSET_UTF8: u8 = 0x6A;

/// One decoded WBXML node: a tag (possibly with children) or a text run.
#[derive(Debug, Clone, PartialEq)]
pub enum WbxmlNode {
    Tag {
        name: String,
        children: Vec<WbxmlNode>,
    },
    Text(String),
}

/// Decodes a WBXML byte stream into a tree, resolving tag tokens against the
/// given codepage tables (codepage -> token -> tag name).
pub struct WbxmlDecoder<'a> {
    data: &'a [u8],
    pos: usize,
    codepages: &'a HashMap<u8, HashMap<u8, &'static str>>,
}

impl<'a> WbxmlDecoder<'a> {
    pub fn new(data: &'a [u8], codepages: &'a HashMap<u8, HashMap<u8, &'static str>>) -> Self {
        Self { data, pos: 0, codepages }
    }

    fn read_byte(&mut self) -> Result<u8> {
        let byte = *self.data.get(self.pos).ok_or_else(|| anyhow::anyhow!("unexpected end of WBXML stream"))?;
        self.pos += 1;
        Ok(byte)
    }

    fn read_mb_uint32(&mut self) -> Result<u32> {
        let mut value: u32 = 0;
        loop {
            let byte = self.read_byte()?;
            value = (value << 7) | (byte & 0x7F) as u32;
            if byte & 0x80 == 0 {
                break;
            }
        }
        Ok(value)
    }

    fn read_str_i(&mut self) -> Result<String> {
        let start = self.pos;
        while self.data.get(self.pos).copied() != Some(0x00) {
            if self.pos >= self.data.len() {
                bail!("unterminated inline string in WBXML stream");
            }
            self.pos += 1;
        }
        let s = String::from_utf8_lossy(&self.data[start..self.pos]).into_owned();
        self.pos += 1; // consume the NUL terminator
        Ok(s)
    }

    /// Parses the 4-byte WBXML header and the (here, always empty) string table.
    fn parse_header(&mut self) -> Result<()> {
        let version = self.read_byte()?;
        if version != WBXML_VERSION {
            bail!("unsupported WBXML version byte: 0x{version:02X}");
        }
        let _public_id = self.read_byte()?;
        let _charset = self.read_byte()?;
        let str_table_len = self.read_mb_uint32()?;
        self.pos += str_table_len as usize;
        Ok(())
    }

    /// Decodes the body into a list of sibling top-level nodes.
    pub fn decode(&mut self) -> Result<Vec<WbxmlNode>> {
        self.parse_header()?;
        let mut current_page: u8 = 0;
        self.decode_nodes(&mut current_page)
    }

    fn decode_nodes(&mut self, current_page: &mut u8) -> Result<Vec<WbxmlNode>> {
        let mut nodes = Vec::new();
        loop {
            if self.pos >= self.data.len() {
                break;
            }
            let byte = self.data[self.pos];
            if byte == END {
                self.pos += 1;
                break;
            }
            if byte == SWITCH_PAGE {
                self.pos += 1;
                *current_page = self.read_byte()?;
                continue;
            }
            if byte == STR_I {
                self.pos += 1;
                let text = self.read_str_i()?;
                nodes.push(WbxmlNode::Text(text));
                continue;
            }
            if byte == LITERAL {
                bail!("LITERAL tag tokens are not supported by this decoder");
            }

            self.pos += 1;
            let has_content = byte & 0x40 != 0;
            let token = byte & 0x3F;
            let name = self
                .codepages
                .get(current_page)
                .and_then(|page| page.get(&token))
                .ok_or_else(|| anyhow::anyhow!("unknown tag token 0x{token:02X} on codepage {current_page}"))?
                .to_string();

            let children = if has_content {
                self.decode_nodes(current_page)?
            } else {
                Vec::new()
            };
            nodes.push(WbxmlNode::Tag { name, children });
        }
        Ok(nodes)
    }
}

/// Encodes a WBXML tree back into bytes, using the given codepage lookup
/// (codepage -> tag name -> token) and emitting codepage switches as needed.
pub struct WbxmlEncoder<'a> {
    out: Vec<u8>,
    codepages: &'a HashMap<u8, HashMap<&'static str, u8>>,
    current_page: u8,
}

impl<'a> WbxmlEncoder<'a> {
    pub fn new(codepages: &'a HashMap<u8, HashMap<&'static str, u8>>) -> Self {
        Self { out: Vec::new(), codepages, current_page: 0 }
    }

    fn write_header(&mut self) {
        self.out.push(WBXML_VERSION);
        self.out.push(PUBLIC_ID_UNKNOWN);
        self.out.push(CHARSET_UTF8);
        self.out.push(0x00); // empty string table
    }

    fn write_str_i(&mut self, text: &str) {
        self.out.push(STR_I);
        self.out.extend_from_slice(text.as_bytes());
        self.out.push(0x00);
    }

    fn resolve_token(&self, page: u8, name: &str) -> Result<u8> {
        self.codepages
            .get(&page)
            .and_then(|p| p.get(name))
            .copied()
            .ok_or_else(|| anyhow::anyhow!("no WBXML token registered for tag '{name}' on codepage {page}"))
    }

    /// Caller must supply which codepage each tag lives on via `page_of`,
    /// since that mapping is specific to each ActiveSync XML schema (AirSync,
    /// Email, Contacts, ...).
    pub fn encode(mut self, nodes: &[WbxmlNode], page_of: &impl Fn(&str) -> u8) -> Result<Vec<u8>> {
        self.write_header();
        self.encode_nodes(nodes, page_of)?;
        Ok(self.out)
    }

    fn encode_nodes(&mut self, nodes: &[WbxmlNode], page_of: &impl Fn(&str) -> u8) -> Result<()> {
        for node in nodes {
            match node {
                WbxmlNode::Text(text) => self.write_str_i(text),
                WbxmlNode::Tag { name, children } => {
                    let page = page_of(name);
                    if page != self.current_page {
                        self.out.push(SWITCH_PAGE);
                        self.out.push(page);
                        self.current_page = page;
                    }
                    let token = self.resolve_token(page, name)?;
                    let has_content = !children.is_empty();
                    let byte = if has_content { token | 0x40 } else { token };
                    self.out.push(byte);
                    if has_content {
                        self.encode_nodes(children, page_of)?;
                        self.out.push(END);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Codepage 0 = AirSync, minimal subset used by FolderSync/Sync.
    fn airsync_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
        let mut page0 = HashMap::new();
        page0.insert(0x05, "Sync");
        page0.insert(0x06, "Responses");
        page0.insert(0x07, "Add");
        page0.insert(0x08, "Change");
        page0.insert(0x09, "Delete");
        page0.insert(0x0D, "Collections");
        page0.insert(0x0E, "Collection");
        page0.insert(0x0F, "Class");
        page0.insert(0x10, "Version");
        page0.insert(0x11, "CollectionId");
        let mut pages = HashMap::new();
        pages.insert(0, page0);
        pages
    }

    fn airsync_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
        let decode = airsync_decode_table();
        let mut encode = HashMap::new();
        for (page, tokens) in decode {
            let mut inverted = HashMap::new();
            for (token, name) in tokens {
                inverted.insert(name, token);
            }
            encode.insert(page, inverted);
        }
        encode
    }

    #[test]
    fn round_trips_a_folder_sync_like_body() {
        // <Sync><Collections><Collection><CollectionId>5</CollectionId></Collection></Collections></Sync>
        let tree = vec![WbxmlNode::Tag {
            name: "Sync".into(),
            children: vec![WbxmlNode::Tag {
                name: "Collections".into(),
                children: vec![WbxmlNode::Tag {
                    name: "Collection".into(),
                    children: vec![WbxmlNode::Tag {
                        name: "CollectionId".into(),
                        children: vec![WbxmlNode::Text("5".into())],
                    }],
                }],
            }],
        }];

        let encode_table = airsync_encode_table();
        let encoded = WbxmlEncoder::new(&encode_table)
            .encode(&tree, &|_name| 0u8)
            .expect("encoding should succeed");

        let decode_table = airsync_decode_table();
        let decoded = WbxmlDecoder::new(&encoded, &decode_table)
            .decode()
            .expect("decoding should succeed");

        assert_eq!(decoded, tree);
    }

    #[test]
    fn decoder_rejects_unsupported_version() {
        let decode_table = airsync_decode_table();
        let bad = vec![0x02, 0x01, 0x6A, 0x00, END];
        let err = WbxmlDecoder::new(&bad, &decode_table).decode().unwrap_err();
        assert!(err.to_string().contains("unsupported WBXML version"));
    }

    #[test]
    fn decoder_reports_unknown_tag_token() {
        let decode_table = airsync_decode_table();
        // header + a tag byte for an unregistered token (0x3A) with no content, then END.
        let stream = vec![WBXML_VERSION, PUBLIC_ID_UNKNOWN, CHARSET_UTF8, 0x00, 0x3A];
        let err = WbxmlDecoder::new(&stream, &decode_table).decode().unwrap_err();
        assert!(err.to_string().contains("unknown tag token"));
    }
}
