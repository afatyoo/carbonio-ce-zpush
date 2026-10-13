use std::collections::HashMap;

/// WBXML codepage 0: AirSync. Token values per [MS-ASWBXML] section 2.1.2.1.
pub const PAGE_AIRSYNC: u8 = 0x00;
/// WBXML codepage 7: FolderHierarchy. Token values per [MS-ASWBXML] section 2.1.2.8.
pub const PAGE_FOLDERHIERARCHY: u8 = 0x07;

/// Tag names used by the FolderSync command and response, mapped to their
/// FolderHierarchy codepage tokens.
const FOLDERHIERARCHY_TAGS: &[(u8, &str)] = &[
    (0x05, "Folders"),
    (0x06, "Folder"),
    (0x07, "DisplayName"),
    (0x08, "ServerId"),
    (0x09, "ParentId"),
    (0x0A, "Type"),
    (0x0B, "Response"),
    (0x0C, "Status"),
    (0x0E, "Changes"),
    (0x0F, "Add"),
    (0x10, "Remove"),
    (0x11, "Update"),
    (0x12, "SyncKey"),
    (0x13, "FolderCreate"),
    (0x14, "FolderDelete"),
    (0x15, "FolderUpdate"),
    (0x16, "FolderSync"),
    (0x17, "Count"),
];

/// ActiveSync folder type codes (MS-ASCMD 2.2.3.165.1) for the Carbonio/Zimbra
/// folder "view" attribute values we map to a FolderSync `<Type>`.
pub mod folder_type {
    pub const USER_GENERIC: &str = "1";
    pub const USER_MAILBOX: &str = "2";
    pub const USER_CALENDAR: &str = "8";
    pub const USER_CONTACTS: &str = "14";
    pub const USER_TASKS: &str = "7";
}

/// Maps a Carbonio/Zimbra `<folder view="...">` attribute to an ActiveSync
/// folder type. Folders without a recognized view (e.g. a plain subfolder)
/// default to generic email so they still show up rather than being dropped.
pub fn activesync_folder_type(view: Option<&str>) -> &'static str {
    match view {
        Some("appointment") => folder_type::USER_CALENDAR,
        Some("contact") => folder_type::USER_CONTACTS,
        Some("task") => folder_type::USER_TASKS,
        Some("message") | None => folder_type::USER_MAILBOX,
        Some(_) => folder_type::USER_GENERIC,
    }
}

pub fn folderhierarchy_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    let mut page = HashMap::new();
    for (token, name) in FOLDERHIERARCHY_TAGS {
        page.insert(*token, *name);
    }
    let mut pages = HashMap::new();
    pages.insert(PAGE_FOLDERHIERARCHY, page);
    pages
}

pub fn folderhierarchy_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    let mut page = HashMap::new();
    for (token, name) in FOLDERHIERARCHY_TAGS {
        page.insert(*name, *token);
    }
    let mut pages = HashMap::new();
    pages.insert(PAGE_FOLDERHIERARCHY, page);
    pages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_carbonio_views_to_activesync_types() {
        assert_eq!(activesync_folder_type(Some("appointment")), folder_type::USER_CALENDAR);
        assert_eq!(activesync_folder_type(Some("contact")), folder_type::USER_CONTACTS);
        assert_eq!(activesync_folder_type(Some("task")), folder_type::USER_TASKS);
        assert_eq!(activesync_folder_type(Some("message")), folder_type::USER_MAILBOX);
        assert_eq!(activesync_folder_type(None), folder_type::USER_MAILBOX);
    }

    #[test]
    fn unknown_view_falls_back_to_generic() {
        assert_eq!(activesync_folder_type(Some("document")), folder_type::USER_GENERIC);
    }

    #[test]
    fn encode_and_decode_tables_are_inverse_of_each_other() {
        let decode = folderhierarchy_decode_table();
        let encode = folderhierarchy_encode_table();
        let decode_page = &decode[&PAGE_FOLDERHIERARCHY];
        let encode_page = &encode[&PAGE_FOLDERHIERARCHY];
        for (token, name) in decode_page {
            assert_eq!(encode_page.get(name), Some(token));
        }
    }
}
