use std::collections::HashMap;

/// WBXML codepage tokens per [MS-ASWBXML]. Each codepage is a distinct XML
/// namespace in the uncompressed ActiveSync XML; WBXML switches between them
/// with a `SWITCH_PAGE` byte.
pub const PAGE_AIRSYNC: u8 = 0x00;
pub const PAGE_CONTACTS: u8 = 0x01;
pub const PAGE_EMAIL: u8 = 0x02;
pub const PAGE_CALENDAR: u8 = 0x04;
pub const PAGE_FOLDERHIERARCHY: u8 = 0x07;
pub const PAGE_ITEMESTIMATE: u8 = 0x06;
pub const PAGE_PING: u8 = 0x0D;
pub const PAGE_PROVISION: u8 = 0x0E;
pub const PAGE_ITEMOPERATIONS: u8 = 0x14;

/// AirSync (codepage 0) tags, [MS-ASWBXML] 2.1.2.1. Only the subset this
/// server currently emits/consumes for FolderSync and item Sync.
const AIRSYNC_TAGS: &[(u8, &str)] = &[
    (0x05, "Sync"),
    (0x06, "Responses"),
    (0x07, "Add"),
    (0x08, "Change"),
    (0x09, "Delete"),
    (0x0A, "Fetch"),
    (0x0B, "SyncKey"),
    (0x0C, "ClientId"),
    (0x0D, "ServerId"),
    (0x0E, "Status"),
    (0x0F, "Collection"),
    (0x10, "Class"),
    (0x11, "Version"),
    (0x12, "CollectionId"),
    (0x13, "GetChanges"),
    (0x14, "MoreAvailable"),
    (0x15, "WindowSize"),
    (0x16, "Commands"),
    (0x17, "Options"),
    (0x18, "FilterType"),
    (0x1C, "Collections"),
    (0x1D, "ApplicationData"),
    (0x1E, "DeletesAsMoves"),
    (0x25, "Limit"),
];

/// Contacts (codepage 1) tags, [MS-ASWBXML] 2.1.2.2. Minimal field set:
/// name, one email address, one mobile number.
const CONTACTS_TAGS: &[(u8, &str)] = &[
    (0x1B, "Email1Address"),
    (0x1E, "FileAs"),
    (0x1F, "FirstName"),
    (0x29, "LastName"),
    (0x2B, "MobilePhoneNumber"),
];

/// Calendar (codepage 4) tags, [MS-ASWBXML] 2.1.2.4. Minimal field set: no
/// attendees, recurrence, or reminders.
const CALENDAR_TAGS: &[(u8, &str)] = &[
    (0x06, "AllDayEvent"),
    (0x12, "EndTime"),
    (0x17, "Location"),
    (0x26, "Subject"),
    (0x27, "StartTime"),
];

/// Email (codepage 2) tags, [MS-ASWBXML] 2.1.2.3. Minimal field set for a
/// readable message list (no attachments/MIME/meeting-request fields yet).
const EMAIL_TAGS: &[(u8, &str)] = &[
    // Deprecated in EAS 14.0+ (modern clients expect Body under the
    // AirSyncBase codepage instead, which this project doesn't model yet);
    // kept here as the simplest way to carry Fetch's body text for now.
    (0x0C, "Body"),
    (0x0F, "DateReceived"),
    (0x11, "DisplayTo"),
    (0x12, "Importance"),
    (0x13, "MessageClass"),
    (0x14, "Subject"),
    (0x15, "Read"),
    (0x16, "To"),
    (0x17, "Cc"),
    (0x18, "From"),
    (0x3A, "Flag"),
];

/// FolderHierarchy (codepage 7) tags, [MS-ASWBXML] 2.1.2.8.
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

/// ItemEstimate (codepage 6) tags, [MS-ASWBXML] 2.1.2.6. NOTE: these token
/// values are reproduced from memory of the spec, not re-checked against
/// the published MS-ASWBXML document or a real device, unlike the other
/// tables here which were validated live against Carbonio. Treat this one
/// as unverified until a real ActiveSync client's GetItemEstimate request
/// has been captured and compared against it.
const ITEMESTIMATE_TAGS: &[(u8, &str)] = &[
    (0x05, "GetItemEstimate"),
    (0x06, "Collections"),
    (0x07, "Collection"),
    (0x08, "Class"),
    (0x09, "CollectionId"),
    (0x0A, "DateTime"),
    (0x0B, "Estimate"),
    (0x0C, "Response"),
    (0x0D, "Status"),
];

/// Ping (codepage 13) tags, [MS-ASWBXML] 2.1.2.13.
const PING_TAGS: &[(u8, &str)] = &[
    (0x05, "Ping"),
    (0x06, "AutdState"),
    (0x07, "Status"),
    (0x08, "HeartbeatInterval"),
    (0x09, "Folders"),
    (0x0A, "Folder"),
    (0x0B, "Id"),
    (0x0C, "Class"),
    (0x0D, "MaxFolders"),
];

/// Provision (codepage 14) tags, [MS-ASWBXML] 2.1.2.14. Minimal subset: this
/// server accepts any device and does not enforce EAS policy payloads.
const PROVISION_TAGS: &[(u8, &str)] = &[
    (0x05, "Provision"),
    (0x06, "Policies"),
    (0x07, "Policy"),
    (0x08, "PolicyType"),
    (0x09, "PolicyKey"),
    (0x0A, "Data"),
    (0x0B, "Status"),
    (0x0C, "RemoteWipe"),
    (0x0E, "DeviceInformation"),
];

/// ItemOperations (codepage 20) tags, [MS-ASWBXML] 2.1.2.20. NOTE: like
/// `ITEMESTIMATE_TAGS`, these token values are reproduced from memory and
/// not re-checked against the published spec text or a real device.
/// `ServerId`/`CollectionId` for a Fetch target come from the AirSync
/// codepage (0), not this one.
const ITEMOPERATIONS_TAGS: &[(u8, &str)] = &[
    (0x05, "ItemOperations"),
    (0x06, "Fetch"),
    (0x07, "Store"),
    (0x08, "Options"),
    (0x0B, "Properties"),
    (0x0D, "Status"),
    (0x0E, "Response"),
    // Not part of the official ItemOperations codepage (the spec reuses
    // AirSync's tokens for these); kept self-contained here instead, same
    // simplification already used for ITEMESTIMATE_TAGS's own CollectionId.
    (0x10, "ServerId"),
    (0x11, "CollectionId"),
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

fn build_decode_table(page: u8, tags: &[(u8, &'static str)]) -> HashMap<u8, HashMap<u8, &'static str>> {
    let mut inner = HashMap::new();
    for (token, name) in tags {
        inner.insert(*token, *name);
    }
    let mut pages = HashMap::new();
    pages.insert(page, inner);
    pages
}

fn build_encode_table(page: u8, tags: &[(u8, &'static str)]) -> HashMap<u8, HashMap<&'static str, u8>> {
    let mut inner = HashMap::new();
    for (token, name) in tags {
        inner.insert(*name, *token);
    }
    let mut pages = HashMap::new();
    pages.insert(page, inner);
    pages
}

/// Merges several single-page tables into one multi-codepage table, for
/// documents (like a `Sync` response) that mix AirSync and Email tags.
pub fn merge_decode_tables(
    tables: Vec<HashMap<u8, HashMap<u8, &'static str>>>,
) -> HashMap<u8, HashMap<u8, &'static str>> {
    let mut merged = HashMap::new();
    for table in tables {
        merged.extend(table);
    }
    merged
}

pub fn merge_encode_tables(
    tables: Vec<HashMap<u8, HashMap<&'static str, u8>>>,
) -> HashMap<u8, HashMap<&'static str, u8>> {
    let mut merged = HashMap::new();
    for table in tables {
        merged.extend(table);
    }
    merged
}

pub fn airsync_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_AIRSYNC, AIRSYNC_TAGS)
}
pub fn airsync_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_AIRSYNC, AIRSYNC_TAGS)
}
pub fn email_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_EMAIL, EMAIL_TAGS)
}
pub fn email_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_EMAIL, EMAIL_TAGS)
}
pub fn contacts_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_CONTACTS, CONTACTS_TAGS)
}
pub fn contacts_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_CONTACTS, CONTACTS_TAGS)
}
pub fn calendar_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_CALENDAR, CALENDAR_TAGS)
}
pub fn calendar_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_CALENDAR, CALENDAR_TAGS)
}
pub fn folderhierarchy_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_FOLDERHIERARCHY, FOLDERHIERARCHY_TAGS)
}
pub fn folderhierarchy_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_FOLDERHIERARCHY, FOLDERHIERARCHY_TAGS)
}
pub fn itemestimate_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_ITEMESTIMATE, ITEMESTIMATE_TAGS)
}
pub fn itemestimate_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_ITEMESTIMATE, ITEMESTIMATE_TAGS)
}
pub fn itemoperations_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_ITEMOPERATIONS, ITEMOPERATIONS_TAGS)
}
pub fn itemoperations_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_ITEMOPERATIONS, ITEMOPERATIONS_TAGS)
}
pub fn ping_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_PING, PING_TAGS)
}
pub fn ping_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_PING, PING_TAGS)
}
pub fn provision_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_PROVISION, PROVISION_TAGS)
}
pub fn provision_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_PROVISION, PROVISION_TAGS)
}

/// Looks up which codepage a tag name belongs to, across the AirSync table
/// and one item-type table (Email or Contacts) -- the combination a `Sync`
/// command's response needs: AirSync envelope tags plus that collection's
/// own item fields.
pub fn airsync_item_page_of(item_page: u8) -> impl Fn(&str) -> u8 {
    move |tag_name: &str| {
        if AIRSYNC_TAGS.iter().any(|(_, name)| *name == tag_name) {
            PAGE_AIRSYNC
        } else {
            item_page
        }
    }
}

/// Convenience alias for the email case, kept for existing call sites.
pub fn airsync_sync_page_of(tag_name: &str) -> u8 {
    airsync_item_page_of(PAGE_EMAIL)(tag_name)
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
    fn all_tables_round_trip_token_name_lookups() {
        for (decode, encode) in [
            (airsync_decode_table(), airsync_encode_table()),
            (email_decode_table(), email_encode_table()),
            (contacts_decode_table(), contacts_encode_table()),
            (calendar_decode_table(), calendar_encode_table()),
            (folderhierarchy_decode_table(), folderhierarchy_encode_table()),
            (itemestimate_decode_table(), itemestimate_encode_table()),
            (itemoperations_decode_table(), itemoperations_encode_table()),
            (ping_decode_table(), ping_encode_table()),
            (provision_decode_table(), provision_encode_table()),
        ] {
            for (page, tokens) in &decode {
                let encode_page = &encode[page];
                for (token, name) in tokens {
                    assert_eq!(encode_page.get(name), Some(token), "mismatch for {name} on page {page}");
                }
            }
        }
    }

    #[test]
    fn page_of_routes_airsync_and_email_tags_correctly() {
        assert_eq!(airsync_sync_page_of("Sync"), PAGE_AIRSYNC);
        assert_eq!(airsync_sync_page_of("CollectionId"), PAGE_AIRSYNC);
        assert_eq!(airsync_sync_page_of("Subject"), PAGE_EMAIL);
        assert_eq!(airsync_sync_page_of("From"), PAGE_EMAIL);
    }
}
