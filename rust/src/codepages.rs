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
pub const PAGE_MOVE: u8 = 0x05;
pub const PAGE_RESOLVERECIPIENTS: u8 = 0x0A;
pub const PAGE_SEARCH: u8 = 0x0F;
pub const PAGE_PING: u8 = 0x0D;
pub const PAGE_PROVISION: u8 = 0x0E;
pub const PAGE_ITEMOPERATIONS: u8 = 0x14;
pub const PAGE_SETTINGS: u8 = 0x12;
pub const PAGE_AIRSYNCBASE: u8 = 0x11;
pub const PAGE_COMPOSEMAIL: u8 = 0x15;

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

/// Calendar (codepage 4) tags, [MS-ASWBXML] 2.1.2.4. `AllDayEvent`/
/// `EndTime`/`Location`/`Subject`/`StartTime` were the only ones this
/// project ever needed to *read* (for the server->device direction), so
/// that's all it originally defined. A real device's own client-created
/// event (confirmed live with Android's Calendar app, a `Sync`
/// `Commands/Add`) carries several more fields in the same
/// `ApplicationData` block this project now also needs to *decode*
/// end-to-end, even for fields it doesn't act on -- a single unknown
/// token anywhere aborts the whole message's decode. The extra tokens
/// below are named from their position in the real captured bytes and
/// content shape (a timezone blob, ISO timestamps, an organizer email
/// matching the sender, a busy-status enum value, etc.), not otherwise
/// used by this project.
const CALENDAR_TAGS: &[(u8, &str)] = &[
    (0x05, "Timezone"),
    (0x06, "AllDayEvent"),
    (0x0D, "BusyStatus"),
    (0x11, "DtStamp"),
    (0x12, "EndTime"),
    (0x17, "Location"),
    (0x18, "MeetingStatus"),
    (0x19, "OrganizerEmail"),
    (0x1A, "OrganizerName"),
    (0x24, "Reminder"),
    (0x25, "Sensitivity"),
    (0x26, "Subject"),
    (0x27, "StartTime"),
    (0x28, "UID"),
];

/// Email (codepage 2) tags, [MS-ASWBXML] 2.1.2.3. Minimal field set for a
/// readable message list. Attachments and the message body are carried
/// through the real AirSyncBase codepage instead (`AIRSYNCBASE_TAGS`);
/// this page's own deprecated pre-12.0 `Attachment`/`Attachments`/
/// `AttName`/`AttSize`/`AttOid`/`AttMethod`/`Body` fields aren't used.
const EMAIL_TAGS: &[(u8, &str)] = &[
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

/// ItemEstimate (codepage 6) tags, [MS-ASWBXML] 2.1.2.6. Cross-checked
/// against the original PHP z-push's `lib/wbxml/wbxmldefs.php` (the fork
/// this project was rewritten from): every token here was off by one
/// (0x06 "Collections" was actually sitting on the deprecated/unused
/// "Version" slot, cascading everything after it), which would have broken
/// `GetItemEstimate` against any real device despite round-tripping fine
/// in this project's own self-consistent encode/decode tests.
const ITEMESTIMATE_TAGS: &[(u8, &str)] = &[
    (0x05, "GetItemEstimate"),
    (0x07, "Collections"),
    (0x08, "Collection"),
    (0x09, "Class"),
    (0x0A, "CollectionId"),
    (0x0C, "Estimate"),
    (0x0D, "Response"),
    (0x0E, "Status"),
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
];

/// ItemOperations (codepage 20) tags, [MS-ASWBXML] 2.1.2.20. Cross-checked
/// against the original PHP z-push's `wbxmldefs.php`: every token here now
/// matches the real spec exactly. `ServerId`/`CollectionId` for a Fetch
/// target, and `FileReference`/`ContentType`/`Data` for the fetched
/// content itself, all come from other codepages a real device actually
/// uses (AirSync and AirSyncBase respectively -- see `AIRSYNCBASE_TAGS`),
/// not self-contained tokens on this page, which is what this project
/// originally invented and which would have failed to decode a real
/// device's request.
const ITEMOPERATIONS_TAGS: &[(u8, &str)] = &[
    (0x05, "ItemOperations"),
    (0x06, "Fetch"),
    (0x07, "Store"),
    (0x08, "Options"),
    (0x0B, "Properties"),
    (0x0C, "Data"),
    (0x0D, "Status"),
    (0x0E, "Response"),
];

/// AirSyncBase (codepage 17) tags, [MS-ASWBXML] 2.1.2.17 (since EAS 12.0).
/// Cross-checked against the original PHP z-push's `wbxmldefs.php`. This
/// is the modern home for email bodies and attachments; this project used
/// to carry both through the deprecated pre-12.0 Email-codepage fields
/// (`EMAIL_TAGS`'s own `Attachment`/`Attachments`/`AttName`/.../`Body`),
/// which a real device built against a current EAS client version won't
/// look for. Minimal subset: no `BodyPart`/`Preview`/inline-body support.
///
/// `BodyPreference`/`Type`/`TruncationSize`/`AllOrNone` were missing here
/// until a real device's actual `Sync` request surfaced a hard decode
/// failure: every real ActiveSync client puts a `BodyPreference` block
/// inside `Sync`'s `Options` to say what body format/truncation it wants,
/// something none of this project's own hand-built WBXML test requests
/// happened to include, so the gap stayed invisible until a real Android
/// Mail client's request hit it (confirmed live via raw body logging).
const AIRSYNCBASE_TAGS: &[(u8, &str)] = &[
    (0x05, "BodyPreference"),
    (0x06, "Type"),
    (0x07, "TruncationSize"),
    (0x08, "AllOrNone"),
    (0x0A, "Body"),
    (0x0B, "Data"),
    (0x0C, "EstimatedDataSize"),
    (0x0D, "Truncated"),
    (0x0E, "Attachments"),
    (0x0F, "Attachment"),
    (0x10, "DisplayName"),
    (0x11, "FileReference"),
    (0x12, "Method"),
    (0x17, "ContentType"),
];

/// ComposeMail (codepage 21) tags, [MS-ASWBXML] 2.1.2.21 (since EAS 14.0),
/// cross-checked against the original PHP z-push's `wbxmldefs.php`. This
/// is how a real EAS 14.0+ device actually sends `SendMail`: the whole
/// RFC 822 message is embedded as `OPAQUE` binary content inside `MIME`,
/// wrapped in a WBXML envelope on this codepage -- not posted as raw RFC
/// 822 text directly, which is what this project originally assumed and
/// which only worked for its own hand-built test requests. Confirmed live
/// capturing a real Android Gmail `SendMail` request. Minimal subset: no
/// `SmartForward`/`SmartReply`/`ReplaceMime`/source-item fields, since
/// this project only composes new messages, it doesn't forward or reply
/// to an existing one via this path.
const COMPOSEMAIL_TAGS: &[(u8, &str)] = &[
    (0x05, "SendMail"),
    (0x08, "SaveInSentItems"),
    (0x10, "MIME"),
    (0x11, "ClientId"),
    (0x12, "Status"),
];

/// Move (codepage 5) tags, [MS-ASWBXML] 2.1.2.5. NOTE: like
/// `ITEMESTIMATE_TAGS`, reproduced from memory and not re-checked against
/// the published spec text or a real device.
const MOVE_TAGS: &[(u8, &str)] = &[
    (0x05, "MoveItems"),
    (0x06, "Move"),
    (0x07, "SrcMsgId"),
    (0x08, "SrcFldId"),
    (0x09, "DstFldId"),
    (0x0A, "Response"),
    (0x0B, "Status"),
    (0x0C, "DstMsgId"),
];

/// ResolveRecipients (codepage 10) tags, [MS-ASWBXML] 2.1.2.10. Minimal
/// subset: no certificate or picture support. Cross-checked against the
/// original PHP z-push's `wbxmldefs.php`: `To` really is part of this
/// codepage at 0x10, not self-contained as this project originally assumed
/// (it was invented at 0x13, a real collision with the spec's own
/// `MaxAmbiguousRecipients`).
const RESOLVERECIPIENTS_TAGS: &[(u8, &str)] = &[
    (0x05, "ResolveRecipients"),
    (0x06, "Response"),
    (0x07, "Status"),
    (0x08, "Type"),
    (0x09, "Recipient"),
    (0x0A, "DisplayName"),
    (0x0B, "EmailAddress"),
    (0x10, "To"),
    (0x12, "RecipientCount"),
];

/// Search (codepage 15) tags, [MS-ASWBXML] 2.1.2.15. Minimal subset: one
/// flat free-text query against a single mailbox collection, no boolean
/// query trees (`And`/`Or`/`LessThan`/etc.), no GAL search. Same
/// unverified-against-spec caveat as `ITEMESTIMATE_TAGS`.
const SEARCH_TAGS: &[(u8, &str)] = &[
    (0x05, "Search"),
    (0x07, "Store"),
    (0x08, "Name"),
    (0x09, "Query"),
    (0x0B, "Range"),
    (0x0C, "Status"),
    (0x0D, "Response"),
    (0x0E, "Result"),
    // Cross-checked against the original PHP z-push's `wbxmldefs.php`:
    // this codepage really does define its own `Properties`, this
    // project had wrongly routed a `Search` result's `Properties` through
    // the ItemOperations codepage instead.
    (0x0F, "Properties"),
    (0x10, "Total"),
];

/// Settings (codepage 18) tags, [MS-ASWBXML] 2.1.2.18. Minimal subset: just
/// enough to accept a `DeviceInformation` `Set` and answer an `Oof` `Get`
/// with "out of office is off". No real per-device settings storage, no
/// Oof message editing. Cross-checked against the original PHP z-push's
/// `wbxmldefs.php`: `DeviceInformation` is really at 0x16 (this project
/// had invented 0x0D, which is actually `OofMessage` in the real spec).
const SETTINGS_TAGS: &[(u8, &str)] = &[
    (0x05, "Settings"),
    (0x06, "Status"),
    (0x07, "Get"),
    (0x08, "Set"),
    (0x09, "Oof"),
    (0x0A, "OofState"),
    (0x16, "DeviceInformation"),
];

/// ActiveSync folder type codes (MS-ASCMD 2.2.3.165.1), cross-checked
/// against the original PHP z-push's `zpushdefs.php`. There's a real
/// distinction this project got wrong before: `2` means "the one true
/// default Inbox", not "any mail folder" -- every default/special folder
/// has its own code, and only a folder the user created themselves gets
/// one of the generic "User*" codes.
pub mod folder_type {
    pub const OTHER: &str = "1";
    pub const INBOX: &str = "2";
    pub const DRAFTS: &str = "3";
    pub const WASTEBASKET: &str = "4";
    pub const SENTMAIL: &str = "5";
    pub const APPOINTMENT: &str = "8";
    pub const CONTACT: &str = "9";
    pub const USER_MAIL: &str = "12";
    pub const USER_APPOINTMENT: &str = "13";
    pub const USER_CONTACT: &str = "14";
}

/// Maps a Carbonio folder to an ActiveSync folder type. Carbonio/Zimbra
/// assigns the standard mail/system folders the same fixed ids on every
/// account (`2`=Inbox, `3`=Trash, `5`=Sent, `6`=Drafts, `7`=Contacts,
/// `10`=Calendar -- confirmed against this project's own live folder
/// listings), which this project didn't use before: every `view="message"`
/// folder (Inbox, Sent, Drafts, Trash, Junk, Archive, custom folders, all
/// of them) was reported as type `2` (Inbox). A real device doesn't expect
/// more than one folder claiming to be the default Inbox, and a mature EAS
/// client (confirmed live against the Gmail app) can get stuck in a
/// permanent resync loop -- never settling into a steady Ping-based
/// state -- when the folder list is this inconsistent with itself.
pub fn activesync_folder_type(folder_id: &str, view: Option<&str>) -> &'static str {
    match folder_id {
        "2" => return folder_type::INBOX,
        "3" => return folder_type::WASTEBASKET,
        "5" => return folder_type::SENTMAIL,
        "6" => return folder_type::DRAFTS,
        "7" => return folder_type::CONTACT,
        "10" => return folder_type::APPOINTMENT,
        _ => {}
    }
    match view {
        Some("appointment") => folder_type::USER_APPOINTMENT,
        Some("contact") => folder_type::USER_CONTACT,
        Some("message") | None => folder_type::USER_MAIL,
        Some(_) => folder_type::OTHER,
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
pub fn airsyncbase_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_AIRSYNCBASE, AIRSYNCBASE_TAGS)
}
pub fn airsyncbase_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_AIRSYNCBASE, AIRSYNCBASE_TAGS)
}
pub fn composemail_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_COMPOSEMAIL, COMPOSEMAIL_TAGS)
}
pub fn composemail_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_COMPOSEMAIL, COMPOSEMAIL_TAGS)
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
pub fn move_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_MOVE, MOVE_TAGS)
}
pub fn move_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_MOVE, MOVE_TAGS)
}
pub fn resolverecipients_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_RESOLVERECIPIENTS, RESOLVERECIPIENTS_TAGS)
}
pub fn resolverecipients_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_RESOLVERECIPIENTS, RESOLVERECIPIENTS_TAGS)
}
pub fn search_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_SEARCH, SEARCH_TAGS)
}
pub fn search_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_SEARCH, SEARCH_TAGS)
}
pub fn settings_decode_table() -> HashMap<u8, HashMap<u8, &'static str>> {
    build_decode_table(PAGE_SETTINGS, SETTINGS_TAGS)
}
pub fn settings_encode_table() -> HashMap<u8, HashMap<&'static str, u8>> {
    build_encode_table(PAGE_SETTINGS, SETTINGS_TAGS)
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
    fn maps_user_created_folders_by_view() {
        assert_eq!(activesync_folder_type("312", Some("appointment")), folder_type::USER_APPOINTMENT);
        assert_eq!(activesync_folder_type("13", Some("contact")), folder_type::USER_CONTACT);
        assert_eq!(activesync_folder_type("312", Some("message")), folder_type::USER_MAIL);
        assert_eq!(activesync_folder_type("312", None), folder_type::USER_MAIL);
    }

    #[test]
    fn unknown_view_falls_back_to_generic() {
        assert_eq!(activesync_folder_type("312", Some("document")), folder_type::OTHER);
    }

    #[test]
    fn maps_carbonios_fixed_system_folder_ids_to_their_own_distinct_types() {
        // Carbonio/Zimbra assigns these ids to the same system folders on
        // every account (confirmed live): only Inbox should ever be type 2.
        assert_eq!(activesync_folder_type("2", Some("message")), folder_type::INBOX);
        assert_eq!(activesync_folder_type("3", None), folder_type::WASTEBASKET);
        assert_eq!(activesync_folder_type("5", Some("message")), folder_type::SENTMAIL);
        assert_eq!(activesync_folder_type("6", Some("message")), folder_type::DRAFTS);
        assert_eq!(activesync_folder_type("7", Some("contact")), folder_type::CONTACT);
        assert_eq!(activesync_folder_type("10", Some("appointment")), folder_type::APPOINTMENT);
        // Junk (id 4) and anything else aren't special-cased -- they fall
        // back to the generic per-view mapping, same as a user's own
        // folders.
        assert_eq!(activesync_folder_type("4", Some("message")), folder_type::USER_MAIL);
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
            (move_decode_table(), move_encode_table()),
            (resolverecipients_decode_table(), resolverecipients_encode_table()),
            (search_decode_table(), search_encode_table()),
            (settings_decode_table(), settings_encode_table()),
            (airsyncbase_decode_table(), airsyncbase_encode_table()),
            (composemail_decode_table(), composemail_encode_table()),
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
