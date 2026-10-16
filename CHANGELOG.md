# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-16

First stable release. Feature-complete for the targeted MS-ASCMD command set,
cross-checked against the original PHP z-push source for codepage correctness,
and verified end-to-end against a real device (Android's Gmail/Calendar apps)
through a public HTTPS reverse proxy, not just hand-built WBXML on localhost.

### Added

- TLS client to Carbonio's SOAP endpoint, with certificate pinning to work
  around Carbonio's default self-signed cert (5-year validity, rejected by
  both rustls/webpki and macOS Security.framework as exceeding the CA/Browser
  Forum's max leaf validity).
- `AuthRequest` (`urn:zimbraAccount`): login with a user's own credentials.
- `GetFolderRequest` (`urn:zimbraMail`): fetch and flatten the mailbox folder
  tree.
- A WBXML binary codec (encode + decode), generic over codepage tables.
- The ActiveSync HTTP endpoint (`POST /Microsoft-Server-ActiveSync`) and an
  `OPTIONS` handshake response (`MS-ASProtocolVersions`/`MS-ASProtocolCommands`),
  which every real EAS client sends before its first `POST`.
- `FolderSync`, with real delta sync backed by Carbonio's own `SyncRequest`
  token (not a counter this project invented), tracked per (user, device)
  under a fixed `__folder_hierarchy__` collection id.
- `Sync` for email, contacts, and calendar events, each with real delta sync
  the same way, picking the right collection kind per folder automatically
  from Carbonio's own `view` attribute.
- `SendMail`: parses the device's RFC 822 body (including Android Gmail's
  WBXML-wrapped `ComposeMail`/`OPAQUE` envelope, see Fixed) and relays it to
  Carbonio via `SendMsgRequest`, including multipart HTML bodies and
  attachments (uploaded via Carbonio's REST `/service/upload`).
- `Sync` `Commands/Add` and `Commands/Change` handling: a calendar event
  created on the device is created in Carbonio via `CreateAppointmentRequest`
  and echoed back with its real `ServerId`; a message marked read/unread on
  the device is applied via `ItemActionRequest`.
- `Provision`: accepts any device so clients that refuse to sync without it
  can get past the handshake (no EAS policy enforcement -- no PIN,
  encryption, or remote wipe).
- `Ping`: genuinely blocks on Carbonio's `WaitSetRequest` long-poll, and its
  `Status 2` response reports exactly which watched folder changed (using
  each folder's own `i4ms` modification counter), not just that something did.
- `GetItemEstimate`, `ItemOperations`/`Fetch` for email bodies, attachments,
  contacts, and calendar events.
- `MoveItems`, with the real MS-ASCMD status table.
- `ResolveRecipients`, resolving every requested address against both
  Carbonio's GAL and personal Contacts.
- `Settings` (acknowledges `DeviceInformation`, answers a static Oof state)
  and `Search` (flat free-text search, no boolean query trees).
- Persistent SyncKey tracking, per (user, device, collection), snapshotted to
  a JSON file (`SYNC_STATE_PATH`) so a restart doesn't force every device
  into a fresh resync.

### Fixed

Everything below was found only through real-device testing (Android's
Gmail and Calendar apps, over the public internet through a real reverse
proxy), not reproducible with this project's own hand-built WBXML:

- **Missing `OPTIONS` handshake.** The router only had a `POST` route, so a
  real device's setup screen failed before any request reached this
  server's logs at all.
- **`BodyPreference` undecodable.** A real `Sync` request's `Options` block
  always includes `BodyPreference`, which the AirSyncBase codepage didn't
  define and `handle_sync`'s decode table never merged in anyway.
- **A permanent FolderSync resync loop.** Fetching attachment metadata via
  `GetMsgRequest` silently marked messages read by default, which bumped the
  folder's own change counter and made every SyncKey reset to "0" on every
  poll. Fixed with `markRead: "0"`.
- **Every mail folder reporting as the default Inbox** (ActiveSync folder
  type 2) because folder-type mapping only looked at a folder's `view`.
  Fixed using Carbonio's own fixed system-folder ids.
- **`SendMail`'s body going missing.** A real EAS 14.0+ client (Android
  Gmail) wraps the RFC 822 message as `OPAQUE` binary content inside a WBXML
  `ComposeMail` envelope, not raw RFC 822 text. Added `OPAQUE` codec support
  and a `ComposeMail` codepage to unwrap it.
- **Top-level folders never showing up in a real device's folder list.**
  `ParentId` was reported as Carbonio's own real root folder id instead of
  the synthetic `"0"` MS-ASCMD expects for "no parent, top level".
- **A real device's "mark message read" push 400ing outright**, which could
  stall its own sync pipeline, because `handle_sync`'s decode table never
  included the Email codepage.
- **Synced emails showing up with no body at all**, because body details
  were only ever fetched for messages already flagged as having an
  attachment.
- **Inconsistent missing email bodies.** Carbonio flags whichever MIME part
  comes first in a `multipart/alternative` as the message "body" regardless
  of whether it has real content; an HTML-only `SendMail` (this project's
  own plain-first `multipart/alternative` construction) ended up with its
  empty plain-text part flagged instead of the real HTML content next to it.
- **HTML-only message bodies still coming back empty**, because Carbonio's
  `GetMsgRequest` omits a part's `content` entirely unless `html: "1"` is
  passed, flipping which part it inlines.
- **Client-created calendar events never reaching Carbonio at all.**
  `handle_sync` processed the device's `Change` entries but never its `Add`
  entries, for any collection kind, while still answering `Status 1` with no
  `Responses` block -- so the device believed the create succeeded and never
  retried it.
- **A real client-created calendar event still failing to decode.** The
  Calendar codepage only ever defined the five fields this project needed to
  read in the other direction; a real device's own event carries several
  more (`Timezone`, `DtStamp`, `OrganizerEmail`, `BusyStatus`, `Reminder`,
  `Sensitivity`, `UID`).

### Known limitations

- **`Settings`' `Oof` is read-only.** Carbonio CE's self-service
  `ModifyPrefsRequest` returns success without actually changing
  `zimbraPrefOutOfOfficeReply*`, while an admin can write it directly via
  `zmprov`. Confirmed as a platform restriction (likely gated to the paid
  Advanced tier), not a wrong API call.
- **No Tasks support.** This Carbonio CE build has no Tasks folder at all
  and rejects `SearchRequest types=task` outright.
- **"New Outlook" (current Outlook for Mac/Windows) doesn't work with this
  server, and can't be made to.** It only ever speaks EWS, never falls back
  to ActiveSync. Implementing EWS is a different, much larger protocol,
  tracked as a possible future project.
- **`Provision` enforces no EAS policy** (no PIN, encryption, or remote wipe).
- **Calendar sync only carries a recurring event's first occurrence**, with
  no recurrence rule, attendees, or reminders.
- **No client-created contacts.** `Sync` `Commands/Add` is only handled for
  calendar events; a contact created on the device isn't pushed to Carbonio yet.

See the [README](README.md#architecture) for the module layout and
[real-device testing setup](README.md#real-device-testing-setup) this was
verified against.
