# carbonio-ce-zpush

ActiveSync (Exchange protocol) connector for **Zextras Carbonio CE**, being rewritten from the original PHP z-push + Zimbra backend into a standalone **Rust** server, dropping the PHP runtime dependency entirely.

Forked from [imanudin11/zimbra-zpush](https://github.com/imanudin11/zimbra-zpush) (PHP z-push with a Zimbra backend). All the original PHP code has been removed from this repo; everything here is the Rust rewrite (`rust/`). The PHP source is still available in the upstream repo if it's needed as a reference while porting a command this rewrite doesn't cover yet.

## Status

Early, working foundation, not yet feature-complete. Verified end-to-end against a live Carbonio CE instance (`carbonio-core` 4.5.14):

- [x] TLS client to Carbonio's SOAP endpoint, with certificate pinning to work around Carbonio's default self-signed cert (5-year validity, rejected by both rustls/webpki and macOS Security.framework as exceeding the CA/Browser Forum's max leaf validity)
- [x] `AuthRequest` (`urn:zimbraAccount`): login with a user's own credentials
- [x] `GetFolderRequest` (`urn:zimbraMail`): fetch and flatten the mailbox folder tree
- [x] WBXML codec (encode + decode), generic over codepage tables
- [x] HTTP ActiveSync endpoint (`POST /Microsoft-Server-ActiveSync`): Basic Auth, `Cmd`/`User`/`DeviceId`/`DeviceType` query parsing
- [x] `FolderSync` command: full round trip from device request, to Carbonio auth, to `GetFolderRequest`, to WBXML response
- [x] `SearchRequest` (`urn:zimbraMail`): list messages in a folder, newest first
- [x] `Sync` command for email: SyncKey "0" returns the current message list and a new key. The same key again returns Status 1 with no changes. A stale or unknown key returns Status 3 (invalid sync key, per MS-ASCMD 2.2.4), telling the device to sync again from scratch
- [x] `Provision`: accepts any device so clients that refuse to sync without it can get past the handshake. Does not enforce any EAS policy (no PIN, encryption, or remote wipe checks)
- [x] `Ping`: responds immediately with "no changes" instead of actually long-polling Carbonio for new mail, so devices poll in a loop rather than holding one open connection
- [x] Persistent SyncKey tracking, per (user, device, collection), snapshotted to a JSON file after every change (set `SYNC_STATE_PATH`) so a restart does not force every device into a fresh FolderSync. Verified across an actual process restart against the live server
- [x] `SendMsgRequest` (`urn:zimbraMail`): send an email through Carbonio
- [x] `SendMail` command: parses the device's raw RFC 822 body (headers + plain text, no multipart/MIME yet) and relays it to Carbonio. Verified end-to-end: sent a real message that landed in a live mailbox
- [x] `Sync` command for contacts: same SyncKey machinery as email, backed by `SearchRequest types=contact`. `Sync` picks email vs. contacts per collection automatically by checking that folder's Carbonio `view` via `GetFolderRequest`. Verified end-to-end against a real contact (name, email, mobile number)
- [ ] Calendar/Tasks item sync: `Sync`-ing one of these folders now returns an explicit `501 Not Implemented` (checked live) instead of silently returning nothing or wrong-shaped data, since there is no handler for them yet
- [ ] `ItemOperations`, `GetItemEstimate`
- [ ] HTML bodies and attachments in `SendMail` (multipart/MIME parsing)
- [ ] Real push: `Ping` needs a Carbonio-side change notification to actually block until new mail arrives
- [ ] FolderSync's own SyncKey is still hardcoded to "1" on every call, unlike the per-collection Sync command, which now tracks a real key

Everything else from the original z-push (non-Carbonio backends, admin CLI tooling, legacy IPC state machines, decade-old device compatibility quirks) is intentionally **not** being ported. This project targets Carbonio CE specifically, not generic ActiveSync server building.

## Building and running

```bash
cd rust
cargo build
cargo test
```

Run the server:

```bash
export CARBONIO_URL="https://<your-carbonio-host>"
export LISTEN_ADDR="0.0.0.0:7272"          # default shown

# TLS trust, pick ONE:
export CARBONIO_CA_PEM="certs/ca.pem"               # normal CA-chain validation
# or, if Carbonio's self-signed cert is rejected for validity-period reasons:
export CARBONIO_PINNED_CERT="certs/server.pem"       # exact-byte-match pinning

# only needed if Carbonio's cert names a hostname with no real DNS record:
export CARBONIO_TLS_HOSTNAME="ce-example.yourdomain.com"
export CARBONIO_TLS_IP="192.168.x.x"

cargo run
```

Optional: `export SYNC_STATE_PATH="sync_state.json"` to persist SyncKeys across restarts. Without it, state is in-memory only and every device starts from a fresh FolderSync whenever the process restarts.

Certificates are not committed (`rust/certs/*.pem` is gitignored, since it's server-identifying material). Copy them from the Carbonio host yourself, e.g.:

```bash
# CA-chain mode:
scp root@<carbonio-host>:/opt/zextras/ssl/carbonio/ca/ca.pem rust/certs/ca.pem
# Pinning mode (needed when the CA mode above fails validity-period checks):
scp root@<carbonio-host>:/opt/zextras/ssl/carbonio/server/server.crt rust/certs/server.pem
```

## Architecture

| Module | Responsibility |
|---|---|
| `src/carbonio.rs` | SOAP/JSON client to Carbonio CE (`urn:zimbraAccount`, `urn:zimbraMail`) |
| `src/tls_pinning.rs` | Custom `rustls` certificate verifier for pinned-cert mode |
| `src/wbxml.rs` | WBXML binary codec (encode/decode), codepage-table driven |
| `src/codepages.rs` | WBXML codepage token tables (AirSync, Email, Contacts, FolderHierarchy, Ping, Provision) and Carbonio→ActiveSync folder type mapping |
| `src/sync_state.rs` | SyncKey store, per (user, device, collection), with optional JSON-file persistence |
| `src/mime_lite.rs` | Minimal RFC 822 header/body parser for `SendMail` bodies |
| `src/activesync_http.rs` | ActiveSync HTTP framing: Basic Auth header, `Cmd`/`User`/`DeviceId`/`DeviceType` query parsing |
| `src/server.rs` | `axum` HTTP server, command dispatch (`FolderSync`, `Sync`, `Provision`, `Ping`, `SendMail`) |

## Why Rust

The original z-push + Zimbra backend is about 100,000 lines of PHP, split across the z-push core and backends for Kopano, LDAP, CalDAV, CardDAV, and maildir that this project never touches. We are not porting that. We are rewriting the ActiveSync protocol layer and a Carbonio-specific backend from scratch, and Rust fits this specific job for four reasons:

**No PHP on the host.** That was the original ask: stop installing a PHP runtime, a web server, and a vendor tree on the mail server just to speak ActiveSync. `cargo build` produces one static binary. Copy it to the server, run it, done. No php-fpm, no Composer, no Apache or nginx config dedicated to z-push.

**WBXML is a binary protocol parsed from untrusted input.** Every ActiveSync command body is raw bytes from a phone or Outlook client, and the parser has to walk tag tokens, codepage switches, and length-prefixed strings by hand. In PHP, a malformed byte sequence can corrupt state silently or crash the worker. In Rust, `wbxml.rs` returns a `Result` at every decode step, so a truncated or hostile WBXML stream is a typed error the caller has to handle, not a guess.

**The compiler catches protocol mismatches before a device does.** `codepages.rs` defines each WBXML tag once, and a test (`all_tables_round_trip_token_name_lookups`) checks that every encode table and decode table agree on the same token for the same tag name. Get a tag code wrong and the test fails at `cargo test`, not three weeks later when a specific iPhone build refuses to render Inbox.

**One process handles many devices without the PHP-FPM cost.** Every connected phone holds a sync session open. PHP-FPM's model is one process or thread per request. Tokio runs all of those sessions as async tasks in one process, so the number of devices scales without scaling worker processes.

Feature parity with the PHP original across every command is the long-term goal, not something this first pass claims.
