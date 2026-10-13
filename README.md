# carbonio-ce-zpush

ActiveSync (Exchange protocol) connector for **Zextras Carbonio CE**, being rewritten from the original PHP z-push + Zimbra backend into a standalone **Rust** server — no PHP runtime dependency.

Forked from [imanudin11/zimbra-zpush](https://github.com/imanudin11/zimbra-zpush) (PHP z-push with a Zimbra backend). The original PHP code is kept in the repo root for reference while the Rust rewrite (`rust/`) replaces it piece by piece.

## Status

Early, working foundation — not yet feature-complete. Verified end-to-end against a live Carbonio CE instance (`carbonio-core` 4.5.14):

- [x] TLS client to Carbonio's SOAP endpoint, with certificate pinning to work around Carbonio's default self-signed cert (5-year validity, rejected by both rustls/webpki and macOS Security.framework as exceeding the CA/Browser Forum's max leaf validity)
- [x] `AuthRequest` (`urn:zimbraAccount`) — login with a user's own credentials
- [x] `GetFolderRequest` (`urn:zimbraMail`) — fetch and flatten the mailbox folder tree
- [x] WBXML codec (encode + decode), generic over codepage tables
- [x] HTTP ActiveSync endpoint (`POST /Microsoft-Server-ActiveSync`) — Basic Auth, `Cmd`/`User`/`DeviceId`/`DeviceType` query parsing
- [x] `FolderSync` command — full round trip: device request → Carbonio auth → `GetFolderRequest` → WBXML response
- [ ] `Sync` (mail/calendar/contacts item sync), `Provision`, `Ping`, `SendMail`, `ItemOperations`, `GetItemEstimate`
- [ ] Persistent sync state (SyncKey tracking across requests — FolderSync currently always returns a fresh key, no delta sync yet)
- [ ] Non-mail folder types (Calendar/Contacts/Tasks item sync)

Everything else from the original z-push (non-Carbonio backends, admin CLI tooling, legacy IPC state machines, decade-old device compatibility quirks) is intentionally **not** being ported — this project targets Carbonio CE specifically, not generic ActiveSync-server-building.

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

# TLS trust — pick ONE:
export CARBONIO_CA_PEM="certs/ca.pem"               # normal CA-chain validation
# or, if Carbonio's self-signed cert is rejected for validity-period reasons:
export CARBONIO_PINNED_CERT="certs/server.pem"       # exact-byte-match pinning

# only needed if Carbonio's cert names a hostname with no real DNS record:
export CARBONIO_TLS_HOSTNAME="ce-example.yourdomain.com"
export CARBONIO_TLS_IP="192.168.x.x"

cargo run
```

Certificates are not committed (`rust/certs/*.pem` is gitignored, since it's server-identifying material) — copy them from the Carbonio host yourself, e.g.:

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
| `src/codepages.rs` | WBXML codepage token tables (AirSync, FolderHierarchy) and Carbonio→ActiveSync folder type mapping |
| `src/activesync_http.rs` | ActiveSync HTTP framing: Basic Auth header, `Cmd`/`User`/`DeviceId`/`DeviceType` query parsing |
| `src/server.rs` | `axum` HTTP server, command dispatch |

## Why Rust

The original z-push + Zimbra backend is ~100k lines of PHP across the full z-push core and every backend (including several — Kopano, LDAP, CalDAV, CardDAV, maildir — never used here). Rewriting *only* the ActiveSync protocol layer and a Carbonio-specific backend, as a single static binary with no runtime dependency, is the goal; full feature parity with the PHP original is a longer-term target, not a one-shot port.
