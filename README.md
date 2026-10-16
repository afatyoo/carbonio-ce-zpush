# carbonio-ce-zpush

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-v1.0.0-brightgreen.svg)](CHANGELOG.md)

An ActiveSync (Exchange protocol) connector for **Zextras Carbonio CE**, written in Rust. It lets ActiveSync clients (Android Mail/Gmail, iOS Mail, classic Outlook, and anything else that speaks EAS) sync email, contacts, and calendar against Carbonio CE without any PHP runtime on the mail server.

Rewritten from scratch, inspired by [imanudin11/zimbra-zpush](https://github.com/imanudin11/zimbra-zpush) (the original PHP z-push with a Zimbra backend). None of the original PHP code lives in this repo. Everything here is the Rust implementation in [`rust/`](rust/).

## Why this exists

The original z-push + Zimbra backend is roughly 100,000 lines of PHP, most of it for backends (Kopano, LDAP, CalDAV, CardDAV, maildir) this project never touches. Running it means a PHP runtime, a web server, and a vendored dependency tree living on the mail server just to speak one protocol.

This project targets Carbonio CE specifically and ships as one static binary:

- **No PHP on the host.** `cargo build` produces a single binary. Copy it to the server, run it, done.
- **A binary WBXML parser reading untrusted bytes gets typed errors, not silent corruption.** Every ActiveSync command body is raw bytes from a phone or Outlook client. [`wbxml.rs`](rust/src/wbxml.rs) returns a `Result` at every decode step, so a truncated or malformed stream is something the caller has to handle, not a guess.
- **The compiler catches codepage mismatches before a device does.** [`codepages.rs`](rust/src/codepages.rs) defines each WBXML tag once, and a test checks every encode/decode table agrees on the same token for the same tag name. A wrong tag code fails `cargo test`, not three weeks later when a specific client refuses to render Inbox.
- **One process handles many devices without per-request process cost.** Tokio runs every open sync session as an async task in one process.

## Status

Feature-complete for the targeted MS-ASCMD command set and verified end-to-end against a real device (Android's Gmail and Calendar apps) through a public HTTPS reverse proxy, not just hand-built WBXML on localhost. See [CHANGELOG.md](CHANGELOG.md) for the full list of what's implemented, what got fixed along the way, and what's still a known limitation.

Commands implemented: `FolderSync`, `Sync` (email, contacts, calendar, with real delta sync), `SendMail`, `Provision`, `Ping`, `GetItemEstimate`, `ItemOperations`/`Fetch`, `MoveItems`, `ResolveRecipients`, `Settings`, `Search`.

## Installation

### Requirements

- A running Carbonio CE instance you have SOAP/HTTPS access to.
- [Rust](https://www.rust-lang.org/tools/install) (stable toolchain) to build from source. There are no prebuilt binaries yet, so you build this directly on (or for) the machine that will run it.
- The machine running this server needs network access to Carbonio's SOAP endpoint, and ActiveSync clients need HTTPS access to this server (see [Exposing it to real devices](#exposing-it-to-real-devices) below if you don't already have TLS in front of it).

### 1. Clone and build

```bash
git clone https://github.com/afatyoo/carbonio-ce-zpush.git
cd carbonio-ce-zpush/rust
cargo build --release
```

The binary lands at `target/release/carbonio-ce-zpush`. Run `cargo test` first if you want to confirm the build is healthy on your machine. It needs no network access or live Carbonio instance.

### 2. Get Carbonio's TLS certificate

Carbonio CE ships a self-signed certificate with a 5-year validity period, which both `rustls`/`webpki` and macOS's `Security.framework` reject as exceeding the CA/Browser Forum's maximum leaf certificate lifetime. Pick **one** of these:

**Pinning mode** (works around the validity-period rejection, the common case for Carbonio's own self-signed cert):

```bash
mkdir -p certs
scp root@<your-carbonio-host>:/opt/zextras/ssl/carbonio/server/server.crt certs/server.pem
```

**CA-chain mode** (if Carbonio is behind a certificate your system already trusts, or you've replaced its self-signed cert):

```bash
mkdir -p certs
scp root@<your-carbonio-host>:/opt/zextras/ssl/carbonio/ca/ca.pem certs/ca.pem
```

Certificates are not committed to this repo (`rust/certs/*.pem` is gitignored, since it identifies your server). Fetch them from your own Carbonio host as shown above.

### 3. Configure and run

```bash
export CARBONIO_URL="https://<your-carbonio-host>"
export LISTEN_ADDR="0.0.0.0:7272"                    # default shown, change the port if needed

# TLS trust: match whichever certificate you fetched in step 2
export CARBONIO_PINNED_CERT="certs/server.pem"       # pinning mode
# export CARBONIO_CA_PEM="certs/ca.pem"              # CA-chain mode (use this one instead if you went that route)

# Only needed if Carbonio's certificate names a hostname with no real DNS record for it:
export CARBONIO_TLS_HOSTNAME="ce-example.yourdomain.com"
export CARBONIO_TLS_IP="192.168.x.x"

# Optional: persist SyncKeys across restarts, so devices don't get forced into a fresh resync every time this restarts.
export SYNC_STATE_PATH="sync_state.json"

./target/release/carbonio-ce-zpush
```

Once it's running, confirm it answers on the ActiveSync path:

```bash
curl -i -X OPTIONS http://localhost:7272/Microsoft-Server-ActiveSync
```

A healthy response includes `MS-ASProtocolVersions` and `MS-ASProtocolCommands` headers.

### 4. Run it as a service

For anything beyond local testing, run the binary under a process supervisor so it survives reboots and crashes. A minimal `systemd` unit:

```ini
[Unit]
Description=carbonio-ce-zpush ActiveSync connector
After=network.target

[Service]
ExecStart=/opt/carbonio-ce-zpush/carbonio-ce-zpush
Environment=CARBONIO_URL=https://your-carbonio-host
Environment=CARBONIO_PINNED_CERT=/opt/carbonio-ce-zpush/server.pem
Environment=LISTEN_ADDR=0.0.0.0:7272
Environment=SYNC_STATE_PATH=/opt/carbonio-ce-zpush/sync_state.json
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Save it as `/etc/systemd/system/carbonio-ce-zpush.service`, then:

```bash
systemctl daemon-reload
systemctl enable --now carbonio-ce-zpush
systemctl status carbonio-ce-zpush
```

### 5. Point a device at it

ActiveSync clients expect HTTPS, and this server only speaks plain HTTP on `LISTEN_ADDR`. It expects a reverse proxy to terminate TLS in front of it. See [Exposing it to real devices](#exposing-it-to-real-devices) below for the setup this project was tested against. Once that's in place, add an "Exchange"/"ActiveSync" account on the device with:

- **Server**: your reverse proxy's public hostname
- **Username / Email**: the Carbonio account's own address
- **Password**: the Carbonio account's own password

## Exposing it to real devices

ActiveSync clients require HTTPS, which this server doesn't terminate itself (`LISTEN_ADDR` is plain HTTP only, on purpose. TLS termination is a reverse proxy's job, not this project's). The setup this was verified against:

```
Real device (Gmail app, etc.)
  -> https://<your-subdomain> (valid Let's Encrypt cert)
  -> nginx reverse proxy, on a separate public host
  -> WireGuard tunnel
  -> this server's plain-HTTP LISTEN_ADDR, on the private network with Carbonio
```

- A public-facing host runs nginx with a `certbot`-issued certificate for a subdomain, reverse-proxying `/Microsoft-Server-ActiveSync` to this server's address.
- This server reaches that host over a WireGuard tunnel (as the client side, with `PersistentKeepalive` if it's behind NAT), so the public host can reach it without exposing your private network directly.
- This server itself keeps running as a normal plain-HTTP service, same as [step 3](#3-configure-and-run) above. The reverse proxy is the only thing handling TLS.

None of this is specific to Carbonio or this project. It's the standard shape for exposing any internal HTTP service to a real ActiveSync client without that service needing its own public IP or certificate.

## Architecture

| Module | Responsibility |
|---|---|
| `src/carbonio.rs` | SOAP/JSON client to Carbonio CE (`urn:zimbraAccount`, `urn:zimbraMail`) |
| `src/tls_pinning.rs` | Custom `rustls` certificate verifier for pinned-cert mode |
| `src/wbxml.rs` | WBXML binary codec (encode/decode), codepage-table driven |
| `src/codepages.rs` | WBXML codepage token tables (AirSync, Email, Contacts, Calendar, FolderHierarchy, ItemEstimate, ItemOperations, Ping, Provision, Move, ResolveRecipients, Search, Settings, AirSyncBase, ComposeMail) and Carbonio→ActiveSync folder type mapping |
| `src/sync_state.rs` | SyncKey store, per (user, device, collection), with optional JSON-file persistence |
| `src/mime_lite.rs` | RFC 822 + MIME multipart parser for `SendMail` bodies (plain/HTML/attachments) |
| `src/activesync_http.rs` | ActiveSync HTTP framing: Basic Auth header, `Cmd`/`User`/`DeviceId`/`DeviceType` query parsing |
| `src/server.rs` | `axum` HTTP server, command dispatch |

## Contributing

Bug reports, fixes, and new MS-ASCMD commands are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and note that everyone participating in this project is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE) © Muhammad Afatyo Ikhsan
