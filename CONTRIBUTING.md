# Contributing

Thanks for considering a contribution. This project is a Rust rewrite of z-push targeting Carbonio CE specifically, not a generic ActiveSync server framework; keep that scope in mind when proposing changes.

## Before you start

Everyone participating in this project is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

For anything beyond a small fix, open an issue first describing what you want to change and why. This avoids spending time on a pull request that doesn't fit the project's direction.

## Reporting a bug

Open a GitHub issue with:

- The ActiveSync command involved (`Sync`, `SendMail`, etc.), if known.
- The client that triggered it (device/app and, if you have it, its user agent string).
- Server logs around the time it happened, if you have access to them.
- Raw request bytes, if you're able to capture them — several real bugs in this project were only found this way (see [CHANGELOG.md](CHANGELOG.md)'s "Fixed" sections for examples), and a hex dump of the actual WBXML body is the fastest way to pin one down.

## Making a change

1. Fork the repo and create a branch from `main`.
2. Make your change in `rust/src/`.
3. Add a test. If you're fixing a decode or protocol bug, prefer a regression test using real captured bytes over a hand-built one — this project's own hand-built WBXML test requests have repeatedly missed gaps that only a real device's actual request shape exposed. See the existing tests in `server.rs`/`carbonio.rs` named `decodes_a_real_*` for the pattern.
4. Run the full test suite:

   ```bash
   cd rust
   cargo test
   ```

5. If your change affects the protocol layer (`wbxml.rs`, `codepages.rs`) or a SOAP call shape (`carbonio.rs`), say in your pull request description whether you verified it against a live Carbonio instance, a real device, or neither. Cross-checking against the original PHP z-push's `wbxmldefs.php`/`zpushdefs.php` is also useful context to include if you did it.
6. Open a pull request describing what changed and why.

## Code style

- Follow the existing code's doc-comment style: explain *why* a piece of code exists the way it does, especially for anything discovered the hard way against a real device, not just *what* it does.
- Don't add abstractions or configuration for cases this project doesn't actually need yet (see [Why this exists](README.md#why-this-exists) for the project's own reasoning about scope).
- Run `cargo fmt` and address `cargo build`'s warnings before opening a pull request.

## What's out of scope

Non-Carbonio backends, admin CLI tooling, and legacy device compatibility quirks from the original z-push project are intentionally not being ported. If you need one of those, the [original PHP project](https://github.com/imanudin11/zimbra-zpush) still has it.
