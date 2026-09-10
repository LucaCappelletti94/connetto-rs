# connetto-file-client

[![Tests](https://github.com/LucaCappelletti94/connetto-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/connetto-rs/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/connetto-rs/blob/main/LICENSE)
[![docs.rs](https://docs.rs/connetto-file-client/badge.svg)](https://docs.rs/connetto-file-client)
[![crates.io](https://img.shields.io/crates/v/connetto-file-client.svg)](https://crates.io/crates/connetto-file-client)

The local encrypted chunk store, the upload outbox, and the content resolver for connetto-rs. Metadata travels as ordinary synced rows and content travels here.

`ContentClient::attach` adds file handling to a running `ConnettoClient`. `stage` chunks a file into the store and commits its manifest in the same transaction as the application row that names it, offline or not. `flush_outbox` uploads what is waiting, under a write ticket the websocket mints. `resolve` answers where a file's bytes are: a short-lived signed URL in the common case, local bytes when the content is unsent or pinned, and `Unavailable` when neither this device nor a server can produce them. `pin_content` keeps a query's files on the device and `tidy_content` reclaims what nothing covers.

In a dedicated browser worker, `BrowserStore` uses an account-isolated `OPFS` namespace and falls back to worker-lifetime memory when persistence or atomic moves are unavailable. `BrowserHttp` supplies the same protocol through `fetch`. `connetto-web` exposes local bytes through reference-counted object URLs and revokes each URL when its last owner drops.

Device archives include only unsent content as plaintext `content/manifests.json` metadata and deduplicated `content/chunks/<hash>` entries. Import verifies chunk lengths, chunk hashes, and file identities before encrypting chunks under the receiving key and committing application rows, manifests, and outbox entries together.

The store itself is the piece that runs without a server, and it is the same one the client uses:

```rust
use connetto_file_client::FsStore;
use connetto_file_core::{ChunkStore, EncryptingStore, MimeClass, process_file, reassemble};

# let dir = tempfile::tempdir().unwrap();
# tokio::runtime::Runtime::new().unwrap().block_on(async {
let photo: Vec<u8> = b"JPEG-ish bytes".iter().copied().cycle().take(4096).collect();
let store = EncryptingStore::new_with(
    FsStore::new(dir.path()),
    &[7u8; 32],
    MimeClass::Jpeg.params().skip_compression,
);

let manifest = process_file(&photo, MimeClass::Jpeg, &store).await.unwrap();
assert_eq!(reassemble(&manifest, &store).await.unwrap(), photo);

// Chunk files hold ciphertext, while uploads carry hash-verifiable plaintext.
let on_disk = std::fs::read(
    dir.path()
        .join(&manifest.chunks()[0].hash.to_string()[..2])
        .join(manifest.chunks()[0].hash.to_string()),
)
.unwrap();
assert_ne!(on_disk, photo);
# });
```

## What lives where

The manifests, the upload outbox and the content pins are three `_connetto_content_*` tables in the replica, not in the device-private tier. The replica is opened `journal_mode=WAL` before the tier is attached, so the two are separate files and SQLite's cross-file atomic commit does not apply: a transaction over both commits with no error while a host crash may update one and not the other. The invariant that a row never outlives its manifest needs one file.

Chunk files live outside SQLite, one per chunk, encrypted with XChaCha20-Poly1305 under a key derived from the same custody the replica's key comes from, so the unlock gate and crypto-shred-on-wipe cover content exactly as they cover rows.

## Reading

`docs/architecture/18-file-handling.md` is normative. The R67 section of `plans/master-implementation-plan.md` records the decisions this crate implements, each with its rejected alternatives.
