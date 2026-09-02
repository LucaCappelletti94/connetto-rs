# connetto-file-core

[![Tests](https://github.com/LucaCappelletti94/connetto-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/connetto-rs/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/connetto-rs/blob/main/LICENSE)
[![docs.rs](https://docs.rs/connetto-file-core/badge.svg)](https://docs.rs/connetto-file-core)
[![crates.io](https://img.shields.io/crates/v/connetto-file-core.svg)](https://crates.io/crates/connetto-file-core)

Platform-neutral file core for connetto-rs. A file's identity is the BLAKE3 hash of its raw bytes, computed in the same pass as `FastCDC` chunking. The manifest records the ordered (hash, length) pairs for each chunk. The `ChunkStore` trait addresses storage by plaintext chunk hash; `EncryptingStore` wraps any store and adds per-chunk zstd compression followed by XChaCha20-Poly1305 encryption, transparently to callers of `process_file` and `reassemble`.

```rust
use connetto_file_core::{
    MimeClass, MemStore, EncryptingStore, process_file, reassemble,
};

let data: Vec<u8> = b"ATGCATGCATGCATGCATGC".iter().copied().cycle().take(512).collect();
let root_key = [0u8; 32];
let store = EncryptingStore::new(MemStore::new(), &root_key);

let manifest = process_file(&data, MimeClass::Fasta, &store).unwrap();
let recovered = reassemble(&manifest, &store).unwrap();
assert_eq!(data, recovered);
```
