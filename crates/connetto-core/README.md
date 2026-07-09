# connetto-core

Shared wire protocol, framing, and I/O trait signatures for the connetto-rs sync stack. Every other crate in the workspace, server and client alike, depends on this one and only this one for its shared vocabulary.

The crate defines two top-level enums, `ControlMessage` and `BulkMessage`, that together cover every frame exchanged between a connetto server and its clients. Control frames carry structured metadata (handshake, subscribe, mutation header, error, keepalive) as uncompressed MessagePack. Bulk frames carry SQLite patchsets and schema blobs whose payload bytes are already Zstd-compressed by the sender. The `codec` module serialises those types with `rmp-serde` and, when the transport lacks its own message boundary, wraps each payload in a `u32` big-endian length header.

The `traits` module defines the seams `connetto-server`, `connetto-client`, and `connetto-client-wasm` each fill: `Transport` for the wire, `Store` for local persistence, `FileStore` for content-addressed chunks, and `AuthPolicy` for the OpenFGA-backed authorization checks. Nothing here reaches for a runtime, a socket, or a database. All that lives in the consumer crates.

See `docs/architecture/` at the workspace root for the full protocol design, and `open-questions.md` for the decision index that names each field and message.
