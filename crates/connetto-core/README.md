# connetto-core

[![Coverage](https://codecov.io/gh/LucaCappelletti94/connetto-rs/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/connetto-rs)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/connetto-rs/blob/main/LICENSE)
[![docs.rs](https://docs.rs/connetto-core/badge.svg)](https://docs.rs/connetto-core)
[![crates.io](https://img.shields.io/crates/v/connetto-core.svg)](https://crates.io/crates/connetto-core)

Shared wire types, framing and I/O traits for the server, native client and browser client. `ControlMessage` carries uncompressed `MessagePack` metadata, while `BulkMessage` carries patchsets and schema payloads whose content is already compressed. The `codec` module adds a `u32` length prefix for byte-stream transports.

```rust
use connetto_core::codec::{decode_control_framed, encode_control_framed};
use connetto_core::messages::{ControlMessage, Ping};

let message = ControlMessage::Ping(Ping { nonce: 42 });
let frame = encode_control_framed(&message).expect("encode control frame");
let (decoded, consumed) = decode_control_framed(&frame).expect("decode control frame");
assert_eq!(decoded, message);
assert_eq!(consumed, frame.len());
```

The `traits` module defines transport, persistence and credential-storage boundaries. Optional features provide native `WebSocket` and loopback transports, device certificates and program logging.

The hosted API documentation and package badges resolve after the first release.
