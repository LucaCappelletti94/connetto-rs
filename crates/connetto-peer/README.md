# connetto-peer

[![Tests](https://github.com/LucaCappelletti94/connetto-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/connetto-rs/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/connetto-rs/blob/main/LICENSE)
[![Coverage](https://codecov.io/gh/LucaCappelletti94/connetto-rs/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/connetto-rs)

The mutual TLS link between certified devices. A `Node` presents one device's certificate and key and dials or accepts other certified devices over TLS 1.3. Every chain verifies against the roots the deployment ships, the attestation levels the device accepts, and the revocation lists it keeps, behind the wall clock a `Clock` supplies. Links carry a small frame protocol for liveness pings and revocation lists the peer lacks, close under the silence bound, and a deterministic duplicate rule keeps one link per peer key when both sides dial at once.

```rust
use std::net::SocketAddr;
use std::sync::Arc;

use connetto_core::device_cert::{DeviceKey, DeviceKeyError, KeyHome};
use connetto_peer::{CloseReason, Identity, Node, SystemClock, Trust};
use tokio::sync::mpsc;

/// A key that signs nothing, enough to hold an identity.
struct Dummy;

impl DeviceKey for Dummy {
    fn public_point(&self) -> [u8; 65] {
        [0; 65]
    }

    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
        Err(DeviceKeyError::Unavailable)
    }

    fn home(&self) -> KeyHome {
        KeyHome::Software
    }
}

# let runtime = tokio::runtime::Runtime::new().expect("a runtime");
# runtime.block_on(async {
let (events, _rx) = mpsc::unbounded_channel();
let trust = Trust {
    roots: Vec::new(),
    accepted: Default::default(),
};
let node = Node::new(trust, Arc::new(SystemClock), events);
let identity = Identity {
    certificate: Vec::new(),
    issuer: Vec::new(),
    key: Arc::new(Dummy),
};
let listen: SocketAddr = "127.0.0.1:0".parse().expect("a loopback address");
let bound = node.serve(listen, identity).expect("the listener binds");
assert_eq!(node.local_addr(), Some(bound));
node.stop(CloseReason::Closed);
# });
```
