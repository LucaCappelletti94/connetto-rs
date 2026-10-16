# connetto-peer-apple

[![Tests](https://github.com/LucaCappelletti94/connetto-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/connetto-rs/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/connetto-rs/blob/main/LICENSE)
[![Coverage](https://codecov.io/gh/LucaCappelletti94/connetto-rs/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/connetto-rs)

The Apple platform bridge for connetto's peer link (R76). `bluetooth` is the host's GATT service and its beacon advertisement, over one process-wide `CBPeripheralManager` on its one serial dispatch queue. `hotspot` is the joiner's `NEHotspotConfiguration` join over the system's shared manager, and its read of the network the device joined. `device_name` and `device_idiom` read `UIDevice` off the app's main queue. This is the workspace's second unsafe crate, and every `unsafe` block sits in its platform module.

Every public call hops onto the queue that owns its work, waited on at most [`HOP_WITHIN`], and the manager's delegate only pushes events into a shared list, so it never calls back into the public API. `notify` holds a frame the platform cannot take yet, and sends the held frames when the platform says it is ready. The platform's peripheral role cannot cancel a central's connection, so `disconnect` stands ready.

The platform answers the device's name only under the `com.apple.developer.device-information.user-assigned-device-name` entitlement, and its generic model name without it, which `device_name` reads as `None`. A WPA3 join asks the platform for its `setWPA3PersonalPassphrase:` selector, and answers `Missing` where the platform does not.

On every target but iOS and iPadOS the functions answer `Unsupported` or empty, and the device's idiom is `Other`.

```rust
assert!(connetto_peer_apple::device_name().is_none());
assert_eq!(connetto_peer_apple::device_idiom(), connetto_peer_apple::Idiom::Other);
assert!(matches!(
    connetto_peer_apple::bluetooth::state(),
    connetto_peer_apple::bluetooth::State::Unsupported
));
assert!(matches!(
    connetto_peer_apple::hotspot::completion(),
    None
));
```
