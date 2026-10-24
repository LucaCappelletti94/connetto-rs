# connetto-peer-apple

[![Tests](https://github.com/connetto-rs/connetto-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/connetto-rs/connetto-rs/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/connetto-rs/connetto-rs/blob/main/LICENSE)
[![Coverage](https://codecov.io/gh/connetto-rs/connetto-rs/graph/badge.svg)](https://codecov.io/gh/connetto-rs/connetto-rs)

The Apple platform bridge for connetto's peer link (R76). `bluetooth` is the host's GATT service and its beacon advertisement, over one process-wide `CBPeripheralManager` on its one serial dispatch queue. On iOS and iPadOS the host serves the exchange, and on the Mac the manager stands the Bluetooth readiness alone, since the Mac never hosts (R76 decision 1). `hotspot` is the joiner's join of the offered network, the Network Extension's on iOS and `CoreWLAN`'s on the Mac by a directed scan and its association, and its read of the network the device joined. `device_name` and `device_idiom` read `UIDevice` off the app's main queue on iOS and iPadOS, and the Mac's hostname and `Other` on the Mac. This is the workspace's second unsafe crate, and every `unsafe` block sits in its platform module.

Every public call hops onto the queue that owns its work, waited on at most [`HOP_WITHIN`], and the manager's delegate only pushes events into a shared list, so it never calls back into the public API. `notify` holds a frame the platform cannot take yet, and sends the held frames when the platform says it is ready. The platform's peripheral role cannot cancel a central's connection, so `disconnect` stands ready. On the Mac the join runs on its own worker thread, the directed scan and the association blocking there, and a generation counter drops a stale worker's answer, whose late association a `leave` standing in between unwinds.

On iOS and iPadOS the platform answers the device's name only under the `com.apple.developer.device-information.user-assigned-device-name` entitlement, and its generic model name without it, which `device_name` reads as `None`. A WPA3 join asks the platform for its `setWPA3PersonalPassphrase:` selector, and answers `Missing` where the platform does not.

`discovery::Bonjour` advertises and browses `_connetto-peer._tcp` through the system's `dns_sd` service for `connetto-peer`'s discovery, since iOS lets an app send and receive raw multicast only under Apple's managed multicast entitlement. An app using it lists the service type in `NSBonjourServices` and sets `NSLocalNetworkUsageDescription`, without which iOS refuses every operation.

On every target but Apple the functions answer `Unsupported` or empty, and the device's idiom is `Other`.

```rust
#[cfg(not(any(target_os = "ios", target_os = "macos")))]
fn main() {
    assert!(connetto_peer_apple::device_name().is_none());
    assert_eq!(connetto_peer_apple::device_idiom(), connetto_peer_apple::Idiom::Other);
    assert!(matches!(
        connetto_peer_apple::bluetooth::state(),
        connetto_peer_apple::bluetooth::State::Unsupported
    ));
    assert!(matches!(connetto_peer_apple::hotspot::completion(), None));
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn main() {
    // The Apple targets stand the platform's live states.
}
```
