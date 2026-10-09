# The peer link's Android permissions

[![Tests](https://github.com/LucaCappelletti94/connetto-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/connetto-rs/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/connetto-rs/blob/main/LICENSE)
[![Coverage](https://codecov.io/gh/LucaCappelletti94/connetto-rs/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/connetto-rs)

The peer link needs two Android permissions: `CHANGE_WIFI_MULTICAST_STATE`, for the mDNS discovery that finds a peer's link, and `NEARBY_WIFI_DEVICES` (API 33 and later), for hosting and joining the local-only hotspot a peer dials through. This crate asks the operating system for whichever is missing and bundles the Kotlin module the rest of the peer link drives over JNI.

`request_peer_permissions` opens the prompt on the Activity, so it runs on the UI thread only. Off Android it does nothing.

```rust
// Off Android the prompt asks nothing, where the peer link's
// permissions do not exist.
connetto_peer_android::request_peer_permissions();
```
