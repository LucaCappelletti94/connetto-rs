# connetto-client

[![Coverage](https://codecov.io/gh/connetto-rs/connetto-rs/graph/badge.svg)](https://codecov.io/gh/connetto-rs/connetto-rs)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/connetto-rs/connetto-rs/blob/main/LICENSE)
[![docs.rs](https://docs.rs/connetto-client/badge.svg)](https://docs.rs/connetto-client)
[![crates.io](https://img.shields.io/crates/v/connetto-client.svg)](https://crates.io/crates/connetto-client)

The native local-first sync client for connetto-rs, a transparent sync layer over a `connetto-server`. The application runs ordinary `diesel` queries against a managed local SQLite connection, and local writes are captured by a SQLite session and drained by `ConnettoConnection::push` into a compressed changeset that carries the old row image. Server patches apply on the same connection with capture suspended, so server-originated changes are never re-uploaded.

The server produces patches with `sqlite-diff-rs`, whose output is the native SQLite session patchset format, so `SqliteSessionExt::apply_patchset` applies them directly. The connection holds a raw SQLite handle, is `!Send`, and is driven from one task with `ConnettoConnection::pump_one`.

`NativeClientBuilder` connects a server URL and its `SyncSchema` anonymously or using a held credential. It is provided by the default `native-transport` feature. `ConnettoClient` provides a shared handle and typed live Diesel queries through `watch` while a background pump drives synchronization.

Optional features add `native-auth` for OAuth sign-in and OS keyring custody, `device-identity` for a device key, `peer` for a server-independent device link, `bot` for a registration signature, and `postgres-types` for aggregate decode of `Uuid` and `Timestamptz`.

The crate is version `0.0.0` and unpublished, so the hosted API documentation and package badges resolve after the first release.
