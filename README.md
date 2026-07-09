# connetto-rs

Transport and sync layer for keeping `SQLite`-based edge and frontend clients in sync with a `PostgreSQL` backend. See `docs/architecture/` for the design; `docs/architecture/00-overview.md` is the entry point and `docs/architecture/open-questions.md` indexes every decision.

The workspace hosts the shared crate today; server, client, and WASM crates land as their real content is ready.

- `crates/connetto-core`: wire protocol types, framing, and I/O trait signatures every side of the system agrees on.

Planned:

- `crates/connetto-server`: session manager and subscription materializer.
- `crates/connetto-client`: native Diesel connection and background sync worker.
- `crates/connetto-client-wasm`: `SharedWorker` and OPFS bindings.
