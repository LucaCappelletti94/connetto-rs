# 09: WASM / Browser

**Status**: draft

---

## Purpose

Document the constraints and design choices specific to running the sync client in a browser via WebAssembly. The goal is to abstract these differences behind a common interface so application code is portable between native and browser targets.

---

## Core Constraints

| Constraint | Native | Browser / WASM |
|---|---|---|
| Threading | OS threads | Dedicated `Worker` (via Web Locks election; no shared memory with main thread; `SharedWorker` is impossible because `createSyncAccessHandle` is `[Exposed=DedicatedWorker]`) |
| Filesystem | Direct (std::fs) | None; must use OPFS or IndexedDB |
| WebSocket | OS socket (via `tokio-tungstenite` or similar) | Browser WebSocket API |
| SQLite | File-backed (libsqlite3) | `sqlite-wasm` over OPFS or in-memory |
| Binary execution | Native binary | WASM module loaded by browser |
| Blocking I/O | Available | Not available on main thread; async only |
| Memory | OS-managed | Heap within WASM linear memory (limited) |

---

## Worker Isolation

All sync logic runs in a **background worker**, never on the main thread. The main thread must not be blocked by sync operations.

### Worker types

| Type | Scope | Notes |
|---|---|---|
| `Worker` | Per-tab | Simplest; sync state is per-tab |
| `ServiceWorker` | Persistent, survives tab close | Most complex; enables background sync |

The shipped topology is a dedicated `Worker` spawned by whichever tab wins a Web Locks election (via `spawn_db_worker` in `crates/connetto-web/src/workers.rs`). `BroadcastChannel` carries the tab-to-worker leg. This is the only viable path: `createSyncAccessHandle` is `[Exposed=DedicatedWorker]` in the WHATWG File System IDL, so `SharedWorker` cannot host the database tier in any conforming browser. Android exclusion is a product choice, not a browser limitation. `ServiceWorker` is a future consideration for background sync.

### Communication with main thread

The worker exposes a message-passing API to the main thread:

```
// Main thread → worker
{ type: "subscribe",    sub_id, spec }
{ type: "unsubscribe",  sub_id }
{ type: "mutate",       mutation }

// Worker → main thread
{ type: "snapshot",     sub_id, rows }
{ type: "row_update",   sub_id, changes }
{ type: "mutation_ack", client_seq }
{ type: "mutation_reject", client_seq, reason }
{ type: "sync_status",  status }  // connected | reconnecting | offline
```

The main thread does not access the local SQLite directly: it reads through the worker or from a local read replica exposed by the worker.

---

## Local Storage: SQLite in the Browser

### OPFS (Origin Private File System)

OPFS provides a synchronous file-like API accessible from `Worker` contexts (not the main thread). This is the preferred backend for `sqlite-wasm`:

- **Pros**: fast, file-backed (survives tab close), standard (available in Chrome 103+, Firefox 111+, Safari 16.4+)
- **Cons**: not available on the main thread. Requires a worker context.

The sync client already runs in a worker, so OPFS is the natural fit.

### IndexedDB fallback

For environments where OPFS is unavailable:

- IndexedDB is universally available
- Less efficient for SQLite (not a natural mapping)
- `absurd-sql` or similar adapters make SQLite run over IndexedDB
- Performance is lower but correctness is maintained

### In-memory fallback

For testing and environments without persistent storage:

- SQLite runs entirely in WASM linear memory
- State is lost when the tab is closed
- Acceptable for ephemeral sessions, not for production offline use.

---

## Transport: WebSocket in the Browser

The browser provides a native `WebSocket` API. In the WASM context:

- The WASM client calls `web-sys::WebSocket` (or a JS interop shim).
- The same `Transport` trait interface used by the native client is implemented for the browser context.
- Reconnect and keepalive logic is the same. Only the underlying socket is different.

**Gotcha**: browser WebSocket connections are subject to browser-imposed limits (e.g. max 6 concurrent connections per origin in some implementations). Leader election ensures a single dedicated `Worker` holds one connection across all tabs, avoiding this limit.

---

## File Content in the Browser

Without filesystem access, file content must be managed through browser APIs:

| Use case | Storage | Notes |
|---|---|---|
| App data files (mutable) | OPFS | Write via `FileSystemWritableFileStream` in worker |
| Static assets / downloads | Cache API | CDN-friendly; immutable by content hash |
| Large binary blobs | OPFS | Stream chunks as they arrive; do not buffer full file |

File chunk streaming is mandatory: the client must write chunks to storage as they arrive, not accumulate a full file in memory first. WASM linear memory is limited and large files would exhaust it.

---

## Common Interface

The native and WASM clients expose the same public API. Platform-specific code is isolated behind trait implementations:

```rust
trait Transport: Send {
    async fn send(&self, msg: WireMessage) -> Result<()>;
    async fn recv(&self) -> Result<WireMessage>;
}

trait Store: Send {
    async fn apply_row_update(&self, patch: LivePatch) -> Result<()>;
    async fn queue_mutation(&self, m: MutationRecord) -> Result<()>;
    async fn get_pending_mutations(&self) -> Result<Vec<MutationRecord>>;
    async fn get_last_lsn(&self) -> Result<u64>;
}

trait FileStore: Send {
    async fn write_chunk(&self, hash: Hash, data: &[u8]) -> Result<()>;
    async fn read_chunk(&self, hash: Hash) -> Result<Vec<u8>>;
    async fn has_chunk(&self, hash: Hash) -> Result<bool>;
}
```

Native implementations use `tokio-tungstenite`, `diesel` (with SQLite backend), and `std::fs`. WASM implementations use `web-sys::WebSocket`, `sqlite-wasm-rs` over OPFS, and OPFS file APIs.

The sync engine crate depends only on these traits: it has no direct dependency on native or WASM I/O primitives.

---

## Build Targets

The crate must compile for two targets:

| Target | Usage |
|---|---|
| `x86_64-unknown-linux-gnu` (or equivalent) | Native binary (server, desktop client) |
| `wasm32-unknown-unknown` | Browser via WASM |

Feature flags (`#[cfg(target_arch = "wasm32")]`) isolate platform-specific code. The shared sync engine is `no_std` compatible where possible to avoid pulling in std abstractions that don't exist in WASM.

---

## Async Runtime

- **Native**: `tokio`
- **WASM**: `wasm-bindgen-futures` / `gloo` (wraps browser promises as Rust futures)

The sync engine uses `async`/`await` throughout but does not depend on a specific runtime. Executor-agnostic async code (no `tokio::spawn` calls in the shared engine) ensures portability.

---

## Memory Management

WASM linear memory is fixed at allocation time (though it can grow up to a limit). Large allocations (e.g. buffering an entire file) must be avoided. Streaming and chunked processing are the rule throughout.

The GC for unreferenced WASM memory is the Rust borrow checker: there is no JavaScript GC involved.

---

## Open Questions

1. ~~**SharedWorker vs. Worker**: is `SharedWorker` a v1 requirement or a later optimization? `SharedWorker` complicates the implementation significantly (messaging, lifetime management).~~ **Decided (Q9.1, dissolved by Q1.3), and since corrected:** the recorded answer was "SharedWorker only, no fallback", and it was never implementable. `createSyncAccessHandle` is `[Exposed=DedicatedWorker]` in the WHATWG File System IDL, so it cannot exist in a `SharedWorker` in any conforming browser, and Chrome does not even expose the `Worker` constructor there, so there is no nested-worker route either. The database tier runs in a dedicated `Worker` spawned by whichever tab wins a Web Locks election (via `spawn_db_worker` in `crates/connetto-web/src/workers.rs`), with `BroadcastChannel` as the port replacement, and `crates/connetto-web/src/broadcast.rs` records the reason. Nothing in the repository constructs a `SharedWorker`. The support table under Q9.2 has been corrected to gate on the APIs connetto actually uses, which moved Chrome desktop and Edge up from 86 to 102, Safari down from 16.0 to 15.4, and both Android platforms from unsupported to supported.
2. ~~**OPFS availability**: what is the fallback story for environments without OPFS (older browsers, some mobile WebViews)? IndexedDB adapter? In-memory only?~~ **Decided (Q9.2):** OPFS required, no fallback. Browsers without OPFS are unsupported.
3. ~~**WASM bundle size**: the WASM binary must be small enough for practical web use. What is an acceptable size limit? Are there obvious heavy dependencies to avoid?~~ **Decided (Q9.3):** No target. Measure once there is a working build. The known heavy component is SQLite (~300-400 KB gzipped).
4. ~~**Main thread read access**: should the main thread be able to query local SQLite directly (e.g. via a synchronous OPFS access in a `Worker`), or should all reads go through the worker message-passing API? The former is faster. The latter is architecturally cleaner.~~ **Decided (Q9.4):** All reads go through the worker that owns the database, via a custom `diesel_async` connection. Application code writes standard `diesel_async` queries and the worker transport is an implementation detail. (The recorded decision said `SharedWorker`, and the shipped worker is dedicated. The substance, that reads do not touch the database directly from a tab, is unaffected. See the note under question 1.)
5. ~~**ServiceWorker**: is background sync (receiving updates even when no tab is open) a requirement? If so, `ServiceWorker` is needed. If not, `Worker` or `SharedWorker` is sufficient.~~ **Decided (Q9.5):** No ServiceWorker. The worker stays alive as long as the tab that spawned it is open, and leadership moves to another tab otherwise. On reopen the client reconnects and receives the pending PatchSet (Q6.5).
6. ~~**TypeScript bindings**: should the WASM client expose TypeScript bindings (via `wasm-bindgen` + `tsify`) for use in JavaScript/TypeScript applications? Is this in scope for v1?~~ **Decided (Q9.6):** Out of scope. The immediate consumer is a Dioxus app (Rust on both sides). TS bindings can be added later if connetto-rs targets non-Rust web apps.
7. ~~**Testing WASM**: how are WASM-specific behaviors tested? `wasm-pack test` with headless Chrome? A mocked browser environment?~~ **Decided (Q9.7):** `wasm-pack test --headless --chrome`. Real headless browser testing against actual browser APIs (OPFS, Web Locks, `BroadcastChannel`).

---

## Decisions

*(none yet)*

---

## Notes

- The constraint that all blocking work happens in a worker is not a limitation specific to this system: it is a browser security model. The architecture embraces this by making the worker the owner of all sync state.
- WASM binary size matters for web performance. Heavy Rust crates (full TLS implementations, large codecs) should be evaluated carefully. Where the browser already provides the capability (WebSocket, fetch), use the browser API rather than re-implementing in Rust.
