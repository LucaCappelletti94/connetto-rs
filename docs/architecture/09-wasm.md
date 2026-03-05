# 09 — WASM / Browser

**Status**: draft

---

## Purpose

Document the constraints and design choices specific to running the sync client in a browser via WebAssembly. The goal is to abstract these differences behind a common interface so application code is portable between native and browser targets.

---

## Core Constraints

| Constraint | Native | Browser / WASM |
|---|---|---|
| Threading | OS threads | `Worker` / `SharedWorker` (no shared memory with main thread by default) |
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
| `SharedWorker` | Cross-tab within origin | One sync connection for all tabs; more efficient |
| `ServiceWorker` | Persistent, survives tab close | Most complex; enables background sync |

Target is `SharedWorker` only — no `Worker` fallback. Chrome for Android and WebView Android have never supported `SharedWorker`, but Android users are expected to use the native app. The web target is desktop browsers and iOS Safari, which all support `SharedWorker`. `ServiceWorker` is a future consideration for background sync.

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

The main thread does not access the local SQLite directly — it reads through the worker or from a local read replica exposed by the worker.

---

## Local Storage: SQLite in the Browser

### OPFS (Origin Private File System)

OPFS provides a synchronous file-like API accessible from `Worker` contexts (not the main thread). This is the preferred backend for `sqlite-wasm`:

- **Pros**: fast, file-backed (survives tab close), standard (available in Chrome 103+, Firefox 111+, Safari 16.4+)
- **Cons**: not available on the main thread; requires a worker context

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
- Acceptable for ephemeral sessions; not for production offline use

---

## Transport: WebSocket in the Browser

The browser provides a native `WebSocket` API. In the WASM context:

- The WASM client calls `web-sys::WebSocket` (or a JS interop shim).
- The same `Transport` trait interface used by the native client is implemented for the browser context.
- Reconnect and keepalive logic is the same; only the underlying socket is different.

**Gotcha**: browser WebSocket connections are subject to browser-imposed limits (e.g. max 6 concurrent connections per origin in some implementations). A `SharedWorker` mitigates this by sharing one connection across tabs.

---

## File Content in the Browser

Without filesystem access, file content must be managed through browser APIs:

| Use case | Storage | Notes |
|---|---|---|
| App data files (mutable) | OPFS | Write via `FileSystemWritableFileStream` in worker |
| Static assets / downloads | Cache API | CDN-friendly; immutable by content hash |
| Large binary blobs | OPFS | Stream chunks as they arrive; do not buffer full file |

File chunk streaming is mandatory — the client must write chunks to storage as they arrive, not accumulate a full file in memory first. WASM linear memory is limited and large files would exhaust it.

---

## Common Interface

The native and WASM clients expose the same public API. Platform-specific code is isolated behind trait implementations:

```rust
trait Transport: Send {
    async fn send(&self, msg: WireMessage) -> Result<()>;
    async fn recv(&self) -> Result<WireMessage>;
}

trait Store: Send {
    async fn apply_row_update(&self, update: RowUpdate) -> Result<()>;
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

The sync engine crate depends only on these traits — it has no direct dependency on native or WASM I/O primitives.

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

The GC for unreferenced WASM memory is the Rust borrow checker — there is no JavaScript GC involved.

---

## Open Questions

1. **SharedWorker vs. Worker**: is `SharedWorker` a v1 requirement or a later optimization? `SharedWorker` complicates the implementation significantly (messaging, lifetime management).
2. **OPFS availability**: what is the fallback story for environments without OPFS (older browsers, some mobile WebViews)? IndexedDB adapter? In-memory only?
3. **WASM bundle size**: the WASM binary must be small enough for practical web use. What is an acceptable size limit? Are there obvious heavy dependencies to avoid?
4. **Main thread read access**: should the main thread be able to query local SQLite directly (e.g. via a synchronous OPFS access in a `Worker`), or should all reads go through the worker message-passing API? The former is faster; the latter is architecturally cleaner.
5. **ServiceWorker**: is background sync (receiving updates even when no tab is open) a requirement? If so, `ServiceWorker` is needed. If not, `Worker` or `SharedWorker` is sufficient.
6. **TypeScript bindings**: should the WASM client expose TypeScript bindings (via `wasm-bindgen` + `tsify`) for use in JavaScript/TypeScript applications? Is this in scope for v1?
7. **Testing WASM**: how are WASM-specific behaviors tested? `wasm-pack test` with headless Chrome? A mocked browser environment?

---

## Decisions

*(none yet)*

---

## Notes

- The constraint that all blocking work happens in a worker is not a limitation specific to this system — it is a browser security model. The architecture embraces this by making the worker the owner of all sync state.
- `SharedWorker` is the right end state for browser deployments that expect multiple tabs. However, `SharedWorker` support is not universal (Safari added it in 16.0; some mobile browsers are inconsistent). The `Worker` fallback must remain viable.
- WASM binary size matters for web performance. Heavy Rust crates (full TLS implementations, large codecs) should be evaluated carefully. Where the browser already provides the capability (WebSocket, fetch), use the browser API rather than re-implementing in Rust.
