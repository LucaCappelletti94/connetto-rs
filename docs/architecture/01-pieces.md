# 01: Pieces Inventory

**Status**: draft

---

## Purpose

A structured inventory of every component that must exist. This is not a dependency graph or an implementation order: it is a catalogue to make sure nothing is forgotten before design begins.

---

## A. Foundation

| Piece | Description |
|---|---|
| `ControlMessage` and `BulkMessage` | The two wire enums, one per plane. Control carries typed frames, bulk carries Zstd-compressed payloads. Shared definitions used by both sides. |
| `MutationHeader` and `MutationPatch` | A client-originating write, split across the two planes: the control frame carries the client sequence number, the bulk frame the compressed patchset. |
| `ChangeRecord` | Server-originated change pushed to clients (table, pk, op, new values, server-LSN or clock). |
| `SubscriptionSpec` | How a client describes what it wants: query shape, parameters, subscription ID. |
| `SchemaVersion` | Versioned description of the tables and columns the client should maintain locally. |
| Core traits | `Transport`, `Store` (local SQLite), `SubscriptionMatcher` — the seams the rest of the system plugs into. Authorization is not one of them: that question goes through `subql`'s visibility trait. |

---

## B. Transport

| Piece | Description |
|---|---|
| Server session | One struct per connected client: holds the WebSocket (or other) sink/stream, client ID, current subscription set, and flow-control budget. |
| Client connector | Opens the connection, sends handshake, drives the read loop, and exposes a typed message channel to higher layers. |
| Reconnect loop | Client-side: exponential back-off, re-sends subscriptions and pending mutations after reconnect. *(Reliability: see §10.)* |
| Flow control | Per-session send-window to prevent the server from flooding a slow client. Server back-pressures CDC delivery when window is exhausted. |
| Keepalive | Ping/pong at a configurable interval; server drops a session after N missed heartbeats. |

---

## C. Subscription Lifecycle

| Piece | Description |
|---|---|
| Subscribe message | Client sends subscription ID + `SubscriptionSpec`. |
| Server subscription registry | Maps `(session_id, sub_id)` → `(spec, auth_context, last_delivered_lsn)`. |
| Initial snapshot sender | On new subscription: runs the query, applies auth filter, streams result rows to client. |
| Unsubscribe message | Client cancels a subscription; server removes it from the registry. |
| Re-subscribe on reconnect | Client re-declares all subscriptions after reconnect; server reconciles with stored state if available. |

---

## D. Mutation Path (client → server)

| Piece | Description |
|---|---|
| Local mutation queue | Client persists pending mutations in SQLite before sending; survives process restart and offline. *(Reliability: see §10.)* |
| Mutation sender | Reads from the local queue, sends in order, awaits acknowledgement before dequeuing. *(Reliability: see §10.)* |
| Server mutation handler | Validates schema and authorization, applies to PostgreSQL, and returns `MutationApplied` or `MutationReject`. Owned by the Subscription Materializer (§10); transient PG failures retried per its policy. |
| Conflict detector | Compares mutation's base version to current server version; emits `Conflict` response when they diverge. |
| Conflict resolution policy | Configurable per-table strategy (last-writer-wins, server-wins, client-wins, or custom merge). |
| Optimistic rollback | On `Reject` or unresolvable `Conflict`, client rolls back the optimistic local write. |

---

## E. CDC Push Path (server → client)

| Piece | Description |
|---|---|
| CDC source | Logical replication stream (pgoutput or wal2json) or a slot poll. `subql`'s `CdcSource` holds the replication connection and produces typed events. The Subscription Materializer (§10) drives the consume loop and owns reconnect with backoff. |
| Subscription matcher | For each incoming event, identifies which active subscriptions are potentially affected. Matching is in-process via `subql` (bitmap prune plus predicate VM) and has no retry surface. Its surrounding CDC ingestion and re-execution reach the database through connections the materializer supplies (§10). |
| Auth filter | **Decided (R5b), not built.** Per-subscription, per-row check via the authorization service: "can this client see this row after this change?" Rows that fail are to be dropped or replaced with a delete event, failing closed on a transient outage. Today the check runs against Postgres row-level security instead, and it fails closed. |
| Delta packager | Groups affected rows into a batch and adds the server LSN for the client's resume position. `subql` folds matched events into `sqlite-diff-rs` patchsets. The Subscription Materializer (§10) selects each session's authorized subset and invokes the builder. |
| Delivery queue | Per-session outbound queue; respects flow-control window; drops or back-pressures when client is slow. *(Reliability: see §10.)* |

---

## F. Row-level SELECT Subscriptions

| Piece | Description |
|---|---|
| Snapshot query executor | Runs the initial SELECT and pages results to the client. |
| Row identity tracker | Tracks which primary keys have been delivered for a subscription so incremental adds/removes can be computed. |
| Incremental update computation | On CDC event: determine if the row enters, leaves, or changes within the subscription's result set. |

---

## G. Aggregate Subscriptions

| Piece | Description |
|---|---|
| Accumulator state | Per-subscription aggregate state (COUNT, SUM, and the variance family), held in memory by `subql` and rebuilt via re-execution on restart. |
| Incremental update handler | On a CDC event, `subql` updates the accumulator and emits a signed delta. The materializer pushes it to the client when the result changes. |
| Full re-execution fallback | For unsupported shapes or when the accumulator is invalid, `subql`'s `reexec` engine classifies the query and either emits a re-execution trigger or auto-resolves it through a caller `Connector`. The Subscription Materializer (§10) runs the query against PG over its own pool, coalesces duplicates, and `install`s the value back into `subql`. *(Reliability: see §10.)* |

*(See `05-aggregate-queries.md` for full discussion.)*

---

## H. Reconnect / Offline

| Piece | Description |
|---|---|
| Client LSN cursor | Client persists its last-known server LSN; sends it in the reconnect handshake. |
| Server oplog | Ring buffer (or table) of recent `ChangeRecord`s keyed by LSN; retention window is configurable. |
| Catchup replayer | On reconnect: if client's LSN is within the window, replays changes since that LSN filtered by subscriptions. |
| Full re-sync trigger | If client's LSN is outside the window (or unknown), triggers full snapshot re-delivery for each subscription. |
| Tombstone store | Deleted rows are retained in the oplog (with a tombstone flag) so deletes can be replayed during catchup. |

---

## I. Schema Distribution

| Piece | Description |
|---|---|
| Schema extractor | Derives a client-facing schema from PostgreSQL catalog (tables, columns, types, PKs) filtered to tables the client can access. |
| Schema version envelope | Wraps schema with a content hash / version number. |
| Schema version handshake | Server advertises the schema version in `HandshakeAck`. The client never fetches or applies a schema at runtime. |
| Stale-build detection | The client compares the advertised version against the version it was baked with. A mismatch means this app build is stale and must reload, since the schema is compiled in and the client runs no DDL. Reload boots a fresh baked template and full-resyncs. |

---

## J. File Sync

| Piece | Description |
|---|---|
| File metadata table | A normal synced table: file ID, path, size, content hash, version. Syncs through the standard row-sync path. |
| Content channel | Separate from the row-sync channel; transfers raw bytes. |
| Chunker | Splits file content into fixed-size chunks addressed by hash. |
| Upload path | Client → server: client announces intent, uploads chunks, server reassembles and stores. *(Reliability: per-chunk retry; see §10.)* |
| Download path | Server → client: server announces new/changed file via metadata update, client requests chunks by hash. *(Reliability: per-chunk retry; see §10.)* |
| Resumability | Client tracks which chunks it already has; skips re-downloading identical chunks. The retry policy and idempotency story for individual chunk transfers live in §10. |
| WASM constraints | No direct filesystem; content must be streamed into browser storage. *(See `09-wasm.md`.)* |

---

## K. Authorization

| Piece | Description |
|---|---|
| Policy source | PostgreSQL RLS definitions (or a derived equivalent) compiled into a fast in-process policy engine. |
| Auth context | Per-session identity and claims passed to every policy evaluation. |
| Read filter | **Built.** Applied to every row before delivery, at snapshot time and on CDC push, and it fails closed: the verdict buffer arrives pre-filled with denials, so a policy that cannot answer denies rather than allows (`RlsAuth::may_see` in `SessionManager::dispatch_event`). The authorization-service form of this is R5b and is not built. |
| Write gate | Applied to every mutation before it is executed. *(Reliability: see §10.)* |
| Auth batching | Policies are evaluated in batch per CDC event to avoid per-row round-trips. |
| File session token | Short-lived token issued for a specific file; gates chunk upload/download without per-chunk auth calls. |

---

## L. WASM / Browser

| Piece | Description |
|---|---|
| Worker isolation | All sync logic runs in a dedicated `Worker` spawned by the Web Locks election winner; main thread is never blocked. |
| Browser storage backend | Local SQLite runs in OPFS (Origin Private File System) or IndexedDB fallback. |
| Transport adapter | WebSocket in the browser context; same `Transport` trait as native. |
| File storage adapter | Content chunks stored in OPFS or browser cache; no direct filesystem access. |
| Common interface boundary | Native and WASM clients expose the same public API so application code is portable. |

---

## Open Questions

1. ~~Should the core traits (`Transport`, `Store`, etc.) live in a dedicated `connetto-core` crate, or inline in this repo?~~ **Decided (Q1.1):** Dedicated `connetto-core` crate, now at `crates/connetto-core`. Both `connetto-server` and `connetto-client` depend on it. Neither depends on the other.
2. ~~Which pieces are in-scope for a first prototype versus later iterations?~~ **Decided (Q1.2):** All pieces (A through L) are in scope for v1, except file sync (J), which is handled by a separate stack.
3. ~~Is `SharedWorker` a requirement for multi-tab browser support, or is tab-per-worker acceptable initially?~~ **Decided (Q1.3), and since corrected twice:** the answer was "`SharedWorker` only, no fallback", and connetto never used one and cannot, because OPFS sync access handles exist only in a dedicated worker. The shipped topology is a dedicated worker with a Web Locks election. Both Android platforms are technically capable, and **Android is supported both on the web and as a native app**: the exclusion rested on the `SharedWorker` premise and both of its reasons are now withdrawn. See the corrections under Q1.3 and Q9.1 in `open-questions.md`.

---

## Decisions

**Crate layout: single Cargo workspace, multiple published crates.** connetto-rs is a reusable transport layer library. All crates live in one workspace and are published independently so downstream projects depend only on the pieces they need.

| Crate | Role | Status |
|---|---|---|
| `connetto-core` | Shared types, traits, and codec (`Transport`, `ControlMessage`, `BulkMessage`, `SubscriptionSpec`). Both `connetto-server` and `connetto-client` depend on it. Neither depends on the other. | **Built** |
| `connetto-server` | Server binary and library: session manager, CDC ingest, subscription materializer, auth stack, and mutation handler. | **Built** |
| `connetto-client` | Native client library: `ConnettoConnection`, `ConnettoClient`, and the live-query API (`LiveQuery`, `LiveValue`, `Watchable`). | **Built** |
| `connetto-web` | Browser platform for wasm32: `BrowserSocket` (a `Transport` over `web_sys::WebSocket`), dedicated-worker relay topology, leader election, and multi-tab routing. | **Built** |
| `connetto-dioxus` | Dioxus adapter: `use_live` and `use_live_fn` hooks binding live queries to component scope. | **Built** |
| `connetto-yew` | Yew adapter: the same `use_live` and `use_live_fn` hooks with an abort-on-unmount lifecycle suited to Yew's detached `spawn_local` task model. | **Built** |
| `connetto-test-harness` | In-process CDC-loop test harness over a real Postgres. Test infrastructure, not a shipped component. Tests run `#[ignore]` against Docker. | **Built** |

---

## Notes

- This inventory will be refined as each area (B to L) gets its own doc and decisions are made.
- Items marked "see Xnn.md" are elaborated in their own file.
