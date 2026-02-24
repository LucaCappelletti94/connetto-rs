# 01 — Pieces Inventory

**Status**: draft

---

## Purpose

A structured inventory of every component that must exist. This is not a dependency graph or an implementation order — it is a catalogue to make sure nothing is forgotten before design begins.

---

## A. Foundation

| Piece | Description |
|---|---|
| `WireMessage` | Enum of all message types exchanged between client and server. Shared definition used by both sides. |
| `MutationRecord` | Representation of a single client-originating write (table, pk, op, payload, client-sequence-number). |
| `ChangeRecord` | Server-originated change pushed to clients (table, pk, op, new values, server-LSN or clock). |
| `SubscriptionSpec` | How a client describes what it wants: query shape, parameters, subscription ID. |
| `SchemaVersion` | Versioned description of the tables and columns the client should maintain locally. |
| Core traits | `Transport`, `Store` (local SQLite), `AuthPolicy`, `SubscriptionMatcher` — the seams the rest of the system plugs into. |

---

## B. Transport

| Piece | Description |
|---|---|
| Server session | One struct per connected client: holds the WebSocket (or other) sink/stream, client ID, current subscription set, and flow-control budget. |
| Client connector | Opens the connection, sends handshake, drives the read loop, and exposes a typed message channel to higher layers. |
| Reconnect loop | Client-side: exponential back-off, re-sends subscriptions and pending mutations after reconnect. |
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
| Local mutation queue | Client persists pending mutations in SQLite before sending; survives process restart and offline. |
| Mutation sender | Reads from the local queue, sends in order, awaits acknowledgement before dequeuing. |
| Server mutation handler | Validates schema and authorization, applies to PostgreSQL, and returns `Ack` or `Reject`. |
| Conflict detector | Compares mutation's base version to current server version; emits `Conflict` response when they diverge. |
| Conflict resolution policy | Configurable per-table strategy (last-writer-wins, server-wins, client-wins, or custom merge). |
| Optimistic rollback | On `Reject` or unresolvable `Conflict`, client rolls back the optimistic local write. |

---

## E. CDC Push Path (server → client)

| Piece | Description |
|---|---|
| CDC source | Logical replication or `LISTEN`/`NOTIFY` listener that produces a stream of `ChangeRecord`s from PostgreSQL. |
| Subscription matcher | For each incoming `ChangeRecord`, identifies which active subscriptions are potentially affected. |
| Auth filter | Per-subscription, per-row check: "can this client see this row after this change?" Rows that fail are dropped or replaced with a delete event. |
| Delta packager | Groups affected rows into a batch message; adds server LSN / clock for the client to store as its resume position. |
| Delivery queue | Per-session outbound queue; respects flow-control window; drops or back-pressures when client is slow. |

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
| Accumulator state | Per-subscription server-side state for supported aggregate shapes (COUNT, SUM, etc.). |
| Incremental update handler | On CDC event: update accumulator and push delta to client if it changes the result. |
| Full re-execution fallback | For unsupported shapes or when accumulator is invalid: re-run the query and push the new value. |

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
| Schema push | Server sends schema on connect and whenever it changes. |
| Client schema applier | Receives schema, diffs against local SQLite schema, runs migrations. |

---

## J. File Sync

| Piece | Description |
|---|---|
| File metadata table | A normal synced table: file ID, path, size, content hash, version. Syncs through the standard row-sync path. |
| Content channel | Separate from the row-sync channel; transfers raw bytes. |
| Chunker | Splits file content into fixed-size chunks addressed by hash. |
| Upload path | Client → server: client announces intent, uploads chunks, server reassembles and stores. |
| Download path | Server → client: server announces new/changed file via metadata update, client requests chunks by hash. |
| Resumability | Client tracks which chunks it already has; skips re-downloading identical chunks. |
| WASM constraints | No direct filesystem; content must be streamed into browser storage. *(See `09-wasm.md`.)* |

---

## K. Authorization

| Piece | Description |
|---|---|
| Policy source | PostgreSQL RLS definitions (or a derived equivalent) compiled into a fast in-process policy engine. |
| Auth context | Per-session identity and claims passed to every policy evaluation. |
| Read filter | Applied to every row before delivery — both at snapshot time and on CDC push. |
| Write gate | Applied to every mutation before it is executed. |
| Auth batching | Policies are evaluated in batch per CDC event to avoid per-row round-trips. |
| File session token | Short-lived token issued for a specific file; gates chunk upload/download without per-chunk auth calls. |

---

## L. WASM / Browser

| Piece | Description |
|---|---|
| Worker isolation | All sync logic runs in a `Worker` or `SharedWorker`; main thread is never blocked. |
| Browser storage backend | Local SQLite runs in OPFS (Origin Private File System) or IndexedDB fallback. |
| Transport adapter | WebSocket in the browser context; same `Transport` trait as native. |
| File storage adapter | Content chunks stored in OPFS or browser cache; no direct filesystem access. |
| Common interface boundary | Native and WASM clients expose the same public API so application code is portable. |

---

## Open Questions

1. Should the core traits (`Transport`, `Store`, etc.) live in a dedicated `connetto-core` crate, or inline in this repo?
2. Which pieces are in-scope for a first prototype versus later iterations?
3. Is `SharedWorker` a requirement for multi-tab browser support, or is tab-per-worker acceptable initially?

---

## Decisions

**Crate layout: single Cargo workspace, multiple published crates.** connetto-rs is a reusable transport layer library. All crates live in one workspace and are published independently so downstream projects depend only on the pieces they need. Split: `connetto-core` (shared types and traits), `connetto-server`, `connetto-client`, `connetto-client-wasm`. Both server and client depend on core; neither depends on the other.

---

## Notes

- This inventory will be refined as each area (B–L) gets its own doc and decisions are made.
- Items marked "see Xnn.md" are elaborated in their own file.
