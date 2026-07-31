# 06: Reconnect and Offline

**Status**: draft

---

## Purpose

Define what happens when a client goes offline (network loss, device sleep, app backgrounding) and later reconnects. The system must resume reliably without data loss and without requiring a full re-sync when avoidable.

---

## The Problem

A client that was connected receives a continuous stream of `LivePatch` bulk frames keyed by server LSN. When it reconnects after a gap, it needs to know:

1. Where did I leave off? (its resume cursor)
2. What changed while I was gone? (the server must have kept a log)
3. Is that log still available? (the server retains only a finite window)
4. If the log is gone, how do I recover? (full re-sync)

Additionally, mutations the client queued while offline must be sent and processed in order.

---

## Client-Side State

The client persists the following in local SQLite across process restarts:

| Item | Description |
|---|---|
| `last_applied_lsn` | Highest server LSN the client has applied to local SQLite. |
| `pending_mutations` | The local mutation queue (see `03-sync-pipeline.md`). |
| `subscriptions` | The set of subscriptions to re-declare on reconnect (spec + sub_id). |
| `session_token` | Durable session handle. **Built, defective**: not persisted and not read back by the server. **Decided (R2)**: persisted outside the local replica and presented on reconnect (chapter 12). |

The `last_applied_lsn` is the client's resume cursor. It is updated atomically with each applied `LivePatch` frame.

**Decided (R3).** A caller with no identity has an in-memory local copy (`Replica::Ephemeral`) and no persistent cursor. It has no offline resume and always starts from a fresh snapshot. See chapter 12.

---

## Server-Side Oplog

The server maintains an **oplog**: an ordered log of `ChangeRecord`s. The oplog is used to replay changes to reconnecting clients.

### Structure

```
oplog(
  lsn        BIGINT PRIMARY KEY,
  table_name TEXT NOT NULL,
  op         TEXT NOT NULL,
  pk         BYTEA NOT NULL,
  old_row    BYTEA,            -- NULL for inserts
  new_row    BYTEA,            -- NULL for deletes
  is_tombstone BOOLEAN NOT NULL DEFAULT FALSE
)
```

Rows deleted from the underlying table are retained in the oplog as tombstones (`is_tombstone = TRUE`, `new_row = NULL`). This allows the server to replay deletes to reconnecting clients.

**Decided (R6).** The catchup path carries the same two-version authorization obligation as the live path: the oplog must carry whatever those checks need, or the confidentiality leak moves to reconnect. What exactly the oplog must carry is an open question recorded in `08-authorization.md`.

### Retention window

The oplog is a ring buffer with a configurable retention window, expressed as:
- Maximum number of entries, **or**
- Maximum age (time-based), **or**
- Both (whichever limit is hit first).

Entries older than the window are purged. Tombstones follow the same retention rules as regular entries.

**Default: 72 hours or 1M entries, whichever is hit first.** Both are configurable per deployment. Pruning is unconditional on the retention window: no per-client cursor tracking. Clients outside the window get a full re-sync.

---

## Reconnect Handshake

On reconnect, the client sends:

```
Handshake {
  client_id:     String,
  last_lsn:      u64,        // client's resume cursor (0 if never connected)
  session_token: String,     // Built, defective: see note below
  grants:        Vec<Grant>, // Decided (R3): zero or more opaque grants
}
```

The server responds with:

```
HandshakeAck {
  session_token:  String,    // Built, defective: see note below
  current_lsn:    u64,
  schema_version: String,
}
```

**Built, defective.** `session_token` exists on the wire in both directions but is non-functional: the server mints `format!("token-{connection_num}")` per connection, never reads the client's presented value back, and no client persists it. See chapter 12 for the full account.

**Decided (R2).** `session_token` becomes a real server-minted durable opaque handle. The client persists it outside its local replica and presents it on reconnect. See chapter 12.

**Decided (R3).** A grant that fails to resolve does not end the connection. The handshake succeeds on whatever resolved. See chapter 12.

After `HandshakeAck`, the client re-sends all its `Subscribe` messages.

---

## Reconnect Flow

### Case 1: Client's LSN is within the oplog window

1. Server checks `last_lsn` against the oldest entry in the oplog.
2. If `last_lsn >= oplog_min_lsn`: the server can replay.
3. For each re-declared subscription:
   - Server queries the oplog for entries since `last_lsn` that match the subscription and the caller's `Principal`, converts them into a SQLite PatchSet, and sends it. The format matches the live path (no special catchup message type).

### Case 2: Client's LSN is outside the oplog window (or LSN = 0)

1. The client's resume cursor predates the oldest available oplog entry. It cannot catch up incrementally.
2. Server sends `FullResyncRequired { reason: "lsn_outside_retention_window" }`: the client shows a "re-syncing..." state and clears local data for affected subscriptions.
3. For each re-declared subscription:
   - Server sends `SnapshotBegin` (control), one or more `SnapshotPatch` bulk frames carrying the matching rows, then `SnapshotEnd(current_lsn)` (control).
4. The client applies the snapshot as a full replacement (not a merge).

**Decided (R7).** `FullResyncReason` gains a variant for an authorization change: a permission row appearing or disappearing on the Postgres change log triggers a per-subscription resync. Adding that variant is itself a wire change because `FullResyncReason` has no fallback for an unknown value. See `08-authorization.md` for the mechanism.

### Case 3: Schema changed while offline

If `HandshakeAck.schema_version` differs from the version the client was built with, the client build is stale. connetto bakes the schema into the app at build time and runs no DDL at runtime, so there is no runtime migration. The client surfaces a terminal stale-build condition at the handshake, before any subscription catchup or pending replay, and the app reloads. The reload boots a fresh baked template and full-resyncs the data under the new schema (Case 2's full-replacement path) rather than migrating in place.

---

## Pending Mutations on Reconnect

After the reconnect handshake and subscription re-declaration:

1. The client sends all pending mutations from the local queue, in `client_seq` order.
2. The server processes them against the current PostgreSQL state.
3. Each mutation may succeed, be rejected, or produce a conflict, the same as the normal write path.

**Ordering note**: pending mutations are sent *after* subscription re-declaration so the server's subscription state is current when the mutations' CDC side effects are emitted.

---

## Tombstones and Delete Replay

When a client catchups via the oplog, tombstone entries (deletes) must be replayed so the client removes those rows from local SQLite.

The delete is delivered as a `LivePatch` frame with `op = Delete`. The client applies it if the row exists locally, or ignores it if the row is not present (idempotent).

Tombstones enable delete replay for rows the caller holds locally. Per the read-denial principle in `08-authorization.md`, a tombstone for a row the caller could never see must not be forwarded. An authorization change that would leave a stale local copy is handled by `FullResyncRequired` instead.

---

## Open Questions

1. ~~**Oplog retention window**: what is the default size (entry count or age)? How does this interact with storage cost on the server?~~ **Decided (Q6.1):** 72 hours or 1M entries, whichever is hit first, both configurable per deployment. Clients whose resume cursor falls outside the window receive a full re-sync.
2. ~~**Forced full re-sync signal**: should the server send an explicit "you must re-sync" message when the client's LSN is outside the window, rather than silently falling back to a snapshot? This would let the client show a "syncing..." state in the UI.~~ **Decided (Q6.2):** Yes, explicit `FullResyncRequired { reason }` message. The client uses it to show a "re-syncing..." state, clear local data for affected subscriptions, and log the reason.
3. ~~**Catchup delivery format**: deliver oplog catchup as a stream of `RowUpdate` messages (reusing existing infrastructure) or as a special `CatchupPatch` snapshot-style message? The former reuses code. The latter may be more efficient for ordering guarantees.~~ **Decided (Q6.3):** Dissolved. The delivery format was already decided as SQLite PatchSet for both the live path and the reconnect/catchup path.
4. ~~**Subscription-level LSN tracking**: should each subscription track its own resume LSN, or is a single global LSN per client sufficient? Per-subscription LSNs enable partial catchup. A global LSN is simpler.~~ **Decided (Q6.4):** Per-subscription cursors, tracked server-side by `subql` and keyed by session token. The client presents only its session token on reconnect and `subql` manages all cursor state.
5. ~~**Oplog storage**: should the oplog live in PostgreSQL (as a table), in a separate fast store (Redis, in-memory ring buffer), or both? PostgreSQL is durable but may be slow under high write volume. In-memory is fast but lost on restart.~~ **Decided (Q6.5):** Per-session pending PatchSet buffer in `subql`, scoped to session cookie lifetime. The PostgreSQL oplog table still exists for CDC propagation across nodes, but the reconnect story is session-scoped.
6. ~~**Concurrent re-sync and live updates**: during a full re-sync snapshot delivery, live CDC events continue arriving. How does the server buffer or order these relative to the snapshot delivery?~~ **Decided (Q6.6):** Dissolved. CDC events arriving during snapshot delivery are appended to the new session's pending PatchSet buffer and delivered after the snapshot completes, via an opaque server-issued cursor the client presents on reconnect.

---

## Decisions

**Oplog is a PostgreSQL table, replicated across the mesh.** Each row is a change record (table, pk, op, old/new values, LSN/position, timestamp). It must be a PostgreSQL table because the mesh requires all nodes to see it. Retention window is managed by periodic cleanup.

**Delivery format is SQLite PatchSet.** The server reads oplog entries relevant to the client's subscriptions and the caller's `Principal`, converts them into a SQLite PatchSet, and sends it. At the wire level, each patchset is Zstd-compressed and carried in a bulk-plane frame: `LivePatch` on the live path, `SnapshotPatch` for a full resync (see `02-protocol.md`). On the live path: CDC event → match subscriptions → authorization check → convert to PatchSet → send. On the reconnect path: query oplog since client's last position → filter by subscriptions and `Principal` → convert to PatchSet → send. The PatchSet format is native to the client (SQLite session extension), so no conversion is needed on the client side.

---

## Notes

- The oplog is the key operational dependency: its size, retention, and durability determine the system's offline resilience. Under-sizing the window forces frequent full re-syncs. Over-sizing it is a storage cost.
- Clients that are offline for extended periods (longer than the retention window) incur a full re-sync penalty. This is expected and acceptable, but applications should be designed to handle the "syncing..." state gracefully.
- Tombstones must not be pruned from the oplog while any client's resume cursor predates them. This is a subtle interaction: aggressive oplog pruning can silently lose deletes. The pruning policy must respect the oldest known client cursor.
