# 06 — Reconnect and Offline

**Status**: draft

---

## Purpose

Define what happens when a client goes offline (network loss, device sleep, app backgrounding) and later reconnects. The system must resume reliably without data loss and without requiring a full re-sync when avoidable.

---

## The Problem

A client that was connected receives a continuous stream of `RowUpdate` messages keyed by server LSN. When it reconnects after a gap, it needs to know:

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

The `last_applied_lsn` is the client's resume cursor. It is updated atomically with each applied `RowUpdate`.

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

### Retention window

The oplog is a ring buffer with a configurable retention window, expressed as:
- Maximum number of entries, **or**
- Maximum age (time-based), **or**
- Both (whichever limit is hit first).

Entries older than the window are purged. Tombstones follow the same retention rules as regular entries.

**Default: 72 hours or 1M entries, whichever is hit first.** Both are configurable per deployment. Pruning is unconditional on the retention window — no per-client cursor tracking. Clients outside the window get a full re-sync.

---

## Reconnect Handshake

On reconnect, the client sends:

```
Handshake {
  client_id:   String,
  last_lsn:    u64,      // client's resume cursor (0 if never connected)
  auth_token:  String,
}
```

The server responds with:

```
HandshakeAck {
  session_id:     String,
  current_lsn:    u64,
  schema_version: String,
}
```

After `HandshakeAck`, the client re-sends all its `Subscribe` messages.

---

## Reconnect Flow

### Case 1: Client's LSN is within the oplog window

1. Server checks `last_lsn` against the oldest entry in the oplog.
2. If `last_lsn >= oplog_min_lsn`: the server can replay.
3. For each re-declared subscription:
   - Server queries the oplog for entries since `last_lsn` that match the subscription + auth context, converts them into a SQLite PatchSet, and sends it. Same format as the live path — no special catchup message type.

### Case 2: Client's LSN is outside the oplog window (or LSN = 0)

1. The client's resume cursor predates the oldest available oplog entry. It cannot catch up incrementally.
2. Server sends `FullResyncRequired { reason: "lsn_outside_retention_window" }` — the client shows a "re-syncing..." state and clears local data for affected subscriptions.
3. For each re-declared subscription:
   - Server sends a full snapshot: `SnapshotBegin` → `SnapshotRows` (all matching rows) → `SnapshotEnd(current_lsn)`.
4. The client applies the snapshot as a full replacement (not a merge).

### Case 3: Schema changed while offline

If `HandshakeAck.schema_version` differs from the client's stored schema version:

1. Server sends a `SchemaUpdate` message before subscription catchup begins.
2. Client applies the schema migration to local SQLite.
3. Subscription catchup proceeds against the new schema.

If the schema change is incompatible with the oplog entries in the catchup window, the server may be forced to trigger a full re-sync for affected subscriptions.

---

## Pending Mutations on Reconnect

After the reconnect handshake and subscription re-declaration:

1. The client sends all pending mutations from the local queue, in `client_seq` order.
2. The server processes them against the current PostgreSQL state.
3. Each mutation may succeed, be rejected, or produce a conflict — the same as the normal write path.

**Ordering note**: pending mutations are sent *after* subscription re-declaration so the server's subscription state is current when the mutations' CDC side effects are emitted.

---

## Tombstones and Delete Replay

When a client catchups via the oplog, tombstone entries (deletes) must be replayed so the client removes those rows from local SQLite.

The delete is delivered as a `RowUpdate` with `op = Delete`. The client applies it if the row exists locally; ignores it if the row is not present (idempotent).

Tombstones also ensure that auth-filtered rows are correctly handled: if a row was deleted while the client was offline, the client needs the delete event even if the row was not visible to the client (in case the client had a stale local copy from before the auth filter changed).

---

## Open Questions

1. **Oplog retention window**: what is the default size (entry count or age)? How does this interact with storage cost on the server?
2. **Forced full re-sync signal**: should the server send an explicit "you must re-sync" message when the client's LSN is outside the window, rather than silently falling back to a snapshot? This would let the client show a "syncing..." state in the UI.
3. **Catchup delivery format**: deliver oplog catchup as a stream of `RowUpdate` messages (reusing existing infrastructure) or as a special `CatchupPatch` snapshot-style message? The former reuses code; the latter may be more efficient for ordering guarantees.
4. **Subscription-level LSN tracking**: should each subscription track its own resume LSN, or is a single global LSN per client sufficient? Per-subscription LSNs enable partial catchup; a global LSN is simpler.
5. **Oplog storage**: should the oplog live in PostgreSQL (as a table), in a separate fast store (Redis, in-memory ring buffer), or both? PostgreSQL is durable but may be slow under high write volume; in-memory is fast but lost on restart.
6. **Concurrent re-sync and live updates**: during a full re-sync snapshot delivery, live CDC events continue arriving. How does the server buffer or order these relative to the snapshot delivery?

---

## Decisions

**Oplog is a PostgreSQL table, replicated across the mesh.** Each row is a change record (table, pk, op, old/new values, LSN/position, timestamp). It must be a PostgreSQL table because the mesh requires all nodes to see it. Retention window is managed by periodic cleanup.

**Delivery format is SQLite PatchSet.** The server reads oplog entries relevant to the client's subscriptions and auth context, converts them into a SQLite PatchSet, and sends it. On the live path: CDC event → match subscriptions → auth filter → convert to PatchSet → send. On the reconnect path: query oplog since client's last position → filter by subscriptions + auth → convert to PatchSet → send. The PatchSet format is native to the client (SQLite session extension), so no conversion is needed on the client side.

---

## Notes

- The oplog is the key operational dependency: its size, retention, and durability determine the system's offline resilience. Under-sizing the window forces frequent full re-syncs; over-sizing it is a storage cost.
- Clients that are offline for extended periods (longer than the retention window) incur a full re-sync penalty. This is expected and acceptable, but applications should be designed to handle the "syncing..." state gracefully.
- Tombstones must not be pruned from the oplog while any client's resume cursor predates them. This is a subtle interaction: aggressive oplog pruning can silently lose deletes. The pruning policy must respect the oldest known client cursor.
