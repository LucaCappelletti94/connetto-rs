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
| `session_token` | Durable session handle. **Built (R2, R3)**: for an identified run the auth store's session id is the handle, an unidentified run gets one minted at handshake, and the `resume_token` credential returned beside it is what proves the handle on the next connect. The client persists the pair outside the local replica (natively where the refresh token lives, worker-only in the browser). Cursors, the watermark and the connection registry key on it (chapter 12). |

The `last_applied_lsn` is the client's resume cursor. It is updated atomically with each applied `LivePatch` frame.

**Built (R3).** A caller with no identity has an in-memory local copy (`Replica::in_memory()`) and no persistent cursor. It has no offline resume and always starts from a fresh snapshot. See chapter 12.

---

## Server-Side Oplog

The server maintains an **oplog**: an ordered log of `ChangeRecord`s. The oplog is used to replay changes to reconnecting clients.

### Structure

```sql
CREATE TYPE connetto_change_op AS ENUM ('insert', 'update', 'delete', 'truncate');

CREATE TABLE oplog (
    lsn          BIGINT PRIMARY KEY,
    table_name   TEXT NOT NULL,
    op           connetto_change_op NOT NULL,
    pk           BYTEA NOT NULL,
    is_tombstone BOOLEAN NOT NULL DEFAULT FALSE,
    event        BYTEA NOT NULL,
    appended_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**Built, and two corrections against an earlier version of this block** (`PgOplog::ensure_schema` in `crates/connetto-server/src/oplog.rs`). The row images are one `event` blob, the serialized `ChangeEvent`, rather than the separate `old_row` and `new_row` that block named, because catchup replays the whole event through the same encoder the live path uses and never reads the two images apart. And `op` is a closed set of four, so it is an enum type rather than text carrying one of four words. `ensure_schema` creates the type and the column, `ChangeRecord::op` returns a `ChangeOp` rather than a string, and `crates/connetto-server/tests/pg_async.rs::pg_oplog_appends_and_reads_back` asserts the column's declared type and that Postgres refuses a verb outside the set, because nothing on the read path consults that column and it would otherwise be free to drift back.

Rows deleted from the underlying table are retained in the oplog as tombstones (`is_tombstone = TRUE`, the retained `event` being a delete). This allows the server to replay deletes to reconnecting clients.

**Decided (R6).** The catchup path carries the same two-version authorization obligation as the live path: the oplog must carry whatever those checks need, or the confidentiality leak moves to reconnect. What exactly the oplog must carry is an open question recorded in `08-authorization.md`.

**Decided (R16 part B): the entry also carries the prepared compressed patch, beside the event.** Catchup rebuilds it today, calling `Materializer::encode_patch` per record per subscription for bytes already built when the change was live, which no comparable system does. Storing it at append time removes the rebuild. **The event stays**, because catchup needs it twice for something else: `Materializer::match_row_consumers` decides whether the subscription matches, and `EventRow::current` supplies the post-image for the visibility question. So the entry grows by the patch on both the in-memory and the Postgres backend. `17-fan-out.md` owns the reasoning and the lifetime consequence, which is that a subscription must outlive its socket for a stored patch to exist at all.

### Retention window

The oplog is a ring buffer with a configurable retention window, bounded three ways, whichever is hit first:

| Bound | Default | Status |
|---|---|---|
| Maximum number of entries | 1M | **Built**, `OplogConfig::max_entries` |
| Maximum age | 72 hours | **Built**, `OplogConfig::max_age` |
| Maximum bytes | on by default | **Decided (R16 part B)** |

Entries outside the window are purged, and tombstones follow the same rules as any other entry. All three bounds are configurable per deployment. Pruning is unconditional on the window: no per-client cursor tracking, and a client outside it gets a full re-sync.

**Why bytes became a bound. Decided (R16 part B).** An entry count and an age are both counts of entries, and neither notices how wide the changed rows are. That was accurate while an entry held only the event, and storing the prepared patch beside it makes the footprint depend on row width: at the thirty-nine bytes R0 measured for a two-column row a full window is tens of megabytes, and at a few kilobytes per row it is gigabytes, held on the heap by `InMemoryOplog`. **Pruning names which bound fired**, in the structured log, because the failure mode of a byte bound set too small is extra full snapshots rather than lost data, and extra snapshots look like a client defect while being a retention setting. The default value has no measurement behind it.

**It is a memory bound and not an abuse defence.** One entry per change event, appended once regardless of who is watching or how many, so a caller cannot enlarge the log by connecting. Only a writer to Postgres adds entries.

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
  connection_id:    String,           // per-connection routing label, not identity
  session_token:    String,           // the run's durable handle, in the clear
  resume_token:     String,           // the credential proving that handle next time
  current_cursor:   Cursor,           // server's current position
  schema_version:   Option<SchemaVersion>,
  initial_credits:  u32,              // flow-control grant
  last_applied_seq: Option<u64>,      // durable mutation watermark
}
```

**Built (R2, R3).** The handle is real and everything operational keys on it: subql's per-subscription cursors resume through it, the exactly-once watermark is keyed on it alone, and the registry serves revocation and supersession by it. `resume_token` proves it, so a handle presented without the credential that proves it starts a fresh run instead of adopting the old one.

**Built (R3).** A grant that fails to resolve does not end the connection. The handshake succeeds on whatever resolved. See chapter 12.

After `HandshakeAck`, the client re-sends all its `Subscribe` messages.

---

## Reconnect Flow

### Case 1: Client's LSN is within the oplog window

1. Server checks `last_lsn` against the oldest entry in the oplog.
2. If `last_lsn >= oplog_min_lsn`: the server can replay.
3. For each re-declared subscription:
   - Server queries the oplog for entries since `last_lsn` that match the subscription and the caller's `Principal`, and sends each one. The format matches the live path (no special catchup message type).

**Decided (R16 part B): the patch is read, not rebuilt.** The entry already carries the prepared compressed bytes (see Structure), so catchup streams them and `Materializer::encode_patch` leaves this path. Two costs per record per client remain and are not addressed there: one predicate match, and one visibility question, the second of which R5b answers with no round trip in its cheapest tier. Catchup frames are not shared between clients, because two clients resuming from different positions receive different sequences, so catchup gets the copy elimination and not the frame sharing.

### Case 2: Client's LSN is outside the oplog window (or LSN = 0)

1. The client's resume cursor predates the oldest available oplog entry. It cannot catch up incrementally.
2. Server sends `FullResyncRequired { reason: "lsn_outside_retention_window" }`: the client shows a "re-syncing..." state and clears local data for affected subscriptions.
3. For each re-declared subscription:
   - Server sends `SnapshotBegin` (control), one or more `SnapshotPatch` bulk frames carrying the matching rows, then `SnapshotEnd(current_lsn)` (control).
4. The client applies the snapshot as a full replacement (not a merge).

The notice waits for the read (R38). `FullResyncRequired` is sent only once the fresh snapshot has been read, immediately ahead of its frames, because it is also the instruction to discard local rows. A read that fails instead draws the same single bare refusal as any other cause, so the caller learns nothing about the name it guessed and keeps its rows for a snapshot that never arrived.

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
