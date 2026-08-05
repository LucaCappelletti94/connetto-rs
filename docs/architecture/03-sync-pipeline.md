# 03: Sync Pipeline

**Status**: draft

---

## Purpose

Describe how mutations flow from client to server (write path) and how server-side changes flow back to clients (read/push path). This file covers the happy path and the main failure modes. Offline/reconnect is in `06-reconnect.md`.

---

## Write Path: Client → Server

### 1. Optimistic local apply

The client writes the mutation to its local SQLite immediately, before the server has confirmed it. This keeps the UI responsive.

The local write is tagged with a `pending` flag and the `client_seq`.

### 2. Local mutation queue

The mutation is persisted to a local queue table in SQLite (`META_DDL` in `crates/connetto-client/src/lib.rs`):

```sql
CREATE TABLE _connetto_pending (
    seq       INTEGER PRIMARY KEY,
    changeset BLOB NOT NULL
);
```

The queue survives process restart and network interruption.

**This replaces a seven-column sketch, and the difference is the design rather than the detail.** That sketch gave a row per operation, carrying the table name, the verb as one of three words in a text column, the key, the values and the base version as separate columns. What is built stores one sqlite-diff changeset per client sequence, which already carries the table, the verb, the key, the new values and the old image, in the same encoding the upload rides in. So the queue holds exactly what it sends rather than a parallel description of it, nothing has to be re-encoded on the way out, and the verb is a decoded value rather than a string nothing checks.

### 3. Sending

The mutation sender reads the head of the queue and sends a `MutationHeader` control frame followed by its `MutationPatch` bulk frame. It does not dequeue until it receives `MutationApplied`, `MutationReject`, or `MutationConflict`.

If the connection drops before an ack, the mutation is re-sent after reconnect (the server is idempotent on duplicate `client_seq` within a session).

### 4. Server validation and apply

On receiving a `MutationHeader` and its `MutationPatch`:

1. Check authorization: does the client have write permission for this table and row?
2. Check schema: does the payload match the current column set?
3. Check for conflict: compare `base_version` to the current row version in PostgreSQL.
4. If all checks pass: `BEGIN`, apply the mutation, `COMMIT`.
5. Reply with `MutationApplied { client_seq }`.

On authorization failure: `MutationReject(client_seq, reason=Unauthorized)`.
On schema mismatch: `MutationReject(client_seq, reason=SchemaMismatch)`.
On constraint violation: `MutationReject(client_seq, reason=Constraint(detail))`.

### 5. Conflict handling

A conflict occurs when `base_version` does not match the server's current row version, meaning the row was modified by someone else since the client last saw it.

The server sends `MutationConflict(client_seq, server_current_value)`.

The client's conflict resolution policy (configured per table) then runs:

| Strategy | Behavior |
|---|---|
| `ServerWins` | Client rolls back the optimistic write; applies server value. |
| `ClientWins` | Client re-sends the mutation without a `base_version` check (force-apply). |
| `LastWriterWins` | Compare timestamps; highest timestamp wins. |
| `Custom` | Application-provided merge function; result re-queued as a new mutation. |

### 6. Rollback on rejection

On `MutationReject`, the client:
1. Removes the mutation from the queue.
2. Reverts the optimistic local write.
3. Notifies the application layer of the rejection.

---

## Read/Push Path: Server → Client (CDC)

### 1. CDC source

`subql`'s `CdcSource` holds PostgreSQL's logical replication connection (`pgoutput` or `wal2json`) and surfaces typed events to the server. Conceptually each event is a `ChangeRecord`:

```
ChangeRecord {
  lsn:       u64,
  table:     String,
  op:        Op,          // Insert | Update | Delete
  pk:        Value,
  old_row:   Option<Row>, // for Update and Delete
  new_row:   Option<Row>, // for Insert and Update
}
```

### 2. Subscription matching

For each `ChangeRecord`, the CDC fanout engine queries the subscription registry:

> Which active subscriptions could be affected by a change to `table`?

This is an index lookup: subscriptions are indexed by the tables they reference. The result is a set of `(session_id, sub_id, spec)` candidates.

`subql` evaluates this in-process (bitmap prune plus predicate VM). Predicates it cannot decide against a single row image (JOINs, subqueries, MIN or MAX extreme removal) fall to re-execution against PostgreSQL through the materializer's `Connector`. See `10-subscription-materializer.md`.

### 3. Authorization filter

For each matched subscription, the auth engine checks:

- **Before the change**: if the client could see the old row, it may need a delete event.
- **After the change**: if the client can see the new row, it gets an insert/update event.
- **Visibility change**: a row becoming visible to a client is delivered as an insert. A row becoming invisible is delivered as a delete (even if the underlying op was an update).

Auth is evaluated in batch for all affected subscriptions at once, not per-subscription serially.

### 4. Delta packager

Matching, authorized changes are grouped into a `LivePatch` frame per session. The frame includes:

- The server LSN (so the client can advance its cursor)
- A list of `(sub_id, op, pk, new_values)` entries

Multiple subscriptions affected by the same underlying change may be bundled in the same `LivePatch` frame.

### 5. Delivery

The packaged `LivePatch` frame is placed in the session's outbound delivery queue. The delivery queue respects the flow-control window (see `02-protocol.md`). If the window is exhausted, delivery is paused.

The message is sent over the WebSocket connection.

### 6. Client apply

On receiving `LivePatch`:

1. Buffer if LSN is not contiguous with the last applied LSN (gap detected: see `06-reconnect.md`).
2. For each entry, apply to local SQLite: INSERT / UPDATE / DELETE on the relevant local table.
3. Clear the `pending` flag on local rows that match a confirmed mutation (matched by pk + LSN).
4. Persist the new LSN as the client's resume cursor.
5. Send `Ack(1)` to the server to replenish one flow-control credit.

---

## Interaction Between Write and Read Paths

When a client's own mutation is successfully applied server-side, it triggers a CDC event. That event flows through the fanout engine and may arrive back at the originating client as a `LivePatch` frame.

The client must recognize this and not double-apply:

- Server-confirmed rows are matched by pk + LSN (the LSN of the mutation's commit is included in `MutationApplied`).
- When a `LivePatch` frame arrives for a row the client already applied optimistically, the client reconciles: if the server value matches the local value, it just clears the `pending` flag. If it differs, it applies the server value (server wins by default for own-mutation reconciliation).

---

## Open Questions

1. ~~**Mutation window**: should the client pipeline multiple in-flight mutations (window of N) or enforce strict one-at-a-time? Pipelining increases throughput but complicates conflict handling when an early mutation in the window is rejected.~~ **Decided (Q3.1):** Dissolved by Q2.2. The client sends PatchSets, not individual mutations, so the concept of a mutation window does not apply.
2. ~~**Base version representation**: what exactly is `base_version`? Row-level timestamp? Vector clock? PostgreSQL `xmin`? Choice affects conflict granularity and server-side comparison cost.~~ **Decided (Q3.2):** `updated_at TIMESTAMPTZ` is the conflict token, using `WHERE id = ? AND updated_at = ?` to detect conflicts. `xmin` wraps internally and is unsuitable. Vector clocks and HLC are overkill for a single-authority PostgreSQL backend.
3. ~~**CDC source**: logical replication vs. trigger-based `NOTIFY`: tradeoffs in latency, setup complexity, and permission requirements.~~ **Decided (Q3.3):** Logical replication. The entire stack is built on logical replication, so no trigger-based `NOTIFY` path is needed or planned.
4. ~~**Predicate evaluation**: for complex subscription filters, should matching be done fully in-process, or should the server issue a small SQL query per CDC event? The latter is accurate but slower.~~ **Decided (Q3.4, Q8.1):** Subscription predicate matching is in-process via `subql` (bitmap-indexed candidate pruning plus predicate bytecode VM), with SQL re-execution fallback for predicates outside its scope (JOINs, subqueries, MIN or MAX extreme removal). Authorization is evaluated via OpenFGA using its Rust SDK (Q8.1), not per-row SQL queries.
5. ~~**Own-mutation echo suppression**: should the server suppress the CDC echo for the originating client (send only `MutationAck` and no `RowUpdate`), or always send both? Suppression is an optimization but complicates LSN tracking.~~ **Decided (Q3.5):** No suppression. The `LivePatch` frame arriving from the CDC fanout is the de-facto acknowledgement: the client matches it against pending ops by PK and clears the pending status. Dedicated reject or conflict messages handle error cases only.

---

## Decisions

*(none yet)*

---

## Notes

- The local mutation queue in SQLite is the durability boundary for writes. Anything not yet in this queue is lost on crash.
- The server LSN stored by the client is the durability boundary for reads. Loss of this value requires full re-sync.
