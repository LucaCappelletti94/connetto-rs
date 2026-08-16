# 03: Sync Pipeline

**Status**: draft

---

## Purpose

Describe how mutations flow from client to server (write path) and how server-side changes flow back to clients (read/push path). This file covers the happy path and the main failure modes. Offline/reconnect is in `06-reconnect.md`.

---

## Write Path: Client → Server

### 1. Optimistic local apply

The client writes the mutation to its local SQLite immediately, before the server has confirmed it. This keeps the UI responsive.

Nothing tags the row itself. The write is recorded by the change-capture session, and pending state lives in the queue below, keyed by `client_seq`. What makes the write "optimistic" is only that the local apply precedes the server's answer: a rejection or a conflict later inverts the captured changeset (see 6 below).

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

1. Decompress and parse the patchset. A payload that does not parse is refused with `reason=Malformed`, and one naming tables or columns outside the current schema with `reason=SchemaMismatch`.
2. Open one transaction and bind the caller (`SET LOCAL app.user_id`, plus the held share keys per R4), so Postgres row-level security gates the writes.
3. For each version-bearing op, probe the row: `WHERE id = ? AND updated_at = ?` against the op's recorded old `updated_at` (the conflict token, Q3.2). A stale or missing row rolls the transaction back and replies `MutationConflict` carrying the server's current copy when the row still exists.
4. Apply the changeset. A row-level-security refusal (a `WITH CHECK` violation, or an `UPDATE`/`DELETE` finding no visible row) rolls back and replies `MutationReject(reason=Unauthorized)`. A constraint violation replies `reason=Constraint(detail)`.
5. On commit: `MutationApplied { client_seq }`, which is what retires the client's pending record.

### 5. Conflict handling

A conflict occurs when a version-bearing op's recorded `updated_at` does not match the server's current row version, meaning the row was modified by someone else since the client last saw it.

The server sends `MutationConflict(client_seq, table, server_row)`, with the server's copy absent when the row is gone.

**The client's response is one policy, revert, and the application layers its own merge on top.** An earlier sketch here tabled four per-table strategies (`ServerWins`, `ClientWins`, `LastWriterWins`, `Custom`). None of that configuration exists and none is planned: the connection inverts the retained changeset and applies the inverse with capture suspended, undoing the optimistic write without re-uploading it, and a row a concurrent server patch already changed is left as the server left it. Both `MutationReject` and `MutationConflict` reach the application carrying the affected rows (`AffectedRow { table, key }`) and, for a conflict, the server's current copy, so an application wanting anything other than server-wins re-writes on top of the reverted state with data it was handed.

### 6. Rollback on rejection

On `MutationReject`, the client retires the pending record, inverts the retained changeset with capture suspended (reverting the optimistic local write), and surfaces the rejection with its affected rows to the application.

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

**Built (R5a, R5b): one question per changed row, asked once for every watcher.** `may_see` takes the row and all matched watchers and returns one verdict each, so authorization is evaluated in batch rather than per-subscription serially. Behind the seam `FgaAuth` (`crates/connetto-server/src/openfga.rs`) is built as of R5b (2026-08-12): `RowPolicy` answers locally from the row's own values (zero round trips for connetto's own policy shape) and `OpenFgaPolicy` batches the rest. The binary constructs it as of 2026-08-12, replacing the `RlsAuth` round trip per watcher that R0 measured as the whole throughput ceiling.

**What the filter consults today is the current row version only, and the two-check form is Decided (R6), not built.** The built behaviour and its two consequences:

- An event whose post-image exists (insert, update) is delivered only to watchers who may see the current row. A row whose update made it **invisible** to a watcher is silently dropped: no delete is synthesized, and that client keeps its stale copy for ever. R6 closes this by consulting the previous version when the current one is absent or invisible and delivering the tombstone the client already applies.
- A delete or truncate has no post-image, so it replays to **every** subscriber of the table unconditionally, disclosing the primary key of a deleted row to callers who could never see it. R6 filters tombstones on the previous version.

**Distinct from both, and built (R44): a predicate departure.** A row that stops matching a subscription's own `WHERE` clause (visibility unchanged) is announced to exactly the subscribers it left, as a delete marked with the patchset op's indirect flag, and the client applies it only when no surviving subscription still covers the row. See `04-subscriptions.md`. Losing authorization is R6's unbuilt case, leaving the predicate window is R44's built one.

### 4. Delta packager

One patchset is encoded per CDC event, compressed once, and the identical bytes go to every matched consumer as a `LivePatch` bulk frame carrying that subscription's `sub_id`, the event's `cursor`, and `patchset_zstd`. There is no per-session bundling and no `(op, pk, values)` entry list: the payload is a Zstd-compressed SQLite patchset, exactly what the client applies. An event that also has departures encodes one further payload, the marked departure delete, shared by every subscriber the row left (R44).

### 5. Delivery

The packaged `LivePatch` frame is placed in the session's outbound delivery queue. The delivery queue respects the flow-control window (see `02-protocol.md`). If the window is exhausted, delivery is paused.

The message is sent over the WebSocket connection.

### 6. Client apply

On receiving `LivePatch`:

1. Apply the patchset to local SQLite inside one transaction, with capture suspended so server rows are never re-uploaded. Frames arrive in commit order on an ordered transport, so there is no gap detection and no reorder buffer on the live path: a gap can only open across a disconnect, and the resume cursor plus catchup or full resync covers it (`06-reconnect.md`).
2. Honour the departure marker: an indirect delete applies only when no surviving subscription's predicate still matches the row (R44).
3. Persist the frame's cursor as the resume position, atomically with the apply.
4. Return flow-control credit to the server (`AckCredits`).

**A resume position is never recorded for data the replica has not applied. Invariant, R33.** It is a promise that everything up to it is already here, and the next attach asks the server only for what follows, so recording one early loses the rows in between with nothing on either side able to notice. The live path holds it by writing the cursor and the rows in one transaction, step 3 above. The snapshot path has no rows of its own to bind to, because its resume position arrives in `SnapshotEnd` rather than on the patch, and holds it instead by that frame sharing the delivery queue with the rows (`02-protocol.md`).

---

## Interaction Between Write and Read Paths

When a client's own mutation is successfully applied server-side, it triggers a CDC event. That event flows through the fanout engine and arrives back at the originating client as an ordinary `LivePatch`.

**The echo is not suppressed and needs no recognition.** Applying it is idempotent: the patch carries the values the client already holds, and re-application converges under the same rule as the snapshot overlap (R28 part A). Pending bookkeeping never rides the echo: the dedicated `MutationApplied { client_seq }` reply is what retires the pending record, and the handshake's durable watermark (`last_applied_seq`) retires anything acknowledged while the client was away.

---

## Open Questions

1. ~~**Mutation window**: should the client pipeline multiple in-flight mutations (window of N) or enforce strict one-at-a-time? Pipelining increases throughput but complicates conflict handling when an early mutation in the window is rejected.~~ **Decided (Q3.1):** Dissolved by Q2.2. The client sends PatchSets, not individual mutations, so the concept of a mutation window does not apply.
2. ~~**Base version representation**: what exactly is `base_version`? Row-level timestamp? Vector clock? PostgreSQL `xmin`? Choice affects conflict granularity and server-side comparison cost.~~ **Decided (Q3.2):** `updated_at TIMESTAMPTZ` is the conflict token, using `WHERE id = ? AND updated_at = ?` to detect conflicts. `xmin` wraps internally and is unsuitable. Vector clocks and HLC are overkill for a single-authority PostgreSQL backend.
3. ~~**CDC source**: logical replication vs. trigger-based `NOTIFY`: tradeoffs in latency, setup complexity, and permission requirements.~~ **Decided (Q3.3):** Logical replication. The entire stack is built on logical replication, so no trigger-based `NOTIFY` path is needed or planned.
4. ~~**Predicate evaluation**: for complex subscription filters, should matching be done fully in-process, or should the server issue a small SQL query per CDC event? The latter is accurate but slower.~~ **Decided (Q3.4, Q8.1):** Subscription predicate matching is in-process via `subql` (bitmap-indexed candidate pruning plus predicate bytecode VM), with SQL re-execution fallback for predicates outside its scope (JOINs, subqueries, MIN or MAX extreme removal). Authorization is evaluated via OpenFGA using its Rust SDK (Q8.1), not per-row SQL queries.
5. ~~**Own-mutation echo suppression**: should the server suppress the CDC echo for the originating client (send only `MutationAck` and no `RowUpdate`), or always send both? Suppression is an optimization but complicates LSN tracking.~~ **Decided (Q3.5):** No suppression. The echo `LivePatch` is delivered like any other and re-applies idempotently. **Mechanism note corrected 2026-08-08**: this entry used to say the echo was the de-facto acknowledgement, matched against pending ops by primary key. It is not and never was built that way: the dedicated `MutationApplied` reply retires the pending record by `client_seq`, and the echo carries no pending bookkeeping at all.

---

## Decisions

*(none yet)*

---

## Notes

- The local mutation queue in SQLite is the durability boundary for writes. Anything not yet in this queue is lost on crash.
- The server LSN stored by the client is the durability boundary for reads. Loss of this value requires full re-sync.
