# 04 — Subscriptions

**Status**: draft

---

## Purpose

Define how clients express interest in data: the lifecycle of a subscription from creation through update to cancellation, and how the server manages the active subscription set.

Aggregate subscriptions are a distinct enough topic to have their own file (`05-aggregate-queries.md`). This file covers row-level SELECT subscriptions.

---

## What Is a Subscription?

A subscription is a standing query: the client says "give me all rows matching this predicate and keep me updated as they change."

A subscription has:

- A **subscription ID** (`sub_id`): a client-chosen string, unique within the session, used to correlate snapshot and update messages.
- A **spec** (`SubscriptionSpec`): describes what data the client wants.
- A **resume cursor**: the server LSN at which the client last received an update for this subscription.

---

## SubscriptionSpec

The spec describes the query the client wants to observe:

```
SubscriptionSpec {
  table:      String,
  filter:     Option<Predicate>,
  columns:    Option<Vec<String>>,   // None = all columns
  order_by:   Option<Vec<OrderBy>>,  // affects snapshot ordering only
  limit:      Option<u32>,           // affects snapshot; incremental updates ignore limit
}
```

### Predicate

A `Predicate` is a tree of conditions:

```
Predicate =
  | Eq(column, value)
  | Ne(column, value)
  | Lt(column, value)
  | Gt(column, value)
  | Le(column, value)
  | Ge(column, value)
  | In(column, [value])
  | And([Predicate])
  | Or([Predicate])
  | Not(Predicate)
```

Predicates are restricted to column comparisons against literal values — no subqueries, no cross-table joins in the predicate itself. This constraint makes server-side subscription matching feasible without issuing a SQL query per CDC event for simple cases.

### Open question: cross-table and join subscriptions

Subscribing to a join or a view is not supported in the initial design. If a client needs data from multiple tables, it creates one subscription per table and joins locally in SQLite.

This may be revisited if cross-table subscriptions are commonly needed.

---

## Subscription Lifecycle

### Registration

Client sends:

```
Subscribe {
  sub_id:  String,
  spec:    SubscriptionSpec,
}
```

Server:

1. Validates the spec (table exists, client has read permission, predicate is well-formed).
2. Records the subscription in the registry: `(session_id, sub_id) → (spec, auth_context, lsn=None)`.
3. Begins snapshot delivery (see below).

On validation failure, server sends `Error(sub_id, reason)` and does not add the subscription.

### Snapshot delivery

After registration, the server delivers an initial snapshot of all matching rows:

```
SnapshotBegin { sub_id }
SnapshotRows  { sub_id, rows: Vec<Row> }   // zero or more, batched
SnapshotEnd   { sub_id, lsn: u64 }
```

The snapshot is taken at a consistent point. The `lsn` in `SnapshotEnd` is the LSN at which the snapshot was read.

Any `RowUpdate` messages for this subscription with `lsn > snapshot_lsn` that arrive after `SnapshotEnd` are applied on top. Any `RowUpdate` messages with `lsn ≤ snapshot_lsn` are discarded.

The client buffers updates received during snapshot delivery and applies them after `SnapshotEnd`.

### Ongoing updates

After `SnapshotEnd`, the server delivers incremental updates via `RowUpdate` messages as the underlying data changes. See `03-sync-pipeline.md` for the CDC fanout path.

### Cancellation

Client sends:

```
Unsubscribe { sub_id }
```

Server removes the subscription from the registry. No further updates are delivered for this `sub_id`.

The client may delete the locally cached data for this subscription, or retain it for offline use — application's choice.

### Update (modify a subscription)

There is no in-place "modify subscription" message. To change a subscription:

1. Client sends `Unsubscribe(sub_id)`.
2. Client sends `Subscribe(sub_id, new_spec)`.

This triggers a new snapshot. The client may choose to retain the old local data until the new snapshot arrives to avoid a blank state.

---

## Server Subscription Registry

The registry maps `(session_id, sub_id)` to:

```
SubscriptionEntry {
  spec:         SubscriptionSpec,
  auth_context: AuthContext,
  last_lsn:     Option<u64>,    // None until SnapshotEnd is sent
  snapshot_lsn: Option<u64>,    // LSN at which snapshot was taken
}
```

The registry is in-memory (session lifetime). It is not persisted server-side; on reconnect the client re-declares all subscriptions.

---

## Matching CDC Events to Subscriptions

The fanout engine indexes subscriptions by table name. When a `ChangeRecord` arrives for table `T`:

1. Fetch all subscription entries for table `T` across all sessions.
2. For each entry, evaluate the subscription predicate against the changed row.
3. For subscriptions where the predicate matches (either `old_row` or `new_row`, or both), proceed to auth filter.

### Predicate evaluation on CDC events

For each CDC event:

- If `op = Insert`: evaluate predicate against `new_row`. If matches → deliver as insert.
- If `op = Delete`: evaluate predicate against `old_row`. If matches → deliver as delete.
- If `op = Update`:
  - Evaluate predicate against `old_row` and `new_row` separately.
  - `old matches, new matches` → deliver as update.
  - `old matches, new does not` → deliver as delete (row left the result set).
  - `old does not, new matches` → deliver as insert (row entered the result set).
  - `old does not, new does not` → no delivery needed.

This ensures clients maintain correct result sets even when rows move in and out of filter bounds.

---

## Re-subscribe on Reconnect

After reconnect, the client re-sends all `Subscribe` messages. The server treats each as a fresh subscription.

If the client's last known LSN for a subscription is still within the server's oplog window:

- The server can deliver a catchup patch (changes since that LSN) instead of a full snapshot.
- This optimization avoids re-sending the full snapshot for subscriptions where little has changed.

If the LSN is outside the window, or if the server does not support catchup patches: full snapshot re-delivery.

*(See `06-reconnect.md` for the full reconnect flow.)*

---

## Open Questions

1. **Predicate language scope**: is the current predicate tree sufficient, or do clients need more expressive filters (e.g. LIKE, IS NULL, array containment)? More expressiveness makes server-side in-process evaluation harder.
2. **Subscription count limits**: should the server enforce a maximum number of subscriptions per session? What happens when the limit is hit?
3. **Snapshot parallelism**: should the server deliver snapshots for multiple subscriptions concurrently, or serially? Concurrency helps latency but increases server load.
4. **Catchup patch optimization**: is the "deliver catchup patch instead of full snapshot on reconnect" optimization in scope for v1?
5. **Column projection**: if a client subscribes with `columns: Some([...])`, does the server track only those columns for matching, or does it always track all columns and project at delivery time?

---

## Decisions

*(none yet)*

---

## Notes

- `limit` in `SubscriptionSpec` is an approximation — it applies to the initial snapshot ordering. As rows are inserted/deleted, the live result set may grow beyond the original limit without the server enforcing it. Clients that need a strict top-N should manage this locally.
- The predicate tree is intentionally simple. Complex logic (full-text search, geographic queries) should be handled by materializing a computed column in PostgreSQL that can then be filtered simply.
