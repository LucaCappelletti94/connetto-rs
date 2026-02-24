# 05 — Aggregate Queries

**Status**: draft

---

## Purpose

Aggregate queries (COUNT, SUM, AVG, MIN, MAX, and GROUP BY variants) present a fundamentally different challenge from row-level subscriptions. This file documents the problem, the primary approach, and the fallback.

---

## The Core Tension

For row-level subscriptions, the client can maintain a local replica and compute aggregates locally at query time. This works when the subscription covers the full dataset the aggregate operates on.

It breaks down when:

- The aggregate spans a large table the client cannot fully replicate (e.g. total order count across all users — a client should not receive all orders)
- The aggregate is over data the client is not authorized to see row-by-row (e.g. anonymized statistics)
- The client does not want the memory/bandwidth cost of syncing all rows just to show a count

In these cases, the server must compute and maintain the aggregate and push updates to the client.

---

## Primary Approach: Server-Side Accumulator

The server maintains per-subscription accumulator state for supported aggregate shapes. When the underlying data changes, the server updates the accumulator incrementally and pushes a delta (or new total) to the client.

### Supported aggregate shapes (initial scope — open question)

| Shape | Incremental update rule |
|---|---|
| `COUNT(*)` | +1 on insert, -1 on delete, 0 on update |
| `COUNT(col)` | +1 on insert where col IS NOT NULL, -1 on delete where col IS NOT NULL, ±1 on update based on nullability change |
| `SUM(col)` | +new_val on insert, -old_val on delete, +(new_val - old_val) on update |
| `MIN(col)` | Incremental only if new value < current min (insert) or old value was the min (delete/update) — else no push needed or re-query needed |
| `MAX(col)` | Symmetric to MIN |
| `COUNT(*) GROUP BY col` | Maintain a map of group → count; update affected bucket |
| `SUM(col) GROUP BY grp` | Maintain a map of group → sum |

MIN and MAX with deletions are problematic for incremental updates: if the current minimum is deleted, the new minimum requires scanning all remaining rows. This is the main reason MIN/MAX fall back to re-execution more readily than COUNT/SUM.

### Accumulator state

```
AggregateSubscriptionEntry {
  sub_id:       String,
  spec:         AggregateSpec,
  auth_context: AuthContext,
  state:        AccumulatorState,  // variant-specific
  last_lsn:     u64,
}
```

`AggregateSpec` includes:
- The table being aggregated
- The aggregate function(s)
- An optional WHERE predicate (same predicate language as row-level subscriptions)
- Optional GROUP BY columns

### Incremental update delivery

When a CDC event arrives:

1. Check if it affects any aggregate subscriptions (by table + predicate matching).
2. For each affected subscription, apply the incremental update rule to the accumulator.
3. If the accumulator value changed, push `AggregateUpdate { sub_id, value }` to the client.

For GROUP BY aggregates, the `value` is the updated group map (or a delta of changed groups).

### Client side

The client stores the aggregate result in a local SQLite table with a schema matching the aggregate shape. On receiving `AggregateUpdate`, it replaces the stored value.

The client does not compute the aggregate locally — it trusts the server's accumulator.

---

## Fallback: Full Re-execution

For aggregate shapes not supported by the incremental engine, or when the accumulator is known to be invalid (e.g. after a MIN deletion), the server re-executes the query against PostgreSQL and pushes the full result.

The re-execution fallback is also used:

- At subscription time (initial value)
- After a reconnect (to ensure the accumulator is current)
- When a CDC event cannot be matched to a known incremental rule (e.g. a trigger-generated change with no old/new row data)

Re-execution is more expensive but always correct. The server should rate-limit re-executions for subscriptions that change at high frequency.

---

## Authorization in Aggregates

Aggregate subscriptions do not expose individual rows to the client. The server applies row-level authorization *before* updating the accumulator:

- For a `COUNT(*)` subscription: only count rows the client is authorized to see.
- For a `SUM(col)` subscription: only sum values from rows the client is authorized to see.

This means the accumulator's state reflects the authorized view, not the raw table state.

When a row's authorization status changes (e.g. it becomes visible to the client), the accumulator is updated as if that row was newly inserted.

---

## Group-By Aggregates

GROUP BY introduces additional complexity:

- The group key is part of the accumulator map.
- A new group appearing is an insert to the group map.
- A group's count/sum reaching zero removes it from the group map (or sets it to zero, depending on application semantics).
- The client receives the full group map on subscription, then deltas per CDC event.

For large group maps, deltas are preferable to re-sending the full map. The delta format is a list of `(group_key, new_value)` pairs.

---

## Interaction with the CDC Path

Aggregate subscriptions share the CDC source and subscription matching infrastructure with row-level subscriptions. The difference is in step 3 of the fanout:

- Row-level: identify which rows changed and deliver them.
- Aggregate: update the accumulator and deliver the new aggregate value.

Both paths are indexed by table name and filtered by predicate.

---

## Open Questions

1. **Which aggregate shapes get IVM (incremental view maintenance) vs. re-execution fallback?** The initial list above is a starting point. MIN and MAX with deletions are the hardest — are they in scope for IVM?
2. **Having clauses**: should `HAVING` filters be supported in the aggregate spec? These apply after grouping and are harder to evaluate incrementally.
3. **Multi-table aggregates**: aggregates that JOIN multiple tables (e.g. `SELECT COUNT(*) FROM orders JOIN users ...`) are not addressed here. Are they in scope?
4. **Accumulator persistence**: is the accumulator state kept only in memory (lost on server restart, requiring re-execution to rebuild) or persisted? Memory is simpler; persistence is more efficient for long-running subscriptions.
5. **Rate-limiting re-execution**: what is the right throttle for re-execution? Per-subscription cooldown? Global quota?
6. **Delta format for GROUP BY**: when many groups change at once (e.g. a batch import), should the server send full group map replacement or a delta list? At what size does full replacement become preferable?
7. **Client schema for aggregate results**: the client stores aggregate results in local SQLite — what does the schema look like for GROUP BY results? A key-value table? A typed table generated from the spec?

---

## Decisions

*(none yet)*

---

## Notes

- The term "IVM" (Incremental View Maintenance) is borrowed from database research. This system implements a subset of IVM for the aggregate shapes listed above.
- A client that only needs row-level data should use a row-level subscription and compute aggregates locally — this is simpler and avoids server-side accumulator state.
- The accumulator approach is stateful on the server: each active aggregate subscription is a resource. Aggregate subscriptions should be used deliberately, not for every possible aggregate a UI might display.
