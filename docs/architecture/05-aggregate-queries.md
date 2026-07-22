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

## Delivered design (landed): two answer paths

Where an aggregate is answered is dictated by where the data lives, and it splits cleanly in two.

Client-authorized view (rows, and per-client aggregates over them). The client holds a local SQLite replica of exactly the rows it is authorized to see, kept current by CDC. Any aggregate scoped to that view (count of my orders, average of my amounts, and the full statistical family) is computed locally over the replica. This is the primary answer path: immediate, available offline, and correct as of the last sync. The server subscription for such a table carries row patches, not aggregate values, so its role is to keep the replica fresh (apply CDC, raise the reactive changed-tables signal, the client recomputes). On reconnect, catchup reconciles whatever was missed offline.

Global, cross-client statistics (non-RLS only). A statistic over rows the client does not hold (total order count across all users, an anonymized average) cannot be computed on the device, so only these go through the server-side delta accumulator that subql maintains in process and pushes as a `ClientEvent::Aggregate`. subql rejects an aggregator on an RLS-protected table at registration (`RegisterError::AggregatorOnRlsTable`), which connetto surfaces as a `ClientEvent::NonFatal` with the session intact, because a single shared accumulator cannot represent a value that differs per viewer. The server-side family is therefore global statistics only, by construction.

The delivered server-side delta family is `COUNT`, `COUNT(col)`, `SUM`, `AVG`, `VAR_POP`, `VAR_SAMP`, `STDDEV_POP`, and `STDDEV_SAMP`, seeded once through the connector then folded per CDC event. `MIN` and `MAX` stay on the re-execution path. See `10-subscription-materializer.md` for the server mechanics and `10-client-connection.md` for the client-query mechanism.

---

## Primary Approach: Server-Side Accumulator

`subql` maintains per-subscription accumulator state in memory for supported aggregate shapes. On a CDC event it updates the accumulator incrementally and emits a signed delta, which the materializer authorizes and pushes to the client as a new total or delta.

In the crate split, the accumulator state and its incremental maintenance live in `subql`. The materializer wraps them with authorization, the re-execution `Connector`, and per-session delivery (see `10-subscription-materializer.md`).

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
3. For GROUP BY subscriptions with a HAVING clause, evaluate the HAVING predicate against the updated accumulator to determine whether each affected group enters, exits, or stays in the result set.
4. If the accumulator value changed (and passes HAVING, if present), push `AggregateUpdate { sub_id, value }` to the client.

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

## Authorization in aggregates

Server-side aggregates are global, non-RLS statistics, so no per-viewer authorization is applied to the accumulator: every consumer of a given server-side aggregate observes the same value. This is enforced at registration, where subql refuses an aggregator on an RLS-protected table (see the delivered design above), so a server-side accumulator never straddles viewers with different authorized row sets.

A per-viewer aggregate, the value over the rows a given client may see, is not a server-side accumulator at all. The client computes it locally over its authorized replica, which already reflects that client's RLS view. The one place that knows a client's authorized rows, its own replica, is where the per-viewer aggregate is computed.

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
2. ~~**Having clauses**: should `HAVING` filters be supported in the aggregate spec? These apply after grouping and are harder to evaluate incrementally.~~ **Decided (Q5.2):** HAVING is evaluated server-side by `subql`. Groups that fail the HAVING predicate are never sent to the client. Follows the same two-tier pattern: in-process fast path for predicates `subql` can evaluate against accumulator state, SQL re-execution fallback for the rest. Per-session map tracks which queries require re-execution; coverage expands over time as `subql`'s fast solver adds support for more HAVING shapes.
3. ~~**Multi-table aggregates**: aggregates that JOIN multiple tables (e.g. `SELECT COUNT(*) FROM orders JOIN users ...`) are not addressed here. Are they in scope?~~ **Decided (Q5.3):** Yes, supported via re-execution fallback. Multi-table aggregates go into the per-session re-execution map. `subql` tracks all involved tables and triggers re-execution on CDC events from any of them. No in-process IVM for joins.
4. ~~**Accumulator persistence**: is the accumulator state kept only in memory (lost on server restart, requiring re-execution to rebuild) or persisted? Memory is simpler; persistence is more efficient for long-running subscriptions.~~ **Decided (Q5.4):** Not a connetto concern. `subql` owns accumulator lifecycle. Currently in-memory; rebuilt via re-execution on restart. Persistence is a future `subql` optimization.
5. ~~**Rate-limiting re-execution**: what is the right throttle for re-execution? Per-subscription cooldown? Global quota?~~ **Decided (Q5.5):** Not a connetto concern. `subql` owns re-execution scheduling — debounce, concurrency caps, and burst coalescing are internal to `subql`.
6. ~~**Delta format for GROUP BY**: when many groups change at once (e.g. a batch import), should the server send full group map replacement or a delta list? At what size does full replacement become preferable?~~ **Decided (Q5.6):** Dissolved. IVM path naturally produces per-group deltas (only changed groups). Re-execution fallback naturally produces full results. No threshold switching needed — the format follows from which path was used.
7. **Client schema for aggregate results**: the client stores aggregate results in local SQLite — what does the schema look like for GROUP BY results? A key-value table? A typed table generated from the spec?

---

## Decisions

**Server-side aggregates are global non-RLS statistics only; per-client aggregates are computed locally.** The earlier plan to route every aggregate through one per-user server-side path was reversed. A per-viewer value cannot be shared across consumers, and the client already holds its authorized rows, so it computes its own view locally over the replica. The server-side delta accumulator is reserved for global statistics over data the client does not replicate, and subql rejects aggregators on RLS tables to enforce it.

**Reason RLS kills materialized views:** a materialized view is a single computed result. Under RLS, `COUNT(*) FROM orders` returns a different value per user — there is no single server-side value to mirror. The result only exists in the context of a specific user's authorization context.

**Aggregate results are connetto-managed client storage, not application schema.** The schema symmetry principle (client mirrors server) applies to row-level data only. Aggregate results have no PostgreSQL counterpart — they are per-session computed values cached by connetto on the client.

**Wire format for aggregate results: JSON.** Results are delivered as JSON and deserialized on the client into `T: serde::DeserializeOwned`. The application defines the result struct; connetto provides the raw JSON.

---

## Notes

- The term "IVM" (Incremental View Maintenance) is borrowed from database research. This system implements a subset of IVM for the aggregate shapes listed above.
- A client that only needs row-level data should use a row-level subscription and compute aggregates locally — this is simpler and avoids server-side accumulator state.
- The accumulator approach is stateful on the server: each active aggregate subscription is a resource. Aggregate subscriptions should be used deliberately, not for every possible aggregate a UI might display.
