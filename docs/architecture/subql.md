# subql — Required Features & Responsibilities

Tracking document for features and responsibilities that connetto's architecture decisions have assigned to `subql`. Each item references the decision that created it and notes whether it has shipped. `subql` has since grown from an in-process predicate filter into a CDC subscription runtime, so the loop surface below is shipped and consumed by the Subscription Materializer (`10-subscription-materializer.md`).

---
## Loop surface (shipped)

`subql` now closes the CDC round trip and exposes it as a library the materializer drives:

- **CDC ingestion.** The `CdcSource` trait plus `PgStreamingCdcSource`, `PollingPgCdcSource`, and `SqliteCdcSource`. The source holds the replication connection. The materializer drives the consume loop and acks.
- **Event to patchset conversion.** `wal2json_patchset`, `pgoutput_patchset`, and `maxwell_patchset`, plus changeset counterparts, fold events over a source-agnostic catalog into one `sqlite-diff-rs` diffset.
- **Inbound apply.** `SubscriptionEngine::apply_diffset_bytes` applies uploaded SQLite session bytes to the source through native diesel adapters.
- **Re-execution engine.** The `reexec` module: `ReExecEngine` (trigger path) and `AutoResolvingEngine` (driven through a caller `Connector`). The DB query and its retry live in the caller.

The items below track the finer-grained responsibilities and their status.

---

## Predicate Evaluation

### UPDATE transition detection (Q3.4)
**Shipped.** `subql` evaluates both `old_row` and `new_row` for UPDATE and returns the transition per consumer through `ConsumerNotifications`: **enter** surfaces in `inserted`, **exit** in `deleted`, **update** in `updated`, and **no-op** yields nothing. connetto delivers correct INSERT and DELETE events when rows move in and out of a subscription's result set.

### SQL WHERE clause input (Q4.1)
`subql` accepts SQL WHERE clause text directly — no custom AST. Supported: `=`, `!=`, `<`, `>`, `IN`, `BETWEEN`, `LIKE`, `ILIKE`, `IS NULL`, `AND`, `OR`, `NOT`, arithmetic. Unsupported constructs are rejected at registration time.

---

## Resource Management

### Subscription registry limits (Q4.2)
Memory management for the subscription registry (mmap, eviction, caps) is owned by `subql`. connetto does not impose its own subscription count limits.

---

## Aggregate IVM

### MIN/MAX incremental maintenance (Q5.1)
**Shipped (v1).** The `reexec` module maintains single-table scalar MIN and MAX incrementally: inserts and most updates and deletes fold in memory from the event's row image. A re-execution fires only when the current extreme is removed or displaced, re-querying through the caller's `Connector` rather than a full scan. This is the `pg_ivm` approach. Streaming-style ordered state per group (Flink or RisingWave) remains overkill. Tie refinement and multi-group extents are future work.

### DISTINCT aggregates (Q5.1b)
`COUNT(DISTINCT col)`, `SUM(DISTINCT col)`, etc. require a per-group frequency map (`HashMap<V, u64>`). Aggregate calls on the same distinct column share one map with per-call counters (RisingWave model). Memory bounded by total distinct values across all groups.

### HAVING evaluation (Q5.2)
HAVING predicates are evaluated server-side by `subql` after updating group accumulators. Two-tier pattern:
- **Fast path:** HAVING predicates evaluable against in-memory accumulator state (e.g. `HAVING COUNT(*) > 10`).
- **Re-execution fallback:** Unsupported HAVING constructs go into the per-session re-execution map.

Goal: expand fast solver coverage over time to reduce re-execution.

---

## Re-execution Fallback Path

### Per-session query map (Q3.4, Q5.2, Q5.3)
`subql` maintains a per-session map of queries that cannot be handled by the fast in-process solver. These require SQL re-execution against PostgreSQL when a CDC event touches any involved table. Query types that currently land here:
- WHERE predicates with JOINs, subqueries, or unsupported functions (Q3.4)
- HAVING predicates outside the fast solver's scope (Q5.2)
- Multi-table (JOIN) aggregates (Q5.3)

The map should track which tables each query depends on, so CDC events can be routed efficiently.

### Multi-table CDC routing (Q5.3)
For queries involving JOINs, `subql` must track all involved tables and trigger re-execution when a CDC event arrives on any of them.

### Re-execution rate limiting (Q5.5)
`subql` collapses duplicate re-execution within a dispatch batch (`AutoResolvingEngine` via `consumers_batch`, or the caller above the bare `ReExecEngine`). Cross-batch debounce, the global concurrency cap, and retry live above the engine, in the materializer and its `Connector`, never inside `subql` (see `10-subscription-materializer.md`). The goals are unchanged:
- **Per-subscription debounce:** coalesce rapid CDC bursts into a single re-execution on the trailing edge, since the latest state matters, not the intermediate states.
- **Global concurrency cap:** bound concurrent re-execution queries against PostgreSQL to protect the database under load.

---

## Accumulator Lifecycle

### In-memory with re-execution rebuild (Q5.4)
Accumulators are currently in-memory. On server restart, they are rebuilt via re-execution. Persisting accumulator state to avoid rebuild cost is a future `subql` optimization — not a connetto concern.
