# subql — Required Features & Responsibilities

Tracking document for features and responsibilities that connetto's architecture decisions have assigned to `subql`. Each item references the decision that created it.

---

## Predicate Evaluation

### UPDATE transition detection (Q3.4)
`subql` currently only evaluates `new_row` for UPDATE events. It needs to evaluate both `old_row` and `new_row` and return a transition: **enter** (old didn't match, new matches), **exit** (old matched, new doesn't), **update** (both match, values changed), **no-op** (neither matches, or no visible change). This is required for connetto to deliver correct INSERT/DELETE events when rows move in and out of a subscription's result set.

### SQL WHERE clause input (Q4.1)
`subql` accepts SQL WHERE clause text directly — no custom AST. Supported: `=`, `!=`, `<`, `>`, `IN`, `BETWEEN`, `LIKE`, `ILIKE`, `IS NULL`, `AND`, `OR`, `NOT`, arithmetic. Unsupported constructs are rejected at registration time.

---

## Resource Management

### Subscription registry limits (Q4.2)
Memory management for the subscription registry (mmap, eviction, caps) is owned by `subql`. connetto does not impose its own subscription count limits.

---

## Aggregate IVM

### MIN/MAX incremental maintenance (Q5.1)
Currently unsupported — falls back to re-execution. The required approach: on delete of the current extremum, re-query only the affected group against PostgreSQL (not a full scan). This is the `pg_ivm` approach. Streaming-style ordered state per group (Flink/RisingWave) is overkill.

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
`subql` owns scheduling of SQL re-execution queries:
- **Per-subscription debounce:** coalesce rapid CDC bursts into a single re-execution (fire on trailing edge — latest state matters, not intermediate states).
- **Global concurrency cap:** limit the number of concurrent re-execution queries against PostgreSQL to protect the database under load.

---

## Accumulator Lifecycle

### In-memory with re-execution rebuild (Q5.4)
Accumulators are currently in-memory. On server restart, they are rebuilt via re-execution. Persisting accumulator state to avoid rebuild cost is a future `subql` optimization — not a connetto concern.
