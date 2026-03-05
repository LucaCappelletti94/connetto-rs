# 10 — Client Connection Layer

**Status**: draft

---

## Purpose

Define the client-side Diesel connection wrapper that makes connetto's sync, reactivity, and aggregate query routing transparent to the application. The app writes normal Diesel queries; the connection layer handles everything underneath.

---

## The Problem

The Dioxus application queries local SQLite via Diesel. Several concerns must be handled transparently at the connection level:

1. **Aggregate query routing**: the app writes `SELECT region, COUNT(*) FROM orders GROUP BY region` against its domain table. But the client may not have all rows — the result must come from a server-computed aggregate cached in a backing table, not from a local computation over a partial replica.
2. **Mutation interception**: writes against local SQLite must be captured and queued for server-bound PatchSet generation.
3. **Reactivity via update hooks**: the Diesel SQLite hooks PR ([diesel-rs/diesel#4969](https://github.com/diesel-rs/diesel/pull/4969)) provides `on_insert`, `on_update`, `on_delete` callbacks that fire during `sqlite3_step()`. These drive UI re-rendering in Dioxus.
4. **SharedWorker boundary**: in WASM, the real SQLite connection lives inside a `SharedWorker`. Tabs in the main thread need a proxy connection that serializes queries over `postMessage`.

---

## Connection Variants

### `ConnettoConnection` — Native (direct)

Used in native (non-WASM) builds. Wraps a real `SqliteConnection` in-process.

```
ConnettoConnection {
    inner: SqliteConnection,
    aggregate_registry: AggregateRegistry,
    // + mutation queue, hook wiring, etc.
}
```

Implements Diesel's `Connection` and `LoadConnection` traits. All query routing, aggregate rewriting, mutation interception, and hook setup happen here.

### `ConnettoWorkerConnection` — WASM SharedWorker

Used inside the `SharedWorker` in browser builds. Nearly identical to `ConnettoConnection` but backed by OPFS SQLite. Owns the WebSocket to the server, applies PatchSets, and serves queries from tabs via `postMessage`.

### `ConnettoProxyConnection` — WASM Tab / Main Thread

Used in the main thread (Dioxus rendering context) in browser builds. Implements the same Diesel `Connection` trait but does not hold a real SQLite connection. Instead:

1. Renders the query to SQL (via `QueryFragment`)
2. Serializes the SQL + bind parameters over `postMessage` to the `SharedWorker`
3. The worker executes it on `ConnettoWorkerConnection` and returns serialized rows
4. The proxy deserializes the result into Diesel's expected row format

The app code is identical on both sides — same Diesel queries, same model types.

| Variant | Context | SQLite access | Aggregate rewrite |
|---|---|---|---|
| `ConnettoConnection` | Native | In-process | Yes |
| `ConnettoWorkerConnection` | WASM SharedWorker | OPFS | Yes |
| `ConnettoProxyConnection` | WASM tab | `postMessage` → worker | Delegated to worker |

---

## Aggregate Query Routing

### Registration

The app registers an aggregate subscription using a Diesel query expression:

```rust
let query = orders::table
    .group_by(orders::region)
    .select((orders::region, count_star()));

conn.subscribe_aggregate(query)?;
```

At registration time, the connection:

1. Renders the query to SQL via Diesel's `QueryFragment` (deterministic — same expression always produces the same SQL string)
2. Sends the SQL to the server as an aggregate subscription
3. Creates a backing SQLite table (`_connetto_agg_{hash}`) with columns matching the query's SELECT list
4. Stores the rendered SQL as a lookup key in the `AggregateRegistry`

### Query interception

When the app later executes the same query:

```rust
let stats = orders::table
    .group_by(orders::region)
    .select((orders::region, count_star()))
    .load::<OrdersByRegion>(&mut conn)?;
```

The connection's `LoadConnection::load` implementation:

1. Renders the incoming query to SQL
2. Looks up the SQL in `AggregateRegistry`
3. **Match**: rewrites to `SELECT region, cnt FROM _connetto_agg_{hash}` and executes against the backing table
4. **No match**: passes through to the inner `SqliteConnection` (executes locally)

Since Diesel generates SQL deterministically from the same type-level query expression, the subscription and the read produce identical SQL — no fuzzy matching or normalization needed beyond what Diesel already guarantees.

### Safety: unsubscribed aggregate detection

If the app executes an aggregate query (GROUP BY, COUNT, SUM, etc.) against a table that is a partial replica and there is no matching aggregate subscription, the result is silently wrong (computed over incomplete data). The connection can detect this:

- It knows which tables are synced (partial replicas)
- It knows which aggregate queries are subscribed
- An unsubscribed aggregate on a synced table → warning or error, configurable by the app

---

## Mutation Interception

Writes (INSERT, UPDATE, DELETE) executed through the connection are:

1. Applied to local SQLite immediately (optimistic)
2. Captured and queued in `_connetto_pending_ops` for server-bound PatchSet generation
3. The update hook fires, notifying the UI of the local change

When the server confirms (via CDC echo) or rejects, the pending status is updated. This is the write path described in `03-sync-pipeline.md`, wired through the connection layer.

---

## Reactivity via Diesel SQLite Hooks

The connection sets up Diesel's SQLite hooks ([diesel-rs/diesel#4969](https://github.com/diesel-rs/diesel/pull/4969)):

- **`on_insert` / `on_update` / `on_delete`**: fire synchronously during `sqlite3_step()` when PatchSets are applied or when the app writes locally. These notify Dioxus that specific tables changed, triggering re-queries and UI re-renders.
- **`on_commit` / `on_rollback`**: used for batching — buffer change notifications during a transaction and flush on commit.
- **`find_by_rowid`**: loads the full row after the hook fires (since callbacks cannot use the connection during the hook). Used when the UI needs the actual row data, not just the change event.

For aggregate backing tables, the same hooks fire when connetto updates them with server-pushed results. The Dioxus component that depends on the aggregate re-queries and re-renders — same mechanism as row-level data.

---

## Open Questions

1. **Query serialization for `ConnettoProxyConnection`**: what is the format for serializing a Diesel query + bind parameters over `postMessage`? Raw SQL string + binds as MessagePack? Or a higher-level representation?
2. **Proxy result format**: how are result rows serialized back from the worker to the tab? Row-level MessagePack? Or raw SQLite row bytes?
3. **Connection pooling in the worker**: does the `SharedWorker` maintain a single `ConnettoWorkerConnection` or a pool? SQLite is single-writer, so writes are serialized regardless, but concurrent reads from multiple tabs might benefit from multiple reader connections (WAL mode).
4. **Aggregate rewrite and Diesel type safety**: the rewritten query (`SELECT * FROM _connetto_agg_{hash}`) must produce rows that Diesel can deserialize into the app's result type. How is the column ordering guaranteed to match?

---

## Notes

- The custom connection approach means the app's Diesel code is backend-agnostic at the query level — it works against local SQLite, remote PostgreSQL (if ever needed), or the connetto proxy, all through the same trait.
- The aggregate rewrite layer is conceptually similar to PostgreSQL's query rewriting for materialized views, but implemented at the application level in Rust.
- The Diesel hooks PR is a prerequisite for the reactivity story. Without it, the client would need to poll for changes or use a separate notification channel.
