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

**Status note.** This section describes the aspirational typed-subscription builder (author a diesel query, render it to SQL). It is not the delivered API. The delivered mechanism is a single `subscribe(sub_id, query)` that takes SQL text, described under "Client query mechanism and the local-first answer model" below.

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

## Native driver: `ConnettoConnection` (v1 landed)

`connetto-client`'s native connection is `ConnettoConnection` (renamed from the earlier `SyncClient`). It implements diesel's `Connection` and `LoadConnection`, so the application runs ordinary diesel queries directly on `&mut conn` (`users::table.load(&mut conn)`, `insert_into(...).execute(&mut conn)`). Execution delegates to the managed capture connection, so those writes are recorded for upload. `conn()` remains as an escape hatch to the underlying `SqliteConnection`, and the driver methods `subscribe()`, `push()`, `pump_one()`, `flush()`, and `next_event()` sit alongside.

Implementing `Connection` requires diesel's `i-implement-a-third-party-backend-and-opt-into-breaking-changes` feature (which unseals `ConnectionSealed`), enabled on `connetto-client`. `establish` is stubbed to error, since the connection is built by the async `connect(...)` that owns the transport and handshake, not from a URL. That is the one impedance mismatch of layering an async-transport connection under diesel's synchronous `Connection`, and diesel's query methods never call `establish`.

Mutation interception (auto-submit) is landed. An `on_commit` hook on the app connection sets a dirty flag whenever a local write commits. The hook may only signal, since SQLite forbids using the connection inside it and the async send cannot run there. The driver's `flush()` then drains the capture session and uploads the mutation, so the app never calls `push()`. `next_event()` flushes pending writes and applies one inbound server frame in a single step, returning the event plus the tables that changed.

Rejection rollback is landed. Each pushed changeset is retained keyed by `client_seq` (bounded by `PENDING_CAP`). When the server replies `MutationReject` or `MutationConflict`, the connection inverts that changeset with `invert_changeset` and applies the inverse on the apply connection, undoing the optimistic local write. The apply connection is not observed by the capture session, so the rollback is never re-uploaded, and a row a concurrent server patch already changed is left as the server left it (the inverse is omitted on any conflict). Both events carry the affected rows as `AffectedRow { table, key }`, the table name and primary-key values (`Vec<KeyValue>`) decoded from the pushed changeset via `op.primary_key()`, so the app can show which rows reverted.

Reactivity is landed. `on_update` hooks on both the app connection and the apply connection record the name of every table whose rows change (local writes and applied server patches alike) into a shared set, surfaced as `Reactive::changed_tables` from `next_event()` for the app to re-query. The connection is `Send` (the capture `Session` is `Send`, mirroring diesel's own `SqliteConnection`), so it can move between threads, but it is driven by one task at a time and is not `Sync`. In WASM this same object is the worker-side connection with a worker `Transport`, while the main-thread tab uses a separate proxy connection that forwards queries over `postMessage`.

The delta aggregate family is now delivered end to end: `COUNT`, `COUNT(col)`, `SUM`, `AVG`, `VAR_POP`, `VAR_SAMP`, `STDDEV_POP`, and `STDDEV_SAMP` are seeded once through the connector and then folded from subql's per-event deltas, delivered as `ClientEvent::Aggregate`. The `MIN`/`MAX` re-execution aggregates remain alongside them. Both are declared through a single `subscribe(sub_id, query)` (there is no longer a `subscribe_aggregate`), and the server classifies row versus aggregate from the SQL. An aggregate on an RLS-protected table is refused at registration (subql's `AggregatorOnRlsTable`) and surfaces as `ClientEvent::NonFatal` with the session intact. Verified end to end by the `loop_emu` tests `delta_aggregates_bootstrap_and_fold_through_the_client`, `aggregate_on_rls_table_is_rejected_without_closing`, and `aggregate_subscription_bootstraps_and_updates_through_the_client` (the `MIN` path), and by the Docker-gated `pg_async` test `async_pg_delta_aggregate_bootstraps_family`. Conflict convergence is landed and rides the existing sync stream: once a `MutationConflict` rolls the local write back, the server's authoritative row arrives as a normal `LivePatch` and applies on the apply connection with the server-wins resolver, so the client converges without the conflict message carrying any server state, verified end to end by the `loop_emu` test `conflicting_write_converges_to_server_after_rollback`. Still ahead: the WASM variants above.

---

## Client query mechanism and the local-first answer model

The client declares a subscription with a single method, `subscribe(sub_id, query)`, where `query` is SQL text. There is no separate `subscribe_aggregate`, and the wire `SubscriptionSpec` carries no kind discriminant. The server classifies the query from its SQL through subql (a row projection, a delta aggregate, or a `MIN`/`MAX` re-execution) and dispatches internally, so the client never declares which path it wants. The client reacts to self-describing events instead: row subscriptions surface as `SnapshotBegin`/`LivePatch`/`SnapshotEnd` applied to the replica, aggregates as `ClientEvent::Aggregate`. Unsupported syntax and aggregators on RLS tables are refused at registration and surface as `ClientEvent::NonFatal` with the session intact. `unsubscribe(sub_id)` cancels either kind.

The query travels as a string because it is parsed and planned server-side by subql against a runtime Postgres catalog, in Postgres dialect. A diesel query object does not serialize and is bound to the client's SQLite replica schema and dialect, so it is the wrong shape to hand the server directly. A future typed-subscription builder can still give compile-time checking: author the query with diesel against the replica schema, then render and translate it to the Postgres string that `subscribe` takes (the SQLite-to-Postgres translation for the shared-schema case already exists in pg2sqlite). That builder is additive and produces the same string this method accepts.

Local-first is the reason queries run against the replica, not merely validation. The replica holds exactly the rows the client is authorized to see, kept current by CDC, so for anything scoped to the client's own view the replica is the source of truth and executing the query locally is the primary answer path: it returns immediately, works offline, and is correct as of the last sync. The server subscription does not answer the query, it keeps the replica fresh (apply CDC, raise the reactive changed-tables signal, the client recomputes), and catchup reconciles on reconnect. The one class the replica cannot answer is a global, cross-client statistic over rows it does not hold, which is exactly what the server-side delta aggregate family serves (see `05-aggregate-queries.md`).

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
