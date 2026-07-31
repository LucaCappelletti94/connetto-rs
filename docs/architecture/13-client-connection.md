# 13: Client Connection Layer

**Status**: draft

---

## Purpose

Define the client-side Diesel connection wrapper that makes connetto's sync, reactivity, and aggregate query routing transparent to the application. The app writes normal Diesel queries. The connection layer handles everything underneath.

---

## The Problem

The Dioxus application queries local SQLite via Diesel. Several concerns must be handled transparently at the connection level:

1. **Aggregate query routing**: the app writes `SELECT region, COUNT(*) FROM orders GROUP BY region` against its domain table. But the client may not have all rows, so the result must come from a server-computed aggregate cached in a backing table, not from a local computation over a partial replica.
2. **Mutation interception**: writes against local SQLite must be captured and queued for server-bound PatchSet generation.
3. **Reactivity via update hooks**: the Diesel SQLite hooks PR ([diesel-rs/diesel#4969](https://github.com/diesel-rs/diesel/pull/4969)) provides `on_insert`, `on_update`, `on_delete` callbacks that fire during `sqlite3_step()`. These drive UI re-rendering in Dioxus.
4. **Dedicated worker boundary**: in WASM, the real SQLite connection lives inside a dedicated `Worker` elected via Web Locks. Tabs in the main thread need a proxy connection that serializes queries over `postMessage`.

---

## Connection Variants

### `ConnettoConnection`: Native (direct)

Used in native (non-WASM) builds. Wraps a real `SqliteConnection` in-process.

```
ConnettoConnection {
    inner: SqliteConnection,
    aggregate_registry: AggregateRegistry,
    // + mutation queue, hook wiring, etc.
}
```

Implements Diesel's `Connection` and `LoadConnection` traits. All query routing, aggregate rewriting, mutation interception, and hook setup happen here.

### `ConnettoWorkerConnection`: WASM dedicated worker

Used inside the dedicated `Worker` in browser builds. Nearly identical to `ConnettoConnection` but backed by OPFS SQLite. Owns the WebSocket to the server, applies PatchSets, and serves queries from tabs via `postMessage`.

### `ConnettoProxyConnection`: WASM Tab / Main Thread

Used in the main thread (Dioxus rendering context) in browser builds. Implements the same Diesel `Connection` trait but does not hold a real SQLite connection. Instead:

1. Renders the query to SQL (via `QueryFragment`)
2. Serializes the SQL + bind parameters over `postMessage` to the dedicated worker
3. The worker executes it on `ConnettoWorkerConnection` and returns serialized rows
4. The proxy deserializes the result into Diesel's expected row format

The app code is identical on both sides: same Diesel queries, same model types.

| Variant | Context | SQLite access | Aggregate rewrite |
|---|---|---|---|
| `ConnettoConnection` | Native | In-process | Yes |
| `ConnettoWorkerConnection` | WASM dedicated worker | OPFS | Yes |
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

1. Renders the query to SQL via Diesel's `QueryFragment` (deterministic: same expression always produces the same SQL string)
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

Since Diesel generates SQL deterministically from the same type-level query expression, the subscription and the read produce identical SQL, with no fuzzy matching or normalization needed beyond what Diesel already guarantees.

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
- **`on_commit` / `on_rollback`**: used for batching: buffer change notifications during a transaction and flush on commit.
- **`find_by_rowid`**: loads the full row after the hook fires (since callbacks cannot use the connection during the hook). Used when the UI needs the actual row data, not just the change event.

For aggregate backing tables, the same hooks fire when connetto updates them with server-pushed results. The Dioxus component that depends on the aggregate re-queries and re-renders (same mechanism as row-level data).

---

## Native driver: `ConnettoConnection` (v1 landed)

`connetto-client`'s native connection is `ConnettoConnection` (renamed from the earlier `SyncClient`). It implements diesel's `Connection` and `LoadConnection`, so the application runs ordinary diesel queries directly on `&mut conn` (`users::table.load(&mut conn)`, `insert_into(...).execute(&mut conn)`). Execution delegates to the managed capture connection, so those writes are recorded for upload. `conn()` remains as an escape hatch to the underlying `SqliteConnection`, and the driver methods `subscribe()`, `push()`, `pump_one()`, `flush()`, and `next_event()` sit alongside.

Implementing `Connection` requires diesel's `i-implement-a-third-party-backend-and-opt-into-breaking-changes` feature (which unseals `ConnectionSealed`), enabled on `connetto-client`. `establish` is stubbed to error, since the connection is built by the async `connect(...)` that owns the transport and handshake, not from a URL. That is the one impedance mismatch of layering an async-transport connection under diesel's synchronous `Connection`, and diesel's query methods never call `establish`.

Mutation interception (auto-submit) is landed. An `on_commit` hook on the app connection sets a dirty flag whenever a local write commits. The hook may only signal, since SQLite forbids using the connection inside it and the async send cannot run there. The driver's `flush()` then drains the capture session and uploads the mutation, so the app never calls `push()`. `next_event()` flushes pending writes and applies one inbound server frame in a single step, returning the event plus the tables that changed.

Rejection rollback is landed. Each pushed changeset is retained keyed by `client_seq` (bounded by `PENDING_CAP`). When the server replies `MutationReject` or `MutationConflict`, the connection inverts that changeset with `invert_changeset` and applies the inverse with capture suspended (`Session::set_enabled` toggled off for the apply, re-enabled by a drop guard), undoing the optimistic local write without re-uploading it. A row a concurrent server patch already changed is left as the server left it (the inverse is omitted on any conflict). Both events carry the affected rows as `AffectedRow { table, key }`, the table name and primary-key values (`Vec<KeyValue>`) decoded from the pushed changeset via `op.primary_key()`, so the app can show which rows reverted. Server patches apply through the same suspension window: the client holds ONE SQLite connection for capture and apply alike, the topology `sqlite-wasm-rs` requires on wasm (no multiple connections per database), adopted on native too so both platforms share it.

Reactivity is landed. The connection's `on_update` hook records the name of every table whose rows change (local writes and applied server patches alike, capture suspension does not silence it) into a shared set, surfaced as `Reactive::changed_tables` from `next_event()` for the app to re-query. The connection is `Send` (the capture `Session` is `Send`, mirroring diesel's own `SqliteConnection`), so it can move between threads, but it is driven by one task at a time and is not `Sync`. In WASM this same object is the worker-side connection with a worker `Transport`, while the main-thread tab uses a separate proxy connection that forwards queries over `postMessage`.

The delta aggregate family is now delivered end to end: `COUNT`, `COUNT(col)`, `SUM`, `AVG`, `VAR_POP`, `VAR_SAMP`, `STDDEV_POP`, and `STDDEV_SAMP` are seeded once through the connector and then folded from subql's per-event deltas, delivered as `ClientEvent::Aggregate`. The `MIN`/`MAX` re-execution aggregates remain alongside them. Both are declared through a single `subscribe(sub_id, query)` (there is no longer a `subscribe_aggregate`), and the server classifies row versus aggregate from the SQL. An aggregate on an RLS-protected table is refused at registration (subql's `AggregatorOnRlsTable`) and surfaces as `ClientEvent::NonFatal` with the session intact. Verified end to end by the `loop_emu` tests `delta_aggregates_bootstrap_and_fold_through_the_client`, `aggregate_on_rls_table_is_rejected_without_closing`, and `aggregate_subscription_bootstraps_and_updates_through_the_client` (the `MIN` path), and by the Docker-gated `pg_async` test `async_pg_delta_aggregate_bootstraps_family`. Conflict convergence is landed and rides the existing sync stream: once a `MutationConflict` rolls the local write back, the server's authoritative row arrives as a normal `LivePatch` and applies under the same capture suspension with the server-wins resolver, so the client converges without the conflict message carrying any server state, verified end to end by the `loop_emu` test `conflicting_write_converges_to_server_after_rollback`. Still ahead: the WASM variants above.

---

## Client query mechanism and the local-first answer model

The client declares a subscription with a single method, `subscribe(sub_id, query)`, where `query` is a SQLite-dialect `SELECT`, the same dialect it runs against its local replica. There is no separate `subscribe_aggregate`, and the wire `SubscriptionSpec` carries no kind discriminant. The server reverse-translates the query to Postgres and classifies it through subql (a row projection, a delta aggregate, or a `MIN`/`MAX` re-execution), dispatching internally, so the client never declares which path it wants. The client reacts to self-describing events instead: row subscriptions surface as `SnapshotBegin`/`LivePatch`/`SnapshotEnd` applied to the replica, aggregates as `ClientEvent::Aggregate`. A query that cannot be translated, unsupported syntax, and aggregators on RLS tables are all refused at registration and surface as `ClientEvent::NonFatal` with the session intact. `unsubscribe(sub_id)` cancels either kind.

Translation happens server-side. The client sends its native SQLite dialect, and the materializer reverse-translates it to Postgres with `pg2sqlite` against its own catalog before subql parses it, so the server stays the schema authority and the client stays catalog-free. Bind values never ride as spliced strings: the wire carries the SQL with `?` placeholders plus typed `SubscriptionSpec.binds`, and the server substitutes them into the parsed statement (AST-level) before reverse translation.

Local-first is the reason queries run against the replica, not merely validation. The replica holds exactly the rows the client is authorized to see, kept current by CDC, so for anything scoped to the client's own view the replica is the source of truth and executing the query locally is the primary answer path: it returns immediately, works offline, and is correct as of the last sync. The server subscription does not answer the query, it keeps the replica fresh (apply CDC, raise the reactive changed-tables signal, the client recomputes), and catchup reconciles on reconnect. The one class the replica cannot answer is a global, cross-client statistic over rows it does not hold, which is exactly what the server-side delta aggregate family serves (see `05-aggregate-queries.md`).

The typed layer on top is delivered as live queries. `ConnettoClient::start(conn)` wraps the connection behind one shared lock and a background pump, and `watch(query)` takes an ordinary typed diesel query: it runs it against the replica for the immediate, offline-capable answer, renders it to SQLite SQL plus bind values with diesel's own query builder and bind collector, and registers the server subscription. The returned `LiveQuery` caches its rows, refreshes whenever a table the query reads changes (server patches and local writes alike), signals each real change through an awaitable `changed()`, and unsubscribes on drop. Dropping the last `ConnettoClient` clone closes the connection cleanly. `subscribe(sub_id, query)` remains the string-level primitive beneath `watch`. Verified end to end by the `loop_emu` test `live_query_stays_fresh_and_unsubscribes_on_drop`.

The two answer paths have two typed methods, and each refuses the other's queries. `watch` serves row projections from the replica. `watch_value` serves scalar aggregates (`COUNT`, `SUM`, `AVG`, `MIN`, `MAX`, variance, stddev) and inverts the answer path: no local read happens, because the replica holds only this client's authorized subset and would answer a global statistic wrongly, so every value (the bootstrap included) arrives as a server `AggregateUpdate` push decoded from JSON into the app's type on a `LiveValue` handle with the same `changed()` and drop-unsubscribe contract. The client classifies the rendered SQL's shape (one ungrouped call to a known aggregate) to route between them, and a misrouted query fails immediately with an error naming the right method. Verified by the `loop_emu` test `live_value_tracks_a_server_aggregate`.

On top of both sits the primary app-facing verb: postfix `query.live(&client)` (trait `Watchable`, with `client.live(query)` as a delegate). It dispatches at compile time on diesel's own aggregation marker, projected from the built query's select clause, so a row projection resolves to `LiveQuery` and a scalar aggregate to `LiveValue`, and a misrouted query does not compile at all. The aggregate's decoded value type is derived from the selection's SQL type through `AggregateWire`, whose decoders follow the wire's rendering rules (`COUNT` an exact `i64`, `SUM` as `Option<f64>` via diesel's own `Numeric` SQL type, extremes carrying the column's type), so a wrong decode type is also uncompilable. `LiveHandle` unifies both handles (`snapshot()`, `changed()`, `sub_id()`), which is what lets one framework hook serve rows and scalars alike. The one shape outside the typed verb is a boxed query (`.into_boxed()` erases the select clause), which stays on the runtime-guarded explicit methods. Pinned by the `live_dispatch` test suite and exercised end to end by both live `loop_emu` tests.

## Framework adapters: `connetto-dioxus` and `connetto-yew`

**Built.** Two single-file crates wrap `ConnettoClient`'s live-query API as UI framework hooks.

Both expose `use_live` and `use_live_fn`. `use_live` takes a `Watchable` query and yields `UseLive<Vec<R>>` for a row projection or `UseLive<Option<V>>` for a scalar aggregate, chosen at compile time from the query's shape through `LiveHandle` (the same compile-time dispatch `query.live(&client)` uses). `use_live_fn` is the row-path peer for boxed (`.into_boxed()`) or otherwise dynamically built queries: they carry no compile-time aggregation marker and are not `Clone`, so they cannot ride `use_live`. It takes a builder closure instead and yields `UseLive<Vec<R>>` with the same lifecycle. Both hooks capture their arguments on first render. Re-render with a different query has no effect: remount to change it.

Both hooks compose with connetto's drop-unsubscribe contract: dropping the `LiveHandle` sends the unsubscribe, and the hook ties the handle's lifetime to the component's. That wiring differs between the two crates, and the difference is why two crates exist.

**`connetto-dioxus`** (`crates/connetto-dioxus/src/lib.rs`): the handle is owned by a component-scoped Dioxus task. Dioxus cancels scope-bound tasks on unmount, so the drop is implicit with no extra wiring.

**`connetto-yew`** (`crates/connetto-yew/src/lib.rs`): Yew's `spawn_local` is detached, unlike a Dioxus scope task, so unmounting the component does not cancel it. The hook wraps the driver future in `Abortable` and returns an effect cleanup that calls `abort()`, which drops the handle at the task's next await point and sends the unsubscribe.

---

## Open Questions

1. ~~**Query serialization for `ConnettoProxyConnection`**: what is the format for serializing a Diesel query + bind parameters over `postMessage`? Raw SQL string + binds as MessagePack? Or a higher-level representation?~~ **Decided (Q2.1, `crates/connetto-web/src/port.rs`):** The tab-to-worker channel uses the same binary framing as the WebSocket transport: one tag byte followed by MessagePack-encoded payload (`ControlMessage` or `BulkMessage`). Query messages are `ControlMessage` frames carrying the SQL text and typed binds.
2. ~~**Proxy result format**: how are result rows serialized back from the worker to the tab? Row-level MessagePack? Or raw SQLite row bytes?~~ **Decided (Q2.1, `crates/connetto-web/src/port.rs`):** Row updates arrive as `BulkMessage` frames (SQLite PatchSets, MessagePack). Snapshot control events and aggregate pushes arrive as `ControlMessage` frames (MessagePack). Aggregate values within those messages are JSON, per Q2.1.
3. ~~**Connection pooling in the worker**: does the dedicated worker maintain a single `ConnettoWorkerConnection` or a pool? SQLite is single-writer, so writes are serialized regardless, but concurrent reads from multiple tabs might benefit from multiple reader connections (WAL mode).~~ **Decided (shipped, `ReplicaStorage::delete_db` in `crates/connetto-web/src/storage.rs`):** The sahpool VFS allows one connection per database. A second open handle trips a `debug_assert`, making pooling impossible in the browser build. The worker maintains a single `ConnettoWorkerConnection`.
4. ~~**Aggregate rewrite and Diesel type safety**: the rewritten query (`SELECT * FROM _connetto_agg_{hash}`) must produce rows that Diesel can deserialize into the app's result type. How is the column ordering guaranteed to match?~~ **Decided (Q5.7):** The `_connetto_agg_{hash}` backing table is superseded by the generic `_connetto_aggregates` table storing results as `result_json TEXT`. JSON deserialization via `T: serde::DeserializeOwned` is field-name-based, so column ordering is not a concern.

---

## Notes

- The custom connection approach means the app's Diesel code is backend-agnostic at the query level: it works against local SQLite, remote PostgreSQL (if ever needed), or the connetto proxy, all through the same trait.
- The aggregate rewrite layer is conceptually similar to PostgreSQL's query rewriting for materialized views, but implemented at the application level in Rust.
- The Diesel hooks PR is a prerequisite for the reactivity story. Without it, the client would need to poll for changes or use a separate notification channel.
