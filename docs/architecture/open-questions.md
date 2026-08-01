# Open Questions: Master Index

All numbered open questions across the architecture docs, in one place.
Each entry links back to its source file where context lives.

---

## 00 · Overview

**Q0.1** ~~What is the initial target transport: WebSocket only, or also HTTP long-poll / SSE for environments where WebSocket is restricted?~~

**Decision: WebSocket only.** HTTP fallback was motivated by legacy transparent proxies and serverless runtimes. Transparent proxies are a non-issue with `wss://`. Serverless runtimes are incompatible with the architecture entirely: they are stateless and short-lived, with no place to hold subscription state, run a CDC listener, or maintain a session registry. HTTP fallback is dead weight.

**Q0.2** ~~Should the client and server crates live in this repository or in separate crates published independently?~~

**Decision: single Cargo workspace in this repo, multiple crates.** connetto-rs is a reusable transport layer library. All crates live in one workspace (core types, server, client, WASM adapters) and are published independently to crates.io so downstream projects can depend on only the pieces they need.

**Q0.3** ~~Is the initial target native clients, WASM/browser, or both simultaneously?~~

**Decision: both simultaneously.** The immediate consumer is a Dioxus application, which compiles to both native and WASM from the same codebase. The trait boundaries between the sync engine and I/O adapters (transport, storage, file store) must be correct from day one, with no retrofitting WASM later.

---

## 01 · Pieces Inventory

**Q1.1** ~~Should the core traits (`Transport`, `Store`, etc.) live in a dedicated `connetto-core` crate, or inline in this repo?~~

**Decision: single `connetto-core` crate.** Shared types and traits (wire format, `Transport`, `Store`, `FileStore`, `AuthPolicy`, etc.) live in `connetto-core`. Both `connetto-server` and `connetto-client` depend on it. Neither depends on the other.

**Q1.2** ~~Which pieces are in-scope for a first prototype versus later iterations?~~

**Decision: all pieces (A to L) are in scope for v1, except file sync (J).** The core transport, subscriptions, mutation path, CDC push, reconnect, schema distribution, authorization, aggregate queries, and WASM adapters all need to work together, and none can be deferred without breaking the whole. File sync (J) is handled by a separate stack. The integration point with connetto is a future design concern.

**Q1.3** ~~Is `SharedWorker` a requirement for multi-tab browser support, or is tab-per-worker acceptable initially?~~

**Decision: `SharedWorker` only, no fallback.** Chrome for Android and WebView Android have never supported `SharedWorker`, but Android users are expected to install the native app rather than use the web version. The web target is desktop browsers and iOS Safari, both of which support `SharedWorker` (Chrome since 2010, Firefox since 2014, Safari since 16.0 / 2022). A `Worker` fallback adds implementation complexity for an audience that should not be using the web target in the first place.

**CORRECTED, 2026-07-30, on both of its reasons.**

The technical reason is void. connetto does not use a `SharedWorker` and cannot: `createSyncAccessHandle` is `[Exposed=DedicatedWorker]` in the WHATWG File System IDL, and Chrome does not expose the `Worker` constructor inside a `SharedWorker` either, so there is no nested-worker route. The shipped topology is a dedicated worker with a Web Locks election and `BroadcastChannel`. See the correction under Q9.1 for the full evidence and the corrected support table under Q9.2.

One factual claim above is also now false. Chrome for Android gained `SharedWorker` in version 148, stated explicitly in `mdn/browser-compat-data`. It was true when written. WebView Android still lacks it, verified by measurement, and that no longer matters.

**The product reason is now also withdrawn, on the maintainer's statement.** It read that Android users install the native app, so the web target was desktop browsers and iOS Safari. That framing came from the `SharedWorker` premise, which is void, and it was never a considered product position in its own right. **Android is supported both in the browser and as a native app.** Both Android platforms run connetto's web topology, with a floor of Chrome Android 109 and WebView 102.

The usage data argues the same way. Chrome for Android is 92.9% of Android browser usage and the single largest browser in the caniuse dataset at 44.75% of all tracked usage, so excluding Android from the web target would exclude the largest browser population there is.

**One split matters and is easy to miss.** Android in a browser and Android in an embedded WebView are different surfaces for key custody. Chrome for Android has had the WebAuthn PRF extension since version 116, so it gets the gate in `14-at-rest-encryption.md`. Android WebView has no WebAuthn at all, not merely no PRF, so it never gets it. And a Dioxus Android app renders in that same WebView while running Rust natively, which would want the OS keystore instead, except that `keyring` has no Android backend. See `14-at-rest-encryption.md`.

---

## 02 · Protocol

**Q2.1** ~~**Serialization format**: which format? Candidates are MessagePack, Protobuf/FlatBuffers, JSON, and CBOR. Decision needed before any message types are implemented.~~

**Decision: MessagePack (`rmp-serde`) for control plane. JSON only for aggregate results.**
- PatchSets (INSERT/UPDATE/DELETE): own binary wire format, handled separately.
- Control plane (Handshake, Subscribe, Unsubscribe, Ack, errors, etc.): typed Rust structs serialized with MessagePack via `rmp-serde`. Known shape at compile time, no dynamic data.
- Aggregate results: JSON via `serde_json`, deserialized client-side into `T: serde::DeserializeOwned`. JSON is used here and only here because the result shape is genuinely unknown at compile time.

Principle: JSON is reserved exclusively for data whose shape is not known at compile time. Everything with a defined structure uses MessagePack.

**Q2.2** ~~**Mutation window**: single in-flight mutation vs. sliding window of N (what is N, and how does it interact with client-seq ordering)?~~

**Decision: dissolved.** The client sends PatchSets (SQLite binary change format), not individual mutations. The server unpacks the PatchSet into individual operations, translates them into PostgreSQL SQL, and applies them within a single transaction using `SAVEPOINT` per operation. Failed ops roll back to their savepoint, and successful ops commit. The server returns per-op results with failure reasons. Dependency handling (FK cascades) is handled by PostgreSQL's constraint system. The client rolls back only failed optimistic local writes and updates a `_connetto_pending_ops` tracking table so the UI can show granular sync status (pending/confirmed/failed with error reason). The CDC echo of successfully applied ops carries the information a client needs to retire a pending record. **Corrected (Built):** the shipped wire also sends an explicit `MutationApplied` per mutation, so the happy path is acknowledged both ways. See the correction under Q3.5.

**Q2.3** ~~**Versioning / evolution**: how are breaking changes to `WireMessage` handled? A version field in `Handshake`? A negotiation step?~~

**Decision: version field in `Handshake`, server rejects incompatible clients with a clear error.** Client sends `protocol_version: u32` in the handshake. Server closes the connection with an explicit `FatalError` if the version does not match. No negotiation, just a clear runtime message so app developers immediately know a version mismatch is the cause.

**Q2.4** ~~**HTTP fallback**: is HTTP SSE + POST (or long-poll) in scope for v1?~~

**Decision: dissolved by Q0.1.** WebSocket only.

**Q2.5** ~~**Compression**: per-message or per-frame compression (e.g. `permessage-deflate` for WebSocket)? Worthwhile for large snapshots?~~

**Decision: Zstd at the application layer on PatchSet and snapshot payloads only.** Benchmarks showed Zstd optimal for PatchSet payloads. Compression is applied at the application layer (not via `permessage-deflate`) so it targets only bulk binary data: PatchSets and snapshots. Control plane messages are not compressed. This maps cleanly onto the two WebSocket frame types: binary frames (PatchSets, snapshots) get Zstd, and text frames (control plane) do not.

---

## 03 · Sync Pipeline

**Q3.1** ~~**Mutation window**: should the client pipeline multiple in-flight mutations (window of N) or enforce strict one-at-a-time? Pipelining increases throughput but complicates conflict handling when an early mutation in the window is rejected.~~

**Decision: dissolved by Q2.2.** Client sends PatchSets. The window concept does not apply.

**Q3.2** ~~**Base version representation**: what exactly is `base_version`? Row-level timestamp? Vector clock? PostgreSQL `xmin`? The choice affects conflict granularity and server-side comparison cost.~~

**Decision: `updated_at TIMESTAMPTZ` as the conflict token.** The application schema already has `updated_at` on all entities. Conflict detection uses `WHERE id = ? AND updated_at = ?`. Zero affected rows means conflict. `xmin` is not suitable (wraps, internal). Vector clocks and HLC are overkill for a single-authority PostgreSQL backend. Clock skew across mesh nodes is an acknowledged open problem, not solved universally in the industry (BDR/PGD takes the same tradeoff). Mitigation: require tight clock sync (NTP/PTP) as an operational prerequisite on the mesh.

**Q3.3** ~~**CDC source**: logical replication vs. trigger-based `NOTIFY`, covering tradeoffs in latency, setup complexity, and required PostgreSQL permissions.~~

**Decision: logical replication.** The entire stack is already built on logical replication. No trigger-based `NOTIFY` path is needed.

**Q3.4** ~~**Predicate evaluation on CDC events**: for complex subscription filters, should matching be done fully in-process, or should the server issue a SQL query per CDC event? In-process is faster. SQL is more accurate for complex predicates.~~

**Decision: in-process via `subql`, with SQL re-execution fallback for unsupported cases.** `subql` handles in-process predicate evaluation with bitmap-indexed candidate pruning, bytecode VM evaluation, WAL parsing, and predicate deduplication. For predicates outside its scope (JOINs, subqueries, unsupported functions, MIN or MAX extreme removal), the `reexec` engine re-runs the registered query against PostgreSQL through a caller `Connector` when a change touches an involved table. UPDATE transition detection has shipped: `subql` evaluates both `old_row` and `new_row` and returns enter, exit, update, or no-op per consumer, so connetto delivers correct INSERT and DELETE events when rows move in and out of a result set.

**Q3.5** ~~**Own-mutation echo suppression**: should the server suppress the CDC echo for the originating client (send only `MutationAck`, no `LivePatch`), or always send both? Suppression is an optimization but complicates LSN tracking.~~

**Decision: no suppression, and the shipped wire went further than this decision recorded.** The client matches an incoming `LivePatch` against its `_connetto_pending_ops` table by primary key and clears the pending status, so the echo does carry the information an acknowledgement would.

**Correction (Built).** The original wording said no separate acknowledgement message exists. One does: `MutationApplied { client_seq }` is a `ControlMessage` variant in `crates/connetto-core/src/messages/mutation.rs`, and the server sends it per mutation in `SessionManager` (`crates/connetto-server/src/session.rs`). So the outcome of every mutation is reported explicitly, alongside `MutationReject` and `MutationConflict` for the failure cases. The decision not to suppress the echo stands. The claim that no acknowledgement message exists does not.

---

## 04 · Subscriptions

**Q4.1** ~~**Predicate language scope**: is the current predicate tree (Eq, Ne, Lt, Gt, In, And, Or, Not) sufficient, or do clients need more expressive filters (LIKE, IS NULL, array containment)? More expressiveness makes in-process server evaluation harder.~~

**Decision: SQL WHERE clauses as strings, not a custom predicate tree.** connetto accepts SQL WHERE clause text directly, matching `subql`'s input format. The predicate tree defined in `04-subscriptions.md` is superseded. No custom AST. The supported predicate language is whatever `subql` supports (=, !=, <, >, IN, BETWEEN, LIKE, ILIKE, IS NULL, AND, OR, NOT, arithmetic). Unsupported constructs are rejected at registration time by `subql`.

**Q4.2** ~~**Subscription count limits**: should the server enforce a maximum number of subscriptions per session? What happens when the limit is reached?~~

**Decision: not a connetto concern.** Subscription registry memory and resource limits are owned by `subql`. Memory management strategies (mmap, eviction, caps) belong there. connetto delegates subscription management to `subql` and does not impose its own limits.

**Q4.3** ~~**Snapshot parallelism**: should the server deliver snapshots for multiple subscriptions concurrently or serially? Concurrency helps latency but increases server load.~~

**Decision: priority-tiered delivery.** Subscriptions declare a priority (e.g. 0 to 3, 0 = highest). Higher-priority tiers complete before lower-priority tiers begin. Within a tier, subscriptions can be delivered concurrently (interleaved on the WebSocket, tagged by `sub_id`). This is the PowerSync model, the state of the art for user-facing sync. Memory is bounded (one tier at a time), backpressure is natural (serial between tiers), and the UX-critical data renders first. Head-of-line blocking is mitigated because the blocked subscriptions are low-priority by definition. Client-side SQLite is single-writer, so parallel delivery within a tier is bounded by client write throughput.

**Q4.4** ~~**Catchup patch optimization**: is the "deliver catchup patch instead of full snapshot on reconnect" optimization in scope for v1?~~

**Decision: yes, in scope.** On reconnect, if the client's LSN is within the oplog (server-side operation log) retention window, the server delivers only the changes since that LSN, not a full snapshot. This avoids re-sending data the client already has after brief network interruptions.

**Q4.5** ~~**Column projection**: if a client subscribes with `columns: Some([...])`, does the server track only those columns for change matching, or always track all columns and project at delivery time?~~

**Decision: out of scope, because the capability does not exist and the design does not want it.** `SubscriptionSpec` in `crates/connetto-core/src/messages/subscription.rs` carries only `priority`, `query` and `binds`, so the `columns` field this question assumes was never on the wire. Projection is expressed inside the `SELECT` itself, delivery is a patchset of whole rows, and the client's own query does the projection locally against its replica. So there is nothing to decide between: the server never watched a subset of columns and no mechanism proposes that it should.

---

## 05 · Aggregate Queries

**Q5.1** ~~**IVM scope**: which aggregate shapes get incremental view maintenance vs. re-execution fallback? MIN and MAX with deletions are the hardest. Are they in scope for IVM?~~

**Decision: follows `subql` capabilities.** The plain aggregates and a v1 single-table MIN/MAX path have shipped.

Supported incrementally by `subql`: COUNT(*), COUNT(col), SUM(col), AVG(col), and the variance and standard-deviation family (VAR_POP, VAR_SAMP, STDDEV_POP, STDDEV_SAMP).
MIN and MAX ship as a v1 incremental path (single-table scalar) that folds inserts and most updates and deletes in memory and re-executes only when the current extreme is removed or displaced.

**MIN/MAX approach**: not self-maintainable, since deleting the current extreme requires touching the base table (Gupta et al., VLDB'93). The standard production approach is to re-query only the affected group, not a full scan. This is what PostgreSQL `pg_ivm` does. Streaming systems (Flink, RisingWave) maintain ordered state per group to avoid any SQL round-trip, at O(distinct values) memory per group, which is overkill for connetto. `subql`'s `reexec` engine implements the targeted re-query on removal of the extreme.

References:
- Gupta et al., "Maintaining Views Incrementally", VLDB'93: https://www.vldb.org/conf/1993/P157.PDF
- PostgreSQL `pg_ivm` (targeted group re-query for MIN/MAX): https://github.com/sraoss/pg_ivm
- Flink `MinWithRetractAggFunction` (MapView state): https://github.com/apache/flink/blob/master/flink-table/flink-table-runtime/src/main/java/org/apache/flink/table/runtime/functions/aggregate/MinWithRetractAggFunction.java
- RisingWave ordered state + TopNStateCache: https://github.com/risingwavelabs/risingwave/blob/main/docs/dev/src/design/aggregation.md

**Q5.1b** ~~**DISTINCT aggregates**: how should `COUNT(DISTINCT col)`, `SUM(DISTINCT col)`, etc. be maintained incrementally? This is a `subql` implementation concern, documented here for SOTA reference.~~

**Decision: exact per-group frequency map. Needs to be implemented in `subql`.**

DISTINCT aggregates (`COUNT(DISTINCT col)`, `SUM(DISTINCT col)`) are harder than plain aggregates because they require tracking **which values are present** and **how many rows carry each value**, not just a running total.

**Core algorithm (frequency map per group):**

For `AGG(DISTINCT col_d) GROUP BY col_g`, maintain a map from `(group_key, distinct_value)` to an occurrence count:

- **Insert row with value `v` in group `g`**: increment `freq[g][v]`. If the count goes from 0 to 1, the distinct value has appeared. Update the aggregate (e.g. increment COUNT, add `v` to SUM).
- **Delete row with value `v` in group `g`**: decrement `freq[g][v]`. If the count goes from 1 to 0, the distinct value has disappeared. Update the aggregate (e.g. decrement COUNT, subtract `v` from SUM). Remove the entry entirely when the count hits 0 to reclaim memory.
- **Update**: treat as delete-old + insert-new.

Complexity per group: O(1) amortized per event (hash map lookup). Memory: O(D_g) per group where D_g = number of distinct values in that group.

**Multiple DISTINCT aggregates on the same column** (e.g. `COUNT(DISTINCT a), SUM(DISTINCT a) GROUP BY g`): share one frequency map keyed on `(g, a)`, with one occurrence counter per aggregate call. This is what RisingWave does: the dedup state table has schema `(group_key..., distinct_value, count_for_agg_0, count_for_agg_1, ...)`.

**Multiple DISTINCT columns in one query** (e.g. `COUNT(DISTINCT a), SUM(DISTINCT b) GROUP BY g`): separate frequency maps: one keyed on `(g, a)`, one on `(g, b)`. No sharing possible across different columns.

**Aggregate hardness hierarchy** (for reference when prioritizing `subql` work):

| Tier | Aggregates | State per group | Update cost |
|------|-----------|----------------|-------------|
| Easy | COUNT(\*), SUM, AVG | O(1), two or three counters | O(1) |
| Medium | COUNT(DISTINCT), SUM(DISTINCT) | O(D_g), frequency map | O(1) amortized |
| Hard | MIN, MAX | O(D_g), all values needed, and a delete of the extremum triggers a re-scan or re-query | O(1) amortized, O(D_g) worst case on extremum delete |

**Approximate alternative (HyperLogLog):** HLL++ (precision p=14, ~12 KB per group, ~0.8% standard error) can approximate `COUNT(DISTINCT)` in O(1) per event with fixed memory. However, **HLL does not support retractions (deletes)**. ksqlDB uses this approach but restricts it to append-only streams. Since connetto must handle deletes, HLL is not viable for the general case. It could be offered as an opt-in approximate mode for append-heavy workloads in the future.

**How production systems do it:**

| System | Approach | Source |
|--------|----------|--------|
| RisingWave | Per-group dedup state table (LSM-backed) with LRU cache. Visibility bitmaps filter duplicates before downstream agg operators. | [`src/stream/src/executor/aggregate/distinct.rs`](https://github.com/risingwavelabs/risingwave/blob/main/src/stream/src/executor/aggregate/distinct.rs) |
| Flink | `MapState<Value, Long>` per group in keyed state (RocksDB-backed). Split-distinct optimization buckets the distinct key into N sub-groups for skew mitigation. | [FLINK-12161 / PR #8148](https://github.com/apache/flink/pull/8148) |
| Materialize | Differential dataflow `distinct()` operator (weight clamping via `Threshold` trait) applied before the reduce. Per-distinct-column dataflow subgraph. | [`src/compute/src/render/reduce.rs`](https://github.com/MaterializeInc/materialize/blob/main/src/compute/src/render/reduce.rs) |
| Feldera (DBSP) | Z-set weight clamping: `distinct(w) = if w > 0 { 1 } else { 0 }`. Requires tracking current weight of every value. | [DBSP paper, VLDB'23](https://www.vldb.org/pvldb/vol16/p1601-budiu.pdf) |
| pg_ivm | **Not supported.** DISTINCT aggregates are excluded from supported view definitions. | [pg_ivm README](https://github.com/sraoss/pg_ivm) |
| ksqlDB | `COUNT_DISTINCT` via HLL only (approximate, append-only streams, no retractions). | [ksqlDB aggregate docs](https://github.com/confluentinc/ksql/blob/master/docs/developer-guide/ksqldb-reference/aggregate-functions.md) |

**Recommended `subql` implementation path:**

1. Add a `FrequencyMap<V>` structure (likely `HashMap<V, u64>`) to the accumulator state.
2. For each aggregate call with DISTINCT, maintain one frequency map per group. Aggregate calls on the same distinct column share one map (with per-call counters, following RisingWave's model).
3. On CDC event: update the frequency map first, then conditionally update the aggregate value based on whether the distinct value appeared (0 to 1) or disappeared (1 to 0).
4. Memory is bounded by total distinct values across all groups, the same order as the base table cardinality in the worst case.

References:
- Budiu et al., "DBSP: Automatic Incremental View Maintenance for Rich Query Languages", VLDB'23 (Best Paper): https://www.vldb.org/pvldb/vol16/p1601-budiu.pdf
- Gupta et al., "Maintaining Views Incrementally", SIGMOD'93: https://dl.acm.org/doi/10.1145/170036.170066
- "Recent Increments in Incremental View Maintenance" (survey, 2024): https://arxiv.org/html/2404.17679v1

**Q5.2** ~~**HAVING clauses**: should `HAVING` filters be supported in the aggregate spec? They apply after grouping and are harder to evaluate incrementally.~~

**Decision: HAVING is evaluated server-side by `subql`. The client never sees groups that fail the predicate.**

HAVING predicates are post-aggregation filters. The client does not have the information to evaluate them locally. `subql` evaluates HAVING after updating group accumulators and suppresses groups that don't satisfy the condition.

This follows the same two-tier pattern as WHERE evaluation (Q3.4) and aggregate maintenance (Q5.1):

- **Fast path (in-process):** HAVING predicates that `subql` can evaluate against its in-memory accumulator state are handled directly, with no DB round-trip. For example, `HAVING COUNT(*) > 10` only requires the count accumulator the solver already maintains.
- **Re-execution fallback:** HAVING predicates that reference unsupported constructs (subqueries, functions outside `subql`'s scope) go into a per-session map of queries requiring SQL re-execution. When a CDC event touches the involved tables, `subql` re-runs the full query against PostgreSQL for those subscriptions.

The goal over time is to expand the fast solver's coverage so fewer HAVING shapes require re-execution. This is a `subql` concern. connetto treats aggregate subscriptions uniformly regardless of which evaluation path `subql` uses internally.

**Q5.3** ~~**Multi-table aggregates**: aggregates that JOIN multiple tables are not addressed. Are they in scope?~~

**Decision: yes, supported via the re-execution fallback path.** Multi-table (JOIN) aggregates go into the per-session map of queries requiring SQL re-execution, the same map used for unsupported HAVING shapes (Q5.2) and unsupported WHERE predicates (Q3.4). `subql` tracks which tables a query touches. A CDC event on any of those tables triggers re-execution of the full query against PostgreSQL. In-process IVM for joins would require maintaining join state (the core problem solved by Materialize, RisingWave, and similar systems), far outside `subql`'s scope. If common join patterns emerge that justify in-process handling, `subql` can add them to the fast solver over time.

**Q5.4** ~~**Accumulator persistence**: is the accumulator state kept only in memory (lost on server restart) or persisted? Memory is simpler. Persistence is more efficient for long-running subscriptions.~~

**Decision: not a connetto concern. `subql` owns accumulator lifecycle.** `subql` currently keeps accumulators in memory. On restart they are rebuilt via re-execution against PostgreSQL. Whether `subql` eventually persists accumulator state to avoid re-execution cost on restart is an internal `subql` optimization. connetto does not depend on or manage accumulator storage.

**Q5.5** ~~**Re-execution rate limiting**: what is the right throttle for query re-execution? Per-subscription cooldown? Global quota?~~

**Decision: `subql` classifies and coalesces within a batch. The materializer owns retry, debounce, and concurrency.** `subql`'s `reexec` engine collapses duplicate re-execution within a dispatch batch but holds no retry surface and no cross-batch scheduler. Cross-batch debounce, the global concurrency cap, and retry against PostgreSQL live above the engine, in the Subscription Materializer and its `Connector` (see `10-subscription-materializer.md`). The throttle goals are unchanged: per-subscription trailing-edge debounce, and a global concurrency cap to protect the database under load.

**Q5.6** ~~**GROUP BY delta format**: when many groups change at once (e.g. a batch import), should the server send a full group-map replacement or a delta list? At what size does full replacement become preferable?~~

**Decision: dissolved. The format follows from the evaluation path.** The IVM path inherently produces per-group deltas (the accumulator update targets specific group keys, emitting only changed groups is the natural output). The re-execution fallback inherently produces full results (it re-runs the query). There is no design choice to make, and no threshold-based switching between formats. The client handles both: a delta upserts the affected rows in the local aggregate table. A full result replaces the entire table.

**Q5.7** ~~**Client schema for aggregate results**: what does the local SQLite schema look like for GROUP BY results: a generic key-value table, or a typed table generated from the spec?~~

**Decision: generic `_connetto_aggregates` table with JSON result column.** A single connetto-managed table stores all aggregate subscription results. Schema: `(sub_id TEXT, group_key BLOB, result_json TEXT, PRIMARY KEY (sub_id, group_key))`. The application reads results via a custom Diesel connection that deserializes the JSON into typed Rust structs (`T: serde::DeserializeOwned`). No per-subscription DDL generation. connetto owns this table entirely. Delta updates upsert by `(sub_id, group_key)`. Full re-execution results replace all rows for that `sub_id`.

**Status split.** The delivered scalar family superseded this table for ungrouped aggregates: values ride `AggregateUpdate` pushes into an in-memory `LiveValue` (`None` until the bootstrap, an online restart re-bootstraps through the startup re-declaration, an offline restart shows no value, accepted). The table remains the recorded design for GROUP BY results only, parked until grouped aggregates gain a `subql` `AggSpec` variant and a phase. The wire already carries the dormant `group_key` field on `AggregateUpdate`. The named obstacle for grouped support is memory: one accumulator per distinct group value per subscription, worst case the base-table cardinality, per the DISTINCT memory analysis earlier in this section. The obstacle is now analyzed with verified precedent in `docs/research-grouped-aggregates.md` (a process artifact, never committed), and revisiting it is phase R30 in `plans/master-implementation-plan.md`.

---

## 06 · Reconnect

**Q6.1** ~~**Oplog retention window**: what is the default size (entry count or age)? How does it interact with storage cost on the server?~~

**Decision: 72 hours or 1M entries, whichever is hit first. Both configurable per deployment.** 72 hours covers overnight offline, weekend-backgrounded apps, and most real-world disconnection patterns. 1M entries prevents unbounded growth on high-throughput tables. Pruning is unconditional on the retention window, with no per-client cursor tracking in the pruning logic. Clients whose `last_applied_lsn` falls outside the window get a full re-sync. These defaults are a starting heuristic. Deployments tune based on observed offline durations and write throughput.

**Q6.2** ~~**Forced full re-sync signal**: should the server send an explicit "you must re-sync" message when the client's LSN is outside the window, rather than silently falling back to a snapshot?~~

**Decision: yes, explicit `FullResyncRequired` control message.** When the client's `last_applied_lsn` is outside the oplog retention window, the server sends a `FullResyncRequired { reason }` message before beginning snapshot delivery for the affected subscriptions. The client uses this to: (1) show a "re-syncing..." state in the UI, (2) clear local data for those subscriptions before applying the snapshot as a full replacement (not a merge/upsert), and (3) provide debuggability, as the reason is visible in logs.

**Q6.3** ~~**Catchup delivery format**: deliver oplog catchup as a stream of `LivePatch` messages (reuses existing infrastructure) or as a special `CatchupPatch` snapshot-style message (may be more efficient)?~~

**Decision: dissolved. Already decided as PatchSet.** The delivery format decision in `06-reconnect.md` established SQLite PatchSet as the universal delivery mechanism for both the live path and the reconnect/catchup path. No separate format distinction needed.

**Q6.4** ~~**Subscription-level LSN tracking**: should each subscription track its own resume LSN, or is a single global LSN per client sufficient? Per-subscription LSNs enable partial catchup. A global LSN is simpler.~~

**Decision: per-subscription cursors, tracked server-side by `subql`, keyed by session.** On reconnect the client sends only its session token. `subql` maintains per-subscription resume cursors server-side, linked to the session. For each subscription, `subql` checks the cursor against the oplog retention window and either delivers a catchup PatchSet or signals `FullResyncRequired` (Q6.2). The client does not manage or persist cursor state. This is entirely a `subql` concern. Per-subscription granularity means a newly added subscription has no catchup debt, and one subscription falling outside the oplog window does not force a full re-sync of all others. This pattern is consistent with production sync systems (PowerSync per-bucket cursors, ElectricSQL per-shape offsets, Firestore per-target resume tokens).

**Q6.5** ~~**Oplog storage backend**: should the oplog live in PostgreSQL (durable, potentially slow under high write volume), a separate fast store (Redis, in-memory ring buffer), or both?~~

**Decision: per-session pending PatchSet buffer in `subql`, scoped to session cookie lifetime.** On disconnect, `subql` continues accumulating changes for the session's subscriptions into a pending PatchSet server-side. On reconnect (session token still valid), the client receives that PatchSet for instant catchup, with no oplog scan. If the session cookie expires before reconnect, the entire session state (subscriptions, cursors, pending PatchSet) is garbage collected. The client must re-authenticate and re-subscribe from scratch (full snapshot). The mesh-visible PostgreSQL oplog table still exists for CDC propagation across nodes, but the reconnect story is session-scoped. The session cookie lifetime is the primary expiry mechanism, not a separate oplog retention window.

**Q6.6** ~~**Concurrent re-sync and live updates**: during a full re-sync snapshot delivery, live CDC events continue arriving. How does the server buffer or order these relative to the snapshot?~~

**Decision: dissolved. Handled by the session-scoped pending PatchSet buffer.** CDC events arriving during snapshot delivery are appended to the new session's pending PatchSet buffer (Q6.5) and delivered after the snapshot completes. The client confirms receipt via a server-issued opaque cursor included in each delivery. On reconnect, the client sends `(session_token, last_applied_cursor)`. `subql` validates the cursor against its own state and builds the catchup PatchSet from the gap. The cursor is opaque to the client. `subql` issues it and `subql` interprets it. A client reporting a wrong cursor can only hurt its own view. The server's canonical state is never compromised. This follows the Firestore model (opaque server-issued `resume_token`). Checksum-based self-healing (PowerSync model) can be layered on later if needed.

---

## 07 · File Sync

**Q7.1 to Q7.8** ~~All file sync questions.~~

**Decision: file sync is permanently outside connetto's scope.** It belongs to a separate stack (Q1.2). The listed design questions (transport channel, chunking, hashing, conflict resolution, GC, size limits, encryption, CDN integration) are for that stack to answer. See https://github.com/LucaCappelletti94/file-system-review for notes and research.

---

## 08 · Authorization

**Q8.1** ~~**Policy evaluation approach**: direct SQL execution vs. in-process policy compilation vs. hybrid? What is the approach?~~

**Decision: OpenFGA via Rust SDK.** RLS policies are the source of truth in PostgreSQL. [`rls2fga`](https://github.com/LucaCappelletti94/rls2fga) translates them into OpenFGA authorization models. At runtime, visibility checks query OpenFGA via its Rust SDK, not direct SQL evaluation or in-process RLS compilation. This decouples authorization evaluation from the database and makes it available to both connetto and `subql` without SQL round-trips to PostgreSQL.

This governs point-shaped questions on the change and write paths. A snapshot is a set-shaped question and Postgres RLS answers it, permanently and by design: `listObjectsMaxResults` defaults to 1000 and `listObjectsDeadline` defaults to 3 seconds, so an enumeration that exceeds either limit is truncated, and a truncated snapshot would be silent data loss rather than an error. Two executors for one policy is safe only because `rls2fga` compiles both from one source, which makes that compilation load-bearing and something that must be tested as such. `rls2fga` classifies policies by confidence and does not translate attribute conditions at all, so `rls2fga` closes those gaps upstream and exposes a seam for what it cannot classify, and connetto refuses to start when a policy has neither a translation nor a supplied mapping: a narrower compiled model means a row the policy allows would be denied on the change path while still appearing in a snapshot.

**Q8.2** ~~**Policy change handling**: if an RLS policy is altered, which response is acceptable: re-snapshot all affected subscriptions, targeted per-row re-check, or defer visibility correction until reconnect?~~

**Decision: two tiers (session invalidation on model change, OpenFGA cache TTL for tuple changes).**

- **Authorization model change** (RLS policy DDL altered, so `rls2fga` re-translates and the OpenFGA model updates): this is a schema-level event. All active sessions are invalidated. Clients must re-authenticate and re-subscribe from scratch (full snapshot). This is the PowerSync approach, conservative but correct. Model changes are rare (deploy-time events).
- **Grant (record) change** (a permission Postgres row is inserted, updated, or deleted): `rls2fga` names which tables carry authorization meaning, because reading the policies is all it does. The changed row names its grantee, and that grantee's affected subscriptions receive a `FullResyncRequired` whose fresh snapshot recomputes what they may see under the current model. Nothing polls the authorization service, and the service is never a notice source, because every permission is backed by a Postgres row: a permission existing only in the service would make it a second source of truth. A synthesized row deletion is not the mechanism, because working out which rows became invisible is the capped enumeration direction and a truncated withdrawal would look complete. Residual case: a nested group model where the changed row joins one group to another names no person, and the affected callers are one join away in Postgres.
- **Relationship tuple change** (latency from grant change to enforcement): all three OpenFGA caches (`checkQueryCache`, `checkIteratorCache`, `cacheController`) default to disabled, each with a 10-second TTL when enabled. Cache invalidation from recent record writes is triggered by incoming questions rather than by a background poller, so an idle store does not invalidate itself. An authorization change takes effect immediately for writes, which use the strict consistency preference because they are low volume and a write accepted against a just-revoked capability must never slip through. For reads, the change takes effect within the cache TTL, because the fast preference is what makes the change-path fan-out affordable. When the change triggers a teardown, it takes effect immediately for both. The consistency preference is per request and not per item inside a batch, so a strict question cannot travel in the same batch as cached ones.

No production sync system enforces policy changes instantly for connected clients. The bounded propagation delay (OpenFGA cache TTL for tuples, session invalidation for model changes) is consistent with the state of the art (Firebase: up to 10 min, Supabase: JWT TTL, PowerSync: full re-sync).

**Q8.3** ~~**Auth context lifetime**: can the auth context be refreshed mid-session (e.g. a role is added without disconnect)? Is this required?~~

**Decision: dissolved. Auth context is always live via OpenFGA.** The session token identifies the user. Actual permissions are resolved per-check from OpenFGA, not cached at session start. Role/permission changes originating as PostgreSQL rows are replicated into OpenFGA tuples via CDC (a WAL event becomes a tuple write). Subsequent visibility checks pick up the change automatically, bounded by OpenFGA's cache TTL (Q8.2). No mid-session refresh mechanism needed.

The mechanism by which permission changes as Postgres rows reach the authorization service is now load-bearing for revocation: see the grant change entry under Q8.2 for how that propagates and what the response is. Open dependency: `rls2fga` today generates whole-table queries that load every permission record from scratch and nothing that produces the change for one row, so keeping the service current row by row is unbuilt and blocks the phase that makes it the change-path executor.

**Q8.4** ~~**File token revocation**: if a file access token is issued and the session is subsequently revoked, can the token still be used until it expires? Is that window acceptable?~~

**Decision: dissolved. File sync is out of scope (Q7.1 to Q7.8).**

**Q8.5** ~~**Tenant isolation**: in a multi-tenant deployment, is there a top-level isolation layer above RLS, or is tenant isolation fully expressed in RLS policies?~~

**Decision: tenant isolation is expressed in the RLS to OpenFGA authorization model.** `rls2fga` translates tenant-scoping RLS policies into FGA tuples/relations (user belongs to tenant, resource belongs to tenant). No separate isolation mechanism above the auth layer. Tenant boundaries are just another dimension of the authorization model. connetto does not need tenant-aware logic. It delegates to OpenFGA like any other visibility check.

**Decided (R8).** `AuthContext.tenant_id`, `.roles`, and `.claims` are deleted. They were written and never read (traced end to end in `12-identity-session-capability.md`). Roles belong in the model too: `rls2fga` emits a `pg_role` type with a `member` relation and requires the deployment to load records mapping users to Postgres roles.

**Q8.6** ~~**Audit log destination**: is the `auth_log` table in PostgreSQL the right destination, or should audit events go to a separate log aggregator?~~

**Decision: structured logging for the firehose, PostgreSQL table for critical events.** High-volume operational events (auth check denials, connection events, CDC visibility checks) go to structured logging (stdout to an external aggregator). Critical state changes (permission changes, session invalidations, model changes) are persisted to a PostgreSQL `auth_events` table for application-level querying. OpenFGA's own audit log covers tuple/model changes on the authorization side.

**Decided, not built.** Structured logging has no implementation today: no `tracing` or `log` dependency anywhere in the workspace. Phase R12 in `plans/master-implementation-plan.md` builds it, and R3 requires it because a refused grant is otherwise visible nowhere. The `auth_events` table is also unbuilt, with its own phase after R3.

Note on log aggregators: the application writes structured logs to stdout. The aggregator is a deployment choice. Common options:
- **ELK** (Elasticsearch + Logstash + Kibana): full-text indexes all log content. Mature, powerful queries, but resource-heavy (Java-based).
- **Loki** (Grafana): indexes only labels/metadata, not full content, which is cheaper to run. Pairs with Grafana for visualization. "Prometheus but for logs."

The choice is an ops decision, not an architecture one. connetto just emits structured logs to stdout.

**Q8.7** ~~**`REPLICA IDENTITY` requirement**: what setting does the change path require, and who enforces it?~~

**Decision: `FULL` is a deployment requirement, checked at startup, refusing to start when a replicated table lacks it. Decided (R6).** The change path needs the previous version of each changed row to distinguish a row that became invisible from one that was never visible. `REPLICA IDENTITY DEFAULT` records only primary key columns and records nothing when a table has no primary key. `FULL` records the previous values of all columns. Every existing test fixture already sets `REPLICA IDENTITY FULL` and nothing checks it, so the change is making an accident into a requirement.

**Q8.8** ~~**Where does the visibility check live**: in connetto, in `subql`, or in the authorization service?~~

**Decision: the trait is defined in `subql`, which ships a ready-made implementation backed by the authorization service. Downstream users may implement the trait themselves.** `subql` holds the replication connection and already computes previous-versus-current transitions per subscriber, making it the right home for the check. connetto's `AuthPolicy` is superseded by it. The architecture diagram currently shows the integration living in `connetto-server`, which is stale.

**Sequenced as two phases, R5a then R5b.** Relocating the seam needs nothing and changes no behaviour, because the implementation behind the trait initially still uses Postgres RLS. Swapping in the authorization service needs a per-row mapping `rls2fga` does not have. Separating them lets the unblocked half land first, puts the measurement's instrumentation on a seam that then never relocates, and reduces the swap to substituting an implementation rather than restructuring a call path. Note that the swap is a correctness prerequisite rather than a performance option: RLS answers only about the row as it is now, and the two-version check under Q8.7 needs an answer about the row as it was, so no measurement can veto it.

---

## 09 · WASM / Browser

**Q9.1** ~~**SharedWorker vs. Worker**: is `SharedWorker` a requirement or a later optimization? It complicates implementation significantly.~~

**Decision: dissolved by Q1.3.** SharedWorker only, no fallback.

**CORRECTED, 2026-07-30. connetto never used a `SharedWorker` and cannot.** `createSyncAccessHandle` is `[Exposed=DedicatedWorker]` in the WHATWG File System IDL, so it does not exist in a `SharedWorkerGlobalScope` in any conforming browser, and Chrome does not even expose the `Worker` constructor there, so delegating the file work to a nested dedicated worker is impossible too (both verified, the second by probing Chrome 150 directly). The shipped topology is a **dedicated** worker spawned by whichever tab wins a Web Locks election (via `spawn_db_worker` in `crates/connetto-web/src/workers.rs`), with `BroadcastChannel` as the cross-context port replacement, and `crates/connetto-web/src/broadcast.rs` records why. Nothing in the repository constructs a `SharedWorker`. So this decision was never implementable and the requirement it imposed is void. The real requirement set is a dedicated `Worker`, `BroadcastChannel`, `navigator.locks`, and OPFS with sync access handles, which is what the table under Q9.2 now gates on.

**Q9.2** ~~**OPFS availability**: what is the fallback story for environments without OPFS (older browsers, some mobile WebViews): IndexedDB adapter, in-memory only, or unsupported?~~

**Decision: OPFS required, no fallback.** Browsers without OPFS are unsupported. No IndexedDB adapter or in-memory fallback.

The minimum supported version is the strictest of the APIs connetto actually uses: a dedicated `Worker`, `BroadcastChannel`, `navigator.locks`, OPFS, and `createSyncAccessHandle`. Versions from `mdn/browser-compat-data`. An asterisk means the data asserts no divergence from the desktop engine rather than stating a version.

| Browser | Worker | BroadcastChannel | navigator.locks | OPFS root | createSyncAccessHandle | Minimum | Binding constraint |
|---|---|---|---|---|---|---|---|
| Chrome desktop | 2 | 54 | 69 | 86 | 102 | **102** | sync access handles |
| Chrome Android | 2* | 54* | 69* | 109 | 109 | **109** | OPFS on Android |
| Edge | 12 | same as Chrome | same as Chrome | same as Chrome | same as Chrome | **102** | sync access handles |
| Firefox desktop | 3.5 | 38 | 96 | 111 | 111 | **111** | OPFS |
| Firefox Android | 3.5* | 38* | 96* | 111* | 111* | **111** | OPFS |
| Safari desktop | 4 | 15.4 | 15.4 | 15.2 | 15.2 | **15.4** | `BroadcastChannel` and Web Locks |
| Safari iOS | 5 | 15.4* | 15.4* | 15.2* | 15.2* | **15.4** | `BroadcastChannel` and Web Locks |
| WebView Android | 2* | 54* | 69* | 86* | 102* | **102** | sync access handles |

**This corrects the previous table in both directions, and one of the errors was unsafe.**

The old table gave Chrome and Edge a minimum of 86, taken from the OPFS root rather than from `createSyncAccessHandle`, which is 102. A Chrome between 86 and 101 therefore satisfied the documented requirement and would fail at runtime, because the sahpool VFS needs the sync handle. The real floor is 102.

Safari drops from 16.0 to 15.4, because 16.0 came from `SharedWorker` and nothing needs it.

**Chrome Android and WebView Android are technically supported**, not unsupported. Their exclusion rested entirely on `SharedWorker`. Verified by measurement rather than by data: on a headless Android 15 emulator, Android WebView 124.0.6367.219 has a dedicated `Worker`, `BroadcastChannel`, `navigator.locks` (a lock was acquired), an OPFS root, and `createSyncAccessHandle` inside a dedicated worker, which wrote 8 bytes to a real file. It genuinely lacks `SharedWorker`, which connetto cannot use anyway. Chrome for Android runs the same engine build and the compatibility data states 109 explicitly rather than mirroring it.

A note for anyone repeating that measurement: `navigator.storage` and `navigator.locks` are both `[SecureContext]`, so serving the probe to an emulator over `http://10.0.2.2:<port>` makes three of the five appear absent. Use `adb reverse` and load it over `http://localhost:<port>`, which is a trustworthy origin. The first run of this probe was wrong for exactly that reason.

**Android on the web is supported. Decided, superseding the deferral this line used to record.** Q1.3 gave two reasons for excluding it. The technical one is void, and the product one has been withdrawn by the maintainer: Android is served both in the browser and by a native app, not by the app alone. Nothing here excludes Android.

Unsupported entirely: any browser below its minimum above.

**Q9.3** ~~**WASM bundle size**: what is an acceptable size limit? Are there heavy dependencies that must be avoided?~~

**Decision: out of scope.** connetto makes no claim about artifact size and sets no budget. A library cannot set a size budget for its consumers, because only the embedding application knows what its own bundle can afford, so the measurement and any ceiling belong there. The heavy component is SQLite, roughly 300 to 400 KB gzipped, and the rest (`rmp-serde`, `serde_json`, Zstd) is light, which is recorded here as a fact for whoever does budget their own bundle rather than as a target of connetto's.

Adding a budget later would be a new decision, not a resumption of this one.

**Q9.4** ~~**Main thread read access**: should the main thread be able to query local SQLite directly (via synchronous OPFS in a Worker), or should all reads go through the worker message-passing API?~~

**Decision: all reads through the worker that owns the database, via a custom `diesel_async` connection.** The main thread uses a custom Diesel async connection that wraps message-passing to that worker. From the application's perspective it is standard `diesel_async` queries and the transport is an implementation detail. No direct OPFS access from the main thread, no secondary read Worker. (The decision originally said `SharedWorker`. The shipped worker is dedicated, per the correction under Q9.1. The substance is unchanged.)

**Q9.5** ~~**ServiceWorker**: is background sync (receiving updates with no tab open) a requirement? If so, `ServiceWorker` is needed.~~

**Decision: no ServiceWorker.** Background sync with no tab or app open is an OS-level limitation, not something connetto can solve. Native apps reconnect on resume. The worker stays alive as long as the tab that spawned it is open, and leadership moves to another tab otherwise. When the last tab closes or the app is suspended, the WebSocket drops. On reopen, the client reconnects and receives the pending PatchSet (Q6.5). Push notifications for "new data available" are a separate concern outside connetto's scope.

**Q9.6** ~~**TypeScript bindings**: should the WASM client expose TypeScript bindings (via `wasm-bindgen` + `tsify`)? Is this in scope?~~

**Decision: TypeScript bindings are not in scope.** The immediate consumer is a Dioxus app (Rust on both sides), so no TypeScript caller exists. Adding bindings would be a new decision taken if connetto-rs ever targets non-Rust web apps, not a resumption of this one.

**Q9.7** ~~**Testing WASM**: how are WASM-specific behaviors tested: `wasm-pack test` with headless Chrome, a mocked browser environment, or another approach?~~

**Decision: `wasm-pack test --headless --chrome`.** Real headless browser testing: compiles to WASM and runs against the actual browser APIs connetto uses (a dedicated `Worker`, `BroadcastChannel`, `navigator.locks`, OPFS). No mocked browser environment.

---

## 10 · Local-only tables

Full contract with verified-facts appendix: `docs/upstream-synql-tier-generation-contract.md`.

**Q10.1** ~~How does an author declare a table as local-only (device-private, never synced)?~~

**Decision: by document membership, two Postgres-dialect source files.** One file per tier (`schema.sql` shared, `frontend.sql` local in the demo), bare table names, no schema prefix. The only knob is the path of the second file. Postgres dialect is kept for both documents, including the one that never touches a real Postgres, because its type system (`uuid`, `timestamptz`, `jsonb`) carries what synql needs to generate faithful Rust types.

**Q10.2** ~~Where does a local-only table live in the replica?~~

**Decision: a second attached SQLite file, capture session on `main` only.** The pinned diesel-sqlite-session hardcodes the session to `main`, so writes to attached tables are physically incapable of being captured, uploaded, rejected, or rolled back, which fixes the destroy-on-reject bug by placement alone. The second file ships as a second baked template (one pg2sqlite invocation per document in `build.rs`), attached via the diesel attach API with `set_attach_create_enabled(false)`. The attach name is an internal constant, never in authored SQL. No sync state lives in the frontend file, so cross-file WAL non-atomicity never spans an invariant.

**Q10.3** ~~Can foreign keys or table names cross the tier boundary?~~

**Decision: no, both are generation-time hard errors, defined as cross-document resolution failures.** The two documents are separate reference universes, so a `REFERENCES` crossing the boundary is a dangling reference, not a policy violation. Frontend-to-shared is enforced by sql-traits `validate_foreign_key_targets` called by pg2sqlite (landed in sql-traits), shared-to-frontend by the real Postgres natively. Semantically correct, not just physically forced: the synced replica is a moving window, so an enforced FK from private data into it would block eviction or cascade-destroy private data. Duplicate table names across documents are also a hard error (SQLite bare-name resolution would silently shadow the frontend table), and that check spans both documents so it belongs to synql.

**Q10.4** ~~How does generation express tiers (the roadmap's cfg-features sketch)?~~

**Decision: no cfg features, documents map to modules.** The cfg sketch is dead twice over: one compiled wasm binary hosts multiple tiers, and Cargo feature unification makes any gate additive across the build graph. It is also unnecessary: the server's generated schema comes from the shared document alone (existence-by-absence holds trivially), and no client code region needs table-hiding since both tiers are legitimately readable, joins included. synql emits one client crate with a module per document (`schema::shared`, `schema::local`) plus `allow_tables_to_appear_in_same_query` across the boundary, and two baked templates.

**Q10.5** ~~How is writability enforced across the two "cannot write" cases?~~

**Decision: two distinct mechanisms, deliberately not unified.** Local-only tables are enforced by placement (the write is welcome, there is nothing to deny). Read-only synced tables are enforced by pg2sqlite role translation: the RLS branch denies via a view without `INSTEAD OF` triggers, the non-RLS branch gets `RAISE(ABORT)` deny triggers (landed in pg2sqlite) under the contract that authoritative applies run with triggers disabled. The server catalog's `NotWritable` stays as the version-skew backstop only, never primary enforcement.

**Q10.6** ~~How do live queries work over local and mixed-tier tables?~~

**Decision: runtime tier dispatch, four cases.** The replica itself knows which file every table lives in, so dispatch is a lookup, no generated constants. Local rows: skip the server `Subscribe`, the existing local refresh path serves the handle. Local aggregates: transparent at the API, served by local re-execution on change (correct because a local table is complete by definition), recorded as re-executed, not incrementally maintained. Mixed rows: auto-subscribe the whole synced table per synced table in the query, tied to the handle lifetime (requirement: the synced side stays live and covering, whole-table subscribe is the disposable v1 mechanism, predicate pushdown a later refinement). Mixed aggregates: hard error at registration, rationale on record as a cost cliff, not impossibility.

**Q10.7** ~~Do retention, eviction, and resume collide with the local tier?~~

**Decision: no, structurally.** No `SubscriptionSpec` can ever carry a frontend table, so eviction has no path to a frontend row. The FK closure rule removes cascade paths. The resume cursor lives in `main._connetto_meta` in the same transaction as patch application, and the frontend file carries zero sync state.

---
## 11 · Authentication

See `11-authentication.md`. The architecture is decided (Backend-For-Frontend, connetto is the OAuth client, it mints its own signed access token plus a stored rotating refresh token, identity resolved once at login by a per-provider registry and held with the sessions and retained provider tokens in one of two auth stores). The questions below are now resolved.

**Q11.1**: ~~Default token lifetimes. What are the shipped defaults for the access-token lifetime and the refresh-token sliding window and absolute ceiling?~~

**Decision: lifetimes are server-side application configuration with a conservative, overridable default posture, and the architecture doc prescribes only the shape, not the numbers.** The shape is a short access token plus a refresh sliding window under an absolute ceiling. Exact defaults are an implementation-time choice, biased conservative, because connetto is a general-purpose tool and offline profiles differ per deployment. The access token is verified once at handshake, so a healthy long-lived connection is not force-expired, and the access-token lifetime is a re-auth cadence rather than the revocation bound (see Q11.4).

**Q11.2**: ~~Provider token retention. In scope, or explicitly out?~~

**Decision: retained, not discarded.** The chosen auth store (in-memory or database) holds the user's provider tokens alongside the identity mapping, so an application that configured the right scopes on the provider reuses them to call the provider's own APIs. connetto exposes a lazy refreshing accessor that refreshes a token inline when it is about to be used and persists the rotated refresh token, and it runs no background refresh job, which is fewer provider requests and no mesh-wide scheduler.

**Q11.3**: ~~Client-side ID token verification. Is the client-as-OAuth-client alternative supported at all, or is BFF the only sanctioned model?~~

**Decision: BFF is the only sanctioned model.** connetto always has a backend so BFF always applies, and the entire session and offline half of the design assumes connetto owns the session, so supporting a second model would mean maintaining a second session lifecycle for a strictly weaker option. Client-side ID-token verification therefore does not arise. The fork-3 verification remains as evidence the alternative is buildable, not as a supported path.

**Q11.4**: ~~Mesh revocation propagation. What is the acceptable propagation latency, and is the access-token lifetime a tight enough bound on its own?~~

**Decision: revocation is authoritative because the handshake checks session liveness, and its reach follows the store variant.** A revoked session is refused even with a time-valid access token, and a live connection is dropped when its node sees the invalidation. In the in-memory or single-server case this is an instant local operation, and in the database mesh case it propagates at replication lag on the same replication that carries the oplog. The access-token lifetime is a re-auth cadence, not the revocation bound, and connetto adds no separate revocation channel.

---

## Cross-cutting / From the Overview

These were called out in the original plan as the most consequential open decisions:

| # | Question | Primary doc |
|---|---|---|
| X1 | Aggregate query IVM scope: which shapes get incremental support, which fall back to re-execution? | Q5.1 |
| X2 | File tree conflict resolution: last-writer-wins vs. CRDT-based tree | Q7.4 |
| X3 | External crate dependency strategy: how to reference the author's other crates during development | Q0.2, Q1.1 |
| X4 | Protocol serialization format: MessagePack / Protobuf / FlatBuffers / CBOR / JSON | Q2.1 |
| X5 | Oplog retention policy: size, age, and what triggers a forced full re-sync | Q6.1, Q6.2 |
| X6 | Clock discipline, OPEN, to be discussed: grace countdowns, the session staleness bound, and cache TTLs all assume a sane running clock, and nothing states monotonic versus wall time or what suspend and resume does (a device waking after a week fires every grace expiry at once, while reconnect races catch-up, under the offline eviction pause) | `15-replica-retention.md` (grace), `11-authentication.md` (staleness bound) |
| X7 | The PostgreSQL mesh, OPEN, needs a design: `11-authentication.md` asserts a multi-server deployment where stores and the oplog replicate, but cursors are positions in one server's change log, and client failover between nodes, cursor validity across them, and per-node replication-slot topology are unexamined. Either design it or scope it out as explicitly as file sync was | `11-authentication.md` (mesh), `06-reconnect.md` (cursors) |
