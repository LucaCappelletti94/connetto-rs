# Open Questions — Master Index

All numbered open questions across the architecture docs, in one place.
Each entry links back to its source file where context lives.

---

## 00 · Overview

**Q0.1** ~~— What is the initial target transport — WebSocket only, or also HTTP long-poll / SSE for environments where WebSocket is restricted?~~

**Decision: WebSocket only.** HTTP fallback was motivated by legacy transparent proxies and serverless runtimes. Transparent proxies are a non-issue with `wss://`. Serverless runtimes are incompatible with the architecture entirely — they are stateless and short-lived, with no place to hold subscription state, run a CDC listener, or maintain a session registry. HTTP fallback is dead weight.

**Q0.2** ~~— Should the client and server crates live in this repository or in separate crates published independently?~~

**Decision: single Cargo workspace in this repo, multiple crates.** connetto-rs is a reusable transport layer library. All crates live in one workspace (core types, server, client, WASM adapters) and are published independently to crates.io so downstream projects can depend on only the pieces they need.

**Q0.3** ~~— Is the initial target native clients, WASM/browser, or both simultaneously?~~

**Decision: both simultaneously.** The immediate consumer is a Dioxus application, which compiles to both native and WASM from the same codebase. The trait boundaries between the sync engine and I/O adapters (transport, storage, file store) must be correct from day one — no retrofitting WASM later.

---

## 01 · Pieces Inventory

**Q1.1** ~~— Should the core traits (`Transport`, `Store`, etc.) live in a dedicated `connetto-core` crate, or inline in this repo?~~

**Decision: single `connetto-core` crate.** Shared types and traits (wire format, `Transport`, `Store`, `FileStore`, `AuthPolicy`, etc.) live in `connetto-core`. Both `connetto-server` and `connetto-client` depend on it; neither depends on the other.

**Q1.2** ~~— Which pieces are in-scope for a first prototype versus later iterations?~~

**Decision: all pieces (A–L) are in scope for v1, except file sync (J).** The core transport, subscriptions, mutation path, CDC push, reconnect, schema distribution, authorization, aggregate queries, and WASM adapters all need to work together — none can be deferred without breaking the whole. File sync (J) is handled by a separate stack; the integration point with connetto is a future design concern.

**Q1.3** ~~— Is `SharedWorker` a requirement for multi-tab browser support, or is tab-per-worker acceptable initially?~~

**Decision: `SharedWorker` only, no fallback.** Chrome for Android and WebView Android have never supported `SharedWorker`, but Android users are expected to install the native app rather than use the web version. The web target is desktop browsers and iOS Safari, both of which support `SharedWorker` (Chrome since 2010, Firefox since 2014, Safari since 16.0 / 2022). A `Worker` fallback adds implementation complexity for an audience that should not be using the web target in the first place.

---

## 02 · Protocol

**Q2.1** ~~— **Serialization format**: which format? Candidates are MessagePack, Protobuf/FlatBuffers, JSON, and CBOR. Decision needed before any message types are implemented.~~

**Decision: MessagePack (`rmp-serde`) for control plane; JSON only for aggregate results.**
- PatchSets (INSERT/UPDATE/DELETE) — own binary wire format, handled separately.
- Control plane (Handshake, Subscribe, Unsubscribe, Ack, errors, etc.) — typed Rust structs serialized with MessagePack via `rmp-serde`. Known shape at compile time; no dynamic data.
- Aggregate results — JSON via `serde_json`, deserialized client-side into `T: serde::DeserializeOwned`. JSON is used here and only here because the result shape is genuinely unknown at compile time.

Principle: JSON is reserved exclusively for data whose shape is not known at compile time. Everything with a defined structure uses MessagePack.

**Q2.2** ~~— **Mutation window**: single in-flight mutation vs. sliding window of N — what is N, and how does it interact with client-seq ordering?~~

**Decision: dissolved.** The client sends PatchSets (SQLite binary change format), not individual mutations. The server unpacks the PatchSet into individual operations, translates them into PostgreSQL SQL, and applies them within a single transaction using `SAVEPOINT` per operation. Failed ops roll back to their savepoint; successful ops commit. The server returns per-op results with failure reasons. Dependency handling (FK cascades) is handled by PostgreSQL's constraint system. The client rolls back only failed optimistic local writes and updates a `_connetto_pending_ops` tracking table so the UI can show granular sync status (pending/confirmed/failed with error reason). The CDC echo of successfully applied ops serves as the de-facto server acknowledgement — no separate `MutationAck` message is needed on the happy path.

**Q2.3** ~~— **Versioning / evolution**: how are breaking changes to `WireMessage` handled? A version field in `Handshake`? A negotiation step?~~

**Decision: version field in `Handshake`, server rejects incompatible clients with a clear error.** Client sends `protocol_version: u32` in the handshake. Server closes the connection with an explicit `FatalError` if the version does not match. No negotiation — just a clear runtime message so app developers immediately know a version mismatch is the cause.

**Q2.4** ~~— **HTTP fallback**: is HTTP SSE + POST (or long-poll) in scope for v1?~~

**Decision: dissolved by Q0.1.** WebSocket only.

**Q2.5** ~~— **Compression**: per-message or per-frame compression (e.g. `permessage-deflate` for WebSocket)? Worthwhile for large snapshots?~~

**Decision: Zstd at the application layer on PatchSet and snapshot payloads only.** Benchmarks showed Zstd optimal for PatchSet payloads. Compression is applied at the application layer (not via `permessage-deflate`) so it targets only bulk binary data — PatchSets and snapshots. Control plane messages are not compressed. This maps cleanly onto the two WebSocket frame types: binary frames (PatchSets, snapshots) get Zstd; text frames (control plane) do not.

---

## 03 · Sync Pipeline

**Q3.1** ~~— **Mutation window**: should the client pipeline multiple in-flight mutations (window of N) or enforce strict one-at-a-time? Pipelining increases throughput but complicates conflict handling when an early mutation in the window is rejected.~~

**Decision: dissolved by Q2.2.** Client sends PatchSets; the window concept does not apply.

**Q3.2** ~~— **Base version representation**: what exactly is `base_version`? Row-level timestamp? Vector clock? PostgreSQL `xmin`? The choice affects conflict granularity and server-side comparison cost.~~

**Decision: `updated_at TIMESTAMPTZ` as the conflict token.** The application schema already has `updated_at` on all entities. Conflict detection uses `WHERE id = ? AND updated_at = ?` — zero affected rows means conflict. `xmin` is not suitable (wraps, internal). Vector clocks and HLC are overkill for a single-authority PostgreSQL backend. Clock skew across mesh nodes is an acknowledged open problem — not solved universally in the industry (BDR/PGD takes the same tradeoff). Mitigation: require tight clock sync (NTP/PTP) as an operational prerequisite on the mesh.

**Q3.3** ~~— **CDC source**: logical replication vs. trigger-based `NOTIFY` — tradeoffs in latency, setup complexity, and required PostgreSQL permissions.~~

**Decision: logical replication.** The entire stack is already built on logical replication. No trigger-based `NOTIFY` path is needed.

**Q3.4** ~~— **Predicate evaluation on CDC events**: for complex subscription filters, should matching be done fully in-process, or should the server issue a SQL query per CDC event? In-process is faster; SQL is more accurate for complex predicates.~~

**Decision: in-process via `subql`; SQL re-execution fallback for unsupported cases.** The `subql` crate handles in-process predicate evaluation with bitmap-indexed candidate pruning, bytecode VM evaluation, WAL parsing, and predicate deduplication. For predicates outside `subql`'s scope (JOINs, subqueries, functions, MIN/MAX), the server re-runs the registered query against PostgreSQL when a change in the involved tables is detected. Note: `subql` currently only evaluates `new_row` for UPDATE events — it needs to be fixed to evaluate both `old_row` and `new_row` and return a transition (enter/exit/update/no-op) so connetto can deliver correct INSERT/DELETE events when rows move in and out of a subscription's result set. This is a `subql` issue, not a connetto concern.

**Q3.5** ~~— **Own-mutation echo suppression**: should the server suppress the CDC echo for the originating client (send only `MutationAck`, no `RowUpdate`), or always send both? Suppression is an optimization but complicates LSN tracking.~~

**Decision: no suppression — the CDC echo IS the ack.** The `RowUpdate` arriving back at the originating client via the CDC fanout path serves as the de-facto acknowledgement. No separate `MutationAck` message exists. The client matches incoming `RowUpdate`s against its `_connetto_pending_ops` table by PK and clears the pending status. Only error cases (`MutationReject`, `MutationConflict`) need dedicated messages.

---

## 04 · Subscriptions

**Q4.1** ~~— **Predicate language scope**: is the current predicate tree (Eq, Ne, Lt, Gt, In, And, Or, Not) sufficient, or do clients need more expressive filters (LIKE, IS NULL, array containment)? More expressiveness makes in-process server evaluation harder.~~

**Decision: SQL WHERE clauses as strings, not a custom predicate tree.** connetto accepts SQL WHERE clause text directly, matching `subql`'s input format. The predicate tree defined in `04-subscriptions.md` is superseded — no custom AST. The supported predicate language is whatever `subql` supports (=, !=, <, >, IN, BETWEEN, LIKE, ILIKE, IS NULL, AND, OR, NOT, arithmetic). Unsupported constructs are rejected at registration time by `subql`.

**Q4.2** ~~— **Subscription count limits**: should the server enforce a maximum number of subscriptions per session? What happens when the limit is reached?~~

**Decision: not a connetto concern.** Subscription registry memory and resource limits are owned by `subql`. Memory management strategies (mmap, eviction, caps) belong there. connetto delegates subscription management to `subql` and does not impose its own limits.

**Q4.3** ~~— **Snapshot parallelism**: should the server deliver snapshots for multiple subscriptions concurrently or serially? Concurrency helps latency but increases server load.~~

**Decision: priority-tiered delivery.** Subscriptions declare a priority (e.g. 0–3, 0 = highest). Higher-priority tiers complete before lower-priority tiers begin. Within a tier, subscriptions can be delivered concurrently (interleaved on the WebSocket, tagged by `sub_id`). This is the PowerSync model — state of the art for user-facing sync. Memory is bounded (one tier at a time), backpressure is natural (serial between tiers), and the UX-critical data renders first. Head-of-line blocking is mitigated because the blocked subscriptions are low-priority by definition. Client-side SQLite is single-writer, so parallel delivery within a tier is bounded by client write throughput.

**Q4.4** ~~— **Catchup patch optimization**: is the "deliver catchup patch instead of full snapshot on reconnect" optimization in scope for v1?~~

**Decision: yes, in scope.** On reconnect, if the client's LSN is within the oplog (server-side operation log) retention window, the server delivers only the changes since that LSN — not a full snapshot. This avoids re-sending data the client already has after brief network interruptions.

**Q4.5** ~~— **Column projection**: if a client subscribes with `columns: Some([...])`, does the server track only those columns for change matching, or always track all columns and project at delivery time?~~

**Decision: deferred.** Column projection is an optimization. The subscription language is SQL WHERE clauses via `subql`, which operates on full rows. Projection can be layered on top at delivery time if bandwidth becomes a concern. Not a priority for the core design.

---

## 05 · Aggregate Queries

**Q5.1** ~~— **IVM scope**: which aggregate shapes get incremental view maintenance vs. re-execution fallback? MIN and MAX with deletions are the hardest — are they in scope for IVM?~~

**Decision: follows `subql` capabilities; MIN/MAX need to be added to `subql`.**

Currently supported incrementally by `subql`: COUNT(*), COUNT(col), SUM(col), AVG(col).
Currently unsupported (re-execution fallback): MIN, MAX.

**MIN/MAX approach**: not self-maintainable — deleting the current extreme requires touching the base table (Gupta et al., VLDB'93). The standard production approach is to re-query the specific affected group only, not a full scan. This is what PostgreSQL `pg_ivm` does. Streaming systems (Flink, RisingWave) maintain ordered state per group to avoid any SQL round-trip, at O(distinct values) memory per group — overkill for connetto. Targeted re-query on delete of extreme is the right approach and needs to be implemented in `subql`.

References:
- Gupta et al., "Maintaining Views Incrementally", VLDB'93: https://www.vldb.org/conf/1993/P157.PDF
- PostgreSQL `pg_ivm` (targeted group re-query for MIN/MAX): https://github.com/sraoss/pg_ivm
- Flink `MinWithRetractAggFunction` (MapView state): https://github.com/apache/flink/blob/master/flink-table/flink-table-runtime/src/main/java/org/apache/flink/table/runtime/functions/aggregate/MinWithRetractAggFunction.java
- RisingWave ordered state + TopNStateCache: https://github.com/risingwavelabs/risingwave/blob/main/docs/dev/src/design/aggregation.md

**Q5.1b** ~~— **DISTINCT aggregates**: how should `COUNT(DISTINCT col)`, `SUM(DISTINCT col)`, etc. be maintained incrementally? This is a `subql` implementation concern — documented here for SOTA reference.~~

**Decision: exact per-group frequency map; needs to be implemented in `subql`.**

DISTINCT aggregates (`COUNT(DISTINCT col)`, `SUM(DISTINCT col)`) are harder than plain aggregates because they require tracking **which values are present** and **how many rows carry each value** — not just a running total.

**Core algorithm — frequency map per group:**

For `AGG(DISTINCT col_d) GROUP BY col_g`, maintain a map `(group_key, distinct_value) → occurrence_count`:

- **Insert row with value `v` in group `g`**: increment `freq[g][v]`. If count goes from 0→1, the distinct value has appeared — update the aggregate (e.g. increment COUNT, add `v` to SUM).
- **Delete row with value `v` in group `g`**: decrement `freq[g][v]`. If count goes from 1→0, the distinct value has disappeared — update the aggregate (e.g. decrement COUNT, subtract `v` from SUM). Remove the entry entirely when count hits 0 to reclaim memory.
- **Update**: treat as delete-old + insert-new.

Complexity per group: O(1) amortized per event (hash map lookup). Memory: O(D_g) per group where D_g = number of distinct values in that group.

**Multiple DISTINCT aggregates on the same column** (e.g. `COUNT(DISTINCT a), SUM(DISTINCT a) GROUP BY g`): share one frequency map keyed on `(g, a)`, with one occurrence counter per aggregate call. This is what RisingWave does — the dedup state table has schema `(group_key..., distinct_value, count_for_agg_0, count_for_agg_1, ...)`.

**Multiple DISTINCT columns in one query** (e.g. `COUNT(DISTINCT a), SUM(DISTINCT b) GROUP BY g`): separate frequency maps — one keyed on `(g, a)`, one on `(g, b)`. No sharing possible across different columns.

**Aggregate hardness hierarchy** (for reference when prioritizing `subql` work):

| Tier | Aggregates | State per group | Update cost |
|------|-----------|----------------|-------------|
| Easy | COUNT(\*), SUM, AVG | O(1) — 2–3 counters | O(1) |
| Medium | COUNT(DISTINCT), SUM(DISTINCT) | O(D_g) — frequency map | O(1) amortized |
| Hard | MIN, MAX | O(D_g) — all values needed; delete of extremum triggers re-scan or re-query | O(1) amortized, O(D_g) worst case on extremum delete |

**Approximate alternative — HyperLogLog:** HLL++ (precision p=14, ~12 KB per group, ~0.8% standard error) can approximate `COUNT(DISTINCT)` in O(1) per event with fixed memory. However, **HLL does not support retractions (deletes)**. ksqlDB uses this approach but restricts it to append-only streams. Since connetto must handle deletes, HLL is not viable for the general case. It could be offered as an opt-in approximate mode for append-heavy workloads in the future.

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
3. On CDC event: update the frequency map first, then conditionally update the aggregate value based on whether the distinct value appeared (0→1) or disappeared (1→0).
4. Memory is bounded by total distinct values across all groups — same order as the base table cardinality in the worst case.

References:
- Budiu et al., "DBSP: Automatic Incremental View Maintenance for Rich Query Languages", VLDB'23 (Best Paper): https://www.vldb.org/pvldb/vol16/p1601-budiu.pdf
- Gupta et al., "Maintaining Views Incrementally", SIGMOD'93: https://dl.acm.org/doi/10.1145/170036.170066
- "Recent Increments in Incremental View Maintenance" (survey, 2024): https://arxiv.org/html/2404.17679v1

**Q5.2** ~~— **HAVING clauses**: should `HAVING` filters be supported in the aggregate spec? They apply after grouping and are harder to evaluate incrementally.~~

**Decision: HAVING is evaluated server-side by `subql`; the client never sees groups that fail the predicate.**

HAVING predicates are post-aggregation filters — the client does not have the information to evaluate them locally. `subql` evaluates HAVING after updating group accumulators and suppresses groups that don't satisfy the condition.

This follows the same two-tier pattern as WHERE evaluation (Q3.4) and aggregate maintenance (Q5.1):

- **Fast path (in-process):** HAVING predicates that `subql` can evaluate against its in-memory accumulator state are handled directly — no DB round-trip. For example, `HAVING COUNT(*) > 10` only requires the count accumulator the solver already maintains.
- **Re-execution fallback:** HAVING predicates that reference unsupported constructs (subqueries, functions outside `subql`'s scope) go into a per-session map of queries requiring SQL re-execution. When a CDC event touches the involved tables, `subql` re-runs the full query against PostgreSQL for those subscriptions.

The goal over time is to expand the fast solver's coverage so fewer HAVING shapes require re-execution. This is a `subql` concern — connetto treats aggregate subscriptions uniformly regardless of which evaluation path `subql` uses internally.

**Q5.3** ~~— **Multi-table aggregates**: aggregates that JOIN multiple tables are not addressed. Are they in scope?~~

**Decision: yes, supported via the re-execution fallback path.** Multi-table (JOIN) aggregates go into the per-session map of queries requiring SQL re-execution — the same map used for unsupported HAVING shapes (Q5.2) and unsupported WHERE predicates (Q3.4). `subql` tracks which tables a query touches; a CDC event on any of those tables triggers re-execution of the full query against PostgreSQL. In-process IVM for joins would require maintaining join state (the core problem solved by Materialize, RisingWave, and similar systems) — far outside `subql`'s scope. If common join patterns emerge that justify in-process handling, `subql` can add them to the fast solver over time.

**Q5.4** ~~— **Accumulator persistence**: is the accumulator state kept only in memory (lost on server restart) or persisted? Memory is simpler; persistence is more efficient for long-running subscriptions.~~

**Decision: not a connetto concern — `subql` owns accumulator lifecycle.** `subql` currently keeps accumulators in memory; on restart they are rebuilt via re-execution against PostgreSQL. Whether `subql` eventually persists accumulator state to avoid re-execution cost on restart is an internal `subql` optimization. connetto does not depend on or manage accumulator storage.

**Q5.5** ~~— **Re-execution rate limiting**: what is the right throttle for query re-execution? Per-subscription cooldown? Global quota?~~

**Decision: not a connetto concern — `subql` owns re-execution scheduling.** Rate limiting of SQL re-execution (per-subscription debounce, global concurrency cap, coalescing of rapid CDC bursts) is internal to `subql`. connetto receives results from `subql` regardless of how `subql` manages its query load. Documented as a required `subql` feature.

**Q5.6** ~~— **GROUP BY delta format**: when many groups change at once (e.g. a batch import), should the server send a full group-map replacement or a delta list? At what size does full replacement become preferable?~~

**Decision: dissolved — the format follows from the evaluation path.** The IVM path inherently produces per-group deltas (the accumulator update targets specific group keys — emitting only changed groups is the natural output). The re-execution fallback inherently produces full results (it re-runs the query). There is no design choice to make; no threshold-based switching between formats. The client handles both: a delta upserts the affected rows in the local aggregate table; a full result replaces the entire table.

**Q5.7** ~~— **Client schema for aggregate results**: what does the local SQLite schema look like for GROUP BY results — a generic key-value table, or a typed table generated from the spec?~~

**Decision: generic `_connetto_aggregates` table with JSON result column.** A single connetto-managed table stores all aggregate subscription results. Schema: `(sub_id TEXT, group_key BLOB, result_json TEXT, PRIMARY KEY (sub_id, group_key))`. The application reads results via a custom Diesel connection that deserializes the JSON into typed Rust structs (`T: serde::DeserializeOwned`). No per-subscription DDL generation — connetto owns this table entirely. Delta updates upsert by `(sub_id, group_key)`; full re-execution results replace all rows for that `sub_id`.

---

## 06 · Reconnect

**Q6.1** ~~— **Oplog retention window**: what is the default size (entry count or age)? How does it interact with storage cost on the server?~~

**Decision: 72 hours or 1M entries, whichever is hit first. Both configurable per deployment.** 72 hours covers overnight offline, weekend-backgrounded apps, and most real-world disconnection patterns. 1M entries prevents unbounded growth on high-throughput tables. Pruning is unconditional on the retention window — no per-client cursor tracking in the pruning logic. Clients whose `last_applied_lsn` falls outside the window get a full re-sync. These defaults are a starting heuristic; deployments tune based on observed offline durations and write throughput.

**Q6.2** ~~— **Forced full re-sync signal**: should the server send an explicit "you must re-sync" message when the client's LSN is outside the window, rather than silently falling back to a snapshot?~~

**Decision: yes, explicit `FullResyncRequired` control message.** When the client's `last_applied_lsn` is outside the oplog retention window, the server sends a `FullResyncRequired { reason }` message before beginning snapshot delivery for the affected subscriptions. The client uses this to: (1) show a "re-syncing..." state in the UI, (2) clear local data for those subscriptions before applying the snapshot as a full replacement (not a merge/upsert), and (3) provide debuggability — the reason is visible in logs.

**Q6.3** ~~— **Catchup delivery format**: deliver oplog catchup as a stream of `RowUpdate` messages (reuses existing infrastructure) or as a special `CatchupPatch` snapshot-style message (may be more efficient)?~~

**Decision: dissolved — already decided as PatchSet.** The delivery format decision in `06-reconnect.md` established SQLite PatchSet as the universal delivery mechanism for both the live path and the reconnect/catchup path. No separate format distinction needed.

**Q6.4** ~~— **Subscription-level LSN tracking**: should each subscription track its own resume LSN, or is a single global LSN per client sufficient? Per-subscription LSNs enable partial catchup; a global LSN is simpler.~~

**Decision: per-subscription cursors, tracked server-side by `subql`, keyed by session.** On reconnect the client sends only its session token. `subql` maintains per-subscription resume cursors server-side, linked to the session. For each subscription, `subql` checks the cursor against the oplog retention window and either delivers a catchup PatchSet or signals `FullResyncRequired` (Q6.2). The client does not manage or persist cursor state — this is entirely a `subql` concern. Per-subscription granularity means a newly added subscription has no catchup debt, and one subscription falling outside the oplog window does not force a full re-sync of all others. This pattern is consistent with production sync systems (PowerSync per-bucket cursors, ElectricSQL per-shape offsets, Firestore per-target resume tokens).

**Q6.5** ~~— **Oplog storage backend**: should the oplog live in PostgreSQL (durable, potentially slow under high write volume), a separate fast store (Redis, in-memory ring buffer), or both?~~

**Decision: per-session pending PatchSet buffer in `subql`, scoped to session cookie lifetime.** On disconnect, `subql` continues accumulating changes for the session's subscriptions into a pending PatchSet server-side. On reconnect (session token still valid), the client receives that PatchSet — instant catchup, no oplog scan. If the session cookie expires before reconnect, the entire session state (subscriptions, cursors, pending PatchSet) is garbage collected; the client must re-authenticate and re-subscribe from scratch (full snapshot). The mesh-visible PostgreSQL oplog table still exists for CDC propagation across nodes, but the reconnect story is session-scoped — the session cookie lifetime is the primary expiry mechanism, not a separate oplog retention window.

**Q6.6** ~~— **Concurrent re-sync and live updates**: during a full re-sync snapshot delivery, live CDC events continue arriving. How does the server buffer or order these relative to the snapshot?~~

**Decision: dissolved — handled by the session-scoped pending PatchSet buffer.** CDC events arriving during snapshot delivery are appended to the new session's pending PatchSet buffer (Q6.5) and delivered after the snapshot completes. The client confirms receipt via a server-issued opaque cursor included in each delivery. On reconnect, the client sends `(session_token, last_applied_cursor)`. `subql` validates the cursor against its own state and builds the catchup PatchSet from the gap. The cursor is opaque to the client — `subql` issues it and `subql` interprets it. A client reporting a wrong cursor can only hurt its own view; the server's canonical state is never compromised. This follows the Firestore model (opaque server-issued `resume_token`). Checksum-based self-healing (PowerSync model) can be layered on later if needed.

---

## 07 · File Sync

**Q7.1–Q7.8** ~~— All file sync questions.~~

**Decision: out of scope.** File sync is handled by a separate stack (Q1.2). All file sync design decisions (transport channel, chunking, hashing, conflict resolution, GC, size limits, encryption, CDN integration) are deferred to that stack. Refer to https://github.com/LucaCappelletti94/file-system-review for notes and research.

---

## 08 · Authorization

**Q8.1** ~~— **Policy evaluation approach**: direct SQL execution vs. in-process policy compilation vs. hybrid? What is the approach?~~

**Decision: OpenFGA via Rust SDK.** RLS policies are the source of truth in PostgreSQL. [`rls2fga`](https://github.com/LucaCappelletti94/rls2fga) translates them into OpenFGA authorization models. At runtime, visibility checks query OpenFGA via its Rust SDK — not direct SQL evaluation or in-process RLS compilation. This decouples authorization evaluation from the database and makes it available to both connetto and `subql` without SQL round-trips to PostgreSQL.

**Q8.2** ~~— **Policy change handling**: if an RLS policy is altered, which response is acceptable — re-snapshot all affected subscriptions, targeted per-row re-check, or defer visibility correction until reconnect?~~

**Decision: two tiers — session invalidation on model change, OpenFGA cache TTL for tuple changes.**

- **Authorization model change** (RLS policy DDL altered → `rls2fga` re-translates → OpenFGA model updated): this is a schema-level event. All active sessions are invalidated; clients must re-authenticate and re-subscribe from scratch (full snapshot). This is the PowerSync approach — conservative but correct. Model changes are rare (deploy-time events).
- **Relationship tuple change** (user loses/gains access to a specific row within existing rules): propagates through OpenFGA's consistency model. `subql` checks visibility via OpenFGA on each CDC event. Latency is bounded by OpenFGA's cache TTL (configurable; `HIGHER_CONSISTENCY` mode bypasses cache for immediate enforcement at higher latency). No session invalidation needed — the change naturally affects subsequent visibility checks.

No production sync system enforces policy changes instantly for connected clients. The bounded propagation delay (OpenFGA cache TTL for tuples, session invalidation for model changes) is consistent with the state of the art (Firebase: up to 10 min, Supabase: JWT TTL, PowerSync: full re-sync).

**Q8.3** ~~— **Auth context lifetime**: can the auth context be refreshed mid-session (e.g. a role is added without disconnect)? Is this required?~~

**Decision: dissolved — auth context is always live via OpenFGA.** The session token identifies the user; actual permissions are resolved per-check from OpenFGA, not cached at session start. Role/permission changes originating as PostgreSQL rows are replicated into OpenFGA tuples via CDC (WAL event → tuple write). Subsequent visibility checks pick up the change automatically, bounded by OpenFGA's cache TTL (Q8.2). No mid-session refresh mechanism needed.

**Q8.4** ~~— **File token revocation**: if a file access token is issued and the session is subsequently revoked, can the token still be used until it expires? Is that window acceptable?~~

**Decision: dissolved — file sync is out of scope (Q7.1–Q7.8).**

**Q8.5** ~~— **Tenant isolation**: in a multi-tenant deployment, is there a top-level isolation layer above RLS, or is tenant isolation fully expressed in RLS policies?~~

**Decision: tenant isolation is expressed in the RLS→OpenFGA authorization model.** `rls2fga` translates tenant-scoping RLS policies into FGA tuples/relations (user belongs to tenant, resource belongs to tenant). No separate isolation mechanism above the auth layer — tenant boundaries are just another dimension of the authorization model. connetto does not need tenant-aware logic; it delegates to OpenFGA like any other visibility check.

**Q8.6** ~~— **Audit log destination**: is the `auth_log` table in PostgreSQL the right destination, or should audit events go to a separate log aggregator?~~

**Decision: structured logging for the firehose, PostgreSQL table for critical events.** High-volume operational events (auth check denials, connection events, CDC visibility checks) go to structured logging (stdout → external aggregator). Critical state changes (permission changes, session invalidations, model changes) are persisted to a PostgreSQL `auth_events` table for application-level querying. OpenFGA's own audit log covers tuple/model changes on the authorization side.

Note on log aggregators: the application writes structured logs to stdout; the aggregator is a deployment choice. Common options:
- **ELK** (Elasticsearch + Logstash + Kibana): full-text indexes all log content. Mature, powerful queries, but resource-heavy (Java-based).
- **Loki** (Grafana): indexes only labels/metadata, not full content — cheaper to run. Pairs with Grafana for visualization. "Prometheus but for logs."

The choice is an ops decision, not an architecture one — connetto just emits structured logs to stdout.

---

## 09 · WASM / Browser

**Q9.1** ~~— **SharedWorker vs. Worker**: is `SharedWorker` a requirement or a later optimization? It complicates implementation significantly.~~

**Decision: dissolved by Q1.3.** SharedWorker only, no fallback.

**Q9.2** ~~— **OPFS availability**: what is the fallback story for environments without OPFS (older browsers, some mobile WebViews) — IndexedDB adapter, in-memory only, or unsupported?~~

**Decision: OPFS required, no fallback.** Browsers without OPFS are unsupported. No IndexedDB adapter or in-memory fallback.

Combined with SharedWorker (Q1.3), the minimum supported browser versions are determined by the stricter of the two requirements:

| Browser | SharedWorker | OPFS | Minimum supported | Release date |
|---------|-------------|------|-------------------|-------------|
| Chrome desktop | 5 (2010) | 86 (2020) | **86** | Oct 2020 |
| Chrome Android | Never | 86 (2020) | **Unsupported** | N/A (use native app) |
| Firefox desktop | 29 (2014) | 111 (2023) | **111** | Mar 2023 |
| Firefox Android | 33 (2015) | 111 (2023) | **111** | Mar 2023 |
| Safari desktop | 16.0 (2022) | 15.2 (2021) | **16.0** | Sep 2022 |
| Safari iOS | 16.0 (2022) | 15.2 (2021) | **16.0** | Sep 2022 |
| WebView Android | Never (SharedWorker) | 86 (2020) | **Unsupported** | N/A (use native app) |
| Edge | Same as Chrome | Same as Chrome | **86** | Oct 2020 |

Unsupported entirely: Chrome Android, WebView Android (no SharedWorker — these users install the native app per Q1.3). Any desktop/iOS browser older than ~3–5 years.

**Q9.3** ~~— **WASM bundle size**: what is an acceptable size limit? Are there heavy dependencies that must be avoided?~~

**Decision: no target — measure once there's a working build.** Setting a size budget before the crate exists is premature. The known heavy component is SQLite (~300–400 KB gzipped); the rest (`rmp-serde`, `serde_json`, Zstd) is lightweight. Optimize when there's something to measure.

**Q9.4** ~~— **Main thread read access**: should the main thread be able to query local SQLite directly (via synchronous OPFS in a Worker), or should all reads go through the worker message-passing API?~~

**Decision: all reads through the SharedWorker via a custom `diesel_async` connection.** The main thread uses a custom Diesel async connection that wraps message-passing to the SharedWorker. From the application's perspective it's standard `diesel_async` queries; the SharedWorker transport is an implementation detail. No direct OPFS access from the main thread, no secondary read Worker.

**Q9.5** ~~— **ServiceWorker**: is background sync (receiving updates with no tab open) a requirement? If so, `ServiceWorker` is needed.~~

**Decision: no ServiceWorker.** Background sync with no tab/app open is an OS-level limitation, not something connetto can solve. Native apps reconnect on resume; the SharedWorker stays alive as long as at least one tab is open. When the last tab closes or the app is suspended, the WebSocket drops. On reopen, the client reconnects and receives the pending PatchSet (Q6.5). Push notifications for "new data available" are a separate concern outside connetto's scope.

**Q9.6** ~~— **TypeScript bindings**: should the WASM client expose TypeScript bindings (via `wasm-bindgen` + `tsify`)? Is this in scope?~~

**Decision: out of scope.** The immediate consumer is a Dioxus app (Rust on both sides). No TypeScript caller exists. TS bindings can be added later if connetto-rs targets non-Rust web apps.

**Q9.7** ~~— **Testing WASM**: how are WASM-specific behaviors tested — `wasm-pack test` with headless Chrome, a mocked browser environment, or another approach?~~

**Decision: `wasm-pack test --headless --chrome`.** Real headless browser testing — compiles to WASM and runs against actual browser APIs (SharedWorker, OPFS). No mocked browser environment.

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
