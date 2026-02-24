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

**Q2.1** — **Serialization format**: which format? Candidates are MessagePack, Protobuf/FlatBuffers, JSON, and CBOR. Decision needed before any message types are implemented.

**Q2.2** — **Mutation window**: single in-flight mutation vs. sliding window of N — what is N, and how does it interact with client-seq ordering?

**Q2.3** — **Versioning / evolution**: how are breaking changes to `WireMessage` handled? A version field in `Handshake`? A negotiation step?

**Q2.4** — **HTTP fallback**: is HTTP SSE + POST (or long-poll) in scope for v1?

**Q2.5** — **Compression**: per-message or per-frame compression (e.g. `permessage-deflate` for WebSocket)? Worthwhile for large snapshots?

---

## 03 · Sync Pipeline

**Q3.1** — **Mutation window**: should the client pipeline multiple in-flight mutations (window of N) or enforce strict one-at-a-time? Pipelining increases throughput but complicates conflict handling when an early mutation in the window is rejected. *(Overlaps Q2.2.)*

**Q3.2** — **Base version representation**: what exactly is `base_version`? Row-level timestamp? Vector clock? PostgreSQL `xmin`? The choice affects conflict granularity and server-side comparison cost.

**Q3.3** — **CDC source**: logical replication vs. trigger-based `NOTIFY` — tradeoffs in latency, setup complexity, and required PostgreSQL permissions.

**Q3.4** — **Predicate evaluation on CDC events**: for complex subscription filters, should matching be done fully in-process, or should the server issue a SQL query per CDC event? In-process is faster; SQL is more accurate for complex predicates.

**Q3.5** — **Own-mutation echo suppression**: should the server suppress the CDC echo for the originating client (send only `MutationAck`, no `RowUpdate`), or always send both? Suppression is an optimization but complicates LSN tracking.

---

## 04 · Subscriptions

**Q4.1** — **Predicate language scope**: is the current predicate tree (Eq, Ne, Lt, Gt, In, And, Or, Not) sufficient, or do clients need more expressive filters (LIKE, IS NULL, array containment)? More expressiveness makes in-process server evaluation harder.

**Q4.2** — **Subscription count limits**: should the server enforce a maximum number of subscriptions per session? What happens when the limit is reached?

**Q4.3** — **Snapshot parallelism**: should the server deliver snapshots for multiple subscriptions concurrently or serially? Concurrency helps latency but increases server load.

**Q4.4** — **Catchup patch optimization**: is the "deliver catchup patch instead of full snapshot on reconnect" optimization in scope for v1?

**Q4.5** — **Column projection**: if a client subscribes with `columns: Some([...])`, does the server track only those columns for change matching, or always track all columns and project at delivery time?

---

## 05 · Aggregate Queries

**Q5.1** — **IVM scope**: which aggregate shapes get incremental view maintenance vs. re-execution fallback? MIN and MAX with deletions are the hardest — are they in scope for IVM?

**Q5.2** — **HAVING clauses**: should `HAVING` filters be supported in the aggregate spec? They apply after grouping and are harder to evaluate incrementally.

**Q5.3** — **Multi-table aggregates**: aggregates that JOIN multiple tables are not addressed. Are they in scope?

**Q5.4** — **Accumulator persistence**: is the accumulator state kept only in memory (lost on server restart) or persisted? Memory is simpler; persistence is more efficient for long-running subscriptions.

**Q5.5** — **Re-execution rate limiting**: what is the right throttle for query re-execution? Per-subscription cooldown? Global quota?

**Q5.6** — **GROUP BY delta format**: when many groups change at once (e.g. a batch import), should the server send a full group-map replacement or a delta list? At what size does full replacement become preferable?

**Q5.7** — **Client schema for aggregate results**: what does the local SQLite schema look like for GROUP BY results — a generic key-value table, or a typed table generated from the spec?

---

## 06 · Reconnect

**Q6.1** — **Oplog retention window**: what is the default size (entry count or age)? How does it interact with storage cost on the server?

**Q6.2** — **Forced full re-sync signal**: should the server send an explicit "you must re-sync" message when the client's LSN is outside the window, rather than silently falling back to a snapshot?

**Q6.3** — **Catchup delivery format**: deliver oplog catchup as a stream of `RowUpdate` messages (reuses existing infrastructure) or as a special `CatchupPatch` snapshot-style message (may be more efficient)?

**Q6.4** — **Subscription-level LSN tracking**: should each subscription track its own resume LSN, or is a single global LSN per client sufficient? Per-subscription LSNs enable partial catchup; a global LSN is simpler.

**Q6.5** — **Oplog storage backend**: should the oplog live in PostgreSQL (durable, potentially slow under high write volume), a separate fast store (Redis, in-memory ring buffer), or both?

**Q6.6** — **Concurrent re-sync and live updates**: during a full re-sync snapshot delivery, live CDC events continue arriving. How does the server buffer or order these relative to the snapshot?

---

## 07 · File Sync

**Q7.1** — **Physical content channel**: same WebSocket connection or a separate HTTP endpoint? HTTP allows range requests and CDN integration; same WebSocket simplifies connection management.

**Q7.2** — **Chunk size**: 256 KiB? 1 MiB? Configurable per-server? Smaller chunks = more round-trips; larger chunks = coarser resume granularity.

**Q7.3** — **Content hash function**: SHA-256 (widely supported) or Blake3 (faster, native Rust)? Does the choice matter for interoperability?

**Q7.4** — **File tree conflict resolution**: if two clients rename or move the same file concurrently, what wins — last-writer-wins on the metadata row, or a CRDT-based file tree?

**Q7.5** — **Chunk store GC**: how does the server clean up unreferenced chunks — reference counting at write time, or a periodic GC sweep?

**Q7.6** — **Large file limits**: is there a maximum file size? What is the backpressure story for a 10 GiB upload?

**Q7.7** — **Encryption at rest**: is content encrypted before storage on the server? Client-side encryption? Out of scope?

**Q7.8** — **CDN integration**: for large-scale deployments, should chunk download bypass the application server and go to a CDN/object store? How does the token model work in that case?

---

## 08 · Authorization

**Q8.1** — **Policy evaluation approach**: direct SQL execution vs. in-process policy compilation vs. hybrid? What is the v1 approach?

**Q8.2** — **Policy change handling**: if an RLS policy is altered, which response is acceptable — re-snapshot all affected subscriptions, targeted per-row re-check, or defer visibility correction until reconnect?

**Q8.3** — **Auth context lifetime**: can the auth context be refreshed mid-session (e.g. a role is added without disconnect)? Is this required?

**Q8.4** — **File token revocation**: if a file access token is issued and the session is subsequently revoked, can the token still be used until it expires? Is that window acceptable?

**Q8.5** — **Tenant isolation**: in a multi-tenant deployment, is there a top-level isolation layer above RLS, or is tenant isolation fully expressed in RLS policies?

**Q8.6** — **Audit log destination**: is the `auth_log` table in PostgreSQL the right destination, or should audit events go to a separate log aggregator?

---

## 09 · WASM / Browser

**Q9.1** — **SharedWorker vs. Worker**: is `SharedWorker` a v1 requirement or a later optimization? It complicates implementation significantly.

**Q9.2** — **OPFS availability**: what is the fallback story for environments without OPFS (older browsers, some mobile WebViews) — IndexedDB adapter, in-memory only, or unsupported?

**Q9.3** — **WASM bundle size**: what is an acceptable size limit? Are there heavy dependencies that must be avoided?

**Q9.4** — **Main thread read access**: should the main thread be able to query local SQLite directly (via synchronous OPFS in a Worker), or should all reads go through the worker message-passing API?

**Q9.5** — **ServiceWorker**: is background sync (receiving updates with no tab open) a requirement? If so, `ServiceWorker` is needed.

**Q9.6** — **TypeScript bindings**: should the WASM client expose TypeScript bindings (via `wasm-bindgen` + `tsify`)? Is this in scope for v1?

**Q9.7** — **Testing WASM**: how are WASM-specific behaviors tested — `wasm-pack test` with headless Chrome, a mocked browser environment, or another approach?

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
