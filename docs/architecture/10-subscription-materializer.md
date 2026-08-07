# 10: Subscription Materializer

**Status**: draft

---

## Purpose

The **Subscription Materializer** is the server-side component that hosts `subql` and turns its per-consumer output into per-session wire output for each client. It is the only server piece that knows about client sessions and the reliability policy. Authorization is split at the boundary: the visibility trait is defined in `subql`, and the materializer holds the implementation.

It is deliberately thin. After the `subql` full-loop work, the library owns the CDC ingestion, the event to patchset conversion, the inbound apply, and the re-execution state machine. The materializer is what remains once those live inside `subql`: the session and reliability surface a sync server must own, and the implementation of the visibility trait `subql` defines. This chapter pins that boundary as it stands today (an earlier draft placed the CDC connection and patchset building inside the materializer, which is no longer where they live) and fixes where reliability and retry sit, which had been folklore under one Transport bullet in `01-pieces.md`.

---

## What subql owns (the materializer only drives it)

`subql` is an in-process library with no async runtime of its own. The materializer supplies the runtime, the connections, and the visibility trait implementation, then drives `subql`. The library owns:

- **CDC ingestion.** The `CdcSource` trait plus concrete sources: `PgStreamingCdcSource` (holds a `pg_walstream` replication connection, issues `START_REPLICATION`, stamps each event with its LSN, and flows acks back so PG can recycle WAL), `PollingPgCdcSource` (drains a slot over plain SQL), and `SqliteCdcSource` on the client side. WAL parsers for pgoutput, wal2json v1 and v2, Maxwell, and Debezium feed one path. The materializer drives the consume loop (`next_event` and `ack`) and decides the ack cadence and reconnect policy, but does not parse WAL or hold the replication protocol.
- **Matching and classification.** The subscription registry, routing by referenced tables, the bitmap-indexed candidate prune, the predicate VM with SQL three-valued logic, and UPDATE transition detection. A base UPDATE surfaces per consumer as `inserted`, `deleted`, or `updated` when a row enters, leaves, or changes within its result set.
- **Aggregate IVM.** `COUNT(*)`, `COUNT(col)`, `SUM`, `AVG`, and the variance and standard-deviation family, maintained in memory and emitted as signed `AggDelta`s.
- **Event to patchset conversion.** `wal2json_patchset`, `pgoutput_patchset`, and `maxwell_patchset` (and their changeset counterparts) fold a batch of events over a source-agnostic catalog into one `sqlite-diff-rs` patchset or changeset.
- **Inbound apply.** `SubscriptionEngine::apply_diffset_bytes` parses uploaded SQLite session bytes, dispatches the patchset or changeset marker, reconstructs against the catalog, and applies transactionally through native diesel adapters (`PgAdapter`, `MysqlAdapter`, `SqliteAdapter`, and `CustomTypePgAdapter` for enum and domain columns). No SQL casts.
- **Re-execution state machine.** The `reexec` module. `ReExecEngine` classifies queries the row-image engine cannot resolve (MIN or MAX extreme removal, single-table row re-execution behind a filter it cannot evaluate, multi-table aggregates, complex HAVING) and either emits a `ReExecutionTrigger` for the caller to service, or, via `AutoResolvingEngine` and a caller-supplied `Connector`, runs the query itself and returns a `ScalarUpdate`. `install(query_id, value)` sets the stored value unconditionally. `subql` owns the classification and the state. The caller owns the actual DB query and its retry.
- **Predicate-state persistence and position types.** Durable shards for predicate state, and the `Checkpoint` family (`PgLsn`, `MysqlBinlogPos`).
- **OpenFGA upkeep.** The per-row upkeep of the permission records lives in `subql`, driven from the change stream, because removing a record requires the value it was built from and `subql` is where both row versions are in hand. **Decided (R5b).** The `rls2fga` per-row mapping this needs landed in full on 2026-08-07 (its `main` at `d8f5dd7`), so what blocks R5b is the subql half alone (`docs/upstream-subql-per-row-visibility.md`), which is **underway** on subql branch `feat/visibility-from-the-row`.

The line to hold onto: `subql` runs re-execution queries through a `Connector` the materializer implements, and it holds no retry anywhere. Everything that can transiently fail crosses a connection the materializer owns or configures.

---

## What the materializer owns

- **Sessions and the wire.** `subql` speaks in consumer ids, typed events, `AggDelta`s, and patchset bytes. It has no notion of a WebSocket session, the flow-control window, keepalive, the reconnect handshake, or the `connetto-core` `ControlMessage` and `BulkMessage`. The materializer maps `subql`'s per-consumer output onto sessions and frames it into `SnapshotPatch`, `LivePatch`, and aggregate envelopes carrying the resume `Cursor`, back-pressured per session.
- **The fan-out unit. Decided (R16 part B).** One change event, not one subscriber. Everything a change costs is charged once per event, and the only work charged per subscriber is the socket write. `17-fan-out.md` owns the shape, what stays proportional to subscriber count and why that is acceptable, and the protocol and materializer changes required to adopt it. Two of them are the materializer's own: the payload travels to every consumer as one shared `Arc<[u8]>` rather than a copy each (**Decided (R14)**), and the subscription registry gains a cap and an eviction policy, since retained subscriptions make a disconnect storm unbounded and `subql`'s `max_subscriptions` defaults to no cap.
- **Authorization.** The visibility trait is defined in `subql`, which holds the replication connection and already computes previous-versus-current transitions per subscriber for the subscription predicate. `subql` ships a ready-made implementation backed by the authorization service, and a downstream user may implement the trait itself. **Built (R5a).** connetto's `AuthPolicy` is gone and all four call sites ask through `subql::visibility::VisibilityPolicy`, with `RlsAuth` behind it. The trait is defined low and consumed upward because its callers are on both sides of the boundary: the change path is the one that eventually moves into `subql`, while the catchup, write and capability-minting paths stay in connetto. This follows an idiom `subql` already uses: query re-execution works by `subql` asking the caller through a `Connector`, because the query and its retry belong to the caller. A row becoming invisible is delivered as a delete. The check runs against both versions of the row, with the previous-version check made only when the current version is absent or invisible. **Decided (R6).** `subql`'s `Connector` carries a `Principal` (which may carry no identity) into a re-execution so an RLS re-query runs under the right role. **Decided (R3).** Write authority: every inbound mutation is gated before apply.
- **Per-session patchset assembly.** `subql`'s builder folds a slice of events into one patchset. Because per-subscription filtering differs per client, the materializer selects each session's matched event subset and invokes the builder for it. The visibility answer for each row comes from the trait `subql` defines, not from a check the materializer performs independently. The primitive is `subql`'s. The per-session selection is the materializer's.
- **The write path end to end.** A client uploads a `MutationPatch`. The materializer authorizes the write (strict consistency preference, versus the fast preference on the change path, **Decided (R5b)**, see `08-authorization.md`), detects conflicts (the `updated_at` token per Q3.2), calls `subql.apply_diffset_bytes` in a transaction against its PG pool, and reports the outcome (per Q3.5 the CDC echo serves as the success ack, so only `MutationReject` and `MutationConflict` are dedicated messages). `client_seq` idempotency and the reply are the materializer's.
- **Oplog, reconnect, and catchup.** The retention-bounded oplog keyed by LSN, the catchup versus `FullResyncRequired` decision, and tombstones (`06-reconnect.md`) are session-bound server state. The catchup path carries the same two-version authorization obligation as the live path, so the oplog must carry whatever those checks need. **Decided (R6).** It also carries the prepared compressed patch, so catchup reads bytes instead of rebuilding them per record per subscription, which is what takes `Materializer::encode_patch` off that path. **Decided (R16 part B)**, and it is what requires a subscription to outlive its socket by the retention window, because `Materializer::dispatch` builds a payload only when a consumer matches.
- **Reliability orchestration.** `subql` keeps zero retry surface on purpose. The materializer is where one backoff primitive covers CDC reconnect, re-execution retry and coalescing, OpenFGA retry, delivery back-pressure, and mutation retry.
- **Wiring choices subql leaves open.** Streaming versus polling source, the bare `ReExecEngine` (explicit coalescing and retry) versus `AutoResolvingEngine` with a `Connector`, and how a stateful subscription bootstraps its first `install`ed value.

This boundary is normative. It is the contract that lets the reliability and retry policy in this chapter live in exactly one place.

---

## Position in the system

The big-picture diagram in `00-overview.md` collapsed everything server-side after CDC into a single "CDC Fanout Engine". Factored against the real crate boundary, the CDC source, matching, conversion, apply, and re-execution engine sit inside `subql`. The materializer wraps that with connections, authorization, and the wire:

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Server                                                                    │
│                                                                            │
│  ┌────────────┐        ┌────────────────── subql ──────────────────────┐  │
│  │ PostgreSQL │        │  CdcSource  (owns the replication connection)  │  │
│  │            │ ─────▶ │  match + aggregate IVM                         │  │
│  │  CDC / WAL │        │  emit:   events  ─▶  sqlite-diff-rs patchset    │  │
│  │            │        │  reexec engine  ─▶  Connector ─────────────┐    │  │
│  │            │ ◀──────┤  apply_diffset_bytes                        │    │  │
│  └────────────┘        └──────────────────┬──────────────────────────────┘  │
│      ▲     ▲                               │ consumer notifs,           │    │
│      │     │ re-exec query                 │ aggregate deltas,          │    │
│      │     │ (via Connector)               ▼ patchset bytes      install │    │
│      │     │           ┌──── Subscription Materializer ──────────────────┴┐ │
│      │     │ mutation  │  drive CdcSource loop + ack                       │ │
│      │     └───────────┤  authorize (visibility trait, write gate)         │ │
│      │       apply     │  per-session patchset assembly + framing          │ │
│      └─────────────────┤  oplog + catchup, all retry                       │ │
│                        └────────────────────────┬──────────────────────────┘ │
│                                                 ▼                            │
│                                        Session Manager / sink                │
└──────────────────────────────────────────────────────────────────────────┘
```

`subql` owns the connection and the byte-level conversion. The materializer owns the sessions, the visibility trait implementation, and the reliability that wraps it.

---

## Inputs

- **From subql**: per-event output, the consumer notifications, aggregate deltas, and re-execution triggers produced by matching and maintenance, plus the patchset and changeset bytes produced by the emit builders.
- **From the CDC source**: the materializer drives `subql`'s `CdcSource` (`next_event` and `ack`) and feeds the resulting events into matching in LSN order. The source, not the materializer, holds the replication connection.
- **From the Session Manager**: subscription declarations (`Subscribe` and `Unsubscribe`), session lifecycle events, and reconnect handshakes carrying the client's resume cursor.

## Outputs

- **To the Session Manager**: per-session SQLite patchsets (with their server LSN) ready for delivery, subscription-state changes (for example `FullResyncRequired`), and errors surfaced to the client (`SyncFailure` with a reason).
- **To subql**: `install(query_id, value)` calls when a re-execution or a bootstrap produces a value `subql` needs to hold (MIN or MAX, materialized aggregates).
- **To PostgreSQL**: re-execution and bootstrap queries, issued through the re-exec `Connector` over the materializer's own connection pool.

---

## Core responsibilities

| Responsibility | Notes |
|---|---|
| **Drive the CDC loop** | Consume `subql`'s `CdcSource`, feed events into matching in order, and ack progress so PG recycles WAL. |
| **Fan out to sessions** | Map `subql`'s per-consumer notifications and aggregate deltas onto sessions, framed as `connetto-core` bulk messages under flow control. The unit is the event: one frame per distinct pair of subscription handle and event, cloned per socket. **Decided (R16 part B)**, and today it is one frame built per subscriber. |
| **Authorize** | Implement the visibility trait `subql` defines, called by `subql` on the live change path and by the materializer on the write and catchup paths. Gate every inbound mutation. |
| **Assemble per-session patchsets** | Select each session's matched event subset (visibility determined by the trait `subql` defines) and invoke `subql`'s patchset builder for it. |
| **Run the write path** | Authorize and conflict-check an uploaded `MutationPatch`, then apply it through `subql.apply_diffset_bytes` transactionally and report the outcome. |
| **Provide the re-exec Connector** | Implement the `Connector` (or service bare `ReExecEngine` triggers) that runs re-execution queries against PG, then `install` the result. |
| **Bootstrap stateful subscriptions** | On `Subscribe`, when `subql` classifies a query as stateful (MIN or MAX, multi-table aggregate, complex HAVING), run it once and `install` the initial value. |
| **Coalesce** | Collapse duplicate or in-flight re-execution work for the same `query_id` so a chatty table is one re-run, not N. |
| **Maintain the oplog** | Append change records with retention and serve catchup on reconnect (`06-reconnect.md`). |
| **All retry** | Every transient failure on every cross-process arrow is the materializer's concern. See below. |

---

## Reliability and retry: ownership

The retry policy lives here because everything that can transiently fail in the subscription pipeline crosses the materializer's boundary with PG, OpenFGA, or the network. `subql`'s event processing (matching, aggregate maintenance, conversion) is deterministic in-memory work and holds no retry surface. The connections it needs (the `CdcSource` and the re-exec `Connector`) are supplied and driven by the materializer, so their failures are retried here too.

### Failure inventory

| # | Failure | Owner | Idempotency key | Policy |
|---|---|---|---|---|
| 1 | CDC source drop (replication slot or slot poll) | materializer, driving `subql`'s `CdcSource` | replication LSN | reconnect with exponential backoff and jitter, resume from the last consumed LSN, alert operators on a bounded outage rather than silently dropping events |
| 2 | Re-execution against PG | materializer, via `subql`'s re-exec `Connector` | `(query_id, last_observed_lsn)` | bounded retries with backoff, then surface `SyncFailure { query_id, reason }` to affected sessions, never lose the trigger (re-arm on reconnect) |
| 3 | Bootstrap re-execution (initial value for a stateful subscription) | materializer | `(sub_id)` | bounded retries, then `Reject` the subscription with the cause and tell the client |
| 4 | Authorization call. **Decided (R5b), not built** | materializer, auth filter | request id plus content hash | Intended, per R5b steps 9 and 12: bounded short-window retries under the one unified backoff policy, then fail closed, delivering nothing and accepting no mutation while the answer is unknown. Today the call goes to Postgres row-level security with no retry, and it fails closed |
| 5 | Patchset write to a session outbound queue | materializer | server LSN of the batch | per-session bounded retries respecting flow-control credits, back-pressure CDC on session-buffer exhaustion rather than dropping events server-side |
| 6 | Server-side mutation apply (transient PG error, serialization failure) | materializer, mutation handler | `client_seq` | bounded retries with backoff, then `MutationReject` with the cause so the client's optimistic write rolls back |
| 7 | Client transport reconnect | client connector (Sync Client) | session id plus `last_applied_lsn` | exponential backoff and jitter, resume via `06-reconnect.md`, full re-sync if the cursor falls off the oplog |
| 8 | Pending-mutation resend | client mutation queue | `client_seq` | resend on reconnect, bounded retries per mutation, then a per-mutation reject to the app |
| 9 | Patchset apply on local SQLite (disk full, locked) | client | server LSN of the batch | bounded retries, then surface `SyncFailure` to the app |
| 10 | File chunk transfer (`07-file-sync.md`) | both, per chunk | chunk content hash | per-chunk bounded retries, chunk resumability already covers the multi-chunk case |

### The replication slot

**Decided (R32).** The slot and the publication are the deployment's to provision and to drop, matching the rule that connetto emits no server DDL on any path a deployment runs, and the tests already practice this. Two Postgres facts make the rest necessary. A slot retains WAL without limit by default (`max_slot_wal_keep_size` is `-1`, the Postgres documentation states "replication slots may retain an unlimited amount of WAL files"), so a decommissioned or long-crashed connetto-server makes the primary retain its journal until the disk fills and writes stop for everyone. And once the deployment caps it, an invalidated slot leaves a gap in connetto's ingest that sits upstream of the oplog, so the oplog never contains those changes and the stale-cursor comparison cannot see the hole.

Three responses, all connetto's. Startup refuses when the slot or the publication is missing, joining the existing refusal pattern, because a silent retry loop against a missing slot helps nobody. **What the publication must contain is not only this chapter's question:** `08-authorization.md` adds that a policy reading a table the publication does not carry also refuses startup, because a permission change the stream never delivers leaves the change-path executor answering from a store that quietly stopped being current. The slot's lag is written to the structured log on a cadence (the R12 facade), so an operator hears about a stalled slot before the cap trips, with alerting belonging to the deployment's aggregator as everywhere else. And an invalidated slot, detected when the replication connection reports it, declares a resync epoch: every session cursor older than the gap is forced through `FullResyncRequired`, because continuing from a fresh slot position without that would silently lose every change that fell in the hole. Deployment guidance: set `max_slot_wal_keep_size` to a bound the primary's disk can afford, and optionally `idle_replication_slot_timeout` (both default to off).

### Shared retry primitive

The materializer and the client connector use one backoff abstraction: exponential with jitter, a hard attempt cap, and a hard total-duration cap, parameterizable per failure class. Per-piece policies live next to the piece (in the table) but call into the same primitive, with no ad-hoc loops scattered across files.

### Coalescing, the subql interaction

Re-execution work is designed to be idempotent and coalescible. The materializer:

1. Keeps a small per-`query_id` in-flight set. A trigger that arrives while a re-execution for that id is already running is dropped, since the in-flight run will reflect a state newer than the trigger.
2. Keeps a per-`query_id` pending flag. A trigger that arrives after the in-flight run started but before it finished sets the flag, and one more run is scheduled after the current one completes. This collapses bursts.
3. After a successful re-execution, calls `subql.install(query_id, value)` for stateful queries and emits the patchset. `install` overwrites unconditionally, so it is safe to call repeatedly.

`AutoResolvingEngine` performs the same collapse across a batch through `consumers_batch`. Above the bare `ReExecEngine` the materializer coalesces itself. Either way the contract `subql` owes is the same: triggers are safely repeatable and `install` is idempotent. Both fall out of the design, since triggers carry no payload and `install` is an unconditional state set.

### Failing closed

- **Authorization failure** is always fail-closed. A row whose auth check could not complete is dropped from delivery, never delivered best effort.
- **CDC source failure** never silently drops events. Outages either resume cleanly (LSN-based) or surface to operators. The client never sees a gap that is not reflected in its resume cursor.
- **Re-execution failure** never loses the trigger. If retries are exhausted the trigger stays armed and is retried on the next relevant event or on reconnect, and the client is told (`SyncFailure`) so it can degrade gracefully.

### What surfaces to the client

When retries are exhausted, the materializer surfaces one of:

- `MutationReject { client_seq, reason }`: write-path failures.
- `SyncFailure { sub_id, reason }`: read-path or re-execution failures. The client may re-subscribe or back off.
- `FullResyncRequired { sub_id }`: state unrecoverable via incremental catchup (`06-reconnect.md`).

These are the only give-up surfaces. Everything else is retried inside the materializer without the client knowing.

---

## subql's reliability contract (what the materializer can assume)

For the retry policy above to work, `subql` guarantees:

1. **Triggers are repeatable.** Receiving the same re-execution trigger for a `query_id` twice is safe and not double-counted. The materializer can coalesce or re-emit at will.
2. **`install(query_id, value)` is idempotent.** It unconditionally overwrites the stored value for that query. It does not accumulate or compare.
3. **Event processing is deterministic.** Given the same sequence of CDC events and `install` calls, `subql`'s matching, aggregate maintenance, and conversion produce the same outputs. The randomness and the I/O live in the connections the materializer owns (the `CdcSource` and the re-exec `Connector`), not in `subql`'s event processing.
4. **No partial state.** `subql` never emits a half-built event. A CDC event is either fully processed (with all resulting notifications and triggers) or not consumed.
5. **No silent drops.** If `subql` cannot process an event (a decode error on a carried cell, for example), it surfaces an error rather than skipping rows.

These five let the materializer treat `subql`'s event processing as a deterministic pure function, so retry, coalesce, and replay are all safe. The retryable I/O sits in the materializer's connections.

---

## Open questions

1. ~~**Bootstrap concurrency.** When a stateful subscription registers, the bootstrap re-execution can race with live CDC events. Two options: (a) freeze CDC dispatch for that subscription until the bootstrap LSN is reached, or (b) re-execute at a snapshot LSN and replay the oplog forward to the live tip.~~ **Decided: (b), which was already the specified behaviour. Built (R28 part A, 2026-08-03).**

   `04-subscriptions.md` pins the wire semantics: the snapshot carries the LSN it was read at, and later patches apply on top. The reconnect path always implemented it: `SessionManager::catch_up_row` installs the route **first**, then takes a ceiling from the oplog, and replays up to it, on the stated grounds that an entry at or below the ceiling "was appended before this consumer could receive live delivery, so replaying it cannot duplicate a live patch".

   **The fresh-subscribe path used to do the opposite**, installing the route last, so everything committed during the snapshot read, compression and transfer was silently lost. R28 part A mirrored the catchup path: `snapshot_row` installs the route before reading. The overlap that creates is re-applied rather than filtered, because neither the snapshot LSN nor a change's WAL position orders by visibility, so the discard rule this question once paired with a client-side dedupe was replaced outright (measured and decided in `04-subscriptions.md`, which is also why no client change was needed). R38 then moved every frame behind the successful read, so a snapshot that fails refuses without disclosing that the subscription had registered.

2. ~~**Trigger executor concurrency.** How many concurrent re-executions per session and per server? A pool with a per-session cap plus a global cap is the obvious shape, but the numbers and the back-pressure behavior when the cap is hit need deciding.~~ **Decided: the shape stands, the numbers are an R0 output rather than a design choice, and the gap today is concurrency itself rather than its bound.**

   There is no pool and no cap. The `dispatched.triggers` loop in `SessionManager::dispatch_event` awaits `execute_scalar` one trigger at a time inside the fan-out loop, and a failure is skipped with `continue`. That is the same serial-await shape `08-authorization.md` names as the current scalability wall for `visible`, in the same loop. Picking cap numbers before R0 measures the loop would be picking numbers for a structure that R14 may replace.

3. ~~**Retry budget surface.** Should retry budgets (per-trigger, per-mutation) be observable to operators via metrics, or only via give-up surfaces to clients? Metrics are cheap and probably the right answer.~~ **Decided: both, and it is not a new surface.**

   The pattern already exists. `SessionManager::ingest_with_reconnect` takes `on_event: impl FnMut(ReconnectEvent<'_>)`, and `ReconnectEvent` carries `Retrying { attempt, backoff, error }` and `GaveUp { attempts, .. }`, leaving the embedder to wire it to whatever it already runs. The trigger and mutation retry budgets extend that same callback rather than introducing a metrics surface of their own. The client-facing give-up stays as well, because the two answer different questions. R12 part A landed the operator half: the reference binary logs a retry as a warning and a give-up as an error naming that live delivery has stopped.
4. ~~**Auth retry policy under outage.** If OpenFGA is down for minutes, should the materializer pause delivery (fail closed, conservative, may stall many clients) or degrade with a cached policy (riskier)? Decide before production.~~ **Decided (R5b), fail closed.** No patch is delivered and no mutation accepted while the answer is unknown, because a patch sent to a caller who may not be allowed to see it cannot be recalled and a stall can. Two wire additions follow: a typed signal that delivery is paused rather than quiet, and a rejection reason meaning cannot determine, which must not reuse `Unauthorized` because a client believing itself unauthorized stops retrying and may discard the mutation. Snapshots are unaffected, since they run on Postgres RLS, so an outage stops live delivery and writes while a fresh connection can still read. See `08-authorization.md`.
5. ~~**CDC source placement.** Is `subql`'s `CdcSource` driven once per server (one ingestor with a fanout) or once per session? Per-server with a fanout is the conventional shape and what the diagram implies.~~ **Decided: per-server with a fan-out, and it is already built.** `SessionManager::ingest` describes itself as "the standing ingestor: one per server, fanning out to every session", generic over `CdcSource` so the same loop runs against the SQLite emulator and a real `PgStreamingCdcSource`. The reference binary spawns exactly one, cloning the manager handle into it, and the test harness does the same. This was never open, only unrecorded.

---

## Cross-references

- `subql.md`: what `subql` does and does not do (the in-process side of the boundary).
- `03-sync-pipeline.md`: the mutation and CDC paths through the materializer.
- `04-subscriptions.md`: subscription registration, bootstrap, and live delivery.
- `05-aggregate-queries.md`: the materialized-aggregate path that this chapter unifies under the re-exec Connector plus `install`.
- `06-reconnect.md`: the per-session resume cursor and oplog catchup that the materializer serves.
- `08-authorization.md`: the OpenFGA call this chapter's auth filter depends on.
- `17-fan-out.md`: how one event reaches many subscribers, the unit of computation, and what adopting it costs.
