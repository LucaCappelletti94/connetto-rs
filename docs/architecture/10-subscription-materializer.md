# 10 — Subscription Materializer

**Status**: draft

---

## Purpose

The **Subscription Materializer** is the server-side component that consumes subql's in-process subscription events and *materializes* them into concrete wire output (SQLite patchsets) for each client session. It sits between subql (a pure in-process filter) and the per-session delivery queue, and it owns every side effect subql does not: re-running queries against PostgreSQL, evaluating OpenFGA authorization, loading row values, building sqlite-diff-rs patchsets, and retrying on transient failure.

This chapter introduces the materializer as a distinct architectural piece and pins where reliability/retry lives in the system, which has so far been folklore (one bullet under Transport in `01-pieces.md`).

---

## Position in the system

The big-picture diagram in `00-overview.md` collapsed everything server-side after CDC into a single "CDC Fanout Engine". The materializer is what that box becomes once subql is factored out as a library:

```
┌──────────────────────────────────────────────────────────────────────┐
│  Server                                                              │
│                                                                      │
│  ┌────────────┐    ┌───────────┐    ┌───────────────────────────┐    │
│  │ PostgreSQL │    │   subql    │    │  Subscription Materializer │   │
│  │            │    │            │    │                           │    │
│  │  CDC / WAL │──▶ │ in-process │──▶ │  notifications  ──┐        │    │
│  │            │    │  matching  │    │  triggers   ──────┘──▶...  │    │
│  │            │    │  + agg IVM │    │                           │    │
│  │            │    └────────────┘    │  ┌── trigger executor ──┐ │    │
│  │            │                      │  │ re-run query vs PG   │ │    │
│  │            │ ◀────────────────────│──┤ load rows            │ │    │
│  │            │       trigger        │  │ retry / coalesce     │ │    │
│  │            │     re-execution     │  └──────────────────────┘ │    │
│  └────────────┘                      │                           │    │
│                                      │  ┌── auth filter ───────┐ │    │
│                                      │  │  OpenFGA / Zanzibar  │ │    │
│                                      │  └──────────────────────┘ │    │
│                                      │  ┌── patchset builder ──┐ │    │
│                                      │  │  sqlite-diff-rs      │ │    │
│                                      │  └──────────────────────┘ │    │
│                                      └────────┬──────────────────┘    │
│                                               ▼                       │
│                                       Session Manager / sink          │
└──────────────────────────────────────────────────────────────────────┘
```

subql runs entirely in-process and never touches the database, OpenFGA, or the wire. The materializer is the only component that does.

---

## Boundary with subql

This boundary is normative. It is the contract that lets the reliability/retry policy in this chapter live in exactly one place.

**subql is responsible for** (in-process only):

- Parsing and classification of subscriptions (predicate, aggregate kind, single-table-row eligibility) using sql-traits' `DataStatementLike` / `DQLLike` / `DMLLike`.
- Routing: per `referenced_tables`, knowing which subscriptions a CDC event can affect.
- Predicate evaluation against CDC events (the bytecode VM).
- Incremental aggregate maintenance held entirely in memory: `COUNT`, `SUM`, `AVG`, `VAR_POP`/`VAR_SAMP`, `STDDEV_POP`/`STDDEV_SAMP`, and `MIN`/`MAX` (the partial path).
- Emitting events: per-consumer notifications (`Inserted` / `Deleted` / `Updated`), aggregate deltas, and `NeedsReexecution { query_id }` triggers for the cases it cannot resolve in memory (MIN/MAX extreme removal, single-table row re-execution with a join in the filter, multi-table aggregates, complex HAVING).
- Maintaining its own per-subscription state and accepting `install(query_id, value)` from the materializer to bootstrap or refresh stateful aggregates.

**subql is not responsible for** (and never will be):

- Opening or holding any database connection.
- Running SQL against PostgreSQL.
- Loading row values from the database.
- Building patchsets.
- Authorization (OpenFGA / RLS).
- Anything network- or session-shaped.
- **Any retry. Anywhere.**

**The Subscription Materializer is responsible for everything in the second list, and for nothing in the first.** It owns the database side and the wire side; subql is the abstract domain in between.

---

## Inputs

- **From CDC source**: a stream of `ChangeRecord`s (logical replication / `LISTEN`). The materializer owns the CDC connection and feeds events into subql in order.
- **From subql**: per-event output - the consumer notifications, aggregate deltas, and `NeedsReexecution` triggers produced by subql's matching/maintenance.
- **From Session Manager**: subscription declarations (`Subscribe` / `Unsubscribe`), session lifecycle events, and reconnect handshakes (which carry the client's resume cursor).

## Outputs

- **To Session Manager**: per-session SQLite patchsets (with their server LSN) ready for delivery; subscription-state changes (e.g. `FullResyncRequired`); errors surfaced to the client (`SyncFailure` with a reason).
- **To subql**: `install(query_id, value)` calls when a triggered re-execution or a bootstrap produces a value subql needs to hold (MIN/MAX, materialized aggregates).
- **To PostgreSQL**: re-execution queries (triggered or bootstrap), with their own connection pool.

---

## Core responsibilities

| Responsibility | Notes |
|---|---|
| **Drive subql** | Hand CDC events to subql; collect its output. |
| **Bootstrap stateful subscriptions** | On `Subscribe`, if subql classifies the query as stateful (MIN/MAX, multi-table aggregate, complex HAVING), run it once against PG and `install` the initial value into subql. |
| **Service `NeedsReexecution` triggers** | Look up the query, re-run against PG, install the value (where applicable), and emit a patchset for affected sessions. |
| **Coalesce** | Collapse duplicate / in-flight `NeedsReexecution` triggers for the same `query_id`; one re-execution serves any number of pending triggers. |
| **Authorize** | Apply OpenFGA per (session, row, event) *after* subql matching and *before* patchset assembly. |
| **Load row values** | For row-level deliveries and re-executed queries, load row values - via sqlite-diff-rs (which itself uses `diesel-dynamic-schema` from the diesel fork for arbitrary-shape rows). |
| **Build patchsets** | Assemble sqlite-diff-rs changesets/patchsets keyed by base-table PK (for row-level subscriptions and DML echoes) or by the aggregate-table key (for materialized aggregates). |
| **Maintain the oplog** | Append `ChangeRecord`s with retention; serve catchup on reconnect (`06-reconnect.md`). |
| **Own the PG CDC connection** | Logical replication slot, `LISTEN`/`NOTIFY` - including reconnect to PG with backoff. |
| **All retry** | Every transient failure on every cross-process arrow is the materializer's concern. See below. |

---

## Reliability and retry — ownership

The retry policy lives here because everything that can transiently fail in the subscription pipeline crosses the materializer's boundary with PG, OpenFGA, or the network. subql holds nothing that can fail transiently (it is deterministic in-memory work).

### Failure inventory

| # | Failure | Owner | Idempotency key | Policy |
|---|---|---|---|---|
| 1 | CDC source drop (logical replication slot, `LISTEN`) | materializer (CDC ingestor) | replication LSN | reconnect with exponential backoff + jitter; resume from last consumed LSN; bounded outage triggers operator alert (do not silently drop events) |
| 2 | Re-execution against PG (triggered) | materializer (trigger executor) | `(query_id, last_observed_lsn)` | bounded retries with backoff; on persistent failure, surface to affected sessions as `SyncFailure { query_id, reason }`; never lose the trigger - re-arm on reconnect |
| 3 | Bootstrap re-execution (initial value for stateful subscription) | materializer | `(sub_id)` | bounded retries; on persistent failure, the subscription is `Rejected` with the cause and the client is told |
| 4 | OpenFGA / authorization call | materializer (auth filter) | request-id + content hash | short-window retries on transient outage; on persistent failure, fail closed (drop the row from delivery, log) - never deliver unauthorized rows |
| 5 | Patchset write to session outbound queue | materializer | server LSN of the batch | per-session bounded retries respecting flow-control credits; on session-buffer exhaustion, back-pressure CDC (do not drop events server-side) |
| 6 | Server-side mutation handler (transient PG error, serialization failure) | materializer (mutation handler) | `client_seq` | bounded retries with backoff; persistent failure -> `MutationReject` with the cause; the client's optimistic write rolls back |
| 7 | Client transport reconnect | client connector (Sync Client) | session_id + `last_applied_lsn` | exponential backoff + jitter; resume via `06-reconnect.md`; full re-sync if the cursor falls off the oplog |
| 8 | Pending-mutation resend | client (mutation queue) | `client_seq` | resend on reconnect; bounded retries per mutation; persistent failure surfaces as a per-mutation reject to the app |
| 9 | Patchset apply on local SQLite (disk full, locked) | client | server LSN of the batch | bounded retries; persistent failure surfaces as `SyncFailure` to the app |
| 10 | File chunk transfer (`07-file-sync.md`) | both, per-chunk | chunk content hash | per-chunk bounded retries; chunk resumability already covers the multi-chunk case |

### Shared retry primitive

The materializer (and the client connector) use one backoff abstraction: exponential with jitter, a hard attempt cap, and a hard total-duration cap, with the policy parameterizable per failure class. Per-piece policies live next to the piece (in the table) but call into the same primitive - no ad-hoc loops scattered across files.

### Coalescing — the subql interaction

Triggers from subql are designed to be **idempotent and coalescible**. The materializer:

1. Maintains a small per-`query_id` "in-flight" set. If a `NeedsReexecution { query_id }` arrives while a re-execution for that id is already running, it is dropped (the in-flight run will reflect a state newer than this trigger).
2. Maintains a per-`query_id` "pending" flag. If a trigger arrives after the in-flight run started but before it finished, the flag is set; one more run is scheduled after the current one completes. This collapses bursts (a chatty table is one re-run, not N).
3. After a successful re-execution, calls `subql.install(query_id, value)` (for stateful queries) and emits the patchset. `install` overwrites unconditionally - safe to call multiple times.

This is the only contract subql owes the materializer for reliability: **triggers are safely repeatable, and `install` is idempotent.** Both fall out of the design (triggers carry no payload; `install` is an unconditional state set).

### Failing closed

- **Authorization failure** is always fail-closed: a row whose auth check could not be completed is dropped from the delivery, never delivered "best effort".
- **CDC source failure** never silently drops events: outages either resume cleanly (LSN-based) or surface to operators. The client never sees a gap that isn't reflected in its resume cursor.
- **Trigger failure** never loses the trigger: if re-execution exhausts retries, the trigger remains armed and is retried on the next relevant event or on reconnect; the client is told (`SyncFailure`) so it can degrade gracefully.

### What surfaces to the client

When retries are exhausted, the materializer surfaces *one* of:

- `MutationReject { client_seq, reason }` — for write-path failures.
- `SyncFailure { sub_id, reason }` — for read-path / re-execution failures; the client may choose to re-subscribe or back off.
- `FullResyncRequired { sub_id }` — when state is unrecoverable via incremental catchup (`06-reconnect.md`).

These are the only "give-up" surfaces; everything else is retried inside the materializer without the client knowing.

---

## subql's reliability contract (what the materializer can assume)

For the retry policy above to work, subql guarantees:

1. **Triggers are repeatable.** Receiving the same `NeedsReexecution { query_id }` twice is safe and not double-counted; the materializer can coalesce or re-emit at will.
2. **`install(query_id, value)` is idempotent.** It unconditionally overwrites subql's stored value for that query; it does not accumulate or compare.
3. **In-process work is deterministic.** Given the same sequence of CDC events and `install` calls, subql produces the same outputs. No randomness, no clocks, no I/O.
4. **No partial state.** subql never emits a half-built event; a CDC event is either fully processed (with all resulting notifications/triggers) or not consumed.
5. **No silent drops.** If subql cannot process an event (parse error in a registered subscription's WHERE during VM eval, for example), it surfaces an error; it does not skip rows.

These five together let the materializer treat subql as a deterministic pure function — retry, coalesce, and replay are all safe.

---

## Open questions

1. **Bootstrap concurrency.** When a stateful subscription is registered, the bootstrap re-execution can race with live CDC events. Two options: (a) freeze CDC dispatch for that subscription until the bootstrap LSN is reached; (b) re-execute at a snapshot LSN and replay the oplog forward to the live tip. Option (b) is what the snapshot/catchup pattern already implies; pin which.
2. **Trigger executor concurrency.** How many concurrent re-executions per session and per server? A pool with a per-session cap, plus a global cap, is the obvious shape - but the numbers and the back-pressure behavior when the cap is hit need to be decided.
3. **Retry budget surface.** Should retry budgets (per-trigger, per-mutation) be observable to operators via metrics, or only via give-up surfaces to clients? Metrics are cheap and probably the right answer.
4. **Auth retry policy under outage.** If OpenFGA is down for minutes, should the materializer pause delivery (fail closed, conservative, may stall many clients) or degrade with a cached policy (riskier)? Decide before production.
5. **CDC ingestor placement.** Is the CDC source connection owned by the materializer per-server (one ingestor) or per-session (one ingestor per client, filtered server-side)? Per-server with a fanout is the conventional shape and what the diagram implies.

---

## Cross-references

- `subql.md` — what subql does and doesn't do (the in-process side of the boundary).
- `03-sync-pipeline.md` — the mutation and CDC paths through the materializer.
- `04-subscriptions.md` — subscription registration, bootstrap, and live delivery.
- `05-aggregate-queries.md` — the materialized-aggregate path that this chapter unifies under "trigger executor + install".
- `06-reconnect.md` — the per-session resume cursor and oplog catchup that the materializer serves.
- `08-authorization.md` — the OpenFGA call this chapter's auth filter row depends on.
