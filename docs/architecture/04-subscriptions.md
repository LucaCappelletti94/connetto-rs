# 04: Subscriptions

**Status**: draft

---

## Purpose

Define how clients express interest in data: the lifecycle of a subscription from creation through update to cancellation, and how the server manages the active subscription set.

Aggregate subscriptions are a distinct enough topic to have their own file (`05-aggregate-queries.md`). This file covers row-level SELECT subscriptions.

---

## What Is a Subscription?

A subscription is a standing query: the client says "give me all rows matching this predicate and keep me updated as they change."

A subscription has:

- A **subscription ID** (`sub_id`): a client-chosen string, unique within the session, used to correlate snapshot and update messages.
- A **spec** (`SubscriptionSpec`): describes what data the client wants.
- A **resume cursor**: the server LSN at which the client last received an update for this subscription.

---

## SubscriptionSpec

The spec describes the query the client wants to observe. The shipped shape (`SubscriptionSpec` in `crates/connetto-core/src/messages/subscription.rs`) is:

```
SubscriptionSpec {
  priority: SubscriptionPriority,  // delivery tier
  query:    String,                // full SELECT in the client's SQLite dialect
  binds:    Vec<BindValue>,        // values for the ? placeholders, in order
}
```

An earlier sketch here showed `table`, `filter`, `columns`, `order_by`, and `limit` as struct fields. That shape predates Q4.1: the table and the filter became the SQL text itself, column projection is deferred by Q4.5, and ordering or pagination (`LIMIT` with any `OFFSET`) ride inside `query`, where pagination shapes the snapshot only and live updates ignore it (see the design note at the end of this chapter).

### Predicate

A `Predicate` is a tree of conditions:

```
Predicate =
  | Eq(column, value)
  | Ne(column, value)
  | Lt(column, value)
  | Gt(column, value)
  | Le(column, value)
  | Ge(column, value)
  | In(column, [value])
  | And([Predicate])
  | Or([Predicate])
  | Not(Predicate)
```

Predicates are restricted to column comparisons against literal values: no subqueries, no cross-table joins in the predicate itself. This constraint makes server-side subscription matching feasible without issuing a SQL query per CDC event for simple cases.

**The tree above is superseded by Q4.1 below.** The subscription language is SQL `WHERE` clause text, parsed by `subql`, which accepts `=`, `!=`, `<`, `>`, `IN`, `BETWEEN`, `LIKE`, `ILIKE`, `IS NULL`, `AND`, `OR`, `NOT` and arithmetic, and rejects anything else at registration. The tree is retained as a statement of the intended expressiveness. What matters for the section below is that the restriction to literals is unchanged, and that the language is owned upstream.

### Cross-table and join subscriptions

**Researched from primary sources.** This section previously declined joins in two sentences and offered "one subscription per table, join locally in SQLite" as the workaround. That workaround answers half the question, and the half it leaves out is already answered elsewhere in this architecture without this chapter saying so. Seven systems were read at pinned commits: PowerSync, ElectricSQL, Zero, Convex, Supabase realtime and walrus, Phoenix, and Materialize.

**"Support joins" is two capabilities, and no system treats them as one.**

A **join as output shape** puts columns from two tables in one result row. A client holding both tables can do this itself, so local SQLite genuinely solves it. This is what the old workaround addressed.

A **join as membership predicate** decides which rows of the second table the client receives at all, based on a relationship to a row in the first: the line items of my orders, the documents in the workspaces I belong to. **A client cannot solve this locally, because it would have to already hold the rows in order to decide whether it should hold them.**

**Only two of the seven support the output-shape join, and six of the seven still provide a membership mechanism.** PowerSync rejects with `Must SELECT from a single table` on the legacy data-query path and `Sync streams can only select from a single table` in the current compiler, then supplies membership through a second query language whose parameter queries populate a bucket index. Electric rejects with `Expected a single table reference`, then supplies membership through `IN (SELECT ...)` tracked as a shape dependency with incremental move-in and move-out. Supabase accepts thirteen filter operators over one table against literals, then lets row-level security decide actual visibility. Convex dissolves the distinction by subscribing to a function's read set, and pays for it with hard caps of 32000 documents, 16 MiB, and 4096 index intervals per transaction. Only Zero and Materialize support the output-shape join outright, both by maintaining materialized state per query. Only Phoenix has no membership mechanism, because it has no data model to attach one to.

**The single-table boundary is therefore correct and stays.** What was missing is the statement of where membership comes from.

### Where membership comes from here

**It comes from row-level security, exactly as in Supabase.** The snapshot query runs with `app.user_id` bound on a pool subject to RLS, and change-time delivery is authorized per row (`08-authorization.md`). A policy is arbitrary SQL and may contain a subquery over another table, so "the line items of my orders" is already expressible today, as a policy rather than as a subscription. The predicate above is the equivalent of Supabase's stage one, and the policy is stage two.

### What is still missing

Three things, and only the first is about joins.

**Authorization is not interest.** RLS returns everything the caller may see, whereas a subscription should say what the caller wants now. Those diverge once the authorized set is large, and a client cannot narrow to a related subset unless the discriminating column sits on the subscribed table as a literal. A transitive relationship offers no such literal.

**Revising a predicate costs a full re-snapshot.** There is no in-place modify, by the lifecycle section below. A client can work around a transitive relationship by computing the parent keys itself and passing them as an `IN` list of literals, which the language allows, but that set goes stale whenever the parent set changes. **Adding one order re-snapshots the line items of every order.** This is the reason the gap is not cosmetic.

**There is no incremental move-out.** Every peer has one: `removed_buckets` in PowerSync, the subquery index in Electric, per-change policy re-evaluation in Supabase, read-set invalidation in Convex. The equivalent here is `FullResyncRequired` per subscription, decided in `08-authorization.md` for grant changes. It is complete by construction, and it is the coarsest option in the set.

**Decided: add a membership term to the subscription language, after R5b and R6.** Its right side names a relationship or a single-table subquery rather than a literal, and it intersects with RLS rather than replacing it. Four systems sharing no implementation converged on this shape, which is the strongest evidence available. It is sequenced after R5b and R6 because the incremental move-in and move-out that makes it worth having is the same machinery as change-time visibility transitions, and building it earlier would deliver the expressiveness while resyncing on every dependency change.

**This lands upstream, not here.** The subscription language belongs to `subql` by Q4.1, so a subquery term is a `subql` capability and the dependency tracking that keeps it current is `subql` machinery. Electric's shape maps onto this almost exactly, since its mechanism is a subquery inside a `WHERE` clause and that is already the input format. The connetto-side work is confined to whatever the wire protocol must carry.

**Decided: the membership term is written once as SQL and evaluated by two executors, exactly as policy already is.** The subquery runs against Postgres for the snapshot, and the compiled relationships answer the per-row question on the change path. This is not a new pattern, it is the split `08-authorization.md` already establishes, adopted for the same reason: a set question ("give me every matching row") suits the database, and a point question ("does this one row match") asked once per changed row per subscriber does not.

The two alternatives are both foreclosed by decisions already in place. Evaluating the subquery per changed row rebuilds the per-row database round trip that R5b exists to remove, in the same loop. Compiling it away entirely cannot serve the snapshot, because enumerating everything a subject may see is capped at `listObjectsMaxResults` 1000 and `listObjectsDeadline` 3 seconds and a truncated snapshot does not announce itself, which is why the snapshot stays on RLS permanently.

**What this costs, stated plainly: a second pair of evaluators that must not diverge.** That risk is already accepted for policy, and it is accepted here for the same reason, that one source compiles to both. It is what makes the compilation load-bearing rather than convenient, and it doubles the surface over which that holds. The failure it produces is a row present in the snapshot and then withdrawn on the first change, or never delivered at all.

**Two consequences follow.** The term must be compilable, so it is bounded by what `rls2fga` can classify, currently thirteen canonical patterns, and a term outside them is refused at registration rather than silently evaluated one way only. And the query set must be known ahead of time for the compilation to happen at all, so **R27 has to establish that for itself**, deriving it from the queries the application already wrote. This was once a dependency on a separate phase that fixed the accepted query set at compile time. That phase is deleted: a curated set of permitted queries is refused on principle, because what a caller may not do is decided by row-level security, by OpenFGA and by roles, never by whether a request appears on a maintained list. The compilation bound is a property of the term, not a permission list.

---

## Subscription Lifecycle

### Registration

Client sends:

```
Subscribe {
  sub_id:  String,
  spec:    SubscriptionSpec,
}
```

Server:

1. Validates the spec (table exists, client has read permission, predicate is well-formed).
2. Records the subscription in the registry: `(session_id, sub_id) → (spec, principal, lsn=None)`.
3. Begins snapshot delivery (see below).

On any failure, before or after registration, the server sends one `Error` frame whose `detail` is the fixed refusal text and does not add the subscription. The cause never reaches the wire and goes to the structured log instead (R38): a detail or a frame sequence that varied with the cause told a caller which stage refused, and so whether the table or column it guessed exists.

### Snapshot delivery

After registration, the server delivers an initial snapshot. `SnapshotBegin { sub_id }` and `SnapshotEnd { sub_id, lsn: u64 }` are control-plane frames that bracket the snapshot. The row data travels on the bulk plane as one or more `SnapshotPatch` frames, each carrying `sub_id` and `patchset_zstd` (a Zstd-compressed SQLite patchset).

The snapshot is read after the route is installed, so live delivery runs throughout it. A change committed while the snapshot is in flight reaches the client as a `LivePatch` queued behind `SnapshotEnd`, which is what keeps it from being lost. Installing the route afterwards dropped every such change silently, which was phase R28 part A. Since R38 no frame goes out until that read has succeeded, so a subscription failing at the snapshot refuses as bare as one refused at registration.

**The overlap is re-applied, not filtered. Decided (R28 part A, 2026-08-03), and this paragraph replaces one that said any `LivePatch` at or below the snapshot's LSN is discarded.** Such a filter looks obvious and loses data. The `lsn` in `SnapshotEnd` is `pg_current_wal_lsn()` read after the rows inside a `REPEATABLE READ` transaction, and a `LivePatch` carries the WAL position of the change record. Neither number orders by visibility: a writer that starts before the snapshot and commits after it produces a change whose position is below the snapshot's, while the snapshot cannot contain its row. Measured on Postgres 16: two writers, the snapshot saw only the committed one and reported `0/151BA18`, and the other writer's row arrived at `0/151B868`. Discarding it would have deleted a row permanently, which is the defect R28 exists to remove.

Re-application is safe instead, and needs nothing on the client. Patches arrive in commit order, so for any row the last patch applied carries that row's current value, and the replica settles on the same state whether or not the snapshot already held it. The cost is that a row can briefly show an older value between `SnapshotEnd` and the end of the overlap, and that the resume cursor moves backwards for that moment, which replays rather than loses. Making the filter correct would need the change stream to report each change's commit position and the snapshot to be paired with a matching consistent point through a replication slot, which buys only the removal of that flicker.

**The client does not buffer updates during snapshot delivery, and it does not need to. Decided (R28 part A), and this paragraph replaces one that said it did.** Ordering is guaranteed by the shape of the server's run loop rather than by anything on the client: that loop is a single two-armed `tokio::select!`, and the code delivering the snapshot is awaited inside the arm that reads from the transport, so the arm draining outbound live patches is not polled meanwhile. Overlapping patches therefore queue in memory and reach the wire only after `SnapshotEnd`, in order. A client cannot observe a `LivePatch` for a subscription before that subscription's `SnapshotEnd`, so a buffer would never fill.

**That guarantee is structural, so it is worth knowing what would break it.** Moving the snapshot send onto its own task, or splitting the two select arms across tasks, would let a live patch overtake the snapshot with no test failing. The loop carries a comment saying so, because the alternative is a silent dependency.

### Ongoing updates

After `SnapshotEnd`, the server delivers incremental updates via `LivePatch` bulk frames as the underlying data changes. See `03-sync-pipeline.md` for the CDC fanout path.

### Cancellation

Client sends:

```
Unsubscribe { sub_id }
```

Server removes the subscription from the registry. No further updates are delivered for this `sub_id`.

The client may delete the locally cached data for this subscription, or retain it for offline use: application's choice.

### Update (modify a subscription)

There is no in-place "modify subscription" message. To change a subscription:

1. Client sends `Unsubscribe(sub_id)`.
2. Client sends `Subscribe(sub_id, new_spec)`.

This triggers a new snapshot. The client may choose to retain the old local data until the new snapshot arrives to avoid a blank state.

---

## Server Subscription Registry

The registry maps `(session_id, sub_id)` to:

```
SubscriptionEntry {
  spec:         SubscriptionSpec,
  principal:    Principal,         // optional identity plus resolved capabilities
  last_lsn:     Option<u64>,    // None until SnapshotEnd is sent
  snapshot_lsn: Option<u64>,    // LSN at which snapshot was taken
}
```

**Decided (R3).** The caller may have no identity at all. See `12-identity-session-capability.md`.

The registry is in-memory (session lifetime). It is not persisted server-side, and on reconnect the client re-declares all subscriptions. Across a client restart the same re-declaration comes from the client's own persisted subscription set, pins always and watch-backed entries still within their grace (`15-replica-retention.md` under "What covers a row", phase R29).

---

## Matching CDC Events to Subscriptions

The fanout engine indexes subscriptions by table name. When a `ChangeRecord` arrives for table `T`:

1. Fetch all subscription entries for table `T` across all sessions.
2. For each entry, evaluate the subscription predicate against the changed row.
3. For subscriptions where the predicate matches (either `old_row` or `new_row`, or both), proceed to auth filter.

### Predicate evaluation on CDC events

For each CDC event:

- If `op = Insert`: evaluate predicate against `new_row`. If matches → deliver as insert.
- If `op = Delete`: evaluate predicate against `old_row`. If matches → deliver as delete.
- If `op = Update`:
  - Evaluate predicate against `old_row` and `new_row` separately.
  - `old matches, new matches` → deliver as update.
  - `old matches, new does not` → deliver as delete (row left the result set).
  - `old does not, new matches` → deliver as insert (row entered the result set).
  - `old does not, new does not` → no delivery needed.

**The two deletes above are different events and the wire must distinguish them. Decided (R29).** The `op = Delete` case removes a row that no longer exists. The `old matches, new does not` case removes a row that still exists and merely left this subscription's window. Today both arrive as a delete and the client cannot tell them apart. The marker is the patchset op's own session-format indirect flag, set on synthesized departure deletes, so no frame or format changes (`15-replica-retention.md`, The one case predicates cannot answer).

That is safe only while one subscription owns a table. With two subscriptions over one table it is not, because patches from both apply into the same replica table, so a row leaving the first one's window deletes it out from under the second, which still covers it. Nor can the client repair this by checking the other predicates itself: on a genuine deletion the server sends a delete to every covering subscription, each is held back by the others still matching the stale local row, and the row is never removed at all.

So a delete carries which of the two it is. A removed row applies unconditionally. A row that left a window applies only when no surviving subscription's predicate still matches it. Free to add, since nothing is published and `PROTOCOL_VERSION` takes one deliberate bump at the first release.

This ensures clients maintain correct result sets even when rows move in and out of filter bounds.

---

## Re-subscribe on Reconnect

After reconnect, the client re-sends all `Subscribe` messages. The server treats each as a fresh subscription.

If the client's last known LSN for a subscription is still within the server's oplog window:

- The server can deliver a catchup patch (changes since that LSN) instead of a full snapshot.
- This optimization avoids re-sending the full snapshot for subscriptions where little has changed.

If the LSN is outside the window, or if the server does not support catchup patches: full snapshot re-delivery.

*(See `06-reconnect.md` for the full reconnect flow.)*

---

## Open Questions

1. ~~**Predicate language scope**: is the current predicate tree sufficient, or do clients need more expressive filters (e.g. LIKE, IS NULL, array containment)? More expressiveness makes server-side in-process evaluation harder.~~ **Decided (Q4.1):** connetto accepts SQL WHERE clause text directly, matching `subql`'s input format. The custom predicate tree is superseded. `subql` supports `=`, `!=`, `<`, `>`, `IN`, `BETWEEN`, `LIKE`, `ILIKE`, `IS NULL`, `AND`, `OR`, `NOT`, and arithmetic, rejecting unsupported constructs at registration time.
2. ~~**Subscription count limits**: should the server enforce a maximum number of subscriptions per session? What happens when the limit is hit?~~ **Decided (Q4.2):** Not a connetto concern. Subscription registry memory management is owned by `subql` (`subql.md`, "Subscription registry limits (Q4.2)"). connetto imposes no limits of its own.
3. ~~**Snapshot parallelism**: should the server deliver snapshots for multiple subscriptions concurrently, or serially? Concurrency helps latency but increases server load.~~ **Decided (Q4.3):** Priority-tiered delivery. Higher-priority tiers complete before lower-priority tiers begin. Within a tier, subscriptions are delivered concurrently, interleaved on the WebSocket and tagged by `sub_id` (the PowerSync model).
4. ~~**Catchup patch optimization**: is the "deliver catchup patch instead of full snapshot on reconnect" optimization in scope for v1?~~ **Decided (Q4.4):** Yes, in scope. On reconnect, if the client's LSN falls within the oplog retention window, the server delivers only changes since that LSN rather than a full snapshot.
5. ~~**Column projection**: if a client subscribes with `columns: Some([...])`, does the server track only those columns for matching, or does it always track all columns and project at delivery time?~~ **Decided (Q4.5):** Deferred. Column projection is an optimization layerable at delivery time. The subscription language is SQL WHERE clauses via `subql`, which operates on full rows, so projection does not affect the core design.

---

## Decisions

- **A subscription names one table, and that boundary stays.** Established from seven systems at pinned commits. Only two allow an output-shape join (Zero, Materialize) and both pay with materialized state per query. Materialize additionally has no parameterized view, so per-viewer incremental maintenance would mean one dataflow per client.
- **Membership comes from row-level security, and this chapter now says so.** The previous workaround, one subscription per table joined locally, answers only the output-shape half. The half a client cannot answer locally was already answered by RLS in `08-authorization.md`, unstated here until now.
- **A membership term is added to the subscription language, after R5b and R6, and it lands in `subql`.** Four independent systems converged on the same shape: keep the subscription single-table and let the predicate name a relationship rather than a value. Sequenced behind the change-time visibility machinery it depends on.
- **The membership term is one written filter with two executors**, the subquery for the snapshot and the compiled relationships for the change path, mirroring the policy split for the same reason. The per-row-query alternative rebuilds the bottleneck R5b removes, and the compile-everything alternative cannot serve a snapshot under the enumeration caps. Cost accepted: a second pair of executors that must agree, and R27 must establish the query set in advance for itself, since compilation needs it and the phase that once promised it is deleted.
- **The set of queries a caller may run is never a maintained list.** No curated allow-list, no enum of permitted requests, no menu anyone keeps up to date. What a caller may not do is decided by row-level security, by OpenFGA and by roles. Knowing the application's queries ahead of time is a compilation requirement and nothing else, and it is satisfied by deriving them from what the application already wrote.

---

## Notes

- Pagination in a subscription query (`LIMIT` and any `OFFSET` riding with it) is an approximation: it applies to the initial snapshot only. As rows are inserted or deleted, the live result set may grow beyond the original window without the server enforcing it. Clients that need a strict top-N should manage this locally.
- The predicate tree is intentionally simple. Complex logic (full-text search, geographic queries) should be handled by materializing a computed column in PostgreSQL that can then be filtered simply. This applies to scalar expressiveness and is unaffected by the membership term above, which adds a relationship rather than a richer scalar comparison.
