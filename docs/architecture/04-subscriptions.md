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

### The membership term (R27, built 2026-08-18)

Three gaps motivated it, and only the first was about joins. Authorization is not interest: RLS returns everything the caller may see, whereas a subscription says what the caller wants now, and the two diverge once the authorized set is large. Revising an `IN` list of parent keys cost a full re-snapshot, so adding one order re-snapshotted the line items of every order. And the only move-out was `FullResyncRequired`, the coarsest option every peer system improves on.

**Built: a subscription's `WHERE` clause narrows through a membership.** The motivating filter is `team_id IN (SELECT team_id FROM team_members WHERE member = current_app_user())`, written in the client's own SQLite dialect. Reverse translation rewrites the caller with the deployment's pairing, the SQLite function `CONNETTO_CALLER_FUNCTION` names against the identity setting, so the subquery reaches Postgres as `current_setting` text the classifier reads. The term is one SQL text with two executors, exactly as policy is: the subquery serves the snapshot on Postgres under row-level security, and `subql`'s compiled term answers the per-row question on the change path. It is seeded at registration (`SessionManager::register_subscription`) from the membership table read as the caller, under the same binding the snapshot uses and inside the same materializer-lock hold as the register, so no dispatch lands between the seed's snapshot and the engine watching. The subscriber is typed at the membership column's own catalog kind, because a mistyped subscriber would admit nobody in silence. A term `rls2fga` cannot classify is refused at registration in R38's fixed shape, bounded by `PatternClass` in `rls2fga`, which is the only correct statement of what classifies. A term whose membership table the publication does not carry is refused the same way, probed live in the seed's own transaction.

**A membership change moves rows, it never resends the subscription.** `subql` reports each move as a narrowing and the server answers it incrementally (`SessionManager::fan_out_moves`). A value entering the set is served by the subscription's own SELECT with `AND <column> = <value>` conjoined, read as the caller so the rest of the filter and the policy still apply. A value leaving it is served by indirect deletes for the keys the change-path executor now denies, read on the privileged pool, because the policy that made them visible is exactly the membership that ended, and sent only when the same event moved a grant reaching the subscribed table, which is what keeps a never-held key undisclosed. The R7 resend yields to the term on exactly the membership tables the term watches, and a failed move escalates through the same ordered replace instruction a moved grant uses rather than skipping. The proof asserts the absence of `FullResyncRequired` in both directions: `crates/connetto-test-harness/tests/membership_term.rs`.

**The server opens a membership subscription on the client's behalf.** The replica needs the caller's own membership rows twice over: the application's query names the membership table locally, and a translated membership policy reads it inside the replica's view, so without those rows the local answer is empty while the server sends the right rows. Registering a term therefore opens one hidden subscription per membership table, labelled `connetto-membership:<table>` and announced with `MembershipOpened` ahead of its own snapshot. It carries the caller's own rows and nothing wider, is counted against R19's allowance before the term is served so a caller at its ceiling is refused as a unit, and is torn down with the last term subscription that needs it. The client keeps its table out of the application-facing changed-tables signal, unconditionally, while the live-query refresh still sees it, which is what re-runs a narrowed query when the membership moves.

**The term intersects the policy, never widening it.** A row the term admits and the policy forbids never arrives, because every move-in is read as the caller and every withdrawal key passes the visibility question. A row the policy admits and the term excludes never arrives, because interest excludes it. Both directions are asserted in the proof above, on a fixture whose policy never reads the membership so the two can disagree.

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

**The bracket is not free of the rows it brackets. Built (R33, 2026-08-09).** `SnapshotEnd` shares the outbound queue with the patches rather than going straight to the socket, so it cannot reach a backlogged client ahead of the data it completes. It costs no credit, it only waits its turn. Before this it went out immediately and a client whose window was shut recorded the resume position that frame carries over an empty replica, so the next attach asked only for what followed rows it never had. Demonstrated first, then fixed, at both the server and the browser relay, which had copied the shape.

The snapshot is read after the route is installed, so live delivery runs throughout it. A change committed while the snapshot is in flight reaches the client as a `LivePatch` queued behind `SnapshotEnd`, which is what keeps it from being lost. Installing the route afterwards dropped every such change silently, which was phase R28 part A. Since R38 no frame goes out until that read has succeeded, so a subscription failing at the snapshot refuses as bare as one refused at registration.

**The overlap is re-applied, not filtered. Decided (R28 part A, 2026-08-03), and this paragraph replaces one that said any `LivePatch` at or below the snapshot's LSN is discarded.** Such a filter looks obvious and loses data. The `lsn` in `SnapshotEnd` is `pg_current_wal_lsn()` read after the rows inside a `REPEATABLE READ` transaction, and a `LivePatch` carries the WAL position of the change record. Neither number orders by visibility: a writer that starts before the snapshot and commits after it produces a change whose position is below the snapshot's, while the snapshot cannot contain its row. Measured on Postgres 16: two writers, the snapshot saw only the committed one and reported `0/151BA18`, and the other writer's row arrived at `0/151B868`. Discarding it would have deleted a row permanently, which is the defect R28 exists to remove.

Re-application is safe instead, and needs nothing on the client. Patches arrive in commit order, so for any row the last patch applied carries that row's current value, and the replica settles on the same state whether or not the snapshot already held it. The cost is that a row can briefly show an older value between `SnapshotEnd` and the end of the overlap, and that the resume cursor moves backwards for that moment, which replays rather than loses. Making the filter correct would need the change stream to report each change's commit position and the snapshot to be paired with a matching consistent point through a replication slot, which buys only the removal of that flicker.

**A snapshot larger than one delivery arrives as several pages. Built (R58, 2026-08-21).** The read is capped at a per-tier byte budget, and a read past it is served in pages ordered by primary key, each resuming past the last row of the one before, never by offset (measured: offset paging costs O(offset) per page). The next page is taken when the client acknowledges the last, so the credit window paces the database reads as well as the wire and the server holds one page at a time. `SnapshotBegin` and `SnapshotEnd` still bracket exactly one read, and the position `SnapshotEnd` carries is the first page's, which can only replay rather than skip. Delivery order carries no promise: the client reads its replica with its own queries, and pagination inside the query text remains a snapshot-shaping device rather than an ordering one. **A `LivePatch` may now arrive between two pages**, which the paragraphs above already cover, because a later page is read after every frame already sent and so can never carry a value older than one the client has applied.

A read the server will not serve is refused rather than truncated: a row above a per-tier ceiling, a table whose typical row is already above it, or a read whose plan needs a sort and runs past its time limit. Every cause is the one fixed refusal on the wire with the cause in the server's log. A read that fails part way through its pages is replaced once, announced as `FullResyncReason::SnapshotInterrupted`, and refused if the replacement fails too.

**The client does not buffer updates during snapshot delivery, and it does not need to. Decided (R28 part A), and this paragraph replaces one that said it did.** Ordering is guaranteed by the shape of the server's run loop rather than by anything on the client: that loop is a single two-armed `tokio::select!`, and the code delivering a page is awaited inside the arm that reads from the transport, so the arm draining outbound live patches is not polled meanwhile. Overlapping patches therefore queue in memory and reach the wire in order. **Corrected by R58:** a client could not observe a `LivePatch` before that subscription's `SnapshotEnd` at all until reads were paged, and now it can, between two pages, because a later page is taken from the acknowledgement rather than inside the first arm's turn. A buffer would still never help, since the ordering that matters is per row and the last patch applied for a row is that row's current value.

**That guarantee is structural, so it is worth knowing what would break it.** Moving the snapshot send onto its own task, or splitting the two select arms across tasks, would let a live patch overtake the snapshot with no test failing. The loop carries a comment saying so, because the alternative is a silent dependency.

**The second structural guarantee is the queue, and it is asserted rather than argued.** `snapshot_order_holds_when_the_credit_window_is_closed` shuts the window by configuration and reads frames in wire order, so a change routing the completion frame around the queue fails a test rather than passing silently.

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

**The two deletes above are different events and the wire distinguishes them. Decided (R29), built by R44 (2026-08-08).** The `op = Delete` case removes a row that no longer exists. The `old matches, new does not` case removes a row that still exists and merely left this subscription's window. The marker is the patchset op's own session-format indirect flag, set on synthesized departure deletes, so no frame or format changed (`15-replica-retention.md`, The one case predicates cannot answer).

**What the server does, since R44.** On an event with departures it encodes a second patchset carrying only the departed rows' table, primary key and `indirect(true)` (`Materializer` in `crates/connetto-server/src/materializer.rs`), identical bytes to every departed subscriber, and splits the consumer list in two rather than fanning out per subscriber. The client applies an indirect delete only when no surviving subscription's predicate still matches the row (`apply_patch` in `crates/connetto-client/src/lib.rs`, predicates from `live::coverage_of`). A direct delete applies unconditionally.

**History, kept because this section went wrong once.** Until 2026-08-08 it read "today both arrive as a delete and the client cannot tell them apart", and that was wrong in a way that mattered: no departure delete was produced at all. The server encoded one patchset per CDC event and sent the identical bytes to every matched consumer, having merged the entered, still-matching and departed lists into one, so a subscriber whose row departed received the update as though the row still matched and the row stayed in that replica for ever. R29 step 4 was written against the delete this section wrongly described and the phase had to be split mid-execution, which is why the departure work is R44.

The distinction is load-bearing once two subscriptions share a table, because patches from both apply into the same replica table. A departure delivered as an unmarked delete would remove a row out from under a sibling subscription that still covers it. Nor can the client repair that by predicate-checking alone: on a genuine deletion the server sends a delete to every covering subscription, each would be held back by the others still matching the stale local row, and the row would never be removed at all. Only the marker is correct in both directions.

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
