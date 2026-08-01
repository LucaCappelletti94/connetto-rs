# 15: Replica retention, eviction, and physical trimming

**Status**: normative. This is the design document referenced as "the retention design" by `docs/upstream-diesel-auto-vacuum-mode.md`, `docs/upstream-diesel-incremental-vacuum.md`, `docs/upstream-diesel-vacuum-into.md`, `docs/upstream-diesel-page-counters.md`, and `docs/upstream-diesel-wal-checkpoint.md`. Nothing in this chapter is built yet. Every normative statement is marked **Decided**, naming its phase in `plans/master-implementation-plan.md`. The trimming mechanisms are blocked on the five upstream diesel proposals landing. Filing them is the first action of R15.

---

## Not the server-side oplog

The word "retention" also appears in `docs/architecture/06-reconnect.md`, where it names the server-side oplog ring buffer: 72 hours or one million entries, managed entirely by connetto-server, that determines how far a client can fall behind before it must re-sync. That is a Postgres table the client never touches.

This chapter is about the client-side replica, a SQLite file that holds a local copy of subscribed query results, and the mechanisms that keep it from growing without bound.

---

## Why the replica grows

**Decided (R15).** The replica holds the union of every subscribed query result the client has ever received. It grows because subscriptions widen or accumulate, not because of a leak. A subscription that covers more rows, a new subscription against an additional table, or a time window that advances each day to include another batch of rows: each causes the replica to grow by the rows it adds. No maintenance pass changes the fact that a broadly-subscribed client holds more data than a narrowly-subscribed one.

The primary control on replica size is therefore subscription shape, not deletion. The trimming mechanisms in this chapter reclaim space freed by eviction, but they do not substitute for a subscription design that bounds what the client holds.

---

## What covers a row

**Decided (R29).** Coverage is application-driven through two mechanisms, watches and pins, and through nothing else. There are no schema-declared keep rules and no connetto-side retention policy, because only the application knows why it holds data.

**Watches.** `ConnettoClient::watch` in `crates/connetto-client/src/live.rs` already ties a wire subscription to a handle: identical queries share one reference-counted `WireSub` entry, and dropping the last handle unsubscribes. On top of that, a watch-backed subscription survives its last drop by a grace period, so navigating away and back does not pay a fresh snapshot. The grace defaults to five minutes, is capped at ten, and is per-watch configurable within the cap. The cap is deliberate: wanting to outlive it is by definition a pin, and the cap enforces that boundary mechanically. Precedent, verified at Zero commit `a8b03c7` in `packages/zql/src/query/ttl.ts`: their per-query TTL serves exactly this navigation case, `DEFAULT_TTL` is five minutes, and `clampTTL` clamps every higher value, `forever` included, to `MAX_TTL` of ten minutes with a warning, precisely so the grace cannot become a retention policy.

Across a restart the countdown runs from the recorded stop moment, so a subscription already past its grace ends at launch. A subscription the app died still watching has no recorded stop moment and gets a fresh countdown from launch, giving the UI time to re-claim it as screens mount. The accepted cost is a small asymmetry: a query unwatched moments before a crash is protected for less time than one watched through it.

**Pins.** A pin is a durable, named request to keep a query's rows synced and covered until the application removes it. `pin(name, query)` creates or replaces, `unpin(name)` ends, and pins are listable. The application chooses the name, so startup pinning is idempotent (same name and same query is a no-op) and re-pinning a changed query under the same name is the upgrade path. Collisions between application features are the application's responsibility. A pin has no clock and no handle: it survives closing and reopening the app, and it survives offline.

Durability is not optional for the offline case. `attach_wire` in `crates/connetto-client/src/live.rs` sends the `Subscribe` frame inline, so `watch` on a synced table fails while the transport is down. An application restarting offline cannot re-establish any watch, and only a persisted record keeps its rows covered until connectivity returns. This is the case that motivated the pin: a dataset downloaded deliberately before going offline, cleared explicitly after coming back.

**Notifications need neither mechanism.** A watch handle is not tied to a page: the application can hold one at application scope, or observe the raw event stream through `ConnettoClient::events`, and turn changes into notifications while the process runs, whatever page is mounted. Startup re-declaration means catch-up is already flowing before any page mounts. Waking a dead process is platform push territory, server-side and outside the replica.

---

## Rotating time-windowed subscriptions

**Decided (R15).** A subscription registered with a predicate such as `WHERE created_at > ?` fixes the bound value at registration time. The bound does not advance as time passes. A client that subscribed in January with a 30-day lookback still holds January rows in December unless it replaces the subscription.

Rotation means tearing down the old subscription and opening a new one with a fresh bound. The new bound excludes rows the old bound covered. Those rows receive no delete instruction from the server: the server knows nothing about the client's retention policy and issues no instruction. They become uncovered, meaning no active subscription includes them, which makes them candidates for local eviction.

The client is the only party that can determine when a row is uncovered. A row that falls outside one subscription's new window may still be covered by a second overlapping subscription, may be referenced by a pending local write that has not yet been uploaded, or may be data the user wants kept for a history pane, which the application expresses as a pin or a held watch. Evicting any of those would lose data the user did not choose to discard, so the eviction step is always separate from the rotation step, and coverage is owned by the application through watches and pins.

---

## Local eviction

**Decided (R15).** Eviction removes from the replica any row that no active subscription covers, where active means a watch-backed subscription still within its grace or a pin. The client determines this by scanning its active subscription set against the local rows.

**Decided (R15).** The pass runs by itself when a subscription ends, that is when a watch's grace expires or the application unpins, and is scoped to the tables that subscription read. A callable tidy pass exists besides, for a free-up-space affordance. Automatic won over app-only triggering because retention exists to bound the replica by default, and the application already expressed its intent by letting the subscription end. The stated cost: deletes run at moments the application did not schedule, though only ever on uncovered rows.

Eviction must run with the capture session suspended. `SuspendedCapture` in `crates/connetto-client/src/lib.rs` is the existing mechanism, used when server patches apply so that server-originated writes are never re-uploaded. A captured eviction delete would be uploaded as a real client mutation and applied to the Postgres backend, discarding server data the user did not ask to delete.

**Built.** Local-tier rows are structurally safe from eviction. The constraint recorded in `docs/architecture/open-questions.md` at decision Q10.7 is that no `SubscriptionSpec` can ever carry a frontend-tier table. Eviction works by checking which rows remain covered by some active `SubscriptionSpec`. Since `SubscriptionSpec` cannot reference the frontend tier, the eviction scan has no path to a frontend row. Device-local data survives a retention pass by placement rather than by a runtime guard, because the FK closure rule that enforces the tier boundary at generation time also forecloses cascade paths into the tier.

**Decided: coverage is recomputed from the subscriptions themselves, and never stored per row.** The client persists its subscriptions in the never-synced tier and derives what is covered by running their queries against the replica. It stores no association between a row and the subscription that brought it.

This is possible because the client already holds, per subscription, the **SQLite-dialect** query text and its bind values (`ConnettoSession::subscribe_spec`), so a subscription is directly runnable against the replica. Storing the association instead was rejected on two grounds: a record per row per covering subscription is more storage than the data itself on a narrow table, which is self-defeating in a feature meant to shrink the replica, and it would need reference counting, which fails in both directions (a leaked count pins rows forever, a lost count deletes live data).

**Overlap falls out for free, which is the property that matters.** Every subscription is a predicate over one table, so the surviving predicates `OR` together and eviction deletes the complement:

```sql
DELETE FROM orders
WHERE NOT ( (<predicate of surviving subscription B>) OR (<predicate of surviving subscription C>) );
```

Dropping a subscription never names it. It stops contributing a clause. A row another subscription still wants matches that clause and survives, and with no surviving subscription on the table the clause list is empty and the statement degenerates to `DELETE FROM orders`.

**The schema is normalised so a shared query is stored once.** Three tables in the never-synced tier: the query text keyed by its own id and unique on the text, the subscription carrying its id and a reference to that query, and the bind values keyed by subscription and position. Two subscriptions differing only in a bind value therefore share one row of query text.

**This also fixes two things that are not about retention.** The same statement replaces `clear_subscription_rows`, which today issues `DELETE FROM "{table}"` per table the subscription reads, so a resync of one subscription wipes a sibling's rows over the same table. And persisting the set replaces the in-memory, best-effort `sub_tables`, which records nothing at all for a query it cannot parse and does not survive a restart. Phase R29.

### The one case predicates cannot answer

**A row-by-row coverage test is wrong for deletions, and the wire has to close the gap.**

Worked through, because the conclusion alone does not read clearly. Table `orders`, one client, two subscriptions: **A** is `status = 'open'` and **B** is `customer = 42`. Row 7 is open and belongs to customer 42, so both want it, and there is **one** copy of it in the replica.

Two different things can happen and **both arrive as the same frame**, a delete for row 7 addressed to A.

- **The row is deleted in Postgres.** It leaves both subscriptions, so the server sends a delete to A and a delete to B.
- **Its status changes to closed.** It leaves A only, so the server sends a delete to A and an ordinary update to B, which still wants it.

Now apply the naive rule, which is to check whether another subscription's predicate still matches before deleting locally. In the second case it is right: `customer = 42` still matches, the row stays, and B keeps what it is entitled to.

In the first case it fails, and it fails twice. A's delete arrives, B's predicate is checked against the row still sitting in the replica, `customer = 42` matches, so the row is kept. Then B's delete arrives, A's predicate is checked against that same untouched row, `status = 'open'` matches, so it is kept again. **Each delete is vetoed by a subscription that is itself being deleted.** Nothing removes the row, and nothing later will, because upstream it no longer exists and will never change again.

| | Row deleted upstream | Row leaves A, B still wants it |
|---|---|---|
| Today | correctly removed | **wrongly removed**, B silently loses it |
| Naive predicate check | **never removed** | correctly kept |
| With the wire distinction | correctly removed | correctly kept |

So today's defect is over-deletion, the naive fix trades it for under-deletion, and only separating the two cases is correct in both directions.

A deletion and a departure from a subscription's window are indistinguishable on the wire today, and the predicate cannot separate them because it is evaluated against a row that is leaving either way. **The delete must therefore carry which it is.** A removed row applies unconditionally. A row that merely left this subscription's window applies only when no surviving predicate matches it. This is a protocol addition and it is free: nothing is published, and `PROTOCOL_VERSION` takes one deliberate bump at the first release.

**Two costs, stated rather than buried.** Recomputation does real work when tidying, one pass per surviving subscription over the affected table, where a stored association would have the answer ready. And a subscription carrying pagination (`LIMIT`, its `OFFSET`, `FETCH`) does not recompute to the set it was delivered, since pagination is already an approximation applied to the snapshot only (`04-subscriptions.md`). **Decided (R29):** such a subscription contributes its predicate with the pagination stripped to the coverage union while it lives, protecting a superset of what it delivered, which can only keep too much, and it dies like any other, so its rows become evictable when it ends and the accumulation is bounded by its lifetime. Pagination is the whole class needing this rule: joins, subqueries and set operations are rejected at registration, aggregate shapes hold no replica rows to evict, and `ORDER BY` or a projection changes no row membership.

---

## Physical trimming

### Eviction leaves free pages

**Decided (R15).** SQLite deletion does not shrink the file. Freed pages go onto the freelist and are available for reuse by future inserts, but the file is not truncated. A bulk eviction that removes a large time window produces a freelist of the same size and the file occupies the same disk space as before. Physical trimming returns those pages to the filesystem.

### The auto_vacuum mode

**Decided (R15).** The `INCREMENTAL` auto-vacuum mode keeps freelist bookkeeping up to date at every commit without reclaiming pages at commit time. `FULL` mode reclaims pages at every commit, which would stall the pump on every server patch. `INCREMENTAL` defers reclamation to an explicit `PRAGMA incremental_vacuum` call, which the trimming pass controls.

The critical constraint, documented in `docs/upstream-diesel-auto-vacuum-mode.md` and verified on SQLite 3.51.1: `auto_vacuum` is stored in the file, not the connection. Changing from `NONE` on a populated database silently does nothing until a full `VACUUM` rewrites the entire file. The mode must be set before the first table exists.

This constraint has no urgency today. The workspace is at `version = "0.0.0"`, unpublished, with no deployment, so no user file exists to foreclose. It becomes irreversible at the first release, which is the actual deadline.

### The trimming pass

**Decided (R15).** The trimming pass runs after each eviction. The five upstream proposals carry verified SQLite facts, version floors, and traps. They are the specification for each mechanism. This chapter records only the policy that drives them.

1. Read `freelist_count` and `page_count` via helpers proposed in `docs/upstream-diesel-page-counters.md`. If the ratio of free pages to total pages is below a threshold, skip the pass. Triggering on ratio rather than a schedule avoids reclaiming a file that has no slack.

2. Run bounded `incremental_vacuum` via the helper proposed in `docs/upstream-diesel-incremental-vacuum.md`. The page-limit parameter is a latency control: a large freelist does not stall the pump in a single step. The proposal pins the drive-to-completion behavior: the underlying pragma frees one page per step, and a consumer that does not drive every result row to completion silently reclaims only one page regardless of what it passed.

3. Run `wal_checkpoint(None, WalCheckpointMode::Truncate)` via the helper proposed in `docs/upstream-diesel-wal-checkpoint.md`. Pages reclaimed by `incremental_vacuum` could otherwise reappear inside a grown WAL file, leaving the file occupying the same space at the filesystem level. The `Truncate` mode moves WAL frames into the database file and shrinks the WAL file to zero bytes.

4. Inspect `WalCheckpointOutcome.busy`. A checkpoint blocked by an open reader reports the blockage through the `busy` field and does not fail. The pass records that it did not complete fully and defers to the next maintenance window rather than retrying in a tight loop.

### When the mode is NONE

**Decided (R15).** A replica opened on a file created before R15 may have `auto_vacuum = NONE`. The `auto_vacuum` helper proposed in `docs/upstream-diesel-auto-vacuum-mode.md` lets the trimming pass read the mode defensively before running, so it can detect this case rather than issuing `incremental_vacuum` against a file that cannot shrink incrementally. If the mode is `NONE` and a full compaction is requested, `vacuum` or `vacuum_into` (proposed in `docs/upstream-diesel-vacuum-into.md`) can rewrite the file. `vacuum_into` writes a compacted copy to a new path without modifying the source, which suits an offline background operation whose output the caller then swaps in.

---

## The create path

**Decided (R15).** The five upstream proposals state that "the replica templates bake `auto_vacuum = INCREMENTAL` at build time." That claim is stale. There is no replica template. `Replica::PlaintextFile` and `connect_with_plaintext_template` were deleted in phase E5 (recorded in `docs/roadmap.md` under "Replica encryption at rest"). Neither symbol exists in `crates/connetto-client/src/replica.rs` or `crates/connetto-client/src/lib.rs`. Baked templates survive only for the local tier's first boot, which is a different SQLite file. connetto creates the replica through `connect_inner` in `crates/connetto-client/src/lib.rs`.

**Built.** The existing pragma sequence in `connect_inner`, documented in `docs/architecture/14-at-rest-encryption.md`, is:

1. `cipher::unlock` (the key pragma, must be the first SQL statement on any encrypted connection)
2. `PRAGMA journal_mode=WAL`
3. `SqlFunctions` installation
4. Application DDL (`sqlite_ddl`)
5. `META_DDL` (connetto's `_connetto_meta` and `_connetto_pending` tables)

**Decided (R15).** `PRAGMA auto_vacuum = INCREMENTAL` joins this sequence after step 2 and before step 4. After step 2 because the key pragma in step 1 must precede any statement that reads the database header, and WAL is established immediately after it. Before step 4 because both the application DDL and `META_DDL` create tables, and the mode must precede the first `CREATE TABLE`. On the `connect_existing` path the database already has its schema and the mode is already stored in the file from the original create, so the pragma applies only on the `connect` path.

Chapter 14 is the authoritative source for the unlock ordering constraint. This chapter records only that `auto_vacuum` joins that sequence and where it lands relative to the DDL steps.

---

## Browser constraints

**Decided (R15).** OPFS quota is the scarce resource in the browser. A replica that grows large faces a higher eviction risk under storage pressure. Physical trimming is therefore more consequential in the browser than natively.

A full `VACUUM` rewrite is expensive in the browser. As `docs/upstream-diesel-vacuum-into.md` documents, it requires up to twice the file size in temporary space and must complete before a new write can land. Bounded `incremental_vacuum` is the appropriate tool for foreground maintenance: it reclaims a configurable number of pages per call and does not block the pump.

**Built.** `sqlite-wasm-rs` allows one connection per database, as recorded in `docs/architecture/14-at-rest-encryption.md`. The sahpool VFS keys its open-file bookkeeping by filename, and a second live connection to the same OPFS file trips a `debug_assert` inside it. The trimming pass must run on the existing replica connection and cannot open a side connection to the same file.

`vacuum_into` is the natural candidate for a full offline compaction in the browser, since it writes to a new path rather than modifying the source. Whether OPFS permits an atomic rename or swap to bring the compacted file into service in place of the original is an open question.

---

## Upstream dependency

All five mechanisms that implement this design are proposed in `docs/` but not yet filed. Filing them is the first action of R15 and everything else is blocked on them landing. Each proposal is deliberately small and self-contained so it reviews quickly.

| Proposal | Mechanism |
|---|---|
| `docs/upstream-diesel-auto-vacuum-mode.md` | `SqliteConnection::set_auto_vacuum`, `SqliteConnection::auto_vacuum`, `AutoVacuumMode` |
| `docs/upstream-diesel-page-counters.md` | `SqliteConnection::page_count`, `SqliteConnection::freelist_count` |
| `docs/upstream-diesel-incremental-vacuum.md` | `SqliteConnection::incremental_vacuum` |
| `docs/upstream-diesel-wal-checkpoint.md` | `SqliteConnection::wal_checkpoint`, `WalCheckpointMode`, `WalCheckpointOutcome` |
| `docs/upstream-diesel-vacuum-into.md` | `SqliteConnection::vacuum`, `SqliteConnection::vacuum_into` |

---

## Open questions

Two questions are genuinely unresolved. First, how eviction interacts with pending local writes that reference rows whose subscription window has moved. The `docs/roadmap.md` entry defers code until that design is complete. Second, whether OPFS provides an atomic path for swapping a `vacuum_into`-produced file into service in place of the original, which determines whether full compaction is practical in the browser. A third question, per-table retention declarations in the synql schema, was resolved by rejection: coverage comes from watches and pins alone, so there is nothing for a schema declaration to add (see What covers a row).
