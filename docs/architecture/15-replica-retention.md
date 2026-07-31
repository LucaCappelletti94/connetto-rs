# 15: Replica retention, eviction, and physical trimming

**Status**: normative. This is the design document referenced as "the retention design" by `docs/upstream-diesel-auto-vacuum-mode.md`, `docs/upstream-diesel-incremental-vacuum.md`, `docs/upstream-diesel-vacuum-into.md`, `docs/upstream-diesel-page-counters.md`, and `docs/upstream-diesel-wal-checkpoint.md`. Nothing in this chapter is built yet. Every normative statement is marked **Decided (R15)**, naming phase R15 in `plans/master-implementation-plan.md`. All mechanisms are blocked on the five upstream diesel proposals landing. Filing them is the first action of R15.

---

## Not the server-side oplog

The word "retention" also appears in `docs/architecture/06-reconnect.md`, where it names the server-side oplog ring buffer: 72 hours or one million entries, managed entirely by connetto-server, that determines how far a client can fall behind before it must re-sync. That is a Postgres table the client never touches.

This chapter is about the client-side replica, a SQLite file that holds a local copy of subscribed query results, and the mechanisms that keep it from growing without bound.

---

## Why the replica grows

**Decided (R15).** The replica holds the union of every subscribed query result the client has ever received. It grows because subscriptions widen or accumulate, not because of a leak. A subscription that covers more rows, a new subscription against an additional table, or a time window that advances each day to include another batch of rows: each causes the replica to grow by the rows it adds. No maintenance pass changes the fact that a broadly-subscribed client holds more data than a narrowly-subscribed one.

The primary control on replica size is therefore subscription shape, not deletion. The trimming mechanisms in this chapter reclaim space freed by eviction, but they do not substitute for a subscription design that bounds what the client holds.

---

## Rotating time-windowed subscriptions

**Decided (R15).** A subscription registered with a predicate such as `WHERE created_at > ?` fixes the bound value at registration time. The bound does not advance as time passes. A client that subscribed in January with a 30-day lookback still holds January rows in December unless it replaces the subscription.

Rotation means tearing down the old subscription and opening a new one with a fresh bound. The new bound excludes rows the old bound covered. Those rows receive no delete instruction from the server: the server knows nothing about the client's retention policy and issues no instruction. They become uncovered, meaning no active subscription includes them, which makes them candidates for local eviction.

The client is the only party that can determine when a row is uncovered. A row that falls outside one subscription's new window may still be covered by a second overlapping subscription, may be referenced by a pending local write that has not yet been uploaded, or may be data the user wants to view in a history pane. Evicting any of those cases would lose data the user did not choose to discard, so the eviction step is always separate from the rotation step and the client owns the decision.

---

## Local eviction

**Decided (R15).** Eviction removes from the replica any row that no active subscription covers. The client determines this by scanning its active subscription set against the local rows.

Eviction must run with the capture session suspended. `SuspendedCapture` in `crates/connetto-client/src/lib.rs` is the existing mechanism, used when server patches apply so that server-originated writes are never re-uploaded. A captured eviction delete would be uploaded as a real client mutation and applied to the Postgres backend, discarding server data the user did not ask to delete.

**Built.** Local-tier rows are structurally safe from eviction. The constraint recorded in `docs/architecture/open-questions.md` at decision Q10.7 is that no `SubscriptionSpec` can ever carry a frontend-tier table. Eviction works by checking which rows remain covered by some active `SubscriptionSpec`. Since `SubscriptionSpec` cannot reference the frontend tier, the eviction scan has no path to a frontend row. Device-local data survives a retention pass by placement rather than by a runtime guard, because the FK closure rule that enforces the tier boundary at generation time also forecloses cascade paths into the tier.

The interplay between eviction, per-table retention declarations in the synql schema, and pending local writes that reference rows whose subscription window has moved is not yet fully designed. The `docs/roadmap.md` entry for this work defers code until that design is settled.

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

Two questions are genuinely unresolved. First, how eviction interacts with per-table retention declarations in the synql schema and with pending local writes that reference rows whose subscription window has moved. The `docs/roadmap.md` entry defers code until that design is complete. Second, whether OPFS provides an atomic path for swapping a `vacuum_into`-produced file into service in place of the original, which determines whether full compaction is practical in the browser.
