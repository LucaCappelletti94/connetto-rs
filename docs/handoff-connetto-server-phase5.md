# Handoff: connetto-server Phase 5 (oplog and reconnect)

Read this first, then `docs/architecture/06-reconnect.md` (normative for this phase), then `docs/plan-connetto-server.md` (the phase list) and `docs/architecture/10-subscription-materializer.md` (the boundary and failure inventory).

## Current state

- Repo `~/github/connetto-rs`, branch `main`, HEAD `366d64e`. No upstream parent, so any authorized PR targets `LucaCappelletti94/connetto-rs` `main`. Working tree clean.
- Phases 0 through 4 are landed and green in `366d64e`: the `connetto-server` crate exists with `auth`, `materializer`, `session`, `snapshot`, and `transport` modules. Write path, Connector-backed snapshot, and re-execution with aggregate delivery all work, verified against SQLite and against real Postgres (three Docker-gated tests pass).
- This session was a side task now fully closed: the integration tests read and seed through typed diesel queries instead of raw SQL, and the `diesel` `future` fork was bumped to `c1aa2e9`, which merged a `table!` macro fix so file-scope `diesel::table!` compiles clean under `missing_docs = forbid` (no private-module wrapper needed). Rationale is recorded in `docs/upstream-diesel-table-macro-missing-docs.md`.

### Toolchain and dependencies

- Workspace `edition = "2024"`, `rust-version = "1.88"`. Workspace lints: `missing_docs = forbid`, `unsafe_code = forbid`, clippy `all = deny` plus `pedantic = warn`, rustdoc link and backtick lints forbid. Every public item needs docs.
- `subql` is a rev-pinned git dep at `2b90db1f5b1b261fdb8604ea45c2de5f19896f00`. The root `Cargo.toml` mirrors subql's `[patch]` blocks (this is load-bearing across workspaces): `diesel` to `LucaCappelletti94/diesel` branch `future` (now `c1aa2e9` in the lock), `sqlparser` and `sqlparser_derive` to `LucaCappelletti94/sqlparser-rs` rev `306abb56`, `pg_walstream` to `LucaCappelletti94/pg-walstream` branch `feat/pgoutput-decoder`. `sqlite-diff-rs` is `0.7.0`.
- The `pg-async` feature turns on the real-Postgres paths: `diesel-async/postgres`, `diesel-async/bb8`, `diesel/postgres_backend`, `diesel/serde_json`, `subql/apply-patchset-postgres-async`, `subql/executor-diesel-async-postgres`. It is off by default.

## Phase 5 goal (from 06-reconnect.md)

Give a reconnecting client the changes it missed without a full re-sync when possible, and fall back to a full snapshot when not.

1. An oplog: a retention-bounded, LSN-keyed, ordered log of change records, with deletes retained as tombstones so they replay.
2. The catchup-versus-`FullResyncRequired` decision: compare the client's resume cursor against the oplog's retained window, replay the gap when the cursor is inside the window, or signal a full re-sync and re-snapshot when it is outside.
3. Wire both into the session run loop so a reconnect either streams the missed ops or triggers a fresh snapshot.

## The one fact that makes this tractable: the cursor is the LSN

In `materializer.rs` (around line 455) `dispatch` builds every outbound cursor as `event.checkpoint()` (a `subql::PgLsn`) encoded big-endian: `lsn.0.to_be_bytes().to_vec()`. When the event carries no checkpoint the cursor is an empty vector. So the opaque `connetto_core::Cursor` is exactly an 8-byte big-endian LSN.

Consequences for this phase:

- Decode `Handshake.last_cursor`: 8 bytes means `u64::from_be_bytes` is the client's resume LSN. Empty or absent means LSN 0, that is a client that never synced, which takes the full-resync path.
- Key the oplog by that same `u64` LSN. The window comparison is `last_lsn` against the oplog's minimum retained LSN.
- `Materializer::advance_cursor(session_id, sub_id, &[u8])` stores the bytes as `subql`'s `OpaqueCheckpoint` and rejects a rewind. subql's `cursor_for` and `cursors_for_session` read them back. The monotonic guard is your backstop against out-of-order replay.

## Wire surface already in connetto-core (no new message types needed)

Everything reconnect needs is already defined and, for the snapshot pieces, already used by `handle_subscribe`.

| Type | Shape | Where it plugs in |
|---|---|---|
| `Handshake` | `new(protocol_version, client_id, auth_token)`, plus `.with_session_token(..)` and `.with_cursor(Cursor)`. Fields `session_token: Option<String>`, `last_cursor: Option<Cursor>` | `serve` currently ignores `last_cursor` and `session_token`. Read them to drive catchup. |
| `HandshakeAck` | `{ session_id, session_token, current_cursor, schema_version, initial_credits }` | `serve` currently sends an empty `current_cursor`. Set it to the server's current LSN watermark. |
| `FullResyncRequired` | `{ sub_id, reason: FullResyncReason }`, a `ControlMessage` variant. `FullResyncReason::CursorOutsideRetention` is the window case. | Send per re-declared subscription when the cursor is outside the window. |
| `SnapshotBegin` / `SnapshotPatch` / `SnapshotEnd` | `SnapshotEnd` carries the read cursor | Already the snapshot path in `handle_subscribe`. Reuse for the full-resync case. |
| `LivePatch` | `new(label, Cursor, payload_zstd)` | The catchup delivery format. See the decision below. |
| `SchemaUpdate` / `SchemaBlob` | schema version plus optional bulk blob | Case 3 (schema changed while offline). Reasonable to defer, see below. |

## Where you hook into the current code

- `session.rs::serve` (around line 408) runs the handshake, sends `HandshakeAck` with an empty `current_cursor` (line 442), then enters the select loop. Reconnect logic slots in right after the ack, before or interleaved with the client's re-sent `Subscribe` messages. Per the spec, catchup runs per re-declared subscription, so it is natural to branch inside `handle_subscribe` on whether the session is resuming.
- `session.rs::dispatch_event` (around line 343) runs `Materializer::dispatch`, advances the per-`(session, sub)` cursor, and fans a `LivePatch` out to each routed session. This is where the oplog append belongs: record the raw `ChangeEvent` once, keyed by its LSN, with table, pk, op, old image, new image, and tombstone flag, before or alongside the per-consumer fan-out. The append is per event, not per consumer, because catchup re-filters per client.
- `session.rs::handle_subscribe` (around line 702) delivers the initial snapshot through the `SnapshotSource` seam, then registers with the materializer and branches on `Registration::Row` versus `Registration::Aggregate`. On a resuming session within the window, catchup for that subscription replaces the initial snapshot.
- `Materializer::dispatch` returns `Dispatched { patches, aggregates, triggers }`. The raw `&ChangeEvent` is the `dispatch_event` argument, which is the oplog record source.

## Design decisions to make (recommendations)

1. Oplog seam. Define a trait in the shape of `SnapshotSource` (an async, `Send + Sync` seam). Suggested surface: `append(record)`, `entries_since(lsn) -> Vec<ChangeRecord>`, `min_lsn()` (the retention watermark), `current_lsn()`, and `prune()`. Ship an in-memory ring-buffer impl for Docker-free tests, and a Postgres-backed impl behind `pg-async`. The spec decision (06-reconnect.md line 163) says the oplog is a Postgres table replicated across the mesh, so the PG impl is the production target and the in-memory one is the test double.
2. Retention. Default 72 hours or 1,000,000 entries, whichever is hit first, both configurable (06-reconnect.md line 69). Put the config next to `SessionConfig` or in an `OplogConfig`.
3. Pruning policy. The spec contradicts itself: line 69 says pruning is unconditional on the window with no per-client cursor tracking, while the Notes (line 173) say do not prune tombstones older than the oldest client cursor. Resolve in favor of line 69 (unconditional window-based pruning). A client behind the watermark simply gets `FullResyncRequired`. This is simpler and is the stated decision. Record the choice.
4. Catchup delivery format. Reuse `LivePatch`, do not invent a catchup message (06-reconnect.md line 106 and the Delivery-format decision at line 165). For each re-declared subscription, take oplog entries since `last_lsn`, run them through the same matching, auth filter, and patchset encoding the live path uses, and send each as a `LivePatch` carrying that entry's cursor. Advance the session cursor as you go so the monotonic guard stays satisfied.
5. Resume-LSN granularity. subql keys cursors per `(session, subscription)`, but the client persists a single `last_applied_lsn` and sends one `last_cursor` (06-reconnect.md Client-Side State, open question 4). For v1 use the single global `last_cursor` from the handshake and replay every re-declared subscription from that LSN. Per-subscription resume is a later refinement.
6. Auth re-filtering on catchup. The oplog stores raw rows, so catchup must re-run the auth filter per client, and must deliver tombstones even for rows that were not visible before (06-reconnect.md line 146). Auth is `PermissiveAuth` today, so the filter is a passthrough, but build the code path so it is a real filter point, not a hardcoded allow.
7. Concurrent live plus catchup ordering (open question 6). While a session catches up, live events keep arriving. Hold live `LivePatch` delivery for the resuming session until its catchup drains, then flush, with the monotonic cursor guard as the backstop against a rewind. Keep this simple for v1.
8. Schema changed while offline (Case 3). `SchemaUpdate` and `SchemaBlob` exist, but schema migration is broader than this phase. Reasonable to defer with a clear note, or send `SchemaUpdate` and force a full resync for affected subscriptions when `HandshakeAck.schema_version` differs. Do not build a migration engine here.

## Acceptance and tests

Follow the established pattern: Docker-free tests are the gate, real Postgres is `#[ignore]` and Docker-gated. Reads and seeds on a diesel connection use typed queries (see the existing tests), not raw SQL. DDL, the `PgSqliteEmuSource::execute(sql)` string API, and subscription or `register` SQL stay as strings, since none has a typed form.

- Catchup within window (Docker-free): drive a sequence of INSERT, UPDATE, and DELETE events through an in-memory oplog, reconnect a client whose `last_cursor` sits mid-stream, and assert it receives exactly the entries after that LSN as `LivePatch` and reaches row parity on a SQLite replica.
- Outside window (Docker-free): reconnect with a `last_cursor` older than the watermark after a prune, and assert `FullResyncRequired { reason: CursorOutsideRetention }` followed by a full snapshot.
- Tombstone replay (Docker-free): delete a row, then reconnect from before the delete, and assert the delete is replayed and the replica drops the row.
- Postgres oplog (`pg-async`, `#[ignore]`): append and read back against a real PG table.

Green-bar gate before the phase is done:

```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --release --all-features
cargo test --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

## Constraints and gotchas

- Never commit, push, or open a PR without an explicit per-time instruction. "Continue" and "proceed" do not authorize a commit. Single-line commit subjects, no conventional-commit prefixes, no `Co-Authored-By`, no generated-by footers. Stage only the exact paths you changed, never `git add -A`.
- ASCII punctuation everywhere you write (chat, code, comments, docs, commit and PR text, assert and panic strings): no semicolons, no em or en dashes, no ASCII dash used as punctuation. Hyphens inside compound words are fine.
- Run Rust tests in release. Docker-backed tests and any heavy task need explicit approval first.
- Sync locks use `parking_lot::{Mutex, RwLock}`. SQLite stays synchronous, no `spawn_blocking`. The async Postgres paths live behind `pg-async` and use `diesel-async`.
- The `Materializer` and `SessionManager` are two-generic (`DB` for the catalog, `W` for the write policy), because Rust coherence forbids attaching a connetto-core trait to subql's `ParserDB`. Keep it that way.
- `AsyncConnector` impls need `#[allow(clippy::manual_async_fn)]` because the trait uses explicit `impl Future + Send`, not `async fn`. `PgAsyncDieselConnector::execute_scalar` decodes `ScalarKind::Int` as `BigInt`, so aggregate columns must be `BIGINT` in Postgres. A diesel `i64` bind assignment-casts into an `int4` column on insert, which is why the tests can declare `BigInt` ids against PG `INT` columns.
- Docker recipe for the `#[ignore]` tests: throwaway `postgres:16-alpine`, container name `connetto-pg-test`, host port `55432` (5432 is often in use), `DATABASE_URL=postgres://postgres:postgres@localhost:55432/postgres`, run with `-- --ignored --test-threads=1`, remove the container after.

## Files to read before writing code

- `docs/architecture/06-reconnect.md` (normative, including the open questions and the two decisions at the bottom).
- `docs/architecture/10-subscription-materializer.md` (boundary and failure inventory) and `docs/architecture/open-questions.md` (the Q6 cursor and resync entries).
- `crates/connetto-server/src/session.rs` (`serve`, `dispatch_event`, `handle_subscribe`, `Outbound`, `SessionState`, `SessionConfig`).
- `crates/connetto-server/src/materializer.rs` (`dispatch`, `advance_cursor`, `MatchedPatch`, and the cursor-equals-LSN encoding near line 455).
- subql's cursor API (`advance_cursor`, `force_set_cursor`, `cursor_for`, `cursors_for_session`, `drop_cursor`, `OpaqueCheckpoint`) and `snapshot_table`, per `docs/architecture/subql.md`.
