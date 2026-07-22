# Handoff: connetto-server through Phase 6 (reliability)

Read this first, then `docs/plan-connetto-server.md` (the phase list, status header refreshed), `docs/architecture/10-subscription-materializer.md` (the boundary and failure inventory), and `docs/architecture/06-reconnect.md`.

## Current state

- Repo `~/github/connetto-rs`, branch `main`, HEAD `a5853cd`. No upstream parent, so any authorized PR targets `LucaCappelletti94/connetto-rs` `main`. Working tree clean.
- Recent history (this line of work):
  - `366d64e` Phases 0 to 4 (materializer, session, snapshot, re-execution).
  - `d31f582` the session host, native client, and real-Postgres RLS read and write paths.
  - `a768743` CDC ingest reconnect with backoff and slot-based resume.
  - `a5853cd` reconnect observer plus the walsender-drop leg in the e2e.
- The product is now a working local-first sync pair over real Postgres for the READ direction, proven end to end across OS processes, plus a verified write path and a resilient CDC stream. The one unproven-through-the-binaries piece is a client-originated write (see "The next necessary step").

## Toolchain and dependencies

- Workspace `edition = "2024"`, `rust-version = "1.88"`. Lints: `missing_docs = forbid`, `unsafe_code = forbid`, clippy `all = deny` plus `pedantic = warn`, rustdoc link and backtick lints forbid. Every public item needs docs. Use `TryFrom` not `as` for fallible casts. `Drop::drop` must stay panic-free.
- `subql` is rev-pinned at `f331aced755f5891fcf7af5e31cf379269cab729` (main HEAD). The root `Cargo.toml` mirrors subql's `[patch]` blocks (load-bearing across workspaces): `diesel` to `LucaCappelletti94/diesel` branch `future`, `sqlparser` and `sqlparser_derive` to `LucaCappelletti94/sqlparser-rs` rev `306abb56`, `pg_walstream` to `LucaCappelletti94/pg-walstream` branch `feat/pgoutput-decoder`. `sqlite-diff-rs` is `0.7.0`. Treat subql's manifest as the source of truth for these revs when bumping the pin.
- `connetto-server` `pg-async` feature: `dep:diesel-async`, `diesel-async/postgres`, `diesel-async/bb8`, `diesel/postgres_backend`, `diesel/serde_json`, `diesel/uuid`, `subql/apply-patchset-postgres-async`, `subql/executor-diesel-async-postgres`, `subql/pg-streaming`. Off by default. Dev-deps `uuid`, `chrono` (build pk components in tests), `tempfile` (isolate per-client SQLite in the e2e). `anyhow` is a normal dep, used only by the binaries.
- `connetto-client` depends on `connetto-core` with `native-transport`, `diesel-sqlite-session`, `sqlite-diff-rs`, `zstd`, `tokio`, `anyhow`.

## What exists now (the shape to build on)

Backend concerns are all trait or enum seams with a Docker-free test double and a real-Postgres implementation, matching the codebase convention:

- `SnapshotSource` (session.rs): `PgSnapshotSource::from_ddl(pool, pg_ddl)` runs the subscription SELECT under the user's RLS GUC. `snapshot(select_sql, &AuthContext)`.
- `AuthPolicy` (connetto-core): `PermissiveAuth`, and `RlsAuth::from_ddl(pool, pg_ddl)` behind `pg-async`. `can_read` decodes the pk and runs `SELECT EXISTS(... WHERE "col" = $n ...)` under `SET LOCAL app.user_id`, binding each key column typed per its value. Key types the bind path does not cover (timestamp, date, time, decimal, json) fail loudly. `can_write` is passthrough (the database is the write gate).
- `Oplog` (oplog.rs): `InMemoryOplog` and `PgOplog` behind `pg-async`, plus `catchup_decision` and `OplogConfig`. Client reconnect and catchup are wired into `serve` and tested in `reconnect.rs`.
- `WriteTarget` (write_target.rs): a concrete enum, `Sqlite(SqliteWriteTarget)` for Docker-free apply-mechanics tests and `Postgres(Box<PgWriteTarget>)` for the enforced path. It is an enum, not a public generic trait, on purpose: the write-plan types (`WritePlan`, `PlannedConflict`) are `pub(crate)`, so a public `WriteTarget` trait bound on `SessionManager` would leak private types (the `private_bounds` lint, denied). `commit` runs the conflict probe and apply and returns `WriteOutcome::{Applied, Conflict}` or `WriteError::{Unauthorized, Materializer, Backend}`. `PgWriteTarget` holds `{ pool, catalog: ParserDB }` and applies via `subql::patchset::apply_diffset_bytes_async_with_catalog(&self.catalog, ...)` inside a `SET LOCAL app.user_id` transaction, so Postgres RLS gates the write. Unauthorized surfaces two ways: a `WITH CHECK` hard error (string-matched on "row-level security") and a rows-affected shortfall (an `UPDATE`/`DELETE` of rows RLS hid).
- `pk` module (pk.rs): the canonical primary-key codec. `encode(&[Value<Postgres>])` (read path), `encode_wire(&[WireValue])` (write path, maps sqlite-diff values into `Value<Postgres>`), `decode(&[u8]) -> Vec<Value<Postgres>>`. MessagePack over subql's own `Value<Postgres>`. The read and write paths encode the same logical key identically.
- CDC ingest (session.rs): `ingest(&mut source)` is the plain loop. `ingest_with_reconnect(connect, &ReconnectPolicy, on_event)` wraps it: on a stream failure it reconnects via the `connect` factory (which rebuilds a fresh source, resuming from the slot's confirmed position), with exponential backoff capped at `max_backoff`, an optional `max_attempts` (`None` retries forever), and a `healthy_after` window that resets the backoff after a connection that stayed up. `ReconnectEvent::{Retrying, GaveUp}` is delivered to `on_event` for logging or metrics.
- Binaries: `crates/connetto-server/src/bin/connetto-server.rs` (config from env: `CONNETTO_BIND`, `DATABASE_URL`, `CONNETTO_PG_DDL[_FILE]`, `CONNETTO_WRITABLE` for the writable-table policy, `CONNETTO_SLOT`, `CONNETTO_PUBLICATION`, optional `CONNETTO_READER_URL` for RLS) and `crates/connetto-client/src/bin/connetto-client.rs` (`CONNETTO_SERVER`, `CONNETTO_DB`, `CONNETTO_SQLITE_DDL[_FILE]`, `CONNETTO_CLIENT_ID`, `CONNETTO_TOKEN`, `CONNETTO_SUB_ID`, `CONNETTO_QUERY`, optional `CONNETTO_WRITE` with one statement per line). The server bin is a `[[bin]]` with `required-features = ["pg-async"]`, so the default build skips it. The server auth is a single concrete `ServerAuth` enum (permissive or RLS) so the spawned session future stays `Send`.
- `connetto-client`: `ConnettoConnection` (renamed from `SyncClient`) implements diesel's `Connection` and `LoadConnection` behind the `i-implement-a-third-party-backend-and-opt-into-breaking-changes` feature, so apps run ordinary diesel queries on `&mut conn`, with execution delegating to the managed capture connection. Explicit primitives remain: `connect`, `subscribe`, `pump_one`, `push`, `conn` (escape hatch to the underlying `SqliteConnection`), `ping`, `close`, plus the ergonomic driver `flush`, `next_event`, and `take_changed`. An `on_commit` hook sets a dirty flag so `flush` and `next_event` auto-submit local writes with no explicit `push`, and `on_update` hooks feed `Reactive::changed_tables` for UI re-query. `establish` errors on purpose (build with `connect`). See `docs/architecture/10-client-connection.md`.

## What is verified

Docker-free tests are the gate. Real-Postgres tests are `#[ignore]` and Docker-gated. All green.

- Docker-free: `connetto-core` wire, `connetto-server` lib units (including `pk::` codec), `read_filter`, `reconnect`, `reexec`, `session_loop`, `write_path`, `snapshot_source`, `inprocess_loop`, and `connetto-client` `loop_emu`.
- Docker-gated (`#[ignore]`, `pg-async`):
  - `pg_async` (4): async apply, snapshot, re-exec bootstrap, PG oplog.
  - `rls_read_filter`: RLS read visibility for int, composite, and uuid keys, plus the loud-fail on a timestamp key.
  - `rls_write_filter`: an owned insert lands, a foreign-owner insert is refused by `WITH CHECK`.
  - `e2e`: multi-process, two client binaries, snapshot plus live plus walsender-drop reconnect.
  - `cdc_reconnect`: in-process, kill the walsender mid-stream, assert the client converges after reconnect.

### Docker test recipe (this machine)

Ports 5432, 5433, 5459, 5462, and 3306 are taken by the user's own services. Use a free high port and never touch those. `postgres:16` is cached locally.

```
docker run -d --rm --name connetto-test-pg -e POSTGRES_PASSWORD=postgres -p 55450:5432 postgres:16 -c wal_level=logical
# wait: docker exec connetto-test-pg pg_isready -U postgres -h 127.0.0.1
DATABASE_URL=postgres://postgres:postgres@localhost:55450/postgres \
  cargo test --release -p connetto-server --features pg-async --test <name> -- --ignored
docker stop connetto-test-pg
```

`wal_level=logical` is only needed by `e2e` and `cdc_reconnect` (they stream); the RLS tests and `pg_async` run against a plain `postgres:16`. The `e2e` also needs both binaries built in the same profile first: `cargo build --release -p connetto-server --features pg-async --bin connetto-server` and `cargo build --release -p connetto-client --bin connetto-client`. Running Docker tests needs explicit approval each time.

## The write leg through the binaries (landed)

The write direction is now proven end to end through the real processes. The `connetto-client` binary reads `CONNETTO_WRITE` (an insert), runs it on `client.conn()` after subscribing (the capture session records it), calls `client.push()` to upload, then keeps pumping so it observes its own echo. The `e2e` test `e2e_client_write_lands_in_pg_and_fans_out` brings a reader up and lets it snapshot the seed, then a writer client inserts and pushes, and it asserts the row lands in Postgres (queried through the admin pool) and the reader converges on it over CDC.

The missing piece that blocked this was the server binary: `Materializer::new` builds an empty write policy, so `plan_write` rejected every mutation with `NotWritable`. The binary now reads `CONNETTO_WRITABLE` (comma-separated `table` or `table:version_column`) and builds the writable catalog via `Materializer::with_write_catalog`. The `e2e` sets `CONNETTO_WRITABLE=orders`. Writes always apply to the source Postgres (the bin always uses `pg_write_target`). The stale `CONNETTO_SQLITE_DDL` and `CONNETTO_SQLITE_TARGET` env docs were removed.

The three Docker-gated `e2e` tests reset the same Postgres and share one replication slot and publication name, so they are serialized with a process-wide `tokio::sync::Mutex` (`PG_SERIAL`), and `drop_slot` terminates any lingering walsender before dropping the slot so a prior test's stream cannot block the drop.

RLS write enforcement is proven too. `e2e_rls_write_enforced_owned_lands_foreign_refused` creates a non-superuser `app_writer` role and an `owned` table with a policy `USING (owner = current_setting('app.user_id', true))`, spawns the server with `CONNETTO_READER_URL` pointed at that role, and drives one `alice` client through three ordered pushes on one session: an owned insert (lands), a foreign insert owned by `bob` (refused by the policy's implicit `WITH CHECK`), and an owned sentinel. Once the sentinel lands, Postgres holds only alice's rows. The identity flows through `Handshake.client_id` to `AuthContext` to `SET LOCAL app.user_id` in the write transaction. The write-flow test uses `PermissiveAuth`, which proves the pipe. This test proves the database gates the write.

## After that

- Write-path polish: an `RlsAuth::can_write` early-reject `EXISTS` for `UPDATE`/`DELETE`, and making the rows-affected shortfall distinguish a real RLS denial from a legitimately-gone row (both classify as `Unauthorized` today, which is safe but imprecise).
- Aggregate subscriptions through the real loop (the `PgAsyncDieselConnector` is wired and unit-tested, but no e2e drives an aggregate end to end).
- Remaining Phase 6 reliability surfaces: the plan's Phase 6 is broader than the CDC reconnect delivered here. Re-execution, delivery, and mutation retry are not yet unified under one backoff primitive. The `ReconnectPolicy` backoff is a reasonable model to generalize.
- Native client ergonomics (landed): `SyncClient` is now `ConnettoConnection`, a full diesel `Connection` and `LoadConnection` (feature-gated) so apps query `&mut conn` directly, with an `on_commit` dirty flag driving `flush` and `next_event` auto-submit and `on_update` hooks feeding `Reactive::changed_tables`. A server `MutationReject` or `MutationConflict` now rolls the optimistic write back locally by inverting the pushed changeset (`invert_changeset`) and applying it on the apply connection, and the event carries the affected rows as `AffectedRow { table, key }` with the primary key decoded from that changeset via `op.primary_key()`. Verified by the `loop_emu` tests `connection_autosubmits_writes_and_reports_changed_tables`, `connection_is_a_diesel_connection`, `rejected_write_rolls_back_locally`, and `conflicting_write_rolls_back_and_reports_keys`. Remaining: aggregate query routing, merging the server's authoritative row on a conflict (today the write is only rolled back), and the WASM connection variants (the same object serves as the worker-side connection). See `docs/architecture/10-client-connection.md`.

## Constraints and gotchas

- Never commit, push, or open a PR without an explicit per-time instruction. "Continue" and "proceed" do not authorize a commit. Single-line commit subjects, no conventional-commit prefixes, no `Co-Authored-By`, no generated-by footers. Stage only the exact paths you changed, never `git add -A`.
- ASCII punctuation everywhere you write (chat, code, comments, docs, commit and PR text, panic and assert strings): no semicolons, no em or en dashes, no ASCII dash as punctuation. Hyphens inside compound words are fine.
- Run Rust tests in release. Docker-backed tests and any heavy task need explicit approval first.
- The async apply is `Send`-safe only through the catalog. subql's `SubscriptionEngine` embeds a `MergeManager` with an `mpsc::Receiver`, so it is `Send` but not `Sync`, and a shared `&SubscriptionEngine` cannot be held across the apply `await` on a multi-thread runtime. This was resolved upstream: `apply_diffset_bytes_async_with_catalog(&DB, ...)` takes only the catalog (`ParserDB` is `Sync`). `PgWriteTarget` uses it. See `docs/upstream-subql-catalog-only-apply.md` (resolved).
- RLS enforcement needs a non-superuser role. A superuser or the table owner bypasses every policy. `PgSnapshotSource`, `RlsAuth`, and `PgWriteTarget` must connect as a role subject to RLS. The server bin uses the `CONNETTO_READER_URL` pool for reads and the write target when set. The RLS tests create an `app_reader` / `app_writer` role for exactly this.
- The `diesel::RunQueryDsl` (sync) and `diesel_async::RunQueryDsl` traits both provide `.execute`, `.load`, `.get_result`. With both in scope, calls on a sync `SqliteConnection` misresolve to the async trait. Fully-qualify: `diesel_async::RunQueryDsl::execute(query, conn).await` for the async side, and keep only one trait in scope for the sync side.
- CDC resume is free from the replication slot: `ingest` acks each dispatched LSN, advancing the slot's `confirmed_flush_lsn`, so reconnecting with `start_lsn = None` resumes exactly where it left off. Delivery is at-least-once (a re-delivered event applies idempotently on the client).
- Simulating a dropped stream in a test: `SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots WHERE slot_name = '...' AND active_pid IS NOT NULL`, then wait past the reconnect backoff before the next insert so it can only arrive over the reconnected stream. Pick a free listen port in a test by binding `127.0.0.1:0`, reading the port, and dropping the listener.
- The `edit` tool matches by basename plus tag, and the root `Cargo.toml` collides with crate `Cargo.toml`; use the full path in the edit header.

## Files to read before writing code

- `crates/connetto-server/src/session.rs` (`SessionManager`, `serve`, `dispatch_event`, `ingest`, `ingest_with_reconnect`, `ReconnectPolicy`, `ReconnectEvent`, `handle_mutation`).
- `crates/connetto-server/src/write_target.rs` (the `WriteTarget` enum and `PgWriteTarget::commit`).
- `crates/connetto-server/src/bin/connetto-server.rs` and `crates/connetto-client/src/{lib.rs,bin/connetto-client.rs}`.
- `crates/connetto-server/tests/e2e.rs` (the multi-process harness to extend) and `rls_write_filter.rs` (the write-path assertions).
- `docs/architecture/10-subscription-materializer.md`, `08-authorization.md`, `06-reconnect.md`.
