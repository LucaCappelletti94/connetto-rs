# Plan: build connetto-server (the Subscription Materializer)

> Status (updated): Phases 0, 1, and 2 are landed and green. The authoritative
> current state and the Phase 3 plan live in `docs/handoff-connetto-server-phase3.md`.
> subql is now consumed at rev `2b90db1` (main HEAD, diesel-async shipped) and
> sqlite-diff-rs is `0.7.0`. The strategic plan below is kept for context.

## Handoff (read this first)

### What this is

connetto-rs is a transport and sync layer that keeps SQLite edge and browser clients in sync with a PostgreSQL backend. The shared wire crate `connetto-core` is built. `subql` now closes the CDC round trip end to end (ingestion, matching, event to patchset conversion, inbound apply, and a re-execution engine). The next deliverable is `connetto-server`, which is the **Subscription Materializer** described normatively in `docs/architecture/10-subscription-materializer.md`.

The materializer is deliberately thin. `subql` owns the connection, the conversion, the apply, and the re-execution state machine. connetto-server is the session, authorization, and reliability host that wraps it. Do not rebuild anything `subql` already provides. Read `10-subscription-materializer.md` and `subql.md` before writing code.

### Repos, branches, toolchain, paths

- connetto-rs: `~/github/connetto-rs`, branch `main`, HEAD `6d19dae`. Remote `git@github.com:LucaCappelletti94/connetto-rs.git`. There is NO upstream parent (this is an original repo), so any PR, when explicitly authorized, targets `LucaCappelletti94/connetto-rs` `main`. Verify with `gh repo view --json parent` before opening one.
- Uncommitted in connetto-rs: `docs/architecture/architecture-diagram.svg` carries a version-label update awaiting a decision to commit. Everything else is clean. This plan file is also uncommitted.
- subql: `~/github/subql`. The full CDC loop plus diesel-async execution are on `origin/main`. connetto consumes it as a rev-pinned git dependency (currently `2b90db1`, PR #10). Read `main` at the pinned rev, not the local checkout's working branch.
- Toolchain: workspace `edition = "2024"`, `rust-version = "1.88"`. Build and test with a 1.88 or newer toolchain. No `unsafe` (the workspace forbids it).
- Ecosystem forks that `subql` pins and that connetto MUST mirror (see the integration gotcha below): `diesel` git `LucaCappelletti94/diesel` branch `future`, `sqlparser` and `sqlparser_derive` git `LucaCappelletti94/sqlparser-rs` rev `306abb569fcb64b84c79ab2284c71d69a4854307`, `pg_walstream` git `LucaCappelletti94/pg-walstream` branch `feat/pgoutput-decoder`. Downstream of `subql` also: `sql-traits` git `earth-metabolome-initiative/sql-traits` branch `main`, `sqlite-diff-rs` `0.7.0` from crates.io (carries the `diesel-async` feature), `pg2sqlite` and `diesel-sqlite-session` from git.

### The boundary (normative, from 10-subscription-materializer.md)

`subql` owns: CDC ingestion (`CdcSource`), matching plus UPDATE transitions plus aggregate IVM, event to patchset conversion, inbound apply, the re-execution state machine (queries run through a caller `Connector`), the per-`(session, subscription)` cursor, and persistence.

connetto-server owns: sessions and wire framing, authorization (read filter plus write gate), per-session patchset assembly from each client's authorized subset, the write path around `apply_diffset_bytes`, the oplog and catchup, all retry, and the wiring choices `subql` leaves open.

### subql API surface you will consume (exact names)

- CDC: the `CdcSource` trait (`next_event`, `ack`). Sources: `PgStreamingCdcSource` / `PgStreamingConfig` and `PollingPgCdcSource` / `PollingPgCdcConfig` (feature `pg-streaming`), `SqliteCdcSource` (feature `sqlite-cdc`), `PgSqliteEmuSource` (feature `pg-sqlite-emu`, a fake Postgres over SQLite that needs no Docker).
- Engine: `SubscriptionEngine` with `register`, `register_select`, `register_follow_update`, `register_batch`, `consumers(&event) -> ConsumerNotifications { inserted, deleted, updated }`, `aggregate_deltas(&event) -> Vec<(ConsumerId, AggDelta)>`, `snapshot_table`, and the cursor API `advance_cursor` (monotonic, rejects rewind), `force_set_cursor`, `cursor_for`, `cursors_for_session`, `drop_cursor` (keyed by `(SessionId, SubscriptionId)`, values are `OpaqueCheckpoint`).
- Emit: `wal2json_patchset(_builder)` and `maxwell_patchset(_builder)` are unconditional, `pgoutput_patchset(_builder)` needs feature `pgoutput-emit`. Changeset counterparts exist. They fold a slice of events over a source-agnostic `WireCatalog` / `WireTable` into one `sqlite-diff-rs` `PatchSet` or `ChangeSet`.
- Apply: `SubscriptionEngine::apply_diffset_bytes(bytes, conn, adapter)` (dispatches the patchset `P` or changeset `T` marker), plus `apply_patchset` and `apply_changeset`. Adapters: `PgAdapter` (feature `apply-patchset-postgres`), `MysqlAdapter` (`apply-patchset-mysql`), `SqliteAdapter` (`apply-patchset-sqlite`), and `CustomTypePgAdapter` with `PgCustomBinder` for Postgres enum and domain columns.
- Re-execution: `ReExecEngine` (`register`, `install`, `consumers`, `consumers_batch`, `ReExecutionTrigger`, `ScalarUpdate`, `BatchOutcome`), `AutoResolvingEngine` plus the `Connector` trait (`execute_scalar`, `execute_rows`, `AuthContext`, `Error`), the shipped `PgDieselConnector` (feature `executor-diesel-postgres`), `PgR2D2DieselConnector`, `MysqlDieselConnector`, and the async peers `AsyncAutoResolvingEngine` and `AsyncConnector`. v1 re-execution covers single-table scalar MIN and MAX. Row-set and aggregate re-execution are designed but not implemented. Aggregators on an RLS table are rejected at register time.
- Position and time: `Checkpoint`, `PgLsn`, `MysqlBinlogPos`, `OpaqueCheckpoint`, `NoCheckpoint`, and `StdClock` / `ManualClock`.

### connetto-core surface (already built) you plug into

`ControlMessage`, `BulkMessage` with `SnapshotPatch` / `LivePatch` / `MutationPatch` / `SchemaBlob`, the `codec` module (rmp-serde plus optional `u32` length framing), the seam traits `Transport` / `Store` / `FileStore` / `AuthPolicy` (with `IncomingFrame`, `MutationOp`, `PendingMutation`), `AuthContext`, `Cursor`, `SchemaVersion`, `PROTOCOL_VERSION`, `CodecError`.

### The one integration gotcha (do this first, in isolation)

connetto is a SEPARATE Cargo workspace from subql, and `[patch]` entries do not cross workspaces. The moment connetto-server depends on `subql` (git) with any diesel-backed feature, connetto's ROOT `Cargo.toml` MUST carry the same patch blocks `subql` uses, or the dependency graph will not resolve consistently. A git dependency's own `[patch]` is ignored by the consuming workspace, so this holds regardless of the dependency source. Copy verbatim from `~/github/subql/Cargo.toml` (lines 15 through 39):

- `[patch.crates-io]` with `diesel` (fork branch `future`), `sqlparser` and `sqlparser_derive` (fork rev), and `pg_walstream` (fork branch `feat/pgoutput-decoder`).
- `[patch."https://github.com/diesel-rs/diesel"]` routing `diesel` to the same `future` fork.

Treat `subql`'s manifest as the source of truth for the exact revs, since they may move. Get `cargo check -p connetto-server` green with `subql` linked before writing any materializer logic. This is the make-or-break step.

### Constraints (hard rules)

- Never commit, push, or open a PR without an explicit per-time instruction. "Continue" and "proceed" never authorize a commit. Staging and local verification are fine.
- Single-line commit subjects, no conventional-commit prefixes (`feat:`, `fix:`, and the like), no `Co-Authored-By`, no self-advertisement or generated-by footers.
- ASCII punctuation everywhere you write (chat, code comments, doc comments, commit and PR text, panic and assert strings): no semicolons, no em or en dashes, no ASCII dash used as punctuation, no non-ASCII typographic characters. Hyphens inside compound words are fine.
- Run Rust tests in release (`cargo test --release`) unless you are targeting debug-only behavior. Prefer runnable doctests over `no_run` or `ignore`.
- Docker-backed end-to-end tests and any heavy or long-running task need explicit approval before running. Check `nvidia-smi` before any GPU work (not expected for connetto-server).
- The new crate must satisfy the workspace lints: `missing_docs = forbid`, `unsafe_code = forbid`, clippy `all = deny` plus `pedantic = warn`. Every public item needs docs.

### Green-bar gate (all pass before a phase is done)

```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --release --all-features
cargo test --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

If `--all-features` on connetto-server pulls too much of subql's diesel surface to be practical, gate connetto-server's PG-backed pieces behind connetto-server features that mirror subql's, and run the gate per feature set. Decide this in Phase 0.

---

## Recommended plan

Work the phases in order. Each is a checkpoint: finish it, pass the green bar, report, and wait for confirmation before the next.

### Phase 0: scaffold and patch wiring (prerequisite)

- Create `crates/connetto-server` and add it to `members` in the root `Cargo.toml`.
- Mirror subql's `[patch]` blocks into connetto's root `Cargo.toml` (see the integration gotcha).
- Dependencies: `connetto-core` (path), `subql` (git `https://github.com/LucaCappelletti94/subql`, `main`, rev-pinned) with a minimal feature set to start (for example `sqlite-cdc`, `pg-sqlite-emu`, `apply-patchset-sqlite`), `tokio`, `diesel` (the `future` fork), `thiserror`. Add features as later phases need them.
- Acceptance: `cargo check -p connetto-server` green with subql linked. This validates the cross-workspace patch wiring.

### Phase 1: in-process end-to-end loop (prove the spine, no socket, no Docker)

- A `Materializer` type owning a `subql::SubscriptionEngine` over a catalog.
- Outbound: register one row subscription, drive events from a `PgSqliteEmuSource` or `SqliteCdcSource` (or hand-built events), run `consumers(&event)`, assemble a per-consumer patchset with the emit builder, frame it into `connetto_core::BulkMessage::LivePatch` carrying the resume `Cursor`, and push to an in-memory sink.
- Inbound: accept a `MutationPatch` and apply it with `engine.apply_diffset_bytes` against a target connection.
- Cursor: `advance_cursor` after a successful dispatch.
- Acceptance: a release-mode test that runs INSERT, UPDATE, and DELETE through to `LivePatch` bytes and applies a `MutationPatch`, asserting row parity. Use `pg-sqlite-emu` or in-memory SQLite so no Docker is needed. This is the smoke test that proves the whole integration.

### Phase 2: session manager and Transport

Per-session state, a `Transport` implementation (start with an in-memory loopback, then `tokio-tungstenite` for native per `09-wasm.md`), the flow-control window, keepalive, `Subscribe` and `Unsubscribe` handling, and initial snapshot delivery via `SnapshotPatch`.

### Phase 3: write path

Authorize each inbound mutation through the `AuthPolicy` seam (a permissive stub until OpenFGA and `rls2fga` land, which are not started), detect conflicts with the `updated_at` token (Q3.2), and reply with `MutationReject` or `MutationConflict`. Per Q3.5 the CDC echo is the success ack, so there is no separate `MutationAck`. Keep `client_seq` idempotency.

### Phase 4: re-execution

Bootstrap stateful subscriptions (run once, `install` the initial value), service triggers through a `Connector` (`PgDieselConnector`, or a custom `Connector` if you want the materializer to own retry and coalescing per Q5.5), and coalesce per `query_id`.

### Phase 5: oplog and reconnect

A retention-bounded oplog keyed by LSN with tombstones, and the catchup versus `FullResyncRequired` decision that compares subql's per-`(session, subscription)` cursor against the oplog watermark (`06-reconnect.md`).

### Phase 6: reliability

One backoff primitive (exponential with jitter, a hard attempt cap, and a hard total-duration cap) covering CDC reconnect, re-execution, delivery, and mutation, per the failure inventory in `10-subscription-materializer.md`.

## Decisions to make early

- Dev and test CDC source: recommend `pg-sqlite-emu` (fake Postgres, no Docker) plus in-memory SQLite for fast tests, with real Postgres behind `#[ignore]` Docker tests later (running those needs approval).
- Async runtime: tokio. subql's `CdcSource` is runtime-agnostic (RPITIT with `Send` bounds), so the materializer picks the runtime.
- Re-execution engine: the bare `ReExecEngine` plus a custom `Connector` gives the materializer full control over retry and coalescing (matches the boundary and Q5.5). `AutoResolvingEngine` is faster to stand up. Pick per how much you want subql to drive.
- Deferred for v1: OpenFGA authorization (use a permissive `AuthPolicy` stub, since `rls2fga` is not started) and file sync (the `FileStore` seam exists but is out of scope).

## Cross-references

`docs/architecture/10-subscription-materializer.md` (boundary, responsibilities, failure inventory), `subql.md` (shipped surface), `03-sync-pipeline.md`, `04-subscriptions.md`, `05-aggregate-queries.md`, `06-reconnect.md`, `08-authorization.md`, and `open-questions.md` (decision index).
