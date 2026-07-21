# Handoff: connetto-server Phase 3 (the write path)

Read this first, then `docs/plan-connetto-server.md` (the original strategic plan), `docs/architecture/10-subscription-materializer.md` (the normative boundary), and `docs/architecture/subql.md` (the shipped subql surface). Phases 0, 1, and 2 are landed and green. This document is the tactical current state plus the Phase 3 plan.

## Repos, HEADs, toolchain

- connetto-rs: `~/github/connetto-rs`, branch `main`, git HEAD `6d19dae`. Remote `git@github.com:LucaCappelletti94/connetto-rs.git`. There is NO upstream parent, so any PR (only when explicitly authorized) targets `LucaCappelletti94/connetto-rs` `main`. Verify with `gh repo view --json parent` before opening one.
- subql: consumed as a rev-pinned git dependency at `2b90db1f5b1b261fdb8604ea45c2de5f19896f00` (main HEAD, PR #10, adds diesel-async execution). Local checkout at `~/github/subql`. The consumed source lives under `~/.cargo/git/checkouts/subql-*/2b90db1/` once fetched. Read subql at that rev, not the local working branch.
- sqlite-diff-rs: `0.7.0` from crates.io (carries the `diesel-async` feature). Local repo at `~/github/sqlite-diff-rs`.
- Ecosystem forks mirrored verbatim in connetto's root `Cargo.toml` `[patch]` blocks: `diesel` git fork branch `future`, `sqlparser`/`sqlparser_derive` git fork rev `306abb56...`, `pg_walstream` git fork branch `feat/pgoutput-decoder`. subql's `[patch]` block is unchanged from the e35258a era, so connetto's mirror still matches. `diesel-async` 0.7 resolves its `diesel ~2.3` requirement against the pinned fork.
- Toolchain: workspace `edition = "2024"`, `rust-version = "1.88"`. No `unsafe` (workspace forbids it). Workspace lints: `missing_docs = forbid`, `unsafe_code = forbid`, clippy `all = deny` plus `pedantic = warn`, and the rustdoc link/backtick lints are forbid. Every public item needs docs.

## Working-tree state (all Phase 0 to 2 work is uncommitted)

Nothing has been committed this session (HEAD is still `6d19dae`). Uncommitted:

- Modified: `Cargo.toml` (member, subql dep, tokio features, `[patch]` blocks), `Cargo.lock`.
- Modified (pre-existing, untouched): `docs/architecture/architecture-diagram.svg`.
- Untracked: `crates/connetto-server/` (the whole crate), `docs/plan-connetto-server.md`, and this handoff.

Do not commit, push, or open a PR without an explicit per-time instruction.

## What is built (Phases 0 to 2, green)

`crates/connetto-server/` on the pgoutput vehicle (`subql::ChangeEvent`, the `pg_walstream` event type both matching and emission consume, so one event drives dispatch and patchset folding with no re-encoding).

Files:
- `src/materializer.rs`: the session-agnostic `Materializer` core plus `MatchedPatch`, `MaterializerError`, and `pub(crate)` `compress`/`decompress` (zstd level 3).
- `src/transport.rs`: `LoopbackTransport` (built by `loopback()`) and `WebSocketTransport` (native `tokio-tungstenite`), plus `LoopbackError`/`WebSocketError`.
- `src/session.rs`: `SessionManager<Snap>`, the per-session state machine, the `SnapshotSource` seam, `Snapshot`, `SessionConfig`, `SessionError`.
- `src/lib.rs`: module wiring and re-exports.
- `tests/inprocess_loop.rs`: Phase 1 in-process CDC-to-apply smoke test (emu source, INSERT/UPDATE/DELETE row parity, inbound `MutationPatch`).
- `tests/session_loop.rs`: Phase 2 session tests (loopback full lifecycle plus a WebSocket socket smoke test).

Public API in use:
- `Materializer::new(pg_ddl) -> Result<Self, MaterializerError>`, `register(consumer_id: u64, select_sql: &str) -> Result<SubscriptionId, _>`, `unregister(sub_id) -> bool`, `dispatch(&ChangeEvent) -> Result<Vec<MatchedPatch>, _>`, `advance_cursor(session_id: u64, sub_id, cursor: &[u8])`, `apply_mutation(&MutationPatch, &mut SqliteConnection) -> Result<usize, _>`, `apply_diffset(payload_zstd: &[u8], &mut SqliteConnection) -> Result<usize, _>`. `MatchedPatch { consumer_id, payload_zstd, cursor }`.
- `SessionManager::<Snap>::new(materializer, snapshot_source, config) -> Arc<Self>`, `dispatch_event(&ChangeEvent) -> Result<(), MaterializerError>`, `serve<T: Transport>(self: Arc<Self>, transport: T) -> Result<(), SessionError>`.
- `SnapshotSource` (async trait): `async fn snapshot(&self, select_sql: &str) -> Result<Snapshot, Self::Error>`. `Snapshot { patchset: Vec<u8> (raw, uncompressed), cursor: Cursor }`.
- `SessionConfig { initial_credits: u32, schema_version: SchemaVersion }` (default 64 credits).
- Transport: `loopback() -> (LoopbackTransport, LoopbackTransport)`, `WebSocketTransport::accept(TcpStream)`, `WebSocketTransport::connect(url, TcpStream)`.

## Decisions locked this session (do not relitigate)

1. Concurrency: `Arc<tokio::Mutex<Materializer>>`. Lock only around the short synchronous engine calls (`dispatch`, `register`, `advance_cursor`, apply), never held across an `.await`. No actor framework, no command-enum task. The system is fully async around those locks.
2. Snapshot: a `SnapshotSource` seam. Phase 2 delivers `SnapshotBegin` then `SnapshotPatch` then `SnapshotEnd` with a placeholder patch. Phase 4 fills the content by running the subscription `SELECT` against Postgres through the re-exec `Connector` and encoding rows with sqlite-diff-rs. No SQLite ever lives on the backend.
3. Flow control: credits are charged only to bulk-plane frames (`LivePatch`, `SnapshotPatch`). Control frames always flow, so keepalive cannot deadlock on an empty credit window. This refines the literal wording in `02-protocol.md`.
4. Transport wire discipline: MessagePack payloads are not valid UTF-8, so control-versus-bulk is distinguished by a one-byte kind tag on each binary WebSocket frame (this is "the caller's own discipline" that connetto-core sanctions).
5. Async DB foundation: diesel-async is the chosen async execution layer for the Postgres and MySQL server-side paths, because it reuses diesel's type-safe, backend-dispatched apply that subql and sqlite-diff-rs are built on (sqlx or tokio-postgres would fracture that foundation, and diesel outperforms sqlx in the diesel benchmark suite). It is now shipped upstream. connetto uses it directly with no `spawn_blocking` shims. SQLite stays sync forever (no async SQLite backend exists, and SQLite is a local file).

## subql async surface for Phase 3 (shipped at rev 2b90db1)

- Async apply on `SubscriptionEngine`: `apply_patchset_async`, `apply_changeset_async`, and `apply_diffset_bytes_async(&self, bytes: &[u8], conn: &mut Conn, adapter: &A) -> impl Future<Output = QueryResult<usize>> + Send` where `Conn: diesel_async::AsyncConnection<Backend = DBend>` and `A: Adapter<DBend, String, Vec<u8>>`. The engine touch (parse plus reconstruct against the catalog) is synchronous up front, then the future carries only the owned batch, `conn`, and `adapter`. This is the byte-level inbound entry point, mirroring the sync `apply_diffset_bytes`.
- Async re-exec connectors: `PgAsyncDieselConnector` and `MysqlAsyncDieselConnector` (both `impl AsyncConnector`), for Phase 4. subql already had the `AsyncConnector` trait and `AsyncAutoResolvingEngine`.
- Feature gates (in subql, mirror as connetto features when wiring): `apply-patchset-postgres-async` (pulls `diesel-async/postgres`, `sqlite-diff-rs/diesel-async`, reuses `PgAdapter`), `apply-patchset-mysql-async`, `executor-diesel-async-postgres` and `executor-diesel-async-mysql` (bb8-pooled async re-exec). `diesel-async` is 0.7 with the `bb8` pool feature.
- Connection and pool for the PG path: `diesel_async::AsyncPgConnection`, pooled through `diesel_async::pooled_connection::bb8`.
- These features are OFF in connetto today because nothing non-Docker exercises them. Turn them on in Phase 3 only for the real-PG path, behind Docker-gated `#[ignore]` tests.

## connetto-core write-path surface (already built)

- Control: `MutationHeader { client_seq: u64, op_count: u32 }` (announces the upload, travels first), `MutationReject { client_seq, reason: MutationRejectReason }`, `MutationConflict { ... }`. Success has no dedicated message: per Q3.5 the CDC echo is the ack.
- Bulk: `MutationPatch { client_seq: u64, patchset_zstd: Vec<u8> }` (paired one-to-one with the immediately preceding `MutationHeader`).
- Auth seam: `AuthPolicy` trait (`can_read(ctx, table, pk)`, `can_write(ctx, table, pk, op)`), `MutationOp { Insert, Update, Delete }`, `AuthContext { user_id, tenant_id, roles, claims }`.
- The current session loop returns a `NonFatalError` placeholder for `MutationHeader` and for any inbound bulk frame. Phase 3 replaces both.

## Phase 3 plan (the write path)

Goal: a client uploads a `MutationHeader` then a `MutationPatch`; the materializer authorizes it, detects conflicts, applies it, and replies only on failure.

1. Pair the frames in the session loop. Track the last `MutationHeader` per session; when the following `MutationPatch` arrives, validate `client_seq` matches, else `MutationReject` or a protocol error. An out-of-pair bulk frame is a protocol violation.
2. Authorization through the `AuthPolicy` seam. Add an `AuthPolicy` to `SessionManager` (generic parameter, or a boxed trait object) with a permissive stub for now (OpenFGA and `rls2fga` are not started). Call `can_write` per op before apply. Fail closed: an auth error or a false result rejects the write, never applies it.
3. Conflict detection via the `updated_at` token (Q3.2). The main design question of the phase: the server must compare the client's basis against the current server row (conceptually `WHERE id = ? AND updated_at = ?`) and, on mismatch, emit `MutationConflict` carrying the current row so the app can resolve. Decide the exact mechanism (the uploaded changeset can carry the old image, or a pre-apply read of the current row). Keep it fail-closed.
4. `client_seq` idempotency. Dedup replays per session (a seen-set or a last-applied sequence) so a resent mutation is not double-applied.
5. Apply, async-first. For real Postgres, use `engine.apply_diffset_bytes_async(&bytes, &mut conn, &adapter).await` with `PgAdapter` over a bb8-pooled `AsyncPgConnection`, behind connetto features mirroring subql (`apply-patchset-postgres-async`) and a Docker-gated `#[ignore]` test (Docker runs need explicit approval). For the Docker-free path, apply to the SQLite emu or target through the existing sync `apply_diffset`. No `spawn_blocking`.
6. Replies. `MutationReject { client_seq, reason }` for write-path failures, `MutationConflict` for stale-row collisions. No `MutationAck` (Q3.5).

Acceptance: a release test that drives a `MutationHeader` plus `MutationPatch` through the session over the loopback transport, asserts the row applies on the happy path (Docker-free, SQLite target), asserts a stale `updated_at` yields `MutationConflict`, asserts an unauthorized write yields `MutationReject`, and asserts a replayed `client_seq` applies once. The real-PG async apply is a separate Docker-gated `#[ignore]` test.

## Phases 4 to 6 (outline, unchanged from the strategic plan)

- Phase 4: re-execution and stateful bootstrap. Implement subql's `AsyncConnector` (use `PgAsyncDieselConnector` or a custom one for materializer-owned retry and coalescing), bootstrap MIN/MAX and materialized aggregates with `install`, coalesce per `query_id`. Fill the `SnapshotSource` seam with a real Connector-backed snapshot at a snapshot LSN.
- Phase 5: oplog and reconnect. Retention-bounded oplog keyed by LSN with tombstones, catchup versus `FullResyncRequired` by comparing subql's per-`(session, subscription)` cursor against the oplog watermark (`06-reconnect.md`).
- Phase 6: reliability. One backoff primitive (exponential with jitter, hard attempt cap, hard total-duration cap) covering CDC reconnect, re-execution, delivery, and mutation, per the failure inventory in `10-subscription-materializer.md`.

## Constraints (hard rules)

- Never commit, push, or open a PR without an explicit per-time instruction. Staging and local verification are fine.
- ASCII punctuation everywhere (chat, code, comments, docs, commit and PR text): no semicolons, no em or en dashes, no ASCII dash used as punctuation, no non-ASCII typographic characters. Hyphens inside compound words are fine.
- Single-line commit subjects, no conventional-commit prefixes, no `Co-Authored-By`, no self-advertisement footers.
- Run Rust tests in release (`cargo test --release`). Prefer runnable doctests over `no_run` or `ignore`.
- Docker-backed tests and any heavy or long-running task need explicit approval before running.

## Green-bar gate (all pass before a phase is done)

```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --release --all-features
cargo test --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

## Prompt for the next session

Copy the block below to start the next session.

```
Resume the connetto-rs build. Phases 0 through 2 of connetto-server (the
Subscription Materializer) are landed and green: the crate scaffold and
cross-workspace [patch] wiring, the session-agnostic Materializer core over
subql on the pgoutput vehicle, and the session layer (loopback plus native
tokio-tungstenite transports, SessionManager, the per-session state machine
with handshake, subscribe with snapshot delivery, live delivery, keepalive,
flow control, and unsubscribe). subql is consumed as a rev-pinned git
dependency at 2b90db1 (main HEAD, diesel-async execution shipped), and
sqlite-diff-rs is 0.7.0 from crates.io.

Read docs/handoff-connetto-server-phase3.md first. It is the authoritative
current state: repos and HEADs, the uncommitted working tree, what is built
with the exact public API, the locked architecture decisions (Arc<tokio::Mutex>
concurrency, the SnapshotSource seam, bulk-only flow-control credits, the
one-byte transport kind tag, and diesel-async as the async DB foundation with
no spawn_blocking and SQLite staying sync), the subql async apply and connector
surface, the connetto-core write-path types, and the Phase 3 plan. Then read
docs/architecture/10-subscription-materializer.md and subql.md for the boundary.

Execute Phase 3: the write path. Pair MutationHeader with MutationPatch in the
session loop (replacing the current NonFatalError placeholders), authorize each
write through the AuthPolicy seam (permissive stub until OpenFGA and rls2fga
land), detect conflicts with the updated_at token (Q3.2) and reply with
MutationReject or MutationConflict, keep client_seq idempotency, and apply
async-first: the real-Postgres path through subql's apply_diffset_bytes_async
with PgAdapter over a bb8-pooled AsyncPgConnection behind a Docker-gated
#[ignore] test, and the Docker-free path through the existing sync SQLite apply.
No spawn_blocking shims. Per Q3.5 the CDC echo is the success ack, so there is
no MutationAck.

Each phase is a checkpoint: pass the handoff's green-bar gate, report, and wait.
Do not commit, push, or open a PR without an explicit instruction. Docker and
any heavy task need explicit approval before running. ASCII punctuation only.
connetto-rs has no upstream parent, so any authorized PR targets
LucaCappelletti94/connetto-rs.
```
