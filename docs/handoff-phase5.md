# Handoff: Phase 5 (delivery credits / flow control)

## Goal

Execute Phase 5 of `docs/plan-relay-parity.md`: make the browser `RelayHub` (`crates/connetto-web/src/relay.rs`) honor a per-tab delivery-credit window, matching `connetto-server`'s backpressure, so a relay tab and a direct-socket client see identical flow control. Phases 0 through 4 are landed and green.

## Constraints and preferences (unchanged, load-bearing)

- ASCII punctuation only in ALL prose (chat, comments, docs, commit messages): no semicolons, no em/en dashes, no ` - ` as punctuation. Hyphens in compound words are fine.
- NO commit, push, PR, or deploy without an explicit per-time instruction in that exact moment. "Proceed"/"continue" do NOT authorize commits. Everything this session is uncommitted on branch `main`.
- NO `Co-Authored-By`, no Claude advertisement or footers.
- Browser runs and Docker need FRESH per-time approval each session. Re-ask for Phase 5.
- Toolchain trap: default nightly ICEs compiling tokio in release. Tests: `cargo +stable test --release`. Clippy: `cargo +nightly clippy ... -D warnings`. Use whatever `+stable` resolves to.
- Test-first: write failing test, show RED, implement, show GREEN. `connetto-web` is wasm-only, so relay tests are browser (`wasm-pack`), not native. Prefer self-contained fake-upstream tests (no server or Docker) like `resync.rs`, `conflict.rs`, `nonfatal.rs`.
- Keep `docs/plan-relay-parity.md` current as the phase cleanup: `AckCredits` table row to `done`, a Phase 5 `Status: landed` note, and flip the "Progress" line near line 54.
- Prefer diesel typed queries; raw `sql_query` only when diesel cannot express it, with a comment.

## What Phase 5 must do

Mirror the server credit mechanism in `crates/connetto-server/src/session.rs`, which is small and well defined:

- `SessionState { credits: u32, pending: VecDeque<BulkMessage> }`, `credits` starts at `initial_credits` (64).
- Only bulk-plane frames are credit-gated: `LivePatch` and `SnapshotPatch`. Control frames (`Pong`, `HandshakeAck`, `SnapshotBegin`/`SnapshotEnd`, `AggregateUpdate`, `MutationApplied`/`Reject`/`Conflict`, `NonFatalError`, `FullResyncRequired`) are NEVER gated, so keepalive cannot deadlock. `SnapshotBegin`/`SnapshotEnd` are control frames; only the `SnapshotPatch` between them is bulk.
- `enqueue_and_flush(transport, credits, pending, msg)` (session.rs:1509) pushes then flushes.
- `flush` (session.rs:1520) drains FIFO while `credits > 0`, decrementing per bulk frame sent.
- `ControlMessage::AckCredits(ack)` (session.rs:946): `credits = credits.saturating_add(ack.credits)`, then flush.

## Relay today (the gap)

- The tab shovel (`fn shovel`, relay.rs:508) uses UNBOUNDED channels and forwards `TabOut::Bulk` straight to `tab.send_bulk` (relay.rs:537-539). The plan is explicit: credits become the hub core bookkeeping in `HubState`/`TabState`, NOT a channel-capacity change. Leave the shovel unbounded.
- `handle_tab_control` treats `ControlMessage::AckCredits(_)` as a no-op (relay.rs:939).
- The relay ack advertises `initial_credits: 64` (relay.rs:897) but never enforces it.
- Three bulk-send sites push `TabOut::Bulk(...)` with no accounting:
  1. `handle_local_mutation` local-tier fan-out (relay.rs ~1107), `LivePatch`.
  2. `handle_worker_event` `LivePatch` routing (relay.rs ~1229), `LivePatch`.
  3. `send_snapshot_patch` (relay.rs ~1520), `SnapshotPatch`.
  Aggregate updates already go via `TabOut::Control` (the `handle_worker_event` Aggregate arm), so they are correctly not gated.

## Implementation shape (proposed, from the plan)

- Add `credits: u32` (init 64 at tab construction or handshake) and `pending: VecDeque<BulkMessage>` to `TabState` (relay.rs:157). Import `VecDeque`.
- Add a hub helper analogous to the server pair, for example `enqueue_tab_bulk(tab: &mut TabState, msg: BulkMessage)` that pushes to `tab.pending` then flushes while `tab.credits > 0` via `tab.out.send(TabOut::Bulk(...))`, decrementing per frame. A dropped `out` send means the tab is gone; keep the existing best-effort `let _ =` behavior.
- Route all three bulk-send sites through that helper. This requires `&mut TabState` at each site:
  - `handle_worker_event` `LivePatch` arm currently iterates `state.tabs.values()` (immutable). Switch to `values_mut()`.
  - `serve_snapshot` and `send_snapshot_patch` currently take `tab: &TabState`. Change to `&mut TabState`.
  - `handle_local_mutation` fan-out needs `&mut` tab access.
  - Watch the borrow interplay with `state.blank`/`state.local`/`state.agg_routes` (disjoint-field borrows, same pattern already used).
- `AckCredits` arm: `tab.credits = tab.credits.saturating_add(ack.credits)` then flush `tab.pending`.
- `resnapshot_after_resync` also calls `serve_snapshot`, so its `&TabState` collection will need adjusting to the new `&mut` signature (it currently collects targets then borrows `state.tabs.get(&tab_id)`; make it `get_mut`).

## Testing (critical subtlety)

A normal `ConnettoConnection` tab auto-replenishes: it sends `AckCredits { credits: 1 }` on every applied `SnapshotPatch` and `LivePatch` (`connetto-client/src/lib.rs` `ack_one`, called at lib.rs:951 and 959). So a pumped client never stalls the window. To test the hub gating deterministically, the test tab MUST be a raw frame-level loopback client that withholds `AckCredits`:

- Attach a raw `LoopbackTransport` tab end (like the raw-client leg in `relay.rs` test 2). Hand-send `Handshake`, receive `HandshakeAck` (note `initial_credits`), hand-send a `Subscribe`.
- Drive a fake upstream to emit more than `initial_credits` bulk frames (`LivePatch`), and count how many `TabOut::Bulk` frames arrive at the raw tab end WITHOUT acking. Account for the subscription's own `SnapshotPatch` consuming one credit.
- Assert the count stops at the window, then hand-send `AckCredits { credits: K }` and assert exactly `K` more drain, in FIFO order.
- Self-contained fake-upstream pattern, no server or Postgres. Model on `examples/wasm-smoke/tests/resync.rs` / `conflict.rs` / `nonfatal.rs`.

## Gate commands

- Standalone `connetto-web`: `cd crates/connetto-web && cargo +stable fmt --check && cargo +nightly clippy --target wasm32-unknown-unknown --all-targets -- -D warnings && RUSTDOCFLAGS="-D warnings" cargo +stable doc --target wasm32-unknown-unknown --no-deps`.
- Standalone `examples/wasm-smoke`: `cargo +stable fmt --check && cargo +nightly clippy --target wasm32-unknown-unknown --all-targets -- -D warnings`.
- Browser: `wasm-pack test --headless --chrome examples/wasm-smoke` (full), or `--test <name>` for one file (put `--test` BEFORE any `--`).
- Root workspace is untouched by relay work (its 4 members do not depend on `connetto-web`), so root gates are unaffected. Run `cargo fmt` after edits (rustfmt reflows multi-line `send` chains; both Phase 3 and Phase 4 needed one `cargo +stable fmt` pass).

## Environment state at handoff

- Docker `connetto-demo-pg` (postgres:16, port 55456, `wal_level=logical`) left UP. Server process STOPPED.
- Server launch recipe (needs rebuild each session): `cargo +stable build -p connetto-server --features pg-async --bin connetto-server`, then `hub start` name `connetto-server`, app `./target/debug/connetto-server`, env `CONNETTO_BIND=127.0.0.1:7777 DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55456/postgres CONNETTO_PG_DDL_FILE=examples/wasm-smoke/schema.sql CONNETTO_WRITABLE=orders`, ready log `listening on 127.0.0.1:7777` plus port 7777. Phase 5's own test is self-contained, but the FINAL full-suite run needs the server up.
- Known flake: the full 13-file browser suite reproducibly SIGKILLs chromedriver at `relay.rs` (heaviest file, around the 10th consecutive) from transient browser resource pressure, not OOM (866 GB free) and not a regression. `relay.rs` passes standalone on retry. When the full suite dies there, run `relay.rs` (and any files after it: `resync`, `smoke`, `topology`) individually to complete coverage.

## Edit-tool hazard (bit both prior phases)

Line numbers shift after each edit; the `#TAG` in the edit response is the fresh anchor. Re-read or anchor on the returned tag after every edit. `_edit`/`_read` match by filename when the path is ambiguous; use full paths for common filenames like `Cargo.toml`.

## Next steps

1. Read the Phase 5 section of `docs/plan-relay-parity.md` (lines ~128-142) and the server credit code (`session.rs` `enqueue_and_flush`/`flush`/`AckCredits`, lines ~1506-1533 and 946-951).
2. Get browser-run approval for Phase 5.
3. Write the failing raw-tab credit-window test first, show RED, implement per-tab credit accounting, show GREEN.
4. Run standalone gates plus the full browser suite. Update `docs/plan-relay-parity.md` (table row, Status note, progress line) before reporting.
5. Report and stop at the phase boundary. Do not commit unless explicitly told.

## Prompt to start Phase 5

Start Phase 5 of `docs/plan-relay-parity.md`: per-tab delivery-credit flow control in the browser `RelayHub` (`crates/connetto-web/src/relay.rs`), matching `connetto-server`'s credit window so a relay tab sees identical backpressure to a direct client.

Mirror the server mechanism in `crates/connetto-server/src/session.rs` (`enqueue_and_flush`/`flush`, `AckCredits` arm, `SessionState.credits`/`pending`): only `LivePatch` and `SnapshotPatch` are credit-gated, control frames never are, initial window is 64. Add `credits` and a `pending` `VecDeque<BulkMessage>` to `TabState`, route the three bulk-send sites (`handle_worker_event` LivePatch routing, `handle_local_mutation` fan-out, `send_snapshot_patch`) through an enqueue-then-flush helper, and make the `AckCredits` tab arm add credits and flush. Keep the shovel unbounded; the credit accounting lives in the hub core.

Test-first, and note the gotcha: a normal `ConnettoConnection` auto-acks one credit per applied patch (`ack_one`), so the credit-window test must use a raw frame-level loopback tab that withholds `AckCredits`, counts bulk frames up to the window, then acks and sees the rest drain in FIFO order. Self-contained fake-upstream test, no server or Postgres, modeled on `tests/resync.rs`/`conflict.rs`/`nonfatal.rs`.

Follow the constraints: ASCII-only prose, no commits without an explicit instruction, re-ask before any browser run. Run the standalone `connetto-web` and `wasm-smoke` gates plus the full browser suite, and update `docs/plan-relay-parity.md` (the `AckCredits` table row, a Phase 5 `Status: landed` note, and the Progress line) before reporting. Stop at the phase boundary.
