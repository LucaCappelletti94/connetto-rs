# Phase 0: platform baseline and the relay-parity test harness

## Where this sits

`docs/plan-relay-parity.md` defines seven parity phases that make the browser relay hub protocol-transparent against the direct server, so the wasm relay topology has the same functionality as a native direct client. Those phases each change protocol behavior. This phase changes none. It establishes the foundation they all stand on: a committed, green platform crate and a reusable test harness that asserts relay-served behavior against direct-server behavior. Every later phase writes its failing test into this harness first, then implements.

## What already exists (state at the start of this phase)

The previous session did the platform promotion but left it uncommitted. Read the working tree before doing anything, it is the substance of this phase:

- `crates/connetto-web` is a new standalone-workspace library holding the six browser platform modules moved out of `examples/wasm-smoke` (`lib.rs` with `BrowserSocket`, `broadcast`, `port`, `locks`, `relay`, `leader`, `workers`). The DB worker orchestration is parameterized: `workers::boot_db_worker(&DbWorkerConfig)` takes the server URL, schema DDL, query, database names, and baked template, so the library bakes nothing app-specific. `leader::join` and `workers::spawn_db_worker` gained an explicit `worker_url` argument (the bootstrap script need not sit beside the wasm glue). It carries the same deny-plus-pedantic lint discipline as the root crates and the `web_sys_unstable_apis` cfg in `.cargo/config.toml`.
- `examples/wasm-smoke` is reduced to its tests plus a thin consumer shim (`src/lib.rs`): it re-exports `connetto-web`, defines the demo schema constants and the baked `FRONTEND_TEMPLATE`, wraps `leader::join`/`spawn_db_worker` to load the co-located `db-worker.js`, and exposes the `#[wasm_bindgen] db_worker_boot`. Every test call site is unchanged.
- `crates/connetto-dioxus` changed: `use_live` relaxed its bound from `Send` to `connetto_core::traits::MaybeSend` (a wasm tab transport is `!Send`), and it now depends on `connetto-client` with `default-features = false` (a dev-dependency re-adds `native-transport` for its own hook test). This is a root-workspace crate.
- `examples/dioxus-web-demo` is scaffolded (the dx web app plus `assets/db-worker.js`, `build.rs`, `schema.sql`, `frontend.sql`). It is a separate concern from parity, parked here (see disposition below).

Verified green last session at compile level: `connetto-web` and `wasm-smoke` build and pass clippy (`--target wasm32-unknown-unknown`, `-D warnings`) and fmt, `connetto-dioxus` builds native and wasm and its native tests compile, the root workspace still resolves exactly its four members. NOT yet verified: the smoke browser suite has not been re-run since the move, and nothing is committed.

## Goal

1. Prove the promotion did not regress anything: the smoke browser suite is green in headless Chrome against the real server and demo Postgres, and the root gate is green for the `connetto-dioxus` change.
2. Stand up the relay-parity test harness: a reusable way to run one live-query scenario against both a direct-to-server client and a relay tab client and assert identical observable behavior (handshake, snapshot rows, live patches, events, values). Establish it with one worked example that already passes (a row live query, which works through both paths today), so phases 1 through 7 copy the template and flip one assertion each.

## Decisions to make

1. Harness home and shape. The natural home is `examples/wasm-smoke/tests` (headless Chrome, real server), with a helper that connects both a `BrowserSocket` direct client and a `BroadcastTransport` relay tab client to the same running stack and drives them through the same steps. Decide whether any parity assertions are cheaper as native or loopback tests (a loopback relay against an in-process server) and split accordingly, since a native test is a faster TDD loop than a browser test. Requirement, not mechanism: each later phase must be able to add a single failing parity assertion with minimal boilerplate.
2. The worked example. Pick a row live-query scenario that passes through both paths today (for example: insert an order via a writer, assert both a direct client and a relay tab client converge on the same rows and the same event sequence). This documents the parity contract and is the template.
3. Demo disposition. `examples/dioxus-web-demo` is not part of parity. Recommended: keep it parked and do not block this phase on the manual three-window walkthrough. Its synced-pane count is derived client-side today because the relay does not serve aggregates, and Phase 1 will let it use a real wire aggregate. Confirm parked, or fold it if you prefer a smaller tree during the parity work.

## Deliverable

A committed-ready, green baseline: `connetto-web` promoted, the smoke browser suite green, the `connetto-dioxus` root gate green, and a relay-parity test harness with one passing worked example that phases 1 through 7 extend. No protocol behavior changes in this phase. Committing requires an explicit per-time instruction, so leave the tree verified and ready, and ask before committing.

## Verification

- Smoke workspace: `cargo +stable fmt --check`, nightly `cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings`, and `wasm-pack test --headless --chrome examples/wasm-smoke` with the demo stack up (all ten existing suites plus the new parity example). Browser runs need fresh per-time approval.
- `connetto-web` standalone: fmt, nightly wasm clippy, both clean.
- Root workspace (for the `connetto-dioxus` change): `cargo +stable fmt --all --check`, nightly `cargo clippy --all-targets --all-features -- -D warnings`, `cargo +stable test --release --all-features`, `RUSTDOCFLAGS="-D warnings" cargo +stable doc --workspace --all-features --no-deps`.

## Running stack

- `connetto-demo-pg`: docker `postgres:16` on port 55456, `wal_level=logical`, long-lived. Holds `orders`, `connetto_slot`, `connetto_pub`, `_connetto_mutations`.
- Server: `cargo +stable build -p connetto-server --features pg-async --bin connetto-server`, run with `CONNETTO_BIND=127.0.0.1:7777`, `DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55456/postgres`, `CONNETTO_PG_DDL_FILE=examples/wasm-smoke/schema.sql`, `CONNETTO_WRITABLE=orders`, ready when port 7777 accepts. Docker and heavy compute need per-time approval.

## Constraints

ASCII punctuation in all prose (no semicolons, no em or en dashes, no ` - ` as punctuation), including doc comments, panic strings, and design docs. No commit, push, PR, or deploy without an explicit per-time instruction. Browser runs and Docker need fresh per-time approval each session. Toolchain trap: the default nightly ICEs compiling tokio in release, so run tests as `cargo +stable test --release` and clippy on nightly. No shortcuts: pursue the long-term optimal design, record requirements separately from mechanisms, verify every tradeoff claim against source before presenting it, and an interim step needs a named blocker.

## Out of scope

Any protocol behavior change. Aggregates, full resync, conflict distinction, non-fatal errors, flow control, handshake and schema-version alignment, and the `SchemaUpdate`/`SchemaBlob` removal are phases 1 through 7. This phase only makes them measurable.
