# Handoff: dioxus-web demo browser verification

## Where the repo is

Branch `main`, HEAD `15d1f17` ("Add schema-version staleness detection and align the relay handshake ack"). The relay-parity plan (`docs/plan-relay-parity.md`, Phases 0 through 7) is fully landed and green: aggregates, full resync, conflict-versus-reject, non-fatal errors, per-tab delivery credits, handshake-ack schema-version forwarding, and server-gated schema-version staleness detection. A tab behind the relay is indistinguishable from a direct socket in every frame the client acts on.

Uncommitted on `main` right now: the `docs/roadmap.md` prune (the stale "relay limits still open" paragraph rewritten to say parity is complete) and these two verification docs. Historical docs from earlier arcs (`docs/handoff-frontend-only-tables.md`, the `docs/upstream-*` proposals, `docs/plan-connetto-server.md` which MUST never be staged) are unchanged.

## The demo is already built. This session verifies it.

`examples/dioxus-web-demo` is feature-complete in code and compiles for `wasm32-unknown-unknown` (`cargo check --target wasm32-unknown-unknown` clean, one pre-existing `non_snake_case` warning on `App`). It has never been run in a real browser. That run, end to end, is the entire task.

What the code already does (`src/main.rs`):
- `main` runs Dioxus in a window context and returns early in a worker context. `db_worker_boot` is the `wasm_bindgen` export the worker bootstrap (`assets/db-worker.js`) awaits.
- `boot_window` joins the Web Locks leader election (`LEADER_LOCK`), the winner spawns the dedicated DB worker, every window holds a tab liveness lock before connecting, connects a tab client over a `BroadcastChannel`, and wraps it in the reconnecting client.
- `App` boots the window and shows a status line. `Dashboard` renders two panes: `orders` (synced, an "Add order" button) and `notes` (device-only, a text input plus "Save note"), both fed by `use_live` against the local mirror. Order totals are derived from the live rows.
- Schema-version baking is wired: the tab config and the `DbWorkerConfig` carry `SchemaVersion::from_source(SCHEMA_SQL)` where `SCHEMA_SQL = include_str!("../schema.sql")`.

## Critical prerequisite (a direct consequence of Phase 7)

Detection is now server-gated and mandatory: if the server advertises a schema version, a client that does not present the matching one is rejected at handshake with `SchemaOutdated`. So the DB worker will fail to boot unless the server's advertised version matches the demo's baked version.

The demo bakes `from_source(examples/dioxus-web-demo/schema.sql)`. That file is byte-identical to `examples/wasm-smoke/schema.sql` today (verified: both are `CREATE TABLE orders (id BIGINT PRIMARY KEY, quantity BIGINT);`), so the existing server recipe (`CONNETTO_PG_DDL_FILE=examples/wasm-smoke/schema.sql`) already produces a matching hash. If the demo's `schema.sql` ever diverges, launch the server with the demo's `schema.sql` instead, or the worker connect is rejected as stale.

## Running the stack

- Docker `connetto-demo-pg`: `postgres:16` on port 55456, `wal_level=logical`, long-lived, holds `orders`, `connetto_slot`, `connetto_pub`, `_connetto_mutations`. Confirm it is up (`docker ps`) and provisioned before starting the server.
- Server (needs rebuild each session): `cargo +stable build -p connetto-server --features pg-async --bin connetto-server`, then start via `hub` (`op:"start"`, name `connetto-server`, app `./target/debug/connetto-server`) with env `CONNETTO_BIND=127.0.0.1:7777`, `DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55456/postgres`, `CONNETTO_PG_DDL_FILE=examples/wasm-smoke/schema.sql`, `CONNETTO_WRITABLE=orders`, ready log `listening on 127.0.0.1:7777` plus port 7777.
- Demo dev server: `dx` is installed (dioxus 0.7.9). From `examples/dioxus-web-demo`, `dx serve` builds the wasm (picking up `--cfg=web_sys_unstable_apis` from `.cargo/config.toml`, needed for Web Locks) and serves at a localhost port (watch the `dx serve` banner for the URL, typically `http://127.0.0.1:8080`). `dx serve` is long-running, so launch it via `hub` (`op:"start"`) and wait for its served-URL banner. The first wasm build is slow.
- Ports already taken on this machine: 5432, 5433, 5459, 5462, 3306, 55456.

## Driving it with the browser tool

Use the `xd://browser` device (real Chromium via puppeteer, headless works, OPFS and Web Locks and Workers all supported).

1. Single window: `open` the served URL as tab `w1`, `run` `tab.observe()` (or `tab.ariaSnapshot()`), confirm status becomes `connected` and both panes render. Click "Add order", re-observe, confirm a row appears and the count/total update. Type a note body into the input, click "Save note", confirm the note row appears.
2. Two windows of one device: `open` a SECOND tab `w2` to the same URL. Same origin means it shares OPFS, the `BroadcastChannel`, and Web Locks, so `w1` is the leader owning the worker and `w2` is a follower. Add an order in `w1`, confirm it converges into `w2` (this proves the Postgres CDC round trip: tab to hub to worker to server to CDC back to every tab). Save a note in `w1`, confirm it converges into `w2` (hub fan-out, never the server).
3. Proof that orders reach Postgres and notes do not: query `connetto-demo-pg` (`docker exec ... psql`), the new order id is in `orders`, and there is no `notes` table server side (the worker replica does not even contain it).
4. Optional, leader failover: `close` the `w1` tab, confirm `w2` wins the lock, spawns a replacement worker that resumes the OPFS replica from its persisted cursor, and keeps serving. This reuses the failover path `tests/failover.rs` already pins.

Capture evidence (a11y snapshots or screenshots) for each claim.

## Gotchas

- Browser runs, Docker, and any dev server need FRESH per-time approval this session. Re-ask before `dx serve` and before the browser tool.
- OPFS persists across runs in the same browser profile. A stale replica can mask a first-boot bug: if results look wrong, clear OPFS or use a fresh profile. The worker deliberately resumes from the persisted cursor, so "no snapshot on reboot" is expected, not a bug.
- The demo id scheme is per-window random-banded so concurrent windows never collide on ids.
- `dx serve` rebuilds on file change. Do not edit demo files mid-run unless intending a rebuild.
- Known unrelated flake: the `wasm-pack` browser suite occasionally SIGKILLs chromedriver at the heavy `relay.rs` file. Not relevant to `dx serve`, but browser resource pressure is a recurring theme, so drive the demo tabs deliberately, not in a tight loop.

## Toolchain and standing rules

- Toolchain trap: the default nightly ICEs compiling tokio in release. Tests: `cargo +stable test --release`. Clippy: `cargo +nightly clippy ... -D warnings` (the repo allows `clippy::unused_async_trait_impl`, unknown to stable). fmt: `+stable`.
- No commit, push, PR, or deploy without an explicit per-time instruction. `dx bundle`, `pages deploy`, Wrangler, and deploy-pattern tags are deploys. ASCII punctuation only in all prose and comments (no semicolons, no em or en dashes, no ` - ` as punctuation). Single-line commit messages, no conventional-commit prefixes, no `Co-Authored-By`. Pursue the long-term optimal design, no shortcuts.

## What "done" looks like

Two browser windows converge on `orders` (through Postgres) and on `notes` (through the DB worker, device-only), writes work from both panes, and the evidence is captured. If verification surfaces a bug, fix it at the source and re-verify. When it is clean, prune the roadmap's "wasm client, after the spike" section to mark the dioxus-web demo verified, and the next browser-track item is the Yew adapter on top of `LiveHandle`.

## Prompt

The starting prompt for this session lives in `docs/prompt-dioxus-web-demo.md`.
