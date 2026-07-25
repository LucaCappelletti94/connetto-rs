# Handoff: entering the dioxus-web demo session

## Where the repo is

Branch `main`, HEAD `adf3943`. The last two sessions landed three commits on top of `efa75d0`:

- `95c5fda` converged every upstream pin: subql `5858f50` (pins sqlite-diff-rs 0.8.0), diesel fork branch `future` at `2c114c6d` (carries `attach_database`/`detach_database`, `set_triggers_enabled`, and the attach hardening knobs), pg2sqlite `d024713` (reference-closed FK validation default on, PR #46), `sqlite-diff-rs = "0.8.0"` workspace wide. Both lockfiles updated.
- `e82f594` moved `_connetto_mutations` provisioning from per-handshake writer-pool DDL to a startup call on the admin pool (`provision_watermark_table`), because Postgres 15+ checks schema CREATE privilege on `CREATE TABLE IF NOT EXISTS` even when the table exists, and handshake DDL races. Fixtures repaired to match.
- `adf3943` is the whole local-only tables arc: client tier machinery (`attach_local_tier`, `attach_local_tier_ddl`, `local_tables`, tier-aware live dispatch with local aggregates through the `json_quote` probe), demo wiring (`frontend.sql`, per-document template bake, `DEMO_TAB_DDL`), the relay hub's local tier fan-out, and four test files pinning it all.

Dirty but intentionally uncommitted, all other arcs: `docs/plan-connetto-server.md` (permanently dirty, MUST never be staged), `docs/architecture/open-questions.md`, the physical-trimming paragraph in `docs/roadmap.md` (retention arc), `docs/handoff-frontend-only-tables.md`, `docs/prompt-frontend-only-tables.md`, the five `docs/upstream-diesel-*` maintenance proposals (auto-vacuum-mode, incremental-vacuum, page-counters, vacuum-into, wal-checkpoint), `docs/upstream-pg2sqlite-readonly-deny-triggers.md`, and `docs/upstream-synql-tier-generation-contract.md`. The retention arc is BLOCKED on the diesel maintenance uphill, which is why the dioxus-web demo is next despite the roadmap ordering.

## What the last session built (hub fan-out for local tables)

The three-window notes behavior exists below the UI. Key architecture fact, verified against the SQLite session docs and load bearing for everything here: `sqlite3changeset_apply` only ever targets the `main` schema of a connection, so relayed changesets cannot be applied into an ATTACHed tier. Consequences:

- Tab mirrors hold BOTH tiers in `main` (`workers.rs` `DEMO_TAB_DDL`, orders plus notes) and the tab client is completely unmodified. With no attached tier its `local_tables` set is empty, so notes look synced to it and it subscribes and pushes over the wire like any table. The HUB keeps the tiers apart, not the tab.
- The DB worker opens the frontend file as a second connection whose `main` IS `connetto-frontend.sqlite` (`LocalTier` in `examples/wasm-smoke/src/relay.rs`, passed as a new `Option<LocalTier>` parameter on `RelayHub::new`/`with_reconnect`). The worker replica never contains notes, so notes cannot reach the server even through a hub bug (a missing table is skipped by apply, documented semantics).
- `handle_tab_bulk` classifies each tab mutation by the tables its changeset touches. Pure local: applied to the tier database with the per-tab watermark (`_connetto_tab_mutations`) in one transaction, acknowledged by the hub itself (`MutationApplied`, the hub is the tier's terminal authority), and the original compressed payload fanned out as a `LivePatch` to every tab with an intersecting subscription, originator included (idempotent under the client's `server_wins` Replace policy). Pure synced: the pre-existing path. Mixed tiers: rejected, the tab rolls the whole changeset back.
- Immediate per-seq hub acks are safe because the client's `MutationApplied` arm retires the EXACT sequence, not a watermark. Only the handshake `last_applied_seq` is a retire-below bound, now the max of the two per-target watermarks, sound because the hub processes a tab's mutations in order and each lands in exactly one tier.
- Snapshots partition per tier and each part is served from the owning connection (`snapshot_patchset` now takes `&mut SqliteConnection`).

## Verification state

All 10 browser suites green in headless Chrome against the real server and demo Postgres, including the new `tests/notes_fanout.rs` (tab write, hub ack, fan-out to sibling, late-tab snapshot leg, mixed-tier rejection and rollback) and every pre-existing suite (election, failover, local_tier, opfs, page, relay x2, smoke, topology). `cargo fmt` and nightly `cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings` clean on the smoke workspace. The root workspace was untouched by the fan-out session (its full native gate was green at the end of the prior session and its files are committed unchanged).

## Running stack

- `connetto-demo-pg`: docker `postgres:16` on port 55456, `wal_level=logical`, LONG LIVED, left running. Holds `orders`, `connetto_slot`, `connetto_pub`, `_connetto_mutations`.
- No server process is running. Recipe: `cargo +stable build -p connetto-server --features pg-async --bin connetto-server`, then run `./target/debug/connetto-server` with env `CONNETTO_BIND=127.0.0.1:7777`, `DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55456/postgres`, `CONNETTO_PG_DDL_FILE=examples/wasm-smoke/schema.sql`, `CONNETTO_WRITABLE=orders`, ready when port 7777 accepts.
- Ports taken on this machine: 5432, 5433, 5459, 5462, 3306, 55456.

## Toolchain trap (unchanged)

Default rustup toolchain is a nightly that ICEs compiling tokio in release. Tests: `cargo +stable test --release`. Clippy: nightly (the repo allows `clippy::unused_async_trait_impl`, unknown to stable). fmt: `+stable` is fine.

## Full gate recipe

Root workspace: `cargo +stable fmt --all -- --check`, nightly `cargo clippy --all-targets --all-features -- -D warnings`, `cargo +stable test --release --all-features`, `RUSTDOCFLAGS="-D warnings" cargo +stable doc --workspace --all-features --no-deps`. Smoke workspace: `cargo +stable fmt`, `cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings`, and `wasm-pack test --headless --chrome examples/wasm-smoke` with the server on 7777. The dioxus desktop demo workspace gets `cargo fmt` only in the root gate (it needs webkit system libraries and stays out of headless gates).

## Standing rules

No commit, push, PR, or deploy without an explicit per-time instruction. `dx bundle`, `pages deploy`, Wrangler, and deploy-pattern tags are deploys. Docker and heavy compute need per-time approval, and browser runs need fresh per-time approval each session. ASCII punctuation in all prose (no semicolons, no em or en dashes, no ` - ` as punctuation), including doc comments, panic strings, and design docs. Single-line commit messages, no conventional-commit prefixes, no `Co-Authored-By`. No shortcuts: pursue the long-term optimal design, record requirements separately from mechanisms, verify every tradeoff claim against source before presenting it. An interim step needs a named blocker, not a price tag.

## Next session

Goal: the dioxus-web demo, the roadmap's "wasm client, after the spike" remainder, which also delivers the save-button UI of the three-window notes demo. The framing, the decisions to make, and the grounding live in `docs/prompt-dioxus-web-demo.md`.
