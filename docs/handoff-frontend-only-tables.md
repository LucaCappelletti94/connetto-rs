# Handoff: entering the frontend-only tables design session

## Where the repo is

Branch `main`, commit `bad5f24` just landed. It squashed the full uncommitted local-first stack into one commit: browser relay topology (increments 1 through 3), the client reconnect and cursor-persistence robustness pass, exactly-once mutation uploads, and the multi-page leader election helper. The only dirty path is `docs/plan-connetto-server.md`, which is permanently dirty and MUST never be staged.

The `docs/roadmap.md` DONE sections are the authoritative record of what shipped and its named limits. Read the "Browser topology and the relay", "Multi-page leader election (DONE)", and "Robustness pass (DONE)" sections there before touching anything.

## What the last session built (leader election)

`examples/wasm-smoke/src/leader.rs` holds `leader::join(leader_lock, glue_url) -> Membership`. Every page calls it with one shared leader lock name, Web Locks serializes the requests across all same-origin contexts, and the winner owns the dedicated DB worker. Handover rides the browser's own liveness: a leader's context death releases the lock and terminates its child worker, the next queued request wins, and the new leader spawns a replacement worker that resumes the OPFS replica from its persisted cursor. Tabs reconnect through the existing reconnect machinery, so handover reuses the failover path. `Membership::is_leader()` exposes the role, and dropping a `Membership` resigns (terminate worker, release lock) so tests can model context death. `topology.rs` now elects through the helper. Proof is `tests/election.rs` (`election_promotes_a_survivor_and_serves_the_tab`).

Named limit, recorded in the roadmap: dropping a `Membership` that has not yet won leadership leaves its queued lock request pending until context death, because the browser only cancels a not-yet-granted request on context death. Real pages resign by dying, where this is a non-issue.

## Verification state

All eight browser tests pass in headless Chrome against a real server and Postgres: `election`, `failover`, `opfs`, `page`, `relay` (two), `smoke`, `topology`. `cargo fmt` and `cargo clippy --target wasm32-unknown-unknown --tests` are clean on the wasm-smoke workspace.

## Running stack (may still be up)

- `connetto-demo-pg`: docker `postgres:16` on port 55456, `wal_level=logical`. It already holds the `orders` table, the `connetto_slot` replication slot, and the `connetto_pub` publication.
- `election-verify-server`: a hub-managed process running the freshly built dev `target/debug/connetto-server` on `127.0.0.1:7777`, env `CONNETTO_BIND=127.0.0.1:7777`, `DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55456/postgres`, `CONNETTO_PG_DDL_FILE=examples/wasm-smoke/schema.sql`, `CONNETTO_WRITABLE=orders`. This binary is current (it sends `MutationApplied`), unlike the old dead `demo-server`. Reuse it for browser runs, or stop it with `hub stop election-verify-server`.

## Toolchain blocker (unchanged)

Default nightly `1.99.0-nightly` ICEs compiling tokio at opt-level 2 or 3, so every release build on nightly fails. Workaround: run release gates with `cargo +1.97.0 test --release --all-features`. Dev, check, clippy, and doc run fine on default nightly. A dev build of `connetto-server` works (that is how the running server was built).

## Full gate recipe

Root workspace: `cargo fmt`, then nightly `cargo clippy --all-targets --all-features -- -D warnings`, then `cargo +1.97.0 test --release --all-features`, then `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`. Standalone workspaces `examples/wasm-smoke` and `examples/dioxus-desktop-demo` get `cargo fmt` each. Browser suite: `WASM_BINDGEN_TEST_TIMEOUT=90 wasm-pack test --headless --chrome examples/wasm-smoke` with a server on 7777.

## Standing rules

No commit, push, PR, or deploy without an explicit per-time instruction. ASCII punctuation in all prose (no semicolons, no em or en dashes, no ` - ` as punctuation), including doc comments, panic strings, and design docs. Single-line commit messages, no conventional-commit prefixes, no `Co-Authored-By`. No shortcuts: pursue the long-term optimal design, record requirements separately from the mechanisms that serve them, and treat every tradeoff-table cell as a claim to verify. An interim step needs a named blocker, not a price tag.

## Next session

Goal is a design discussion, not code: how to characterize local-only (frontend-only) tables cleanly. The framing and the open questions live in `docs/prompt-frontend-only-tables.md`. The current decided-but-unbuilt sketch is the "Frontend-only tables" section of `docs/roadmap.md`.
