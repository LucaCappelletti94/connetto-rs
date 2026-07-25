# Next session: the dioxus-web demo

## Goal

Build the dioxus-web demo: a real browser page, built with Dioxus 0.7 for wasm32, that exercises the shipped browser topology end to end and is verified in a real browser against the real server and Postgres. This is the roadmap's remaining "wasm client, after the spike" item, and it subsumes the save-button UI of the three-window notes demo: three browser windows of the same app, a synced `orders` list that converges through Postgres, and a device-private `notes` list with a save button that converges across the windows through the DB worker while never reaching the server. The Yew adapter is a later arc, not this session.

Every layer below the UI already exists and is proven by the browser test suite: leader election (`leader::join`), the dedicated DB worker owning the OPFS replica and the local tier file, per-tab `BroadcastChannel` transports with dead-worker detection, client reconnect, the relay hub with local tier fan-out, and the `connetto-dioxus` `use_live` hook. The session's work is packaging, wiring, and UI, plus one structural decision.

## The structural decision to make first

The browser platform machinery (`leader.rs`, `workers.rs`, `relay.rs`, `broadcast.rs`, `port.rs`, `locks.rs`) lives inside `examples/wasm-smoke`, a test scaffold crate. The demo needs all of it. Decide where it lives long term:

1. Promote it into a real crate (for example `crates/connetto-web`) that both the smoke tests and the demo consume. This is the long-term optimal shape: the machinery is product code, proven by tests, and a demo depending on a test crate inverts the dependency direction. The demo constants (`DEMO_WS_URL`, DDL strings, template bytes) stay behind in the smoke crate or move to the demo, since a library crate must not bake demo schemas.
2. Depend on `connetto-wasm-smoke` from the demo workspace. Cheaper today, but it is a shortcut wearing a costume: the demo would ship test scaffolding, and the smoke crate's `build.rs` bakes demo templates the library consumer cannot control.

Lean toward promotion, but scope it honestly: move the six platform modules, keep the smoke crate as tests plus demo constants, and let the demo workspace mirror the root patch blocks the way `examples/dioxus-desktop-demo/Cargo.toml` already documents (verbatim branch refs, the lockfile does the pinning). If promotion is chosen, it is the first deliverable and the smoke suite must stay green after the move.

## The decisions that follow

1. Worker packaging under a dioxus-web build. The DB worker is spawned from a JS glue file (`db-worker.js` loads the wasm module and calls `db_worker_boot`). In the test harness the glue URL is recovered from `performance.getEntriesByType("resource")`, a trick that works because wasm-bindgen-test serves the module at a known place. A dioxus-web app built and served by `dx` has its own asset story and its own wasm module URL. Decide the mechanism: a dioxus asset for the worker JS, the module URL discovered at runtime or injected at build, and whether the app wasm and the worker wasm are the same module (they should be, `db_worker_boot` is a `wasm_bindgen` export of the same crate) or separate builds. This is the genuinely new engineering of the session. Verify against Dioxus 0.7 asset documentation, not memory.

2. App boot flow per window. Every window runs the same sequence the tests pin: `leader::join(shared_lock, glue_url)` (the winner spawns the worker), `await_db_worker_ready()`, hold the tab liveness lock BEFORE connecting, connect a tab client over `tab_wire_factory` with `ConnettoClient::with_reconnect` and the browser sleeper, then register live queries. Decide how this maps onto Dioxus app lifecycle (a resource or coroutine that owns the client before the first render, error surface when the stack is down).

3. UI surface. Synced pane: live `orders` list plus a `COUNT(*)` or `SUM(quantity)` aggregate via `use_live`, and an "add order" button writing through the tab (insert on the mirror, then `push`). Local pane: live `notes` list, a text box and save button writing `notes`, visibly badged as device-only. Status line: `Reconnecting`/`Reconnected`/`MutationApplied`/`MutationRejected` events surfaced from the client event stream, so the demo shows the ack story. Keep the UI minimal, the demo is the topology, not the styling.

4. Schema source. The desktop demo bakes its own `schema.sql` via `build.rs`. The web demo's tab mirrors need `DEMO_TAB_DDL` shape (both tiers in the tab's main schema) and the worker needs the two baked templates. Decide whether the demo reuses the smoke crate's `schema.sql` plus `frontend.sql` documents verbatim (lean yes, one demo schema everywhere) and where the bake happens after the promotion decision.

5. External writer stand-in. The desktop demo has backend writer buttons over direct Postgres, impossible from a browser. Options: drop it (tab writes already round trip through Postgres and echo to every window, which demonstrates convergence), or keep a tiny native side script for demos. Lean: drop it, a second window IS the external writer in this topology.

6. Aggregate over notes. Local aggregates work in the single-context tier client, but a TAB's notes queries ride the hub as ordinary subscriptions, and the hub does not serve aggregate subscriptions (a recorded relay limit). If a notes count is wanted in the UI, either count rows client-side from the live Vec (lean, trivial) or extend the hub, which is out of scope.

## Deliverable

A standalone `examples/dioxus-web-demo` workspace (plus the promoted platform crate if that is decided) that builds with `dx` for wasm32, runs against the demo stack (server on 7777, `connetto-demo-pg` on 55456), and demonstrably converges three windows: an order added in window A appears in B and C via Postgres CDC, a note saved in window A appears in B and C via the hub and survives a full browser restart, and the server database never contains a notes table. Verification is a manual three-window walkthrough in a real browser (record what was exercised), plus the existing browser suite staying green if the platform modules moved. No new test harness is required for the UI itself, but any promoted crate keeps its tests.

## Grounding to read first

- `docs/roadmap.md`: "Local-only tables" (the fan-out contract just built), "Browser topology and the relay", "wasm client, after the spike".
- `examples/wasm-smoke/src/workers.rs` (`db_worker_boot`, `tab_wire_factory`, `DEMO_TAB_DDL`, the hello-channel rendezvous) and `tests/notes_fanout.rs` plus `tests/topology.rs` (the exact boot sequence a window must reproduce).
- `crates/connetto-dioxus/src/lib.rs` (`use_live`, `LiveHandle` ownership and drop-unsubscribe) and `examples/dioxus-desktop-demo/src/main.rs` (the desktop shape: setup, hook usage, writer plumbing, and the workspace/patch-block pattern its `Cargo.toml` documents).
- `examples/wasm-smoke/db-worker.js` and `src/leader.rs` for how the worker is spawned and what the glue URL must point at.

## Constraints

ASCII punctuation in all prose. No commit, push, PR, or deploy without explicit per-time instruction, and `dx bundle` or any pages deploy is a deploy. Browser runs and Docker need fresh per-time approval. No shortcuts: the long-term best version, requirements recorded separately from mechanisms, every tradeoff claim verified against source or docs before it is presented, an interim step needs a named blocker. Do not weaken a requirement to preserve a mechanism.
