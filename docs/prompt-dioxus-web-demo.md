# Prompt: verify the dioxus-web demo in a real browser

Read `docs/handoff-dioxus-web-demo.md` first, then verify the `examples/dioxus-web-demo` app end to end in a real browser.

The demo is already feature-complete in code and compiles for `wasm32-unknown-unknown`. It has never been run in a browser. Your job is to run it and prove the connetto browser topology works: a leader window owns one dedicated DB worker (OPFS replica, server connection, relay hub, device-private tier), and every window runs a tab client over a `BroadcastChannel` with live queries against a local SQLite mirror.

Bring the stack up and drive it:

1. Confirm the Docker `connetto-demo-pg` (postgres:16, port 55456, `wal_level=logical`) is up and provisioned. Rebuild and start `connetto-server` on 7777 with `CONNETTO_PG_DDL_FILE=examples/wasm-smoke/schema.sql` and `CONNETTO_WRITABLE=orders` (the demo's `schema.sql` is byte-identical, so this version matches). Serve the demo with `dx serve` from `examples/dioxus-web-demo` (dioxus 0.7.9 is installed) and note the served URL.
2. Using the `xd://browser` tool, open the served URL, confirm the status reaches `connected` and both panes render, then click "Add order" and "Save note" and confirm each row appears with the count and total updating.
3. Open a second tab to the same URL (a second window of the same device). Confirm an order added in one window converges into the other (the full Postgres CDC round trip), and a note saved in one window converges into the other through the hub without ever reaching the server.
4. Prove the tier boundary: the new order id is present in Postgres (`docker exec ... psql`), and there is no `notes` table server side.
5. Optional but valuable: close the leader window and confirm a follower wins the Web Locks election, spawns a replacement worker that resumes the OPFS replica from its persisted cursor, and keeps serving.

Capture evidence (a11y snapshots or screenshots) for each claim. The critical Phase-7 consequence to remember: detection is now server-gated, so if the server's advertised `schema_version` does not match the demo's baked `from_source(schema.sql)`, the DB worker is rejected at handshake with `SchemaOutdated` and the demo cannot boot. That is the first thing to check if the worker never comes up.

Follow the standing rules: browser runs, Docker, and dev servers need fresh per-time approval, so ask before `dx serve` and before driving the browser. ASCII punctuation only. No commit, push, or deploy without an explicit per-time instruction (`dx bundle` and `pages deploy` are deploys). Toolchain trap: default nightly ICEs on tokio release, so use `+stable` for tests and builds and `+nightly` for clippy.

If a bug surfaces, fix it at the source and re-verify rather than papering over it. When the demo is verified clean, prune the roadmap's "wasm client, after the spike" section to mark the dioxus-web demo verified, and tee up the Yew adapter on `LiveHandle` as the next browser-track item.
