# Implementation roadmap

Open implementation work, in recommended order. Architecture decisions live in `docs/architecture/open-questions.md`, this file tracks what remains to build and why. Prune entries as they land.

## wasm spike first, validation before construction

The wasm client work starts BEFORE the robustness pass, deliberately. The reconnect state machine must be shared across native and wasm (see the constraint below), and its seams are speculative until wasm exists to test them. The disalignment that motivated this ordering is RESOLVED: `ConnettoConnection` was built on two SQLite connections to the same file (captured plus uncaptured sibling), which `sqlite-wasm-rs` cannot express (no multiple connections on any VFS). It now holds ONE connection, with capture suspended around server patch applies and rollbacks (`Session::set_enabled` behind a re-enable drop guard), on native and wasm alike. The `loop_emu` suite (echo prevention, rollback, conflict convergence, refresh) passes unchanged on the unified topology.

The spike's goal is to falsify assumptions, not to ship. First findings, all positive:

- **Unification is possible with zero upstream changes.** `diesel-sqlite-session` already exposes `Session::set_enabled` over `sqlite3session_enable` and pins the contract in its integration tests (a write with tracking disabled is not captured, a write after re-enable is). connetto has exactly two capture bypass sites, `apply_patch` (server patches) and `rollback` (inversion of rejected writes), both behind the `apply` connection. Each becomes a disable window with a re-enable guard on the single connection. The WAL pragma is harmless on a VFS without WAL support (SQLite returns the old journal mode, no error), and single connection mode does not need WAL at all.
- **The client core already compiles for wasm32-unknown-unknown.** `cargo check -p connetto-client --target wasm32-unknown-unknown --no-default-features` passes: diesel (the fork has first class wasm sqlite over `sqlite-wasm-rs`), the session extension, zstd, sqlparser, and subql's typed render all cross compile. The only native coupling was the `native-transport` feature (now default on, off for wasm) and one `tokio::spawn`, now split as `ConnettoClient::with_pump` returning the pump future for the caller to drive (`spawn_local` on wasm) with `start` as the feature gated native convenience.
- **The MaybeSend seam is cut and the browser smoke PASSES.** `connetto_core::traits::MaybeSend` is `Send` on native (supertrait plus blanket impl, so native bounds are unchanged) and vacuous on wasm, where transport futures hold JS values and can never be `Send`. The `Transport` methods and the client's transport riding bounds use it, the dispatch layer included, so the whole typed `live()` surface compiles for wasm32. `examples/wasm-smoke` (standalone workspace) holds a `web_sys` WebSocket transport reusing `connetto_core::codec` framing (the wire tags moved there from the feature gated native transport module), and its dedicated worker test `full_sync_loop_in_a_dedicated_worker` runs green in headless Chrome against the real `connetto-server` and Postgres: connect, subscribe with a server translated query, snapshot, a captured local diesel write pushed and applied, the replication echo applied under capture suspension, and a second push proving the echo was NOT recaptured. This is also the full cdylib link proof for the dependency stack. Run it with the demo stack up: `wasm-pack test --headless --chrome examples/wasm-smoke`.

Remaining in the spike: OPFS sahpool first boot from the baked replica template (the smoke runs on the memory VFS), the pump under `spawn_local` via `ConnettoClient::with_pump` exercised in the browser, then the platform seams are written down from evidence and reconnect is built once on top of them.

## Browser topology and the tab proxy (decided)

Decisions from the design discussion, in force for everything below:

- **Topology: SharedWorker plus one nested dedicated DB worker.** OPFS sync access handles exist only in dedicated workers, so the whole client core (SQLite on sahpool, the capture session, the pump, and the WebSocket, which dedicated workers support) lives in the nested worker. The SharedWorker is the per origin singleton that owns that one nested worker and multiplexes tabs. Nested workers work in Chrome, Firefox, and Safari 15.4 and later.
- **Tab query surface: a diesel `Proxy` backend, staged in two phases.** The tab renders typed queries to SQL plus binds locally (rendering is pure) and decodes returned rows through a custom lightweight backend that declares Sqlite's `SqlDialect` choices (identical SQL rendering from diesel's generic impls) plus `FromSql` impls over typed MessagePack wire values. App structs change nothing, `Queryable` derives are backend generic. Phase one ships connetto verbs (`use_live` parity, an atomic `batch`, a typed `load`). Phase two adds the formal `diesel_async::AsyncConnection` impl on top, additive over the same backend. The known risk is diesel-async's `Send` bounds against the tab's `!Send` postMessage futures: single threaded wasm can carry a SendWrapper style shim, and if diesel-async needs a `?Send` story that becomes an uphill doc, never a workaround, phase one does not wait on it.
- **Transactions from the tab: forbidden.** Writes are single statements or one atomic batch executed in a single worker round trip inside one transaction. The phase two `TransactionManager` errors on interactive `begin`. No tab can starve the database.
- **Refresh recall across the boundary.** The DB worker holds the real `LiveQuery` and `LiveValue` handles in a registry keyed by proxy subscription id. Each `changed()` firing pushes the serialized snapshot `{sub_id, rows}` through the SharedWorker to every subscribed tab, whose `use_live` mirror sets its signal and re-renders. Tab mirror drop sends the unsubscribe, preserving the RAII chain end to end. Dead tab cleanup needs heartbeats or `navigator.locks` liveness, SharedWorker ports have no reliable close event.

Remaining after the spike: the SharedWorker router and nested worker wiring, the tab proxy phases above, the dioxus-web demo, and the Yew adapter.

## Robustness pass

**Client reconnect.** A transport drop kills the pump and strands every `LiveQuery` and `LiveValue`. The pieces already exist: the client registry holds each subscription's SQL and binds, the server keeps per subscription resume cursors with oplog catchup (`docs/architecture/06-reconnect.md`), and `connect_with_replica_template` reuses an existing replica untouched. What remains is the client side loop: re-establish the transport, re-handshake with the persisted cursor, re-subscribe every registered query, and resume the pump without dropping handles. Production claims wait on this.

**Constraint: one reconnect state machine for native and wasm.** The backoff policy, cursor resume, re-subscribe ordering, pending mutation replay, and the event vocabulary the UI observes are correctness, and correctness written twice diverges. The state machine must be a single shared implementation, generic over a transport factory (make a new connection), a timer for backoff, and the driving mode, with no tokio types and no gratuitous `Send` bounds inside it (the `Send` question is the known wasm seam, `docs/architecture/09-wasm.md`). Native injects `TcpStream` plus `tokio`, wasm injects the browser WebSocket plus `spawn_local` inside the `SharedWorker`, and neither reimplements the loop. Building it native first with `tokio::spawn` baked in means rebuilding it for wasm, which Q0.3 forbids.

**Snapshot failure should not kill the session.** A snapshot error in `subscribe_row` tears down the whole session (`session ended: snapshot error`), taking every other subscription with it, aggregates included. It should surface as a `NonFatalError` scoped to the one subscription, leaving the session and its siblings alive. Found during the real Postgres desktop e2e when the dialect bug made every snapshot fail.

## Frontend-only tables

Decided model, not yet built. Existence is controlled by cfg features in the generated schema crate (a table absent from a tier cannot be imported there), placement is the schema qualifier, and writability is enforced physically.

- `ConnettoConnection` attaches a second database as schema `frontend` and creates the capture session on `main` only, so frontend-only tables are physically incapable of uploading. Today a write to a table the server does not accept is captured, uploaded, rejected, and rolled back, which destroys device-private data.
- `live()` dispatches on the schema qualifier in the rendered SQL: a query over `frontend.*` registers no server subscription and refreshes from local writes alone.
- Read-only synced tables need no new machinery: pg2sqlite's role-aware translation already emits deny triggers that fail the write synchronously at the statement (`translate_create_table_for_role`), with the server catalog as the version skew backstop.
- The demo gains a `frontend.drafts` table with a save button, proving across three windows that a draft never crosses the wire.
- A synql generation contract doc in the `upstream-*` style: cfg features per tier, DDL split (`main` replica, `frontend` attached, plus the baked template file), and the role facts pg2sqlite already consumes. Deferred cell, documented there: a table visible in the frontend for live aggregates but never replicated has no home yet, since cfg visibility implies presence.

## Replica retention and eviction

The replica holds the union of subscribed query results, so bloat control decomposes into rotating time-windowed subscriptions (a standing `WHERE created_at > X` fixes `X` at registration, rotation means periodic re-subscribe with a fresh bound) and local eviction of rows no active subscription covers. Eviction MUST run with capture suspended (the same `SuspendedCapture` window server patches use): through live capture it would be recorded and sync to the backend as real deletes. Interplay with resume cursors and per table retention declared in the synql schema needs its own design doc before any code.

## wasm client, after the spike

De-risked so far: `sqlite-wasm-rs` compiles and links SQLite 3.53 with `SQLITE_ENABLE_SESSION` and `SQLITE_ENABLE_PREUPDATE_HOOK` for `wasm32-unknown-unknown` with the stock toolchain, and the template based first boot (`connect_with_replica_template`) maps directly onto OPFS as fetch bytes, write file, no DDL execution. The spike above settles the topology, the transport, and the driving mode. What remains afterward is the full client: the `SharedWorker` topology (Q1.3), the dioxus-web demo verified in a real browser, and the Yew adapter on top of `LiveHandle`.

## Smaller deferred items

- `watch_fn(|| build_query())` closure variant for boxed and dynamic queries, which cannot carry the compile time dispatch markers.
- Subscription dedup by SQL hash, so identical queries from many components share one server subscription.
- `LiveValue` decode support for custom user-declared aggregates beyond the built-in family.
- Awaitable mutation confirmation, undecided: a typed write verb was rejected as over-engineering, but flows that take irreversible actions after a write still have no way to await the server verdict short of watching the events stream by hand.
- The demo id scheme (pid banded integers) stands in for a real distributed key strategy, UUIDs or server issued ranges.
