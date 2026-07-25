# Plan: relay parity with the direct server

## Why this plan exists

The browser dioxus-web work surfaced a structural gap. A browser tab does not talk to `connetto-server` directly. It talks to the `RelayHub` in the DB worker (`crates/connetto-web/src/relay.rs`), which re-serves the connetto wire protocol from a worker-held connection so that many tabs share one OPFS replica and one server session. The hub re-implements the server's protocol, but only partially. Several live-query legs that work against the direct server silently do nothing through the relay.

The client code is already unified. `ConnettoClient` and `ConnettoConnection` are the same crate on native and wasm, and the whole typed `live()` surface compiles and runs on wasm. So this is not a native-versus-wasm code gap. The asymmetry is entirely the server stand-in:

- Direct topology: `ConnettoClient` over a socket to `connetto-server`. Full protocol.
- Relay topology: `ConnettoClient` over a `BroadcastChannel` to `RelayHub`, which owns a second `ConnettoClient` to `connetto-server`. Partial protocol.

The browser production topology is the relay (one OPFS worker, many tabs). So "wasm and native have the same functionality" reduces to one precise requirement: **`RelayHub` reaches protocol parity with `connetto-server`'s session handler, with identical names and semantics, so a tab client cannot tell whether it is behind a relay or on a direct socket.**

This document is a plan only. Each phase is a separate, small, test-first session. Do not batch them.

## Requirement versus mechanism

The requirement is protocol transparency of the relay. The mechanism today is a hand-written subset in `run_hub`/`handle_tab_control`/`handle_worker_event`. When a phase changes the mechanism, keep the requirement fixed: every `ControlMessage` and `BulkMessage` the server can send to a client, the hub must also be able to send to a tab, and every frame a client can send the server, the hub must accept.

## Method for every phase

Test-first, one functionality per session:

1. Write the failing test first and show it failing. Native, socket-level, or unit tests come before any browser test, because they are cheaper and pin the contract precisely. A browser test (`examples/wasm-smoke/tests`, headless Chrome against the real server and demo Postgres) is added only for the end-to-end leg and is gated on explicit per-time approval to run.
2. Implement the smallest change that makes the test pass.
3. Run the green gate for the crates touched (`cargo fmt --check`, nightly `clippy -D warnings`, `cargo test --release` for native crates, `wasm-pack test` for the browser leg when approved).
4. Report what was delivered and stop. Each phase is independently shippable.

## Protocol surface: reference table

`ControlMessage` and `BulkMessage` from `connetto-core`, with the relay's current behavior. "Server -> client" frames are the ones the hub must be able to originate toward a tab. Line references are into `crates/connetto-web/src/relay.rs` unless noted.

| Frame | Direction | Direct server | Relay hub today | Parity phase |
|---|---|---|---|---|
| `Handshake` / `HandshakeAck` | both | full | served: the ack forwards the upstream server's real `schema_version` (the worker learned it at its own handshake), with a stable per-tab `session_id = "relay-{client_id}"` | done |
| `Subscribe` / `Unsubscribe` (row) | client -> server | full | served from the worker replica and the tier | done |
| `SnapshotBegin` / `SnapshotPatch` / `SnapshotEnd` | server -> client | full | sent by `serve_snapshot` | done |
| `LivePatch` | server -> client | full | routed by table in `handle_worker_event` | done |
| `MutationHeader` / `MutationPatch` upload | client -> server | full | accepted, applied, re-uploaded | done |
| `MutationApplied` | server -> client | full | forwarded, and originated for local tier | done |
| `MutationReject` | server -> client | full | forwarded | done |
| `AggregateUpdate` | server -> client | full (`watch_value`, `LiveValue`) | served: a tab aggregate `Subscribe` registers a private upstream sub on the worker connection (`agg-{tab}-{sub}`) and its pushes demux back to the owning tab | done |
| `FullResyncRequired` | server -> client | full | served: an upstream `FullResync` clears the worker replica and the hub fans a `FullResyncRequired` plus a fresh snapshot out to every affected tab subscription | done |
| `MutationConflict` | server -> client | full | served: an upstream `ClientEvent::MutationConflict` maps back to the owning tab as a `MutationConflict`, distinct from a reject | done |
| `NonFatalError` | server -> client | full | served: a tab subscription the hub cannot serve draws a scoped `NonFatalError` and the worker's own `NonFatal` maps back to the owning tab subscriptions, instead of a tab teardown | done |
| `AckCredits` and delivery credits | both | server enforces backpressure (`session.rs` `flush`/`credits`) | served: each tab has a credit window (`INITIAL_CREDITS`), bulk frames queue when it reaches zero and drain on `AckCredits`, control frames never gated | done |
| `SchemaUpdate` / `SchemaBlob` | server -> client | removed: contradicted the no-runtime-DDL model, never sent or handled | deleted from `connetto-core` | done |
| `Ping` / `Pong` | both | full | served | done |

## Phases

Ordered by user-facing severity. Each is a session.

Progress: Phases 0 through 7 are landed and green (platform baseline, aggregates, full resync, conflict distinction, non-fatal errors, flow control, handshake alignment, schema-version detection). The relay reaches protocol parity with the direct server, and the dead `SchemaUpdate`/`SchemaBlob` surface is removed.

### Phase 1: aggregate subscriptions through the relay

Status: landed. `ClientEvent::Aggregate` now carries `group_key` and `is_full_result` filled from the wire `AggregateUpdate`, `subscription_is_aggregate` is public in `connetto-client`, and `relay.rs` multiplexes a per-tab upstream aggregate subscription (`agg-{tab}-{sub}`), demuxes each push back to the owning tab under its own sub id, and tears the upstream down on `Unsubscribe` and tab death. `hub_recover` re-declares the aggregate upstreams after a resume. Covered by `connetto-client/tests/aggregate_relay.rs` (widened decode of a grouped delta the direct server never emits), the `subscription_is_aggregate` unit test, and the browser `aggregate_is_relay_transparent` parity test in `examples/wasm-smoke/tests/parity.rs` (bootstrap plus a live insert, direct versus relay). One honest gap: the post-reconnect re-declaration is implemented but not yet exercised by a test.

Functionality. `watch_value` and the aggregate arm of `use_live` return a `LiveValue` fed by server-pushed `AggregateUpdate`. The replica holds only this client's authorized rows, so the value must come from the server: a global aggregate cannot be computed from a tab mirror or the worker replica without silently becoming a per-user number.

Native reference. `connetto-server` maintains aggregate subscriptions (`session.rs` `agg_subs`) and pushes `AggregateUpdate`. The client decodes it into `ClientEvent::Aggregate` (`connetto-client/src/lib.rs`, `ControlMessage::AggregateUpdate` arm).

Relay today. A tab `Subscribe` is handled one way only: `subscription_tables` then `serve_snapshot`, a row snapshot. There is no aggregate classification. The worker's own `ClientEvent::Aggregate` is dropped by the `_ => Ok(())` arm in `handle_worker_event`. A tab `watch_value` therefore never resolves and its `LiveValue` stays `None` forever.

Name alignment. `ClientEvent::Aggregate` today carries only `sub_id` and `result_json`, dropping `group_key` and `is_full_result` from the wire `AggregateUpdate`. A relay cannot faithfully forward a grouped aggregate without those two fields. Align the event shape with the wire message.

Hard blocker verdict. No hard blocker. It was deferred as a relay increment. The one design point, not a blocker: per-tab aggregate subscriptions must be multiplexed onto the single worker connection with a private upstream sub id, then de-multiplexed back to the owning tab.

TDD session.
- Sub-step 1a (native, no browser). Widen `ClientEvent::Aggregate` with `group_key: Option<Vec<u8>>` and `is_full_result: bool`, filled from `AggregateUpdate`. Expose a public aggregate-shape classifier in `connetto-client` (for example `subscription_is_aggregate(sql) -> Result<bool, ClientError>`), mirroring the existing public `subscription_tables`. Failing test first: a `connetto-client` unit test asserting the classifier and the widened event decode. This sub-step alone is fully native-testable.
- Sub-step 1b (relay plus browser). In `relay.rs`: classify a tab `Subscribe`, and for an aggregate register a private upstream subscription on the worker connection (`agg-{tab}-{sub}`), record an upstream-id to `(tab, tab_sub)` map plus the spec for reconnect, skip `serve_snapshot`, and in `handle_worker_event` forward `ClientEvent::Aggregate` as a `ControlMessage::AggregateUpdate` to the owning tab. Clean up the upstream sub on `Unsubscribe`, tab death, and re-declare it in `hub_recover`. Failing test first: a browser test where a tab `watch_value(orders.count())` resolves to the correct total and updates when another tab inserts.

Acceptance. A tab `LiveValue` resolves through the hub and tracks changes, single-group and grouped. `hub_recover` re-declares aggregate subs after an upstream drop.

### Phase 2: full-resync propagation through the relay

Status: landed. The fix is in two parts. First, the client: `ConnettoConnection` now records each row subscription's tables and, on `FullResyncRequired`, clears them (capture suspended) before the fresh snapshot repopulates, so the insert-only apply no longer leaves rows deleted during the outage behind. This is the load-bearing correctness fix, shared by the direct client and the relay's own worker replica. Second, the relay: `handle_worker_event` maps an upstream `ClientEvent::FullResync` to a resyncing mark, and on the matching `SnapshotEnd` (the worker replica is whole again) `resnapshot_after_resync` fans a `FullResyncRequired` plus a fresh snapshot out to every tab subscription reading the affected tables, keyed by a worker-sub-to-tables map built from the reconnect specs. Covered by `connetto-client/tests/full_resync.rs` (a fake server hand-feeds the resume sequence, red without the clear, green with it) and the browser test `full_resync_is_relay_transparent` in `examples/wasm-smoke/tests/resync.rs` (a fake upstream through an in-test hub, tab stays attached, asserts the tab observes `FullResync` and drops the deleted row). Gap: a real mid-session upstream retention overflow reaching a still-attached tab is not deterministically triggerable from the browser harness (it cannot sever the worker's upstream socket without killing the worker, which makes the tab reconnect instead of staying attached), so the browser test drives that leg through a fake upstream rather than a live server resync.

Functionality. When the server cannot resume a subscription incrementally (the resume cursor fell out of retention) it sends `FullResyncRequired`. The client responds by re-snapshotting that subscription, which also removes rows deleted while it was away.

Native reference. `ControlMessage::FullResyncRequired` decodes to `ClientEvent::FullResync`, and the client re-subscribes.

Relay today. The worker's `ClientEvent::FullResync` is dropped by `handle_worker_event`. The worker re-snapshots its own replica, but the hub forwards only `LivePatch`, never a re-snapshot, so a tab mirror keeps stale rows and only receives go-forward patches. After an upstream retention overflow, tab mirrors diverge.

Name alignment. Client event `FullResync` versus wire `FullResyncRequired`. Keep the wire name authoritative on the relay leg.

Hard blocker verdict. No hard blocker. Design point: the clean fix relays `FullResyncRequired` per affected tab subscription and lets the tab's own client drive the re-subscribe, which re-enters `serve_snapshot`. Confirm the tab client's `FullResync` handling issues a fresh `Subscribe` through the relay, and that a re-snapshot into a non-empty mirror converges (insert patchset under `server_wins` Replace, plus stale-row removal, which is the substance of this phase).

TDD session. Failing test first: a browser test that forces an upstream resync (kill and resume the hub upstream past retention, or a server test hook) and asserts a tab mirror drops a row deleted during the outage. Then implement `FullResync` mapping in `handle_worker_event` and the re-snapshot path.

Acceptance. A tab converges exactly after an upstream full resync, including deletions, with no stale rows.

### Phase 3: mutation conflict distinction

Status: landed. `handle_worker_event` no longer collapses the two outcomes: the worker's `ClientEvent::MutationRejected` still routes through `reject_tab_mutation` (a `MutationReject`), while `ClientEvent::MutationConflict` now routes through the new `conflict_tab_mutation`, which maps the worker sequence back to the owning tab and sends a `MutationConflict` under the tab's own sequence number. The tab's own client decodes it into `ClientEvent::MutationConflict` and rolls its optimistic write back from its pending changeset, so a relay tab draws the same reject-versus-conflict distinction a direct client does. Covered by the browser test `examples/wasm-smoke/tests/conflict.rs` (`upstream_conflict_reaches_the_tab_as_a_conflict`): a fake upstream conflicts the tab write the worker forwards, and the tab observes `MutationConflict`, never a rejection, and drops the rolled-back row. Gap: the server's own conflicting-row snapshot (`table`, `server_updated_at`, `server_row_json`) is not carried through the relay, because the worker client surfaces only the sequence number and its locally rolled-back rows. This is no fidelity loss over a direct client, whose `ClientEvent::MutationConflict` exposes only the sequence number and its own rolled-back rows too. The relay fills the table name from the rolled-back rows and leaves the other informational fields empty. A test-only, no-server, no-Postgres run.

Functionality. The server distinguishes a rejected mutation (`MutationReject`) from a conflicted one (`MutationConflict`, collided with a newer server row). Both roll back locally, but the client surfaces them as distinct events with the affected rows.

Native reference. `ClientEvent::MutationConflict { client_seq, rows }` versus `MutationRejected { client_seq, rows }`.

Relay today. `handle_worker_event` maps both the worker's `MutationRejected` and `MutationConflict` through `reject_tab_mutation`, which always sends `MutationReject`. A tab never sees a conflict.

Name alignment. Stop collapsing two named outcomes into one. The recorded limit ("an upstream conflict reaches the tab as a plain rejection") is this phase.

Hard blocker verdict. No hard blocker. The worker's `ClientEvent::MutationConflict` already carries `client_seq` and `rows`, enough to send a faithful `ControlMessage::MutationConflict`. It was a simplification.

TDD session. Failing test first: a browser test where a tab write that conflicts upstream surfaces `MutationConflict` on the tab, not `MutationReject`. Then split `reject_tab_mutation` into reject and conflict paths.

Acceptance. A tab observes `MutationConflict` for a conflict and `MutationReject` for a rejection, each with the rolled-back rows.

### Phase 4: non-fatal error propagation

Status: landed. The relay no longer turns a recoverable per-request failure into a teardown. In `handle_tab_control`, a tab `Subscribe` the hub cannot serve draws a `NonFatalError` correlated to its sub id instead of a `TabFault::Close`: an unparsable query (either classifier errors), an unservable one (`subscription_tables` errors), and a failed snapshot (`serve_snapshot` errors) all scope to the tab, which stays alive with every sibling subscription, mirroring the direct server's `subscription rejected` and `snapshot failed` frames. The row and aggregate subscription serving moved into a `handle_tab_subscribe` helper (keeping `handle_tab_control` under the line limit) that takes the disjoint `HubState` fields so the tab borrow still holds. Genuine protocol violations (a second handshake, a frame before handshake, a mutation header while one is in flight, an unsupported frame) stay `TabFault::Close`. In `handle_worker_event`, the worker's own `ClientEvent::NonFatal` is forwarded by `forward_worker_nonfatal`: an aggregate upstream (`agg-{tab}-{sub}`) maps to its one owning tab subscription via `agg_routes`, and a row upstream fans out to every tab subscription reading one of its tables via `resync_tables`, mirroring the resync fan-out. An error the hub cannot correlate to a tab is dropped. Covered by `examples/wasm-smoke/tests/nonfatal.rs` (three tests, no server or Postgres): a bad tab subscription yields a scoped `NonFatal` while a ping still round-trips, an aggregate upstream `NonFatal` reaches the owning tab under its sub id, and a row upstream `NonFatal` fans out to a reading tab. Module doc updated.

Functionality. The server attaches a non-fatal error to a request (most commonly a rejected or untranslatable subscription) and keeps the session open. The client surfaces `ClientEvent::NonFatal { related_to, detail }`.

Native reference. `ControlMessage::NonFatalError` decodes to `ClientEvent::NonFatal`.

Relay today. Never relayed. A tab subscription the hub cannot serve becomes a `TabFault::Close`, which tears down the whole tab rather than reporting a scoped, recoverable error. The worker's own `NonFatal` is dropped.

Name alignment. A recoverable per-request error must arrive as `NonFatalError`, not as a silent tab close.

Hard blocker verdict. No hard blocker. Design point: decide which current `TabFault::Close` cases are actually non-fatal (an unparseable or unsupported tab subscription query) and convert those to a `NonFatalError` frame scoped by `related_to = sub_id`, keeping genuine protocol violations fatal. Also forward the worker's `NonFatal` for the hub's own and aggregate upstream subs.

TDD session. Failing test first: a browser test where a tab registers an unsupported subscription and receives `ClientEvent::NonFatal` with the session and its sibling subscriptions still alive. Then reclassify the relevant faults.

Acceptance. A bad subscription yields a scoped `NonFatal`, not a tab teardown. Protocol violations stay fatal.

### Phase 5: delivery credits and flow control

Status: landed. `TabState` carries a `credits` window (`INITIAL_CREDITS`, 64) and a `pending` `VecDeque<BulkMessage>`. Only `LivePatch` and `SnapshotPatch` are credit-gated, routed through `enqueue_tab_bulk`/`flush_tab_bulk` (mirrors of the server's `enqueue_and_flush`/`flush`), and the `AckCredits` tab arm replenishes then flushes. Control frames are never gated, so keepalive and acknowledgements cannot deadlock. Covered by `examples/wasm-smoke/tests/credits.rs`, a raw frame-level tab that withholds `AckCredits` and uses an ungated upstream `NonFatalError` as a race-free barrier to prove exactly the window drains before an ack and exactly the granted count after.

Functionality. The server bounds in-flight bulk frames by a per-session credit window: it queues when credits reach zero and drains on `AckCredits` (`session.rs` `flush`/`credits`, replenished by the client's `AckCredits`). This is real backpressure against a slow consumer.

Native reference. Server enforces credits, client replenishes with `AckCredits { credits: 1 }`.

Relay today. The hub accepts `AckCredits` as a no-op and pushes bulk frames to tabs as they arrive, ignoring the credit window entirely.

Name alignment. None new. This is a feature-parity phase, not a naming one.

Hard blocker verdict. No hard blocker. Implement a per-tab credit window in the hub mirroring the server's pending-queue plus flush-while-credits pattern. Design point: the tab shovel currently uses unbounded channels, so credits become the hub's own backpressure bookkeeping, not a channel-capacity change.

TDD session. Failing test first: a native or loopback relay test with a slow tab that asserts the hub stops sending past the credit window and resumes on `AckCredits`. Then add per-tab credit accounting.

Acceptance. The hub honors the credit window per tab, matching the server's backpressure semantics.

### Phase 6: handshake ack and schema-version alignment

Status: landed. `ConnettoConnection` now records the server's `schema_version` from its own `HandshakeAck` (`exchange_handshake` returns it, stored and exposed via `schema_version()`), and the relay stamps `worker.schema_version()` into every tab's ack instead of the `SchemaVersion::new("relay", ...)` placeholder, so a tab behind the relay reads the same version a direct client would. This is the propagation Phase 7's staleness detection depends on. Covered by `examples/wasm-smoke/tests/handshake.rs`, a raw frame-level tab asserting its `HandshakeAck.schema_version` equals a distinctive upstream version and is not the placeholder.

Functionality. The handshake ack advertises `session_id`, `session_token`, `schema_version`, and `initial_credits`. A tab should not be able to distinguish a relay ack from a server ack in any field the client acts on.

Native reference. `connetto-server` sends a real `schema_version` (`SessionConfig`) and session identity.

Relay today. The ack uses `session_id = "relay-{client_id}"`, `session_token = "relay"`, and `schema_version = SchemaVersion::new("relay", ...)`. The client ignores `session_id` today, and does not yet enforce `schema_version`, so this is latent, but it becomes load-bearing the moment schema-version checks or session-scoped features land.

Name alignment. This is the naming phase proper: the relay ack should carry the upstream server's `schema_version` (the worker learned it at its own handshake) rather than the literal string "relay", and a documented, stable session identity.

Hard blocker verdict. No hard blocker. The worker already receives the server's `HandshakeAck`, so the hub can propagate the real `schema_version` and current cursor. Requires threading the worker's ack fields into the hub state.

TDD session. Failing test first: a browser or loopback test asserting the tab's `HandshakeAck.schema_version` equals the upstream server's. Then propagate it.

Acceptance. A tab's ack fields match the upstream server's for every field the client reads.

### Phase 7: schema-version mismatch detection and reload

Status: landed. `SchemaVersion` is a content-hash newtype (the `id` label was dropped as it was never read; a short hex `Display` keeps errors legible). `connetto-core` gained `schema_hash` (SHA-256 over newline-normalized schema source) and `SchemaVersion::from_source`, the shared fingerprint both sides compute from the same Postgres source. The server derives its `schema_version` from `pg_ddl` instead of a placeholder. `ClientConfig` gained `schema_version` (the build's baked version), and `exchange_handshake` compares it against the ack before any pending replay, returning `ClientError::SchemaOutdated` so a stale build fails at the door and never pushes old-schema changesets. Detection is server-gated and mandatory: once the server advertises a version, a client must present a matching one (an undeclared, empty client is stale); only a server that advertises no version opts out. The demos and every real-server test bake their version from the same `schema.sql` the server reads, threaded to the DB worker through `DbWorkerConfig`. The dead `SchemaUpdate`/`SchemaBlob` surface is deleted. Covered by `connetto-client/tests/schema_detection.rs` (native) and `examples/wasm-smoke/tests/schema.rs` (relay transparency).

Functionality. Schema evolution in connetto is not a runtime migration. The schema is baked into the app at build time (`build.rs` translates the source document through pg2sqlite into a template) and the client never runs DDL at runtime, which is exactly what makes the wasm and OPFS boot work (`connect_with_replica_template` writes bytes, it does not execute DDL). So a schema change is a new app build, that is a redeploy, that is a reload for the user. The right runtime behavior is detection, not migration: compare the client's baked schema version against the server's and, on a mismatch, signal that this app build is stale and must reload.

Native reference. The handshake already carries `schema_version` both ways (`Handshake` and `HandshakeAck`). Today the server advertises it and the client ignores it: there is no comparison and no reaction. So detection is unbuilt on native as well as through the relay.

Relay today. The hub's ack hardcodes `schema_version = SchemaVersion::new("relay", ...)` rather than the upstream server's version (Phase 6 fixes the propagation). With detection unbuilt, nothing acts on it yet.

Name alignment. Keep `schema_version` as the detection field. There is no `SchemaUpdate` event in the target model, so no event to name.

Hard blocker verdict. No hard blocker. The client compares its baked version against `HandshakeAck.schema_version` and, on a mismatch, surfaces a distinct terminal condition (for example `ClientEvent::SchemaOutdated`) instead of proceeding. The app reload path then boots a fresh template and full-resyncs the data under the new schema. This composes with Phase 2: a reload is a template-fresh full resync, not an in-place DDL migration.

TDD session. Failing test first: a native test where a client whose baked `schema_version` differs from the server's ack surfaces the stale-build condition rather than subscribing. Then wire the comparison and the terminal event. The relay leg is covered by Phase 6 (forward the real version), so a tab detects staleness identically.

Acceptance. A client with a stale baked schema is told to reload rather than silently mis-parsing new columns. A matching version proceeds normally.

## Removed protocol surface: `SchemaUpdate` and `SchemaBlob`

`ControlMessage::SchemaUpdate` and `BulkMessage::SchemaBlob` are dead surface that contradicts the implemented model. They describe a runtime schema push plus a client "schema applier that runs migrations", which appears only in the early architecture docs (`docs/architecture/01-pieces.md`, `02-protocol.md`, `06-reconnect.md`), written before the build-time-baked-template decision. Grep confirms neither is ever sent or handled. Runtime DDL migration is incompatible with the baked-template, no-DDL client (and with the wasm build), so this is not a feature to build later, it is surface to delete. This plan removes `SchemaUpdate`/`SchemaBlob` from `connetto-core` and corrects the three stale architecture docs to describe detection plus reload (Phase 7) instead of runtime migration. There is nothing to relay.
Status: done. `ControlMessage::SchemaUpdate`, `BulkMessage::SchemaBlob`, their structs, and re-exports are deleted from `connetto-core`, and the three architecture docs (`01-pieces.md`, `02-protocol.md`, `06-reconnect.md`) now describe detection plus reload.


## Sequencing

Phases 1 through 7 are independent and each is shippable alone. Recommended order is the table order by severity: aggregates, full resync, conflict distinction, non-fatal errors, flow control, handshake alignment, then schema-version detection. The `SchemaUpdate`/`SchemaBlob` removal is a small cleanup that can ride with Phase 7, since both concern the same corrected schema-evolution model.
