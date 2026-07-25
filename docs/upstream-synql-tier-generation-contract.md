# synql tier generation contract: local-only tables (decided design, not yet built)

## Status

Decided design for the connetto pipeline (sql-traits, pg2sqlite, synql, connetto-client), all seven decisions ruled in discussion. The three upstream prerequisites are complete: the diesel attach API (see `docs/upstream-diesel-attach-database-api.md`, landed on the fork's future branch), the pg2sqlite deny triggers for read-only non-RLS tables (`docs/upstream-pg2sqlite-readonly-deny-triggers.md`), and the sql-traits FK target validation (`docs/upstream-sql-traits-fk-target-validation.md`). Grounded facts are collected in the appendix with file and line citations, all source-verified at the named pins.

## The problem

A table the server does not accept is not merely rejected today, it is destroyed. A local write to such a table is captured by the session, uploaded, rejected by the server catalog, and rolled back, which erases device-private data (`notes` in the demo reproduces this). The requirement: a local-only table must be physically incapable of reaching the wire. Not filtered, not denied, not configured away, but structurally outside the capture and upload machinery.

## The model: two documents (decision 1, revised from the schema-prefix form)

Requirement: the author declares which tables are local-only and which are synced, in one dialect, with enough type information for synql to generate faithful Rust.

Mechanism: two Postgres-dialect source files, one per tier (the demo uses `schema.sql` for the shared tier and `frontend.sql` for the local tier). Table names are bare, no schema prefix anywhere. The tier of a table is defined by which document it lives in, and the only knob is the path of the second file handed to the generator. Postgres dialect is retained for both documents, including the one that never touches a real Postgres, because its type system (`uuid`, `timestamptz`, `jsonb`) carries exactly what synql needs and SQLite dialect cannot express it.

The two documents are separate reference universes. That yields the linking rule (decision 3) as a resolution property rather than a policy check:

- **Dangling reference, hard error.** A `REFERENCES` clause pointing from one document into the other is a reference to a table that does not exist in that universe. Frontend-to-shared is enforced by `ParserDB::validate_foreign_key_targets` (sql-traits) called by pg2sqlite at translation, per the upstream doc. Shared-to-frontend is enforced natively by the real Postgres server, which has never heard of the frontend tables. Semantically this is correct, not just physically forced: the synced side of a replica is a moving window (filtered subscriptions, future eviction), so an enforced FK from private data into it would either block eviction or cascade-destroy private data. Within a tier, FKs work normally. No advisory-link metadata is generated, the error stands alone.
- **Duplicate table name across documents, hard error.** SQLite resolves a bare name by searching `main` first, so a collision would silently shadow the frontend table. This check spans both documents, so it belongs to synql, the only layer that sees both.

## Placement (decision 2)

Requirement: local tables live where the sync engine cannot see them.

Mechanism: a second SQLite database file attached to the replica connection. The capture session is created on `main` only (hardcoded in the pinned diesel-sqlite-session, appendix item 1), so writes to attached tables are never captured, never uploaded, never rolled back. The second file ships as a second baked template, symmetric with the primary: `build.rs` invokes pg2sqlite once per document, preserving the no-DDL-at-startup principle. The attach goes through the diesel attach API with `set_attach_create_enabled(false)` as hardening, and the attach name is an internal constant that never appears in authored SQL or application queries.

Cross-file transactions are not crash-atomic under WAL, so no invariant may span the two files. This holds by construction: the frontend file carries zero sync state (the cursor, pending mutations, and meta tables all live in `main`), so its crash consistency is SQLite's ordinary single-file guarantee.

## Generation (decision 4, revises the roadmap's cfg sketch)

Requirement: server code must not be able to touch local tables, and the generated client schema must expose both tiers.

Mechanism: documents map to modules, no Cargo features. The cfg-features sketch ("a table absent from a tier cannot be imported there") is dead for two independent reasons: one compiled wasm binary hosts multiple tiers (the leader tab spawns the DB worker from the same artifact), and Cargo feature unification makes any gate additive across the build graph. It is also unnecessary. On the server, existence-by-absence holds trivially because the server's generated schema is produced from the shared document alone, it never parses `frontend.sql`. On the client, no code region needs table-hiding: both tiers are legitimately readable, joins included.

synql therefore emits one generated client crate with a module per document (for example `schema::shared::orders`, `schema::local::drafts`), bare table names, `allow_tables_to_appear_in_same_query` across the boundary so cross-tier joins type-check, plus the two baked templates. The roadmap's deferred cell (a table visible for live aggregates but never replicated) dissolves: visibility and presence are no longer coupled through features, and local aggregates have a home (decision 6).

## Write enforcement (decision 5)

Two different "you cannot write this" situations, two distinct mechanisms, deliberately not unified:

- **Local-only table**: writable by the device, must never reach the wire. Enforcement is placement (the attached file the capture session cannot see). The write is welcome, there is nothing to deny.
- **Read-only synced table**: reaches the device from the wire, must reject local writes. Enforcement is pg2sqlite role translation: the RLS branch already denies via a view without `INSTEAD OF` write triggers, and the non-RLS branch gets the three `RAISE(ABORT)` deny triggers per the upstream doc, under the contract that authoritative patch applies run in a triggers-disabled window (same shape as `SuspendedCapture`).

The server catalog's `NotWritable` rejection remains in both worlds solely as the version-skew backstop for clients holding a stale replica schema, never as primary enforcement. Expressing local-only as a writability role is explicitly rejected: it would route device-private data back through deny machinery and reintroduce the destroy-on-reject bug class.

## Live queries (decision 6)

Tier dispatch is a runtime lookup: the replica itself knows which database file every table lives in, so no generated constants are needed and nothing is handrolled in the demo. Four cases:

- **Local rows**: skip the server `Subscribe`, keep the registry entry. The existing refresh path already re-runs the query against the replica whenever a table it reads changes (appendix item 8), so local writes drive the handle with no new machinery.
- **Local aggregates**: transparent at the API, served by re-executing the aggregate locally on change. Correct because a local table is the one place the replica is not a window but the entire universe of the table. Recorded as deliberate: local aggregates are re-executed, not incrementally maintained (O(table) per change instead of the server path's O(delta), microseconds at device-private volumes, IVM would be complexity with no customer).
- **Mixed rows** (a query joining tiers, joins work across the attach boundary): requirement, the synced tables of a mixed row query stay live and covering while the handle exists. Without that, a join against an unsubscribed synced table looks alive while permanently frozen. The v1 mechanism, explicitly disposable: auto-subscribe the whole synced table (`SELECT *` per synced table in the query), lifetime tied to the handle. Deriving a minimal covering subscription from the join predicate depends on local data and means dynamically re-negotiated subscriptions, deferred as a possible refinement. Documented caveat: whole-table subscribe pulls the entire table into the replica for the handle's life.
- **Mixed aggregates**: hard error at `watch_value` registration. The server cannot compute them (it lacks the local tables) and a window-local answer would violate the semantics that an aggregate means truth. Rationale on record: rejected because of the cost cliff, not impossibility (whole-table subscribe would make a local computation truthful, but silently escalating a `count(*)` into a full-table sync is a trap).

To verify during implementation: an auto-created whole-table subscription overlapping a user's narrower subscription on the same table must not double-apply patches. Server-side overlap handling has not been verified.

## Retention and resume non-collision (decision 7)

Holds structurally, not by care:

- No `SubscriptionSpec` can ever carry a frontend table (local queries register no spec, mixed queries subscribe only their synced tables), so eviction, which removes rows no active subscription covers, has no path to a frontend row.
- The FK closure rule removes cascade paths, so evicting a shared row cannot touch local data even if FK enforcement is ever enabled.
- The resume cursor lives in `main._connetto_meta`, persisted in the same transaction as patch application, and the frontend file carries no sync state, so cross-file WAL non-atomicity never spans an invariant.

## What to test

In synql, when it exists:

- Two documents generate two modules and two templates, the server target consumes only the shared document.
- A duplicate table name across documents fails generation with an error naming both documents.
- Cross-tier joins type-check in the generated client crate.

In the demo and connetto-client (the demo hand-rolls what synql will automate):

- `notes` moves from `DEMO_SQLITE_DDL` to `frontend.sql`, baked as a second template, imported and attached in `workers.rs`. A write to `notes` produces no `MutationHeader` (capture stays empty) and the destroy-on-reject reproduction is gone across reconnect and rollback paths.
- `frontend.sql` containing `REFERENCES orders(id)` fails the template bake in `build.rs` (via the sql-traits validation through pg2sqlite).
- A row `watch` on `notes` sends no `Subscribe` and refreshes on local writes.
- A `watch_value` aggregate on `notes` updates on local writes with no server subscription.
- A mixed row `watch` joining `notes` and `orders` registers a whole-table subscription on `orders`, refreshes on both a local `notes` write and a server `orders` patch, and drops the subscription with the handle.
- A mixed aggregate `watch_value` errors at registration.
- Characterization: an auto whole-table subscription overlapping a narrower user subscription on the same table does not double-apply patches.
- Once eviction exists: eviction runs never touch the frontend file.

## Non-goals

- No incremental maintenance for local aggregates.
- No predicate pushdown for mixed-query auto-subscriptions in v1.
- No cfg features in any generated crate.
- No advisory FK-link metadata, the cross-document reference error stands alone.
- No trimming or compression here, that belongs to the replica retention design (see the roadmap's retention section).

## Appendix: verified facts

1. The capture session is physically main-only: diesel-sqlite-session pin `f6aba48` hardcodes `sqlite3session_create(raw, c"main")` (`src/session.rs:159,179`). `push()` recreates a fresh session per flush (`connetto-client/src/lib.rs:869-875`), which kills any table-filter alternative (a filter would need reinstalling every flush).
2. In-repo attach precedent: `RelayHub` attaches `connetto_hub` for tab watermarks (`examples/wasm-smoke/src/relay.rs:161-164`), browser-proven with a sahpool attach (`workers.rs:208`).
3. Cross-attach FK, tested with the sqlite3 CLI: with `PRAGMA foreign_keys=ON`, DML on an attached table declaring `REFERENCES orders(id)` fails at prepare with "no such table". With enforcement off (connetto never enables it) the clause is dead text. Cross-schema JOIN works. Cross-file transactions are not crash-atomic under WAL (ATTACH documentation), and `connect_inner` sets WAL.
4. ATTACH accepts bound parameters for both operands and succeeds inside an open transaction (tested on SQLite 3.51.1).
5. The update hook is connection-wide including attached databases, the tracker records `event.table_name` only (`connetto-client/src/lib.rs:440-449`), and an empty changeset is never uploaded (`lib.rs:850`), so frontend writes tripping `dirty` are harmless.
6. pg2sqlite pin `ee65e30`, `translate_create_table_for_role` (`src/impls/translator_impls/statement.rs:246`): non-selectable tables are omitted entirely, readonly with RLS becomes a view without `INSTEAD OF` write triggers (`rls.rs:1672,1765,1774`), readonly without RLS was a plain writable table (now closed by the deny-triggers upstream doc).
7. `sqlite3changeset_apply` executes plain DML (`sqlite3session.c:4460,4567,4636,4650`), so triggers fire during server patch apply, hence the triggers-disabled apply contract. Adjacent latent finding: the RLS rename path puts a view at the public name (`rls.rs:1780`) and changeset apply silently skips tables it cannot match, flagged in the pg2sqlite upstream doc.
8. Row-shaped live queries refresh locally already: rows refresh "whenever a table the query reads changes (a server patch or a local write alike)" (`connetto-client/src/live.rs:8-11`), the refresh closure re-runs the query against the replica (`live.rs:568-577`), the pump drives it (`live.rs:875`). Aggregates are answered by server pushes (`live.rs:81`). `parse_subscription` extracts bare table names (`live.rs:120-137`).
9. Neither ParserDB nor pg2sqlite errors on a dangling FK at the current pins: ingestion stores FKs unresolved (sql-traits `e9e31c3`, `sqlparser.rs:824-828,881`), later lookups are tolerant (`sqlparser.rs:130-138`, pg2sqlite `object_name.rs:251-257`). Closed by the sql-traits upstream doc.
10. Server rejection path for the backstop: `RuntimeWritableCatalog::is_writable` and `MaterializerError::NotWritable` (`connetto-server/src/materializer.rs:88-91,853,884`), `CONNETTO_WRITABLE` parsing in `bin/connetto-server.rs:99-112`.
