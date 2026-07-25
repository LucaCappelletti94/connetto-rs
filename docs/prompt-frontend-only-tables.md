# Next session: design local-only (frontend-only) tables

## Goal

Decide, cleanly and for the long term, how a table is characterized as local-only (device-private, never synced to the server) in a stack where tables, their Rust structs, and their query logic are all derived from SQL parsing (`sql-traits`, `subql`, and the `synql` generation layer the roadmap refers to). This session is a design discussion that ends in a written design doc, not an implementation. No shortcuts: pick the durable mechanism, and record the requirement separately from the mechanism that serves it.

The motivating correctness gap is real and live: today a write to a table the server does not accept is captured by the session, uploaded, rejected, and rolled back, which destroys device-private data. A local-only table must be physically incapable of ever reaching the wire.

## The core tension

Everything downstream (the diesel `table!` definitions, the `Queryable`/`Selectable` structs, the subscription catalog, the Postgres catalog DDL, the SQLite replica DDL, the baked template) is generated from one SQL-shaped source of truth. A local-only table is a table that must exist in some of those outputs (the client SQLite tiers) but be absent from others (the Postgres catalog, the capture session, the subscription surface). So the whole question is: what is the authoring primitive that says "this table is local-only", and how does it flow through generation and runtime so the table lands in exactly the right places and nowhere else.

## The decisions to make (each records a requirement, then weighs mechanisms)

1. Authoring primitive. How does the schema author mark a table local-only in the source of truth? Candidate mechanisms: a dedicated schema namespace in the declaration (a `frontend.` qualifier), a per-table annotation or attribute consumed by `synql` codegen, or a separate declaration file per tier. Which one keeps the single source of truth honest and makes "absent from the server" the default-safe outcome rather than an opt-in the author can forget.

2. Physical placement in the client. The roadmap's current sketch attaches a second SQLite database as schema `frontend` and creates the capture session on `main` only, so frontend tables cannot be captured or uploaded. Weigh that against a marker on tables inside one database, or a fully separate database file. The chosen mechanism must make non-capture a physical property, not a policy check that can be bypassed.

3. Linking to synced tables. Can a local-only table reference a synced table (foreign key, join)? SQLite does not enforce foreign keys across attached databases, but cross-schema JOINs in a query are fine. Decide what linking is supported, what is only advisory, and how `live()` handles a query that spans a synced schema and the local-only schema (it registers a server subscription for the synced part and refreshes the local part from local writes).

4. Generation contract across targets. `synql` must emit different DDL per target: the Postgres catalog gets synced tables only, the SQLite `main` replica gets the synced tables, and the SQLite `frontend` tier gets the local-only tables. The roadmap frames existence as controlled by cfg features in the generated schema crate, so a table absent from a tier cannot be imported there. Confirm that cfg-per-tier is the right existence mechanism, or find a cleaner one, and define the split precisely: `main` replica DDL, `frontend` attached DDL, and the baked template file.

5. Write enforcement, two cases. Local-only writes must be captured never (physical, via placement in the non-captured schema). Read-only synced tables are a different case already handled: `pg2sqlite`'s role-aware translation emits deny triggers that fail the write synchronously at the statement (`translate_create_table_for_role`), with the server catalog as the version-skew backstop. Keep these two mechanisms distinct and state why each is correct for its case.

6. The hard deferred cell. A table that wants live-query and live-aggregate semantics locally but is never replicated to the server has no home in the sketch, because cfg visibility implies presence and the current model ties "local-only" to "not a server table". Decide whether this case is in scope, and if so where such a table lives and how `live()` and the aggregate machinery serve it with no server subscription.

7. Interplay with retention and resume. Local-only tables must not be touched by replica retention and eviction (that machinery runs with capture suspended and reasons about subscribed rows), and they carry no resume cursor. Confirm the boundaries so the two designs do not collide.

## Deliverable

A design doc in the `docs/upstream-*` and `docs/architecture` style: the `synql` generation contract for tiers (the roadmap already calls for exactly this). It states the authoring primitive, the per-target DDL split, the runtime placement and capture boundary, the linking rules, the `live()` dispatch on the schema qualifier, and an explicit resolution or explicit deferral of the live-local-aggregate cell. Add the resolved questions to `docs/architecture/open-questions.md` in that file's decided-question style.

## Grounding to read first

- `docs/roadmap.md`, the "Frontend-only tables" section (the decided-but-unbuilt sketch) and the "Replica retention and eviction" section (the machinery that must not touch these tables).
- `examples/wasm-smoke/schema.sql` and `examples/wasm-smoke/src/workers.rs` (`DEMO_SQLITE_DDL`), where `orders` is the synced table and `notes` already exists only in the replica tiers, a concrete stand-in for a local-only table to design against.
- How a replica is currently created: `ConnettoConnection::connect` takes a DDL string, `connect_with_replica_template` bakes a template (native only), and `connect_existing` opens with no DDL. The build script in `examples/wasm-smoke/build.rs` runs `schema.sql` through `pg2sqlite` to produce the template.
- `docs/architecture/subql.md` and the subscription docs for how the catalog and `live()` consume table declarations.

## Constraints

ASCII punctuation in all prose. No shortcuts, the long-term best version. Every tradeoff-table cell is a claim to verify against source or docs before it is presented. An interim step needs a named blocker, not a price tag. Do not weaken a requirement to preserve a mechanism.
