# pg2sqlite: a translation manifest exporting the logical to physical table map (landed upstream)

## Status

**Resolved: landed on `LucaCappelletti94/pg2sqlite` main** (PR #45, `c22fd04`), right after the read-only deny triggers (PR #44), so `WrapperKind::ReadOnly` shipped from day one. The landed shape refines this proposal in two ways: `translation_manifest` is a fallible method on the `Pg2Sqlite` builder, `Pg2Sqlite::translation_manifest(&self, options: &Pg2SqliteOptions) -> Result<Vec<TableManifestEntry>, Error>` (`src/pg2sqlite.rs:540`), not a free function over a prebuilt schema, and it is role-aware: with a configured `session_user_role` it omits tables that role cannot SELECT, mirroring the classification `translate` itself uses. The types live in `pg2sqlite::manifest` as proposed. The connetto workspace still pins `ee65e30`, which predates it, so the pin bump happens when the sync boundaries consuming the manifest get implemented. The proposal below is kept as written for the rationale record, file:line cites refer to `ee65e30`.

## The problem

The RLS translation rewrites one Postgres table into three SQLite objects: the physical backing table renamed with the configured suffix, a view holding the logical name, and `INSTEAD OF` triggers enforcing the policies (`src/impls/translator_impls/rls.rs:6-7`, view generation at `rls.rs:1357`, insert trigger at `rls.rs:1422`). After translation the logical name no longer names a table.

Any consumer that moves data in or out of the translated database *by table name* therefore needs the logical to physical map. The sharpest case is SQLite's own changeset apply, which fails silently in both relevant shapes. A section whose name resolves to nothing is skipped with only an `sqlite3_log` line (`sqlite3session.c:5677-5682`). A section whose name resolves to the RLS *view* is subtler: `sessionTableInfo` reads columns through `PRAGMA table_xinfo`, which works on views, and since a view declares no PK the session synthesizes an implicit rowid key (`sqlite3session.c:1116,1129-1139,1165-1172`), the shape checks pass, and every row then fails as a per-row `Constraint` conflict, which a server-wins conflict policy maps to Omit (connetto `crates/connetto-client/src/lib.rs:241-245`). Either way apply reports success and delivers nothing, verified end to end in `crates/connetto-client/tests/rls_name_mapping.rs`.

The map cannot be reconstructed downstream by string convention, because the suffix is a configurable option: `rls_table_suffix`, default `"_rls"` (`src/options.rs:97`, `with_rls_table_suffix` in `src/traits/translation_options.rs:141-143`). A downstream crate hardcoding `_rls` breaks silently under any non-default configuration. The map has to come from the translator that made the naming decision.

## What already exists

The per-table primitives are public today:

- `table_has_rls(table_name, schema)` classifies one table (`rls.rs:62`).
- `resolve_trigger_table_name(base_name, schema, options)` returns the backing name for RLS tables and the input name otherwise (`rls.rs:96`).
- The trigger translator already consumes them to redirect user `BEFORE`/`AFTER` triggers to the backing table (`src/impls/translator_impls/create_trigger.rs:330-334`), proving the classification logic is the one the generator itself trusts.

What is missing is the enumeration: one call that walks the schema and returns every table's outcome with a classification a consumer can dispatch on, instead of every consumer re-implementing the walk and the wrapper taxonomy.

## Proposed API

```rust
/// How the translation wrapped one table.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperKind {
    /// Translated one to one. The logical name is a real table.
    Plain,
    /// RLS translation. The physical table carries the configured
    /// suffix, a view holds the logical name, and INSTEAD OF
    /// triggers enforce the policies.
    RlsView,
    /// Read-only translation. The table keeps its name and BEFORE
    /// triggers deny writes.
    ReadOnly,
}

/// One table's translation outcome.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableManifestEntry {
    /// The table name in the source (Postgres) schema.
    pub logical: String,
    /// The SQLite table that physically stores the rows.
    pub physical: String,
    /// The wrapper generated around the physical table.
    pub wrapper: WrapperKind,
}

/// Enumerate the logical to physical outcome of translating `schema`
/// under `options`, one entry per table, in schema order.
pub fn translation_manifest<DB: DatabaseLike>(
    schema: &DB,
    options: &Pg2SqliteOptions,
) -> Vec<TableManifestEntry>
```

Both types are `#[non_exhaustive]`: future transforms add wrapper variants (a transparent column transform was evaluated downstream and shelved, but the door stays open) and future needs add fields (per-table generated artifact names, for example) without a breaking release.

Deliberately minimal: no serde derives and no output format. Consumers that need a file format serialize the entries themselves. The primary consumer bakes the map into generated Rust source at build time, so a wire format here would be dead weight.

## Implementation notes

A thin wrapper over the existing public functions, no new analysis: iterate the schema's tables in deterministic schema order (reproducible build outputs), classify each with `table_has_rls` (and the read-only marker once that feature exists), and compute the physical name with `resolve_trigger_table_name`. The function must share the exact code path the DDL generator uses for naming, so the manifest can never drift from the statements actually emitted.

## Tests

- A schema with one plain table and one RLS table yields two entries with the expected names and kinds, and the physical name of the RLS entry matches the `CREATE TABLE` name in the actually generated DDL statements (drift guard, asserted against the generator output rather than a literal).
- `with_rls_table_suffix("_x")` is reflected in the manifest.
- An empty schema yields an empty vector.
- Once deny triggers land: a read-only table yields `logical == physical` with `WrapperKind::ReadOnly`.

## Downstream use

connetto generates its replica schemas at build time by running pg2sqlite over the two tier documents. The generation step calls `translation_manifest` and bakes the result into the generated schema module as a static table, next to the DDL. The client then consumes the baked map at three boundaries, under the contract that the wire always speaks logical Postgres names:

1. **Download**: rewrite table names in incoming server changesets from logical to physical before `sqlite3changeset_apply`, because applying a logical name against a view silently drops the section (see above). Applying into the backing table also correctly bypasses the local policy triggers, since server data is authoritative.
2. **Upload**: rewrite captured changesets from physical back to logical before sending, because the server side resolves tables against the Postgres catalog.
3. **Live-query routing**: map update-hook notifications (which fire on the physical table) back to the logical name that subscription SQL mentions, so live handles refresh.

The changeset rewrite itself is `sqlite-diff-rs` territory and has its own sibling proposal, `docs/upstream-sqlite-diff-rs-changeset-table-rename.md`.
