# pg2sqlite: reference-closed translation via `validate_foreign_key_targets` (resolved)

## Status

**Resolved: landed on `LucaCappelletti94/pg2sqlite` main** (PR #46, `d024713`) with exactly the proposed shape: default-on validation after the schema build in `translate_internal` (`src/pg2sqlite.rs:387-388` on main) and in `translation_manifest` (`src/pg2sqlite.rs:557-558`), plus the `with_dangling_foreign_keys_allowed()` / `is_dangling_foreign_keys_allowed()` opt-out pair (`src/options.rs:321-327`). connetto pins the merge in both crates. This was the downstream half of `docs/upstream-sql-traits-fk-target-validation.md`, whose primitive landed on sql-traits `main` as `ParserDB::validate_foreign_key_targets` (`7f3598a`, PR #13). The proposal below is kept as written for the rationale record, file:line cites refer to the pre-landing pin `f122e7c`.

## The problem

pg2sqlite plays the role for a translated document that real Postgres plays for a natively applied one, and real Postgres rejects a `REFERENCES` clause whose target does not exist. pg2sqlite currently does not. The translation entry point ingests the document into a `ParserDB` (`src/pg2sqlite.rs:385` in `translate_internal`, `src/pg2sqlite.rs:513` in `build_schema`) and translates whatever parsed, and every later lookup that touches FK targets is deliberately tolerant: `table_has_implicit_public_rls` maps a missing target to "no RLS" via `is_some_and` (`src/impls/object_name.rs:251-256`) instead of raising.

The consequence is that a dangling foreign key, an error class Postgres would catch at DDL apply, is laundered into valid-looking SQLite DDL. SQLite accepts FK clauses naming missing tables while enforcement is off, so the mistake ships as dead `REFERENCES` text in the emitted schema. It also silently skews classification: a table whose RLS status is derived through a dangling reference is classified as if the reference did not exist.

For connetto specifically, the local-only tier design (two source documents, each a separate reference universe) requires that a document which is not reference-closed fails the template bake. The shared document gets this from real Postgres. The frontend document's only DDL consumer is pg2sqlite, so pg2sqlite's tolerance is the one hole in the closure rule.

## Proposed change

Validate at the emission boundary, default on. After the schema is built inside `translate_internal` (`src/pg2sqlite.rs:385`), and after `build_schema()` inside `translation_manifest` (`src/pg2sqlite.rs:540`), run:

```rust
if !options.is_dangling_foreign_keys_allowed() {
    schema.validate_foreign_key_targets()?;
}
```

The error converts for free: `Error::SchemaError(#[from] sql_traits::errors::Error)` already exists (`src/errors.rs:26`), and the sql-traits error names the owning table and the unresolved target or missing column.

`Pg2SqliteOptions` gains one opt-out knob in the existing builder style (`src/options.rs`):

```rust
/// Permit foreign keys whose target table or columns do not resolve in
/// this document. By default translation fails on the first dangling
/// reference, matching what Postgres itself would do at DDL apply.
fn with_dangling_foreign_keys_allowed(mut self) -> Self;
fn is_dangling_foreign_keys_allowed(&self) -> bool;
```

Placement notes:

- Both `translate_internal` and `translation_manifest` validate, so the manifest and the emitted DDL always agree on the schema they describe. All public translate flavors (`translate`, `translate_with_report`, `translate_to_sql`) funnel through `translate_internal`, so one call covers them.
- `build_schema` stays unvalidated. It is a raw accessor used for reverse translation over possibly partial catalogs, and strictness policy belongs to the emission entry points, not to parsing.
- Default on rather than opt-in. The crate has an opt-in precedent (`with_strict_rls_validation`, `src/options.rs:298`), but that guards a policy interpretation question. A dangling FK in a document handed to whole-document translation is a bug in the input, and the tool's job is Postgres fidelity, so silence is the wrong default. The crate is pre-1.0 and the opt-out preserves any consumer that genuinely translates partial documents.

## What to test

- A document with `REFERENCES missing_table(id)` fails `translate_to_sql`, `translate_with_report`, and `translation_manifest` before any statement is emitted, and the error names the owning table and the target.
- The missing-column form (`REFERENCES real_table(missing_col)`) fails the same way.
- A forward reference (target defined later in the document) passes, matching the sql-traits order-insensitive semantics.
- With `with_dangling_foreign_keys_allowed()`, the current behavior is restored verbatim, dead `REFERENCES` text included.
- Existing fixtures with resolvable FKs translate unchanged, which doubles as the regression sweep for the default flip.

## Downstream use in connetto

Nothing to call and nothing to remember: the template bake in `build.rs` already goes through `translate_to_sql`, so a `frontend.sql` containing `REFERENCES orders(id)` fails the build with the sql-traits error surfaced, for both documents, by construction. synql inherits the same guarantee when it takes over template generation, and the acceptance item in `docs/upstream-synql-tier-generation-contract.md` (the FK-across-boundary build failure) needs no connetto-side validation code at all.
