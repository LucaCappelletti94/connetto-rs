# sql-traits: foreign key target resolution validation (resolved)

## Status

**Resolved: both halves landed.** The primitive landed on `earth-metabolome-initiative/sql-traits` main as `ParserDB::validate_foreign_key_targets` (`7f3598a`, PR #13, `src/structs/generic_db/sqlparser.rs:694`), with the proposed order-insensitive, opt-in semantics. The pg2sqlite wiring landed on `LucaCappelletti94/pg2sqlite` main (PR #46, `d024713`), see `docs/upstream-pg2sqlite-fk-target-validation.md`. connetto pins both. The proposal below is kept as written for the rationale record, file:line cites refer to the pre-landing pin `e9e31c3`.

## The problem

`ParserDB` ingestion stores foreign keys without ever resolving their targets. Column-level FK options are pushed straight into the builder (`src/structs/generic_db/sqlparser.rs:824-828`), table-level constraints go through `process_foreign_key_table_constraint` (`sqlparser.rs:881`) the same way, and the builder has no validation pass. A schema whose FK points at a table that does not exist in the document parses successfully into a `ParserDB` that silently carries the dangling constraint.

Where resolution does happen later, it is deliberately tolerant. `is_table_referenced` resolves the FK's `foreign_table` with `resolve_table_object_name_in_iter(...).ok().flatten()` and simply skips the constraint when the target is missing (`sqlparser.rs:130-138`). Downstream, pg2sqlite's `table_has_implicit_public_rls` maps a missing target to `is_some_and(...) = false`, treating a dangling reference as "no RLS" rather than an error (`pg2sqlite ee65e30, src/impls/object_name.rs:251-257`). The only hard error in the neighborhood, `ensure_schema_resolves`, fires solely for an explicit schema qualifier other than `public`, so a bare-name dangling reference never trips it.

The concrete consequence for connetto: `REFERENCES orders(id)` inside the frontend document, where `orders` does not exist, translates to dead text in the baked SQLite template. SQLite accepts FK clauses to missing tables when enforcement is off, so the mistake survives all the way into a shipped replica. The reverse direction is already guarded for free, because the shared document is applied to real Postgres, which natively rejects a reference to a table it does not have. The frontend-to-shared direction has no guard anywhere.

## Proposed change

Add a public validation method on the parsed database, along the lines of:

```rust
impl ParserDB {
    /// Checks that every foreign key resolves: the referenced table exists in
    /// this database and every referenced column exists on that table.
    pub fn validate_foreign_key_targets(&self) -> Result<(), Error>;
}
```

For each stored foreign key, resolve `foreign_table` against the database with the same implicit-public lookup semantics the crate already uses for other object-name resolution, then check that each referenced column exists on the resolved table. On failure, return an error naming the constraint's owning table, the unresolved target (or missing column), and enough identity to locate the clause in the source.

Two semantic points worth pinning in the doc comment:

- Validation runs against the fully ingested database, so it is order-insensitive. A table defined later in the document is a valid target even though Postgres itself would reject the forward reference at sequential DDL apply. This is intentional: the check answers "is this document reference-closed", not "would this script apply in order".
- Self-referential foreign keys resolve trivially and pass.

The method is opt-in rather than wired into parsing, because consumers legitimately parse partial schemas. Callers that want a priori strictness invoke it right after parse. pg2sqlite should call it at the top of its translation entry point (or expose a strict-mode option that does), so every translated document is reference-closed by construction. connetto's build then gets the frontend-to-shared error for free on both documents.

## What to test

In sql-traits:

- FK to an existing table with existing columns validates cleanly, for both the column-option form (`REFERENCES t(c)` on a column) and the table-constraint form (`FOREIGN KEY (a) REFERENCES t(c)`).
- FK to a missing table errors, and the error names the owning table and the unresolved target.
- FK to an existing table but a missing column errors, naming the column.
- Bare-name and explicit `public.` qualified targets resolve identically under the implicit-public policy.
- A forward reference (target defined later in the document) validates cleanly.
- A self-referential FK validates cleanly.
- A document with several dangling constraints reports a deterministic first error (or all errors, whichever shape the crate's `Error` favors, pinned by the test either way).

In pg2sqlite, once wired:

- Translating a document with a dangling FK fails before any statement is emitted, instead of producing dead `REFERENCES` text.
- Existing fixtures with resolvable FKs translate unchanged.

In connetto:

- A `frontend.sql` containing `REFERENCES orders(id)` fails the template bake in `build.rs` with the sql-traits error surfaced, pinning the two-document closure rule at build time.

## Non-goals

- No change to the existing tolerant lookups. `is_table_referenced` and the RLS target lookup keep their skip-on-missing behavior, since they serve queries over possibly partial catalogs, not document validation.
- No enforcement of Postgres's rule that referenced columns must carry a unique constraint or primary key. That is a real Postgres apply-time error, but it is a different class of check and the real server already raises it for the shared document. It can be a later extension of the same method.
- No validation-by-default inside `ParserDB` parsing. The method is explicit, and strictness policy belongs to the caller.
