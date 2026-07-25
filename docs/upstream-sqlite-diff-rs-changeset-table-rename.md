# sqlite-diff-rs: in-place table rename on `ParsedDiffSet` (landed upstream)

## Status

**Resolved: landed on `LucaCappelletti94/sqlite-diff-rs` main** (PR #38, `541a3dd`) with exactly the proposed signature, `ParsedDiffSet::rename_tables<F: FnMut(&str) -> Option<String>>(&mut self, rename: F) -> usize` (`src/parser.rs:331` on main), and released to crates.io as `0.8.0`. The proposal below is kept as written for the rationale record, file:line cites refer to `7a05c68` (0.7.1).

## The problem

A diffset captured against one schema sometimes has to apply against another where the same tables carry different physical names. The concrete case: pg2sqlite's RLS translation renames the storage table and puts a view under the logical name, and `sqlite3changeset_apply` has no table-name hook of its own. Worse, applying under the wrong name is not an error. A name resolving to nothing skips the section with only an `sqlite3_log` line (`sqlite3session.c:5677-5682`), and a name resolving to the view passes the shape checks (`PRAGMA table_xinfo` works on views and the missing PK becomes an implicit rowid key, `sqlite3session.c:1116,1129-1139`) only for every row to misfire as a per-row `Constraint` conflict that a server-wins policy omits. Both shapes are silent data loss, so the rename must happen on the changeset bytes, between capture and apply.

The crate already round-trips the bytes: `ParsedDiffSet::parse` and `From<ParsedDiffSet> for Vec<u8>` (`src/parser.rs:257-264`), with row order preserved across roundtrips (`src/builders/change.rs:1071-1073`). But the table name is frozen on the way through: `TableSchema` keeps `name` private with only a getter (`src/parser.rs:93-105`, getter at `:123`), `DiffSet.tables` is `pub(crate)` (`src/builders/change.rs:1080`), and no rename API exists (no hit for `rename` outside serde attributes). A consumer today has no path short of rebuilding the whole diffset through `DiffSetBuilder`, re-inserting every operation by hand, to change nothing but a name.

Renaming is name-only by construction of the use case: the logical and physical tables have identical columns and primary keys (the physical table may carry *extra trailing* columns, which apply tolerates per `sqlite3session.c:5683-5689`), so column count, pk flags, and operations are untouched.

## Proposed API

```rust
impl ParsedDiffSet {
    /// Rename table sections in place. For each table section the
    /// callback receives the current name and returns the new name,
    /// or `None` to leave the section unchanged. Returns the number
    /// of sections renamed.
    pub fn rename_tables<F>(&mut self, rename: F) -> usize
    where
        F: FnMut(&str) -> Option<String>;
}
```

A callback instead of a map parameter: it imposes no map type and lets consumers close over whatever they have (a baked static table, a `HashMap`, a suffix rule). Only the schema name field changes. If the callback maps two sections to the same name they stay two sections: the binary format permits repeated sections for one table and apply processes sections sequentially, so no merging is attempted or needed.

## Implementation notes

One method on `ParsedDiffSet`, matching on the two variants and mutating `TableSchema::name` directly, which is trivial from inside the crate and impossible from outside. No public field exposure, no builder round-trip, no re-hashing: the frozen `DiffSet` stores tables as an ordered `Vec`, not keyed by name (`change.rs:1078-1081`), so a name swap cannot invalidate any lookup structure.

## Tests

- End-to-end proof that renamed bytes are valid: capture a real changeset against `orders` via the session extension, parse, rename to `orders_rls`, encode via `Vec<u8>::from`, and `sqlite3changeset_apply` it into a database whose physical table is `orders_rls`. Assert the rows landed.
- The all-`None` callback returns 0 and re-encodes to an equivalent diffset (the existing roundtrip guarantees apply unchanged).
- The rename count matches the number of sections actually renamed, not the number of callback invocations.
- Patchset variant of the end-to-end test.
- Empty diffset returns 0.

## Downstream use

connetto's sync contract makes the wire speak logical Postgres names while RLS-translated replicas store rows under suffixed physical names. The client rewrites at two byte boundaries: incoming server changesets from logical to physical before apply, and captured local changesets from physical back to logical before upload. The map driving the callback is exported at build time by pg2sqlite, see the sibling proposal `docs/upstream-pg2sqlite-translation-manifest.md`.
