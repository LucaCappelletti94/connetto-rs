# diesel: `vacuum` and `vacuum_into` helpers for `SqliteConnection` (proposal, not yet filed)

## Status

Proposal for `diesel-rs/diesel` (the workspace builds on the fork's `future` branch). Not filed yet. One of five deliberately small sibling proposals for the SQLite maintenance surface.

## The problem

`VACUUM` is the statement every SQLite deployment eventually runs, and `VACUUM INTO` is the engine's recommended online backup primitive (a consistent, minimal, defragmented copy written without blocking the source). Both are strings today. For plain `VACUUM` that is only mild friction, but `VACUUM INTO` takes a filename, and a hand-formatted filename has the same hazards the `attach_database` proposal documents: quote breakage and an injection surface for paths that come from config or user directories.

## Proposed API

```rust
impl SqliteConnection {
    /// Rebuild a database file, repacking it into minimal disk space.
    ///
    /// `schema` selects an attached database, `None` targets `main`.
    /// Fails inside an open transaction.
    pub fn vacuum(&mut self, schema: Option<&str>) -> QueryResult<()>;

    /// Write a vacuumed copy of a database into a new file at `path`.
    ///
    /// The path is passed as a bound parameter, so no escaping is applied
    /// or needed. `schema` selects an attached database, `None` copies
    /// `main`. The destination must not exist. The source is not modified.
    pub fn vacuum_into(&mut self, schema: Option<&str>, path: &str) -> QueryResult<()>;
}
```

Implementation notes:

- Verified on SQLite 3.51.1: the `VACUUM INTO` filename is an expression and **binds as a parameter** (`VACUUM INTO ?`), the same fact that makes `attach_database` safe. No quoting code for the path at all.
- The schema operand is an identifier, not an expression, so it is interpolated double-quoted with interior quotes doubled, as in the sibling proposals.
- No new ffi symbols: pure SQL through the existing statement path, compiling identically across diesel's whole accepted `libsqlite3-sys` range (`>=0.17.2`, which links the system SQLite by default) and the `sqlite-wasm-rs` backend.
- The runtime version floor is the one real gate in this series, because system linkage can meet genuinely old SQLite: `VACUUM INTO` requires 3.27.0 (2019) and the schema-targeted `VACUUM <schema>` form requires 3.24.0 (2018). On older SQLite both fail at prepare with an ordinary `QueryResult` syntax error, never undefined behavior, and the doc comments carry a "Requires SQLite 3.27.0 / 3.24.0, otherwise returns an error" line in the existing house style (the dbconfig knobs already document 3.49.0 the same way).
- The doc comments carry the operational rules: `VACUUM` cannot run inside a transaction, needs up to twice the file size in temporary space, and resets `rowid`s of tables without an explicit `INTEGER PRIMARY KEY`. `VACUUM INTO` fails if the destination exists and does not fsync-guarantee the copy until the returned call completes.

## Tests for the diesel PR

- After a bulk delete, `vacuum(None)` reduces `page_count`.
- `vacuum_into` produces a copy that opens and returns identical rows, including through a destination path containing a single quote (pins the bound parameter).
- `vacuum_into` to an existing path fails with an ordinary `QueryResult` error.
- `vacuum` inside an open transaction fails cleanly.
- Attached database targeted by `schema` for both methods.

## Downstream use in connetto (once landed)

`vacuum_into` is the natural implementation of replica export and of full-rewrite compaction where incremental vacuum is unavailable (a template shipped without `auto_vacuum`), and plain `vacuum` is the escape hatch that makes a late `auto_vacuum` mode change take effect. See the replica retention section of `docs/roadmap.md`.
