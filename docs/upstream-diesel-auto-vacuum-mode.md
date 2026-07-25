# diesel: typed `auto_vacuum` mode control for `SqliteConnection` (proposal, not yet filed)

## Status

Proposal for `diesel-rs/diesel` (the workspace builds on the fork's `future` branch, which tracks main closely in this area). Not filed yet. One of five deliberately small sibling proposals for the SQLite maintenance surface (auto-vacuum mode, incremental vacuum, WAL checkpoint, page counters, vacuum into), sliced per API so each PR reviews quickly.

## The problem

`auto_vacuum` decides whether a SQLite file can ever shrink, and it is the single pragma that must be set before the schema exists: switching from `NONE` on a populated file silently does nothing until a full `VACUUM` rewrites it. Today diesel consumers write `batch_execute("PRAGMA auto_vacuum = INCREMENTAL")` by hand, get no value back when reading the mode, and learn the stickiness rule from production file bloat instead of from a doc comment.

## Proposed API

```rust
/// The auto_vacuum mode of a database.
pub enum AutoVacuumMode {
    /// Freed pages stay on the freelist and the file never shrinks (default).
    None,
    /// Freed pages are reclaimed and the file truncated at every commit.
    Full,
    /// Freelist bookkeeping is kept, pages are reclaimed only when
    /// `incremental_vacuum` runs.
    Incremental,
}

impl SqliteConnection {
    /// Read the auto_vacuum mode. `schema` selects an attached database,
    /// `None` reads `main`.
    pub fn auto_vacuum(&mut self, schema: Option<&str>) -> QueryResult<AutoVacuumMode>;

    /// Set the auto_vacuum mode. `schema` selects an attached database,
    /// `None` targets `main`.
    pub fn set_auto_vacuum(&mut self, schema: Option<&str>, mode: AutoVacuumMode) -> QueryResult<()>;
}
```

Implementation notes:

- `PRAGMA` accepts no bound parameters, so the schema name is interpolated as a double-quoted identifier with interior quotes doubled. This is the one place the helper does its own quoting, and the reason a helper beats hand-rolled strings.
- The read maps `0/1/2` to the enum and returns a deserialization error on anything else.
- No new ffi symbols: pure SQL through the existing statement path, so the method compiles identically across diesel's whole accepted `libsqlite3-sys` range (`>=0.17.2`, which links the system SQLite by default) and the `sqlite-wasm-rs` backend. The pragma itself predates (2005 to 2007) every SQLite that range can meet, so no version note is needed.
- Verified on SQLite 3.51.1: setting `INCREMENTAL` on a fresh database (memory databases included) reads back `2` and sticks after the first `CREATE TABLE`.

The doc comment carries the semantics that make the API worth having: the mode is stored in the file, not the connection, `Full` and `Incremental` can be switched at any time, but changing from or to `None` only takes effect on a database with no tables yet or after a subsequent `VACUUM` rewrites the file.

## Tests for the diesel PR

- Fresh database: set `Incremental`, read back `Incremental`, create a table, read back still `Incremental`.
- Populated `None` database: set `Full`, read back still `None` (the stickiness rule pinned as observable behavior), then `VACUUM`, read back `Full`.
- Attached database targeted by `schema`, including a schema name containing a double quote.
- All three modes roundtrip on fresh files.

## Downstream use in connetto (once landed)

The replica templates bake `auto_vacuum = INCREMENTAL` at build time (the only moment the rule allows it for free), and the retention design's trimming pass reads the mode defensively before running incremental vacuum. See the replica retention section of `docs/roadmap.md`.
