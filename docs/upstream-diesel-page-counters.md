# diesel: `page_count` and `freelist_count` readers for `SqliteConnection` (proposal, not yet filed)

## Status

Proposal for `diesel-rs/diesel` (the workspace builds on the fork's `future` branch). Not filed yet. One of five deliberately small sibling proposals for the SQLite maintenance surface. This is the observability half: the other proposals act, these two decide when acting is worth it.

## The problem

Every vacuum policy is a comparison of two numbers: how big the file is (`page_count` times the page size) and how much of it is reclaimable slack (`freelist_count`). Neither is readable through diesel today without a hand-rolled `sql_query` row type per pragma, so maintenance code either skips the check and vacuums blindly, or every consumer reinvents the same two structs.

## Proposed API

```rust
impl SqliteConnection {
    /// Total pages in a database. `schema` selects an attached database,
    /// `None` reads `main`. Multiply by the page size for the file size the
    /// database accounts for.
    pub fn page_count(&mut self, schema: Option<&str>) -> QueryResult<i64>;

    /// Unused pages on the freelist. `schema` selects an attached database,
    /// `None` reads `main`. A growing freelist is reclaimable space.
    pub fn freelist_count(&mut self, schema: Option<&str>) -> QueryResult<i64>;
}
```

Implementation notes:

- Both wrap the schema-qualified pragma form, `PRAGMA "schema".page_count`. The pragma table-valued functions are not usable for schema targeting: verified on SQLite 3.51.1, `pragma_page_count('main')` accepts the schema argument while `pragma_freelist_count('main')` fails with "too many arguments, max 0". The qualified pragma form works uniformly for both, so the implementation must use it.
- `PRAGMA` accepts no bound parameters, so the schema name is interpolated as a double-quoted identifier with interior quotes doubled.
- Returns `i64`: page counts are 32-bit unsigned in the file format, which does not fit `i32`.
- No new ffi symbols: pure SQL through the existing statement path, compiling identically across diesel's whole accepted `libsqlite3-sys` range (`>=0.17.2`, system SQLite by default) and the `sqlite-wasm-rs` backend. Both pragmas date to 2007 and 2008, below anything that range can meet.

## Tests for the diesel PR

- `page_count` is positive on a fresh database and grows after bulk inserts.
- `freelist_count` is zero on a fresh database, grows after a bulk delete, and returns to zero after `VACUUM`.
- Attached database targeted by `schema` reports its own counts, not `main`'s.
- A schema name containing a double quote is handled.

## Downstream use in connetto (once landed)

The retention design's trimming pass triggers on `freelist_count` relative to `page_count` (reclaim only when slack crosses a threshold) instead of vacuuming on a timer, and the same counters feed replica size reporting in the browser, where OPFS quota is the scarce resource. See the replica retention section of `docs/roadmap.md`.
