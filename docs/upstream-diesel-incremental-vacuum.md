# diesel: an `incremental_vacuum` helper for `SqliteConnection` (proposal, not yet filed)

## Status

Proposal for `diesel-rs/diesel` (the workspace builds on the fork's `future` branch). Not filed yet. One of five deliberately small sibling proposals for the SQLite maintenance surface. Pairs naturally with the `AutoVacuumMode` proposal but has no code dependency on it.

## The problem

`PRAGMA incremental_vacuum` is the only way to return freelist pages to the filesystem without a full `VACUUM` rewrite, and it carries a trap that makes a first-class helper more than sugar. Verified on SQLite 3.51.1: the pragma frees **one page per step** and yields one result row per freed page. A consumer who prepares it and steps once (the natural shape of "execute a statement, ignore the output") frees exactly one page and silently leaves the rest, which is indistinguishable from "it ran" until the file keeps growing. The statement must be driven to completion, which `sqlite3_exec` (diesel's `batch_execute`) does and a single prepared step does not.

## Proposed API

```rust
impl SqliteConnection {
    /// Free pages from the freelist of a database in incremental
    /// auto-vacuum mode, truncating the file.
    ///
    /// `schema` selects an attached database, `None` targets `main`.
    /// `pages` bounds how many pages are reclaimed, `None` clears the
    /// whole freelist. A no-op on databases in any other auto-vacuum mode.
    pub fn incremental_vacuum(&mut self, schema: Option<&str>, pages: Option<u32>) -> QueryResult<()>;
}
```

Implementation notes:

- Executes `PRAGMA <schema>.incremental_vacuum` (or `(N)`) through `batch_execute`, which steps every row to completion. The implementation comment states the one-page-per-step behavior so the exec choice survives refactors.
- `PRAGMA` accepts no bound parameters, so the schema name is interpolated as a double-quoted identifier with interior quotes doubled, and `pages` is formatted from a `u32`, which cannot carry an injection.
- No new ffi symbols: pure SQL through the existing statement path, compiling identically across diesel's whole accepted `libsqlite3-sys` range (`>=0.17.2`, system SQLite by default) and the `sqlite-wasm-rs` backend. The pragma dates to 3.4.0 (2007), below anything that range can meet.
- The `pages` bound exists for latency control: a per-frame maintenance tick can reclaim a few pages at a time instead of stalling on a large freelist.

## Tests for the diesel PR

- On an `INCREMENTAL` mode file: insert and delete enough rows to grow the freelist, `incremental_vacuum(None, None)` drives `freelist_count` to zero (this pins the drive-to-completion behavior, the single-step bug would leave it near its starting value).
- `incremental_vacuum(None, Some(n))` with `n` smaller than the freelist reclaims at most `n` pages.
- On a `NONE` mode database the call succeeds and changes nothing.
- Attached database targeted by `schema`.

## Downstream use in connetto (once landed)

The retention design's trimming pass runs bounded incremental vacuum after eviction so deleted windows actually return disk (and OPFS quota in the browser). See the replica retention section of `docs/roadmap.md`.
