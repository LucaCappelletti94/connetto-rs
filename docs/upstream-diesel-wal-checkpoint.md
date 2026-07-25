# diesel: a typed `wal_checkpoint` for `SqliteConnection` (proposal, not yet filed)

## Status

Proposal for `diesel-rs/diesel` (the workspace builds on the fork's `future` branch). Not filed yet. One of five deliberately small sibling proposals for the SQLite maintenance surface.

## The problem

diesel's own documentation already tells users to run WAL checkpoints as strings: the `SqliteConnection` establishing example runs `batch_execute("PRAGMA wal_checkpoint(TRUNCATE);")` and the `on_wal` hook example does the same inside the callback. The string form throws away the pragma's entire result: whether the checkpoint was blocked by a busy reader, and how many frames were actually moved. Those values are the difference between "the WAL is bounded" and "the WAL silently grows because a long-lived reader pins it", and today a diesel user cannot see them without hand-rolling a `sql_query` row type.

## Proposed API

```rust
/// The checkpoint mode, per sqlite3_wal_checkpoint_v2.
pub enum WalCheckpointMode {
    /// Checkpoint what is possible without waiting on readers or writers.
    Passive,
    /// Wait for writers, then checkpoint every frame.
    Full,
    /// Like Full, then wait until no reader uses the WAL, so the next
    /// writer restarts the log.
    Restart,
    /// Like Restart, then truncate the WAL file to zero bytes.
    Truncate,
}

/// The result of a checkpoint run.
pub struct WalCheckpointOutcome {
    /// Whether the checkpoint stopped early because of a busy reader or writer.
    pub busy: bool,
    /// Frames in the WAL after the checkpoint, `None` when the database is
    /// not in WAL mode.
    pub log_frames: Option<i64>,
    /// Frames successfully moved into the database file, `None` when the
    /// database is not in WAL mode.
    pub checkpointed_frames: Option<i64>,
}

impl SqliteConnection {
    /// Checkpoint the write-ahead log.
    ///
    /// `schema` selects one attached database, `None` checkpoints every
    /// attached database (the unqualified pragma's behavior).
    pub fn wal_checkpoint(&mut self, schema: Option<&str>, mode: WalCheckpointMode) -> QueryResult<WalCheckpointOutcome>;
}
```

Implementation notes:

- Wraps `PRAGMA wal_checkpoint(MODE)`, whose result row is `(busy, log, checkpointed)`, verified on SQLite 3.51.1. On a database not in WAL mode the row is `(0, -1, -1)`, mapped to `busy: false` with `None` frame counts, so the call is safe to issue unconditionally.
- The `schema: None` semantics differ from the other maintenance pragmas on purpose: an unqualified `wal_checkpoint` applies to every attached database, while an unqualified `auto_vacuum` or `page_count` reads `main`. The doc comment states this asymmetry explicitly because it is SQLite's, not the helper's.
- No new ffi symbols, and that is a deliberate choice: `sqlite3_wal_checkpoint_v2` would deliver the same three values through the C API, but diesel's ffi is an alias spanning the whole accepted `libsqlite3-sys` range (`>=0.17.2`, system SQLite by default) plus the `sqlite-wasm-rs` shim, and the pragma form sidesteps that surface entirely while returning the identical row.
- Requires SQLite 3.7.0 (2010, WAL itself) at runtime, otherwise the statement fails with an ordinary error. Below every bundled build, only reachable through system linkage against museum pieces.
- `PRAGMA` accepts no bound parameters, so the schema name is interpolated as a double-quoted identifier with interior quotes doubled.

## Tests for the diesel PR

- WAL file database, write, `Truncate`: `busy` is false and both frame counts are `Some(0)` (the log was truncated).
- Non-WAL database (memory works): `Ok` with both frame counts `None`.
- A checkpoint with an open reader on another connection reports `busy` for the blocking modes.
- All four mode keywords render and execute.
- Attached WAL database targeted by `schema`.

## Downstream use in connetto (once landed)

The replica connections run WAL, and the retention design's trimming pass follows eviction with `wal_checkpoint(None, Truncate)` so the reclaimed space is not immediately re-hidden inside a grown WAL file. The `busy` flag feeds the pass's retry decision. See the replica retention section of `docs/roadmap.md`.
