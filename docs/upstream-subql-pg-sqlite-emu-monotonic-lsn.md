# subql `PgSqliteEmuSource` assigns monotonic LSNs (resolved)

## Status

Resolved in `LucaCappelletti94/subql` on `main` (`61591ca`), via `fix/pg-sqlite-emu-monotonic-lsn`: the emulator now stamps a monotonic `next_lsn` per frame. This workspace pins that commit. connetto removed the test-side LSN stamping and the `pg_walstream` dev-dependency, and the reconnect and oplog tests now run against the emulator's real LSNs. The rationale below is kept so the change is not mistaken for accidental.

## The problem

`PgSqliteEmuSource` (subql `src/pg_sqlite_emu/source.rs`) is the Docker-free CDC source: it observes a SQLite session, re-encodes each change as a `pgoutput` frame, and decodes it back into a typed `ChangeEvent`. It decodes every frame with a hardcoded zero LSN:

```rust
// announce_if_needed
let _ = self.decoder.decode_message(buf, Lsn::new(0));
// push_frame
if let Some(decoded) = self.decoder.decode_message(buf, Lsn::new(0))? {
    self.pending.extend(into_engine_events(decoded));
}
```

A `pgoutput` data message (`Insert`, `Update`, `Delete`) carries no LSN in its body. Only `Begin` and `Commit` carry LSNs. Since the emulator emits bare data frames and passes `Lsn::new(0)` as the fallback position, every emitted `ChangeEvent` ends up with `event.lsn == Lsn(0)`, so `CdcEvent::checkpoint()` returns `Some(PgLsn(0))` for every event.

A real Postgres logical-replication stream never does this: each change is associated with a distinct, monotonically increasing WAL position. The emulator is meant to be a faithful stand-in, so this is a fidelity gap, not just a test nuisance.

## Why it matters to connetto

connetto's reconnect and oplog design (see `docs/architecture/06-reconnect.md`) keys entirely on distinct per-event LSNs. The opaque resume cursor is exactly the source `PgLsn` encoded 8 bytes big-endian. The oplog is keyed by that `u64`, and the catchup-versus-full-resync decision compares the client's resume LSN against the oplog window. When every event collapses to LSN 0:

- The oplog stores every record under key 0.
- `entries_since(0)` returns nothing (it is strictly greater than the argument).
- Catchup, reconnect, and the retention window cannot be exercised through the emulator at all.

Because the emulator is the whole Docker-free test path, this makes the most important reliability feature untestable without real Postgres.

## Current workaround in connetto

The reconnect and oplog tests stamp a distinct monotonic LSN onto each emulator event before dispatching it, simulating the WAL positions a real source supplies:

```rust
while let Some(mut event) = source.next_event().await? {
    *next_lsn += 1;
    event.lsn = Lsn::new(*next_lsn);
    manager.dispatch_event(&event).await?;
}
```

This lives in `crates/connetto-server/tests/reconnect.rs` and `crates/connetto-server/tests/pg_async.rs`, and it forced a `pg_walstream` dev-dependency (for the `Lsn` type) into `crates/connetto-server/Cargo.toml`.

## Proposed fix

Have `PgSqliteEmuSource` own a monotonically increasing LSN counter and hand each emitted frame a fresh position, so decoded events carry strictly increasing, distinct checkpoints.

The minimal form is a per-frame counter used in `push_frame`:

```rust
struct PgSqliteEmuSource {
    // ...
    next_lsn: u64,
}

fn push_frame(&mut self, msg: &LogicalReplicationMessage) -> Result<(), PgSqliteEmuError> {
    let mut buf = BytesMut::new();
    encode_message(msg, PROTOCOL_VERSION, &mut buf);
    self.next_lsn += 1;
    if let Some(decoded) = self.decoder.decode_message(buf, Lsn::new(self.next_lsn))? {
        self.pending.extend(into_engine_events(decoded));
    }
    Ok(())
}
```

`Relation` frames in `announce_if_needed` never emit an event, so they can keep `Lsn::new(0)` (or share the counter without consuming a visible position).

A more faithful form wraps each drained transaction in `Begin`/`Commit` with an increasing commit LSN and lets the decoder attach the commit position to the enclosed changes, mirroring how a real stream carries the position on the `Commit`. The simple per-frame counter is enough for a test double and is the smaller change.

## Acceptance

- Every event `PgSqliteEmuSource` yields has a `checkpoint()` strictly greater than the previous event's, starting above zero.
- connetto deletes the test-side LSN stamping in `reconnect.rs` and `pg_async.rs`, drops the `pg_walstream` dev-dependency, and drives catchup, reconnect, and oplog tests directly against the emulator.
- Existing subql tests and doctests that assert on emulator event LSNs are updated to expect the monotonic values.
