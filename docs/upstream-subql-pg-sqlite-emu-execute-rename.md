# subql `PgSqliteEmuSource::execute` renamed to `execute_sql` (resolved)

## Status

Resolved in `LucaCappelletti94/subql` on `main` (`61591ca`), via `fix/pg-sqlite-emu-execute-sql-rename`: the emulator method is now `execute_sql`, which no longer collides with diesel's blanket `RunQueryDsl::execute`. This workspace pins that commit and calls `source.execute_sql(...)` throughout. The rationale below is kept for the record.

## The problem

`PgSqliteEmuSource` (subql `src/pg_sqlite_emu/source.rs`) exposes an inherent method to run DML against the emulated backend:

```rust
pub fn execute(&mut self, sql: &str) -> Result<usize, PgSqliteEmuError> { ... }
```

diesel provides `RunQueryDsl` with a blanket implementation for all types, and its method takes `self` by value:

```rust
fn execute<'conn, 'query>(self, conn: &'conn mut Conn) -> ...
```

When a consumer has `diesel::RunQueryDsl` in scope (which is common, since it is in `diesel::prelude`), the call `source.execute(sql)` resolves to `RunQueryDsl::execute`, not the inherent method. Rust builds its receiver-candidate list starting with the by-value receiver, and at that first step the by-value `RunQueryDsl::execute(self, conn)` matches before the inherent `execute(&mut self, sql)` (which needs an autoref step). The compiler then reads `source` as the query and `sql` as the connection, producing a confusing type error:

```
error[E0308]: mismatched types
   |
   |     source.execute(sql)
   |            ------- ^^^ types differ in mutability
   |                        expected `&mut _`, found `&str`
```

The inherent method is effectively shadowed whenever the emulator and diesel's query DSL are used together, which is the normal case for a SQLite-backed test.

## Current workaround in connetto

`crates/connetto-server/tests/pg_async.rs` calls the inherent method with fully-qualified syntax to sidestep resolution:

```rust
PgSqliteEmuSource::execute(&mut source, sql).expect("execute dml");
```

Other tests that do not import `RunQueryDsl` unqualified still write `source.execute(sql)`, so the same code reads two different ways depending on imports, which is exactly the footgun.

## Proposed fix

Rename the emulator's inherent method to a name that does not collide with diesel's trait method. `execute_sql` reads well and states intent:

```rust
pub fn execute_sql(&mut self, sql: &str) -> Result<usize, PgSqliteEmuError> { ... }
```

`run_sql` is an acceptable alternative. This is a breaking change to the emulator's inherent surface, so subql's own tests, doctests, and the `PgSqliteEmuSource` examples that call `.execute(...)` are updated in the same change.

## Acceptance

- `source.execute_sql(sql)` resolves to the emulator method unambiguously even with `diesel::RunQueryDsl` (or `diesel::prelude::*`) in scope.
- connetto replaces the fully-qualified `PgSqliteEmuSource::execute(&mut source, sql)` and every `source.execute(...)` call with `source.execute_sql(...)`.
