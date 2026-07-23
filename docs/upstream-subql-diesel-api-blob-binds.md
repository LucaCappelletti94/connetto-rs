# subql diesel_api SQLite render should accept blob binds (resolved)

## Status

Resolved in `LucaCappelletti94/subql` on `main` (`d999fbd7`, PR 18). connetto-client now renders through `render_typed` and deleted its hand-rolled collector walk. The proposal below is kept for the record.

## The problem

`diesel_api::render_typed::<Sqlite, _>` renders a typed diesel query into placeholder SQL plus decoded `Value<SQLite>` binds. The SQLite bind decode (`owned_sqlite_to_value`, `src/diesel_api/mod.rs` line 222) rejects the blob variant with "a BLOB has no direct scalar representation in the supported subset".

That restriction is internally inconsistent. `Value<SQLite>` has a `Bytes` variant (`src/backend.rs` line 130), and the SQLite CDC decode path already maps blob wire values into it (`src/sqlite_cdc/parser.rs` line 302, `WireValue::Blob(b)` to `Value::Bytes(b)`). The render path is the only place a SQLite blob is unrepresentable, and after it every other `OwnedSqliteBindValue` variant is covered, so the rejection arm disappears entirely.

## Context in connetto

connetto-client renders typed diesel queries to SQL plus wire binds with its own `SqliteQueryBuilder` plus `SqliteBindCollector` walk (`crates/connetto-client/src/live.rs`, `render_query`), which maps `OwnedSqliteBindValue::Binary` to its wire blob type. That function duplicates `render_typed`'s `BindDecode` impl for SQLite, and subql is already a direct dependency of connetto-client. The only functional gap stopping connetto-client from deleting `render_query` in favor of `render_typed` is this blob rejection. This is the motivating downstream, and the reason the change is worth making even though blob predicates are a rare workload.

## Proposed change

In `owned_sqlite_to_value`, map the blob variant to bytes instead of rejecting it:

```rust
OwnedSqliteBindValue::Binary(b) => Ok(Value::Bytes(b.to_vec())),
```

(using whatever ownership shape the surrounding match already works with). No signature changes. The doc comment loses its blob caveat.

## Tests

- Render with a blob bind: a typed diesel query filtering a binary column by `vec![1u8, 2, 3]` renders to SQL containing a `?` placeholder, no inlined value, and binds equal to `vec![Value::Bytes(vec![1, 2, 3])]`.
- Empty blob renders to `Value::Bytes(vec![])`.
- Bind order: a query with a text bind, then a blob bind, then an integer bind yields the three values in exactly that order, so placeholder position and bind position stay aligned.
- Existing variants unchanged: null, integer, float, and text binds decode as before (regression guard).
- End to end with the placeholder-resolution change: `register_typed` over a SQLite-dialect engine with a blob-filtered query registers and matches a row carrying the same bytes. Marked as depending on the `Value::Bytes` bind-resolution change landing first.

## Correctness expectations

The rendered pair equals what diesel itself would execute locally: the SQL skeleton is unchanged by this fix, bind values are bit-exact copies of the diesel binds, and bind order matches placeholder order. After the change the SQLite decode is total over `OwnedSqliteBindValue`, so `render_typed::<Sqlite, _>` can no longer fail on a bind's type, only on diesel failing to render the query.
