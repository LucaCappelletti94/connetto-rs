# subql placeholder resolution should accept Value::Bytes binds (resolved)

## Status

Resolved in `LucaCappelletti94/subql` on `main` (`d999fbd7`, PR 17), pinned by the workspace. Bytes binds resolve through the hex literal round trip and connetto registers blob binds natively. The proposal below is kept for the record.

## The problem

Registration resolves `Value::Placeholder` leaves against `SubscriptionRequest::binds` by converting each typed bind into a sqlparser literal and re-injecting it into the AST (`src/compiler/parser.rs`, `resolve_placeholders` at line 371, `value_to_sql_value` at line 311). The conversion supports `Null`, `Int`, `Float`, and `String`. Everything else, `Value::Bytes` included, is rejected:

```rust
Value::Bool(_)
| Value::Bytes(_)
| ...
| Value::Jsonb(_) => Err(RegisterError::BindResolution(format!(
    "bind value of {kind:?} scalar not yet supported through placeholder resolution",
    ...
)))
```

The comment above the function says these stay rejected "until a downstream test exercises them and pins a canonical round-trip format". For `Bytes` that format already exists in the opposite direction inside the same compiler: `SqlLiteralParse::parse_literal` maps `SqlValue::HexStringLiteral` to `Value::Bytes` for all three backends (`src/compiler/literals.rs` lines 191, 238, and 289). The decode leg is pinned, only the encode leg is missing.

## Context in connetto

connetto clients bind blobs through diesel (`BindValue::Blob` on the wire). Today the connetto server injects them itself as `SqlValue::HexStringLiteral` before subql ever sees the query, inside its own literal substitution pass. That pass duplicates `resolve_placeholders` and is being deleted so binds ride `SubscriptionRequest::binds` natively. Without this change, deleting it would regress blob binds from working to rejected. The downstream test the comment asks for is exactly connetto's typed live query path.

## Proposed change

Add one arm to `value_to_sql_value`:

```rust
Value::Bytes(b) => Ok(SqlValue::HexStringLiteral(hex_upper(b.as_ref()))),
```

with uppercase hex encoding (matching sqlparser's conventional `X'DEADBEEF'` rendering), leaving every other rejected variant untouched. `Bool` stays rejected for the reason already documented there, its sqlparser spelling is backend-specific under a generic `B`.

## Tests

- Encode and decode round trip, per backend: for `Postgres`, `SQLite`, and `MySql`, `parse_literal(&value_to_sql_value(&Value::Bytes(v))?, ScalarKind::Bytes)` returns `Value::Bytes(v)` for `v = vec![0xde, 0xad, 0xbe, 0xef]` and for `v = vec![]`.
- Registration level: `SubscriptionRequest::new(c, "SELECT * FROM t WHERE payload = $1").binds(vec![Value::Bytes(...)])` registers successfully where it errors today.
- Matching level, through the existing `testing::TestEvent` harness: after registering the query above, a CDC row whose `payload` cell equals the bound bytes matches, and a row with different bytes does not. Comparison semantics follow the existing `value_cmp` rules (bytewise equality, lexicographic ordering).
- Positional form: the same registration through a bare `?` placeholder resolves identically.
- Unchanged rejections: a `Value::Missing` bind and a `Value::Bool` bind still produce `RegisterError::BindResolution` (regression guard on the untouched arms).

## Correctness expectations

The pinned contract is the internal identity round trip: `parse_literal(value_to_sql_value(Value::Bytes(v))) == Value::Bytes(v)` for every byte vector, empty included. A bytes bind then behaves exactly as if the caller had written the equivalent `X'...'` literal inline, which the compiler already supports, so no new literal semantics are introduced anywhere downstream of resolution.

## Out of scope

Normalized SQL containing hex literals is also what reaches connector re-execution and aggregate bootstrap statements, which run on a real backend where `X'...'` means different things (a Postgres bit string rather than a `bytea`). That concern predates this change, applies equally to inline hex literals today, and is not altered by encoding binds the same way. It should be tracked separately if connector-executed queries over bytes columns become a real workload.
