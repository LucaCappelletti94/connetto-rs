# Implement `SchemaWithPK` for the parsed `TableSchema` (upstream to sqlite-diff-rs)

## Status

Resolved in the crates.io `0.7.1` release. `TableSchema<S>` implements `SchemaWithPK` (`parser.rs:177`, the header wraps across two lines), alongside the `SchemaWithPK::primary_key_columns()` default and the `ChangesetOp`/`PatchsetOp::primary_key()` op accessors from the companion PR. `op.primary_key()` works on parsed diffs, so both connetto crates consume `0.7.1` directly. Kept as the rationale for the change.

## The gap

`sqlite-diff-rs` already has a full primary-key abstraction, `SchemaWithPK` (in `schema/dyn_table.rs`), with `number_of_primary_keys`, `primary_key_index`, and `extract_pk`, and `IndexableValues` is implemented for every value shape the op views carry: `&[Value<S, B>]` (an INSERT's `values` and a DELETE's `old_values`) and `&[(O, Option<Value<S, B>>)]` (a changeset UPDATE's `(old, new)` pairs). The builder schema `SimpleTable` implements `SchemaWithPK`.

The parsed schema does not. `TableSchema<S>` (in `parser.rs`), which is the schema type every `ChangesetOp` and `PatchsetOp` carries after `ParsedDiffSet::parse`, implements only `DynTable`. So a consumer that parses a diff cannot reach any of the PK helpers through the trait and must hand-roll extraction from the concrete `TableSchema::pk_flags()`. connetto-server does exactly that today (a private `fn pk_indices(schema: &TableSchema<String>)` in `crates/connetto-server/src/materializer.rs`), and connetto-client is about to need the identical code for the write-conflict event, which surfaces the affected rows by primary key.

## The change

Implement `SchemaWithPK` for `TableSchema<S>`, derived from the `pk_flags` the schema already stores. Per the `DynTable::write_pk_flags` contract, each flag byte is the 1-based ordinal position of that column within the composite key, or 0 when the column is not part of the key.

- `number_of_primary_keys(&self)`: the count of non-zero flags.
- `primary_key_index(&self, col)`: `flag(col) - 1` when the flag is non-zero, else `None`.
- `extract_pk(&self, values)`: the key cells read from `values` through `IndexableValues`, matching whatever ordering contract `SimpleTable::extract_pk` already documents, so the parse and build sides behave identically.

Also add a forward, ordered accessor for the key columns, since the trait today only offers the inverse `primary_key_index(col) -> Option<usize>`:

- `primary_key_columns(&self) -> Vec<usize>`: the column indices of the key, ordered by the flag ordinal (key order), as a provided (default) method on `SchemaWithPK` computed from `number_of_columns` plus `primary_key_index`. connetto's read-path key codec encodes composite keys in key order, and the changeset UPDATE case (see the second PR) needs to walk the key columns in order, so an ordered list is required and should not be re-derived by every consumer.

Note the supertrait bound `SchemaWithPK: DynTable + Clone + Hash`. `TableSchema<S>` may need a `Hash` derive (or manual impl) to satisfy it, which is a small additional change in the same PR.

## Why it belongs upstream

Parity. `SimpleTable` (build side) implements `SchemaWithPK`; the parsed schema (read side) should too, so the two are symmetric and diffs are equally ergonomic whether you built them or parsed them. It also removes a class of hand-rolled PK extraction from every downstream that parses diffs, connetto being one.

## Consuming changes in connetto

- Delete the private `fn pk_indices` in `crates/connetto-server/src/materializer.rs` and use `TableSchema::primary_key_columns()` (and `extract_pk` where a full row is in hand).
- connetto-client uses `extract_pk` and `primary_key_columns()` for the conflict-event key extraction rather than copying the server's helper.

## Testing

Parse a diff over a table with a single-column key and over a table with a composite key whose key-column order differs from its table-column order (for example columns `(a, b, c)` with key `(b, a)`, flags `[2, 1, 0]`). Assert `number_of_primary_keys`, `primary_key_index`, `primary_key_columns` (in key order), and `extract_pk` match the `SimpleTable` results for the same shape.
