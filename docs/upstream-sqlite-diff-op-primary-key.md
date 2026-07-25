# A `primary_key()` accessor on `ChangesetOp` and `PatchsetOp` (upstream to sqlite-diff-rs)

## Status

Resolved in the crates.io `0.7.1` release. `ChangesetOp::primary_key()` and `PatchsetOp::primary_key()` shipped (`builders/view.rs`), with the old-first UPDATE rule below, and they compose with the companion PR's `impl SchemaWithPK for TableSchema`, so `op.primary_key()` works on parsed diffs. connetto now consumes `0.8.0` workspace-wide. Kept as the rationale for the change.

## The gap

`ChangesetOp` (in `builders/view.rs`) exposes `table()` but no way to read the primary-key cells of the operation. A consumer that wants the identity of a row in a parsed diff has to match all three variants and, for the UPDATE case, unpack the `(Option<old>, Option<new>)` pairs by hand. That last part has a real subtlety that is easy to get wrong: the key must be read old-first, `old.or(new)`, because a changeset UPDATE reliably carries the key in the old slot (it is the row's identity) while the new slot may be absent for a key column that did not change. connetto-server already hand-rolls exactly this in `plan_changeset_op`, taking `values[i].0.clone().or_else(|| values[i].1.clone())`, and connetto-client needs the same logic for its write-conflict event.

## The change

Add an accessor that folds the variant match once and returns the key cells in key order:

```rust
impl<'a, T: SchemaWithPK, S: Clone, B: Clone> ChangesetOp<'a, T, S, B> {
    pub fn primary_key(&self) -> Vec<Value<S, B>> { /* see below */ }
}
```

Behavior per variant, using `table().extract_pk` and `table().primary_key_columns()` from the companion PR:

- `Insert { values, .. }`: `table.extract_pk(values)`. The row is full, the key is present.
- `Delete { old_values, .. }`: `table.extract_pk(old_values)`. Same, over the old row.
- `Update { values, .. }`: for each column index in `table.primary_key_columns()`, take `values[i].0` (old) or, when that is `None`, `values[i].1` (new). This is the old-first rule above and is the reason the accessor cannot simply call `extract_pk` on the pair slice: `IndexableValues` over a pair slice yields the new value, which can be `None` for an unchanged key column.

Add the matching `PatchsetOp::primary_key()`. Patchsets already carry only the key columns for UPDATE and DELETE, so those variants return their cells directly, and INSERT uses `extract_pk` as above.

## Why it belongs upstream

It is the single ergonomic capstone over the first PR. With it, reading the identity of every operation in a parsed diff is `op.primary_key()`, with no variant match and no old-first pair handling at the call site. It removes the duplicated, subtle extraction from connetto-server (`plan_changeset_op`) and gives connetto-client a one-liner. The old-first UPDATE rule is a correctness trap that belongs encoded once in the crate rather than re-derived by each consumer.

## Consuming changes in connetto

- connetto-server: replace the per-variant PK extraction in `plan_changeset_op` with `op.primary_key()`.
- connetto-client: the write-conflict event is built as `for op in diff.iter() { rows.push((op.table().name().to_owned(), op.primary_key())) }`.

## Testing

For a table with a single-column key and one with a composite key, assert `primary_key()` returns the expected cells in key order for each of INSERT, UPDATE, and DELETE. Include an UPDATE that changes only a non-key column, to confirm the key still comes back (from the old slot) rather than a `None`. Repeat the INSERT and the DELETE-or-UPDATE key-only cases for `PatchsetOp`.
