# Diesel `table!` and `missing_docs = forbid` (resolved)

## Status

Resolved in the `LucaCappelletti94/diesel` `future` fork, commit `c1aa2e9`. The workspace `Cargo.lock` pins that commit. The five integration tests in `crates/connetto-server/tests/` (`inprocess_loop.rs`, `session_loop.rs`, `snapshot_source.rs`, `write_path.rs`, `pg_async.rs`) declare `diesel::table!` at file scope again. The private `mod schema { ... }` wrappers that worked around the old behavior are gone.

This note is kept as the rationale for the fork change, so the behavior is not mistaken for accidental and reverted.

## The problem

The workspace sets `missing_docs = "forbid"`. A bare `diesel::table! { ... }` used to fail to compile because two generated public items carried no documentation: the table module `pub mod #table_name`, and each per-column struct `pub struct #column_name`. Both emitted only the caller's doc comments (`#(#meta)*`), which are empty for an undocumented table or column. That `#(#meta)*`-only pattern was upstream from 2022, not a fork regression. Upstream and the fork had documented every other generated item (`dsl`, the `table` struct, `columns`, `star`, `BoxedQuery`, `AllColumns`, `all_columns`, `SqlType`), but not these two.

`missing_docs` is `forbid`, not `deny`, so the macro could not emit an `#[allow(missing_docs)]` escape hatch: that is rejected with `E0453: allow(missing_docs) incompatible with previous forbid`. The generated items had to either carry real docs or be hidden from the doc surface.

## The fix

Fabricated fallback doc strings were rejected on purpose: a doc that restates the item name carries no information. Instead the macro marks the two items `#[doc(hidden)]` when, and only when, the caller supplied no doc comment. `missing_docs` does not fire on `#[doc(hidden)]` items, and `#[doc(hidden)]` on a module propagates to every descendant. This matches diesel's existing style, which already uses `#[doc(hidden)]` internally (for example the `pub use self::view as table` re-export).

In `diesel_derives/src/table.rs` the fork adds:

```rust
/// Emits `#[doc(hidden)]` unless the caller documented the item.
fn doc_hidden_unless_documented(meta: &[syn::Attribute]) -> TokenStream {
    if meta.iter().any(|attr| attr.path().is_ident("doc")) {
        TokenStream::new()
    } else {
        quote::quote!(#[doc(hidden)])
    }
}
```

applied before `pub mod #table_name` (using the table-level `meta`) and before `pub struct #column_name` (using the column `meta`). The doc check reuses the same `attr.path().is_ident(...)` pattern the file already uses for `cfg` detection.

## Resulting behavior

| table doc | column doc | result |
| --- | --- | --- |
| present | present | both visible in rustdoc with the caller's text |
| present | absent | module visible, undocumented column structs are `#[doc(hidden)]` |
| absent | either | module is `#[doc(hidden)]`, so the whole schema is hidden |

An undocumented public module cannot be both visible and `forbid`-clean, so an undocumented table is hidden. To surface any part of a table's schema in rustdoc, give the table a doc comment. This is why the table doc drives module visibility.

## Optional follow-up

Upstream still documents the internal helper types (`dsl`, the `table` struct, `star`, `BoxedQuery`) with generic fabricated text, the same low-value kind of doc this fix avoids. Converting those to `#[doc(hidden)]` would make the generated schema fully consistent, but it is a larger change against upstream's direction and was not part of this fix.
