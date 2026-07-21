# subql diffset apply should depend on the catalog, not the whole engine (resolved)

## Status

Resolved in `LucaCappelletti94/subql` on `main` (`f331aced`), via `refactor/diffset-apply-catalog`: `apply_diffset_bytes` and `apply_diffset_bytes_async` now delegate to public catalog-only entry points `apply_diffset_bytes_with_catalog` and `apply_diffset_bytes_async_with_catalog` (in `src/patchset/mod.rs`), each taking `&DB` instead of `&SubscriptionEngine`. This workspace pins that commit, and `PgWriteTarget` holds one parsed `ParserDB` and applies through `apply_diffset_bytes_async_with_catalog(&self.catalog, ...)`, so there is no per-write parse or engine build. The proposal below is kept for the record.

## The problem

The inbound apply entry points are methods on `SubscriptionEngine` (subql `src/patchset/mod.rs`, `impl<E, I, DB> SubscriptionEngine<E, I, DB>` at line 94):

```rust
pub fn apply_diffset_bytes<DBend, Conn, A>(
    &self, bytes: &[u8], conn: &mut Conn, adapter: &A,
) -> QueryResult<usize> { ... }

pub fn apply_diffset_bytes_async<'a, DBend, Conn, A>(
    &self, bytes: &[u8], conn: &'a mut Conn, adapter: &'a A,
) -> impl Future<Output = QueryResult<usize>> + Send + 'a { ... }
```

Both take `&self`, so a caller must hold a whole `SubscriptionEngine` to apply a diffset. That is a problem for a consumer that only wants to apply, for two reasons.

First, the engine is expensive and irrelevant to apply. Constructing a `SubscriptionEngine` via `SubscriptionEngine::new` allocates the subscription partitions, the consumer dictionaries, the dedup index, the `Vm`, and the re-exec `MergeManager` (which allocates an `mpsc` channel). Apply touches none of that.

Second, the engine is `!Sync`. `SubscriptionEngine` embeds `MergeManager` (subql `src/persistence/merge.rs`), which holds a `std::sync::mpsc::Receiver`. A `Receiver` is `Send` but not `Sync`, so `SubscriptionEngine` is `Send` but not `Sync`. A consumer therefore cannot hold a shared `&SubscriptionEngine` across the apply `await` on a multi-thread runtime, because that would make the future `!Send`. `apply_diffset_bytes_async` itself is written correctly to return a `Send` future (it reconstructs synchronously up front, then the returned future carries only the owned batch, the connection, and the adapter), but the caller still cannot share one engine across concurrent applies.

The key observation is that apply does not need the engine at all. It needs only the catalog. Tracing the async entry point:

- `apply_diffset_bytes_async` calls `self.reconstruct_patchset(&diff)` or `self.reconstruct_changeset(&diff)` (private, `src/patchset/mod.rs` lines 410 and 463).
- Each `reconstruct_*` resolves every op's table shape through `self.catalog_table(name)` (line 512), which uses only `self.database()` plus `catalog_helpers::{table_id, simple_table}`. Nothing else on `self` is read.
- The returned future then runs `apply_transactional_async(conn)` over the reconstructed batch and the adapter. No `self`.

So the whole apply path depends only on the catalog `DB`. The `&self` requirement is incidental to these being methods on `SubscriptionEngine`.

## Current workaround in connetto

`crates/connetto-server/src/write_target.rs` (`PgWriteTarget`) applies each client mutation to the source Postgres under the user's RLS context. Because it cannot hold a shared engine across the apply `await`, it holds only the pool and the catalog DDL string and builds a fresh, owned engine inside every `commit`:

```rust
let catalog = ParserDB::parse::<PostgreSqlDialect>(&self.ddl)?;
let engine: SubscriptionEngine<ChangeEvent, DefaultIds, ParserDB> =
    SubscriptionEngine::new(catalog, PostgreSqlDialect {});
// ... move `engine` into the transaction future and call
// engine.apply_diffset_bytes_async(&bytes, conn, &adapter).await
```

An owned engine moved into the future is `Send`, so this compiles and runs, but every write reparses the DDL and allocates a full `SubscriptionEngine` (including an `mpsc` channel) that is discarded after one apply. Reparsing plus engine construction is small next to the Postgres round trip, but the allocation churn is pure waste and the code constructs subscription machinery it never uses.

## Proposed change

Expose a catalog-only apply surface in subql, parameterized by `DB: DatabaseLike` rather than by `&SubscriptionEngine`.

Make the reconstruction depend on the catalog. Change `catalog_table`, `reconstruct_patchset`, and `reconstruct_changeset` to take `&DB` instead of `&self` (they already read only `self.database()`), for example as free functions in `patchset`:

```rust
fn catalog_table<DB: DatabaseLike>(catalog: &DB, name: &str) -> QueryResult<SimpleTable> { ... }
fn reconstruct_patchset<DB: DatabaseLike>(catalog: &DB, diff: &DiffSet<PatchsetFormat, ...>) -> QueryResult<PatchSet<SimpleTable, String, Vec<u8>>> { ... }
fn reconstruct_changeset<DB: DatabaseLike>(catalog: &DB, diff: &DiffSet<ChangesetFormat, ...>) -> QueryResult<ChangeSet<SimpleTable, String, Vec<u8>>> { ... }
```

Add public catalog-based entry points. Either free functions in `patchset`:

```rust
pub fn apply_diffset_bytes_with_catalog<DB, DBend, Conn, A>(
    catalog: &DB, bytes: &[u8], conn: &mut Conn, adapter: &A,
) -> QueryResult<usize>
where DB: DatabaseLike, /* existing DBend/Conn/A bounds */ { ... }

pub fn apply_diffset_bytes_async_with_catalog<'a, DB, DBend, Conn, A>(
    catalog: &'a DB, bytes: &[u8], conn: &'a mut Conn, adapter: &'a A,
) -> impl Future<Output = QueryResult<usize>> + Send + 'a
where DB: DatabaseLike, /* existing bounds */ { ... }
```

or, if a grouped surface reads better, a lightweight applier newtype that borrows the catalog:

```rust
pub struct DiffsetApplier<'a, DB>(pub &'a DB);

impl<'a, DB: DatabaseLike> DiffsetApplier<'a, DB> {
    pub fn apply_bytes<...>(&self, bytes, conn, adapter) -> QueryResult<usize> { ... }
    pub fn apply_bytes_async<...>(&self, bytes, conn, adapter) -> impl Future<Output = QueryResult<usize>> + Send { ... }
}
```

Either shape is fine. The important property is that the entry point borrows only `&DB`, and `ParserDB` is `Sync`, so a consumer can build the catalog once and share `&catalog` across concurrent applies with no per-write allocation.

Keep the existing `SubscriptionEngine::apply_diffset_bytes` and `apply_diffset_bytes_async` as thin wrappers that delegate to the catalog-based entry points using `self.database()`, so this is not a breaking change:

```rust
impl<E, I, DB> SubscriptionEngine<E, I, DB> {
    pub fn apply_diffset_bytes_async<'a, ...>(&self, bytes, conn, adapter) -> impl Future + Send + 'a {
        apply_diffset_bytes_async_with_catalog(self.database(), bytes, conn, adapter)
    }
}
```

## Downstream change in connetto once this lands

`PgWriteTarget` stops rebuilding an engine per write. It parses the catalog once at construction and holds it:

```rust
pub struct PgWriteTarget {
    pool: Pool<AsyncPgConnection>,
    catalog: ParserDB, // built once; ParserDB is Sync
}
```

`commit` then applies with a shared borrow, so concurrent client writes share one catalog with zero per-write setup and no lock:

```rust
let adapter = PgAdapter::new(&self.catalog);
let affected = subql::patchset::apply_diffset_bytes_async_with_catalog(
    &self.catalog, &bytes, conn, &adapter,
).await?;
```

The per-write `ParserDB::parse` and `SubscriptionEngine::new` both disappear, and the doc comment on `PgWriteTarget` that currently explains the owned-engine workaround is removed.

## Acceptance

- A caller can apply a byte-level patchset or changeset given only `&DB` (a `ParserDB` or any `DatabaseLike`), with no `SubscriptionEngine` in scope.
- The catalog-based async entry point returns an `impl Future + Send`, and a shared `&catalog` (for a `Sync` catalog such as `ParserDB`) can be held across the `await`, so a single catalog serves concurrent applies on a multi-thread runtime.
- The existing `SubscriptionEngine::apply_diffset_bytes` and `apply_diffset_bytes_async` still compile and behave identically, now delegating to the catalog-based path.
- subql's own apply tests cover the catalog-based entry point for both a patchset and a changeset, including a primary-key-changing changeset update (the case `apply_diffset_bytes` documents).
- connetto's `PgWriteTarget` drops the per-write `ParserDB::parse` and `SubscriptionEngine::new`, holds one `ParserDB`, and the Docker-gated `rls_write_filter` test still passes (owned insert lands, foreign-owner insert refused by RLS).

## Non-goals

- No change to the apply semantics, the adapter abstraction, or the transaction boundary.
- The sync `apply_diffset_bytes` gets the same catalog-based treatment for symmetry, but the motivating case is the async path.
- Making `SubscriptionEngine` itself `Sync` is not required and not proposed. The fix is to stop requiring the engine for apply, not to change the engine.
