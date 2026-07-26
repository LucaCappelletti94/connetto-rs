# Upstream: `rosetta-uuid` must generate `utc_v7()` on `wasm32-unknown-unknown` under `uuid` 1.24

## Why connetto needs this

connetto is adopting `rosetta_uuid::Uuid` as the ONE primary-key type for synced tables across every app, so a single diesel `table!` and `struct` serve both the SQLite frontend replica and the Postgres backend. That is the whole point of the crate for us: `rosetta_uuid::diesel_impls::Uuid` carries `sqlite_type(name = "Binary")` and `postgres_type(oid = 2950)` on one SQL type, so the compiler checks the same schema on both ends instead of us keeping a `Vec<u8>` (SQLite) and a `diesel::sql_types::Uuid` (Postgres) side by side.

The key is client-authored: an offline browser client mints its own v7 key with no server round trip. In connetto that happens through a SQLite column `DEFAULT (uuidv7())`, where the `uuidv7` scalar function is registered per connection and its implementation is `rosetta_uuid::Uuid::utc_v7`. So `utc_v7()` MUST work in the browser, in both a `Window` and a dedicated `Worker` context (the connetto DB worker runs there).

Today it does not, under the `uuid` version this workspace resolves to.

## The problem: the wasm RNG backend does not match `uuid` 1.24

`rosetta_uuid::Uuid::utc_v7()` (src/lib.rs) calls `uuid::Uuid::new_v7(Timestamp::from_unix_time(...))`. `new_v7` generates the random bits itself, so it needs a working RNG backend on the target.

`rosetta-uuid` 0.1.2 wires wasm randomness like this (Cargo.toml):

```toml
[dependencies.uuid]
version = "1.20"
features = ["serde", "v4", "v7"]

[target.'cfg(all(target_arch = "wasm32", target_os = "unknown"))'.dependencies.getrandom]
version = "0.2"
features = ["js"]

# uuid "js" only appears in wasm DEV-dependencies, not the library graph.
[target.'cfg(all(target_arch = "wasm32", target_os = "unknown"))'.dev-dependencies.uuid]
version = "1.20"
features = ["js"]
```

That wiring was correct against the `uuid` 1.20 line. It is stale against `uuid` 1.24, which this workspace resolves to (root `Cargo.lock`: `uuid 1.24.0`). `uuid` 1.24 reworked its RNG backend (`uuid-1.24.0/Cargo.toml`):

- `v4 = ["rng"]`, `v7 = ["rng"]`, and `rng = ["dep:getrandom"]`.
- `getrandom` (now `0.4`) is a dependency ONLY for `cfg(not(all(target_arch = "wasm32", any(target_os = "unknown", target_os = "none"))))`. It is not compiled for `wasm32-unknown-unknown` at all.
- On wasm the RNG comes from a separate optional crate, `uuid-rng-internal` (declared as `uuid-rng-internal-lib`, `optional = true`), pulled in only by the `rng-getrandom` or `rng-rand` features:

```toml
rng-getrandom = ["rng", "dep:getrandom", "uuid-rng-internal", "uuid-rng-internal/getrandom"]
rng-rand      = ["rng", "dep:rand",      "uuid-rng-internal", "uuid-rng-internal/rand"]
js = ["dep:wasm-bindgen", "dep:js-sys"]   # note: js does NOT enable rng
```

Consequences for `rosetta-uuid` 0.1.2 + `uuid` 1.24 on `wasm32-unknown-unknown`:

1. `rosetta` enables only `uuid` `v4`/`v7` (hence bare `rng`), never `rng-getrandom`/`rng-rand`, so `uuid-rng-internal` is never pulled and there is no wasm RNG backend behind `new_v7`.
2. `rosetta`'s `getrandom = { version = "0.2", features = ["js"] }` targets a `getrandom` that `uuid` 1.24 does not use on wasm (uuid's off-wasm getrandom is `0.4`, and on wasm it routes through `uuid-rng-internal`), so that declaration is dead weight and does not feed uuid's generator.
3. `uuid`'s `js` feature is only a wasm DEV-dependency, so the library build never gets even `wasm-bindgen`/`js-sys` from uuid.

Net: `utc_v7()` (and `new_v4()`) have no randomness source on `wasm32-unknown-unknown`. Empirically this workspace's current wasm builds pull no `getrandom` and no `uuid-rng-internal` at all, so adopting `utc_v7()` as-is would fail in the browser (a getrandom/link or runtime error), not merely fall back.

`chrono::Utc::now()` inside `utc_v7()` is fine: `rosetta` depends on `chrono = "0.4"` with default features, so `clock`/`wasmbind` are on and `Utc::now()` resolves through `js-sys` `Date` on wasm. No change needed there.

## Required change 1: align the wasm RNG backend to `uuid` 1.24

Bump the `uuid` floor to `>= 1.24` (the version that introduced `rng-getrandom` and `uuid-rng-internal`) and enable a real wasm RNG backend in the LIBRARY graph, not just dev-dependencies.

Recommended (getrandom backend, matches the browser `crypto.getRandomValues`, available in both `Window` and `Worker`):

```toml
[dependencies.uuid]
version = "1.24"
default-features = false
features = ["v4", "v7", "rng-getrandom"]   # rng-getrandom pulls uuid-rng-internal + its getrandom
# keep "serde" here only if the serde feature path still needs it

# Make the getrandom backend uuid-rng-internal uses actually target the browser.
# uuid-rng-internal re-exports a getrandom; verify its MAJOR version and wire the
# matching wasm backend:
#   - if getrandom 0.2.x  -> features = ["js"]
#   - if getrandom 0.3.x+ -> no "js" feature exists; set the backend via
#     RUSTFLAGS='--cfg getrandom_backend="wasm_js"' (documented in the crate README
#     and the consuming app's .cargo/config.toml), and depend on getrandom with the
#     "wasm_js" feature.
[target.'cfg(all(target_arch = "wasm32", target_os = "unknown"))'.dependencies.getrandom]
version = "<match uuid-rng-internal>"
features = ["<js or wasm_js per the above>"]
```

Action item for whoever fixes rosetta: pin down which `getrandom` major `uuid-rng-internal` 1.24 depends on, then pick the `js` (0.2) versus `wasm_js` cfg (0.3+) path accordingly. The `rng-rand` alternative works too but drags in `rand`, which is heavier than we want for a key generator.

Because `getrandom_backend="wasm_js"` (the 0.3+ path) is set by RUSTFLAGS in the FINAL binary, the connetto apps that consume rosetta will carry that flag in their `.cargo/config.toml` if that path is chosen. Call this out in the rosetta README so consumers know.

## Required change 2 (README correctness): register uuid generators as NONDETERMINISTIC

The rosetta README example registers the SQLite `uuidv7` function with the deterministic registrar:

```rust
uuidv7_utils::register_impl(&connection, rosetta_uuid::Uuid::utc_v7);
```

For a column `DEFAULT (uuidv7())`, a DETERMINISTIC function is a correctness bug: SQLite may fold the call to a single constant, so every row inserted without an explicit id gets the SAME uuid. A uuid generator MUST be registered with the nondeterministic registrar:

```rust
uuidv7_utils::register_nondeterministic_impl(&connection, rosetta_uuid::Uuid::utc_v7);
```

`#[diesel::declare_sql_function]` already generates `register_nondeterministic_impl` beside `register_impl`, so no code change is needed, only the README example and a one-line caveat. connetto verified this in a headless-Chrome spike: the deterministic path constant-folds, the nondeterministic path mints a distinct 16-byte id per row.

## Required change 3: implement diesel's ordering marker so typed aggregates and comparisons work

We want typed queries everywhere, including the backend "delete newest" path, which is naturally `orders::table.select(diesel::dsl::max(orders::id))` over the shared schema. In the pinned diesel fork, `max`/`min` are gated on `diesel::sql_types::SqlOrd` (via the blanket `SqlOrdAggregate: SqlOrd + SingleValue`), and the ordering comparison operators (`.gt()`, `.lt()`, `.between()`, and friends) are gated on the same marker. `rosetta_uuid::diesel_impls::Uuid` does not implement it, so those typed forms do not compile and a consumer is forced back to raw SQL, which defeats the point of the crate.

Implement the marker on the SQL type:

```rust
// src/diesel_impls.rs
impl diesel::sql_types::SqlOrd for crate::diesel_impls::Uuid {}
```

This is semantically valid on every backend the type targets: SQLite orders `BLOB` by `memcmp`, PostgreSQL `uuid` has a total order, and a v7 uuid sorts by its embedded timestamp, so `MAX`/`MIN`/`ORDER BY`/range comparisons all mean "newest/oldest by creation time." `SqlOrd` is a public marker trait and `diesel_impls::Uuid` is rosetta's own type, so the impl is orphan-rule clean. `SqlOrd for Nullable<Uuid>` then comes free from diesel's blanket `impl<T: SqlOrd> SqlOrd for Nullable<T>`, so `max(orders::id): Nullable<Uuid>` works out of the box.

`.order(orders::id)` and `.order(orders::id.desc())` already work without this marker (ordering a query by a column needs no `SqlOrd`), but `max`/`min` and the comparison operators do, so ship the impl.

## Optional ergonomic: a public `sql_types` alias

The SQL type used in `diesel::table!` is `rosetta_uuid::diesel_impls::Uuid`. `diesel_impls` reads like an internal module, and it is the name that ends up in every consumer's schema. A friendlier public surface would be a re-export, for example:

```rust
pub mod sql_types {
    pub use crate::diesel_impls::Uuid;
}
```

so consumers write `id -> rosetta_uuid::sql_types::Uuid`. Purely cosmetic, not blocking.

## Verification rosetta should add

`rosetta-uuid` already has `tests/wasm.rs`. Extend it to actually exercise generation under the library feature set (not dev-only features) in headless Chrome:

- `Uuid::utc_v7()` returns a value whose bytes are length 16.
- Two successive `utc_v7()` calls differ.
- The same for `new_v4()`.
- A round-trip through a `SqliteConnection` (sqlite-wasm-rs) with `uuidv7_utils::register_nondeterministic_impl(&conn, Uuid::utc_v7)` and a table `id BLOB DEFAULT (uuidv7()) CHECK (length(id) = 16) NOT NULL`, inserting twice omitting the id, asserting two distinct 16-byte ids. This mirrors exactly how connetto uses the crate and would have caught the RNG gap.

Run: `wasm-pack test --headless --chrome` in the rosetta crate.

## How connetto will consume it

Once rosetta cuts a release (or a pinnable rev) whose `utc_v7()` works on `wasm32-unknown-unknown`, connetto will:

- Add `rosetta-uuid` with `features = ["diesel", "sqlite"]` to the web apps and the wasm-smoke suite, and `["diesel", "sqlite", "postgres"]` to the desktop demo (which also writes Postgres).
- Type every synced `orders` schema as `id -> rosetta_uuid::diesel_impls::Uuid` and `struct Order { id: rosetta_uuid::Uuid, .. }`, one `table!` shared across SQLite and Postgres.
- Register the app `uuidv7` scalar function with `register_nondeterministic_impl(&conn, rosetta_uuid::Uuid::utc_v7)` through connetto's `SqlFunctions` mechanism, so connetto installs it on every replica connection it opens and the `DEFAULT (uuidv7())` mints the key.
- Pin the exact rosetta version/rev this fix lands in, and align it across all four standalone workspaces plus the root, next to the `pg2sqlite` pin.

If the wasm RNG fix is not desirable in rosetta itself, the fallback (kept out of scope here) is for connetto's wasm `uuidv7` registrar to build the 16 bytes from `Date::now` plus the browser CSPRNG and wrap them via `rosetta_uuid::Uuid::from([u8; 16])`, while native uses `utc_v7()`. That preserves the strong type end to end and only swaps the generator on wasm. State a preference so connetto plumbs one path, not both.
