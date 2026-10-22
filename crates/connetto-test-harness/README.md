# connetto-test-harness

[![Tests](https://github.com/LucaCappelletti94/connetto-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/connetto-rs/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/connetto-rs/blob/main/LICENSE)
[![Coverage](https://codecov.io/gh/LucaCappelletti94/connetto-rs/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/connetto-rs)
[![Publish](https://img.shields.io/badge/publish-workspace%20only-blue.svg)](https://github.com/LucaCappelletti94/connetto-rs/blob/main/crates/connetto-test-harness/Cargo.toml)

In-process integration fixtures that drive the production PostgreSQL write, snapshot, CDC and aggregate-read paths. `HarnessAuth` selects roster, RLS or `OpenFGA` authorization.

`Fixture` manages isolated databases and role-specific connection pools. Container-backed fixtures require Docker, with authorization and OIDC test services started as needed. Fixture setup handles schema and replication statements, and read-back assertions use Diesel's typed DSL.

`with_user` and `with_host` derive connection strings for a role or reachable host without changing which database is addressed.

```rust
use connetto_test_harness::{with_host, with_user};

let admin = "postgres://postgres:postgres@localhost:5432/postgres";
let writer = with_user(admin, "app_writer", "writer");
assert_eq!(writer, "postgres://app_writer:writer@localhost:5432/postgres");
assert_eq!(
    with_host(admin, "172.17.0.2"),
    "postgres://postgres:postgres@172.17.0.2:5432/postgres"
);
```

This crate is workspace-only (`publish = false`). Render its API documentation locally with `cargo doc --no-deps -p connetto-test-harness`.
