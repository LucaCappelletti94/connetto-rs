//! Preflight integration tests.
//!
//! Each negative test spins up a fresh Postgres container with a specific
//! misconfiguration and verifies that `preflight` refuses with the named error.

use connetto_file_server::{DEPLOYMENT_DDL, DefaultFileSchema, PreflightError, preflight};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::fixture::{FIXTURE_STMTS, Pg, connect_admin, split_simple};

/// Applies `DEPLOYMENT_DDL` + `FIXTURE_STMTS` then the extra `overrides` DDL.
async fn setup_with(conn: &mut AsyncPgConnection, overrides: &[&str]) {
    for stmt in split_simple(DEPLOYMENT_DDL) {
        diesel::sql_query(stmt).execute(conn).await.ok();
    }
    for stmt in FIXTURE_STMTS {
        diesel::sql_query(*stmt).execute(conn).await.ok();
    }
    for stmt in overrides {
        diesel::sql_query(*stmt)
            .execute(conn)
            .await
            .expect("override DDL");
    }
}

fn role_password() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(1);
    format!("rw{}", SEQ.fetch_add(1, Ordering::Relaxed))
}

#[tokio::test]
async fn preflight_happy_path_passes() {
    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    setup_with(&mut conn, &[]).await;
    preflight::<DefaultFileSchema>(&mut conn)
        .await
        .expect("preflight must pass with correct DDL");
}

/// `_cfs_manifests.file_id` typed as TEXT instead of BYTEA is refused by name.
#[tokio::test]
async fn preflight_refuses_wrong_column_type() {
    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    setup_with(
        &mut conn,
        &[
            // Drop the chunk-rows table first (FK prevents dropping manifests directly).
            "DROP TABLE IF EXISTS _cfs_manifest_chunks CASCADE",
            "DROP TABLE IF EXISTS _cfs_manifests CASCADE",
            "CREATE TABLE _cfs_manifests (
             file_id        TEXT        NOT NULL PRIMARY KEY,
             total_len      BIGINT      NOT NULL,
             accepted_bytes BIGINT      NOT NULL DEFAULT 0,
             committed      BOOLEAN     NOT NULL DEFAULT FALSE,
             uploaded_by    TEXT        NOT NULL,
             created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
         )",
        ],
    )
    .await;

    let err = preflight::<DefaultFileSchema>(&mut conn)
        .await
        .expect_err("wrong column type must be refused");
    match err {
        PreflightError::WrongColumnType {
            table,
            column,
            expected,
            actual,
        } => {
            assert_eq!(table, "_cfs_manifests", "wrong table in error");
            assert_eq!(column, "file_id", "wrong column in error");
            assert_eq!(expected, "bytea", "wrong expected type");
            assert_ne!(actual, "bytea", "actual must differ from expected");
        }
        other => panic!("expected WrongColumnType, got {other}"),
    }
}

/// `connetto_visible_files` installed as SECURITY DEFINER leaks all files and
/// must be refused.
#[tokio::test]
async fn preflight_refuses_visible_files_security_definer() {
    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    setup_with(
        &mut conn,
        &[
            "CREATE OR REPLACE FUNCTION connetto_visible_files(p_file_ids BYTEA[])
         RETURNS BYTEA[] LANGUAGE sql SECURITY DEFINER AS $$
             SELECT p_file_ids
         $$",
        ],
    )
    .await;

    let err = preflight::<DefaultFileSchema>(&mut conn)
        .await
        .expect_err("DEFINER visible_files must be refused");
    match err {
        PreflightError::WrongSecurityMode {
            function,
            expected_mode,
        } => {
            assert_eq!(function, "connetto_visible_files");
            assert!(
                expected_mode.contains("INVOKER"),
                "expected_mode must mention INVOKER, got {expected_mode}"
            );
        }
        other => panic!("expected WrongSecurityMode, got {other}"),
    }
}

/// `connetto_set_content_state` installed as SECURITY INVOKER must be refused
/// (it needs DEFINER to write the application metadata table).
#[tokio::test]
async fn preflight_refuses_setter_security_invoker() {
    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    setup_with(
        &mut conn,
        &[
            // Replace the 3-arg DEFINER from FIXTURE_STMTS with a 3-arg INVOKER so the
            // security-mode check fires on the same signature (CREATE OR REPLACE matches).
            "CREATE OR REPLACE FUNCTION connetto_set_content_state(
                 p_file_id BYTEA, p_new_state TEXT, p_caller TEXT
             ) RETURNS BYTEA LANGUAGE plpgsql SECURITY INVOKER
                 SET search_path TO '' AS $$
             BEGIN RETURN p_file_id; END; $$",
        ],
    )
    .await;

    let err = preflight::<DefaultFileSchema>(&mut conn)
        .await
        .expect_err("INVOKER setter must be refused");
    match err {
        PreflightError::WrongSecurityMode {
            function,
            expected_mode,
        } => {
            assert_eq!(function, "connetto_set_content_state");
            assert!(
                expected_mode.contains("DEFINER"),
                "expected_mode must mention DEFINER, got {expected_mode}"
            );
        }
        other => panic!("expected WrongSecurityMode, got {other}"),
    }
}

/// Startup refuses a SECURITY DEFINER function with no pinned `search_path`.
#[tokio::test]
async fn preflight_refuses_definer_without_search_path() {
    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    setup_with(
        &mut conn,
        &[
            // Same 3-arg DEFINER signature but without SET search_path.
            "CREATE OR REPLACE FUNCTION connetto_set_content_state(
                 p_file_id BYTEA, p_new_state TEXT, p_caller TEXT
             ) RETURNS BYTEA LANGUAGE plpgsql SECURITY DEFINER AS $$
             BEGIN RETURN p_file_id; END; $$",
        ],
    )
    .await;

    let err = preflight::<DefaultFileSchema>(&mut conn)
        .await
        .expect_err("DEFINER without search_path must be refused");
    match err {
        PreflightError::UnpinnedSearchPath { function } => {
            assert_eq!(function, "connetto_set_content_state");
        }
        other => panic!("expected UnpinnedSearchPath, got {other}"),
    }
}

/// Startup refuses a SECURITY INVOKER function with no pinned `search_path`.
#[tokio::test]
async fn preflight_refuses_invoker_without_search_path() {
    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    setup_with(
        &mut conn,
        &[
            // visible_files without SET search_path.
            "CREATE OR REPLACE FUNCTION connetto_visible_files(p_file_ids BYTEA[])
             RETURNS BYTEA[] LANGUAGE sql SECURITY INVOKER AS $$
                 SELECT p_file_ids
             $$",
        ],
    )
    .await;

    let err = preflight::<DefaultFileSchema>(&mut conn)
        .await
        .expect_err("INVOKER without search_path must be refused");
    match err {
        PreflightError::UnpinnedSearchPath { function } => {
            assert_eq!(function, "connetto_visible_files");
        }
        other => panic!("expected UnpinnedSearchPath, got {other}"),
    }
}

/// `connetto_visible_files` with a wrong argument type (TEXT[] instead of BYTEA[])
/// must be refused, naming the function and position.
#[tokio::test]
async fn preflight_refuses_visible_files_wrong_arg_type() {
    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    setup_with(
        &mut conn,
        &[
            // DROP the correct overload so the wrong-typed version is the only one.
            // CREATE OR REPLACE with different arg types adds a NEW overload rather
            // than replacing the existing one, which would hide the defect.
            "DROP FUNCTION IF EXISTS connetto_visible_files(BYTEA[])",
            "CREATE FUNCTION connetto_visible_files(p_file_ids TEXT[])
         RETURNS TEXT[] LANGUAGE sql SECURITY INVOKER AS $$
             SELECT p_file_ids
         $$",
        ],
    )
    .await;

    let err = preflight::<DefaultFileSchema>(&mut conn)
        .await
        .expect_err("wrong arg type for visible_files must be refused");
    match err {
        PreflightError::WrongArgType {
            function,
            pos,
            expected,
            actual,
        } => {
            assert_eq!(function, "connetto_visible_files");
            assert_eq!(pos, 0, "wrong argument position");
            assert_eq!(expected, "bytea[]");
            assert_ne!(actual, "bytea[]");
        }
        // Return type is also wrong in this fixture. Either error is acceptable.
        PreflightError::WrongReturnType { function, .. } => {
            assert_eq!(function, "connetto_visible_files");
        }
        other => panic!("expected WrongArgType or WrongReturnType, got {other}"),
    }
}

/// `connetto_visible_files` with BYTEA[] argument but wrong return type (BYTEA)
#[tokio::test]
async fn preflight_refuses_visible_files_wrong_return_type() {
    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    setup_with(
        &mut conn,
        &[
            // Return type change is blocked by Postgres for same-signature functions.
            // Drop and recreate to install the wrong return type cleanly.
            "DROP FUNCTION IF EXISTS connetto_visible_files(BYTEA[])",
            "CREATE FUNCTION connetto_visible_files(p_file_ids BYTEA[])
         RETURNS BYTEA LANGUAGE sql SECURITY INVOKER AS $$
             SELECT p_file_ids[1]
         $$",
        ],
    )
    .await;

    let err = preflight::<DefaultFileSchema>(&mut conn)
        .await
        .expect_err("wrong return type for visible_files must be refused");
    match err {
        PreflightError::WrongReturnType {
            function,
            expected,
            actual,
        } => {
            assert_eq!(function, "connetto_visible_files");
            assert_eq!(expected, "bytea[]");
            assert_ne!(actual, "bytea[]");
        }
        other => panic!("expected WrongReturnType, got {other}"),
    }
}

/// Proves: `serve()` refuses with a named error when `_cfs_chunk_registry` is
/// absent.  The registry table is the new addition in the derived-liveness
/// redesign. Its absence must be caught at startup, not at request time.
#[tokio::test]
async fn serve_refuses_when_chunk_registry_absent() {
    use connetto_file_server::{AnyStore, AppPools, Config, DefaultFileSchema, FsStore, serve};

    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    // Apply full DDL + fixture, then drop the registry table.
    setup_with(&mut conn, &["DROP TABLE IF EXISTS _cfs_chunk_registry"]).await;
    drop(conn);

    let dir = tempfile::TempDir::new().unwrap();
    let cfg: Config<DefaultFileSchema> = Config {
        pools: AppPools {
            admin: pg.admin_pool().await,
            reader: pg.reader_pool().await,
        },
        store: AnyStore::Fs(FsStore::new(dir.path()).expect("fs store")),
        verifier: crate::fixture::make_signer().1,
        grace: std::time::Duration::from_secs(3600),
        _schema: std::marker::PhantomData,
    };
    let err = serve(cfg)
        .await
        .expect_err("serve must refuse with missing registry");
    match err {
        PreflightError::MissingTable(name) => {
            assert_eq!(
                name, "_cfs_chunk_registry",
                "error must name the missing table"
            );
        }
        other => panic!("expected MissingTable, got {other}"),
    }
}

/// Proves: `serve()` refuses when the index the sweep's anti-join needs is
/// absent, so a deployment cannot start and then scan sequentially per candidate.
#[tokio::test]
async fn serve_refuses_when_sweep_index_absent() {
    use connetto_file_server::{AnyStore, AppPools, Config, DefaultFileSchema, FsStore, serve};

    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    setup_with(
        &mut conn,
        &["DROP INDEX IF EXISTS _cfs_manifest_chunks_chunk_hash_idx"],
    )
    .await;
    drop(conn);

    let dir = tempfile::TempDir::new().unwrap();
    let cfg: Config<DefaultFileSchema> = Config {
        pools: AppPools {
            admin: pg.admin_pool().await,
            reader: pg.reader_pool().await,
        },
        store: AnyStore::Fs(FsStore::new(dir.path()).expect("fs store")),
        verifier: crate::fixture::make_signer().1,
        grace: std::time::Duration::from_secs(3600),
        _schema: std::marker::PhantomData,
    };
    let err = serve(cfg)
        .await
        .expect_err("serve must refuse without the sweep index");
    match err {
        PreflightError::MissingIndex { table, column } => {
            assert_eq!(table, "_cfs_manifest_chunks");
            assert_eq!(column, "chunk_hash");
        }
        other => panic!("expected MissingIndex, got {other}"),
    }
}

/// Proves: `serve()` also refuses when the grace-scan index on `created_at` is
/// absent, so the two-index contract is verified in both directions.
#[tokio::test]
async fn serve_refuses_when_grace_index_absent() {
    use connetto_file_server::{AnyStore, AppPools, Config, DefaultFileSchema, FsStore, serve};

    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    setup_with(
        &mut conn,
        &["DROP INDEX IF EXISTS _cfs_manifests_uncommitted_created_at_idx"],
    )
    .await;
    drop(conn);

    let dir = tempfile::TempDir::new().unwrap();
    let cfg: Config<DefaultFileSchema> = Config {
        pools: AppPools {
            admin: pg.admin_pool().await,
            reader: pg.reader_pool().await,
        },
        store: AnyStore::Fs(FsStore::new(dir.path()).expect("fs store")),
        verifier: crate::fixture::make_signer().1,
        grace: std::time::Duration::from_secs(3600),
        _schema: std::marker::PhantomData,
    };
    let err = serve(cfg)
        .await
        .expect_err("serve must refuse without the grace index");
    match err {
        PreflightError::MissingIndex { table, column } => {
            assert_eq!(table, "_cfs_manifests");
            assert_eq!(column, "created_at");
        }
        other => panic!("expected MissingIndex, got {other}"),
    }
}

/// Proves the predicate comparison is live: a valid, ready index leading with
/// `created_at` but predicated `WHERE false` optimizes nothing and is refused.
///
/// This is what the plain missing-index test cannot show, and it also pins the
/// expected normalized text against what Postgres actually stores.
#[tokio::test]
async fn serve_refuses_a_degenerate_partial_grace_index() {
    use connetto_file_server::{AnyStore, AppPools, Config, DefaultFileSchema, FsStore, serve};

    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    setup_with(
        &mut conn,
        &[
            "DROP INDEX IF EXISTS _cfs_manifests_uncommitted_created_at_idx",
            "CREATE INDEX _cfs_manifests_useless_idx \
             ON _cfs_manifests (created_at) WHERE false",
        ],
    )
    .await;
    drop(conn);

    let dir = tempfile::TempDir::new().unwrap();
    let cfg: Config<DefaultFileSchema> = Config {
        pools: AppPools {
            admin: pg.admin_pool().await,
            reader: pg.reader_pool().await,
        },
        store: AnyStore::Fs(FsStore::new(dir.path()).expect("fs store")),
        verifier: crate::fixture::make_signer().1,
        grace: std::time::Duration::from_secs(3600),
        _schema: std::marker::PhantomData,
    };
    let err = serve(cfg)
        .await
        .expect_err("a WHERE false index must not satisfy preflight");
    match err {
        PreflightError::MissingIndex { table, column } => {
            assert_eq!(table, "_cfs_manifests");
            assert_eq!(column, "created_at");
        }
        other => panic!("expected MissingIndex, got {other}"),
    }
}

/// Proves: serve refuses when the reader pool connects as a superuser.
///
/// A superuser silently bypasses row level security, making the visibility
/// checks the server relies on meaningless.
#[tokio::test]
async fn serve_refuses_superuser_reader_role() {
    use connetto_file_server::{AnyStore, AppPools, Config, DefaultFileSchema, FsStore, serve};

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let cfg: Config<DefaultFileSchema> = Config {
        pools: AppPools {
            admin: pg.admin_pool().await,
            reader: pg.admin_pool().await,
        },
        store: AnyStore::Fs(FsStore::new(dir.path()).expect("fs store")),
        verifier: crate::fixture::make_signer().1,
        grace: std::time::Duration::from_secs(3600),
        _schema: std::marker::PhantomData,
    };
    let err = serve(cfg)
        .await
        .expect_err("serve must refuse a superuser reader");
    assert!(
        matches!(err, PreflightError::ReaderIsSuperuser),
        "expected ReaderIsSuperuser, got {err}"
    );
}

/// Proves: serve refuses when the reader pool connects as a role with BYPASSRLS.
///
/// A BYPASSRLS role silently skips every row level security policy, making
/// the visibility checks this server relies on meaningless.
#[tokio::test]
async fn serve_refuses_bypassrls_reader_role() {
    use connetto_file_server::{AnyStore, AppPools, Config, DefaultFileSchema, FsStore, serve};
    use diesel_async::pooled_connection::{AsyncDieselConnectionManager, bb8::Pool};

    let pg = Pg::start().await;
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    let pw = role_password();
    diesel::sql_query(format!(
        "DO $$ BEGIN \
             CREATE ROLE cfs_bypassrls_test LOGIN PASSWORD '{pw}' \
             NOSUPERUSER BYPASSRLS NOINHERIT; \
         EXCEPTION WHEN duplicate_object THEN NULL; \
         END $$"
    ))
    .execute(&mut admin_conn)
    .await
    .expect("create bypassrls role");
    diesel::sql_query("GRANT CONNECT ON DATABASE test TO cfs_bypassrls_test")
        .execute(&mut admin_conn)
        .await
        .expect("grant connect");
    drop(admin_conn);

    let url = pg.url_for("cfs_bypassrls_test", &pw);
    let mgr = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let bypassrls_pool = Pool::builder()
        .max_size(1)
        .build(mgr)
        .await
        .expect("bypassrls pool");

    let dir = tempfile::TempDir::new().unwrap();
    let cfg: Config<DefaultFileSchema> = Config {
        pools: AppPools {
            admin: pg.admin_pool().await,
            reader: bypassrls_pool,
        },
        store: AnyStore::Fs(FsStore::new(dir.path()).expect("fs store")),
        verifier: crate::fixture::make_signer().1,
        grace: std::time::Duration::from_secs(3600),
        _schema: std::marker::PhantomData,
    };
    let err = serve(cfg)
        .await
        .expect_err("serve must refuse a BYPASSRLS reader");
    assert!(
        matches!(err, PreflightError::ReaderBypassesRls),
        "expected ReaderBypassesRls, got {err}"
    );
}

/// Proves: serve refuses when the reader pool connects as the owner of a file-server table.
///
/// Postgres bypasses row level security for a table owner, so a reader that
/// owns any of the file-server tables bypasses the constraints it must enforce.
#[tokio::test]
async fn serve_refuses_table_owner_reader_role() {
    use connetto_file_server::{AnyStore, AppPools, Config, DefaultFileSchema, FsStore, serve};
    use diesel_async::pooled_connection::{AsyncDieselConnectionManager, bb8::Pool};

    let pg = Pg::start().await;
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    let pw = role_password();
    diesel::sql_query(format!(
        "DO $$ BEGIN \
             CREATE ROLE cfs_owner_test LOGIN PASSWORD '{pw}' \
             NOSUPERUSER NOINHERIT; \
         EXCEPTION WHEN duplicate_object THEN NULL; \
         END $$"
    ))
    .execute(&mut admin_conn)
    .await
    .expect("create owner role");
    diesel::sql_query("GRANT CONNECT ON DATABASE test TO cfs_owner_test")
        .execute(&mut admin_conn)
        .await
        .expect("grant connect");
    diesel::sql_query("ALTER TABLE _cfs_manifests OWNER TO cfs_owner_test")
        .execute(&mut admin_conn)
        .await
        .expect("transfer table ownership");
    drop(admin_conn);

    let url = pg.url_for("cfs_owner_test", &pw);
    let mgr = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let owner_pool = Pool::builder()
        .max_size(1)
        .build(mgr)
        .await
        .expect("owner pool");

    let dir = tempfile::TempDir::new().unwrap();
    let cfg: Config<DefaultFileSchema> = Config {
        pools: AppPools {
            admin: pg.admin_pool().await,
            reader: owner_pool,
        },
        store: AnyStore::Fs(FsStore::new(dir.path()).expect("fs store")),
        verifier: crate::fixture::make_signer().1,
        grace: std::time::Duration::from_secs(3600),
        _schema: std::marker::PhantomData,
    };
    let err = serve(cfg)
        .await
        .expect_err("serve must refuse a reader that owns _cfs_manifests");
    assert!(
        matches!(err, PreflightError::ReaderOwnsTable { ref table } if table == "_cfs_manifests"),
        "expected ReaderOwnsTable(_cfs_manifests), got {err}"
    );
}

/// Proves: serve accepts a correctly configured reader role.
///
/// The standard `connetto_file_server` role is non-privileged and subject to
/// row level security, so the check must not refuse it.
#[tokio::test]
async fn serve_accepts_correctly_configured_reader_role() {
    use connetto_file_server::{AnyStore, AppPools, Config, DefaultFileSchema, FsStore, serve};

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let cfg: Config<DefaultFileSchema> = Config {
        pools: AppPools {
            admin: pg.admin_pool().await,
            reader: pg.reader_pool().await,
        },
        store: AnyStore::Fs(FsStore::new(dir.path()).expect("fs store")),
        verifier: crate::fixture::make_signer().1,
        grace: std::time::Duration::from_secs(3600),
        _schema: std::marker::PhantomData,
    };
    let _router = serve(cfg)
        .await
        .expect("serve must accept the standard non-privileged reader role");
}

/// Proves: `serve()` refuses when `connetto_set_content_state` is absent.
///
/// The setter is validated once at startup via preflight, not per-request.
/// A deployment that has not installed the function must be refused before
/// it can accept any traffic.
#[tokio::test]
async fn serve_refuses_when_content_state_fn_absent() {
    use connetto_file_server::{AnyStore, AppPools, Config, DefaultFileSchema, FsStore, serve};

    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    setup_with(
        &mut conn,
        &["DROP FUNCTION IF EXISTS connetto_set_content_state(BYTEA, TEXT, TEXT)"],
    )
    .await;
    drop(conn);

    let dir = tempfile::TempDir::new().unwrap();
    let cfg: Config<DefaultFileSchema> = Config {
        pools: AppPools {
            admin: pg.admin_pool().await,
            reader: pg.reader_pool().await,
        },
        store: AnyStore::Fs(FsStore::new(dir.path()).expect("fs store")),
        verifier: crate::fixture::make_signer().1,
        grace: std::time::Duration::from_secs(3600),
        _schema: std::marker::PhantomData,
    };
    let err = serve(cfg)
        .await
        .expect_err("serve must refuse when connetto_set_content_state is absent");
    assert!(
        matches!(err, PreflightError::MissingSetterFunction),
        "expected MissingSetterFunction, got {err}"
    );
}

/// Proves: `serve()` accepts a correctly installed `connetto_set_content_state`.
///
/// The positive counterpart to the absence test: the startup check must not
/// refuse a valid function, so the check cannot pass by refusing everything.
#[tokio::test]
async fn serve_accepts_when_content_state_fn_valid() {
    use connetto_file_server::{AnyStore, AppPools, Config, DefaultFileSchema, FsStore, serve};

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let cfg: Config<DefaultFileSchema> = Config {
        pools: AppPools {
            admin: pg.admin_pool().await,
            reader: pg.reader_pool().await,
        },
        store: AnyStore::Fs(FsStore::new(dir.path()).expect("fs store")),
        verifier: crate::fixture::make_signer().1,
        grace: std::time::Duration::from_secs(3600),
        _schema: std::marker::PhantomData,
    };
    let _router = serve(cfg)
        .await
        .expect("serve must accept a correctly installed content-state function");
}
