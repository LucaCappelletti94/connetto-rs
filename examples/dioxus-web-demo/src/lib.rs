//! Browser test worker entry points for the dioxus web demo photo surface.

use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

include!(concat!(env!("OUT_DIR"), "/replica-tables.rs"));

// SchemaVersion hashes this string; it must be byte-identical to
// examples/wasm-smoke/schema.sql, which the browser-stack server uses.
pub const SCHEMA_SQL: &str = include_str!("../schema.sql");

/// The policy source the translation read beside the schema, hashed into the
/// version with it because a changed policy changes the replica's own views.
pub const POLICIES_SQL: &str = include_str!("../policies.sql");

pub const DEMO_SQLITE_DDL: &str = include_str!(concat!(env!("OUT_DIR"), "/replica-ddl.sql"));
pub const DEMO_FRONTEND_DDL: &str = include_str!(concat!(env!("OUT_DIR"), "/frontend-ddl.sql"));
pub const DEMO_TAB_DDL: &str = concat!(
    include_str!(concat!(env!("OUT_DIR"), "/replica-ddl.sql")),
    "\n",
    include_str!(concat!(env!("OUT_DIR"), "/frontend-ddl.sql")),
);

pub const DEMO_WS_URL: &str = "ws://127.0.0.1:7777/";
pub const DEMO_QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
pub const PHOTO_QUERY: &str = "SELECT * FROM photos";
pub const CALLER_FUNCTION: &str = "current_app_user";

/// The replica's local name for the share keys the caller holds, which the
/// membership arm of `photos_p` searches. A boot holding no key answers NULL,
/// so that arm admits nothing.
pub const SUBJECTS_FUNCTION: &str = "current_app_subjects";

// Each test gets unique OPFS filenames so Chrome's delayed handle release after
// Worker.terminate() never blocks the next worker's file open.
const ALIGN_DB_PREFIX: &str = "connetto-dioxus-align";
const ALIGN_HUB_META: &str = "connetto-dioxus-align-hub-meta.sqlite";
const ALIGN_AUTH_DB: &str = "connetto-dioxus-align-auth.sqlite";

const PHOTO_DB_PREFIX: &str = "connetto-dioxus-photo";
const PHOTO_HUB_META: &str = "connetto-dioxus-photo-hub-meta.sqlite";
const PHOTO_AUTH_DB: &str = "connetto-dioxus-photo-auth.sqlite";

/// The schema version this build was compiled against.
#[must_use]
pub fn demo_schema_version() -> connetto_core::SchemaVersion {
    connetto_core::SchemaVersion::from_sources([SCHEMA_SQL, POLICIES_SQL])
}

#[diesel::declare_sql_function]
extern "SQL" {
    /// Client-authored primary key: a 16-byte UUID v4, stored as a BLOB.
    fn uuidv4() -> diesel::sql_types::Binary;
}

/// The registrar connetto installs on every connection it opens for this app.
#[must_use]
pub fn uuidv4_functions() -> connetto_client::SqlFunctions {
    connetto_client::SqlFunctions::new().with(std::sync::Arc::new(
        |conn: &mut diesel::SqliteConnection| {
            uuidv4_utils::register_impl_with_behavior(
                conn,
                diesel::sqlite::SqliteFunctionBehavior::INNOCUOUS,
                rosetta_uuid::Uuid::new_v4,
            )
        },
    ))
}

/// The policy table map for this build.
#[must_use]
pub fn demo_policy_tables() -> connetto_client::PolicyTables {
    connetto_client::PolicyTables::from_translation(
        POLICY_TABLES.iter().copied(),
        POLICY_VIEWS.iter().copied(),
    )
}

/// Worker entry point for the alignment test; uses `connetto-dioxus-align*` OPFS files.
///
/// # Errors
///
/// A string describing the VFS, upstream connect, or subscribe failure.
#[wasm_bindgen]
pub async fn db_worker_boot_align() -> Result<(), JsValue> {
    boot_with(ALIGN_DB_PREFIX, ALIGN_HUB_META, ALIGN_AUTH_DB).await
}

/// Worker entry point for the photo test; uses `connetto-dioxus-photo*` OPFS files.
///
/// # Errors
///
/// A string describing the VFS, upstream connect, or subscribe failure.
#[wasm_bindgen]
pub async fn db_worker_photo_boot() -> Result<(), JsValue> {
    boot_with(PHOTO_DB_PREFIX, PHOTO_HUB_META, PHOTO_AUTH_DB).await
}

async fn boot_with(
    db_prefix: &'static str,
    hub_meta: &'static str,
    auth_db: &'static str,
) -> Result<(), JsValue> {
    connetto_web::logging::init_console();
    connetto_web::workers::boot_db_worker::<String>(
        &connetto_web::workers::DbWorkerConfig::new(demo_schema_version())
            .with_ws_url(DEMO_WS_URL)
            .with_replica_db_prefix(db_prefix)
            .with_replica_ddl(DEMO_SQLITE_DDL)
            .with_frontend_ddl(DEMO_FRONTEND_DDL)
            .with_upstream_sub_id("db-upstream")
            .with_upstream_query(DEMO_QUERY)
            .with_extra_upstream("db-photos-upstream", PHOTO_QUERY)
            .with_hub_meta_name(hub_meta)
            .with_content_namespace("connetto-photo-content")
            .with_sql_functions(uuidv4_functions())
            .with_policy_tables(demo_policy_tables())
            .with_caller_function(CALLER_FUNCTION)
            .with_subjects_function(SUBJECTS_FUNCTION)
            .with_auth(Some(connetto_web::auth::WorkerAuthConfig::new(
                "http://127.0.0.1:18099",
                "dev-idp",
                "http://127.0.0.1:18099/dev/landing",
            )))
            .with_auth_db_name(auth_db),
    )
    .await
    .map(drop)
    .map_err(JsValue::from)
}
