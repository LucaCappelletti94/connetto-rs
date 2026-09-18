//! Browser photo worker infrastructure for the yew web demo.
//!
//! This lib target exposes the `db_worker_photo_boot` wasm-bindgen entry point
//! for browser tests that drive the photo flow through the real content routes.
//! The main binary (`src/main.rs`) is the actual Yew application.

use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

include!(concat!(env!("OUT_DIR"), "/replica-tables.rs"));

/// Schema SQL this build was compiled against (matches the browser-stack server).
pub const SCHEMA_SQL: &str = include_str!("../schema.sql");

/// The synced replica schema (worker replica, policy-split by build.rs).
pub const DEMO_SQLITE_DDL: &str = include_str!(concat!(env!("OUT_DIR"), "/replica-ddl.sql"));

/// The local tier schema (device-private, attached, never synced).
pub const DEMO_FRONTEND_DDL: &str = include_str!(concat!(env!("OUT_DIR"), "/frontend-ddl.sql"));

/// The tab mirror schema: both tiers in the tab's main schema.
pub const DEMO_TAB_DDL: &str = concat!(
    include_str!(concat!(env!("OUT_DIR"), "/replica-ddl.sql")),
    "\n",
    include_str!(concat!(env!("OUT_DIR"), "/frontend-ddl.sql")),
);

/// The demo server the DB worker connects upstream to.
pub const DEMO_WS_URL: &str = "ws://127.0.0.1:7777/";

/// The upstream subscription the DB worker registers.
pub const DEMO_QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

/// The extra upstream subscription for photos.
pub const PHOTO_QUERY: &str = "SELECT * FROM photos";

/// The OPFS file base for the worker's durable synced replica.
pub const DB_NAME: &str = "connetto-photo-yew.sqlite";

/// The registered caller-identity function connetto installs on every connection.
pub const CALLER_FUNCTION: &str = "current_app_user";

/// The schema version this build was compiled against.
#[must_use]
pub fn demo_schema_version() -> connetto_core::SchemaVersion {
    connetto_core::SchemaVersion::from_source(SCHEMA_SQL)
}

// The uuidv4 SQL function registered on every connection so the orders
// and photos DEFAULT (uuidv4()) mints a UUID on local writes.
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

/// The policy table map for this build, for `ClientConfig::with_policy_tables`.
#[must_use]
pub fn demo_policy_tables() -> connetto_client::PolicyTables {
    connetto_client::PolicyTables::from_translation(
        POLICY_TABLES.iter().copied(),
        POLICY_VIEWS.iter().copied(),
    )
}

/// DB worker entry point: boot the connetto DB tier with the photo config.
///
/// The test's blob worker bootstrap imports this crate's wasm module and awaits this.
///
/// # Errors
///
/// A string describing the VFS, upstream connect, or subscribe failure.
#[wasm_bindgen]
pub async fn db_worker_photo_boot() -> Result<(), JsValue> {
    connetto_web::logging::init_console();
    connetto_web::workers::boot_db_worker::<String>(
        &connetto_web::workers::DbWorkerConfig::new(demo_schema_version())
            .with_ws_url(DEMO_WS_URL)
            .with_replica_db_prefix(DB_NAME)
            .with_replica_ddl(DEMO_SQLITE_DDL)
            .with_frontend_ddl(DEMO_FRONTEND_DDL)
            .with_upstream_sub_id("db-upstream")
            .with_upstream_query(DEMO_QUERY)
            .with_extra_upstream("db-photos-upstream", PHOTO_QUERY)
            .with_hub_meta_name("connetto-photo-yew-hub-meta.sqlite")
            .with_content_namespace("connetto-photo-content")
            .with_sql_functions(uuidv4_functions())
            .with_policy_tables(demo_policy_tables())
            .with_caller_function(CALLER_FUNCTION)
            .with_auth(Some(connetto_web::auth::WorkerAuthConfig::new(
                "http://127.0.0.1:18099",
                "dev-idp",
                "http://127.0.0.1:18099/dev/landing",
            )))
            .with_auth_db_name("connetto-photo-yew-auth.sqlite"),
    )
    .await
    .map(drop)
    .map_err(JsValue::from)
}
