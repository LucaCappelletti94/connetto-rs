//! Browser smoke tests for the `connetto-web` platform crate.
//!
//! The platform machinery (the WebSocket, `BroadcastChannel`, and
//! `MessagePort` transports, Web Locks liveness, leader election, the relay
//! hub, and the DB worker orchestration) lives in `connetto-web`. This crate
//! supplies the demo schema constants and the baked local tier template, wraps
//! the leader and worker-spawn entry points to load the co-located
//! `db-worker.js`, and exposes the `db_worker_boot` wasm-bindgen entry point
//! that the worker bootstrap calls. The `tests` directory drives the whole
//! topology in headless Chrome against a real `connetto-server` and Postgres.

pub use connetto_web::{
    BrowserSocket, BrowserSocketError, HubNotice, MessageTransport, MessageTransportError,
    RelayError, RelayHub, TabId, locks,
};

/// The Postgres schema source the demo server is launched with
/// (`CONNETTO_PG_DDL_FILE`). Hashing it yields the version the server
/// advertises, so a client that bakes the same source presents a matching
/// version at handshake.
pub const DEMO_SCHEMA_SQL: &str = include_str!("../schema.sql");

// The logical-to-physical table map and view list the build's translation
// produced, as `POLICY_TABLES` and `POLICY_VIEWS`.
include!(concat!(env!("OUT_DIR"), "/replica-tables.rs"));

/// The replica's local name for `current_setting('app.user_id')`, which
/// `policies.sql` compares `orders.owner_id` against. connetto registers a
/// function of this name returning the identity the replica belongs to, so the
/// same policy filters the same rows locally and on the server.
pub const CALLER_FUNCTION: &str = "current_app_user";

/// The tables `schema.sql` plus `policies.sql` split, for
/// `ClientConfig::with_policy_tables`.
#[must_use]
pub fn demo_policy_tables() -> connetto_client::PolicyTables {
    connetto_client::PolicyTables::from_translation(
        POLICY_TABLES.iter().copied(),
        POLICY_VIEWS.iter().copied(),
    )
}

/// The schema version this build was compiled against, for staleness detection.
/// Every client that reaches the real demo server (directly or through the
/// relay) presents this so its handshake is not rejected as stale.
#[must_use]
pub fn demo_schema_version() -> connetto_core::SchemaVersion {
    connetto_core::SchemaVersion::from_source(DEMO_SCHEMA_SQL)
}

// The synced key generator: `orders.id` bakes to `DEFAULT (uuidv4())`, so a
// client write omits the id and this registered function mints it. connetto
// installs the registrar on every connection it opens (the DB worker replica,
// the local tier, and each tab mirror) through the `sql_functions` config. The
// impl is `rosetta_uuid::Uuid::new_v4`, the same strongly typed key the
// `orders` schema uses on SQLite and Postgres.
#[diesel::declare_sql_function]
extern "SQL" {
    /// Client-authored primary key: a 16-byte UUID v4, stored as a BLOB.
    fn uuidv4() -> diesel::sql_types::Binary;
}

/// The registrar connetto installs on every connection it opens for the smoke
/// topology. Nondeterministic, so SQLite calls `uuidv4()` per row instead of
/// folding the DEFAULT to a constant.
#[must_use]
pub fn uuidv4_functions() -> connetto_client::SqlFunctions {
    connetto_client::SqlFunctions::new().with(std::sync::Arc::new(
        |conn: &mut diesel::SqliteConnection| {
            uuidv4_utils::register_nondeterministic_impl(conn, rosetta_uuid::Uuid::new_v4)
        },
    ))
}

/// Resolve the co-located `db-worker.js` bootstrap script beside the
/// wasm-bindgen glue module the smoke harness serves.
fn worker_url(glue_url: &str) -> String {
    web_sys::Url::new_with_base("db-worker.js", glue_url)
        .expect("resolve db-worker.js beside the glue")
        .href()
}

/// Multi-page leader election, spawning the smoke harness's co-located worker.
pub mod leader {
    pub use connetto_web::leader::Membership;

    /// Join the topology, spawning `db-worker.js` from beside `glue_url`.
    #[must_use]
    pub fn join(leader_lock: &str, glue_url: &str) -> Membership {
        connetto_web::leader::join(
            leader_lock,
            glue_url,
            connetto_web::workers::WorkerBootstrap::Script(super::worker_url(glue_url)),
        )
    }
}

/// DB worker glue, demo schema constants, and the baked local tier template
/// for the smoke topology.
pub mod workers {
    use wasm_bindgen::JsValue;
    use wasm_bindgen::prelude::wasm_bindgen;
    use web_sys::Worker;

    pub use connetto_web::workers::{
        DB_ALIVE_LOCK, HELLO_CHANNEL, announce_tab, await_db_worker_ready, sleep, tab_wire_factory,
    };

    /// The demo server every smoke context connects to.
    pub const DEMO_WS_URL: &str = "ws://127.0.0.1:7777/";
    /// The synced replica schema, translated from `schema.sql` and
    /// `policies.sql` by build.rs. Hand-copying it here is what used to keep
    /// the browser suite off the translator's real output, which for a
    /// policy-bearing table is a backing table, a view and triggers rather
    /// than one plain table.
    pub const DEMO_SQLITE_DDL: &str = include_str!(concat!(env!("OUT_DIR"), "/replica-ddl.sql"));
    /// The local tier schema: `notes` is device-private and never synced.
    pub const DEMO_FRONTEND_DDL: &str = include_str!(concat!(env!("OUT_DIR"), "/frontend-ddl.sql"));
    /// The mirror schema for tab clients: both tiers live in the tab's main
    /// schema, because every relayed patch (snapshot, upstream, and local
    /// fan-out alike) applies to main. The hub, not the tab, keeps the tiers
    /// apart.
    pub const DEMO_TAB_DDL: &str = concat!(
        include_str!(concat!(env!("OUT_DIR"), "/replica-ddl.sql")),
        "\n",
        include_str!(concat!(env!("OUT_DIR"), "/frontend-ddl.sql")),
    );
    /// The upstream subscription the DB worker registers.
    pub const DEMO_QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
    /// The OPFS file holding the DB worker's durable replica.
    pub const DB_NAME: &str = "connetto-relay.sqlite";

    /// Spawn the dedicated DB worker from the co-located `db-worker.js`.
    ///
    /// # Errors
    ///
    /// The `Worker` constructor's error when the worker cannot be created.
    pub fn spawn_db_worker(glue_url: &str) -> Result<Worker, JsValue> {
        connetto_web::workers::spawn_db_worker(
            glue_url,
            &connetto_web::workers::WorkerBootstrap::Script(super::worker_url(glue_url)),
        )
    }

    /// DB worker entry point: boot the connetto DB tier with the smoke config.
    /// The `db-worker.js` bootstrap imports the crate glue and awaits this.
    ///
    /// # Errors
    ///
    /// A string describing the VFS, upstream connect, or subscribe failure.
    #[wasm_bindgen]
    pub async fn db_worker_boot() -> Result<(), JsValue> {
        connetto_web::logging::init_console();
        // `Id` names the user id the server mints. The server requires a session
        // from the dev identity provider, so the worker authenticates before
        // connecting and names the replica after the acquired identity.
        connetto_web::workers::boot_db_worker::<String>(
            &connetto_web::workers::DbWorkerConfig::new(crate::demo_schema_version())
                .with_ws_url(DEMO_WS_URL)
                .with_replica_db_prefix(DB_NAME)
                .with_replica_ddl(DEMO_SQLITE_DDL)
                .with_frontend_ddl(DEMO_FRONTEND_DDL)
                .with_upstream_sub_id("db-upstream")
                .with_upstream_query(DEMO_QUERY)
                .with_hub_meta_name("connetto-hub-meta.sqlite")
                .with_sql_functions(crate::uuidv4_functions())
                .with_policy_tables(crate::demo_policy_tables())
                .with_caller_function(crate::CALLER_FUNCTION)
                .with_auth(Some(connetto_web::auth::WorkerAuthConfig::new(
                    "http://127.0.0.1:18099",
                    "dev-idp",
                    "http://127.0.0.1:18099/dev/landing",
                )))
                .with_auth_db_name("connetto-auth.sqlite"),
        )
        .await
        .map(drop)
    }
}
