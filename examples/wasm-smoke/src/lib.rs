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

pub const DEMO_SCHEMA_SQL: &str = connetto_demo_deployment::SCHEMA_SQL;

/// The policy source the same translation read, hashed into the version beside
/// the schema because a changed policy changes the replica's own views.
pub const DEMO_POLICIES_SQL: &str = connetto_demo_deployment::POLICIES_SQL;

// The logical-to-physical table map and view list the build's translation
// produced, as `POLICY_TABLES` and `POLICY_VIEWS`.
include!(concat!(env!("OUT_DIR"), "/replica-tables.rs"));

pub const CALLER_FUNCTION: &str = connetto_demo_deployment::CALLER_FUNCTION;

pub const SUBJECTS_FUNCTION: &str = connetto_demo_deployment::SUBJECTS_FUNCTION;

/// Where the browser stack serves the share key it minted for this run.
///
/// A real deployment hands a key to whoever opened a share link. A demo has
/// no sharing surface of its own, so it asks the stack, at run time rather
/// than at build time: a value baked into the binary survives a rebuild that
/// the database's own rows do not.
pub const SHARE_URL: &str = "http://127.0.0.1:18099/dev/share";

/// The share key this run minted, as the signed grant and the subject it
/// names, with the photo only that key reaches.
///
/// # Errors
///
/// The fetch or the answer's shape, as text, when the stack is not serving.
#[cfg(target_arch = "wasm32")]
pub async fn fetch_share() -> Result<(String, String, String), String> {
    use wasm_bindgen::JsCast as _;

    fn field(body: &str, name: &str) -> Option<String> {
        let opening = body.find(&format!("\"{name}\":\""))? + name.len() + 4;
        let rest = body.get(opening..)?;
        let closing = rest.find('"')?;
        Some(rest.get(..closing)?.to_owned())
    }

    let scope: web_sys::WorkerGlobalScope = js_sys::global()
        .dyn_into()
        .map_err(|_| "the share key is fetched from a worker".to_owned())?;
    let response: web_sys::Response =
        wasm_bindgen_futures::JsFuture::from(scope.fetch_with_str(SHARE_URL))
            .await
            .map_err(|err| format!("{err:?}"))?
            .dyn_into()
            .map_err(|_| "the share route answered no response".to_owned())?;
    let body =
        wasm_bindgen_futures::JsFuture::from(response.text().map_err(|err| format!("{err:?}"))?)
            .await
            .map_err(|err| format!("{err:?}"))?
            .as_string()
            .ok_or_else(|| "the share route answered no text".to_owned())?;
    let grant = field(&body, "grant").ok_or_else(|| format!("no grant in {body}"))?;
    let subject = field(&body, "subject").ok_or_else(|| format!("no subject in {body}"))?;
    let photo = field(&body, "photo").ok_or_else(|| format!("no photo in {body}"))?;
    Ok((grant, subject, photo))
}

/// The grant and subject halves of [`fetch_share`].
///
/// # Errors
///
/// As [`fetch_share`].
#[cfg(target_arch = "wasm32")]
pub async fn fetch_share_key() -> Result<(String, String), String> {
    let (grant, subject, _) = fetch_share().await?;
    Ok((grant, subject))
}

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
    connetto_demo_deployment::schema_version()
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
/// folding the DEFAULT to a constant, and `INNOCUOUS` because the replica runs
/// with trusted schema off and a column DEFAULT is a schema object.
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
        BootIdentity, DB_ALIVE_LOCK, HELLO_CHANNEL, announce_tab, request_custody, sleep,
        tab_wire_factory,
    };

    /// Waits for the DB worker, acting on a boot failure of `known` alone.
    ///
    /// A test that spawned the worker passes the identity it was given, and one that only
    /// joined passes nothing, which is what a follower tab does.
    ///
    /// # Errors
    ///
    /// The readiness failure as [`connetto_web::workers::IntakeError`] describes it.
    pub async fn await_db_worker_ready(known: &[BootIdentity]) -> Result<(), JsValue> {
        connetto_web::workers::await_db_worker_ready(known)
            .await
            .map_err(JsValue::from)
    }

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
    /// The extra upstream subscription the photo flow needs.
    pub const PHOTO_QUERY: &str = "SELECT * FROM photos";
    /// A test-only gate that keeps the photo worker offline until opened.
    pub const PHOTO_CONNECT_CHANNEL: &str = "connetto-photo-connect";
    /// The OPFS file holding the DB worker's durable replica.
    pub const DB_NAME: &str = "connetto-relay.sqlite";
    /// OPFS file for unlock-protocol tests, separate from DB_NAME so the two
    /// suites do not share a replica when running in the same browser session.
    pub const UNLOCK_DB_NAME: &str = "connetto-unlock-relay.sqlite";

    /// Spawn the dedicated DB worker from the co-located `db-worker.js`.
    ///
    /// # Errors
    ///
    /// The `Worker` constructor's error when the worker cannot be created.
    pub fn spawn_db_worker(glue_url: &str) -> Result<(Worker, BootIdentity), JsValue> {
        connetto_web::workers::spawn_db_worker(
            glue_url,
            &connetto_web::workers::WorkerBootstrap::Script(super::worker_url(glue_url)),
        )
        .map_err(JsValue::from)
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
                .with_subjects_function(crate::SUBJECTS_FUNCTION)
                .with_auth(Some(connetto_web::auth::WorkerAuthConfig::new(
                    "http://127.0.0.1:18099",
                    "dev-idp",
                    "http://127.0.0.1:18099/dev/landing",
                )))
                .with_auth_db_name("connetto-auth.sqlite"),
        )
        .await
        .map(drop)
        .map_err(JsValue::from)
    }

    /// DB worker entry point for the photo flow test binary.
    ///
    /// # Errors
    ///
    /// A string describing the VFS, upstream connect, or subscribe failure.
    #[wasm_bindgen]
    pub async fn db_worker_photo_boot() -> Result<(), JsValue> {
        connetto_web::logging::init_console();
        connetto_web::workers::boot_db_worker::<String>(
            &connetto_web::workers::DbWorkerConfig::new(crate::demo_schema_version())
                .with_ws_url(DEMO_WS_URL)
                .with_replica_db_prefix(DB_NAME)
                .with_replica_ddl(DEMO_SQLITE_DDL)
                .with_frontend_ddl(DEMO_FRONTEND_DDL)
                .with_upstream_sub_id("db-upstream")
                .with_upstream_query(DEMO_QUERY)
                .with_extra_upstream("db-photos-upstream", PHOTO_QUERY)
                .with_hub_meta_name("connetto-hub-meta.sqlite")
                .with_content_namespace("connetto-photo-content")
                .with_sql_functions(crate::uuidv4_functions())
                .with_policy_tables(crate::demo_policy_tables())
                .with_caller_function(crate::CALLER_FUNCTION)
                .with_subjects_function(crate::SUBJECTS_FUNCTION)
                .with_auth(Some(connetto_web::auth::WorkerAuthConfig::new(
                    "http://127.0.0.1:18099",
                    "dev-idp",
                    "http://127.0.0.1:18099/dev/landing",
                )))
                .with_auth_db_name("connetto-auth.sqlite"),
        )
        .await
        .map(drop)
        .map_err(JsValue::from)
    }

    /// DB worker entry point for the share-key test binary: the same photo
    /// tier, booted holding the key the stack minted.
    ///
    /// The key stands for one a user obtained by opening a share link. This
    /// demo takes it from the environment the browser stack exported, because
    /// a test needs the same key the stack seeded a row for.
    ///
    /// # Errors
    ///
    /// A string describing the VFS, upstream connect, or subscribe failure.
    #[wasm_bindgen]
    pub async fn db_worker_share_boot() -> Result<(), JsValue> {
        connetto_web::logging::init_console();
        let (grant, subject) = crate::fetch_share_key()
            .await
            .map_err(|err| JsValue::from_str(&format!("fetching the demo share key: {err}")))?;
        let share_keys = [(grant, subject)];
        connetto_web::workers::boot_db_worker::<String>(
            &connetto_web::workers::DbWorkerConfig::new(crate::demo_schema_version())
                .with_ws_url(DEMO_WS_URL)
                .with_replica_db_prefix(DB_NAME)
                .with_replica_ddl(DEMO_SQLITE_DDL)
                .with_frontend_ddl(DEMO_FRONTEND_DDL)
                .with_upstream_sub_id("db-upstream")
                .with_upstream_query(DEMO_QUERY)
                .with_extra_upstream("db-photos-upstream", PHOTO_QUERY)
                .with_hub_meta_name("connetto-hub-meta.sqlite")
                .with_content_namespace("connetto-photo-content")
                .with_sql_functions(crate::uuidv4_functions())
                .with_policy_tables(crate::demo_policy_tables())
                .with_caller_function(crate::CALLER_FUNCTION)
                .with_subjects_function(crate::SUBJECTS_FUNCTION)
                .with_share_keys(share_keys)
                .with_auth(Some(connetto_web::auth::WorkerAuthConfig::new(
                    "http://127.0.0.1:18099",
                    "dev-idp",
                    "http://127.0.0.1:18099/dev/landing",
                )))
                .with_auth_db_name("connetto-auth.sqlite"),
        )
        .await
        .map(drop)
        .map_err(JsValue::from)
    }

    /// DB worker entry point for the offline photo flow test binary.
    ///
    /// # Errors
    ///
    /// A string describing the VFS, upstream connect, or subscribe failure.
    #[wasm_bindgen]
    pub async fn db_worker_photo_offline_boot() -> Result<(), JsValue> {
        connetto_web::logging::init_console();
        connetto_web::workers::boot_db_worker::<String>(
            &connetto_web::workers::DbWorkerConfig::new(crate::demo_schema_version())
                .with_ws_url(DEMO_WS_URL)
                .with_replica_db_prefix(DB_NAME)
                .with_replica_ddl(DEMO_SQLITE_DDL)
                .with_frontend_ddl(DEMO_FRONTEND_DDL)
                .with_upstream_sub_id("db-upstream")
                .with_upstream_query(DEMO_QUERY)
                .with_extra_upstream("db-photos-upstream", PHOTO_QUERY)
                .with_hub_meta_name("connetto-hub-meta.sqlite")
                .with_content_namespace("connetto-photo-content")
                .with_sql_functions(crate::uuidv4_functions())
                .with_policy_tables(crate::demo_policy_tables())
                .with_caller_function(crate::CALLER_FUNCTION)
                .with_subjects_function(crate::SUBJECTS_FUNCTION)
                .with_auth(Some(connetto_web::auth::WorkerAuthConfig::new(
                    "http://127.0.0.1:18099",
                    "dev-idp",
                    "http://127.0.0.1:18099/dev/landing",
                )))
                .with_auth_db_name("connetto-auth.sqlite")
                .with_connect_gate(PHOTO_CONNECT_CHANNEL),
        )
        .await
        .map(drop)
        .map_err(JsValue::from)
    }

    /// DB worker entry point for the unlock-protocol test binary. Same as
    /// `db_worker_boot` except the passkey unlock protocol is enabled.
    ///
    /// # Errors
    ///
    /// A string describing the VFS, acquisition, or subscribe failure.
    #[wasm_bindgen]
    pub async fn db_worker_unlock_boot() -> Result<(), JsValue> {
        connetto_web::logging::init_console();
        connetto_web::workers::boot_db_worker::<String>(
            &connetto_web::workers::DbWorkerConfig::new(crate::demo_schema_version())
                .with_ws_url(DEMO_WS_URL)
                .with_replica_db_prefix(UNLOCK_DB_NAME)
                .with_replica_ddl(DEMO_SQLITE_DDL)
                .with_frontend_ddl(DEMO_FRONTEND_DDL)
                .with_upstream_sub_id("db-unlock-upstream")
                .with_upstream_query(DEMO_QUERY)
                .with_hub_meta_name("connetto-unlock-hub-meta.sqlite")
                .with_sql_functions(crate::uuidv4_functions())
                .with_policy_tables(crate::demo_policy_tables())
                .with_caller_function(crate::CALLER_FUNCTION)
                .with_subjects_function(crate::SUBJECTS_FUNCTION)
                .with_auth(Some(connetto_web::auth::WorkerAuthConfig::new(
                    "http://127.0.0.1:18099",
                    "dev-idp",
                    "http://127.0.0.1:18099/dev/landing",
                )))
                .with_auth_db_name("connetto-unlock-auth.sqlite")
                .with_unlock(true),
        )
        .await
        .map(drop)
        .map_err(JsValue::from)
    }
}
