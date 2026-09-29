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
include!(concat!(env!("OUT_DIR"), "/connetto-schema.rs"));

pub use connetto_demo_deployment::{AUTH_BASE, auth_landing};

/// Where the browser stack serves the share key it minted for this run, a
/// route on [`AUTH_BASE`].
///
/// A real deployment hands a key to whoever opened a share link. A demo has
/// no sharing surface of its own, so it fetches the key from this route when
/// it runs, because a key baked into the binary would survive a rebuild that
/// the database's own rows do not.
#[must_use]
pub fn share_url() -> String {
    format!("{AUTH_BASE}/dev/share")
}

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
        wasm_bindgen_futures::JsFuture::from(scope.fetch_with_str(&share_url()))
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

/// The builder pieces the browser suites share.
pub mod build {
    use connetto_client::{
        ClientError, ContentPlace, Grant, HeldCredential, Located, MemoryKeyStore, ReplicaKey,
        ReplicaPlace, SyncSchema, TransportFactory,
    };
    use connetto_core::SchemaBundle;
    use connetto_core::traits::{ReplicaKeyStore as _, Transport};

    use crate::BrowserSocket;

    /// A schema over one raw DDL, no policies, no local tier, for a suite
    /// whose tables are its own rather than the deployment's.
    #[must_use]
    pub fn raw_schema(ddl: &str) -> SyncSchema {
        SyncSchema::new(SchemaBundle::new(
            "",
            "",
            ddl,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            None::<&str>,
        ))
    }

    /// A credential for the session a suite minted, `token` standing for
    /// `user_id`.
    ///
    /// # Panics
    ///
    /// When the identity cannot be serialized, which a string always can.
    #[must_use]
    pub fn held(token: String, user_id: &str) -> HeldCredential {
        HeldCredential::new(Grant::new(token), user_id).expect("a string identity serializes")
    }

    /// A replica file in the sahpool pool under a name the suite picks,
    /// fresh or already there as the suite says, since the suite alone
    /// knows which boot it is running.
    pub struct SuitePlace {
        url: String,
        exists: bool,
    }

    impl SuitePlace {
        /// The pool file `db`, already there when `exists`.
        #[must_use]
        pub fn new(db: &str, exists: bool) -> Self {
            Self {
                url: connetto_client::cipher::cipher_url(db, "opfs-sahpool"),
                exists,
            }
        }
    }

    impl ReplicaPlace for SuitePlace {
        fn locate(&self, name: &str) -> Result<Located, ClientError> {
            Ok(Located::new(
                name,
                self.url.clone(),
                self.exists,
                ContentPlace::InMemory,
            ))
        }
    }

    /// A key store holding `key` under the name `credential` gives its
    /// replica, since the browser has no platform RNG to mint one.
    ///
    /// # Panics
    ///
    /// Never, the in-memory store cannot fail.
    pub async fn keys_for(credential: &HeldCredential, key: ReplicaKey) -> MemoryKeyStore {
        let store = MemoryKeyStore::default();
        store
            .store(credential.replica_name(), &key)
            .await
            .expect("the in-memory store never fails");
        store
    }

    /// Dial the browser stack's sync endpoint, once per call.
    pub fn server() -> impl FnMut() -> core::pin::Pin<
        Box<dyn core::future::Future<Output = Result<BrowserSocket, crate::BrowserSocketError>>>,
    > {
        || Box::pin(BrowserSocket::connect(crate::workers::DEMO_WS_URL))
    }

    /// The refusal a one-shot dialer answers once its transport is spent.
    #[derive(Debug)]
    pub struct Spent;

    impl core::fmt::Display for Spent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("the one-shot dialer has no second transport")
        }
    }

    /// A dialer that hands out one transport the suite already holds, the
    /// worker's end of a loopback pair for instance.
    pub struct Once<T>(Option<T>);

    impl<T> Once<T> {
        /// A dialer handing out `transport` once.
        #[must_use]
        pub fn new(transport: T) -> Self {
            Self(Some(transport))
        }
    }

    impl<T: Transport + 'static> TransportFactory for Once<T> {
        type Transport = T;
        type Error = Spent;

        fn connect(&mut self) -> impl core::future::Future<Output = Result<T, Spent>> {
            core::future::ready(self.0.take().ok_or(Spent))
        }
    }
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
        connetto_web::leader::join(leader_lock, glue_url, bootstrap(glue_url))
    }

    /// How the election's winner spawns the smoke worker, `db-worker.js`
    /// beside `glue_url`.
    #[must_use]
    pub fn bootstrap(glue_url: &str) -> connetto_web::workers::WorkerBootstrap {
        connetto_web::workers::WorkerBootstrap::Script(super::worker_url(glue_url))
    }
}

/// DB worker glue, demo schema constants, and the baked local tier template
/// for the smoke topology.
pub mod workers {
    use crate::connetto_schema_bundle;
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

    pub use connetto_demo_deployment::DEMO_WS_URL;

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
    /// OPFS file for the gate-protocol tests, separate from the other
    /// suites' replicas for the same reason.
    pub const GATE_DB_NAME: &str = "connetto-gate-relay.sqlite";

    /// The demo schema this build was compiled against.
    #[must_use]
    pub fn demo_schema() -> connetto_client::SyncSchema {
        connetto_client::SyncSchema::new(connetto_schema_bundle::bundle())
    }

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
        connetto_web::builder::WebClientBuilder::new(DEMO_WS_URL, demo_schema())
            .with_hub_meta_name("connetto-hub-meta.sqlite")
            .with_upstream("db-upstream", DEMO_QUERY)
            .signed_in(connetto_client::Auth::new(crate::AUTH_BASE, "dev-idp"))
            .with_redirect_uri(crate::auth_landing())
            .with_auth_db_name("connetto-auth.sqlite")
            .durable(DB_NAME)
            .with_gate(connetto_client::Gate::off())
            .boot::<String>()
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
        connetto_web::builder::WebClientBuilder::new(DEMO_WS_URL, demo_schema())
            .with_hub_meta_name("connetto-hub-meta.sqlite")
            .with_upstream("db-upstream", DEMO_QUERY)
            .with_upstream("db-photos-upstream", PHOTO_QUERY)
            .with_content_namespace("connetto-photo-content")
            .with_content_heal_lost(
                "SELECT content_id FROM photos WHERE content_state = 'lost'",
                "content_id",
            )
            .signed_in(connetto_client::Auth::new(crate::AUTH_BASE, "dev-idp"))
            .with_redirect_uri(crate::auth_landing())
            .with_auth_db_name("connetto-auth.sqlite")
            .durable(DB_NAME)
            .with_gate(connetto_client::Gate::off())
            .boot::<String>()
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
        let share_keys = [(
            connetto_client::Grant::new(grant),
            connetto_core::CapabilitySubject::<String>::new(subject),
        )];
        connetto_web::builder::WebClientBuilder::new(DEMO_WS_URL, demo_schema())
            .with_hub_meta_name("connetto-hub-meta.sqlite")
            .with_upstream("db-upstream", DEMO_QUERY)
            .with_upstream("db-photos-upstream", PHOTO_QUERY)
            .with_content_namespace("connetto-photo-content")
            .with_content_heal_lost(
                "SELECT content_id FROM photos WHERE content_state = 'lost'",
                "content_id",
            )
            .with_share_keys(share_keys)
            .signed_in(connetto_client::Auth::new(crate::AUTH_BASE, "dev-idp"))
            .with_redirect_uri(crate::auth_landing())
            .with_auth_db_name("connetto-auth.sqlite")
            .durable(DB_NAME)
            .with_gate(connetto_client::Gate::off())
            .boot::<String>()
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
        connetto_web::builder::WebClientBuilder::new(DEMO_WS_URL, demo_schema())
            .with_hub_meta_name("connetto-hub-meta.sqlite")
            .with_upstream("db-upstream", DEMO_QUERY)
            .with_upstream("db-photos-upstream", PHOTO_QUERY)
            .with_content_namespace("connetto-photo-content")
            .with_content_heal_lost(
                "SELECT content_id FROM photos WHERE content_state = 'lost'",
                "content_id",
            )
            .with_connect_gate(PHOTO_CONNECT_CHANNEL)
            .signed_in(connetto_client::Auth::new(crate::AUTH_BASE, "dev-idp"))
            .with_redirect_uri(crate::auth_landing())
            .with_auth_db_name("connetto-auth.sqlite")
            .durable(DB_NAME)
            .with_gate(connetto_client::Gate::off())
            .boot::<String>()
            .await
            .map(drop)
            .map_err(JsValue::from)
    }

    /// DB worker entry point for the unlock-protocol test binary. Same as
    /// `db_worker_boot` except the gate is on, which arms the passkey
    /// unlock protocol.
    ///
    /// # Errors
    ///
    /// A string describing the VFS, acquisition, or subscribe failure.
    #[wasm_bindgen]
    pub async fn db_worker_unlock_boot() -> Result<(), JsValue> {
        connetto_web::logging::init_console();
        connetto_web::builder::WebClientBuilder::new(DEMO_WS_URL, demo_schema())
            .with_hub_meta_name("connetto-unlock-hub-meta.sqlite")
            .with_upstream("db-unlock-upstream", DEMO_QUERY)
            .signed_in(connetto_client::Auth::new(crate::AUTH_BASE, "dev-idp"))
            .with_redirect_uri(crate::auth_landing())
            .with_auth_db_name("connetto-unlock-auth.sqlite")
            .durable(UNLOCK_DB_NAME)
            .boot::<String>()
            .await
            .map(drop)
            .map_err(JsValue::from)
    }

    /// DB worker entry point for the away-and-return gate test binary. The
    /// unlock boot with the away-and-return gate set to re-check on return,
    /// the boot installing it on the hub's gate controller.
    ///
    /// `grace_ms` is the away grace in milliseconds. `None` re-checks once
    /// per launch and `Some(0)` re-checks on every return.
    ///
    /// # Errors
    ///
    /// A string describing the VFS, acquisition, or subscribe failure.
    #[wasm_bindgen]
    pub async fn db_worker_gate_boot(grace_ms: Option<f64>) -> Result<(), JsValue> {
        connetto_web::logging::init_console();
        let recheck = grace_ms.map(|ms| {
            // The demo passes whole non-negative milliseconds.
            debug_assert!(
                ms >= 0.0 && ms.fract() == 0.0,
                "the away grace must be whole milliseconds"
            );
            std::time::Duration::from_millis(ms as u64)
        });
        connetto_web::builder::WebClientBuilder::new(DEMO_WS_URL, demo_schema())
            .with_hub_meta_name("connetto-gate-hub-meta.sqlite")
            .with_upstream("db-gate-upstream", DEMO_QUERY)
            .signed_in(connetto_client::Auth::new(crate::AUTH_BASE, "dev-idp"))
            .with_redirect_uri(crate::auth_landing())
            .with_auth_db_name("connetto-gate-auth.sqlite")
            .durable(GATE_DB_NAME)
            .with_gate(connetto_client::Gate::default().with_recheck(recheck))
            .boot::<String>()
            .await
            .map(drop)
            .map_err(JsValue::from)
    }

    /// DB worker entry point for the gate suite's default case, the gate
    /// boot with no gate setting, so the builder's own default decides.
    ///
    /// # Errors
    ///
    /// A string describing the VFS, unlock, upstream connect, or subscribe
    /// failure.
    #[wasm_bindgen]
    pub async fn db_worker_default_gate_boot() -> Result<(), JsValue> {
        connetto_web::logging::init_console();
        connetto_web::builder::WebClientBuilder::new(DEMO_WS_URL, demo_schema())
            .with_hub_meta_name("connetto-gate-hub-meta.sqlite")
            .with_upstream("db-gate-upstream", DEMO_QUERY)
            .signed_in(connetto_client::Auth::new(crate::AUTH_BASE, "dev-idp"))
            .with_redirect_uri(crate::auth_landing())
            .with_auth_db_name("connetto-gate-auth.sqlite")
            .durable(GATE_DB_NAME)
            .boot::<String>()
            .await
            .map(drop)
            .map_err(JsValue::from)
    }
}
