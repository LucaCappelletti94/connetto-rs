//! The browser client builder.
//!
//! The browser's layer over `connetto_client::ClientBuilder` adds the
//! worker's dialer, the OPFS replica, the provider sign-in through the browser, the
//! relay hub and the worker's services. Three typed stages mirror the native
//! builder. `WebClientBuilder` names the server and the schema and boots an
//! anonymous worker in memory, `signed_in` names the sign-in and the auth
//! store, and `durable` names the replica's database prefix and alone offers
//! the gate, since an in-memory replica has nothing durable to protect.

use std::rc::Rc;

use connetto_client::builder::gate::Gate;
use connetto_client::builder::schema::SyncSchema;
use connetto_client::builder::sign_in::{SignInKind, WebSignIn};
use connetto_client::builder::tuning::SyncTuning;
use connetto_client::{
    ClientBuilder, ClientError, ConnettoClient, ConnettoConnection, FirstThen, Grant,
    ReconnectPolicy,
};
use connetto_core::auth::{CapabilityKey, CapabilitySubject};
use connetto_file_client::BrowserHttp;

use crate::content::TabContent;
use crate::frames::MessageTransportError;
use crate::leader::{self, Membership};
use crate::locks::{self, HeldLock};
use crate::workers::{
    BootError, BootedSession, DB_ALIVE_LOCK, IntakeError, TabWire, WorkerBootstrap, announce_tab,
    await_db_worker_ready, tab_wire_factory,
};
use crate::{BrowserSocket, MessageTransport};
use web_sys::BroadcastChannel;

/// The core build a browser build wraps, dialing the server's WebSocket.
pub(crate) type CoreBuild = ClientBuilder<BrowserSocket, ()>;

/// Everything a boot reads besides the core build.
pub(crate) struct WebConfig {
    /// The server's WebSocket endpoint.
    pub(crate) ws_url: &'static str,
    /// The prefix every durable replica of this application is named under,
    /// `None` for an anonymous boot, whose replica is in memory.
    pub(crate) replica_db_prefix: Option<&'static str>,
    /// The one sync schema, which a tab's mirror is built from too.
    pub(crate) schema: SyncSchema,
    /// The tuning levers, which a tab's mirror takes too.
    pub(crate) tuning: SyncTuning,
    /// The reconnect policy of the worker's upstream.
    pub(crate) policy: ReconnectPolicy,
    /// The hub's upstream subscriptions, primary first.
    pub(crate) upstream: Vec<(&'static str, &'static str)>,
    /// The hub metadata database name.
    pub(crate) hub_meta_name: &'static str,
    /// The content archive's namespace seed, `None` for a build without files.
    pub(crate) content_namespace: Option<&'static str>,
    /// The content loss-heal queries and their `content_id` columns.
    pub(crate) content_heal_lost: Vec<(&'static str, &'static str)>,
    /// The content transfer client.
    pub(crate) content_http: BrowserHttp,
    /// The channel a first connect waits on, `None` to dial at boot.
    pub(crate) connect_gate: Option<&'static str>,
    /// The sign-in, `None` for an anonymous boot.
    pub(crate) sign_in: Option<SignInKind>,
    /// The page the provider login returns to.
    pub(crate) redirect_uri: Option<String>,
    /// The account index database name.
    pub(crate) auth_db_name: &'static str,
    /// The away-and-return gate. Off for an anonymous boot, which has
    /// nothing durable to protect.
    pub(crate) gate: Gate,
}

impl WebConfig {
    /// The hub's upstream subscriptions, primary then extras.
    pub(crate) fn upstream_subscriptions(
        &self,
    ) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
        self.upstream.iter().copied()
    }
}

/// A resolved browser build, the core build the connection comes from beside
/// the browser's own configuration.
pub(crate) struct WebBuild {
    /// The core build, which constructs the worker's connection.
    pub(crate) core: CoreBuild,
    /// The browser's own configuration.
    pub(crate) web: WebConfig,
}

/// A browser client's builder, before a sign-in is chosen.
///
/// `boot` runs it anonymously in the worker, with the replica in memory.
#[must_use]
pub struct WebClientBuilder {
    build: WebBuild,
}

impl WebClientBuilder {
    /// A build for the server at `ws_url` over `schema`.
    pub fn new(ws_url: &'static str, schema: SyncSchema) -> Self {
        let dial = move || BrowserSocket::connect(ws_url);
        Self {
            build: WebBuild {
                core: ClientBuilder::new(schema.clone(), dial),
                web: WebConfig {
                    ws_url,
                    replica_db_prefix: None,
                    schema,
                    tuning: SyncTuning::default(),
                    policy: ReconnectPolicy::default(),
                    upstream: Vec::new(),
                    hub_meta_name: "connetto-hub-meta.sqlite",
                    content_namespace: None,
                    content_heal_lost: Vec::new(),
                    content_http: BrowserHttp::new(),
                    connect_gate: None,
                    sign_in: None,
                    redirect_uri: None,
                    auth_db_name: "connetto-auth.sqlite",
                    gate: Gate::off(),
                },
            },
        }
    }

    /// The tuning levers the build carries.
    pub fn with_tuning(mut self, tuning: SyncTuning) -> Self {
        self.build.core = self.build.core.with_tuning(tuning);
        self.build.web.tuning = tuning;
        self
    }

    /// The reconnect policy of the worker's upstream.
    pub fn with_reconnect(mut self, policy: ReconnectPolicy) -> Self {
        self.build.web.policy = policy;
        self
    }

    /// Keep files, under a content namespace derived from `seed` and the
    /// replica's name.
    pub fn with_content_namespace(mut self, seed: &'static str) -> Self {
        self.build.web.content_namespace = Some(seed);
        self
    }

    /// Heal a file lost from every store by re-reading the rows `query`
    /// selects, naming the file through `column`. Repeatable.
    pub fn with_content_heal_lost(mut self, query: &'static str, column: &'static str) -> Self {
        self.build.web.content_heal_lost.push((query, column));
        self
    }

    /// How long a file transfer may sit idle before it fails.
    pub fn with_transfer_idle_bound(mut self, bound: core::time::Duration) -> Self {
        self.build.web.content_http = self.build.web.content_http.with_idle_bound(bound);
        self
    }

    /// Wait for a message on the `channel` broadcast channel before the first
    /// connect, and refuse every connect until one arrives, so a boot never
    /// dials a server that is not ready.
    pub fn with_connect_gate(mut self, channel: &'static str) -> Self {
        self.build.web.connect_gate = Some(channel);
        self
    }

    /// Name the database the worker's hub keeps its own state in.
    pub fn with_hub_meta_name(mut self, name: &'static str) -> Self {
        self.build.web.hub_meta_name = name;
        self
    }

    /// Subscribe the worker upstream to `query` as `subscription_id`.
    /// Repeatable, the first one being the primary.
    pub fn with_upstream(mut self, subscription_id: &'static str, query: &'static str) -> Self {
        self.build.web.upstream.push((subscription_id, query));
        self
    }

    /// Present the share keys the build holds, each beside the subject it
    /// renders as, whether or not anyone is signed in.
    pub fn with_share_keys<K: CapabilityKey>(
        mut self,
        keys: impl IntoIterator<Item = (Grant, CapabilitySubject<K>)>,
    ) -> Self {
        self.build.core = self.build.core.with_share_keys(keys);
        self
    }

    /// Sign in, moving the build to the signed-in stage.
    pub fn signed_in<S: WebSignIn>(mut self, sign_in: S) -> WebSignedIn {
        self.build.web.sign_in = Some(sign_in.into_kind());
        WebSignedIn { build: self.build }
    }

    /// Boot the worker anonymously, with the replica and the device-private
    /// tier in memory.
    ///
    /// # Errors
    ///
    /// A [`BootError`] from the storage, replica, connect, or service setup.
    pub async fn boot<Id>(self) -> Result<BootedSession<Id>, BootError>
    where
        Id: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Display,
    {
        crate::workers::boot_db_worker::<Id>(self.build).await
    }
}

/// The signed-in stage, with a sign-in named and the replica not yet placed.
#[must_use]
pub struct WebSignedIn {
    build: WebBuild,
}

impl WebSignedIn {
    /// The page the provider login returns to.
    pub fn with_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.build.web.redirect_uri = Some(uri.into());
        self
    }

    /// Name the database the account index is kept in.
    pub fn with_auth_db_name(mut self, name: &'static str) -> Self {
        self.build.web.auth_db_name = name;
        self
    }

    /// Keep the replica in OPFS under `prefix`, moving to the durable stage.
    ///
    /// Each identity's replica is named under the prefix, so two
    /// applications on one origin, or two test suites, keep separate
    /// replicas and key records.
    pub fn durable(mut self, prefix: &'static str) -> WebDurable {
        self.build.web.replica_db_prefix = Some(prefix);
        self.build.web.gate = Gate::default();
        WebDurable { build: self.build }
    }
}

/// The durable stage, an OPFS replica under a key, gated on the passkey
/// unlock unless the application turns the gate off.
#[must_use]
pub struct WebDurable {
    build: WebBuild,
}

impl WebDurable {
    /// The away-and-return gate, on by default.
    pub fn with_gate(mut self, gate: Gate) -> Self {
        self.build.web.gate = gate;
        self
    }

    /// Boot the worker, running the pending wipes, the key store and its
    /// unlock, the sign-in and the account choice, the replica, the connect, content, the
    /// relay hub, the services, and the gate's re-check.
    ///
    /// # Errors
    ///
    /// A [`BootError`] from the storage, unlock, sign-in, replica, connect,
    /// or service setup.
    pub async fn boot<Id>(self) -> Result<BootedSession<Id>, BootError>
    where
        Id: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Display,
    {
        crate::workers::boot_db_worker::<Id>(self.build).await
    }
}

/// Where a tab finds its application's worker, the election lock every page
/// of the application competes on and how the winner spawns the worker.
pub struct TabTopology<'a> {
    /// The election lock, identical across every page of one application.
    pub leader_lock: &'a str,
    /// The wasm-bindgen glue module the worker is spawned from.
    pub glue_url: &'a str,
    /// How the winner launches the worker from the glue.
    pub bootstrap: WorkerBootstrap,
}

/// A tab attached to its application's worker.
///
/// The tab competes for leadership for as long as this lives, and its tab
/// lock tells the worker it is alive, so dropping it detaches the tab.
pub struct AttachedTab {
    /// The tab's running client, whose mirror the worker's hub fills.
    pub client: ConnettoClient<TabWire>,
    /// The tab's content handle, present when the build keeps files.
    pub content: Option<Rc<TabContent<BroadcastChannel>>>,
    /// This page's place in the worker election.
    pub membership: Rc<Membership>,
    _tab_lock: HeldLock,
}

/// A tab attached to its application's worker, its connection unstarted for
/// a caller that drives it frame by frame.
pub struct AttachedDriven {
    /// The connected, unstarted connection.
    pub connection: ConnettoConnection<TabWire>,
    /// This page's place in the worker election.
    pub membership: Rc<Membership>,
    _tab_lock: HeldLock,
}

/// Why a tab could not attach to its worker.
#[derive(Debug, thiserror::Error)]
pub enum AttachError {
    /// The worker never answered, or the tab's wire was not acknowledged.
    #[error("the worker did not answer: {0}")]
    Intake(#[from] IntakeError),
    /// The tab's wire could not be opened.
    #[error("the tab's wire: {0}")]
    Wire(#[from] MessageTransportError),
    /// The tab's mirror could not be opened or handshaken.
    #[error("the tab's mirror: {0}")]
    Client(#[from] ClientError),
}

impl WebConfig {
    /// Join the election, wait for the worker, hold the tab lock, and open the
    /// tab's first wire, returning the core build of the tab's mirror.
    async fn tab_build(
        &self,
        topology: TabTopology<'_>,
    ) -> Result<
        (
            ClientBuilder<TabWire, ()>,
            Option<Rc<TabContent<BroadcastChannel>>>,
            Rc<Membership>,
            HeldLock,
            String,
        ),
        AttachError,
    > {
        let client_id = rosetta_uuid::Uuid::new_v4().to_string();
        let membership = leader::join(topology.leader_lock, topology.glue_url, topology.bootstrap);
        // A leader waits on the boot it spawned, a follower on whichever
        // boot is announced.
        let boot = membership
            .boot_identity()
            .map_or_else(Vec::new, |id| vec![id]);
        await_db_worker_ready(&boot).await?;
        // Held before the wire opens, so the worker never sees a live wire
        // whose tab it believes dead.
        let tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
        let wire = format!("connetto-wire-{client_id}-boot");
        announce_tab(&wire).await?;
        let mut first =
            MessageTransport::<BroadcastChannel>::with_peer_liveness(&wire, DB_ALIVE_LOCK)?;
        let content = self
            .content_namespace
            .map(|_| Rc::new(TabContent::new(&mut first)));
        let core = ClientBuilder::new(
            self.schema.clone().relay_mirror(),
            FirstThen::new(first, tab_wire_factory(client_id.clone())),
        )
        .with_client_id(client_id.clone())
        .with_tuning(self.tuning)
        .with_reconnect(self.policy.clone())
        .with_sleeper(crate::workers::sleep);
        Ok((core, content, Rc::new(membership), tab_lock, client_id))
    }

    /// Attach a tab and start its mirror.
    async fn attach(&self, topology: TabTopology<'_>) -> Result<AttachedTab, AttachError> {
        let (core, content, membership, tab_lock, client_id) = self.tab_build(topology).await?;
        let (running, pump) = core.connect_with_pump().await?;
        wasm_bindgen_futures::spawn_local(pump);
        crate::visibility::report_visibility(client_id);
        Ok(AttachedTab {
            client: running.client().clone(),
            content,
            membership,
            _tab_lock: tab_lock,
        })
    }

    /// Attach a tab and hand its connection back unstarted.
    async fn attach_driven(
        &self,
        topology: TabTopology<'_>,
    ) -> Result<AttachedDriven, AttachError> {
        let (core, _content, membership, tab_lock, _client_id) = self.tab_build(topology).await?;
        let connection = core.connect_driven().await?;
        Ok(AttachedDriven {
            connection,
            membership,
            _tab_lock: tab_lock,
        })
    }
}

/// The tab terminals every stage carries, since a tab needs none of the
/// worker's sign-in or storage.
macro_rules! tab_terminals {
    ($stage:ty) => {
        impl $stage {
            /// Attach this page as a tab of the application's worker, spawning the
            /// worker when this page wins the election, and start the tab's
            /// mirror of the worker's replica.
            ///
            /// The worker states who it is signed in as and its gate to the tab,
            /// so the mirror answers its policy views and refuses while locked as
            /// the worker's replica does, and the tab reports its visibility to
            /// the worker's away input.
            ///
            /// # Errors
            ///
            /// [`AttachError`] when the worker never answers, or the tab's wire or
            /// mirror cannot be opened.
            pub async fn attach(
                &self,
                topology: TabTopology<'_>,
            ) -> Result<AttachedTab, AttachError> {
                self.build.web.attach(topology).await
            }

            /// Like [`attach`](Self::attach), with the tab's connection handed back
            /// connected and unstarted, for a caller that drives it frame by frame.
            ///
            /// # Errors
            ///
            /// [`AttachError`] when the worker never answers, or the tab's wire or
            /// mirror cannot be opened or handshaken.
            pub async fn attach_driven(
                &self,
                topology: TabTopology<'_>,
            ) -> Result<AttachedDriven, AttachError> {
                self.build.web.attach_driven(topology).await
            }
        }
    };
}

tab_terminals!(WebClientBuilder);
tab_terminals!(WebSignedIn);
tab_terminals!(WebDurable);
