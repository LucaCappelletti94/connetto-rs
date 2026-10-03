//! The platform-neutral client builder, the one construction path every
//! platform layer builds over.
//!
//! The builder composes the shared pieces, the schema, the tuning, the
//! reconnect policy, the content seam and the share keys, over an injected
//! dialer and an injected backoff sleep, forks on a held credential, and ends
//! in a durable step that names the replica location and the key store the
//! platform uses. No stage spawns anything, because spawning is the platform
//! layer's job. Every stage ends in the client and its pump future, or in the
//! connected, unstarted connection a caller drives frame by frame.

use core::fmt::Display;
use core::pin::Pin;
use core::time::Duration;
use std::sync::Arc;

use connetto_core::auth::{CapabilityKey, CapabilitySubject};
use connetto_core::custody::Custody;
use connetto_core::messages::Grant;
use connetto_core::schema::CALLER_FUNCTION;
use connetto_core::traits::{MaybeSend, ReplicaKeyStore, Transport};

use crate::Replica;
use crate::ReplicaStorage;
use crate::TransportFactory;
use crate::builder::content::{AttachContent, ContentPlace};
use crate::builder::gate::Gate;
use crate::builder::schema::SyncSchema;
use crate::builder::sign_in::HeldCredential;
use crate::builder::tuning::SyncTuning;
use crate::cipher::ReplicaKey;
use crate::live::ConnettoClient;
#[cfg(not(feature = "native-transport"))]
use crate::reconnect::NoSleep;
#[cfg(feature = "native-transport")]
use crate::reconnect::TokioSleeper;
use crate::reconnect::{ReconnectPolicy, Sleeper};
use crate::replica::Encrypted;
#[cfg(feature = "native-transport")]
use crate::replica::provision_replica_key;
use crate::{AccessTokenSource, ClientConfig, ClientError, ConnettoConnection};
use crate::{GateAskOutcome, GateMechanism};

/// The replica name a build with no identity uses for its client id, and the
/// prefix every durable replica record is named under. Fixed, because the
/// name is the recovery contract between one run and the next.
pub const REPLICA_PREFIX: &str = "connetto";

/// The pump future a build's terminal hands back, owned so it borrows
/// nothing. The platform drives it on its executor, spawning it natively or
/// polling it by hand.
#[cfg(feature = "native-transport")]
pub type CorePump = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
/// The pump future a build's terminal hands back, owned so it borrows
/// nothing. The platform polls it by hand on its single-threaded runtime.
#[cfg(not(feature = "native-transport"))]
pub type CorePump = Pin<Box<dyn Future<Output = ()> + 'static>>;

/// A dial failure the builder surfaces before it can name a transport error.
/// `InsecureWebSocket` carries the core's typed refusal of a plain `ws` URL
/// aimed at a non-loopback host, and `Other` flattens any other dial failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DialFailure {
    /// A plain `ws` URL named a non-loopback host, refused before a socket opens.
    #[cfg(feature = "native-transport")]
    #[error("insecure websocket: {host} is not a loopback host")]
    InsecureWebSocket { host: String },
    /// Any other dial failure.
    #[error("dial failed: {0}")]
    Other(String),
    /// A TLS-layer refusal the platform verifier will not pass on a retry,
    /// such as a certificate it does not trust.
    #[cfg(feature = "native-transport")]
    #[error("tls refused: {0}")]
    Tls(String),
}

impl DialFailure {
    /// Whether a retry could succeed, which decides whether a first dial that
    /// fails starts the client offline or refuses the build.
    fn is_permanent(&self) -> bool {
        match self {
            #[cfg(feature = "native-transport")]
            Self::InsecureWebSocket { .. } | Self::Tls(_) => true,
            Self::Other(_) => false,
        }
    }
}

/// The build's surface for a dial failure.
fn dial_error(err: DialFailure) -> ClientError {
    match err {
        #[cfg(feature = "native-transport")]
        DialFailure::InsecureWebSocket { host } => ClientError::InsecureWebSocket { host },
        #[cfg(feature = "native-transport")]
        DialFailure::Tls(msg) => ClientError::Transport(msg),
        DialFailure::Other(msg) => ClientError::Transport(msg),
    }
}

/// The dialer closure the build owns. `MaybeSend` is a marker trait rather
/// than an auto trait, so the platform's `Send` half is stated on the
/// object itself.
#[cfg(feature = "native-transport")]
type DialFn<T> = Box<
    dyn FnMut() -> Pin<Box<dyn Future<Output = Result<T, DialFailure>> + Send + 'static>>
        + Send
        + 'static,
>;
#[cfg(not(feature = "native-transport"))]
type DialFn<T> =
    Box<dyn FnMut() -> Pin<Box<dyn Future<Output = Result<T, DialFailure>> + 'static>> + 'static>;

/// The lock that serializes the dialer's factory across concurrent dials.
/// `tokio::sync::Mutex` yields on any executor, so it holds across the dial
/// on wasm without blocking the single-threaded runtime.
type Slot<T> = tokio::sync::Mutex<T>;

/// The dialer a builder owns, one closure that hands out a fresh transport
/// on every call, the same closure the first dial and every reconnect use.
pub(crate) struct BoxedDialer<T: Transport> {
    pub(crate) dial: DialFn<T>,
}

impl<T: Transport + MaybeSend + 'static> BoxedDialer<T> {
    /// Wrap a caller-supplied factory.
    pub(crate) fn injected<F>(factory: F) -> Self
    where
        F: TransportFactory<Transport = T> + MaybeSend + 'static,
        F::Error: Display,
    {
        let slot = Arc::new(Slot::new(Some(factory)));
        Self {
            dial: Box::new(move || {
                let slot = Arc::clone(&slot);
                Box::pin(async move {
                    let mut guard = slot.lock_owned().await;
                    guard
                        .as_mut()
                        .expect("the dialer slot is never emptied")
                        .connect()
                        .await
                        .map_err(|err| DialFailure::Other(err.to_string()))
                })
            }),
        }
    }

    async fn connect(&mut self) -> Result<T, DialFailure> {
        (self.dial)().await
    }
}

impl<T: Transport + MaybeSend + 'static> TransportFactory for BoxedDialer<T> {
    type Transport = T;
    type Error = DialFailure;

    fn connect(&mut self) -> impl Future<Output = Result<T, DialFailure>> + MaybeSend {
        (self.dial)()
    }
}

/// The backoff sleep a build injects, owned so the pump can hold one.
/// `MaybeSend` is a marker trait rather than an auto trait, so the
/// platform's `Send` half is stated on the object itself.
#[cfg(feature = "native-transport")]
type SleeperFn =
    Box<dyn FnMut(Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> + Send + 'static>;
#[cfg(not(feature = "native-transport"))]
type SleeperFn = Box<dyn FnMut(Duration) -> Pin<Box<dyn Future<Output = ()> + 'static>> + 'static>;

/// The backoff sleep a build that named none rides. Native takes the ambient
/// runtime's timer. Wasm names its own, because the built-in sleep is instant
/// and turns the backoff into a retry loop with no pause.
fn default_sleeper() -> SleeperFn {
    #[cfg(feature = "native-transport")]
    {
        Box::new(|d| {
            Box::pin(async move {
                let mut sleeper = TokioSleeper;
                sleeper.sleep(d).await;
            })
        })
    }
    #[cfg(not(feature = "native-transport"))]
    {
        Box::new(|d| {
            Box::pin(async move {
                let mut sleeper = NoSleep;
                sleeper.sleep(d).await;
            })
        })
    }
}

/// The fields every stage carries and moves into the next.
pub(crate) struct Base<T: Transport, C> {
    /// The schema the build presents and applies on a fresh replica.
    pub(crate) schema: SyncSchema,
    /// The tuning levers.
    pub(crate) tuning: SyncTuning,
    /// The reconnect policy the pump drives.
    pub(crate) policy: ReconnectPolicy,
    /// The content piece, when the build names one.
    pub(crate) content: Option<C>,
    /// The share keys the build presents, when it holds any. The build applies
    /// them to the replica's subjects function and the handshake on every
    /// platform, so an anonymous and a signed-in client hold the same keys.
    pub(crate) share_keys: Option<ShareKeys>,
    /// The dialer the first dial and every reconnect use.
    pub(crate) dialer: BoxedDialer<T>,
    /// The backoff sleep the platform injected, when it named one.
    pub(crate) sleeper: Option<SleeperFn>,
    /// The client id an anonymous build presents, when the app named one.
    pub(crate) client_id: Option<String>,
}

/// The share keys a build presents, normalized to the subject rendering.
#[derive(Clone)]
pub(crate) struct ShareKeys {
    /// The separator the subjects function packs with.
    pub(crate) separator: char,
    /// Each grant beside the subject string it renders as.
    pub(crate) keys: Vec<(Grant, String)>,
}

impl ShareKeys {
    /// The keys `keys` names, rendered through their own key type.
    pub(crate) fn new<K: CapabilityKey>(
        keys: impl IntoIterator<Item = (Grant, CapabilitySubject<K>)>,
    ) -> Self {
        Self {
            separator: K::SEPARATOR,
            keys: keys
                .into_iter()
                .map(|(grant, subject)| (grant, subject.key().to_string()))
                .collect(),
        }
    }
}

impl<T: Transport, C> Base<T, C> {
    /// The same build with `content` as its content piece.
    pub(crate) fn with_content<A>(self, content: A) -> Base<T, A> {
        Base {
            schema: self.schema,
            tuning: self.tuning,
            policy: self.policy,
            content: Some(content),
            share_keys: self.share_keys,
            dialer: self.dialer,
            sleeper: self.sleeper,
            client_id: self.client_id,
        }
    }

    /// The same build dialing through `dialer`.
    #[cfg(feature = "native-transport")]
    pub(crate) fn with_dialer<U: Transport>(self, dialer: BoxedDialer<U>) -> Base<U, C> {
        Base {
            schema: self.schema,
            tuning: self.tuning,
            policy: self.policy,
            content: self.content,
            share_keys: self.share_keys,
            dialer,
            sleeper: self.sleeper,
            client_id: self.client_id,
        }
    }
}

/// The setters the core builder and the native layer over it share before
/// the sign-in fork, written once for both.
macro_rules! base_setters {
    ($builder:ident) => {
        /// The tuning levers the build carries.
        #[must_use]
        pub fn with_tuning(mut self, tuning: SyncTuning) -> Self {
            self.base.tuning = tuning;
            self
        }

        /// The reconnect policy the pump drives.
        #[must_use]
        pub fn with_reconnect(mut self, policy: ReconnectPolicy) -> Self {
            self.base.policy = policy;
            self
        }

        /// The client id an anonymous build presents, replacing the core
        /// prefix. A signed-in build presents the replica name the credential
        /// carries, so this names nothing there.
        #[must_use]
        pub fn with_client_id(mut self, id: impl Into<String>) -> Self {
            self.base.client_id = Some(id.into());
            self
        }

        /// Attach content handling, the platform's file layer plugged in
        /// through [`AttachContent`].
        #[must_use]
        pub fn with_content<A>(self, content: A) -> $builder<T, A>
        where
            A: AttachContent<T>,
        {
            $builder {
                base: self.base.with_content(content),
            }
        }

        /// Present the share keys the build holds, each beside the subject it
        /// renders as. The subject function is the core constant, never
        /// settable, and its separator is the key's.
        ///
        /// The build applies them to the replica's subjects function and the
        /// handshake on every platform, so the replica's local answer and the
        /// server's binding agree about which keys are held.
        #[must_use]
        pub fn with_share_keys<K: CapabilityKey>(
            mut self,
            keys: impl IntoIterator<Item = (Grant, CapabilitySubject<K>)>,
        ) -> Self {
            self.base.share_keys = Some(ShareKeys::new(keys));
            self
        }
    };
}
#[cfg(feature = "native-transport")]
pub(crate) use base_setters;

/// The resolved inputs a connect runs, owned so the pump it returns borrows
/// nothing.
pub(crate) struct RunInputs {
    /// The stable client id, the replica name when signed in.
    pub(crate) client_id: String,
    /// The login grant, absent for an anonymous build.
    pub(crate) login: Option<Grant>,
    /// The caller identity, absent for an anonymous build.
    pub(crate) caller: Option<String>,
    /// A source of fresh access tokens, consulted on every reconnect.
    pub(crate) token_source: Option<AccessTokenSource>,
    /// The root key the content store encrypts under.
    pub(crate) root_key: [u8; 32],
    /// Where the content store sits.
    pub(crate) place: ContentPlace,
    /// The custody the build reports.
    pub(crate) custody: Custody,
    /// The away-and-return gate and its mechanism, when the gate is on.
    pub(crate) gate: Option<(Gate, Arc<dyn GateMechanism>)>,
    /// Whether the replica is fresh, which decides connect from open.
    pub(crate) fresh: bool,
}

/// The custody a build reports, the weakest claim of the stores it uses. An
/// `Ephemeral` claim dominates, because a key that dies with the process
/// protects nothing after it, and an `Unverified` claim beats `Verified`.
pub(crate) fn custody_of(claims: &[Custody]) -> Custody {
    if claims
        .iter()
        .any(|claim| matches!(claim, Custody::Ephemeral))
    {
        return Custody::Ephemeral;
    }
    claims
        .iter()
        .copied()
        .find(|claim| matches!(claim, Custody::Unverified(_)))
        .unwrap_or(Custody::Verified)
}

/// The in-memory replica a build with nothing at rest opens, with the
/// device-private tier attached when the build has one. The DDL is the
/// caller's to keep alive beside the replica it borrows.
pub(crate) fn in_memory_replica(local_tier_ddl: Option<&str>) -> Replica<'_, crate::InMemory> {
    match local_tier_ddl {
        Some(ddl) => Replica::in_memory().with_tier(ddl),
        None => Replica::in_memory(),
    }
}

/// Build the client config from the shared pieces.
pub(crate) fn build_config(
    schema: &SyncSchema,
    tuning: &SyncTuning,
    client_id: &str,
    login: Option<Grant>,
    caller: Option<&str>,
    custody: Custody,
) -> ClientConfig {
    ClientConfig::new(client_id.to_owned())
        .with_login(login)
        .with_caller(CALLER_FUNCTION, caller)
        .with_schema_version(Some(schema.version()))
        .with_sql_functions(schema.sql_functions().clone())
        .with_policy_tables(schema.policy_tables().clone())
        .with_unrecorded_tables(schema.unrecorded_tables().iter().cloned())
        .with_tuning(*tuning)
        .with_custody(custody)
}

/// The share keys the build folds into the base config after it, applied on
/// every platform so the replica's subjects function and the handshake agree
/// about the keys held.
pub(crate) fn fold_config_aspects(
    config: ClientConfig,
    share_keys: Option<ShareKeys>,
) -> ClientConfig {
    // The subjects function is registered even for a build holding no key,
    // because a translated view calls it whatever the caller holds.
    let keys = share_keys.unwrap_or_else(|| ShareKeys {
        separator: <String as CapabilityKey>::SEPARATOR,
        keys: Vec::new(),
    });
    config.with_share_keys_rendered(keys.separator, keys.keys)
}

/// A running connetto client a build's terminal returns.
///
/// Holds the shared client and, when the build named content, the content
/// handle the build attached on the same root key. The custody the build
/// reports is fixed at connect, since the stores are the ones the build chose
/// and the gate changes only when the key is closed, never how it is held.
pub struct CoreClient<T: Transport, C = ()> {
    client: ConnettoClient<T>,
    content: Option<C>,
    custody: Custody,
}

impl<T, C> CoreClient<T, C>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
{
    /// The shared client.
    #[must_use]
    pub fn client(&self) -> &ConnettoClient<T> {
        &self.client
    }

    /// The content handle, when the build named content.
    #[must_use]
    pub fn content(&self) -> Option<&C> {
        self.content.as_ref()
    }

    /// How the key protecting this client's data is held.
    #[must_use]
    pub fn custody(&self) -> Custody {
        self.custody
    }

    /// End the pump and close the transport while the clones stay alive.
    ///
    /// The pump exits as the last clone's drop would end it. The transport
    /// closes with the proper handshake and no reconnect is attempted.
    pub async fn close(&self) {
        self.client.close().await;
    }
}

/// The platform-neutral connetto client builder, before a sign-in is chosen.
///
/// The build names its schema and its dialer and tunes the rest. `T` is the
/// transport the dialer hands out, so a build is only as platform-specific as
/// the dialer it is given. `connect_with_pump` runs the build anonymously and
/// in memory, `connect_driven` returns the connected, unstarted connection a
/// caller drives frame by frame, and `signed_in` forks the build toward a
/// credential the caller already holds.
///
/// The platform layers add their own dialing and sign-in on top of this
/// builder. The native layer dials a server URL and forks the provider
/// sign-in into its keyring stores, and the web layer injects the browser
/// socket and resolves the browser sign-in into a held credential.
///
/// ```no_run
/// use connetto_client::{ClientBuilder, SyncSchema};
/// use connetto_core::{LoopbackError, LoopbackTransport, SchemaBundle};
/// # let bundle = SchemaBundle::new(
/// #     "SCHEMA", "POLICIES", "DDL",
/// #     Vec::<(String, String)>::new(),
/// #     Vec::<String>::new(),
/// #     None::<&str>,
/// # );
/// // `connect_with_pump` returns a future. Await it on your platform's
/// // executor, and drive the pump future it hands back.
/// let _pending = ClientBuilder::new(
///     SyncSchema::new(bundle),
///     || core::future::pending::<Result<LoopbackTransport, LoopbackError>>(),
/// )
/// .connect_with_pump();
/// ```
///
/// The anonymous builder has no gate and no durable step, because a build
/// that connects anonymous keeps nothing at rest, and those pieces have
/// nothing to act on.
///
/// ```compile_fail
/// # use connetto_client::{ClientBuilder, Gate, MemoryKeyStore, SyncSchema};
/// # use connetto_core::{LoopbackError, LoopbackTransport, SchemaBundle};
/// # let bundle = SchemaBundle::new(
/// #     "SCHEMA", "POLICIES", "DDL",
/// #     Vec::<(String, String)>::new(),
/// #     Vec::<String>::new(),
/// #     None::<&str>,
/// # );
/// let builder = ClientBuilder::new(
///     SyncSchema::new(bundle),
///     || core::future::pending::<Result<LoopbackTransport, LoopbackError>>(),
/// );
/// builder.durable("/data", MemoryKeyStore::default());
/// ```
///
/// ```compile_fail
/// # use connetto_client::{ClientBuilder, Gate, SyncSchema};
/// # use connetto_core::{LoopbackError, LoopbackTransport, SchemaBundle};
/// # let bundle = SchemaBundle::new(
/// #     "SCHEMA", "POLICIES", "DDL",
/// #     Vec::<(String, String)>::new(),
/// #     Vec::<String>::new(),
/// #     None::<&str>,
/// # );
/// let builder = ClientBuilder::new(
///     SyncSchema::new(bundle),
///     || core::future::pending::<Result<LoopbackTransport, LoopbackError>>(),
/// );
/// builder.with_gate(Gate::off());
/// ```
pub struct ClientBuilder<T: Transport, C = ()> {
    pub(crate) base: Base<T, C>,
}

impl<T: Transport + MaybeSend + 'static> ClientBuilder<T, ()> {
    /// Start a platform-neutral build over `schema`, dialing through
    /// `dialer`, which hands out a fresh `T` on every call.
    ///
    /// The dialer has no honest default on a platform-neutral build, so it is
    /// stated here rather than named later. The platform layers wrap this with
    /// their own dialing, the native layer over a server URL and the web
    /// layer over the browser socket.
    #[must_use]
    pub fn new<F>(schema: SyncSchema, dialer: F) -> Self
    where
        F: TransportFactory<Transport = T> + MaybeSend + 'static,
        F::Error: Display,
    {
        Self {
            base: Base {
                schema,
                tuning: SyncTuning::default(),
                policy: ReconnectPolicy::default(),
                content: None,
                share_keys: None,
                dialer: BoxedDialer::injected(dialer),
                sleeper: None,
                client_id: None,
            },
        }
    }
}

impl<T, C> ClientBuilder<T, C>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    C: AttachContent<T>,
{
    base_setters!(ClientBuilder);

    /// The backoff sleep the reconnect driver waits on, replacing the
    /// platform default. The closure resolves a fresh future per pause, so a
    /// browser build wires the platform timer through it.
    #[must_use]
    pub fn with_sleeper<F, Fut>(mut self, mut sleeper: F) -> Self
    where
        F: FnMut(Duration) -> Fut + MaybeSend + 'static,
        Fut: Future<Output = ()> + MaybeSend + 'static,
    {
        let boxed: SleeperFn = Box::new(move |d| Box::pin(sleeper(d)));
        self.base.sleeper = Some(boxed);
        self
    }

    /// Sign in with a credential the caller already holds, moving the build
    /// to the signed-in stage.
    ///
    /// The platform layers fork the provider sign-in into their own stores
    /// before reaching this builder, and hand the result here as a held
    /// credential.
    #[must_use]
    pub fn signed_in(self, credential: HeldCredential) -> CoreSignedIn<T, C> {
        CoreSignedIn {
            base: self.base,
            credential,
        }
    }

    /// Connect anonymous and in memory, returning the running client beside
    /// the pump future that keeps it running.
    ///
    /// The build reads whatever the deployment's policy shows an anonymous
    /// caller and writes only where a capability says it may. Nothing is
    /// named at rest, so the custody is `Ephemeral`. The pump is the
    /// application's to drive, spawned on the platform's executor or polled
    /// by hand.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a dial, database, or handshake failure.
    pub async fn connect_with_pump(
        self,
    ) -> Result<(CoreClient<T, C::Handle>, CorePump), ClientError> {
        let mut base = self.base;
        let client_id = base
            .client_id
            .take()
            .unwrap_or_else(|| REPLICA_PREFIX.to_owned());
        let tier = base.schema.local_tier_ddl().map(str::to_owned);
        let replica = in_memory_replica(tier.as_deref());
        run_core(
            &replica,
            base,
            RunInputs {
                client_id,
                login: None,
                caller: None,
                token_source: None,
                root_key: [0u8; 32],
                place: ContentPlace::InMemory,
                custody: Custody::Ephemeral,
                gate: None,
                fresh: true,
            },
        )
        .await
    }
}

impl<T> ClientBuilder<T, ()>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
{
    /// Connect anonymous and in memory, returning the connected, unstarted
    /// connection for a caller that drives it frame by frame.
    ///
    /// The replica opens offline first, so local reads answer at once, and a
    /// failed dial leaves the connection usable offline. The driver API is
    /// the frame-by-frame surface, one `pump_one` per frame with the
    /// subscription declared in between. A build that names content cannot
    /// use this terminal, because the content handle attaches to a running
    /// client and there is none here.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a dial, database, or handshake failure.
    pub async fn connect_driven(self) -> Result<ConnettoConnection<T>, ClientError> {
        self.driven().connect().await
    }

    /// Open anonymous and in memory with no transport, returning the
    /// unstarted, offline connection for a caller that attaches one by hand
    /// later. [`connect_driven`](Self::connect_driven) without the dial.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a database or cipher failure.
    pub fn open_driven(self) -> Result<ConnettoConnection<T>, ClientError> {
        self.driven().open()
    }

    /// The anonymous build's driven inputs.
    fn driven(self) -> Driven<T> {
        let mut base = self.base;
        let client_id = base
            .client_id
            .take()
            .unwrap_or_else(|| REPLICA_PREFIX.to_owned());
        Driven {
            base,
            client_id,
            login: None,
            caller: None,
            custody: Custody::Ephemeral,
            token_source: None,
            replica: DrivenReplica::InMemory,
        }
    }
}

/// The signed-in stage of a platform-neutral build, with a credential named
/// and the replica still in process.
///
/// The credential signs the login and names the replica, and its token source
/// rides every reconnect. `durable` moves the build to the durable stage, and
/// the terminals connect in memory.
pub struct CoreSignedIn<T: Transport, C = ()> {
    pub(crate) base: Base<T, C>,
    pub(crate) credential: HeldCredential,
}

impl<T, C> CoreSignedIn<T, C>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    C: AttachContent<T>,
{
    /// Connect signed in, in memory, returning the running client beside the
    /// pump future that keeps it running.
    ///
    /// The credential signs the login and names the replica, and the token
    /// source rides every reconnect. The replica is in process, so the
    /// custody is `Ephemeral`.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a dial, database, or handshake failure.
    pub async fn connect_with_pump(
        self,
    ) -> Result<(CoreClient<T, C::Handle>, CorePump), ClientError> {
        let (name, caller, login, token_source) = self.credential.into_parts();
        let tier = self.base.schema.local_tier_ddl().map(str::to_owned);
        let replica = in_memory_replica(tier.as_deref());
        run_core(
            &replica,
            self.base,
            RunInputs {
                client_id: name,
                login: Some(login),
                caller: Some(caller),
                token_source,
                root_key: [0u8; 32],
                place: ContentPlace::InMemory,
                custody: Custody::Ephemeral,
                gate: None,
                fresh: true,
            },
        )
        .await
    }

    /// Move to the durable stage, naming where the replica lives and the key
    /// store the build will use.
    ///
    /// `place` locates the replica file from the name the credential carries,
    /// and says whether one is already there, so two identities on one
    /// device keep separate files and keys. A platform without a platform
    /// RNG, the browser among them, holds the key of a fresh replica in the
    /// store before this step runs.
    #[must_use]
    pub fn durable<P, KS>(self, place: P, key_store: KS) -> CoreDurable<T, C, KS, P>
    where
        P: ReplicaPlace,
        KS: ReplicaKeyStore<Error = ClientError> + MaybeSend + 'static,
    {
        CoreDurable {
            base: self.base,
            credential: self.credential,
            place,
            key_store,
            claims: Vec::new(),
            gate: Gate::default(),
            mechanism: None,
        }
    }
}

impl<T> CoreSignedIn<T, ()>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
{
    /// Connect signed in, in memory, returning the connected, unstarted
    /// connection for a caller that drives it frame by frame.
    ///
    /// The replica opens offline first, so local reads answer at once, and a
    /// failed dial leaves the connection usable offline.
    ///
    /// The driver API is the frame-by-frame surface, one `pump_one` per
    /// frame with the subscription declared in between. A build that names
    /// content cannot use this terminal, because the content handle attaches
    /// to a running client and there is none here.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a dial, database, or handshake failure.
    pub async fn connect_driven(self) -> Result<ConnettoConnection<T>, ClientError> {
        self.driven().connect().await
    }

    /// Open signed in, in memory, with no transport, returning the unstarted,
    /// offline connection for a caller that attaches one by hand later.
    /// [`connect_driven`](Self::connect_driven) without the dial.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a database or cipher failure.
    pub fn open_driven(self) -> Result<ConnettoConnection<T>, ClientError> {
        self.driven().open()
    }

    /// The signed-in build's driven inputs.
    fn driven(self) -> Driven<T> {
        let (name, caller, login, token_source) = self.credential.into_parts();
        Driven {
            base: self.base,
            client_id: name,
            login: Some(login),
            caller: Some(caller),
            custody: Custody::Ephemeral,
            token_source,
            replica: DrivenReplica::InMemory,
        }
    }
}

/// Where a durable replica lives on one platform.
///
/// The build knows the replica's name only once a credential names it, so
/// the platform locates the file from that name, a file under a data
/// directory natively and an OPFS pool entry in the browser. The platform alone
/// knows whether the file is there, which decides between opening an
/// existing replica and creating one.
pub trait ReplicaPlace {
    /// Locate the replica called `name`.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the platform cannot name a location for it.
    fn locate(&self, name: &str) -> Result<Located, ClientError>;
}

/// A located replica, naming where its key record goes, the location
/// `Replica::encrypted_file` takes, whether a replica is already there, and
/// where its content lives.
#[derive(Debug, Clone)]
pub struct Located {
    record: String,
    url: String,
    exists: bool,
    content: ContentPlace,
}

impl Located {
    /// A replica whose key is recorded under `record`, at `url`, present when
    /// `exists`, with content at `content`.
    ///
    /// The record is the file's own name wherever the key store is shared
    /// more widely than the place, as the browser's is across an origin, so
    /// two places never share a key record.
    #[must_use]
    pub fn new(
        record: impl Into<String>,
        url: impl Into<String>,
        exists: bool,
        content: ContentPlace,
    ) -> Self {
        Self {
            record: record.into(),
            url: url.into(),
            exists,
            content,
        }
    }

    /// The name the replica's key record goes under.
    #[must_use]
    pub fn record(&self) -> &str {
        &self.record
    }

    /// Whether a replica is already at this location.
    #[must_use]
    pub const fn exists(&self) -> bool {
        self.exists
    }
}

/// The durable stage of a platform-neutral build, a replica file under a
/// key beside its content, gated on the away input when the gate is on.
///
/// Only this stage has the place, the key store and the gate, because a
/// build that names a file names its key and its lock together.
pub struct CoreDurable<T: Transport, C, KS, P> {
    pub(crate) base: Base<T, C>,
    pub(crate) credential: HeldCredential,
    pub(crate) place: P,
    pub(crate) key_store: KS,
    /// Protection claims from stores beside the key store, which a platform
    /// layer adds for the refresh store it signed in through.
    pub(crate) claims: Vec<Custody>,
    pub(crate) gate: Gate,
    pub(crate) mechanism: Option<Arc<dyn GateMechanism>>,
}

/// The resolved inputs a durable build's terminals run.
struct DurableResolved<T: Transport, C> {
    /// The fields every stage carries.
    base: Base<T, C>,
    /// The replica name the credential carries, which the handshake presents as the client id.
    name: String,
    /// The caller value the server binds.
    caller: String,
    /// The login grant.
    login: Grant,
    /// A source of fresh access tokens, consulted on every reconnect.
    token_source: Option<AccessTokenSource>,
    /// The replica key the store hands over.
    key: ReplicaKey,
    /// The located replica.
    located: Located,
    /// The device-private tier, when the build has one.
    ddl: Option<String>,
    /// The custody the stores' claims fold into.
    custody: Custody,
    /// The away-and-return gate and its mechanism, when the gate is on.
    gate: Option<(Gate, Arc<dyn GateMechanism>)>,
}

impl<T, C, KS, P> CoreDurable<T, C, KS, P>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    C: AttachContent<T>,
    KS: ReplicaKeyStore<Error = ClientError> + MaybeSend + 'static,
    P: ReplicaPlace,
{
    /// The away-and-return gate, on by default.
    #[must_use]
    pub fn with_gate(mut self, gate: Gate) -> Self {
        self.gate = gate;
        self
    }

    /// The mechanism the gate's lock and ask ride on. The platform's
    /// biometric ceremony implements it, and the one tests use to approve or
    /// dismiss a check.
    #[must_use]
    pub fn with_gate_mechanism(mut self, mechanism: impl GateMechanism + 'static) -> Self {
        self.mechanism = Some(Arc::new(mechanism));
        self
    }

    /// Connect with the durable replica, returning the running client beside
    /// the pump future that keeps it running.
    ///
    /// An existing replica opens under the key the store holds for it. A
    /// fresh one takes the stored key, or one minted where the platform can
    /// mint. Content attaches where the place put it, on the same root key.
    /// The custody is the weakest of the stores' claims.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a key, dial, database, or handshake failure, and
    /// [`ClientError::ReplicaKeyMissing`] when the store holds no key for an
    /// existing replica, or for a fresh one on a platform that cannot mint.
    pub async fn connect_with_pump(
        self,
    ) -> Result<(CoreClient<T, C::Handle>, CorePump), ClientError> {
        let DurableResolved {
            base,
            name,
            caller,
            login,
            token_source,
            key,
            located,
            ddl,
            custody,
            gate,
        } = self.resolve().await?;
        let replica = open_encrypted_replica(&located.url, &key, !located.exists, ddl.as_ref())?;
        run_core(
            &replica,
            base,
            RunInputs {
                client_id: name,
                login: Some(login),
                caller: Some(caller),
                token_source,
                root_key: *key.as_bytes(),
                place: located.content,
                custody,
                gate,
                fresh: !located.exists,
            },
        )
        .await
    }

    async fn resolve(self) -> Result<DurableResolved<T, C>, ClientError> {
        let (name, caller, login, token_source) = self.credential.into_parts();
        let mut located = self.place.locate(&name)?;
        let stored = match self.key_store.load(&located.record).await {
            Err(ClientError::ReplicaKeyLost) => {
                wipe_lost(&located)?;
                located = self.place.locate(&name)?;
                None
            }
            stored => stored?,
        };
        let key = match stored {
            Some(key) => key,
            None if located.exists => return Err(ClientError::ReplicaKeyMissing),
            None => mint_key(&self.key_store, &located.record).await?,
        };
        let mut claims = self.claims;
        claims.push(self.key_store.protection());
        let custody = custody_of(&claims);
        let gate = if self.gate.on() {
            self.mechanism.map(|mechanism| (self.gate, mechanism))
        } else {
            None
        };
        let ddl = self.base.schema.local_tier_ddl().map(str::to_owned);
        Ok(DurableResolved {
            base: self.base,
            name,
            caller,
            login,
            token_source,
            key,
            located,
            ddl,
            custody,
            gate,
        })
    }
}

/// Wipe a replica whose key the platform lost, with its tier and content,
/// since nothing can open it again. Its unsynced writes went with the key.
#[cfg(feature = "native-transport")]
fn wipe_lost(located: &Located) -> Result<(), ClientError> {
    tracing::warn!(
        replica = %located.url,
        "the platform lost the replica key, starting a fresh replica"
    );
    crate::teardown::purge_replica(std::path::Path::new(&located.url), &[], true)
        .map_err(|err| ClientError::Session(format!("wiping a replica whose key was lost: {err}")))
}

/// The browser keeps its keys in its own storage, which never reports a lost
/// key, so the refusal stands there.
#[cfg(not(feature = "native-transport"))]
fn wipe_lost(_located: &Located) -> Result<(), ClientError> {
    Err(ClientError::ReplicaKeyLost)
}

/// Mint and store the key of a fresh replica, where the platform has an RNG.
#[cfg(feature = "native-transport")]
async fn mint_key<KS>(key_store: &KS, name: &str) -> Result<ReplicaKey, ClientError>
where
    KS: ReplicaKeyStore<Error = ClientError>,
{
    provision_replica_key(key_store, name).await
}

/// A platform without an RNG here mints the key before the durable step, so
/// a fresh replica with no stored key is refused.
#[cfg(not(feature = "native-transport"))]
#[expect(
    clippy::unused_async,
    reason = "the native twin awaits the store, and both are awaited alike"
)]
async fn mint_key<KS>(_key_store: &KS, _name: &str) -> Result<ReplicaKey, ClientError> {
    Err(ClientError::ReplicaKeyMissing)
}

/// Open the replica file at `location` under `key`, with the device-private
/// tier when the build has one. The replica owns its copy of the key, and
/// the caller keeps its own for the content root key.
fn open_encrypted_replica<'a>(
    location: &'a str,
    key: &ReplicaKey,
    fresh: bool,
    ddl: Option<&'a String>,
) -> Result<Replica<'a, Encrypted>, ClientError> {
    let replica = Replica::encrypted_file(location, Some(key.clone()))?;
    Ok(match (fresh, ddl) {
        (true, Some(ddl)) => replica.with_tier(ddl),
        (false, Some(_)) => replica.with_existing_tier(),
        (_, None) => replica,
    })
}

impl<T, KS, P> CoreDurable<T, (), KS, P>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    KS: ReplicaKeyStore<Error = ClientError> + MaybeSend + 'static,
    P: ReplicaPlace,
{
    /// Connect with the durable replica, returning the connected, unstarted
    /// connection for a caller that drives it frame by frame.
    ///
    /// The driver API is the frame-by-frame surface, one `pump_one` per
    /// frame with the subscription declared in between. A build that names
    /// content cannot use this terminal, because the content handle attaches
    /// to a running client and there is none here.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a key, dial, database, or handshake failure,
    /// including a first dial that fails, since nothing here retries it.
    pub async fn connect_driven(self) -> Result<ConnettoConnection<T>, ClientError> {
        self.driven().await?.connect().await
    }

    /// Open the durable replica with no transport, returning the unstarted
    /// connection for a caller that attaches one by hand later.
    /// [`connect_driven`](Self::connect_driven) without the dial.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a key, database, or cipher failure.
    pub async fn open_driven(self) -> Result<ConnettoConnection<T>, ClientError> {
        self.driven().await?.open()
    }

    /// The durable build's driven inputs, once its key is resolved.
    async fn driven(self) -> Result<Driven<T>, ClientError> {
        let DurableResolved {
            base,
            name,
            caller,
            login,
            token_source,
            key,
            located,
            custody,
            ..
        } = self.resolve().await?;
        Ok(Driven {
            base,
            client_id: name,
            login: Some(login),
            caller: Some(caller),
            custody,
            token_source,
            replica: DrivenReplica::Encrypted { located, key },
        })
    }
}

/// Where a driven terminal opens its replica.
enum DrivenReplica {
    /// In process, with the device-private tier when the schema has one.
    InMemory,
    /// The located file under its key.
    Encrypted { located: Located, key: ReplicaKey },
}

/// The owned inputs every driven terminal runs, so the connect and the open
/// build the replica and the config one way on every stage.
struct Driven<T: Transport> {
    base: Base<T, ()>,
    client_id: String,
    login: Option<Grant>,
    caller: Option<String>,
    custody: Custody,
    token_source: Option<AccessTokenSource>,
    replica: DrivenReplica,
}

impl<T> Driven<T>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
{
    /// The client config the stage's identity and custody make.
    fn config(&self) -> ClientConfig {
        let config = build_config(
            &self.base.schema,
            &self.base.tuning,
            &self.client_id,
            self.login.clone(),
            self.caller.as_deref(),
            self.custody,
        );
        fold_config_aspects(config, self.base.share_keys.clone())
    }

    /// Open the replica, then dial once, failing when the dial fails.
    async fn connect(self) -> Result<ConnettoConnection<T>, ClientError> {
        let config = self.config();
        let Self {
            mut base,
            token_source,
            replica,
            ..
        } = self;
        let tier = base.schema.local_tier_ddl().map(str::to_owned);
        match replica {
            DrivenReplica::InMemory => {
                let replica = in_memory_replica(tier.as_deref());
                offline_connect_core(
                    &replica,
                    &base.schema,
                    &config,
                    true,
                    token_source,
                    &mut base.dialer,
                    FirstDial::Required,
                )
                .await
            }
            DrivenReplica::Encrypted { located, key } => {
                let fresh = !located.exists;
                let replica = open_encrypted_replica(&located.url, &key, fresh, tier.as_ref())?;
                offline_connect_core(
                    &replica,
                    &base.schema,
                    &config,
                    fresh,
                    token_source,
                    &mut base.dialer,
                    FirstDial::Required,
                )
                .await
            }
        }
    }

    /// Open the replica with no transport.
    fn open(self) -> Result<ConnettoConnection<T>, ClientError> {
        let config = self.config();
        let Self {
            base,
            token_source,
            replica,
            ..
        } = self;
        let tier = base.schema.local_tier_ddl().map(str::to_owned);
        match replica {
            DrivenReplica::InMemory => {
                let replica = in_memory_replica(tier.as_deref());
                open_driven_core(&replica, &base.schema, &config, true, token_source)
            }
            DrivenReplica::Encrypted { located, key } => {
                let fresh = !located.exists;
                let replica = open_encrypted_replica(&located.url, &key, fresh, tier.as_ref())?;
                open_driven_core(&replica, &base.schema, &config, fresh, token_source)
            }
        }
    }
}

/// What the shared connect does when its one dial fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FirstDial {
    /// A running client starts offline and its reconnect loop attaches later.
    MayFail,
    /// A driven connection has no loop to retry, so the build fails.
    Required,
}

/// The shared connect opens the replica so local reads answer at once, then
/// tries one dial and attaches it on success. A refusal no retry can cure fails
/// the build either way, and any other failure follows `first_dial`. The
/// replica is opened by the caller, which knows its storage.
pub(crate) async fn offline_connect_core<T, S>(
    replica: &Replica<'_, S>,
    schema: &SyncSchema,
    config: &ClientConfig,
    fresh: bool,
    token_source: Option<AccessTokenSource>,
    dialer: &mut BoxedDialer<T>,
    first_dial: FirstDial,
) -> Result<ConnettoConnection<T>, ClientError>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    S: ReplicaStorage,
{
    let mut conn = if fresh {
        ConnettoConnection::open(replica, schema.replica_ddl(), config, None)
    } else {
        ConnettoConnection::open_existing(replica, config, None)
    }?;
    match dialer.connect().await {
        Ok(transport) => conn.attach(transport).await?,
        Err(err) => {
            if err.is_permanent() || first_dial == FirstDial::Required {
                return Err(dial_error(err));
            }
            tracing::warn!(
                error = %err,
                "no server reachable on the first dial, starting offline"
            );
        }
    }
    Ok(match token_source {
        Some(source) => conn.with_token_source(source),
        None => conn,
    })
}

/// The shared driven open, which opens the replica offline with no transport
/// at all for a caller that attaches one by hand later. [`offline_connect_core`]
/// minus the dial.
pub(crate) fn open_driven_core<T, S>(
    replica: &Replica<'_, S>,
    schema: &SyncSchema,
    config: &ClientConfig,
    fresh: bool,
    token_source: Option<AccessTokenSource>,
) -> Result<ConnettoConnection<T>, ClientError>
where
    T: Transport,
    S: ReplicaStorage,
{
    let conn = if fresh {
        ConnettoConnection::open(replica, schema.replica_ddl(), config, None)
    } else {
        ConnettoConnection::open_existing(replica, config, None)
    }?;
    Ok(match token_source {
        Some(source) => conn.with_token_source(source),
        None => conn,
    })
}

/// Dial, connect, start the pump, gate and attach content. The replica is
/// opened by the caller, which knows its storage.
pub(crate) async fn run_core<T, C, S>(
    replica: &Replica<'_, S>,
    base: Base<T, C>,
    inputs: RunInputs,
) -> Result<(CoreClient<T, C::Handle>, CorePump), ClientError>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    C: AttachContent<T>,
    S: ReplicaStorage,
{
    let Base {
        schema,
        tuning,
        policy,
        content,
        share_keys,
        mut dialer,
        sleeper,
        // Taken by the signed-in and durable stages before run_core.
        client_id: _,
    } = base;
    let config = build_config(
        &schema,
        &tuning,
        &inputs.client_id,
        inputs.login,
        inputs.caller.as_deref(),
        inputs.custody,
    );
    let config = fold_config_aspects(config, share_keys);
    let conn = offline_connect_core(
        replica,
        &schema,
        &config,
        inputs.fresh,
        inputs.token_source,
        &mut dialer,
        FirstDial::MayFail,
    )
    .await?;
    let sleeper = sleeper.unwrap_or_else(default_sleeper);
    let (client, pump) = ConnettoClient::with_reconnect(conn, dialer, sleeper, policy);
    // Content attaches before the gate arms, since its heal pass reads the
    // replica through the client.
    let content = match content {
        Some(content) => Some(
            content
                .attach(client.clone(), inputs.root_key, inputs.place)
                .await?,
        ),
        None => None,
    };
    if let Some((gate, mechanism)) = inputs.gate {
        // The launch prompt resolves before the client is handed back, as the
        // browser's boot waits on its unlock, so nothing the application
        // starts meets the lock. A launch whose sign-in already read the
        // secrets behind the platform's verification asks nothing more.
        if !mechanism.is_open() && mechanism.ask().await == GateAskOutcome::Dismissed {
            return Err(ClientError::Locked);
        }
        client.enable_verified_gate(gate.recheck(), mechanism).await;
    }
    let pump: CorePump = Box::pin(pump);
    Ok((
        CoreClient {
            client,
            content,
            custody: inputs.custody,
        },
        pump,
    ))
}

/// The no-content seam. A build that names no content still rides the same
/// `with_content`-typed path, with the identity attach.
impl<T: Transport> AttachContent<T> for () {
    type Handle = ();

    #[expect(
        clippy::manual_async_fn,
        reason = "the body must stay a no-capture async block: `client` is `ConnettoClient<T>` under a bare `T: Transport` bound, which is not `Send`, so an `async fn` (which captures its parameters into the future) would make the returned future non-`Send` and violate the `MaybeSend` bound"
    )]
    fn attach(
        self,
        _client: ConnettoClient<T>,
        _root_key: [u8; 32],
        _place: ContentPlace,
    ) -> impl Future<Output = Result<(), ClientError>> + MaybeSend {
        async { Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use connetto_core::custody::{Custody, NoGate};

    use super::custody_of;

    #[test]
    fn a_build_reports_the_weakest_claim_of_the_stores_it_uses() {
        let offerable = Custody::Unverified(NoGate::Offerable);
        let unsupported = Custody::Unverified(NoGate::Unsupported);
        assert_eq!(
            custody_of(&[Custody::Verified, Custody::Verified]),
            Custody::Verified
        );
        assert_eq!(custody_of(&[Custody::Verified, offerable]), offerable);
        assert_eq!(custody_of(&[unsupported, Custody::Verified]), unsupported);
        assert_eq!(
            custody_of(&[offerable, Custody::Ephemeral]),
            Custody::Ephemeral
        );
    }
}
