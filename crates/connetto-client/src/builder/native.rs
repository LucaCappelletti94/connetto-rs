//! The native builders and the client they produce.
//!
//! The native layer is the core builder with its dialing and sign-in
//! resolved to the platform's, a built-in dialer over the server URL, the
//! provider sign-in forked into its keyring stores, and a spawn that the
//! platform's runtime owns. Everything the build composes rides the core.

use std::fmt::Display;
use std::path::PathBuf;
use std::sync::Arc;

use connetto_core::auth::CapabilityKey;
use connetto_core::auth::CapabilitySubject;
use connetto_core::messages::Grant;
use connetto_core::traits::{MaybeSend, ReplicaKeyStore, Transport};
use connetto_core::{DialError, NativeStream, WebSocketTransport, dial};

use crate::GateMechanism;
use crate::TransportFactory;
#[cfg(feature = "native-auth")]
use crate::auth::{KeyringKeyStore, NativeAuthenticator, remembered_account};
use crate::builder::content::{AttachContent, ContentPlace};
use crate::builder::core::{
    Base, BoxedDialer, ClientBuilder, CoreClient, CoreDurable, CorePump, CoreSignedIn, DialFailure,
    Located, ReplicaPlace, ShareKeys, base_setters,
};
use crate::builder::gate::Gate;
use crate::builder::schema::SyncSchema;
#[cfg(feature = "native-auth")]
use crate::builder::sign_in::{AccountChoice, Keyring};
use crate::builder::sign_in::{HeldCredential, NativeSignIn, NoKeyring, SignInKind, StorageMarker};
use crate::builder::tuning::SyncTuning;
use crate::cipher::ReplicaKey;
use crate::reconnect::ReconnectPolicy;
#[cfg(feature = "native-auth")]
use crate::replica::encode_identity;
use crate::teardown::content_dir;
#[cfg(feature = "native-auth")]
use crate::teardown::{ForgetError, PurgeError, forget_device, wipe_replica};
use crate::{ClientError, ConnettoClient, Custody};

/// The platform transport, a WebSocket over a plain loopback socket or a
/// TLS stream the platform's trust store verified.
pub type NativeTransport = WebSocketTransport<NativeStream>;

impl BoxedDialer<NativeTransport> {
    /// The built-in dialer, re-dialing the build's `wss` or loopback `ws` URL.
    fn server(server: String) -> Self {
        Self {
            dial: Box::new(move || {
                let url = server.clone();
                Box::pin(async move {
                    dial(&url).await.map_err(|err| match err {
                        DialError::PlainToNonLoopback(host) => {
                            DialFailure::InsecureWebSocket { host }
                        }
                        DialError::Tls(msg) => DialFailure::Tls(msg),
                        other => DialFailure::Other(other.to_string()),
                    })
                })
            }),
        }
    }
}

/// A native connetto client's builder, before a sign-in is chosen.
///
/// The build names its server and its schema and tunes the rest. `connect`
/// runs it anonymously and in memory, and `signed_in` forks it toward a
/// credential.
///
/// ```no_run
/// # use connetto_client::{NativeClientBuilder, SyncSchema};
/// # use connetto_core::schema::SchemaBundle;
/// # let bundle = SchemaBundle::new(
/// #     "SCHEMA", "POLICIES", "DDL",
/// #     Vec::<(String, String)>::new(),
/// #     Vec::<String>::new(),
/// #     None::<&str>,
/// # );
/// // `connect` runs the build and returns a future; await it in your runtime.
/// let _pending =
///     NativeClientBuilder::new("wss://sync.example.com", SyncSchema::new(bundle)).connect();
/// ```
///
/// The anonymous builder has no gate, no data directory and no account
/// choice, because a build that connects anonymous keeps nothing at rest and
/// those pieces have nothing to act on.
///
/// ```compile_fail
/// # use connetto_client::{NativeClientBuilder, SyncSchema};
/// # use connetto_core::schema::SchemaBundle;
/// # let bundle = SchemaBundle::new(
/// #     "SCHEMA", "POLICIES", "DDL",
/// #     Vec::<(String, String)>::new(),
/// #     Vec::<String>::new(),
/// #     None::<&str>,
/// # );
/// let builder = NativeClientBuilder::new(
///     "wss://sync.example.com",
///     SyncSchema::new(bundle),
/// );
/// builder.durable("/data");
/// ```
///
/// ```compile_fail
/// # use connetto_client::{AccountChoice, NativeClientBuilder, SyncSchema};
/// # use connetto_core::schema::SchemaBundle;
/// # let bundle = SchemaBundle::new(
/// #     "SCHEMA", "POLICIES", "DDL",
/// #     Vec::<(String, String)>::new(),
/// #     Vec::<String>::new(),
/// #     None::<&str>,
/// # );
/// let builder = NativeClientBuilder::new(
///     "wss://sync.example.com",
///     SyncSchema::new(bundle),
/// );
/// builder.with_account(AccountChoice::New);
/// ```
pub struct NativeClientBuilder<T: Transport = NativeTransport, C = ()> {
    base: Base<T, C>,
}

impl NativeClientBuilder<NativeTransport> {
    /// A native build dialing `server`, a `wss://` URL or a loopback
    /// `ws://` URL.
    ///
    /// A `ws://` URL whose host is not loopback is refused with
    /// [`ClientError::InsecureWebSocket`] before any socket opens.
    #[must_use]
    pub fn new(server: impl Into<String>, schema: SyncSchema) -> Self {
        Self {
            base: Base {
                schema,
                tuning: SyncTuning::default(),
                policy: ReconnectPolicy::default(),
                content: None,
                share_keys: None,
                dialer: BoxedDialer::server(server.into()),
                sleeper: None,
                client_id: None,
            },
        }
    }
}

impl<T, C> NativeClientBuilder<T, C>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    C: AttachContent<T>,
{
    base_setters!(NativeClientBuilder);

    /// Dial fresh transports through the caller's factory instead of the
    /// default, for a transport other than the platform one or a test that
    /// hands a loopback.
    #[must_use]
    pub fn with_dialer<F>(self, factory: F) -> NativeClientBuilder<F::Transport, C>
    where
        F: TransportFactory + MaybeSend + 'static,
        F::Transport: Transport + MaybeSend + 'static,
        F::Error: Display,
    {
        NativeClientBuilder {
            base: self.base.with_dialer(BoxedDialer::injected(factory)),
        }
    }

    /// Sign in, moving the build to the signed-in stage.
    ///
    /// A bare [`Auth`](crate::Auth) does not compile here, because natively a
    /// credential needs a store and the platform fork states one.
    ///
    /// ```compile_fail
    /// # use connetto_client::{Auth, NativeClientBuilder, SyncSchema};
    /// # use connetto_core::schema::SchemaBundle;
    /// # let bundle = SchemaBundle::new(
    /// #     "SCHEMA", "POLICIES", "DDL",
    /// #     Vec::<(String, String)>::new(),
    /// #     Vec::<String>::new(),
    /// #     None::<&str>,
    /// # );
    /// let builder = NativeClientBuilder::new(
    ///     "wss://sync.example.com",
    ///     SyncSchema::new(bundle),
    /// );
    /// builder.signed_in(Auth::new("https://auth.example.com", "github"));
    /// ```
    #[must_use]
    pub fn signed_in<S: NativeSignIn>(self, sign_in: S) -> NativeSignedIn<T, C, S::Storage> {
        let (kind, storage) = sign_in.into_parts();
        NativeSignedIn {
            base: self.base,
            kind,
            storage,
        }
    }

    /// Connect anonymous and in memory.
    ///
    /// The build reads whatever the deployment's policy shows an anonymous
    /// caller and writes only where a capability says it may. Nothing is
    /// named at rest, so the custody is `Ephemeral`.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a dial, database, or handshake failure.
    pub async fn connect(self) -> Result<NativeClient<T, C::Handle>, ClientError> {
        let (client, pump) = self.connect_with_pump().await?;
        tokio::spawn(pump);
        Ok(client)
    }

    /// Like [`connect`](Self::connect), but the pump future comes back for
    /// the application to drive on its own executor.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a dial, database, or handshake failure.
    pub async fn connect_with_pump(
        self,
    ) -> Result<(NativeClient<T, C::Handle>, CorePump), ClientError> {
        let (core, pump) = ClientBuilder { base: self.base }
            .connect_with_pump()
            .await?;
        Ok((NativeClient::bare(core), pump))
    }
}

/// The signed-in stage, with a credential named and the replica still in
/// process.
///
/// The `K` marker says where the credentials live, and so which durable
/// step compiles. A keyring sign-in moves to `durable(dir)`, a stored
/// sign-in to `durable(dir, key_store)`, and a held credential to the
/// latter, because it names no keyring.
pub struct NativeSignedIn<T: Transport, C, K: StorageMarker> {
    base: Base<T, C>,
    kind: SignInKind,
    storage: K,
}

impl<T, C, K> NativeSignedIn<T, C, K>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    C: AttachContent<T>,
    K: StorageMarker,
{
    /// Connect signed in, in memory.
    ///
    /// The credential signs the login and names the replica, and the token
    /// source rides every reconnect. The replica is in process, so the
    /// custody is `Ephemeral` whatever the stores claim.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a sign-in, dial, database, or handshake failure.
    pub async fn connect(self) -> Result<NativeClient<T, C::Handle>, ClientError> {
        let (client, pump) = self.connect_with_pump().await?;
        tokio::spawn(pump);
        Ok(client)
    }

    /// Like [`connect`](Self::connect), but the pump future comes back for
    /// the application to drive on its own executor.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a sign-in, dial, database, or handshake failure.
    pub async fn connect_with_pump(
        self,
    ) -> Result<(NativeClient<T, C::Handle>, CorePump), ClientError> {
        let (core, resolved) = self.into_core().await?;
        let (core, pump) = core.connect_with_pump().await?;
        #[cfg(not(feature = "native-auth"))]
        let _ = resolved;
        Ok((
            NativeClient {
                core,
                #[cfg(feature = "native-auth")]
                session: resolved.provider.map(|(session, _)| session),
                #[cfg(feature = "native-auth")]
                teardown: None,
            },
            pump,
        ))
    }

    /// The core signed-in stage this build is, once its sign-in resolved,
    /// beside the provider session behind it.
    async fn into_core(self) -> Result<(CoreSignedIn<T, C>, Resolved), ClientError> {
        // The refresh token is durable even when the replica is not, so the
        // keyring keeps it gated. No re-check runs without a durable stage.
        let _ = self.storage.arm_gate(true)?;
        let resolved = resolve_sign_in(self.kind, &self.storage).await?;
        let core = CoreSignedIn {
            base: self.base,
            credential: resolved.credential.clone(),
        };
        Ok((core, resolved))
    }
}

#[cfg(feature = "native-auth")]
impl<T, C> NativeSignedIn<T, C, Keyring>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    C: AttachContent<T>,
{
    /// Move to the durable stage, the keyring services still named by the
    /// app id the sign-in was forked with.
    ///
    /// A keyring sign-in cannot take a key store, because the service already
    /// names it.
    ///
    /// ```compile_fail
    /// # use connetto_client::{Auth, MemoryKeyStore, NativeClientBuilder, SyncSchema};
    /// # use connetto_core::schema::SchemaBundle;
    /// # let bundle = SchemaBundle::new(
    /// #     "SCHEMA", "POLICIES", "DDL",
    /// #     Vec::<(String, String)>::new(),
    /// #     Vec::<String>::new(),
    /// #     None::<&str>,
    /// # );
    /// let builder = NativeClientBuilder::new(
    ///     "wss://sync.example.com",
    ///     SyncSchema::new(bundle),
    /// );
    /// let signed_in = builder.signed_in(
    ///     Auth::new("https://auth.example.com", "github").keyring("my-app"),
    /// );
    /// signed_in.durable("/data", MemoryKeyStore::default());
    /// ```
    #[must_use]
    pub fn durable(
        self,
        data_dir: impl Into<PathBuf>,
    ) -> NativeDurable<T, C, Keyring, KeyringKeyStore> {
        let key_store = KeyringKeyStore::new(self.storage.app_id.clone());
        NativeDurable {
            base: self.base,
            kind: self.kind,
            storage: self.storage,
            data_dir: data_dir.into(),
            key_store,
            gate: Gate::default(),
            mechanism: None,
        }
    }
}

impl<T, C> NativeSignedIn<T, C, NoKeyring>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    C: AttachContent<T>,
{
    /// Move to the durable stage, naming the replica-key store the build
    /// will use.
    ///
    /// A stored sign-in cannot name its key store itself, so the durable
    /// step takes one.
    ///
    /// ```compile_fail
    /// # use connetto_client::{Auth, MemoryRefreshStore, NativeClientBuilder, SyncSchema};
    /// # use connetto_core::schema::SchemaBundle;
    /// # let bundle = SchemaBundle::new(
    /// #     "SCHEMA", "POLICIES", "DDL",
    /// #     Vec::<(String, String)>::new(),
    /// #     Vec::<String>::new(),
    /// #     None::<&str>,
    /// # );
    /// let builder = NativeClientBuilder::new(
    ///     "wss://sync.example.com",
    ///     SyncSchema::new(bundle),
    /// );
    /// let signed_in = builder.signed_in(
    ///     Auth::new("https://auth.example.com", "github")
    ///         .refresh_store(MemoryRefreshStore::default()),
    /// );
    /// signed_in.durable("/data");
    /// ```
    #[must_use]
    pub fn durable<KS>(
        self,
        data_dir: impl Into<PathBuf>,
        key_store: KS,
    ) -> NativeDurable<T, C, NoKeyring, KS>
    where
        KS: ReplicaKeyStore<Error = ClientError> + Send + Sync + 'static,
    {
        NativeDurable {
            base: self.base,
            kind: self.kind,
            storage: self.storage,
            data_dir: data_dir.into(),
            key_store,
            gate: Gate::default(),
            mechanism: None,
        }
    }
}

/// The durable stage, a replica file under a key beside a content
/// directory, gated on the away input when the gate is on.
///
/// Only this stage has the data directory, the key store and the gate,
/// because a build that names a file names its key and its lock together.
pub struct NativeDurable<T: Transport, C, K: StorageMarker, KS> {
    base: Base<T, C>,
    kind: SignInKind,
    storage: K,
    data_dir: PathBuf,
    key_store: KS,
    gate: Gate,
    mechanism: Option<Arc<dyn GateMechanism>>,
}

/// A data directory, the native place of a durable replica.
///
/// The replica file is the name under the directory, and its content lives
/// in the directory `teardown::content_dir` derives from that file, which is
/// where every teardown primitive looks for it.
#[derive(Debug, Clone)]
pub struct DataDir(PathBuf);

impl DataDir {
    /// The data directory at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }
}

impl ReplicaPlace for DataDir {
    fn locate(&self, name: &str) -> Result<Located, ClientError> {
        let path = self.0.join(name);
        let url = path
            .to_str()
            .ok_or_else(|| ClientError::Session("the replica path is not valid UTF-8".to_owned()))?
            .to_owned();
        Ok(Located::new(
            name,
            url,
            path.exists(),
            ContentPlace::Durable(content_dir(&path)),
        ))
    }
}

impl<T, C, K, KS> NativeDurable<T, C, K, KS>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    C: AttachContent<T>,
    K: StorageMarker,
    KS: ReplicaKeyStore<Error = ClientError> + Send + Sync + 'static,
{
    /// The away-and-return gate, on by default.
    #[must_use]
    pub fn with_gate(mut self, gate: Gate) -> Self {
        self.gate = gate;
        self
    }

    /// The mechanism the gate's lock and ask ride on, in place of the one the
    /// platform keyring supplies. The seam a key store the application names
    /// gates through, and the one tests use to approve or dismiss a check.
    #[must_use]
    pub fn with_gate_mechanism(mut self, mechanism: impl GateMechanism + 'static) -> Self {
        self.mechanism = Some(Arc::new(mechanism));
        self
    }

    /// Connect with the durable replica.
    ///
    /// The build loads the replica key the store holds under the replica
    /// name, or provisions it on a fresh run, opens the file under the
    /// device-private tier when the build has one, and attaches content at
    /// the directory beside the file on the same root key. The custody is
    /// the weakest of the stores' claims, `Verified` when the platform's
    /// keyring holds the secrets behind its user verification.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a sign-in, key, dial, database, or handshake
    /// failure, and when the file exists but its key cannot be loaded.
    pub async fn connect(self) -> Result<NativeClient<T, C::Handle>, ClientError> {
        let (client, pump) = self.connect_with_pump().await?;
        tokio::spawn(pump);
        Ok(client)
    }

    /// Like [`connect`](Self::connect), but the pump future comes back for
    /// the application to drive on its own executor.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a sign-in, key, dial, database, or handshake
    /// failure.
    pub async fn connect_with_pump(
        self,
    ) -> Result<(NativeClient<T, C::Handle>, CorePump), ClientError> {
        let (core, resolved, key_store) = self.into_core().await?;
        #[cfg(feature = "native-auth")]
        let (session, teardown) = {
            let name = resolved.credential.replica_name().to_owned();
            let (session, authenticator) = resolved.provider.unzip();
            let teardown: Box<dyn Forget> = Box::new(ReplicaTeardown {
                authenticator,
                path: core.place.0.join(&name),
                name,
                key_store,
            });
            (session, Some(teardown))
        };
        #[cfg(not(feature = "native-auth"))]
        let _ = (resolved, key_store);
        let (core, pump) = core.connect_with_pump().await?;
        Ok((
            NativeClient {
                core,
                #[cfg(feature = "native-auth")]
                session,
                #[cfg(feature = "native-auth")]
                teardown,
            },
            pump,
        ))
    }

    /// The core durable stage this build is, once its sign-in resolved,
    /// beside the provider session behind it and the key store the core
    /// shares with the client's teardown.
    async fn into_core(
        self,
    ) -> Result<
        (
            CoreDurable<T, C, SharedKeys<KS>, DataDir>,
            Resolved,
            Arc<KS>,
        ),
        ClientError,
    > {
        // The platform's own mechanism, when the storage has one, gates the
        // secrets before the sign-in first touches them. A mechanism the
        // application named takes its place.
        let platform = self.storage.arm_gate(self.gate.on())?;
        let mechanism = self.mechanism.or(platform);
        let resolved = resolve_sign_in(self.kind, &self.storage).await?;
        let claims = self
            .storage
            .refresh_store()
            .map(|store| store.protection())
            .into_iter()
            .collect();
        let key_store = Arc::new(self.key_store);
        let core = CoreDurable {
            base: self.base,
            credential: resolved.credential.clone(),
            place: DataDir(self.data_dir),
            key_store: SharedKeys(Arc::clone(&key_store)),
            claims,
            gate: self.gate,
            mechanism,
        };
        Ok((core, resolved, key_store))
    }
}

/// A running native connetto client.
///
/// The platform-neutral client a build's terminal returns, with what the
/// native sign-in and the data directory add to it. A provider sign-in
/// reports its session, and a durable build can forget the device it wrote
/// to, with the stores and the authenticator the build itself chose.
pub struct NativeClient<T: Transport, C = ()> {
    core: CoreClient<T, C>,
    #[cfg(feature = "native-auth")]
    session: Option<NativeSession>,
    #[cfg(feature = "native-auth")]
    teardown: Option<Box<dyn Forget>>,
}

impl<T, C> NativeClient<T, C>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
{
    /// The shared client.
    #[must_use]
    pub fn client(&self) -> &ConnettoClient<T> {
        self.core.client()
    }

    /// The content handle, when the build named content.
    #[must_use]
    pub fn content(&self) -> Option<&C> {
        self.core.content()
    }

    /// How the key protecting this client's data is held.
    #[must_use]
    pub fn custody(&self) -> Custody {
        self.core.custody()
    }

    /// End the pump and close the transport while the clones stay alive.
    pub async fn close(&self) {
        self.core.close().await;
    }
}

#[cfg(feature = "native-auth")]
impl<T, C> NativeClient<T, C>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
{
    /// The provider session this client signed in with, absent for an
    /// anonymous build or a held credential.
    #[must_use]
    pub fn session(&self) -> Option<&NativeSession> {
        self.session.as_ref()
    }

    /// Revoke the session, destroy the replica key and delete the replica,
    /// its tier and its content.
    ///
    /// Writes the server has not acknowledged block the wipe unless `force`
    /// is set, and they are read before anything is destroyed, since once
    /// the credential is gone they can no longer be uploaded. A held
    /// credential has no session to revoke, so its build only wipes. The
    /// client is closed and its replica swapped for an empty in-memory one
    /// before the files go, since Windows refuses to delete an open file, so
    /// clones still alive read an empty replica. The application drops it
    /// afterwards.
    ///
    /// # Errors
    ///
    /// [`ForgetError::NoReplica`] for a build that kept nothing on the
    /// device, [`ForgetError::Client`] when the unsynced writes cannot be
    /// read, [`ForgetError::Purge`] when the guard refuses or the wipe fails,
    /// and [`ForgetError::NotRevoked`] when the wipe succeeded but the server
    /// was not reached.
    pub async fn forget_device(&self, force: bool) -> Result<(), ForgetError> {
        let teardown = self.teardown.as_ref().ok_or(ForgetError::NoReplica)?;
        let unsynced = self.core.client().unsynced().await?;
        if !unsynced.is_empty() && !force {
            return Err(ForgetError::Purge(PurgeError::Unsynced(unsynced)));
        }
        self.core.close().await;
        self.core.client().release_replica().await?;
        teardown.forget(&unsynced, force).await
    }
}

/// The session a provider sign-in acquired.
#[cfg(feature = "native-auth")]
pub struct NativeSession {
    user_id: String,
    account: String,
    expires_at: std::time::SystemTime,
    accounts: Vec<String>,
}

#[cfg(feature = "native-auth")]
impl NativeSession {
    /// The signed-in user id, as the server minted it.
    #[must_use]
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// The account key the refresh store keeps this identity under, which
    /// [`AccountChoice::Account`] takes.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// When the local session lapses if it is never refreshed again.
    #[must_use]
    pub const fn expires_at(&self) -> std::time::SystemTime {
        self.expires_at
    }

    /// Every account the refresh store held a credential for when the build
    /// signed in, this one among them. A change of account builds again, so
    /// the list cannot go stale under a running client.
    #[must_use]
    pub fn accounts(&self) -> &[String] {
        &self.accounts
    }
}

/// The wipe a durable build knows how to run, erased over its key store.
#[cfg(feature = "native-auth")]
trait Forget: Send + Sync {
    fn forget<'a>(
        &'a self,
        unsynced: &'a [u64],
        force: bool,
    ) -> core::pin::Pin<Box<dyn Future<Output = Result<(), ForgetError>> + Send + 'a>>;
}

/// The replica a durable build wrote, and what revokes its session.
#[cfg(feature = "native-auth")]
struct ReplicaTeardown<KS> {
    authenticator: Option<Arc<NativeAuthenticator>>,
    path: PathBuf,
    name: String,
    key_store: Arc<KS>,
}

#[cfg(feature = "native-auth")]
impl<KS> Forget for ReplicaTeardown<KS>
where
    KS: ReplicaKeyStore<Error = ClientError> + Send + Sync + 'static,
{
    fn forget<'a>(
        &'a self,
        unsynced: &'a [u64],
        force: bool,
    ) -> core::pin::Pin<Box<dyn Future<Output = Result<(), ForgetError>> + Send + 'a>> {
        Box::pin(async move {
            match &self.authenticator {
                Some(authenticator) => {
                    forget_device(
                        authenticator,
                        &self.path,
                        self.key_store.as_ref(),
                        &self.name,
                        unsynced,
                        force,
                    )
                    .await
                }
                None => wipe_replica(
                    &self.path,
                    self.key_store.as_ref(),
                    &self.name,
                    unsynced,
                    force,
                )
                .await
                .map_err(ForgetError::from),
            }
        })
    }
}

/// A key store the build and the client's teardown both hold.
struct SharedKeys<KS>(Arc<KS>);

impl<KS> ReplicaKeyStore for SharedKeys<KS>
where
    KS: ReplicaKeyStore<Error = ClientError> + Send + Sync + 'static,
{
    type Error = ClientError;

    fn load(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<ReplicaKey>, ClientError>> + MaybeSend {
        self.0.load(name)
    }

    fn store(
        &self,
        name: &str,
        key: &ReplicaKey,
    ) -> impl Future<Output = Result<(), ClientError>> + MaybeSend {
        self.0.store(name, key)
    }

    fn clear(&self, name: &str) -> impl Future<Output = Result<(), ClientError>> + MaybeSend {
        self.0.clear(name)
    }

    fn protection(&self) -> Custody {
        self.0.protection()
    }
}

/// A resolved sign-in, the credential beside the provider session behind it
/// when there is one.
struct Resolved {
    credential: HeldCredential,
    #[cfg(feature = "native-auth")]
    provider: Option<(NativeSession, Arc<NativeAuthenticator>)>,
}

impl<T: Transport, C> NativeClient<T, C> {
    /// A client with no session and nothing to forget.
    fn bare(core: CoreClient<T, C>) -> Self {
        Self {
            core,
            #[cfg(feature = "native-auth")]
            session: None,
            #[cfg(feature = "native-auth")]
            teardown: None,
        }
    }
}

/// Resolve a sign-in into the credential it signs in with.
#[expect(
    clippy::manual_async_fn,
    reason = "the provider await is native-auth only, so an `async fn` trips `unused_async` in a native-transport-only build"
)]
fn resolve_sign_in<K: StorageMarker>(
    kind: SignInKind,
    storage: &K,
) -> impl Future<Output = Result<Resolved, ClientError>> + '_ {
    async move {
        match kind {
            SignInKind::Held(credential) => Ok(Resolved {
                credential,
                #[cfg(feature = "native-auth")]
                provider: None,
            }),
            #[cfg(feature = "native-auth")]
            provider @ SignInKind::Provider { .. } => {
                resolve_provider_sign_in(provider, storage).await
            }
            #[cfg(not(feature = "native-auth"))]
            SignInKind::Provider { .. } => {
                let _ = storage;
                Err(ClientError::Auth(
                    "a provider sign-in needs the native-auth feature".to_owned(),
                ))
            }
        }
    }
}

/// The provider half of [`resolve_sign_in`], native-auth only.
#[cfg(feature = "native-auth")]
async fn resolve_provider_sign_in<K: StorageMarker>(
    kind: SignInKind,
    storage: &K,
) -> Result<Resolved, ClientError> {
    let SignInKind::Provider {
        origin,
        login_origin,
        provider,
        account,
        chooser,
        opener,
        claimed,
    } = kind
    else {
        return Err(ClientError::Auth(
            "a held credential is not a provider sign-in".to_owned(),
        ));
    };
    let store = storage
        .refresh_store()
        .ok_or_else(|| ClientError::Auth("a provider sign-in names no refresh store".to_owned()))?;
    let account = match account {
        AccountChoice::LastUsed => remembered_account(store.as_ref()).await?,
        AccountChoice::Account(name) => Some(name),
        AccountChoice::New => None,
        AccountChoice::Ask => {
            let chooser = chooser.ok_or_else(|| {
                ClientError::Auth("the account choice is Ask but no chooser is set".to_owned())
            })?;
            match chooser(store.accounts().await?).await {
                AccountChoice::LastUsed => remembered_account(store.as_ref()).await?,
                AccountChoice::Account(name) => Some(name),
                AccountChoice::New => None,
                AccountChoice::Ask => {
                    return Err(ClientError::Auth(
                        "the chooser answered Ask, which is not an answer".to_owned(),
                    ));
                }
            }
        }
    };
    let mut authenticator = NativeAuthenticator::new(origin, provider, Arc::clone(&store), account)
        .with_login_base(login_origin);
    if let Some(opener) = opener {
        authenticator = authenticator.with_browser_opener(opener);
    }
    if let Some((uri, session)) = claimed {
        authenticator = authenticator.with_claimed_redirect(uri, session);
    }
    let authenticator = Arc::new(authenticator);
    let session = authenticator.acquire::<String>().await?;
    let credential = HeldCredential::new(Grant::new(session.access_token), &session.user_id)?
        .with_token_source(authenticator.token_source());
    let native = NativeSession {
        account: encode_identity(&session.user_id)?,
        user_id: session.user_id,
        expires_at: session.session_expires_at,
        accounts: store.accounts().await?,
    };
    Ok(Resolved {
        credential,
        provider: Some((native, authenticator)),
    })
}
