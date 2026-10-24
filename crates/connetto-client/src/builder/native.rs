//! The native builders and the client they produce.
//!
//! The native layer is the core builder with its dialing and sign-in
//! resolved to the platform's, a built-in dialer over the server URL, the
//! provider sign-in forked into its keyring stores, and a spawn that the
//! platform's runtime owns. Everything the build composes rides the core.

use std::fmt::Display;
#[cfg(feature = "peer")]
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use connetto_core::auth::CapabilityKey;
use connetto_core::auth::CapabilitySubject;
use connetto_core::messages::Grant;
use connetto_core::traits::{MaybeSend, ReplicaKeyStore, Transport};
use connetto_core::{DialError, NativeStream, WebSocketTransport, dial};

use crate::GateMechanism;
#[cfg(feature = "peer")]
use crate::PeerError;
use crate::TransportFactory;
#[cfg(feature = "native-auth")]
use crate::auth::{KeyringKeyStore, NativeAuthenticator, remembered_account};
use crate::builder::content::{AttachContent, ContentPlace};
use crate::builder::core::{
    Base, BoxedDialer, ClientBuilder, CoreClient, CoreDurable, CorePump, CoreSignedIn, DialFailure,
    Located, ReplicaPlace, base_setters,
};
use crate::builder::gate::Gate;
use crate::builder::schema::SyncSchema;
#[cfg(feature = "native-auth")]
use crate::builder::sign_in::{AccountChoice, Keyring};
use crate::builder::sign_in::{
    Held, HeldCredential, NativeSignIn, NoKeyring, SignInKind, StorageMarker,
};
use crate::builder::tuning::SyncTuning;
use crate::cipher::ReplicaKey;
#[cfg(feature = "peer")]
use crate::enrolment::Peer;
#[cfg(feature = "device-identity")]
use crate::enrolment::{CertificateError, DeviceKeys, EnrolHandle, Enroller, PlatformKeys};
use crate::reconnect::ReconnectPolicy;
#[cfg(feature = "native-auth")]
use crate::replica::encode_identity;
#[cfg(feature = "native-auth")]
use crate::share_keys::share_key_record;
use crate::share_keys::{ErasedShareKeyStore, RefreshStoreShareKeys, ShareKeyStore};
use crate::teardown::content_dir;
#[cfg(feature = "native-auth")]
use crate::teardown::{ForgetError, PurgeError, forget_device, wipe_replica};
use crate::{ClientError, ConnettoClient, Custody};
#[cfg(feature = "peer")]
use crate::{ClientEvent, HotspotError, HotspotOffer, JoinError};
#[cfg(feature = "peer")]
use connetto_core::device_cert::AttestationLevel;
#[cfg(feature = "device-identity")]
use connetto_core::device_cert::{DeviceCertificate, DeviceDescriptor, KeyHome};
#[cfg(feature = "peer")]
use tokio::sync::mpsc;

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
/// #     "-- connetto:major 1", "POLICIES", "DDL",
/// #     Vec::<(String, String)>::new(),
/// #     Vec::<String>::new(),
/// #     None::<&str>,
/// # ).expect("the source declares major 1");
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
/// #     "-- connetto:major 1", "POLICIES", "DDL",
/// #     Vec::<(String, String)>::new(),
/// #     Vec::<String>::new(),
/// #     None::<&str>,
/// # ).expect("the source declares major 1");
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
/// #     "-- connetto:major 1", "POLICIES", "DDL",
/// #     Vec::<(String, String)>::new(),
/// #     Vec::<String>::new(),
/// #     None::<&str>,
/// # ).expect("the source declares major 1");
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
    /// #     "-- connetto:major 1", "POLICIES", "DDL",
    /// #     Vec::<(String, String)>::new(),
    /// #     Vec::<String>::new(),
    /// #     None::<&str>,
    /// # ).expect("the source declares major 1");
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
/// sign-in to `durable(dir, key_store)`, and a held credential to
/// `durable(dir, key_store, share_key_store)`, because it names no keyring.
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
                #[cfg(feature = "device-identity")]
                device: None,
                #[cfg(feature = "peer")]
                beacon: None,
                #[cfg(feature = "peer")]
                nearby: None,
                #[cfg(feature = "peer")]
                bt_state: None,
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
    /// #     "-- connetto:major 1", "POLICIES", "DDL",
    /// #     Vec::<(String, String)>::new(),
    /// #     Vec::<String>::new(),
    /// #     None::<&str>,
    /// # ).expect("the source declares major 1");
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
            share_key_store: None,
            gate: Gate::default(),
            mechanism: None,
            #[cfg(feature = "device-identity")]
            device: DeviceSetup::default(),
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
    /// #     "-- connetto:major 1", "POLICIES", "DDL",
    /// #     Vec::<(String, String)>::new(),
    /// #     Vec::<String>::new(),
    /// #     None::<&str>,
    /// # ).expect("the source declares major 1");
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
            share_key_store: None,
            gate: Gate::default(),
            mechanism: None,
            #[cfg(feature = "device-identity")]
            device: DeviceSetup::default(),
        }
    }
}

impl<T, C> NativeSignedIn<T, C, Held>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    C: AttachContent<T>,
{
    /// Move to the durable stage, naming the replica-key store and the
    /// share-key store the build will use.
    ///
    /// A held credential names no keyring, so the durable step takes both
    /// stores itself, and the share-key store persists the build's share
    /// keys beside its other records.
    #[must_use]
    pub fn durable<KS, SS>(
        self,
        data_dir: impl Into<PathBuf>,
        key_store: KS,
        share_key_store: SS,
    ) -> NativeDurable<T, C, Held, KS>
    where
        KS: ReplicaKeyStore<Error = ClientError> + Send + Sync + 'static,
        SS: ShareKeyStore<Error = ClientError> + Send + Sync + 'static,
    {
        let share_key_store: Option<ErasedShareKeyStore> = Some(Arc::new(share_key_store));
        NativeDurable {
            base: self.base,
            kind: self.kind,
            storage: self.storage,
            data_dir: data_dir.into(),
            key_store,
            share_key_store,
            gate: Gate::default(),
            mechanism: None,
            #[cfg(feature = "device-identity")]
            device: DeviceSetup::default(),
        }
    }
}

/// The durable stage, a replica file under a key beside its share keys and
/// a content directory, gated on the away input when the gate is on.
///
/// Only this stage has the data directory, the key store and the gate,
/// because a build that names a file names its key, its keys and its lock
/// together.
pub struct NativeDurable<T: Transport, C, K: StorageMarker, KS> {
    base: Base<T, C>,
    kind: SignInKind,
    storage: K,
    data_dir: PathBuf,
    key_store: KS,
    /// The share-key store the build named, if it named one, the refresh
    /// store standing in for it otherwise.
    share_key_store: Option<ErasedShareKeyStore>,
    gate: Gate,
    mechanism: Option<Arc<dyn GateMechanism>>,
    #[cfg(feature = "device-identity")]
    device: DeviceSetup,
}

/// What a keyring build enrols its device key with (R74).
#[cfg(feature = "device-identity")]
#[cfg_attr(
    feature = "peer",
    expect(
        clippy::struct_excessive_bools,
        reason = "autolink, scan, autojoin and prompt are independent switches the application sets one by one"
    )
)]
struct DeviceSetup {
    lifetime: Option<core::time::Duration>,
    descriptor: Vec<u8>,
    refused: Option<String>,
    roots: Vec<Vec<u8>>,
    #[cfg(feature = "peer")]
    peer_autolink: bool,
    #[cfg(feature = "peer")]
    peer_listen: SocketAddr,
    #[cfg(feature = "peer")]
    peer_accepted: Vec<AttestationLevel>,
    #[cfg(feature = "peer")]
    bt_scan: bool,
    #[cfg(feature = "peer")]
    bt_autojoin: bool,
    #[cfg(feature = "peer")]
    bt_prompt: bool,
    #[cfg(target_os = "android")]
    java: Option<Arc<dyn crate::device_key::JavaAccess>>,
}

#[cfg(feature = "device-identity")]
impl Default for DeviceSetup {
    /// No descriptor is `()`, which a deployment naming none decodes.
    fn default() -> Self {
        Self {
            lifetime: None,
            descriptor: rmp_serde::to_vec_named(&()).unwrap_or_default(),
            refused: None,
            roots: Vec::new(),
            #[cfg(feature = "peer")]
            peer_autolink: true,
            #[cfg(feature = "peer")]
            peer_listen: SocketAddr::from(([0, 0, 0, 0], 0)),
            #[cfg(feature = "peer")]
            peer_accepted: AttestationLevel::ALL.to_vec(),
            #[cfg(feature = "peer")]
            bt_scan: true,
            #[cfg(feature = "peer")]
            bt_autojoin: false,
            #[cfg(feature = "peer")]
            bt_prompt: true,
            #[cfg(target_os = "android")]
            java: None,
        }
    }
}

/// The largest descriptor the server accepts.
#[cfg(feature = "device-identity")]
const DESCRIPTOR_LIMIT: usize = 4096;

#[cfg(feature = "device-identity")]
impl DeviceSetup {
    /// The account's key on this platform's chip, else in the keyring under `service`.
    fn keys(&self, service: &str, account: &str) -> Result<Arc<dyn DeviceKeys>, ClientError> {
        if let Some(reason) = &self.refused {
            return Err(ClientError::DeviceDescriptor(reason.clone()));
        }
        if self.roots.is_empty() {
            return Err(ClientError::MissingDeploymentRoots);
        }
        if let Some(index) = self
            .roots
            .iter()
            .position(|root| connetto_core::device_cert::certificate_key_id(root).is_err())
        {
            return Err(ClientError::InvalidDeploymentRoot { index });
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let chip = Arc::new(crate::device_key::SecureEnclave);
        #[cfg(target_os = "android")]
        let chip = Arc::new(crate::device_key::AndroidKeystore::new(
            self.java.clone().ok_or(ClientError::MissingJavaAccess)?,
        ));
        #[cfg(target_os = "windows")]
        let chip = Arc::new(crate::device_key::Tpm);
        #[cfg(not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows"
        )))]
        let chip = Arc::new(crate::device_key::NoChip);
        Ok(Arc::new(PlatformKeys {
            chip,
            records: crate::keyring::Keyring::new(service),
            service: service.to_owned(),
            account: account.to_owned(),
        }))
    }
}

#[cfg(feature = "device-identity")]
impl<T, C, KS> NativeDurable<T, C, Keyring, KS>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    C: AttachContent<T>,
    KS: ReplicaKeyStore<Error = ClientError> + Send + Sync + 'static,
{
    /// The lifetime this device's certificate is asked for at enrolment and
    /// renewed at, the server's default (24 hours) unless set. A lifetime over
    /// the server's ceiling is refused, never shortened.
    #[must_use]
    pub fn with_certificate_lifetime(mut self, lifetime: core::time::Duration) -> Self {
        self.device.lifetime = Some(lifetime);
        self
    }

    /// What the lost-device list shows about this device, sent at enrolment
    /// and every renewal in `MessagePack` of at most 4096 bytes. A descriptor that
    /// does not serialize or is larger fails the connect.
    #[must_use]
    pub fn with_device_descriptor<D: DeviceDescriptor>(mut self, descriptor: &D) -> Self {
        match rmp_serde::to_vec_named(descriptor) {
            Ok(bytes) if bytes.len() <= DESCRIPTOR_LIMIT => {
                self.device.descriptor = bytes;
                self.device.refused = None;
            }
            Ok(bytes) => {
                self.device.refused = Some(format!(
                    "{} bytes, over the {DESCRIPTOR_LIMIT} the server accepts",
                    bytes.len()
                ));
            }
            Err(err) => self.device.refused = Some(err.to_string()),
        }
        self
    }

    /// The DER roots of the deployment, shipped with the application, which
    /// every certificate this device receives and every revocation list must
    /// chain to (decisions 3 and 23). A build with a device identity that
    /// names none fails to connect. Several roots carry a root rollover.
    #[must_use]
    pub fn with_deployment_roots(mut self, roots: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.device.roots = roots.into_iter().collect();
        self
    }

    /// The address this device's peer listener binds, every interface on a
    /// system-chosen port by default (R76 decision 6).
    #[cfg(feature = "peer")]
    #[must_use]
    pub fn with_peer_listener(mut self, listen: SocketAddr) -> Self {
        self.device.peer_listen = listen;
        self
    }

    /// Whether this device dials the peers discovery finds, on by default
    /// (R76 decision 12).
    #[cfg(feature = "peer")]
    #[must_use]
    pub fn with_peer_autolink(mut self, autolink: bool) -> Self {
        self.device.peer_autolink = autolink;
        self
    }

    /// The attestation levels this device accepts from its peers, all three
    /// by default (R76 decision 8).
    #[cfg(feature = "peer")]
    #[must_use]
    pub fn with_peer_accepted_attestation(
        mut self,
        accepted: impl IntoIterator<Item = AttestationLevel>,
    ) -> Self {
        self.device.peer_accepted = accepted.into_iter().collect();
        self
    }

    /// Whether the device scans for nearby hosts in the background, on by
    /// default (R76 decision 19).
    #[cfg(feature = "peer")]
    #[must_use]
    pub fn with_hotspot_scan(mut self, scan: bool) -> Self {
        self.device.bt_scan = scan;
        self
    }

    /// Whether the device joins the strongest host it sees, off by default
    /// (R76 decision 19). Implies the scan.
    #[cfg(feature = "peer")]
    #[must_use]
    pub fn with_hotspot_autojoin(mut self, autojoin: bool) -> Self {
        self.device.bt_autojoin = autojoin;
        if autojoin {
            self.device.bt_scan = true;
        }
        self
    }

    /// Whether the call-driven Bluetooth prompts run, on by default (R76
    /// decision 21).
    #[cfg(feature = "peer")]
    #[must_use]
    pub fn with_bluetooth_prompt(mut self, prompt: bool) -> Self {
        self.device.bt_prompt = prompt;
        self
    }

    /// The JNI access the Android Keystore key needs, which an Android build
    /// with a device identity must hand in (decision 20).
    /// `connetto_auth_session::java_access()` is one for a Dioxus application.
    #[cfg(target_os = "android")]
    #[must_use]
    pub fn with_java_access(mut self, java: Arc<dyn crate::device_key::JavaAccess>) -> Self {
        self.device.java = Some(java);
        self
    }
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
    #[expect(
        clippy::too_many_lines,
        reason = "the device-identity, native-auth and peer seams each add their cfg-forked block"
    )]
    pub async fn connect_with_pump(
        self,
    ) -> Result<(NativeClient<T, C::Handle>, CorePump), ClientError> {
        #[cfg(feature = "device-identity")]
        let mut this = self;
        #[cfg(not(feature = "device-identity"))]
        let this = self;
        #[cfg(feature = "device-identity")]
        let (device, service) = (
            core::mem::take(&mut this.device),
            this.storage.device_service().map(str::to_owned),
        );
        let (core, resolved, key_store) = this.into_core().await?;
        #[cfg(feature = "device-identity")]
        let keys = service
            .map(|service| device.keys(&service, resolved.credential.replica_name()))
            .transpose()?;
        #[cfg(feature = "native-auth")]
        let (session, teardown) = {
            let name = resolved.credential.replica_name().to_owned();
            let (session, authenticator) = resolved.provider.unzip();
            let share_key_store = core.share_key_store.clone();
            let share_record = share_key_record(&name);
            let teardown: Box<dyn Forget> = Box::new(ReplicaTeardown {
                authenticator,
                path: core.place.0.join(&name),
                name,
                key_store,
                share_key_store,
                share_record,
            });
            (session, Some(teardown))
        };
        #[cfg(not(feature = "native-auth"))]
        let _ = (resolved, key_store);
        let (core, pump) = core.connect_with_pump().await?;
        #[cfg(feature = "peer")]
        let mut beacon: Option<
            tokio::sync::watch::Receiver<crate::bluetooth::BeaconState>,
        > = None;
        #[cfg(feature = "peer")]
        let mut nearby: Option<
            tokio::sync::watch::Receiver<Vec<crate::bluetooth::NearbyHost>>,
        > = None;
        #[cfg(feature = "peer")]
        let mut bt_state: Option<Arc<dyn crate::bluetooth::ReadinessBackend>> = None;
        #[cfg(feature = "device-identity")]
        let (device, pump) = match keys {
            Some(keys) => {
                // Read before the pump runs, so a restarted client reports its
                // certificate from the moment it is handed back.
                let held = core.client().stored_certificate().await?;
                let (kept, lists) = core.client().revocation_inbox().await?;
                #[cfg(feature = "peer")]
                let (peer_events, peer_events_rx) = mpsc::unbounded_channel();
                #[cfg(feature = "peer")]
                let (hotspot_tx, hotspot_rx) = mpsc::unbounded_channel();
                #[cfg(feature = "peer")]
                let (bluetooth_tx, bluetooth_rx) = mpsc::unbounded_channel();
                #[cfg(feature = "peer")]
                let node = connetto_peer::Node::new(
                    connetto_peer::Trust {
                        roots: device.roots.clone(),
                        accepted: device.peer_accepted,
                    },
                    Arc::new(connetto_peer::SystemClock),
                    peer_events,
                )
                .map_err(|connetto_peer::TrustError::Root { index, .. }| {
                    ClientError::InvalidDeploymentRoot { index }
                })?;
                #[cfg(feature = "peer")]
                let (discovery_events, discovery_events_rx) = mpsc::unbounded_channel();
                #[cfg(feature = "peer")]
                let peer_node = node.clone();
                #[cfg(feature = "peer")]
                let peer = Peer {
                    node: node.clone(),
                    discovery: platform_discovery(connetto_peer::Discovery::new(
                        node,
                        device.peer_autolink,
                        discovery_events,
                    )),
                    listen: device.peer_listen,
                    events: peer_events_rx,
                    discovery_events: discovery_events_rx,
                    #[cfg(all(feature = "peer", target_os = "android"))]
                    java: device.java.clone(),
                };
                let (enroller, handle) = Enroller::new(
                    Arc::clone(&keys),
                    device.lifetime,
                    device.descriptor,
                    device.roots,
                    held,
                    kept,
                    lists,
                    #[cfg(feature = "peer")]
                    peer,
                    #[cfg(feature = "peer")]
                    hotspot_tx,
                    #[cfg(feature = "peer")]
                    bluetooth_tx,
                );
                core.client()
                    .with_device_writer(keys, handle.writer_retirement())
                    .await?;
                let enrolment = core.client().enrolment(enroller);
                #[cfg(feature = "peer")]
                let (runner, beacon_rx, nearby_rx, bt_backend) = Box::pin(async {
                    let backend: Arc<dyn crate::hotspot::HotspotBackend> = {
                        #[cfg(target_os = "android")]
                        {
                            match device.java.clone() {
                                Some(java) => {
                                    Arc::new(crate::hotspot::AndroidHotspotBackend::new(java))
                                }
                                None => Arc::new(crate::hotspot::UnsupportedBackend),
                            }
                        }
                        #[cfg(any(target_os = "ios", target_os = "macos"))]
                        {
                            Arc::new(crate::hotspot::AppleHotspotBackend::new())
                        }
                        #[cfg(target_os = "linux")]
                        {
                            match connetto_peer::linux::ZbusNm::new().await {
                                Ok(io) => {
                                    Arc::new(crate::hotspot::LinuxHotspotBackend::new(Arc::new(io)))
                                }
                                Err(err) => {
                                    tracing::warn!(%err, "the system bus did not stand");
                                    Arc::new(crate::hotspot::UnsupportedBackend)
                                }
                            }
                        }
                        #[cfg(not(any(
                            target_os = "android",
                            target_os = "ios",
                            target_os = "linux",
                            target_os = "macos"
                        )))]
                        {
                            Arc::new(crate::hotspot::UnsupportedBackend)
                        }
                    };
                    let port_node = peer_node.clone();
                    #[cfg(target_os = "android")]
                    let bind_node = peer_node.clone();
                    let dial_handle = handle.clone();
                    let event_sender = core.client().event_sender();
                    let event_sender_bt = event_sender.clone();
                    #[cfg(target_os = "android")]
                    let bind = {
                        let java = device.java.clone();
                        Arc::new(
                            move |subnet: Option<(std::net::Ipv4Addr, u8)>| match subnet {
                                Some(subnet) => {
                                    if let Some(java) = &java {
                                        bind_node.set_socket_prep(Some(Arc::new(
                                            crate::hotspot::JoinedBind::new(java.clone(), subnet),
                                        )));
                                    }
                                }
                                None => bind_node.set_socket_prep(None),
                            },
                        )
                    };
                    #[cfg(not(target_os = "android"))]
                    let bind = Arc::new(|_| {});
                    let machine = crate::hotspot::Machine::new(
                        backend,
                        device.peer_autolink,
                        Arc::new(move || port_node.local_addr().map(|addr| addr.port())),
                        bind,
                        Arc::new(
                            move |addr: SocketAddr,
                                  answer: tokio::sync::oneshot::Sender<
                                crate::hotspot::DialAnswer,
                            >| {
                                let handle = dial_handle.clone();
                                tokio::spawn(async move {
                                    let dial = handle.link_peer(addr).await;
                                    let outcome = crate::hotspot::DialAnswer::of(&dial);
                                    if let (crate::hotspot::DialAnswer::Failed, Err(err)) =
                                        (outcome, &dial)
                                    {
                                        tracing::debug!(
                                            %addr,
                                            ?err,
                                            "the dial to the joined hotspot's gateway failed"
                                        );
                                    }
                                    let _ = answer.send(outcome);
                                });
                            },
                        ),
                        Arc::new(move |event: ClientEvent| {
                            let _ = event_sender.send(event);
                        }),
                    );
                    #[cfg(target_os = "android")]
                    let (bt_readiness, bt_peripheral, bt_starter) = match device.java.clone() {
                        Some(java) => {
                            let backend =
                                Arc::new(crate::bluetooth::AndroidBluetoothBackend::new(java));
                            (
                                Arc::clone(&backend) as Arc<dyn crate::bluetooth::ReadinessBackend>,
                                Arc::clone(&backend)
                                    as Arc<dyn crate::bluetooth::PeripheralBackend>,
                                Some(crate::bluetooth::btleplug_starter()),
                            )
                        }
                        None => crate::bluetooth::unsupported_backends(),
                    };
                    #[cfg(any(target_os = "ios", target_os = "macos"))]
                    let (bt_readiness, bt_peripheral, bt_starter) = {
                        let backend = Arc::new(crate::bluetooth::AppleBluetoothBackend::new());
                        (
                            Arc::clone(&backend) as Arc<dyn crate::bluetooth::ReadinessBackend>,
                            Arc::clone(&backend) as Arc<dyn crate::bluetooth::PeripheralBackend>,
                            Some(crate::bluetooth::btleplug_starter()),
                        )
                    };
                    #[cfg(target_os = "linux")]
                    let (bt_readiness, bt_peripheral, bt_starter) = {
                        match connetto_peer::linux::BluerBluez::new().await {
                            Ok(io) => {
                                let backend = Arc::new(
                                    crate::bluetooth::LinuxBluetoothBackend::new(Arc::new(io)),
                                );
                                (
                                    Arc::clone(&backend)
                                        as Arc<dyn crate::bluetooth::ReadinessBackend>,
                                    Arc::clone(&backend)
                                        as Arc<dyn crate::bluetooth::PeripheralBackend>,
                                    Some(crate::bluetooth::btleplug_starter()),
                                )
                            }
                            Err(err) => {
                                tracing::warn!(%err, "the BlueZ session did not stand");
                                crate::bluetooth::unsupported_backends()
                            }
                        }
                    };
                    #[cfg(not(any(
                        target_os = "android",
                        target_os = "ios",
                        target_os = "linux",
                        target_os = "macos"
                    )))]
                    let (bt_readiness, bt_peripheral, bt_starter) =
                        crate::bluetooth::unsupported_backends();
                    let bt_state = Arc::clone(&bt_readiness);
                    let serving_handle = handle.clone();
                    let join_handle = handle.clone();
                    let handed_handle = handle.clone();
                    let beacon_node = peer_node.clone();
                    let bt_machine = crate::bluetooth::Machine::new(
                        bt_readiness,
                        bt_peripheral,
                        bt_starter,
                        beacon_node,
                        device.bt_scan,
                        device.bt_autojoin,
                        device.bt_prompt,
                        Arc::new({
                            let handle = serving_handle;
                            move || handle.peer_serving_fingerprint()
                        }),
                        Arc::new(move |offer, reply| {
                            let handle = join_handle.clone();
                            tokio::spawn(async move {
                                let answer = handle.join_hotspot(&offer).await;
                                let _ = reply.send(answer);
                            });
                        }),
                        Arc::new(move |event: ClientEvent| {
                            let _ = event_sender_bt.send(event);
                        }),
                        Arc::new({
                            let handle = handed_handle;
                            move || handle.personal_offer_handed_out()
                        }),
                    );
                    (
                        crate::bluetooth::run(machine, hotspot_rx, bt_machine.0, bluetooth_rx),
                        bt_machine.1,
                        bt_machine.2,
                        bt_state,
                    )
                })
                .await;
                #[cfg(feature = "peer")]
                let pump: CorePump = Box::pin(with_device_tasks(pump, async move {
                    tokio::join!(enrolment, runner);
                }));
                #[cfg(not(feature = "peer"))]
                let pump: CorePump = Box::pin(with_device_tasks(pump, enrolment));
                #[cfg(feature = "peer")]
                {
                    beacon = Some(beacon_rx);
                    nearby = Some(nearby_rx);
                    bt_state = Some(bt_backend);
                }
                (Some(handle), pump)
            }
            None => (None, pump),
        };
        Ok((
            NativeClient {
                core,
                #[cfg(feature = "native-auth")]
                session,
                #[cfg(feature = "native-auth")]
                teardown,
                #[cfg(feature = "device-identity")]
                device,
                #[cfg(feature = "peer")]
                beacon,
                #[cfg(feature = "peer")]
                nearby,
                #[cfg(feature = "peer")]
                bt_state,
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
        let share_key_store = self
            .share_key_store
            .clone()
            .or_else(|| {
                let store: ErasedShareKeyStore = self
                    .storage
                    .refresh_store()
                    .map(RefreshStoreShareKeys)
                    .map(Arc::new)?;
                Some(store)
            })
            .ok_or_else(|| {
                ClientError::Auth("the durable build named no store for its share keys".to_owned())
            })?;
        let core = CoreDurable {
            base: self.base,
            credential: resolved.credential.clone(),
            place: DataDir(self.data_dir),
            key_store: SharedKeys(Arc::clone(&key_store)),
            share_key_store,
            claims,
            gate: self.gate,
            mechanism,
        };
        Ok((core, resolved, key_store))
    }
}

#[cfg(feature = "device-identity")]
async fn with_device_tasks(mut pump: CorePump, tasks: impl Future<Output = ()>) {
    // Auxiliary tasks retain client handles, so the core pump owns their lifetime.
    tokio::select! {
        () = &mut pump => {}
        () = tasks => pump.await,
    }
}

/// Discovery through the system Bonjour service on iOS, which grants an app no raw multicast, and through `mdns-sd` elsewhere (R76).
#[cfg(feature = "peer")]
fn platform_discovery(discovery: connetto_peer::Discovery) -> connetto_peer::Discovery {
    #[cfg(target_os = "ios")]
    {
        discovery.with_dns_sd(Arc::new(connetto_peer_apple::discovery::Bonjour))
    }
    #[cfg(not(target_os = "ios"))]
    {
        discovery
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
    #[cfg(feature = "device-identity")]
    device: Option<EnrolHandle>,
    #[cfg(feature = "peer")]
    /// The host's beacon standing, for the application's panel (R76).
    beacon: Option<tokio::sync::watch::Receiver<crate::bluetooth::BeaconState>>,
    #[cfg(feature = "peer")]
    /// The nearby hosts' standing, for the application's panel (R76).
    nearby: Option<tokio::sync::watch::Receiver<Vec<crate::bluetooth::NearbyHost>>>,
    #[cfg(feature = "peer")]
    /// The platform's Bluetooth standing, readable at any time (R76).
    bt_state: Option<Arc<dyn crate::bluetooth::ReadinessBackend>>,
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

    /// Close the transport and end enrolment and radio work while client clones remain alive.
    pub async fn close(&self) {
        self.core.close().await;
    }

    /// Ask the server for a certificate at `lifetime` now, replacing the one
    /// this device holds, and renew at that lifetime from then on (R74).
    ///
    /// # Errors
    ///
    /// [`CertificateError::Offline`] with no server reachable,
    /// [`CertificateError::OverCeiling`] for a lifetime the server refuses,
    /// [`CertificateError::Revoked`] when this device's key was revoked, which
    /// deletes it, [`CertificateError::Refused`] for any other refusal, and
    /// [`CertificateError::NoIdentity`] for a build without a device identity.
    #[cfg(feature = "device-identity")]
    pub async fn reissue_certificate(
        &self,
        lifetime: core::time::Duration,
    ) -> Result<(), CertificateError> {
        match &self.device {
            Some(device) => device.reissue(lifetime).await,
            None => Err(CertificateError::NoIdentity),
        }
    }

    /// The certificate this device holds, `None` before its first enrolment
    /// and for a build without a device identity (R74).
    #[cfg(feature = "device-identity")]
    #[must_use]
    pub fn device_certificate(&self) -> Option<DeviceCertificate> {
        self.device.as_ref().and_then(EnrolHandle::certificate)
    }

    /// The account's devices, for the lost-device list, each descriptor read
    /// as the application's `D` (R74 step 5).
    ///
    /// # Errors
    ///
    /// [`CertificateError::Offline`] with no server reachable,
    /// [`CertificateError::Refused`] for a refusal, and
    /// [`CertificateError::NoIdentity`] for a build without a device identity.
    #[cfg(feature = "device-identity")]
    pub async fn devices<D: DeviceDescriptor>(
        &self,
    ) -> Result<Vec<crate::enrolment::DeviceEntry<D>>, CertificateError> {
        match &self.device {
            Some(device) => device.devices().await,
            None => Err(CertificateError::NoIdentity),
        }
    }

    /// Report the account's device holding `key` lost. The server lists its
    /// certificates, closes its connections and revokes its sessions, and a
    /// device reporting itself deletes its own key (R74 step 5).
    ///
    /// # Errors
    ///
    /// [`CertificateError::Offline`] with no server reachable,
    /// [`CertificateError::Refused`] for a key that is not the account's, and
    /// [`CertificateError::NoIdentity`] for a build without a device identity.
    #[cfg(feature = "device-identity")]
    pub async fn revoke_device(
        &self,
        key: connetto_core::device_cert::KeyId,
    ) -> Result<(), CertificateError> {
        match &self.device {
            Some(device) => device.revoke(key).await,
            None => Err(CertificateError::NoIdentity),
        }
    }

    /// Where this device's key lives, a chip or software in the secret
    /// store, once it is open, and `None` for a build without a device
    /// identity (R74 step 2). Reported beside [`custody`](Self::custody) and
    /// never folded into it, since the key sits outside the unlock gate.
    #[cfg(feature = "device-identity")]
    #[must_use]
    pub fn device_key_home(&self) -> Option<KeyHome> {
        self.device.as_ref().and_then(EnrolHandle::key_home)
    }

    /// The address this device's peer listener binds, once the device's
    /// standing serves it, and `None` before that or for a build without a
    /// device identity (R76).
    #[cfg(feature = "peer")]
    #[must_use]
    pub fn peer_address(&self) -> Option<SocketAddr> {
        self.device.as_ref().and_then(EnrolHandle::peer_address)
    }

    /// The peers this device's node reports linked, each with its kept link's
    /// remote address, an empty list without a device (R76).
    #[cfg(feature = "peer")]
    #[must_use]
    pub fn linked_peers(&self) -> Vec<connetto_peer::PeerLink> {
        self.device
            .as_ref()
            .map_or_else(Vec::new, EnrolHandle::linked_peers)
    }

    /// Dial `addr`, refusing by this device's standing before any socket
    /// opens and handing back the peer's identity once the link is live
    /// (R76).
    ///
    /// # Errors
    ///
    /// [`PeerError::NoIdentity`] with no key or certificate, or a build
    /// without a device identity, [`PeerError::CertificateExpired`] with a
    /// certificate past its expiry, which also raises
    /// `ClientEvent::CertificateExpired`, [`PeerError::ClockOutsideWindow`]
    /// with the local clock outside the certificate's window, and
    /// [`PeerError::Link`] for a failed dial.
    #[cfg(feature = "peer")]
    pub async fn link_peer(
        &self,
        addr: SocketAddr,
    ) -> Result<connetto_core::device_cert::DeviceIdentity, PeerError> {
        match &self.device {
            Some(device) => device.link_peer(addr).await,
            None => Err(PeerError::NoIdentity),
        }
    }

    /// Host this device's hotspot, the beacon's outcome beside its details
    /// or the reason it will not, within the machines' bounds (R76).
    ///
    /// # Errors
    ///
    /// [`HotspotError::Unsupported`] on a system without a hotspot or for a
    /// build without a device identity, [`HotspotError::MissingPermission`]
    /// with a permission the device has not granted, the mapped failure from
    /// the device's Wi-Fi manager, and [`HotspotError::TimedOut`] when the
    /// hotspot does not start within its bound. The beacon's refusal stands
    /// beside the offer on the success.
    #[cfg(feature = "peer")]
    pub async fn host_hotspot(&self) -> Result<crate::bluetooth::Hosted, HotspotError> {
        match &self.device {
            Some(device) => device.host_hotspot().await,
            None => Err(HotspotError::Unsupported),
        }
    }

    /// Host this device's personal hotspot under the caller's typed
    /// details, the beacon's outcome beside the offer, within the
    /// machines' bounds (R76 decision 26).
    ///
    /// # Errors
    ///
    /// [`HotspotError::Unsupported`] on a system without a personal
    /// hotspot or for a build without a device identity,
    /// [`HotspotError::Incompatible`] on a model that cannot host, and
    /// [`HotspotError::TimedOut`] when the answer does not stand within
    /// its bound. The beacon's refusal stands beside the offer on the
    /// success.
    #[cfg(feature = "peer")]
    pub async fn host_personal_hotspot(
        &self,
        ssid: &str,
        passphrase: &str,
    ) -> Result<crate::bluetooth::Hosted, HotspotError> {
        match &self.device {
            Some(device) => device.host_personal_hotspot(ssid, passphrase).await,
            None => Err(HotspotError::Unsupported),
        }
    }

    /// The personal hotspot's network name, where the platform answers one
    /// (R76 decision 26).
    #[cfg(feature = "peer")]
    #[must_use]
    pub fn personal_hotspot_name(&self) -> Option<String> {
        #[cfg(target_os = "ios")]
        {
            connetto_peer_apple::device_name()
        }
        #[cfg(not(target_os = "ios"))]
        {
            None
        }
    }

    /// Stop hosting, or cancel the pending request (R76).
    ///
    /// A no-op on a system without a hotspot or for a build without a device
    /// identity.
    #[cfg(feature = "peer")]
    #[expect(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "uniform awaited hotspot API, the command send is synchronous"
    )]
    pub async fn stop_hotspot(&self) {
        if let Some(device) = &self.device {
            device.stop_hotspot();
        }
    }

    /// Join `offer`'s network, answering its gateway or the reason it will
    /// not, within the machine's bound (R76).
    ///
    /// # Errors
    ///
    /// [`JoinError::Unsupported`] on a system without a hotspot or for a
    /// build without a device identity, [`JoinError::MissingPermission`]
    /// with a permission the device has not granted,
    /// [`JoinError::Declined`] when the network is not available, and
    /// [`JoinError::TimedOut`] when the network does not answer within its
    /// bound.
    #[cfg(feature = "peer")]
    pub async fn join_hotspot(&self, offer: &HotspotOffer) -> Result<std::net::IpAddr, JoinError> {
        match &self.device {
            Some(device) => device.join_hotspot(offer).await,
            None => Err(JoinError::Unsupported),
        }
    }

    /// Leave the joined network, or cancel the pending request (R76).
    ///
    /// A no-op on a system without a hotspot or for a build without a device
    /// identity.
    #[cfg(feature = "peer")]
    #[expect(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "uniform awaited hotspot API, the command send is synchronous"
    )]
    pub async fn leave_hotspot(&self) {
        if let Some(device) = &self.device {
            device.leave_hotspot();
        }
    }

    /// The platform's Bluetooth standing, readable at any time (R76
    /// decision 21).
    #[cfg(feature = "peer")]
    #[must_use]
    pub fn bluetooth_state(&self) -> crate::bluetooth::BluetoothState {
        match &self.bt_state {
            Some(backend) => backend.state(),
            None => crate::bluetooth::BluetoothState::Unsupported,
        }
    }

    /// The host's beacon standing, for the application's panel (R76).
    #[cfg(feature = "peer")]
    #[must_use]
    pub fn beacon_state(&self) -> crate::bluetooth::BeaconState {
        match &self.beacon {
            Some(receiver) => receiver.borrow().clone(),
            None => crate::bluetooth::BeaconState::Off {
                reason: "no bluetooth on this system",
            },
        }
    }

    /// The nearby hosts the Bluetooth scan stands on, each with its host
    /// key, beacon prefix and last signal, an empty list without a device
    /// or without Bluetooth (R76).
    #[cfg(feature = "peer")]
    #[must_use]
    pub fn nearby_hosts(&self) -> Vec<crate::bluetooth::NearbyHost> {
        self.nearby
            .as_ref()
            .map_or_else(Vec::new, |receiver| receiver.borrow().clone())
    }

    /// Enable Bluetooth, the platform's action inside the call, within the
    /// machine's bound (R76 decision 21).
    ///
    /// # Errors
    ///
    /// [`BluetoothError::Unsupported`](crate::BluetoothError::Unsupported) for a build without a device
    /// identity, [`BluetoothError::Off`](crate::BluetoothError::Off) or [`BluetoothError::NotPermitted`](crate::BluetoothError::NotPermitted)
    /// with the prompt's outcome once the action declines, and
    /// [`BluetoothError::TimedOut`](crate::BluetoothError::TimedOut) when the action does not finish within
    /// its bound.
    #[cfg(feature = "peer")]
    pub async fn enable_bluetooth(&self) -> Result<(), crate::bluetooth::BluetoothError> {
        match &self.device {
            Some(device) => device.enable_bluetooth().await,
            None => Err(crate::bluetooth::BluetoothError::Unsupported),
        }
    }

    /// Join the nearby host's hotspot through the exchange, answered with
    /// the host's proved identity and the network's gateway, within the
    /// machines' bounds (R76 decisions 19 and 25).
    ///
    /// # Errors
    ///
    /// [`JoinNearbyError::Bluetooth`](crate::JoinNearbyError::Bluetooth) with the Bluetooth reason the exchange
    /// or the platform's action gives, and [`JoinNearbyError::Join`](crate::JoinNearbyError::Join) with the
    /// hotspot's reason the network gives.
    #[cfg(feature = "peer")]
    pub async fn join_nearby(
        &self,
        host: &crate::bluetooth::HostId,
    ) -> Result<
        (connetto_core::device_cert::DeviceIdentity, std::net::IpAddr),
        crate::bluetooth::JoinNearbyError,
    > {
        match &self.device {
            Some(device) => device.join_nearby(host).await,
            None => Err(crate::bluetooth::JoinNearbyError::Bluetooth(
                crate::bluetooth::BluetoothError::Unsupported,
            )),
        }
    }

    /// Fetch the nearby host's offer through the exchange, answered with
    /// the host's proved identity, within the machine's bound (R76
    /// decisions 19 and 25).
    ///
    /// # Errors
    ///
    /// [`BluetoothError::Busy`](crate::BluetoothError::Busy) while an exchange runs,
    /// [`BluetoothError::Exchange`](crate::BluetoothError::Exchange) with the link's reason the host's chain
    /// refuses or the exchange stalls, and
    /// [`BluetoothError::TimedOut`](crate::BluetoothError::TimedOut) at the bound.
    #[cfg(feature = "peer")]
    pub async fn fetch_offer(
        &self,
        host: &crate::bluetooth::HostId,
    ) -> Result<
        (connetto_core::device_cert::DeviceIdentity, HotspotOffer),
        crate::bluetooth::BluetoothError,
    > {
        match &self.device {
            Some(device) => device.fetch_offer(host).await,
            None => Err(crate::bluetooth::BluetoothError::Unsupported),
        }
    }

    /// The scan's standing, at run time (R76 decision 19). A no-op for a
    /// build without a device identity.
    #[cfg(feature = "peer")]
    pub fn set_hotspot_scan(&self, scan: bool) {
        if let Some(device) = &self.device {
            device.set_hotspot_scan(scan);
        }
    }

    /// The autojoin's standing, at run time, implying the scan (R76 decision
    /// 19). A no-op for a build without a device identity.
    #[cfg(feature = "peer")]
    pub fn set_hotspot_autojoin(&self, autojoin: bool) {
        if let Some(device) = &self.device {
            device.set_hotspot_autojoin(autojoin);
        }
    }

    /// The prompt's standing, at run time (R76 decision 21). A no-op for a
    /// build without a device identity.
    #[cfg(feature = "peer")]
    pub fn set_bluetooth_prompt(&self, prompt: bool) {
        if let Some(device) = &self.device {
            device.set_bluetooth_prompt(prompt);
        }
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
    /// read or, once the wipe stands, the device key cannot be deleted,
    /// [`ForgetError::Purge`] when the guard refuses or the wipe fails,
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
        let forgotten = teardown.forget(&unsynced, force).await;
        // The certificate went with the replica, and the key goes once the
        // wipe stands, whether or not the server heard (lifecycle row
        // "`forget_device`").
        #[cfg(feature = "device-identity")]
        if matches!(forgotten, Ok(()) | Err(ForgetError::NotRevoked(_)))
            && let Some(device) = &self.device
        {
            device.delete_key().await?;
        }
        forgotten
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
        unsynced: &'a [crate::UnsyncedWrite],
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
    share_key_store: ErasedShareKeyStore,
    share_record: String,
}

#[cfg(feature = "native-auth")]
impl<KS> Forget for ReplicaTeardown<KS>
where
    KS: ReplicaKeyStore<Error = ClientError> + Send + Sync + 'static,
{
    fn forget<'a>(
        &'a self,
        unsynced: &'a [crate::UnsyncedWrite],
        force: bool,
    ) -> core::pin::Pin<Box<dyn Future<Output = Result<(), ForgetError>> + Send + 'a>> {
        Box::pin(async move {
            let forgotten = match &self.authenticator {
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
            };
            // Local secret cleanup is required even when revocation cannot be confirmed.
            if matches!(forgotten, Ok(()) | Err(ForgetError::NotRevoked(_))) {
                self.share_key_store
                    .clear(&self.share_record)
                    .await
                    .map_err(|err| ForgetError::Purge(PurgeError::KeyStore(err.to_string())))?;
            }
            forgotten
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
            #[cfg(feature = "device-identity")]
            device: None,
            #[cfg(feature = "peer")]
            beacon: None,
            #[cfg(feature = "peer")]
            nearby: None,
            #[cfg(feature = "peer")]
            bt_state: None,
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

#[cfg(all(test, feature = "native-transport", feature = "peer"))]
mod tests {
    use core::future::Future;
    use core::marker::PhantomData;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use connetto_core::device_cert::{AttestationLevel, DeploymentId, RootCa};
    use connetto_core::schema::SchemaBundle;
    use connetto_core::test_support::FakeTransport;
    use connetto_core::traits::{MaybeSend, Transport};
    use tokio::sync::{mpsc, watch};

    use super::NativeClient;
    use crate::bluetooth::{BeaconState, BluetoothState};
    use crate::enrolment::{DeviceKeys, Enroller};
    use crate::{ClientBuilder, Grant, HeldCredential, TransportFactory};

    /// The major line the schema source declares.
    const SOURCE: &str = "-- connetto:major 1";

    /// A schema a test's bundle holds.
    fn bundle() -> crate::SyncSchema {
        crate::SyncSchema::new(
            SchemaBundle::new(
                SOURCE,
                "",
                "CREATE TABLE t (id INTEGER PRIMARY KEY)",
                Vec::<(String, String)>::new(),
                Vec::<String>::new(),
                None::<&str>,
            )
            .expect("the source declares major 1"),
        )
    }

    /// The refusal a dialer that never reaches a server hands back.
    #[derive(Debug, thiserror::Error)]
    #[error("no server is reachable")]
    struct Unreachable;

    /// A dialer that never reaches a server, so a running client stays
    /// offline (R76 slice 5a).
    struct NeverDial<T>(PhantomData<fn() -> T>);

    impl<T> Default for NeverDial<T> {
        fn default() -> Self {
            Self(PhantomData)
        }
    }

    impl<T: Transport + MaybeSend + 'static> TransportFactory for NeverDial<T> {
        type Transport = T;
        type Error = Unreachable;

        fn connect(&mut self) -> impl Future<Output = Result<T, Unreachable>> + MaybeSend {
            core::future::ready(Err(Unreachable))
        }
    }

    /// The credential the tests sign in with.
    fn held(user: &str) -> HeldCredential {
        HeldCredential::new(Grant::new(format!("user:{user}")), user).expect("a held credential")
    }

    /// A device key that stands nowhere, for the build the task runs without
    /// one (R76 slice 5a).
    struct NowhereKeys;

    impl DeviceKeys for NowhereKeys {
        fn open(
            &self,
        ) -> core::pin::Pin<
            Box<
                dyn Future<
                        Output = Result<
                            crate::device_key::OpenedKey<
                                Box<dyn connetto_core::device_cert::DeviceKey>,
                            >,
                            crate::ClientError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                Err(crate::ClientError::Transport(
                    "the test holds no device key".into(),
                ))
            })
        }

        fn delete(
            &self,
        ) -> core::pin::Pin<Box<dyn Future<Output = Result<(), crate::ClientError>> + Send + '_>>
        {
            Box::pin(async { Ok(()) })
        }
    }

    /// The autojoin's standing implies the scan's at the build stage, the
    /// way the runtime's standing does (R76 decision 19).
    #[test]
    fn an_autojoin_standing_implies_the_scan_standing() {
        let builder = super::NativeClientBuilder::new("ws://127.0.0.1:1/", bundle())
            .signed_in(
                crate::Auth::new("http://127.0.0.1:9", "test")
                    .with_account(crate::AccountChoice::New)
                    .keyring("cov-autojoin-implies-scan"),
            )
            .durable(std::env::temp_dir().join("cov-native-builder"))
            .with_hotspot_scan(false)
            .with_hotspot_autojoin(true)
            .with_bluetooth_prompt(false);
        assert!(builder.device.bt_autojoin, "the autojoin stands");
        assert!(builder.device.bt_scan, "the autojoin implies the scan");
        assert!(!builder.device.bt_prompt, "the prompt stands as asked");
    }

    /// A build without a device identity refuses the peer's calls with the
    /// typed reasons the calls document (R76 slice 5a).
    #[tokio::test]
    async fn a_build_without_a_device_identity_refuses_the_peer_calls() {
        let client = super::NativeClientBuilder::new("ws://127.0.0.1:1/", bundle())
            .with_dialer(NeverDial::<FakeTransport>::default())
            .signed_in(held("carol"))
            .connect()
            .await
            .expect("the build opens offline");

        let offer = crate::hotspot::HotspotOffer::new(
            "camp",
            "opensesame",
            crate::hotspot::HotspotSecurity::Wpa2,
            Some(5678),
        );
        assert!(
            matches!(
                client.host_hotspot().await,
                Err(crate::hotspot::HotspotError::Unsupported)
            ),
            "the build has no device identity to host"
        );
        assert!(
            matches!(
                client
                    .host_personal_hotspot("iphone", "the passphrase")
                    .await,
                Err(crate::hotspot::HotspotError::Unsupported)
            ),
            "the build has no device identity to host personally"
        );
        assert!(
            matches!(
                client.join_hotspot(&offer).await,
                Err(crate::hotspot::JoinError::Unsupported)
            ),
            "the build has no device identity to join"
        );
        assert!(
            matches!(
                client.enable_bluetooth().await,
                Err(crate::bluetooth::BluetoothError::Unsupported)
            ),
            "the build has no device identity to enable"
        );
        assert!(
            matches!(
                client.fetch_offer(&3).await,
                Err(crate::bluetooth::BluetoothError::Unsupported)
            ),
            "the build has no device identity to fetch"
        );
        assert!(
            matches!(
                client.join_nearby(&3).await,
                Err(crate::bluetooth::JoinNearbyError::Bluetooth(
                    crate::bluetooth::BluetoothError::Unsupported
                ))
            ),
            "the build has no device identity to join nearby"
        );
        assert_eq!(client.bluetooth_state(), BluetoothState::Unsupported);
        assert!(
            client.personal_hotspot_name().is_none(),
            "no personal hotspot name without the device"
        );
        assert_eq!(
            client.beacon_state(),
            BeaconState::Off {
                reason: "no bluetooth on this system"
            }
        );
        assert!(
            client.peer_address().is_none(),
            "nothing serves without the device"
        );
        assert!(
            client.linked_peers().is_empty(),
            "nothing links without the device"
        );
        assert!(
            client.nearby_hosts().is_empty(),
            "no nearby host without the device"
        );
        assert!(client.device_certificate().is_none());
        assert!(client.device_key_home().is_none());
        let address: std::net::SocketAddr = "127.0.0.1:0".parse().expect("loopback");
        assert!(
            matches!(
                client.link_peer(address).await,
                Err(crate::PeerError::NoIdentity)
            ),
            "the build has no identity to present"
        );

        // The no-ops run without the device.
        client.stop_hotspot().await;
        client.leave_hotspot().await;
        client.set_hotspot_scan(true);
        client.set_hotspot_autojoin(true);
        client.set_bluetooth_prompt(false);

        client.close().await;
    }

    /// A device build hands its hotspot and Bluetooth calls to the machines
    /// and reads their standings, and refuses the peer calls a
    /// certificate-less device cannot take (R76 slice 5a).
    #[expect(
        clippy::too_many_lines,
        reason = "the build, the machines and the calls are one scenario"
    )]
    #[tokio::test]
    async fn a_device_build_hands_its_calls_to_the_machines_and_reads_their_standings() {
        // The core opens offline, the way the signed-in stage does.
        let (core, pump) = ClientBuilder::<FakeTransport>::new(bundle(), NeverDial::default())
            .signed_in(held("carol"))
            .connect_with_pump()
            .await
            .expect("the build opens offline");
        let pump = tokio::spawn(pump);

        // The machines stand in for the platform's, each answering as the
        // platform answers once its radio stands.
        let (hotspot_tx, mut hotspot_rx) = mpsc::unbounded_channel();
        let (bluetooth_tx, mut bluetooth_rx) = mpsc::unbounded_channel();
        let (note_tx, mut note_rx) = mpsc::channel(8);
        // The identity the nearby host proves in the exchange.
        let host = connetto_core::device_cert::DeviceIdentity::new(
            connetto_core::device_cert::DeploymentId::from_uuid(uuid::Uuid::from_u128(7)),
            "host",
            connetto_core::device_cert::KeyId::from_bytes([7; 32]),
        )
        .expect("an identity holds");
        let machine_host = host.clone();
        let machine = tokio::spawn(async move {
            let host = machine_host;
            let gateway: std::net::IpAddr = "192.168.4.1".parse().expect("a private gateway");
            let offer = crate::hotspot::HotspotOffer::new(
                "camp",
                "opensesame",
                crate::hotspot::HotspotSecurity::Wpa2,
                Some(5678),
            );
            loop {
                tokio::select! {
                    command = hotspot_rx.recv() => match command {
                        Some(crate::hotspot::Command::Host(reply)) => {
                            let _ = reply.send(Ok(offer.clone()));
                        }
                        Some(crate::hotspot::Command::Join { reply, .. }) => {
                            let _ = reply.send(Ok(gateway));
                        }
                        Some(crate::hotspot::Command::StopHost) => {
                            let _ = note_tx.send("stop").await;
                        }
                        Some(crate::hotspot::Command::Leave) => {
                            let _ = note_tx.send("leave").await;
                        }
                        // The personal request the runner links stands
                        // unanswered here, and the hand out notes its
                        // arrival.
                        Some(command) => {
                            if matches!(
                                command,
                                crate::hotspot::Command::PersonalOfferHandedOut
                            ) {
                                let _ = note_tx.send("handed out").await;
                            }
                        }
                        None => break,
                    },
                    command = bluetooth_rx.recv() => match command {
                        Some(crate::bluetooth::Command::Enable(reply)) => {
                            let _ = reply.send(Ok(()));
                        }
                        Some(crate::bluetooth::Command::JoinNearby { reply, .. }) => {
                            let _ = reply.send(Ok((host.clone(), gateway)));
                        }
                        Some(crate::bluetooth::Command::Fetch { reply, .. }) => {
                            let _ = reply.send(Ok((host.clone(), offer.clone())));
                        }
                        Some(crate::bluetooth::Command::Host(reply)) => {
                            let _ = reply.send(Ok(crate::bluetooth::Hosted {
                                offer: offer.clone(),
                                beacon: Ok(()),
                            }));
                        }
                        Some(crate::bluetooth::Command::SetScan(on)) => {
                            let _ = note_tx
                                .send(if on { "scan true" } else { "scan false" })
                                .await;
                        }
                        Some(crate::bluetooth::Command::SetAutojoin(on)) => {
                            let _ = note_tx
                                .send(if on { "autojoin true" } else { "autojoin false" })
                                .await;
                        }
                        Some(crate::bluetooth::Command::SetPrompt(on)) => {
                            let _ = note_tx
                                .send(if on { "prompt true" } else { "prompt false" })
                                .await;
                        }
                        // The personal hotspot is the iPhone's, which this test does not host.
                        Some(_) => {}
                        None => break,
                    },
                }
            }
        });

        // The device stands beside the core, the way the durable stage
        // stands it, with the machines' channels in its place.
        let now = SystemTime::now();
        let root = RootCa::create(
            DeploymentId::from_uuid(uuid::Uuid::from_u128(7)),
            now - Duration::from_hours(10),
            Duration::from_hours(3650 * 24),
        )
        .expect("the root issues");
        let root_der = root.certificate().to_vec();
        let (node_events, node_events_rx) = mpsc::unbounded_channel();
        let node = connetto_peer::Node::new(
            connetto_peer::Trust {
                roots: vec![root_der],
                accepted: AttestationLevel::ALL.to_vec(),
            },
            Arc::new(connetto_peer::SystemClock),
            node_events,
        )
        .expect("the roots hold keys");
        let (discovery_events, discovery_events_rx) = mpsc::unbounded_channel();
        let discovery = connetto_peer::Discovery::new(node.clone(), false, discovery_events);
        let peer = crate::enrolment::Peer {
            node,
            discovery,
            listen: "127.0.0.1:0".parse().expect("loopback"),
            events: node_events_rx,
            discovery_events: discovery_events_rx,
        };
        let (enroller, device) = Enroller::new(
            Arc::new(NowhereKeys),
            None,
            Vec::new(),
            vec![],
            None,
            Vec::new(),
            mpsc::unbounded_channel().1,
            peer,
            hotspot_tx,
            bluetooth_tx,
        );
        drop(enroller);
        let (_beacon, beacon_rx) = watch::channel(BeaconState::Advertising { prefix: [7; 8] });
        let (nearby_tx, nearby_rx) = watch::channel(Vec::new());
        nearby_tx.send_replace(vec![crate::bluetooth::NearbyHost {
            host: 9,
            prefix: Some([3; 8]),
            rssi: Some(-55),
        }]);
        let (readiness, _, _) = crate::bluetooth::unsupported_backends();
        let client = NativeClient {
            core,
            #[cfg(feature = "native-auth")]
            session: None,
            #[cfg(feature = "native-auth")]
            teardown: None,
            #[cfg(feature = "device-identity")]
            device: Some(device),
            #[cfg(feature = "peer")]
            beacon: Some(beacon_rx),
            #[cfg(feature = "peer")]
            nearby: Some(nearby_rx),
            #[cfg(feature = "peer")]
            bt_state: Some(readiness),
        };

        // The calls hand back what the machines answer.
        let hosted = client.host_hotspot().await.expect("the machine answers");
        assert_eq!(
            hosted.offer.ssid, "camp",
            "the machine's offer reaches the caller"
        );
        assert!(hosted.beacon.is_ok(), "the beacon stands beside the offer");
        let offer = crate::hotspot::HotspotOffer::new(
            "camp",
            "opensesame",
            crate::hotspot::HotspotSecurity::Wpa2,
            Some(5678),
        );
        let gateway = client
            .join_hotspot(&offer)
            .await
            .expect("the machine answers");
        assert_eq!(
            gateway,
            "192.168.4.1"
                .parse::<std::net::IpAddr>()
                .expect("a private gateway"),
            "the machine's gateway reaches the caller"
        );
        client
            .enable_bluetooth()
            .await
            .expect("the machine answers");
        let (identity, gateway) = client.join_nearby(&9).await.expect("the machine answers");
        assert_eq!(
            identity, host,
            "the host's proven identity reaches the caller"
        );
        assert_eq!(
            gateway,
            "192.168.4.1"
                .parse::<std::net::IpAddr>()
                .expect("a private gateway")
        );
        let (identity, fetched) = client.fetch_offer(&9).await.expect("the machine answers");
        assert_eq!(
            identity, host,
            "the host's proven identity reaches the caller"
        );
        assert_eq!(
            fetched.ssid, "camp",
            "the machine's offer reaches the caller"
        );

        // The personal host's call reaches the Bluetooth machine, whose
        // dropped reply fails it, and the hand out notes its arrival on
        // the hotspot's side.
        let error = client
            .host_personal_hotspot("iphone", "the passphrase")
            .await
            .expect_err("the machine drops the personal host's reply");
        assert!(
            matches!(error, crate::hotspot::HotspotError::Failed),
            "a machine that drops the reply fails the call, got {error:?}"
        );
        client
            .device
            .as_ref()
            .expect("the device stands")
            .personal_offer_handed_out();

        // The standings read the machines', and the cancels and the run-time
        // standings reach them.
        assert_eq!(
            client.bluetooth_state(),
            BluetoothState::Unsupported,
            "the readiness stands where the platform stands"
        );
        assert_eq!(
            client.beacon_state(),
            BeaconState::Advertising { prefix: [7; 8] },
            "the beacon's standing stands beside the device"
        );
        assert_eq!(
            client.nearby_hosts(),
            vec![crate::bluetooth::NearbyHost {
                host: 9,
                prefix: Some([3; 8]),
                rssi: Some(-55)
            }],
            "the nearby read stands beside the device"
        );
        assert!(
            client.linked_peers().is_empty(),
            "nothing links before the device serves a link"
        );
        client.stop_hotspot().await;
        client.leave_hotspot().await;
        client.set_hotspot_scan(true);
        client.set_hotspot_autojoin(false);
        client.set_bluetooth_prompt(true);
        // The standings reach their machines, from the two machines' channels,
        // so the order the notes come back in is not the order sent.
        let mut noted: Vec<&str> = Vec::new();
        for _ in 0..6 {
            let got = tokio::time::timeout(Duration::from_secs(10), note_rx.recv())
                .await
                .expect("the machine notes the standing within its bound")
                .expect("the machine is still running");
            noted.push(got);
        }
        noted.sort_unstable();
        assert_eq!(
            noted,
            [
                "autojoin false",
                "handed out",
                "leave",
                "prompt true",
                "scan true",
                "stop"
            ],
            "each standing reaches its machine"
        );

        // A certificate-less device refuses the peer's calls by its standing.
        assert!(
            client.peer_address().is_none(),
            "nothing serves before the standing"
        );
        assert!(
            client.device_certificate().is_none(),
            "nothing is enrolled yet"
        );
        assert!(client.device_key_home().is_none());
        let address: std::net::SocketAddr = "127.0.0.1:0".parse().expect("loopback");
        assert!(
            matches!(
                client.link_peer(address).await,
                Err(crate::PeerError::NoIdentity)
            ),
            "the device holds no certificate to present"
        );

        tokio::time::timeout(Duration::from_secs(10), client.close())
            .await
            .expect("the client closes within its bound");
        drop(client);
        tokio::time::timeout(Duration::from_secs(10), machine)
            .await
            .expect("the machine ends within its bound")
            .expect("the machine ends");
        tokio::time::timeout(Duration::from_secs(10), pump)
            .await
            .expect("the pump ends within its bound")
            .expect("the pump ends");
    }

    #[tokio::test(start_paused = true)]
    async fn closing_the_native_client_releases_background_tasks_with_clones_alive() {
        let (core, pump) = ClientBuilder::<FakeTransport>::new(bundle(), NeverDial::default())
            .signed_in(held("carol"))
            .connect_with_pump()
            .await
            .expect("the build opens offline");
        let retained_client = core.client().clone();
        let (started, running) = tokio::sync::oneshot::channel();
        let (released, release) = tokio::sync::oneshot::channel::<()>();
        let tasks = async move {
            let _retained_client = retained_client;
            let _released = released;
            started
                .send("native-background-close")
                .expect("the observer remains");
            tokio::time::sleep(Duration::from_secs(60)).await;
        };
        let pump = tokio::spawn(super::with_device_tasks(pump, tasks));
        let client = NativeClient::bare(core);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), running)
                .await
                .expect("the background starts within its bound")
                .expect("the background reports its start"),
            "native-background-close"
        );
        client.close().await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), release)
                .await
                .expect("close releases background resources within its bound")
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(1), pump)
            .await
            .expect("the native pump ends within its bound")
            .expect("the native pump completes");
        drop(client);
    }
}
