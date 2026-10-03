//! The sign-in values the builders consume, and the traits that seal them.

use connetto_core::messages::Grant;
use connetto_core::traits::RefreshTokenStore;
use core::fmt::Display;
use serde::Serialize;
#[cfg(feature = "native-auth")]
use std::pin::Pin;
use std::sync::Arc;

use crate::AccessTokenSource;
use crate::ClientError;
#[cfg(feature = "native-auth")]
use crate::auth::KeyringStore;
use crate::away::GateMechanism;
use crate::builder::core::REPLICA_PREFIX;
use crate::replica::replica_db_name;
#[cfg(feature = "native-auth")]
use crate::{AuthorizationSession, BrowserOpener};

/// Who the application signs in as, asked once at launch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AccountChoice {
    /// The account this device signed in as last.
    #[default]
    LastUsed,
    /// A stored account, named as the store holds it.
    Account(String),
    /// A fresh login, whatever this device has stored.
    New,
    /// Ask the platform's chooser.
    Ask,
}

/// A credential the application already holds, the one the bot carries
/// (R91).
///
/// The grant is the same shape the provider sign-in mints, so a held
/// credential and a provider login reach the same replica and present the
/// same caller identity. A held credential has no refresh store and no
/// platform sign-in hooks, and there is no setter that gives it either.
#[derive(Clone, Debug)]
pub struct HeldCredential {
    grant: Grant,
    /// The caller value the server binds, the id's `Display` rendering.
    caller: String,
    /// The name the replica file and the key record take, hashed over the
    /// id's own serde encoding.
    replica_name: String,
    token_source: Option<AccessTokenSource>,
}

impl HeldCredential {
    /// Hold `grant` for the identity `user_id`.
    ///
    /// The replica file and the key record take
    /// [`replica_db_name`] over the core
    /// prefix and the id's own serde encoding, and the caller function the
    /// replica registers answers the id's `Display` rendering, the same
    /// value the server binds the caller as.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the id cannot be serialized.
    pub fn new<Id: Serialize + Display + ?Sized>(
        grant: Grant,
        user_id: &Id,
    ) -> Result<Self, ClientError> {
        Ok(Self {
            grant,
            caller: user_id.to_string(),
            replica_name: replica_db_name(REPLICA_PREFIX, user_id)?,
            token_source: None,
        })
    }

    /// The name the replica file and the key record take. A platform without
    /// a platform file system names its OPFS file from the same value, so
    /// the credential and the file it drives cannot disagree.
    #[must_use]
    pub fn replica_name(&self) -> &str {
        &self.replica_name
    }

    /// A source of fresh access tokens, consulted on every reconnect.
    #[must_use]
    pub fn with_token_source(mut self, source: AccessTokenSource) -> Self {
        self.token_source = Some(source);
        self
    }

    /// The parts the core builder consumes, in order the replica name, the
    /// caller value, the login grant and the token source.
    pub(crate) fn into_parts(self) -> (String, String, Grant, Option<AccessTokenSource>) {
        (
            self.replica_name,
            self.caller,
            self.grant,
            self.token_source,
        )
    }
}

/// The provider sign-in, before a platform has said where its credentials
/// live.
///
/// The web build uses it as is, and the native build forks it into a keyring
/// sign-in or a stored sign-in, because a native credential needs a store
/// and the bare value does not name one.
#[derive(Clone, Debug)]
pub struct Auth {
    origin: String,
    login_origin: Option<String>,
    provider: String,
    account: AccountChoice,
}

impl Auth {
    /// Provider sign-in against `auth_origin` with `provider`.
    #[must_use]
    pub fn new(auth_origin: impl Into<String>, provider: impl Into<String>) -> Self {
        Self {
            origin: auth_origin.into(),
            login_origin: None,
            provider: provider.into(),
            account: AccountChoice::default(),
        }
    }

    /// The origin the login page navigates to, when it differs from the
    /// origin the token fetches use.
    #[must_use]
    pub fn with_login_origin(mut self, origin: Option<String>) -> Self {
        self.login_origin = origin;
        self
    }

    /// Who to be, asked once at launch.
    #[must_use]
    pub fn with_account(mut self, choice: AccountChoice) -> Self {
        self.account = choice;
        self
    }

    /// The origin the token and refresh endpoints live under.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The origin the login page navigates to, when it differs.
    #[must_use]
    pub fn login_origin(&self) -> Option<&str> {
        self.login_origin.as_deref()
    }

    /// The provider the login names.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// The native fork that keeps the refresh token and the replica key in
    /// the OS keyring, both services named by `app_id`.
    #[cfg(feature = "native-auth")]
    #[must_use]
    pub fn keyring(self, app_id: impl Into<String>) -> KeyringAuth {
        KeyringAuth {
            inner: self.provider_state(),
            app_id: app_id.into(),
            #[cfg(target_os = "android")]
            keystore_prompt: None,
            #[cfg(target_os = "windows")]
            hello_owner: None,
        }
    }

    /// The native fork that keeps the refresh token in `store`.
    #[cfg(feature = "native-auth")]
    #[must_use]
    pub fn refresh_store<R>(self, store: R) -> StoredAuth<R>
    where
        R: RefreshTokenStore<Error = ClientError> + Send + Sync + 'static,
    {
        StoredAuth {
            inner: self.provider_state(),
            store: Arc::new(store),
        }
    }

    #[cfg(feature = "native-auth")]
    fn provider_state(self) -> ProviderSignin {
        ProviderSignin {
            origin: self.origin,
            login_origin: self.login_origin,
            provider: self.provider,
            account: self.account,
            chooser: None,
            opener: None,
            claimed: None,
        }
    }
}

impl WebSignIn for Auth {
    #[doc(hidden)]
    fn into_kind(self) -> SignInKind {
        SignInKind::Provider {
            origin: self.origin,
            login_origin: self.login_origin,
            provider: self.provider,
            account: self.account,
            #[cfg(feature = "native-auth")]
            chooser: None,
            #[cfg(feature = "native-auth")]
            opener: None,
            #[cfg(feature = "native-auth")]
            claimed: None,
        }
    }
}

/// The native sign-in hooks both provider forks take, written once for both.
#[cfg(feature = "native-auth")]
macro_rules! provider_hooks {
    () => {
        /// The platform's chooser, consulted when the account choice is `Ask`.
        #[must_use]
        pub fn with_account_chooser(mut self, chooser: AccountChooser) -> Self {
            self.inner.chooser = Some(chooser);
            self
        }

        /// Replace the browser opener that runs the interactive login.
        #[must_use]
        pub fn with_browser_opener(mut self, opener: BrowserOpener) -> Self {
            self.inner.opener = Some(opener);
            self
        }

        /// Log in through `redirect_uri`, a redirect the app registered with its
        /// operating system, with `session` running the browser and returning
        /// what the redirect delivered.
        #[must_use]
        pub fn with_claimed_redirect(
            mut self,
            redirect_uri: impl Into<String>,
            session: Arc<dyn AuthorizationSession>,
        ) -> Self {
            self.inner.claimed = Some((redirect_uri.into(), session));
            self
        }
    };
}

/// A native provider sign-in whose credentials live in the OS keyring named
/// by the app id, which names both the refresh-token and the replica-key
/// services.
#[cfg(feature = "native-auth")]
#[derive(Clone)]
pub struct KeyringAuth {
    inner: ProviderSignin,
    app_id: String,
    #[cfg(target_os = "android")]
    keystore_prompt: Option<Arc<dyn crate::KeystorePrompt>>,
    #[cfg(target_os = "windows")]
    hello_owner: Option<Arc<dyn crate::HelloOwner>>,
}

#[cfg(feature = "native-auth")]
impl KeyringAuth {
    provider_hooks!();

    /// The prompt the Keystore-gated secrets unlock through. Without one an
    /// Android build keeps its secrets ungated and reports the gate
    /// unsupported.
    #[cfg(target_os = "android")]
    #[must_use]
    pub fn with_keystore_prompt(mut self, prompt: Arc<dyn crate::KeystorePrompt>) -> Self {
        self.keystore_prompt = Some(prompt);
        self
    }

    /// The window the Windows Hello prompt over the gated secrets opens over.
    /// Without one a Windows build keeps its secrets ungated and reports the
    /// gate unsupported.
    #[cfg(target_os = "windows")]
    #[must_use]
    pub fn with_hello_owner(mut self, owner: Arc<dyn crate::HelloOwner>) -> Self {
        self.hello_owner = Some(owner);
        self
    }
}

#[cfg(feature = "native-auth")]
impl NativeSignIn for KeyringAuth {
    type Storage = Keyring;

    #[doc(hidden)]
    fn into_parts(self) -> (SignInKind, Keyring) {
        (
            self.inner.into_kind(),
            Keyring {
                app_id: self.app_id,
                #[cfg(target_os = "android")]
                keystore_prompt: self.keystore_prompt,
                #[cfg(target_os = "windows")]
                hello_owner: self.hello_owner,
            },
        )
    }
}

/// A native provider sign-in whose refresh token lives in a caller-supplied
/// store, so the durable replica step needs its key store supplied too.
#[cfg(feature = "native-auth")]
#[derive(Clone)]
pub struct StoredAuth<R> {
    inner: ProviderSignin,
    store: Arc<R>,
}

#[cfg(feature = "native-auth")]
impl<R: RefreshTokenStore<Error = ClientError> + Send + Sync> StoredAuth<R> {
    provider_hooks!();
}

#[cfg(feature = "native-auth")]
impl<R> NativeSignIn for StoredAuth<R>
where
    R: RefreshTokenStore<Error = ClientError> + Send + Sync + 'static,
{
    type Storage = NoKeyring;

    #[doc(hidden)]
    fn into_parts(self) -> (SignInKind, NoKeyring) {
        (
            self.inner.into_kind(),
            NoKeyring {
                store: Some(self.store),
            },
        )
    }
}

impl WebSignIn for HeldCredential {
    #[doc(hidden)]
    fn into_kind(self) -> SignInKind {
        SignInKind::Held(self)
    }
}

#[cfg(feature = "native-transport")]
impl NativeSignIn for HeldCredential {
    type Storage = NoKeyring;

    #[doc(hidden)]
    fn into_parts(self) -> (SignInKind, NoKeyring) {
        (SignInKind::Held(self), NoKeyring { store: None })
    }
}

/// The platform's chooser, giving the stored accounts and answering with who
/// to be.
#[cfg(feature = "native-auth")]
pub type AccountChooser =
    Arc<dyn Fn(Vec<String>) -> Pin<Box<dyn Future<Output = AccountChoice> + Send>> + Send + Sync>;

/// The state a provider sign-in carries, shared by its two native forks.
#[cfg(feature = "native-auth")]
#[derive(Clone)]
struct ProviderSignin {
    origin: String,
    login_origin: Option<String>,
    provider: String,
    account: AccountChoice,
    chooser: Option<AccountChooser>,
    opener: Option<BrowserOpener>,
    claimed: Option<(String, Arc<dyn AuthorizationSession>)>,
}

#[cfg(feature = "native-auth")]
impl ProviderSignin {
    fn into_kind(self) -> SignInKind {
        SignInKind::Provider {
            origin: self.origin,
            login_origin: self.login_origin,
            provider: self.provider,
            account: self.account,
            chooser: self.chooser,
            opener: self.opener,
            claimed: self.claimed,
        }
    }
}

/// Where a native sign-in's credentials live, carried by the marker the
/// builder stages on.
///
/// A provider sign-in always names a refresh store and a held credential
/// never does, so the marker the sign-in hands over decides what the durable
/// step can do with it.
#[doc(hidden)]
#[derive(Clone)]
pub enum SignInKind {
    /// A provider sign-in, with the platform hooks the native forks carry.
    Provider {
        /// The auth origin the token endpoints live under.
        origin: String,
        /// The origin the login page navigates to, when it differs.
        login_origin: Option<String>,
        /// The provider name the login names.
        provider: String,
        /// Who to be, asked once at launch.
        account: AccountChoice,
        /// The platform's chooser, absent when the account choice is not `Ask`.
        #[cfg(feature = "native-auth")]
        chooser: Option<AccountChooser>,
        /// The browser opener, absent for the system browser.
        #[cfg(feature = "native-auth")]
        opener: Option<BrowserOpener>,
        /// The claimed redirect and its session, absent for a loopback login.
        #[cfg(feature = "native-auth")]
        claimed: Option<(String, Arc<dyn AuthorizationSession>)>,
    },
    /// A credential the caller already holds.
    Held(HeldCredential),
}

/// A native sign-in, sealed to the kinds present today.
///
/// A bare [`Auth`] never satisfies it, because natively a credential needs a
/// store and the platform fork states one.
#[cfg(feature = "native-transport")]
pub trait NativeSignIn: private::Sealed {
    /// Where this sign-in's credentials live.
    type Storage: StorageMarker;

    /// The parts the builder stores, the kind and the storage the sign-in
    /// carries.
    #[doc(hidden)]
    fn into_parts(self) -> (SignInKind, Self::Storage);
}

/// A web sign-in, sealed to the kinds present today.
pub trait WebSignIn: private::Sealed {
    /// The kind the builder consumes.
    #[doc(hidden)]
    fn into_kind(self) -> SignInKind;
}

/// The storage kinds a native sign-in can have.
#[doc(hidden)]
pub trait StorageMarker: private::Sealed {
    /// The refresh store a provider sign-in reads from, absent for a held
    /// credential.
    fn refresh_store(
        &self,
    ) -> Option<Arc<dyn RefreshTokenStore<Error = ClientError> + Send + Sync>>;

    /// Apply the build's gate setting to the secrets this storage holds, and
    /// hand back the mechanism the client's re-check drives, `None` when the
    /// storage has none.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the platform store cannot be opened.
    fn arm_gate(&self, on: bool) -> Result<Option<Arc<dyn GateMechanism>>, ClientError>;
}

/// The OS keyring names both credential services with the app id.
#[cfg(feature = "native-auth")]
#[derive(Clone)]
pub struct Keyring {
    pub(crate) app_id: String,
    #[cfg(target_os = "android")]
    keystore_prompt: Option<Arc<dyn crate::KeystorePrompt>>,
    #[cfg(target_os = "windows")]
    hello_owner: Option<Arc<dyn crate::HelloOwner>>,
}

#[cfg(feature = "native-auth")]
impl core::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keyring")
            .field("app_id", &self.app_id)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "native-auth")]
impl StorageMarker for Keyring {
    fn refresh_store(
        &self,
    ) -> Option<Arc<dyn RefreshTokenStore<Error = ClientError> + Send + Sync>> {
        Some(Arc::new(KeyringStore::new(self.app_id.clone())))
    }

    fn arm_gate(&self, on: bool) -> Result<Option<Arc<dyn GateMechanism>>, ClientError> {
        #[cfg(target_os = "android")]
        if let Some(prompt) = &self.keystore_prompt {
            crate::keyring::set_keystore_prompt(&self.app_id, Arc::clone(prompt))?;
        }
        #[cfg(target_os = "windows")]
        if let Some(owner) = &self.hello_owner {
            crate::keyring::set_hello_owner(&self.app_id, Arc::clone(owner))?;
        }
        crate::keyring::arm_gate(&self.app_id, on)
    }
}

/// No keyring. A held credential names no store and a stored sign-in names
/// its refresh store.
#[cfg(feature = "native-transport")]
#[derive(Clone)]
pub struct NoKeyring {
    store: Option<Arc<dyn RefreshTokenStore<Error = ClientError> + Send + Sync>>,
}

#[cfg(feature = "native-transport")]
impl StorageMarker for NoKeyring {
    fn refresh_store(
        &self,
    ) -> Option<Arc<dyn RefreshTokenStore<Error = ClientError> + Send + Sync>> {
        self.store.clone()
    }

    fn arm_gate(&self, _on: bool) -> Result<Option<Arc<dyn GateMechanism>>, ClientError> {
        Ok(None)
    }
}

mod private {
    #[cfg(feature = "native-transport")]
    use super::NoKeyring;
    use super::{Auth, HeldCredential};
    #[cfg(feature = "native-auth")]
    use super::{ClientError, Keyring, KeyringAuth, RefreshTokenStore, StoredAuth};

    pub trait Sealed {}

    impl Sealed for Auth {}
    impl Sealed for HeldCredential {}

    #[cfg(feature = "native-transport")]
    impl Sealed for NoKeyring {}

    #[cfg(feature = "native-auth")]
    impl Sealed for Keyring {}
    #[cfg(feature = "native-auth")]
    impl Sealed for KeyringAuth {}
    #[cfg(feature = "native-auth")]
    impl<R> Sealed for StoredAuth<R> where
        R: RefreshTokenStore<Error = ClientError> + Send + Sync + 'static
    {
    }
}

#[cfg(test)]
mod tests {
    use super::HeldCredential;
    use crate::builder::core::REPLICA_PREFIX;
    use crate::replica::replica_db_name;
    use connetto_core::messages::Grant;

    /// The replica name hashes the id's own serde encoding under the core
    /// prefix, and never an encoding of the id.
    #[test]
    fn a_held_credential_derives_the_replica_name_from_the_identity_itself() {
        let user_id = "alice".to_owned();
        let credential =
            HeldCredential::new(Grant::new("user:unit"), &user_id).expect("a held credential");
        assert_eq!(
            credential.replica_name(),
            replica_db_name(REPLICA_PREFIX, &user_id).expect("derive"),
            "the name hashes the id's own serde encoding under the core prefix"
        );
        let encoded = format!("{user_id:?}");
        assert_ne!(
            credential.replica_name(),
            replica_db_name(REPLICA_PREFIX, &encoded).expect("derive"),
            "an encoding of the id is not the id"
        );
    }
}
