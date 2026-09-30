//! The builders that compose a connetto client, the platform-neutral core
//! builder and the platform stacks over it.
//!
//! The core builder is the one construction path, composing the shared
//! pieces, the injected dialer, the sign-in fork and the durable step with no
//! platform splicing. The native stack layers its dialing and sign-in over the core,
//! and the web stack lives in connetto-web over the core and the same shared
//! pieces.

pub mod content;
pub mod core;
pub mod gate;
#[cfg(feature = "native-transport")]
pub mod native;
pub mod schema;
pub mod sign_in;
pub mod tuning;

pub use content::{AttachContent, ContentPlace};
pub use core::REPLICA_PREFIX;
pub use core::{
    ClientBuilder, CoreClient, CoreDurable, CorePump, CoreSignedIn, Located, ReplicaPlace,
};
pub use gate::Gate;
pub use schema::SyncSchema;
pub use sign_in::{AccountChoice, Auth, HeldCredential, SignInKind, StorageMarker, WebSignIn};
#[cfg(feature = "native-auth")]
pub use sign_in::{Keyring, KeyringAuth, StoredAuth};
#[cfg(feature = "native-transport")]
pub use sign_in::{NativeSignIn, NoKeyring};
pub use tuning::SyncTuning;
