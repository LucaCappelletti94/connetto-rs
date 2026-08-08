//! Which replica an identity owns, where it lives, and whether it is encrypted.
//!
//! connetto enforces identity continuity by file selection, not by a stamp
//! inside the replica. The client derives the replica's name from the
//! authenticated `user_id` before it opens any transport, so a re-authentication
//! that resolves to a different identity opens a different file and a
//! cross-identity resume is unrepresentable rather than detected after the fact.
//!
//! Each identity keeps its own replica, so a device may hold several. Switching
//! back resumes from that replica's persisted cursor rather than
//! re-snapshotting, and a mutation the identity never uploaded is still there
//! to replay. Destroying one is an explicit data wipe, never a side effect of
//! another identity signing in. Protecting a resident replica at rest is the
//! encryption work's job, not this one's.
//!
//! The derivation deliberately does not go through `Display`. Text on the
//! `user_id` path survives only at the two genuinely textual edges, the JWT
//! `sub` claim and the RLS `app.user_id` GUC. Here the id's own serde encoding
//! is the canonical byte source, hashed so the name is fixed-length, filesystem
//! safe, and does not spell the user id out in a directory listing.

use crate::cipher::ReplicaKey;
use sha2::{Digest, Sha256};

mod sealed {
    /// Closes [`ReplicaStorage`](super::ReplicaStorage) so the two cases below
    /// are the whole space and no downstream type can invent a third.
    pub trait Sealed {}
}

/// What a run keeps at rest, as a marker the compiler can see.
///
/// It exists so that the one dangerous arrangement, a durable device-private
/// database beside a replica with no key, is not a program. The tier would
/// inherit the replica's key through its `ATTACH`, an in-memory replica has
/// none, and the result is the durable-plaintext variant phase E5 deleted
/// arriving through the back door.
pub trait ReplicaStorage: sealed::Sealed {}

/// Nothing at rest: the replica is SQLite's own `:memory:` and so is anything
/// beside it.
#[derive(Debug, Clone, Copy)]
pub struct InMemory;

/// Something at rest, its pages encrypted under a per-replica key.
#[derive(Debug, Clone, Copy)]
pub struct Encrypted;

impl sealed::Sealed for InMemory {}
impl sealed::Sealed for Encrypted {}
impl ReplicaStorage for InMemory {}
impl ReplicaStorage for Encrypted {}

/// The device-private database beside the replica, which never syncs.
///
/// Reachable only through the builders on [`Replica`], and those are what
/// enforce that a durable one belongs to an encrypted replica alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Tier<'a> {
    /// No device-private database.
    #[default]
    None,
    /// Attach the one already at `path`, refusing to create it, so a missing
    /// file fails loudly instead of materializing as an empty database.
    Existing {
        /// Where it lives.
        path: &'a str,
    },
    /// Attach the one at `path`, creating it and applying `ddl` when empty.
    Create {
        /// Where it lives, `:memory:` when the replica keeps nothing at rest.
        path: &'a str,
        /// `CREATE TABLE` statements, each requalified into the attached schema.
        ddl: &'a str,
    },
}

impl<'a> Tier<'a> {
    /// Where it lives, or `None` when there is no device-private database.
    #[must_use]
    pub const fn path(&self) -> Option<&'a str> {
        match self {
            Self::None => None,
            Self::Existing { path } | Self::Create { path, .. } => Some(path),
        }
    }
}

/// Everything one run keeps at rest: the replica, whether its pages are
/// encrypted, and the device-private database beside it.
///
/// One value rather than several arguments, because the parts are not
/// independent and pretending otherwise let the dangerous case wear the
/// harmless one's name. A run with nothing at rest has no key, because a key
/// would encrypt heap pages against an attacker who already owns the heap, and
/// for the same reason it cannot have a durable database beside it. Both of
/// those combinations are unrepresentable rather than rejected: the builders
/// that name a file exist only on [`Encrypted`].
///
/// There is no `Default` and no `Option`. A caller with something at rest says
/// [`encrypted_file`](Self::encrypted_file), a caller with nothing at rest says
/// [`in_memory`](Self::in_memory), and there is no third choice.
///
/// A durable replica with its pages in the clear was a third case until phase
/// E5, and it went because the key is minted on the device
/// ([`provision_replica_key`](crate::auth::provision_replica_key)). A deployment
/// with no authentication at all therefore still has a key: it names the
/// key-store record after the bare replica prefix, the same way the browser's
/// `device_key` names one after a literal to protect the store it has to read
/// before any identity exists.
///
/// The legal pairings, both of which compile:
///
/// ```
/// use connetto_client::{Replica, ReplicaKey};
/// # const DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY)";
/// # let key = ReplicaKey::from_bytes([7u8; ReplicaKey::LEN]);
/// let visitor = Replica::in_memory().with_tier(DDL);
/// assert_eq!(visitor.tier().path(), Some(":memory:"));
///
/// let signed_in = Replica::encrypted_file("alice.db", Some(key))?.with_tier("alice-drafts.db", DDL);
/// assert_eq!(signed_in.tier().path(), Some("alice-drafts.db"));
/// # Ok::<(), connetto_client::ClientError>(())
/// ```
///
/// And the one that must not be a program. A run with no identity has no key,
/// so a device-private file beside it would be written in the clear, which is
/// the durable-plaintext case phase E5 deleted arriving through the back door.
/// The builder that names a path does not exist on this side:
///
/// ```compile_fail
/// use connetto_client::Replica;
/// # const DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY)";
/// let leaky = Replica::in_memory().with_tier("drafts.db", DDL);
/// ```
///
/// ```compile_fail
/// use connetto_client::Replica;
/// let leaky = Replica::in_memory().with_existing_tier("drafts.db");
/// ```
#[derive(Debug, Clone)]
pub struct Replica<'a, S: ReplicaStorage> {
    path: &'a str,
    key: Option<ReplicaKey>,
    tier: Tier<'a>,
    storage: core::marker::PhantomData<S>,
}

impl<'a> Replica<'a, InMemory> {
    /// In-process and gone when the connection closes: a caller with no
    /// identity, a tab's mirror of the worker's replica, or a throwaway in a
    /// test.
    ///
    /// Nothing is at rest, so there is no cipher to choose. This is the case a
    /// browser tab is structurally confined to: only the DB worker holds
    /// credentials, so a tab has no key and must never be given one, the
    /// per-replica key being permanent where an access token expires.
    #[must_use]
    pub const fn in_memory() -> Self {
        Self {
            path: ":memory:",
            key: None,
            tier: Tier::None,
            storage: core::marker::PhantomData,
        }
    }

    /// A device-private database beside it, in memory as the replica is.
    ///
    /// There is no variant taking a path, which is the guard: durable
    /// device-private data needs an account, because a device-wide file is
    /// readable by everyone who uses the machine and there would be no key to
    /// write it under.
    #[must_use]
    pub const fn with_tier(mut self, ddl: &'a str) -> Self {
        self.tier = Tier::Create {
            path: ":memory:",
            ddl,
        };
        self
    }
}

impl<'a> Replica<'a, Encrypted> {
    /// The encrypted replica at `path` under the key the key store holds for
    /// it, refusing when there is none.
    ///
    /// This is the check that stops a durable replica from opening without the
    /// key it was written under, and it is the only place that refusal lives, so
    /// the browser worker and a native application get the same behaviour.
    /// `None` is what
    /// [`ReplicaKeyStore::load`](connetto_core::traits::ReplicaKeyStore::load)
    /// returns for a
    /// replica whose key-store record is gone while the file survived, and its
    /// recoveries are restoring the key, or an explicit data wipe followed by a
    /// re-sync. Neither of them is "open it in the clear", so this returns an
    /// error rather than choosing for the application.
    ///
    /// Note the asymmetry with
    /// [`provision_replica_key`](crate::auth::provision_replica_key), which cannot
    /// return `None` because it mints: a replica being created always has a key,
    /// and only one already on disk can be missing its own.
    ///
    /// # Errors
    ///
    /// [`ClientError::ReplicaKeyMissing`](crate::ClientError::ReplicaKeyMissing)
    /// when `resolved` is `None`.
    pub fn encrypted_file(
        path: &'a str,
        resolved: Option<ReplicaKey>,
    ) -> Result<Self, crate::ClientError> {
        let Some(key) = resolved else {
            return Err(crate::ClientError::ReplicaKeyMissing);
        };
        Ok(Self {
            path,
            key: Some(key),
            tier: Tier::None,
            storage: core::marker::PhantomData,
        })
    }

    /// A durable device-private database at `path`, created with `ddl` when it
    /// is empty.
    ///
    /// This is the only way to first-boot one, and the reason is a property of
    /// the page codec rather than a preference. A database created through an
    /// `ATTACH` on a keyed connection inherits the main database's key salt, and
    /// an `ATTACH` of an existing database applies the main database's derived
    /// key regardless of any `KEY` clause, so a file created by some other
    /// connection carries a different salt and will not decrypt here.
    #[must_use]
    pub const fn with_tier(mut self, path: &'a str, ddl: &'a str) -> Self {
        self.tier = Tier::Create { path, ddl };
        self
    }

    /// A durable device-private database that a previous run already created.
    ///
    /// Attach-create is disabled around the attach, so a missing file fails
    /// loudly rather than materializing as an empty database.
    #[must_use]
    pub const fn with_existing_tier(mut self, path: &'a str) -> Self {
        self.tier = Tier::Existing { path };
        self
    }
}

impl<'a, S: ReplicaStorage> Replica<'a, S> {
    /// The key, or `None` when nothing is at rest to key.
    ///
    /// For a second connection that has to match this replica's cipher, which in
    /// the browser is the device-local tier: it is its own main database, so it
    /// is unlocked separately rather than inheriting through an `ATTACH`.
    #[must_use]
    pub const fn key(&self) -> Option<&ReplicaKey> {
        self.key.as_ref()
    }

    /// The database URL to open. Nothing at rest is SQLite's own `:memory:`,
    /// which connetto supplies so the magic string appears once.
    #[must_use]
    pub const fn path(&self) -> &'a str {
        self.path
    }

    /// The device-private database beside it.
    #[must_use]
    pub const fn tier(&self) -> &Tier<'a> {
        &self.tier
    }
}

/// The hashed identity component of a replica name, in hex characters. 128
/// bits of SHA-256, which is far past any collision concern for the handful of
/// identities one device ever holds.
const DIGEST_HEX_LEN: usize = 32;

/// The name of the replica file belonging to `user_id`, under `prefix`.
///
/// Deterministic: the same identity always selects the same file, so a resumed
/// session finds its own replica and its persisted cursor. Distinct identities
/// select distinct files, so an account switch cannot adopt another identity's
/// rows or pending mutations.
///
/// The unauthenticated name is `prefix` itself, which no derived name can
/// collide with.
///
/// # Errors
///
/// [`ClientError::Session`](crate::ClientError::Session) when the id's
/// `Serialize` impl fails, which for an id type is a programming error rather
/// than a runtime condition.
pub fn replica_db_name<Id>(prefix: &str, user_id: &Id) -> Result<String, crate::ClientError>
where
    Id: serde::Serialize + ?Sized,
{
    let canonical = serde_json::to_vec(user_id).map_err(|err| {
        crate::ClientError::Session(format!(
            "serializing the user id for the replica name: {err}"
        ))
    })?;
    let digest = Sha256::digest(&canonical);
    let mut name = String::with_capacity(prefix.len() + 1 + DIGEST_HEX_LEN);
    name.push_str(prefix);
    name.push('-');
    for byte in &digest[..DIGEST_HEX_LEN / 2] {
        // Two lowercase hex digits per byte, written directly so the helper
        // needs no encoding dependency.
        name.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        name.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    Ok(name)
}

/// The credential-store record naming the account this device last signed in
/// as.
///
/// It sits beside the refresh token rather than in a store of its own, because
/// the two are written together at every login and read together at every
/// start, and because that store is already reachable before any account is
/// known: it opens under a device key, which is the whole reason a silent
/// refresh works at all.
///
/// A derived replica name is always a prefix followed by a hash, so it can
/// never collide with this literal.
pub const IDENTITY_RECORD: &str = "connetto-device-identity";

/// Encode `user_id` for [`IDENTITY_RECORD`].
///
/// The encoding is the id's own serde form, the same byte source
/// [`replica_db_name`] hashes, so an account
/// read back from the record names the replica it named when it was written.
/// That is the property a start with no network depends on: nothing else on
/// the device says who the stored credential belongs to.
///
/// # Errors
///
/// [`ClientError::Session`](crate::ClientError::Session) when the id's
/// `Serialize` impl fails, which for an id type is a programming error rather
/// than a runtime condition.
pub fn encode_identity<Id>(user_id: &Id) -> Result<String, crate::ClientError>
where
    Id: serde::Serialize + ?Sized,
{
    serde_json::to_string(user_id).map_err(|err| {
        crate::ClientError::Session(format!(
            "serializing the user id for the identity record: {err}"
        ))
    })
}

/// Decode what [`encode_identity`] wrote.
///
/// # Errors
///
/// [`ClientError::Session`](crate::ClientError::Session) when the record does not decode as this
/// deployment's id type, which means the record was written by a build whose
/// id type differed. The recovery is a fresh login, which rewrites it.
pub fn decode_identity<Id>(record: &str) -> Result<Id, crate::ClientError>
where
    Id: serde::de::DeserializeOwned,
{
    serde_json::from_str(record).map_err(|err| {
        crate::ClientError::Session(format!("reading the remembered user id: {err}"))
    })
}

#[cfg(test)]
mod tests {
    use super::{Replica, Tier, replica_db_name};
    use crate::ClientError;
    use crate::cipher::ReplicaKey;

    #[test]
    fn a_run_with_nothing_at_rest_opens_sqlites_own_memory_database() {
        let replica = Replica::in_memory();
        assert_eq!(replica.path(), ":memory:");
        assert!(
            replica.key().is_none(),
            "nothing is at rest, so there is nothing to key"
        );
        assert_eq!(replica.tier(), &Tier::None);
    }

    #[test]
    fn its_device_private_database_is_in_memory_too() {
        let replica = Replica::in_memory().with_tier("CREATE TABLE drafts (id INTEGER)");
        assert_eq!(
            replica.tier().path(),
            Some(":memory:"),
            "a run with no key cannot name a file to write in the clear"
        );
    }

    #[test]
    fn an_encrypted_file_carries_its_path_and_key() {
        let key = ReplicaKey::from_bytes([3u8; ReplicaKey::LEN]);
        let replica = Replica::encrypted_file("replica.sqlite", Some(key.clone()))
            .expect("a resolved key builds an encrypted replica");
        assert_eq!(replica.path(), "replica.sqlite");
        assert_eq!(replica.key(), Some(&key));
    }

    #[test]
    fn an_encrypted_replica_may_name_a_durable_device_private_database() {
        let key = ReplicaKey::from_bytes([3u8; ReplicaKey::LEN]);
        let replica = Replica::encrypted_file("replica.sqlite", Some(key))
            .expect("a resolved key builds an encrypted replica")
            .with_existing_tier("frontend.sqlite");
        assert_eq!(replica.tier().path(), Some("frontend.sqlite"));
    }

    /// The property a start with no network rests on: an account read back out
    /// of the record names the replica it named when it was written.
    #[test]
    fn a_remembered_account_names_the_same_replica() {
        let written = super::encode_identity("alice").expect("encode");
        let read: String = super::decode_identity(&written).expect("decode");
        assert_eq!(
            replica_db_name("app.db", &read).expect("derive"),
            replica_db_name("app.db", "alice").expect("derive"),
        );
    }

    /// A typed id survives the record too, since the encoding is the id's own
    /// serde form rather than a rendering of it.
    #[test]
    fn a_typed_account_survives_the_record() {
        let written = super::encode_identity(&7_u64).expect("encode");
        let read: u64 = super::decode_identity(&written).expect("decode");
        assert_eq!(read, 7);
        assert_ne!(
            replica_db_name("app.db", &read).expect("derive"),
            replica_db_name("app.db", "7").expect("derive"),
            "the record keeps a number a number, so it cannot collide with its text",
        );
    }

    /// A record written by a build whose id type differed is refused rather
    /// than silently naming the wrong file.
    #[test]
    fn a_record_of_the_wrong_shape_is_refused() {
        let written = super::encode_identity("alice").expect("encode");
        let read = super::decode_identity::<u64>(&written);
        assert!(matches!(read, Err(ClientError::Session(_))));
    }

    /// The record name can never be mistaken for a replica, which matters
    /// because both live in stores addressed by name.
    #[test]
    fn the_record_name_cannot_collide_with_a_derived_one() {
        assert_ne!(
            replica_db_name(super::IDENTITY_RECORD, "alice").expect("derive"),
            super::IDENTITY_RECORD,
        );
    }

    #[test]
    fn an_absent_key_refuses_rather_than_falling_back_to_plaintext() {
        // The whole point: an authenticating deployment whose key store was
        // cleared gets an error it must handle, not a readable file it did not
        // ask for.
        match Replica::encrypted_file("replica.sqlite", None) {
            Err(ClientError::ReplicaKeyMissing) => {}
            Err(other) => panic!("expected ReplicaKeyMissing, got {other:?}"),
            Ok(_) => panic!("an absent key must not silently open anything"),
        }
    }

    #[test]
    fn a_name_is_stable_per_identity_and_distinct_across_identities() {
        let alice = replica_db_name("app.db", "alice").expect("derive");
        let again = replica_db_name("app.db", "alice").expect("derive");
        let bob = replica_db_name("app.db", "bob").expect("derive");

        assert_eq!(alice, again, "the same identity always selects one file");
        assert_ne!(alice, bob, "distinct identities select distinct files");
        assert!(alice.starts_with("app.db-"), "named under its prefix");
        assert!(
            !alice.contains("alice"),
            "the name does not spell out the identity"
        );
    }

    #[test]
    fn a_derived_name_never_collides_with_the_unauthenticated_one() {
        // A consumer with no auth configured keeps the bare prefix as its
        // replica name, which no derived name may take.
        let derived = replica_db_name("app.db", "alice").expect("derive");
        assert_ne!(derived, "app.db");
    }

    #[test]
    fn distinct_id_types_derive_from_their_own_encoding() {
        // The id is serialized, not formatted, so a typed id needs no Display.
        let numeric = replica_db_name("app.db", &7_u64).expect("derive");
        let text = replica_db_name("app.db", "7").expect("derive");
        assert_ne!(
            numeric, text,
            "the encoding distinguishes a number from its text"
        );
    }
}
