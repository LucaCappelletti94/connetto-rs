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

/// The replica a connection is about to open.
///
/// Storage kind and cipher are one value rather than two arguments, because the
/// two are not independent and pretending otherwise let the dangerous case wear
/// the harmless one's name. An ephemeral replica has nothing at rest, so a key
/// would encrypt heap pages against an attacker who already owns the heap: it
/// cannot carry one, and that combination is now unrepresentable. A durable
/// replica does have something at rest, so it has to say which of the two it is,
/// in a word that does not also mean "in memory".
///
/// There is no `Default` and no `Option`. A caller with something at rest says
/// [`EncryptedFile`](Self::EncryptedFile), a caller with nothing at rest says
/// [`Ephemeral`](Self::Ephemeral), and there is no third choice.
///
/// A durable replica with its pages in the clear was the third variant until
/// phase E5, and it went because the key is minted on the device
/// ([`provision_replica_key`](crate::auth::provision_replica_key)). A deployment
/// with no authentication at all therefore still has a key: it names the
/// key-store record after the bare replica prefix, the same way the browser's
/// `device_key` names one after a literal to protect the store it has to read
/// before any identity exists.
#[derive(Debug, Clone)]
pub enum Replica<'a> {
    /// In-process and gone when the connection closes. A tab's mirror of the
    /// worker's replica, or a throwaway in a test.
    ///
    /// Nothing is at rest, so there is no cipher to choose. This is the case a
    /// browser tab is structurally confined to: only the DB worker holds
    /// credentials, so a tab has no key and must never be given one, the
    /// per-replica key being permanent where an access token expires.
    Ephemeral,
    /// A durable replica at `path`, its pages encrypted under `key`.
    ///
    /// `path` is a filesystem path natively. In the browser it is the codec URL
    /// [`cipher_url`](crate::cipher::cipher_url) composes over the installed VFS,
    /// because the browser codec intercepts as a VFS shim and a bare name would
    /// leave it out of the stack.
    EncryptedFile {
        /// Where the replica lives.
        path: &'a str,
        /// The per-replica key, from
        /// [`provision_replica_key`](crate::auth::provision_replica_key) or the
        /// browser equivalent.
        key: ReplicaKey,
    },
}

impl<'a> Replica<'a> {
    /// The encrypted replica at `path` under the key the key store holds for it,
    /// refusing when there is none.
    ///
    /// This is the check that stops a durable replica from opening without the
    /// key it was written under, and it is the only place that refusal lives, so
    /// the browser worker and a native application get the same behaviour.
    /// `None` is what
    /// [`ReplicaKeyStore::load`](crate::auth::ReplicaKeyStore::load) returns for a
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
        match resolved {
            Some(key) => Ok(Self::EncryptedFile { path, key }),
            None => Err(crate::ClientError::ReplicaKeyMissing),
        }
    }

    /// The key, or `None` for [`Ephemeral`](Self::Ephemeral), which has nothing
    /// at rest to key.
    ///
    /// For a second connection that has to match this replica's cipher, which in
    /// the browser is the device-local tier: it is its own main database, so it
    /// is unlocked separately rather than inheriting through an `ATTACH`.
    #[must_use]
    pub const fn key(&self) -> Option<&ReplicaKey> {
        match self {
            Self::Ephemeral => None,
            Self::EncryptedFile { key, .. } => Some(key),
        }
    }

    /// The database URL to open. [`Ephemeral`](Self::Ephemeral) is SQLite's own
    /// `:memory:`, which connetto supplies so the magic string appears once.
    #[must_use]
    pub const fn path(&self) -> &'a str {
        match self {
            Self::Ephemeral => ":memory:",
            Self::EncryptedFile { path, .. } => path,
        }
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

#[cfg(test)]
mod tests {
    use super::{Replica, replica_db_name};
    use crate::ClientError;
    use crate::cipher::ReplicaKey;

    #[test]
    fn an_ephemeral_replica_opens_sqlites_own_memory_database() {
        assert_eq!(Replica::Ephemeral.path(), ":memory:");
        assert!(
            Replica::Ephemeral.key().is_none(),
            "nothing is at rest, so there is nothing to key"
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
