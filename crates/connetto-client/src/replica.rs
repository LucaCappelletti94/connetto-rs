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
/// There is no `Default` and no `Option`. A caller with a key says
/// [`EncryptedFile`](Self::EncryptedFile), a caller with no file says
/// [`Ephemeral`](Self::Ephemeral), and a caller writing a readable file on disk
/// has to type the word plaintext. That third case is not a free choice between
/// equals: see [`PlaintextFile`](Self::PlaintextFile) for the single situation it
/// is correct in.
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
        /// [`resolve_replica_key`](crate::auth::resolve_replica_key) or the
        /// browser equivalent.
        key: ReplicaKey,
    },
    /// A durable replica at `path` with its pages in the clear: readable by
    /// anyone who can read the file, and by anyone who later recovers the disk.
    ///
    /// **Correct in exactly one situation: the deployment has no authentication
    /// configured.** Then there is no identity, no key store record to address,
    /// and no provisioning server, so no key exists to encrypt under. That is
    /// the dev loops, the pre-auth test suites, and connetto's own demos.
    ///
    /// Note that this is narrower than "the user is logged out". The per-replica
    /// key is deliberately not session-scoped: it survives logout so a returning
    /// user resumes from their replica instead of re-syncing, and only an
    /// explicit data wipe destroys it. So a logged-out client of an
    /// authenticating deployment still opens
    /// [`EncryptedFile`](Self::EncryptedFile) from its cached key.
    ///
    /// It follows that an authenticating deployment reaching this variant is
    /// always a bug. Two arguments for allowing it deliberately were considered
    /// and both fail. Inspectability does not need it, because `sqlcipher` opens
    /// an encrypted database and the key is in the keyring of the same user on
    /// the same machine. Loss tolerance argues for something else entirely: the
    /// fear is that a wiped key store takes the device-local tier with it, and
    /// the answer to that is backing up the key or syncing the tier, not trading
    /// away confidentiality to buy durability. Cheaper page crypto and an
    /// external reader that links no codec are costs with their own fixes, not
    /// reasons.
    ///
    /// One thing this variant is **not** is the answer to "no key arrived from
    /// the server". A key is 32 random bytes, and both clients already mint
    /// security-critical randomness locally: the PKCE verifier on each side, and
    /// in the browser the AES-GCM IV that wraps this very key. So an
    /// unauthenticated deployment could encrypt under a device-minted key, and
    /// then this variant would have no justified use at all. That path does not
    /// exist yet, which is why the variant is currently reachable by necessity.
    /// See `docs/handoff-auth-at-rest-encryption.md`.
    PlaintextFile {
        /// Where the replica lives.
        path: &'a str,
    },
}

impl<'a> Replica<'a> {
    /// The encrypted replica at `path` under the key
    /// [`resolve_replica_key`](crate::auth::resolve_replica_key) returned,
    /// refusing when there is none.
    ///
    /// This is the check that stops an authenticating deployment from silently
    /// falling back to [`PlaintextFile`](Self::PlaintextFile), and it is the only
    /// place that refusal lives, so the browser worker and a native application
    /// get the same behaviour. `None` means the login carried no key and nothing
    /// was cached, which is the cleared-key-store case. Its recoveries are a
    /// fresh interactive login, which provisions one, or an explicit data wipe.
    /// Neither of them is "open it in the clear", so this returns an error rather
    /// than choosing for the application.
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

    /// The key, or `None` when these pages are not encrypted.
    ///
    /// For a second connection that has to match this replica's cipher, which in
    /// the browser is the device-local tier: it is its own main database, so it
    /// is unlocked separately rather than inheriting through an `ATTACH`.
    #[must_use]
    pub const fn key(&self) -> Option<&ReplicaKey> {
        match self {
            Self::Ephemeral | Self::PlaintextFile { .. } => None,
            Self::EncryptedFile { key, .. } => Some(key),
        }
    }

    /// The database URL to open. [`Ephemeral`](Self::Ephemeral) is SQLite's own
    /// `:memory:`, which connetto supplies so the magic string appears once.
    #[must_use]
    pub const fn path(&self) -> &'a str {
        match self {
            Self::Ephemeral => ":memory:",
            Self::EncryptedFile { path, .. } | Self::PlaintextFile { path } => path,
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
    fn a_plaintext_file_carries_no_key() {
        let replica = Replica::PlaintextFile {
            path: "replica.sqlite",
        };
        assert_eq!(replica.path(), "replica.sqlite");
        assert!(replica.key().is_none());
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
