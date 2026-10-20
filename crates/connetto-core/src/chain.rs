//! The hash chain a writer's pending entries form (R75 step 1, R74 decision 12).
//!
//! Each entry hashes the entry before it, its own sequence and its changeset,
//! as a Scuttlebutt feed links each message to the previous one. The client
//! keeps the hash with each pending entry, and the server computes the same
//! chain from the entries it settles, so a direct write carries no hash on
//! the wire. A device writer signs the newest entry of a range it hands to a
//! peer or a courier, and a receiver checks the range back to the last entry
//! it verified.

use sha2::{Digest, Sha256};

/// The hash the first entry of every writer chains from.
pub const GENESIS: [u8; 32] = [0; 32];

/// The domain separator of an entry hash.
const ENTRY_DOMAIN: &[u8] = b"connetto-chain-v1\0";

/// The domain separator of the message a device key signs over a range.
const SIGN_DOMAIN: &[u8] = b"connetto-chain-sign-v1\0";

/// The hash of the entry at `seq` carrying `changeset`, chained from
/// `previous`, the hash of the entry at `seq - 1` or [`GENESIS`] for the
/// writer's first entry.
#[must_use]
pub fn entry_hash(previous: &[u8; 32], seq: u64, changeset: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ENTRY_DOMAIN);
    hasher.update(previous);
    hasher.update(seq.to_be_bytes());
    hasher.update(Sha256::digest(changeset));
    hasher.finalize().into()
}

/// The message a device key signs to vouch for its chain up to the entry at
/// `seq` whose hash is `head`.
///
/// The key id is inside the message, so a signature over one writer's chain
/// cannot be presented as another writer's.
#[must_use]
pub fn range_message(key_id: &[u8; 32], seq: u64, head: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGN_DOMAIN.len() + 32 + 8 + 32);
    message.extend_from_slice(SIGN_DOMAIN);
    message.extend_from_slice(key_id);
    message.extend_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(head);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_input_moves_the_hash() {
        let base = entry_hash(&GENESIS, 1, b"changeset");
        assert_ne!(base, entry_hash(&[1; 32], 1, b"changeset"));
        assert_ne!(base, entry_hash(&GENESIS, 2, b"changeset"));
        assert_ne!(base, entry_hash(&GENESIS, 1, b"changesex"));
        assert_eq!(base, entry_hash(&GENESIS, 1, b"changeset"));
    }

    #[test]
    fn a_chain_commits_to_every_entry_before_its_head() {
        let first = entry_hash(&GENESIS, 1, b"one");
        let head = entry_hash(&first, 2, b"two");
        let forked_first = entry_hash(&GENESIS, 1, b"uno");
        assert_ne!(head, entry_hash(&forked_first, 2, b"two"));
    }

    #[test]
    fn a_range_message_names_its_writer() {
        let head = entry_hash(&GENESIS, 1, b"one");
        assert_ne!(
            range_message(&[1; 32], 1, &head),
            range_message(&[2; 32], 1, &head)
        );
        assert_ne!(
            range_message(&[1; 32], 1, &head),
            range_message(&[1; 32], 2, &head)
        );
    }
}
