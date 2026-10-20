//! The hash chain a writer's pending entries form (R75 step 1, R74 decision 12).
//!
//! Each entry hashes the entry before it, its own sequence and its changeset,
//! as a Scuttlebutt feed links each message to the previous one. The client
//! keeps the hash with each pending entry, and the server computes the same
//! chain from the entries it settles, so a direct write carries no hash on
//! the wire. A device writer signs the newest entry of a range it hands to a
//! peer, and a receiver checks the range back to the last entry it verified.
//! A range a writer hands a courier takes the separate courier attestation,
//! which also covers every entry's provenance original.

use sha2::{Digest, Sha256};

use crate::messages::{Provenance, WriterRef};

/// The hash the first entry of every writer chains from.
pub const GENESIS: [u8; 32] = [0; 32];

/// The domain separator of an entry hash.
const ENTRY_DOMAIN: &[u8] = b"connetto-chain-v1\0";

/// The domain separator of the message a device key signs over a range.
const SIGN_DOMAIN: &[u8] = b"connetto-chain-sign-v1\0";

/// The domain separator of the message a device key signs over a courier
/// range.
const COURIER_SIGN_DOMAIN: &[u8] = b"connetto-chain-courier-sign-v1\0";

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

/// Encodes the author, terminal chain head and every courier entry's original.
///
/// # Panics
///
/// Panics if the entry count exceeds `u64::MAX`.
#[must_use]
pub fn courier_range_message(
    key_id: &[u8; 32],
    seq: u64,
    head: &[u8; 32],
    entries: impl ExactSizeIterator<Item = (u64, Option<Provenance>)>,
) -> Vec<u8> {
    let count = u64::try_from(entries.len()).expect("courier entry count fits u64");
    let mut message =
        Vec::with_capacity(COURIER_SIGN_DOMAIN.len() + 32 + 8 + 32 + 8 + entries.len() * 49);
    message.extend_from_slice(COURIER_SIGN_DOMAIN);
    message.extend_from_slice(key_id);
    message.extend_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(head);
    message.extend_from_slice(&count.to_be_bytes());
    for (entry_seq, provenance) in entries {
        message.extend_from_slice(&entry_seq.to_be_bytes());
        match provenance {
            None => message.push(0),
            Some(provenance) => match provenance.writer {
                WriterRef::Device(key) => {
                    message.push(1);
                    message.extend_from_slice(&key);
                    message.extend_from_slice(&provenance.seq.to_be_bytes());
                }
                WriterRef::Number(number) => {
                    message.push(2);
                    message.extend_from_slice(&number.to_be_bytes());
                    message.extend_from_slice(&provenance.seq.to_be_bytes());
                }
            },
        }
    }
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

    #[test]
    fn a_courier_range_message_covers_every_field() {
        let original = Provenance {
            writer: WriterRef::Device([1; 32]),
            seq: 7,
        };
        let entries = &[(1u64, None), (2, Some(original))];
        let base = courier_range_message(&[3; 32], 2, &GENESIS, entries.iter().copied());
        assert_ne!(
            base,
            courier_range_message(&[4; 32], 2, &GENESIS, entries.iter().copied()),
            "the author key is inside the message"
        );
        let head = entry_hash(&GENESIS, 2, b"two");
        assert_ne!(
            base,
            courier_range_message(&[3; 32], 3, &head, entries.iter().copied()),
            "the terminal sequence and chain head are inside the message"
        );
        assert_ne!(
            base,
            courier_range_message(&[3; 32], 2, &GENESIS, [(1, None)].into_iter()),
            "the entry count is inside the message"
        );
        assert_ne!(
            base,
            courier_range_message(
                &[3; 32],
                2,
                &GENESIS,
                [(5, None), (2, Some(original))].into_iter()
            ),
            "each entry sequence is inside the message"
        );
        assert_ne!(
            base,
            courier_range_message(&[3; 32], 2, &GENESIS, [(1, None), (2, None)].into_iter()),
            "a stripped provenance is not the signed one"
        );
        assert_ne!(
            base,
            courier_range_message(
                &[3; 32],
                2,
                &GENESIS,
                [
                    (1, None),
                    (
                        2,
                        Some(Provenance {
                            writer: WriterRef::Number(9),
                            seq: 7
                        })
                    )
                ]
                .into_iter()
            ),
            "a substituted writer kind is not the signed one"
        );
        assert_ne!(
            base,
            courier_range_message(
                &[3; 32],
                2,
                &GENESIS,
                [
                    (1, None),
                    (
                        2,
                        Some(Provenance {
                            writer: WriterRef::Device([2; 32]),
                            seq: 7
                        })
                    )
                ]
                .into_iter()
            ),
            "a substituted writer identity is not the signed one"
        );
        assert_ne!(
            base,
            courier_range_message(
                &[3; 32],
                2,
                &GENESIS,
                [
                    (1, None),
                    (
                        2,
                        Some(Provenance {
                            writer: WriterRef::Device([1; 32]),
                            seq: 8
                        })
                    )
                ]
                .into_iter()
            ),
            "a changed original sequence is not the signed one"
        );
    }

    #[test]
    fn a_courier_range_message_keeps_the_originals_kinds_apart() {
        let device = Provenance {
            writer: WriterRef::Device([7; 32]),
            seq: 1,
        };
        let number = Provenance {
            writer: WriterRef::Number(7),
            seq: 1,
        };
        assert_ne!(
            courier_range_message(&[3; 32], 1, &GENESIS, [(1, Some(device))].into_iter()),
            courier_range_message(&[3; 32], 1, &GENESIS, [(1, Some(number))].into_iter()),
            "the device and number encodings cannot collide"
        );
    }

    #[test]
    fn a_courier_range_message_is_canonical_and_domain_separated() {
        let a = courier_range_message(&[3; 32], 1, &GENESIS, [(1, None)].into_iter());
        let count_offset = COURIER_SIGN_DOMAIN.len() + 32 + 8 + 32;
        assert_eq!(&a[count_offset..count_offset + 8], &1u64.to_be_bytes());
        assert_ne!(
            a,
            range_message(&[3; 32], 1, &GENESIS),
            "the courier attestation is its own message"
        );
        assert_ne!(
            courier_range_message(&[3; 32], 0, &GENESIS, [].into_iter()),
            courier_range_message(&[3; 32], 1, &GENESIS, [].into_iter()),
            "an empty range vouches the writer's own head"
        );
    }
}
