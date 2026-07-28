//! Which replica file an authenticated identity owns.
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

use sha2::{Digest, Sha256};

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
    use super::replica_db_name;

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
