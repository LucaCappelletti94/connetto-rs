//! Write one encrypted replica to the path given as the first argument, keyed
//! with the spike's fixed test key, so another backend can try to read it.
//!
//! This is the cross-backend compatibility fixture: the file this emits under
//! the native `SQLCipher` codec must be readable by the browser codec configured
//! to the same scheme, or the two backends are not running one construction.
//!
//! Run with `cargo +stable run --release --example emit_encrypted -- <path>`.

use connetto_at_rest_encryption_spike::{ReplicaKey, unlock};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;

/// The row written into the replica, which a reader must recover verbatim.
pub const MARKER: &str = "connetto-plaintext-canary-a7f31c0e";

diesel::table! {
    canary (id) {
        id -> Integer,
        note -> Text,
    }
}

/// The fixed key both sides of a cross-backend check use.
pub fn fixture_key() -> ReplicaKey {
    ReplicaKey::new([0x5a; ReplicaKey::LEN])
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("a destination path as the first argument");

    let mut conn = SqliteConnection::establish(&path).expect("open the replica");
    unlock(&mut conn, &fixture_key()).expect("unlock the replica");
    conn.batch_execute("CREATE TABLE canary (id INTEGER PRIMARY KEY, note TEXT NOT NULL);")
        .expect("create the canary table");
    diesel::insert_into(canary::table)
        .values((canary::id.eq(1), canary::note.eq(MARKER)))
        .execute(&mut conn)
        .expect("insert the canary row");

    println!("wrote {path}");
}
