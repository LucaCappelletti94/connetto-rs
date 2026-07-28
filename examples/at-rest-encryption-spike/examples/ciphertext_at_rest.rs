//! Demonstration, not assertion: build one plaintext replica and one encrypted
//! replica with identical contents, then print the first bytes of each file and
//! the page layout the codec negotiated with SQLite.
//!
//! Run with `cargo +stable run --release --example ciphertext_at_rest`.

use connetto_at_rest_encryption_spike::{ReplicaKey, unlock};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;

/// A string written into both replicas, so its presence or absence in the file
/// bytes is the whole demonstration.
const MARKER: &str = "connetto-plaintext-canary-a7f31c0e";

diesel::table! {
    canary (id) {
        id -> Integer,
        note -> Text,
    }
}

fn main() {
    let dir = tempfile::tempdir().expect("a temporary directory");

    let plain = build(&dir, "plain.db", None);
    let encrypted = build(
        &dir,
        "encrypted.db",
        Some(ReplicaKey::new([0x5a; ReplicaKey::LEN])),
    );

    report("plaintext replica", &plain);
    report("encrypted replica", &encrypted);
}

/// Create a replica, optionally keyed, write the marker row, and return its
/// bytes once the connection has been dropped.
fn build(dir: &tempfile::TempDir, name: &str, key: Option<ReplicaKey>) -> Vec<u8> {
    let path = dir.path().join(name);
    let url = path.to_str().expect("a utf-8 temporary path").to_owned();
    {
        let mut conn = SqliteConnection::establish(&url).expect("open the replica");
        if let Some(key) = key {
            unlock(&mut conn, &key).expect("unlock the replica");
        }
        conn.batch_execute("CREATE TABLE canary (id INTEGER PRIMARY KEY, note TEXT NOT NULL);")
            .expect("create the canary table");
        diesel::insert_into(canary::table)
            .values((canary::id.eq(1), canary::note.eq(MARKER)))
            .execute(&mut conn)
            .expect("insert the canary row");
    }
    std::fs::read(&path).expect("read the replica back")
}

/// Print the header fields and whether the marker survived in the clear.
fn report(label: &str, bytes: &[u8]) {
    let head: Vec<String> = bytes[..32]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let marker_present = bytes
        .windows(MARKER.len())
        .any(|window| window == MARKER.as_bytes());

    println!("{label}");
    println!("  bytes 0..32       {}", head.join(" "));
    println!(
        "  ascii 0..16       {:?}",
        String::from_utf8_lossy(&bytes[..16])
    );
    println!(
        "  page size field   {}",
        u32::from(u16::from_be_bytes([bytes[16], bytes[17]]))
    );
    println!("  reserved per page {}", bytes[20]);
    println!("  marker in clear   {marker_present}");
    println!("  file size         {}", bytes.len());
    println!();
}
