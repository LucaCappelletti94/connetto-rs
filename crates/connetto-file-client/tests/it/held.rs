//! The held-content half of a rebuild at a newer major (R31): what `hold`
//! moves aside, what retention spares, and what `forget` clears.

use connetto_client::live::ConnettoClient;
use connetto_core::Major;
use connetto_file_client::{FsStore, held_content};
use connetto_file_core::{ChunkHash, ChunkStore, EncryptingStore, MimeClass};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Binary};
use tempfile::tempdir;

use crate::support::{ROOT_KEY, Scripted, offline_content, stage_photo};

/// The test schema's major, the one a rebuild holds content from.
fn major() -> Major {
    Major::new(1).expect("the test major is from 1 up")
}

/// One held chunk's hash, as a raw SQL row reads it back.
#[derive(diesel::QueryableByName)]
struct HeldHash {
    #[diesel(sql_type = Binary)]
    hash: Vec<u8>,
}

/// The number of held chunk rows, as a raw SQL scalar.
#[derive(diesel::QueryableByName)]
struct HeldCount {
    #[diesel(sql_type = BigInt)]
    chunks: i64,
}

/// Holds an authored file and asserts the hook held something.
async fn hold(client: &ConnettoClient<Scripted>) {
    let held = held_content();
    let did_hold = client
        .with_conn(|conn| (held.hold)(conn.conn(), major()))
        .await
        .expect("read the replica")
        .expect("copy the authored content aside");
    assert!(did_hold, "an authored file is held");
}

/// Holds a file, simulates the rebuild dropping the normal content tables,
/// tidies, and shows the held bytes and rows survive the pass.
#[tokio::test]
async fn held_bytes_and_rows_survive_tidy() {
    let dir = tempdir().expect("a scratch directory");
    let (client, content) = offline_content(dir.path()).await;
    stage_photo(&content, 1, b"a held photo", MimeClass::Jpeg).await;
    hold(&client).await;

    // The rebuild drops the normal content tables, leaving the file held only.
    client
        .with_conn(|conn| {
            conn.conn().batch_execute(
                "DELETE FROM _connetto_content_outbox; \
                     DELETE FROM _connetto_content_chunks;",
            )
        })
        .await
        .expect("read the replica")
        .expect("drop the normal content rows");

    // The held chunk's hash, read straight from the held table.
    let HeldHash { hash } = client
        .with_conn(|conn| {
            diesel::sql_query(
                "SELECT hash FROM _connetto_held_content_chunks \
                 WHERE major = 1 ORDER BY ordinal LIMIT 1",
            )
            .get_result::<HeldHash>(conn.conn())
        })
        .await
        .expect("read the held chunk row")
        .expect("one held chunk");

    content.tidy_content().await.expect("tidy the content");

    // The bytes the held row names are still in the store.
    let store = FsStore::new(dir.path().join("chunks"));
    let enc = EncryptingStore::new(store, &ROOT_KEY);
    let chunk = ChunkHash::from_bytes(hash.try_into().expect("a 32-byte hash"));
    assert_eq!(
        enc.read_chunk(&chunk)
            .await
            .expect("the held chunk survives tidy"),
        b"a held photo",
    );

    // The file is still held, so the drain can still send it.
    let held = held_content();
    let count = client
        .with_conn(|conn| (held.count)(conn.conn(), major()))
        .await
        .expect("read the replica")
        .expect("count the held file");
    assert_eq!(count, 1, "the file is still held after tidy");
}

/// `hold` counts an authored file, and `forget` clears it and reports how many.
#[tokio::test]
async fn hold_counts_and_forget_clears() {
    let dir = tempdir().expect("a scratch directory");
    let (client, content) = offline_content(dir.path()).await;
    stage_photo(
        &content,
        1,
        b"a photo held across a rebuild",
        MimeClass::Jpeg,
    )
    .await;

    let held = held_content();
    let did_hold = client
        .with_conn(|conn| (held.hold)(conn.conn(), major()))
        .await
        .expect("read the replica")
        .expect("copy the authored file aside");
    assert!(did_hold, "an authored file is held");

    let count = client
        .with_conn(|conn| (held.count)(conn.conn(), major()))
        .await
        .expect("read the replica")
        .expect("count the held file");
    assert_eq!(count, 1, "the held file is counted");

    let HeldCount { chunks } = client
        .with_conn(|conn| {
            diesel::sql_query(
                "SELECT COUNT(*) AS chunks FROM _connetto_held_content_chunks WHERE major = 1",
            )
            .get_result::<HeldCount>(conn.conn())
        })
        .await
        .expect("read the held chunks")
        .expect("count the held chunk rows");
    assert!(chunks > 0, "the held file's chunks are copied");

    let forgotten = client
        .with_conn(|conn| (held.forget)(conn.conn(), major()))
        .await
        .expect("read the replica")
        .expect("forget the held file");
    assert_eq!(forgotten, 1, "forgetting reports the file");

    let count = client
        .with_conn(|conn| (held.count)(conn.conn(), major()))
        .await
        .expect("read the replica")
        .expect("count after forget");
    assert_eq!(count, 0, "nothing is held after forget");
}

/// A replica with no content tables holds nothing, so `hold` is a no-op.
#[tokio::test]
async fn hold_is_a_no_op_without_content() {
    let dir = tempdir().expect("a scratch directory");
    let client = crate::support::offline_client(&dir.path().join("replica.sqlite")).await;
    let held = held_content();
    let did_hold = client
        .with_conn(|conn| (held.hold)(conn.conn(), major()))
        .await
        .expect("read the replica")
        .expect("hold finds no content tables");
    assert!(!did_hold, "no content, nothing held");
}
