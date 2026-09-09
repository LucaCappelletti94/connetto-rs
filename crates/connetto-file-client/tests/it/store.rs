//! Tests for [`FsStore`] through the [`ChunkStore`] trait, over a `TempDir`.

use connetto_file_client::FsStore;
use connetto_file_core::{ChunkHash, ChunkStore};
use tempfile::tempdir;

/// Recursively counts files whose name ends with `.tmp` under `dir`.
fn count_tmp_files(dir: &std::path::Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries.flatten().fold(0, |acc, e| {
        let p = e.path();
        if p.is_dir() {
            acc + count_tmp_files(&p)
        } else if p.extension().is_some_and(|ext| ext == "tmp") {
            acc + 1
        } else {
            acc
        }
    })
}

/// Recursively counts all regular files under `dir`.
fn count_all_files(dir: &std::path::Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries.flatten().fold(0, |acc, e| {
        let p = e.path();
        if p.is_dir() {
            acc + count_all_files(&p)
        } else {
            acc + 1
        }
    })
}

/// A written chunk reads back byte-identical, and `has_chunk` reports it present.
#[tokio::test]
async fn written_chunk_reads_back_identical_and_has_chunk_reports_it() {
    let dir = tempdir().expect("temp dir");
    let store = FsStore::new(dir.path());
    let hash = ChunkHash::from_bytes([1u8; 32]);
    let data = b"hello world";
    store.write_chunk(&hash, data).await.expect("write");
    assert!(
        store.has_chunk(&hash).await.expect("has_chunk"),
        "has_chunk must be true immediately after write"
    );
    assert_eq!(
        store.read_chunk(&hash).await.expect("read"),
        data,
        "read must return the exact bytes that were written"
    );
}

/// `has_chunk` is false for an unwritten hash, and `read_chunk` returns an error rather than empty bytes.
#[tokio::test]
async fn absent_hash_has_chunk_false_and_read_chunk_is_error() {
    let dir = tempdir().expect("temp dir");
    let store = FsStore::new(dir.path());
    let hash = ChunkHash::from_bytes([2u8; 32]);
    assert!(
        !store.has_chunk(&hash).await.expect("has_chunk"),
        "has_chunk must be false for a hash never written"
    );
    assert!(
        store.read_chunk(&hash).await.is_err(),
        "read_chunk on an absent hash must be an error, not empty bytes"
    );
}

/// `delete_chunk` makes `has_chunk` false; a second call on the same hash still succeeds.
#[tokio::test]
async fn delete_chunk_removes_it_and_second_delete_succeeds() {
    let dir = tempdir().expect("temp dir");
    let store = FsStore::new(dir.path());
    let hash = ChunkHash::from_bytes([3u8; 32]);
    store.write_chunk(&hash, b"to delete").await.expect("write");
    store.delete_chunk(&hash).await.expect("first delete");
    assert!(
        !store
            .has_chunk(&hash)
            .await
            .expect("has_chunk after delete"),
        "has_chunk must be false after delete"
    );
    store
        .delete_chunk(&hash)
        .await
        .expect("second delete must succeed; a sweep re-running over its own list is ordinary");
}

/// No `.tmp` file survives a successful write, and the final file holds the exact payload.
#[tokio::test]
async fn no_tmp_file_remains_and_final_path_holds_full_payload() {
    let dir = tempdir().expect("temp dir");
    let store = FsStore::new(dir.path());
    let hash = ChunkHash::from_bytes([4u8; 32]);
    let payload = b"full payload bytes";
    store.write_chunk(&hash, payload).await.expect("write");
    assert_eq!(
        count_tmp_files(dir.path()),
        0,
        "no .tmp file should survive a successful write"
    );
    let hex = hash.to_string();
    let final_path = dir.path().join(&hex[..2]).join(&hex);
    assert_eq!(
        std::fs::read(&final_path).expect("final file must exist"),
        payload,
        "final file must hold the exact bytes that were written"
    );
}

/// Two clones of one `FsStore` write different chunks concurrently without temp-name collision.
#[tokio::test]
async fn two_clones_write_different_chunks_concurrently() {
    let dir = tempdir().expect("temp dir");
    let store = FsStore::new(dir.path());
    let s1 = store.clone();
    let s2 = store.clone();
    let h1 = ChunkHash::from_bytes([5u8; 32]);
    let h2 = ChunkHash::from_bytes([6u8; 32]);
    let (r1, r2) = tokio::join!(
        s1.write_chunk(&h1, b"chunk-one"),
        s2.write_chunk(&h2, b"chunk-two"),
    );
    r1.expect("concurrent write via clone 1");
    r2.expect("concurrent write via clone 2");
    assert_eq!(
        store.read_chunk(&h1).await.expect("read h1"),
        b"chunk-one",
        "clone 1 chunk must read back correctly"
    );
    assert_eq!(
        store.read_chunk(&h2).await.expect("read h2"),
        b"chunk-two",
        "clone 2 chunk must read back correctly"
    );
}

/// After one write, exactly one file exists at `<root>/<first-two-hex>/<full-64-hex>`.
#[tokio::test]
async fn fan_out_layout_matches_documented_scheme() {
    let dir = tempdir().expect("temp dir");
    let store = FsStore::new(dir.path());
    let hash = ChunkHash::from_bytes([7u8; 32]);
    store.write_chunk(&hash, b"any bytes").await.expect("write");
    let hex = hash.to_string();
    assert_eq!(
        hex.len(),
        64,
        "ChunkHash Display must produce exactly 64 hex chars"
    );
    let expected_path = dir.path().join(&hex[..2]).join(&hex);
    assert!(
        expected_path.exists(),
        "chunk must live at <root>/<first-two-hex>/<full-64-hex>"
    );
    assert_eq!(
        count_all_files(dir.path()),
        1,
        "exactly one file must exist in the store tree after one write"
    );
}
