//! Property tests for the file-core round-trip. Native-only: proptest forks a
//! subprocess for failure persistence, which is unavailable on wasm32.

#![cfg(not(target_arch = "wasm32"))]

use connetto_file_core::{
    ChunkStore, EncryptingStore, FileId, MemStore, MimeClass, process_file,
    process_file_from_reader, reassemble,
};
use proptest::prelude::*;

/// Single-thread runtime for use inside proptest closures.
///
/// proptest runs sync test bodies. Wrapping each async call in `rt().block_on`
/// is the standard bridge: proptest owns the thread, the runtime is created and
/// dropped per-invocation, and no tokio context is active around us.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("single-thread runtime")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn round_trip_generic(data in proptest::collection::vec(any::<u8>(), 0..=512_000)) {
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = rt().block_on(process_file(&data, MimeClass::Generic, &store)).unwrap();
        let recovered = rt().block_on(reassemble(&manifest, &store)).unwrap();
        prop_assert_eq!(data, recovered);
    }

    #[test]
    fn identity_stable_across_mime_classes(data in proptest::collection::vec(any::<u8>(), 0..=8192)) {
        let key = [0u8; 32];
        let s1 = EncryptingStore::new(MemStore::new(), &key);
        let s2 = EncryptingStore::new_with(MemStore::new(), &key, true);
        let s3 = EncryptingStore::new(MemStore::new(), &key);
        let id1: FileId = rt().block_on(process_file(&data, MimeClass::Fasta, &s1)).unwrap().file_id();
        let id2: FileId = rt().block_on(process_file(&data, MimeClass::Jpeg,  &s2)).unwrap().file_id();
        let id3: FileId = rt().block_on(process_file(&data, MimeClass::Csv,   &s3)).unwrap().file_id();
        prop_assert_eq!(id1, id2);
        prop_assert_eq!(id1, id3);
    }

    #[test]
    fn small_file_is_one_chunk(
        data in proptest::collection::vec(any::<u8>(), 0..=4096),
    ) {
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = rt().block_on(process_file(&data, MimeClass::Generic, &store)).unwrap();
        prop_assert_eq!(manifest.chunks().len(), 1, "short file must be one chunk");
    }

    #[test]
    fn round_trip_fasta(data in proptest::collection::vec(any::<u8>(), 0..=131_072)) {
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = rt().block_on(process_file(&data, MimeClass::Fasta, &store)).unwrap();
        let recovered = rt().block_on(reassemble(&manifest, &store)).unwrap();
        prop_assert_eq!(data, recovered);
    }

    #[test]
    fn round_trip_jpeg(data in proptest::collection::vec(any::<u8>(), 0..=131_072)) {
        let store = EncryptingStore::new_with(MemStore::new(), &[0u8; 32], true);
        let manifest = rt().block_on(process_file(&data, MimeClass::Jpeg, &store)).unwrap();
        let recovered = rt().block_on(reassemble(&manifest, &store)).unwrap();
        prop_assert_eq!(data, recovered);
    }

    #[test]
    fn tampered_ciphertext_rejected(
        data in proptest::collection::vec(any::<u8>(), 1..=1024),
        flip_offset in 0usize..100usize,
    ) {
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = rt().block_on(process_file(&data, MimeClass::Generic, &store)).unwrap();
        let chunk_hash = &manifest.chunks()[0].hash;

        let junk = MemStore::new();
        let flip = u8::try_from(flip_offset).expect("flip_offset < 256 by proptest bounds");
        let junk_bytes: Vec<u8> = (0..128_u8).map(|i| i.wrapping_add(flip)).collect();
        rt().block_on(junk.write_chunk(chunk_hash, &junk_bytes)).unwrap();
        let bad_store = EncryptingStore::new(junk, &[0u8; 32]);

        prop_assert!(
            rt().block_on(bad_store.read_chunk(chunk_hash)).is_err(),
            "tampered bytes must not decrypt"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn reader_matches_slice_generic(
        data in proptest::collection::vec(any::<u8>(), 0..=512_000),
    ) {
        let key = [0u8; 32];
        let store_s = EncryptingStore::new(MemStore::new(), &key);
        let store_r = EncryptingStore::new(MemStore::new(), &key);
        let mf_slice = rt().block_on(process_file(&data, MimeClass::Generic, &store_s)).unwrap();
        let mf_read = rt().block_on(process_file_from_reader(
            std::io::Cursor::new(&data[..]),
            MimeClass::Generic,
            &store_r,
        ))
        .unwrap();
        prop_assert_eq!(mf_slice.file_id(), mf_read.file_id());
        prop_assert_eq!(mf_slice.chunks(), mf_read.chunks());
    }

    #[test]
    fn reader_round_trip_fasta(
        data in proptest::collection::vec(any::<u8>(), 0..=131_072),
    ) {
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let mf = rt().block_on(process_file_from_reader(
            std::io::Cursor::new(&data[..]),
            MimeClass::Fasta,
            &store,
        ))
        .unwrap();
        let recovered = rt().block_on(reassemble(&mf, &store)).unwrap();
        prop_assert_eq!(data, recovered);
    }

    #[test]
    fn reader_round_trip_jpeg(
        data in proptest::collection::vec(any::<u8>(), 0..=131_072),
    ) {
        let store = EncryptingStore::new_with(MemStore::new(), &[0u8; 32], true);
        let mf = rt().block_on(process_file_from_reader(
            std::io::Cursor::new(&data[..]),
            MimeClass::Jpeg,
            &store,
        ))
        .unwrap();
        let recovered = rt().block_on(reassemble(&mf, &store)).unwrap();
        prop_assert_eq!(data, recovered);
    }
}

fn xorshift_bytes(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect()
}

struct ChoppedRead<R>(R);

impl<R: std::io::Read> std::io::Read for ChoppedRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(4093);
        self.0.read(&mut buf[..n])
    }
}

/// (a) 5 MiB Generic-class: exercises the CDC multi-chunk streaming branch.
#[tokio::test]
async fn reader_multi_chunk_generic_5mib() {
    const SIZE: usize = 5 * 1024 * 1024;
    let data = xorshift_bytes(0xdead_beef, SIZE);
    let key = [0u8; 32];
    let store_s = EncryptingStore::new(MemStore::new(), &key);
    let mf_slice = process_file(&data, MimeClass::Generic, &store_s)
        .await
        .unwrap();
    let store_r = EncryptingStore::new(MemStore::new(), &key);
    let mf_reader = process_file_from_reader(
        std::io::Cursor::new(&data[..]),
        MimeClass::Generic,
        &store_r,
    )
    .await
    .unwrap();
    assert!(
        mf_reader.chunks().len() > 1,
        "5 MiB input must produce more than one CDC chunk"
    );
    assert_eq!(
        mf_slice.file_id(),
        mf_reader.file_id(),
        "file identities must agree"
    );
    assert_eq!(
        mf_slice.chunks(),
        mf_reader.chunks(),
        "manifests must agree"
    );
    let recovered = reassemble(&mf_reader, &store_r).await.unwrap();
    assert_eq!(
        data.as_slice(),
        recovered.as_slice(),
        "round-trip must restore original bytes"
    );
}

/// (b) 17 MiB JPEG-class: exercises the fixed-slab multi-slab streaming branch.
#[tokio::test]
async fn reader_multi_slab_jpeg_17mib() {
    const SIZE: usize = 17 * 1024 * 1024;
    let data = xorshift_bytes(0xcafe_babe, SIZE);
    let key = [0u8; 32];
    let store_s = EncryptingStore::new_with(MemStore::new(), &key, true);
    let mf_slice = process_file(&data, MimeClass::Jpeg, &store_s)
        .await
        .unwrap();
    let store_r = EncryptingStore::new_with(MemStore::new(), &key, true);
    let mf_reader =
        process_file_from_reader(std::io::Cursor::new(&data[..]), MimeClass::Jpeg, &store_r)
            .await
            .unwrap();
    assert!(
        mf_reader.chunks().len() > 1,
        "17 MiB input must produce more than one slab"
    );
    assert_eq!(
        mf_slice.file_id(),
        mf_reader.file_id(),
        "file identities must agree"
    );
    assert_eq!(
        mf_slice.chunks(),
        mf_reader.chunks(),
        "manifests must agree"
    );
    let recovered = reassemble(&mf_reader, &store_r).await.unwrap();
    assert_eq!(
        data.as_slice(),
        recovered.as_slice(),
        "round-trip must restore original bytes"
    );
}

/// (c) Same 5 MiB Generic data fed through `ChoppedRead`: proves incremental feeding.
#[tokio::test]
async fn reader_multi_chunk_generic_short_reads() {
    const SIZE: usize = 5 * 1024 * 1024;
    let data = xorshift_bytes(0xdead_beef, SIZE);
    let key = [0u8; 32];
    let store_ref = EncryptingStore::new(MemStore::new(), &key);
    let mf_ref = process_file_from_reader(
        std::io::Cursor::new(&data[..]),
        MimeClass::Generic,
        &store_ref,
    )
    .await
    .unwrap();
    let store_chopped = EncryptingStore::new(MemStore::new(), &key);
    let mf_chopped = process_file_from_reader(
        ChoppedRead(std::io::Cursor::new(&data[..])),
        MimeClass::Generic,
        &store_chopped,
    )
    .await
    .unwrap();
    assert_eq!(
        mf_ref.file_id(),
        mf_chopped.file_id(),
        "short-read must not change file identity"
    );
    assert_eq!(
        mf_ref.chunks(),
        mf_chopped.chunks(),
        "short-read must not change manifest"
    );
    let recovered = reassemble(&mf_chopped, &store_chopped).await.unwrap();
    assert_eq!(
        data.as_slice(),
        recovered.as_slice(),
        "round-trip must restore original bytes"
    );
}

/// No slab from `stream_slabs` exceeds the configured max bytes.
///
/// A Jpeg-class file of 2 * max + 1 bytes forces `stream_slabs` to produce
/// at least one full second slab; before the fix `read_prefix` looped to
/// limit + 1, so that slab was max + 1 bytes.
#[tokio::test]
async fn slab_chunks_do_not_exceed_max() {
    let params = MimeClass::Jpeg.params();
    let max = usize::try_from(params.max).expect("max fits usize");
    let size = 2 * max + 1;
    let data = xorshift_bytes(0x1234_5678, size);
    let store = EncryptingStore::new_with(MemStore::new(), &[0u8; 32], true);
    let mf = process_file(&data, MimeClass::Jpeg, &store).await.unwrap();
    let max_u64 = u64::from(params.max);
    for chunk in mf.chunks() {
        assert!(
            chunk.len <= max_u64,
            "chunk of {} bytes exceeds configured max {}",
            chunk.len,
            max_u64
        );
    }
}
