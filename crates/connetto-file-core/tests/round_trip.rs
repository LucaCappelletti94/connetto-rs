//! Property tests for the file-core round-trip. Native-only: proptest forks a
//! subprocess for failure persistence, which is unavailable on wasm32.

#![cfg(not(target_arch = "wasm32"))]

use connetto_file_core::{
    EncryptingStore, FileId, MemStore, MimeClass, process_file, process_file_from_reader,
    reassemble,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Chunk, compress, encrypt, store, read, decrypt, decompress, reassemble
    /// must yield the original bytes for any input with the Generic MIME class.
    #[test]
    fn round_trip_generic(data in proptest::collection::vec(any::<u8>(), 0..=512_000)) {
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = process_file(&data, MimeClass::Generic, &store).unwrap();
        let recovered = reassemble(&manifest, &store).unwrap();
        prop_assert_eq!(data, recovered);
    }

    /// The file identity is stable: the same bytes produce the same `FileId`
    /// regardless of which MIME class (and therefore chunking parameters) is used.
    #[test]
    fn identity_stable_across_mime_classes(data in proptest::collection::vec(any::<u8>(), 0..=8192)) {
        let key = [0u8; 32];
        let s1 = EncryptingStore::new(MemStore::new(), &key);
        let s2 = EncryptingStore::new_with(MemStore::new(), &key, true);
        let s3 = EncryptingStore::new(MemStore::new(), &key);

        let id1: FileId = process_file(&data, MimeClass::Fasta, &s1).unwrap().file_id();
        let id2: FileId = process_file(&data, MimeClass::Jpeg, &s2).unwrap().file_id();
        let id3: FileId = process_file(&data, MimeClass::Csv, &s3).unwrap().file_id();

        prop_assert_eq!(id1, id2);
        prop_assert_eq!(id1, id3);
    }

    /// A file whose total length is at or under the class's max chunk size must
    /// produce exactly one chunk.
    #[test]
    fn small_file_is_one_chunk(
        // Generic max is 4 MiB, limited to 4096 here to keep tests fast.
        data in proptest::collection::vec(any::<u8>(), 0..=4096),
    ) {
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = process_file(&data, MimeClass::Generic, &store).unwrap();
        prop_assert_eq!(manifest.chunks().len(), 1, "short file must be one chunk");
    }

    /// Round-trip for FASTA data (text class, compression enabled).
    #[test]
    fn round_trip_fasta(data in proptest::collection::vec(any::<u8>(), 0..=131_072)) {
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = process_file(&data, MimeClass::Fasta, &store).unwrap();
        let recovered = reassemble(&manifest, &store).unwrap();
        prop_assert_eq!(data, recovered);
    }

    /// Round-trip for JPEG data (compressed media class, no compression).
    #[test]
    fn round_trip_jpeg(data in proptest::collection::vec(any::<u8>(), 0..=131_072)) {
        let store = EncryptingStore::new_with(MemStore::new(), &[0u8; 32], true);
        let manifest = process_file(&data, MimeClass::Jpeg, &store).unwrap();
        let recovered = reassemble(&manifest, &store).unwrap();
        prop_assert_eq!(data, recovered);
    }

    /// A tampered ciphertext must be refused at decrypt time.
    #[test]
    fn tampered_ciphertext_rejected(
        data in proptest::collection::vec(any::<u8>(), 1..=1024),
        flip_offset in 0usize..100usize,
    ) {
        use connetto_file_core::ChunkStore as _;

        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = process_file(&data, MimeClass::Generic, &store).unwrap();
        let chunk_hash = &manifest.chunks()[0].hash;

        // Inject a junk block at the chunk hash in a fresh store.
        let junk = MemStore::new();
        let flip = u8::try_from(flip_offset).expect("flip_offset < 256 by proptest bounds");
        let junk_bytes: Vec<u8> = (0..128_u8).map(|i| i.wrapping_add(flip)).collect();
        junk.write_chunk(chunk_hash, &junk_bytes).unwrap();
        let bad_store = EncryptingStore::new(junk, &[0u8; 32]);

        prop_assert!(
            bad_store.read_chunk(chunk_hash).is_err(),
            "tampered bytes must not decrypt"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The reader path and the slice path produce identical file identities and
    /// manifests for any input with the Generic MIME class.
    #[test]
    fn reader_matches_slice_generic(
        data in proptest::collection::vec(any::<u8>(), 0..=512_000),
    ) {
        let key = [0u8; 32];
        let store_s = EncryptingStore::new(MemStore::new(), &key);
        let store_r = EncryptingStore::new(MemStore::new(), &key);
        let mf_slice = process_file(&data, MimeClass::Generic, &store_s).unwrap();
        let mf_read = process_file_from_reader(
            std::io::Cursor::new(&data[..]),
            MimeClass::Generic,
            &store_r,
        )
        .unwrap();
        prop_assert_eq!(mf_slice.file_id(), mf_read.file_id());
        prop_assert_eq!(mf_slice.chunks(), mf_read.chunks());
    }

    /// The reader path round-trips correctly for FASTA data (text class).
    #[test]
    fn reader_round_trip_fasta(
        data in proptest::collection::vec(any::<u8>(), 0..=131_072),
    ) {
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let mf = process_file_from_reader(
            std::io::Cursor::new(&data[..]),
            MimeClass::Fasta,
            &store,
        )
        .unwrap();
        let recovered = reassemble(&mf, &store).unwrap();
        prop_assert_eq!(data, recovered);
    }

    /// The reader path round-trips correctly for JPEG data (media class).
    #[test]
    fn reader_round_trip_jpeg(
        data in proptest::collection::vec(any::<u8>(), 0..=131_072),
    ) {
        let store = EncryptingStore::new_with(MemStore::new(), &[0u8; 32], true);
        let mf = process_file_from_reader(
            std::io::Cursor::new(&data[..]),
            MimeClass::Jpeg,
            &store,
        )
        .unwrap();
        let recovered = reassemble(&mf, &store).unwrap();
        prop_assert_eq!(data, recovered);
    }
}

/// Generates `len` deterministic bytes from a seeded xorshift32 state.
///
/// The low byte of the state after each step is taken via `to_le_bytes()[0]`,
/// which avoids any cast: the array index produces a `u8` directly.
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

/// Wraps a `Read` impl and caps each call to at most 4093 bytes, simulating
/// incremental delivery from a slow or framed upstream transport.
struct ChoppedRead<R>(R);

impl<R: std::io::Read> std::io::Read for ChoppedRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(4093);
        self.0.read(&mut buf[..n])
    }
}

/// (a) 5 MiB Generic-class: exercises the CDC multi-chunk streaming branch.
///
/// Every proptest input for Generic is bounded at 512 `KiB`, so the `> max`
/// branch in `process_file_from_reader` is never reached by the proptest
/// suite. This test uses seeded deterministic bytes and verifies that the
/// reader path produces the same file identity, manifest, and round-trip
/// result as the slice path.
#[test]
fn reader_multi_chunk_generic_5mib() {
    const SIZE: usize = 5 * 1024 * 1024;
    let data = xorshift_bytes(0xdead_beef, SIZE);
    let key = [0u8; 32];

    let store_s = EncryptingStore::new(MemStore::new(), &key);
    let mf_slice = process_file(&data, MimeClass::Generic, &store_s).unwrap();

    let store_r = EncryptingStore::new(MemStore::new(), &key);
    let mf_reader = process_file_from_reader(
        std::io::Cursor::new(&data[..]),
        MimeClass::Generic,
        &store_r,
    )
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
    let recovered = reassemble(&mf_reader, &store_r).unwrap();
    assert_eq!(
        data.as_slice(),
        recovered.as_slice(),
        "round-trip must restore original bytes"
    );
}

/// (b) 17 MiB JPEG-class: exercises the fixed-slab multi-slab streaming branch.
///
/// JPEG uses fixed 16 MiB slabs with `avg == 0`. A 17 MiB input crosses the
/// slab boundary and forces `stream_slabs` to emit a second chunk. The same
/// identity, manifest, and round-trip checks as (a) apply.
#[test]
fn reader_multi_slab_jpeg_17mib() {
    const SIZE: usize = 17 * 1024 * 1024;
    let data = xorshift_bytes(0xcafe_babe, SIZE);
    let key = [0u8; 32];

    let store_s = EncryptingStore::new_with(MemStore::new(), &key, true);
    let mf_slice = process_file(&data, MimeClass::Jpeg, &store_s).unwrap();

    let store_r = EncryptingStore::new_with(MemStore::new(), &key, true);
    let mf_reader =
        process_file_from_reader(std::io::Cursor::new(&data[..]), MimeClass::Jpeg, &store_r)
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
    let recovered = reassemble(&mf_reader, &store_r).unwrap();
    assert_eq!(
        data.as_slice(),
        recovered.as_slice(),
        "round-trip must restore original bytes"
    );
}

/// (c) Same 5 MiB Generic data fed through `ChoppedRead`: proves incremental feeding.
///
/// `ChoppedRead` caps each `read` call to 4093 bytes. Both `read_prefix` and
/// `StreamCDC` must accumulate partial reads correctly to yield the same file
/// identity and manifest as an unrestricted `Cursor`.
#[test]
fn reader_multi_chunk_generic_short_reads() {
    const SIZE: usize = 5 * 1024 * 1024;
    let data = xorshift_bytes(0xdead_beef, SIZE);
    let key = [0u8; 32];

    let store_ref = EncryptingStore::new(MemStore::new(), &key);
    let mf_ref = process_file_from_reader(
        std::io::Cursor::new(&data[..]),
        MimeClass::Generic,
        &store_ref,
    )
    .unwrap();

    let store_chopped = EncryptingStore::new(MemStore::new(), &key);
    let mf_chopped = process_file_from_reader(
        ChoppedRead(std::io::Cursor::new(&data[..])),
        MimeClass::Generic,
        &store_chopped,
    )
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
    let recovered = reassemble(&mf_chopped, &store_chopped).unwrap();
    assert_eq!(
        data.as_slice(),
        recovered.as_slice(),
        "round-trip must restore original bytes"
    );
}
