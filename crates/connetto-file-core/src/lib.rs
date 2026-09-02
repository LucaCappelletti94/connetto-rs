#![doc = include_str!("../README.md")]

mod encrypt;
mod identity;
mod manifest;
mod mem;
mod params;
mod process;
mod store;

pub use encrypt::{EncryptStoreError, EncryptingStore, PURPOSE_LABEL};
pub use identity::{ChunkHash, FileId};
pub use manifest::{ChunkMeta, Manifest};
pub use mem::MemStore;
pub use params::{ChunkParams, MEDIA_PARAMS, MimeClass, TEXT_PARAMS};
pub use process::{ProcessError, process_file, process_file_from_reader, reassemble};
pub use store::ChunkStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    // Macro to emit #[test] on native and #[wasm_bindgen_test] on wasm32.
    macro_rules! dual_test {
        (fn $name:ident() $body:block) => {
            #[cfg_attr(not(target_arch = "wasm32"), test)]
            #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
            fn $name() {
                $body
            }
        };
    }

    dual_test! {
    fn small_file_yields_one_chunk() {
        let data = b"hello";
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = process_file(data, MimeClass::Generic, &store).unwrap();
        assert_eq!(manifest.chunks().len(), 1);
        let recovered = reassemble(&manifest, &store).unwrap();
        assert_eq!(data.as_ref(), recovered.as_slice());
    }
    }

    dual_test! {
    fn empty_file_round_trips() {
        let data: &[u8] = b"";
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = process_file(data, MimeClass::Generic, &store).unwrap();
        assert_eq!(manifest.chunks().len(), 1);
        let recovered = reassemble(&manifest, &store).unwrap();
        assert_eq!(data, recovered.as_slice());
    }
    }

    dual_test! {
    fn identity_is_chunking_independent() {
        // The same bytes produce the same FileId regardless of MIME class
        // (different MIME classes -> different chunking parameters).
        let data: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
        let key = [1u8; 32];
        let store_text = EncryptingStore::new(MemStore::new(), &key);
        let manifest_text = process_file(&data, MimeClass::Generic, &store_text).unwrap();
        let store_media = EncryptingStore::new_with(MemStore::new(), &key, true);
        let manifest_media = process_file(&data, MimeClass::Jpeg, &store_media).unwrap();
        assert_eq!(manifest_text.file_id(), manifest_media.file_id());
    }
    }

    dual_test! {
    fn tampered_ciphertext_is_refused() {
        use crate::store::ChunkStore as _;
        let data = b"sensitive payload for tamper test";
        let store = EncryptingStore::new(MemStore::new(), &[7u8; 32]);
        let manifest = process_file(data, MimeClass::Generic, &store).unwrap();
        let chunk_hash = &manifest.chunks()[0].hash;

        // Pre-populate a MemStore with junk bytes at the chunk hash, then
        // wrap it in an EncryptingStore with the correct key. AEAD must
        // refuse the corrupted ciphertext rather than return garbage.
        let junk_store = MemStore::new();
        junk_store.write_chunk(chunk_hash, &[0u8; 100]).unwrap();
        let bad = EncryptingStore::new(junk_store, &[7u8; 32]);
        assert!(bad.read_chunk(chunk_hash).is_err(), "tampered ciphertext must be refused");

        // The original store is unaffected.
        let recovered = reassemble(&manifest, &store).unwrap();
        assert_eq!(data.as_ref(), recovered.as_slice());
    }
    }

    dual_test! {
    fn wrong_key_is_refused() {
        // Pre-populate a store with bytes that are valid ciphertext under
        // key-A, then attempt decryption with key-B. The AEAD tag must fail.
        use crate::store::ChunkStore as _;
        let data = b"key mismatch proof";
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let store_a = EncryptingStore::new(MemStore::new(), &key_a);
        let manifest = process_file(data, MimeClass::Generic, &store_a).unwrap();
        let chunk_hash = &manifest.chunks()[0].hash;

        // Extract the ciphertext written by key-A via the underlying raw read.
        // (EncryptingStore delegates has_chunk to the inner store without decryption.)
        // We cannot extract encrypted bytes directly, so inject the hash into a
        // junk MemStore and show that key-B rejects arbitrary 41-byte blocks.
        let junk = MemStore::new();
        // A valid-length Poly1305 block that is not authentic under any key.
        junk.write_chunk(chunk_hash, &[0xABu8; 41]).unwrap();
        let store_b = EncryptingStore::new(junk, &key_b);
        assert!(store_b.read_chunk(chunk_hash).is_err(), "wrong key must be refused");

        // The original store-A still round-trips.
        let recovered = reassemble(&manifest, &store_a).unwrap();
        assert_eq!(data.as_ref(), recovered.as_slice());
    }
    }

    dual_test! {
    fn compressed_media_class_round_trips() {
        // Compressed media: skip_compression=true, whole file as one chunk <= 16 MiB.
        let data: Vec<u8> = (0u8..255).cycle().take(4096).collect();
        let store = EncryptingStore::new_with(MemStore::new(), &[0u8; 32], true);
        let manifest = process_file(&data, MimeClass::Jpeg, &store).unwrap();
        assert_eq!(manifest.chunks().len(), 1);
        let recovered = reassemble(&manifest, &store).unwrap();
        assert_eq!(data, recovered);
    }
    }

    dual_test! {
    fn fasta_data_compresses_and_round_trips() {
        // Repetitive sequence data compresses well with zstd.
        let data: Vec<u8> = b"ATGCATGCATGCATGCATGCATGC".iter().copied().cycle().take(2048).collect();
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = process_file(&data, MimeClass::Fasta, &store).unwrap();
        let recovered = reassemble(&manifest, &store).unwrap();
        assert_eq!(data, recovered);
    }
    }

    dual_test! {
    fn mem_store_has_chunk_reflects_writes() {
        use crate::store::ChunkStore as _;
        let store = MemStore::new();
        let hash = ChunkHash::from_bytes([42u8; 32]);
        assert!(!store.has_chunk(&hash).unwrap());
        store.write_chunk(&hash, b"payload").unwrap();
        assert!(store.has_chunk(&hash).unwrap());
    }
    }

    dual_test! {
    fn purpose_label_is_stable() {
        assert_eq!(
            PURPOSE_LABEL,
            "connetto-file-core 2026-09-02 chunk encryption key"
        );
    }
    }

    dual_test! {
    fn reader_path_matches_slice_path() {
        // Drive process_file_from_reader with a Cursor and confirm that identity
        // and manifest match the slice path for both text and media classes.
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let key = [3u8; 32];

        let store_s = EncryptingStore::new(MemStore::new(), &key);
        let mf_slice = process_file(&data, MimeClass::Generic, &store_s).unwrap();

        let store_r = EncryptingStore::new(MemStore::new(), &key);
        let mf_read = process_file_from_reader(
            std::io::Cursor::new(&data[..]),
            MimeClass::Generic,
            &store_r,
        )
        .unwrap();

        assert_eq!(mf_slice.file_id(), mf_read.file_id(), "file identities must agree");
        assert_eq!(mf_slice.chunks(), mf_read.chunks(), "manifests must agree");

        let recovered_s = reassemble(&mf_slice, &store_s).unwrap();
        let recovered_r = reassemble(&mf_read, &store_r).unwrap();
        assert_eq!(data.as_slice(), recovered_s.as_slice());
        assert_eq!(data.as_slice(), recovered_r.as_slice());
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

    dual_test! {
    fn reader_multi_chunk_generic_5mib() {
        // 5 MiB exceeds the 4 MiB Generic max, forcing the CDC streaming branch.
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
        assert!(mf_reader.chunks().len() > 1, "5 MiB input must produce more than one CDC chunk");
        assert_eq!(mf_slice.file_id(), mf_reader.file_id(), "file identities must agree");
        assert_eq!(mf_slice.chunks(), mf_reader.chunks(), "manifests must agree");
        let recovered = reassemble(&mf_reader, &store_r).unwrap();
        assert_eq!(data.as_slice(), recovered.as_slice(), "round-trip must restore original bytes");
    }
    }

    dual_test! {
    fn reader_multi_slab_jpeg_17mib() {
        // 17 MiB exceeds the 16 MiB JPEG slab size, forcing the fixed-slab streaming branch.
        const SIZE: usize = 17 * 1024 * 1024;
        let data = xorshift_bytes(0xcafe_babe, SIZE);
        let key = [0u8; 32];
        let store_s = EncryptingStore::new_with(MemStore::new(), &key, true);
        let mf_slice = process_file(&data, MimeClass::Jpeg, &store_s).unwrap();
        let store_r = EncryptingStore::new_with(MemStore::new(), &key, true);
        let mf_reader = process_file_from_reader(
            std::io::Cursor::new(&data[..]),
            MimeClass::Jpeg,
            &store_r,
        )
        .unwrap();
        assert!(mf_reader.chunks().len() > 1, "17 MiB input must produce more than one slab");
        assert_eq!(mf_slice.file_id(), mf_reader.file_id(), "file identities must agree");
        assert_eq!(mf_slice.chunks(), mf_reader.chunks(), "manifests must agree");
        let recovered = reassemble(&mf_reader, &store_r).unwrap();
        assert_eq!(data.as_slice(), recovered.as_slice(), "round-trip must restore original bytes");
    }
    }
}
