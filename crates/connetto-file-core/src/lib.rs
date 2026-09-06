#![doc = include_str!("../README.md")]

mod encrypt;
mod identity;
mod manifest;
mod maybe_send;
mod mem;
mod params;
mod process;
mod store;

pub use encrypt::{EncryptStoreError, EncryptingStore, PURPOSE_LABEL};
pub use identity::{ChunkHash, FileId};
pub use manifest::{ChunkMeta, Manifest};
pub use maybe_send::MaybeSend;
pub use mem::MemStore;
pub use params::{ChunkParams, MEDIA_PARAMS, MimeClass, TEXT_PARAMS};
pub use process::{ProcessError, process_file, process_file_from_reader, reassemble};
pub use store::ChunkStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    // Emits #[tokio::test] on native and #[wasm_bindgen_test] on wasm32.
    // Both test runners handle async fn natively.
    macro_rules! dual_test {
        (fn $name:ident() $body:block) => {
            #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
            #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
            async fn $name() {
                $body
            }
        };
    }

    dual_test! {
    fn small_file_yields_one_chunk() {
        let data = b"hello";
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = process_file(data, MimeClass::Generic, &store).await.unwrap();
        assert_eq!(manifest.chunks().len(), 1);
        let recovered = reassemble(&manifest, &store).await.unwrap();
        assert_eq!(data.as_ref(), recovered.as_slice());
    }
    }

    dual_test! {
    fn empty_file_round_trips() {
        let data: &[u8] = b"";
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = process_file(data, MimeClass::Generic, &store).await.unwrap();
        assert_eq!(manifest.chunks().len(), 1);
        let recovered = reassemble(&manifest, &store).await.unwrap();
        assert_eq!(data, recovered.as_slice());
    }
    }

    dual_test! {
    fn identity_is_chunking_independent() {
        let data: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
        let key = [1u8; 32];
        let store_text = EncryptingStore::new(MemStore::new(), &key);
        let manifest_text = process_file(&data, MimeClass::Generic, &store_text).await.unwrap();
        let store_media = EncryptingStore::new_with(MemStore::new(), &key, true);
        let manifest_media = process_file(&data, MimeClass::Jpeg, &store_media).await.unwrap();
        assert_eq!(manifest_text.file_id(), manifest_media.file_id());
    }
    }

    dual_test! {
    fn tampered_ciphertext_is_refused() {
        let data = b"sensitive payload for tamper test";
        let store = EncryptingStore::new(MemStore::new(), &[7u8; 32]);
        let manifest = process_file(data, MimeClass::Generic, &store).await.unwrap();
        let chunk_hash = &manifest.chunks()[0].hash;

        let junk_store = MemStore::new();
        junk_store.write_chunk(chunk_hash, &[0u8; 100]).await.unwrap();
        let bad = EncryptingStore::new(junk_store, &[7u8; 32]);
        assert!(bad.read_chunk(chunk_hash).await.is_err(), "tampered ciphertext must be refused");

        let recovered = reassemble(&manifest, &store).await.unwrap();
        assert_eq!(data.as_ref(), recovered.as_slice());
    }
    }

    dual_test! {
    fn wrong_key_is_refused() {
        let data = b"key mismatch proof";
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let store_a = EncryptingStore::new(MemStore::new(), &key_a);
        let manifest = process_file(data, MimeClass::Generic, &store_a).await.unwrap();
        let chunk_hash = &manifest.chunks()[0].hash;

        let junk = MemStore::new();
        junk.write_chunk(chunk_hash, &[0xABu8; 41]).await.unwrap();
        let store_b = EncryptingStore::new(junk, &key_b);
        assert!(store_b.read_chunk(chunk_hash).await.is_err(), "wrong key must be refused");

        let recovered = reassemble(&manifest, &store_a).await.unwrap();
        assert_eq!(data.as_ref(), recovered.as_slice());
    }
    }

    dual_test! {
    fn compressed_media_class_round_trips() {
        let data: Vec<u8> = (0u8..255).cycle().take(4096).collect();
        let store = EncryptingStore::new_with(MemStore::new(), &[0u8; 32], true);
        let manifest = process_file(&data, MimeClass::Jpeg, &store).await.unwrap();
        assert_eq!(manifest.chunks().len(), 1);
        let recovered = reassemble(&manifest, &store).await.unwrap();
        assert_eq!(data, recovered);
    }
    }

    dual_test! {
    fn fasta_data_compresses_and_round_trips() {
        let data: Vec<u8> = b"ATGCATGCATGCATGCATGCATGC".iter().copied().cycle().take(2048).collect();
        let store = EncryptingStore::new(MemStore::new(), &[0u8; 32]);
        let manifest = process_file(&data, MimeClass::Fasta, &store).await.unwrap();
        let recovered = reassemble(&manifest, &store).await.unwrap();
        assert_eq!(data, recovered);
    }
    }

    dual_test! {
    fn mem_store_has_chunk_reflects_writes() {
        let store = MemStore::new();
        let hash = ChunkHash::from_bytes([42u8; 32]);
        assert!(!store.has_chunk(&hash).await.unwrap());
        store.write_chunk(&hash, b"payload").await.unwrap();
        assert!(store.has_chunk(&hash).await.unwrap());
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
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let key = [3u8; 32];

        let store_s = EncryptingStore::new(MemStore::new(), &key);
        let mf_slice = process_file(&data, MimeClass::Generic, &store_s).await.unwrap();

        let store_r = EncryptingStore::new(MemStore::new(), &key);
        let mf_read = process_file_from_reader(
            std::io::Cursor::new(&data[..]),
            MimeClass::Generic,
            &store_r,
        )
        .await
        .unwrap();

        assert_eq!(mf_slice.file_id(), mf_read.file_id(), "file identities must agree");
        assert_eq!(mf_slice.chunks(), mf_read.chunks(), "manifests must agree");

        let recovered_s = reassemble(&mf_slice, &store_s).await.unwrap();
        let recovered_r = reassemble(&mf_read, &store_r).await.unwrap();
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
        const SIZE: usize = 5 * 1024 * 1024;
        let data = xorshift_bytes(0xdead_beef, SIZE);
        let key = [0u8; 32];
        let store_s = EncryptingStore::new(MemStore::new(), &key);
        let mf_slice = process_file(&data, MimeClass::Generic, &store_s).await.unwrap();
        let store_r = EncryptingStore::new(MemStore::new(), &key);
        let mf_reader = process_file_from_reader(
            std::io::Cursor::new(&data[..]),
            MimeClass::Generic,
            &store_r,
        )
        .await
        .unwrap();
        assert!(mf_reader.chunks().len() > 1, "5 MiB input must produce more than one CDC chunk");
        assert_eq!(mf_slice.file_id(), mf_reader.file_id());
        assert_eq!(mf_slice.chunks(), mf_reader.chunks());
        let recovered = reassemble(&mf_reader, &store_r).await.unwrap();
        assert_eq!(data.as_slice(), recovered.as_slice());
    }
    }

    dual_test! {
    fn reader_multi_slab_jpeg_17mib() {
        const SIZE: usize = 17 * 1024 * 1024;
        let data = xorshift_bytes(0xcafe_babe, SIZE);
        let key = [0u8; 32];
        let store_s = EncryptingStore::new_with(MemStore::new(), &key, true);
        let mf_slice = process_file(&data, MimeClass::Jpeg, &store_s).await.unwrap();
        let store_r = EncryptingStore::new_with(MemStore::new(), &key, true);
        let mf_reader = process_file_from_reader(
            std::io::Cursor::new(&data[..]),
            MimeClass::Jpeg,
            &store_r,
        )
        .await
        .unwrap();
        assert!(mf_reader.chunks().len() > 1, "17 MiB input must produce more than one slab");
        assert_eq!(mf_slice.file_id(), mf_reader.file_id());
        assert_eq!(mf_slice.chunks(), mf_reader.chunks());
        let recovered = reassemble(&mf_reader, &store_r).await.unwrap();
        assert_eq!(data.as_slice(), recovered.as_slice());
    }
    }
}
