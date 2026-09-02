//! Encrypting chunk store: XChaCha20-Poly1305 over optional zstd compression.
//!
//! The stored format for each chunk is:
//! ```text
//! nonce[24] || ciphertext
//! ```
//! where the AEAD plaintext is `flag[1] || payload` and the chunk's plaintext
//! hash bytes serve as authenticated associated data, binding each ciphertext
//! to its store key.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use thiserror::Error;

use crate::identity::ChunkHash;
use crate::store::ChunkStore;

/// Context string for BLAKE3 key derivation.
///
/// The chunk encryption key is `blake3::derive_key(PURPOSE_LABEL, root_key)`.
/// Changing this label rotates all existing chunk keys.
pub const PURPOSE_LABEL: &str = "connetto-file-core 2026-09-02 chunk encryption key";

const NONCE_LEN: usize = 24;
const FLAG_COMPRESSED: u8 = 0x01;
const FLAG_RAW: u8 = 0x00;

/// Errors produced by [`EncryptingStore`].
#[derive(Debug, Error)]
pub enum EncryptStoreError<E: std::error::Error + Send + Sync + 'static> {
    /// Random nonce generation failed.
    #[error("nonce generation failed: {0}")]
    Nonce(getrandom::Error),
    /// XChaCha20-Poly1305 encryption failed.
    #[error("encryption failed")]
    Encrypt,
    /// XChaCha20-Poly1305 decryption rejected the ciphertext.
    #[error("decryption failed: ciphertext may be tampered")]
    Decrypt,
    /// zstd compression failed.
    #[error("compression failed")]
    Compress(#[source] std::io::Error),
    /// zstd decompression failed.
    #[error("decompression failed")]
    Decompress(#[source] std::io::Error),
    /// The bytes retrieved from the underlying store have an unexpected format.
    #[error("stored chunk has unexpected format")]
    BadFormat,
    /// The underlying store returned an error.
    #[error(transparent)]
    Inner(E),
}

/// Encrypting decorator over any [`ChunkStore`].
///
/// On write, each chunk is optionally zstd-compressed (the flag byte records
/// whether compression was applied before encryption), then encrypted with
/// XChaCha20-Poly1305 under a fresh 24-byte random nonce. On read the process
/// is reversed and the original plaintext is returned.
///
/// The chunk encryption key is derived from the caller-supplied root key via
/// `blake3::derive_key` with [`PURPOSE_LABEL`] as the context string. The
/// plaintext chunk hash bytes serve as authenticated associated data.
pub struct EncryptingStore<S: ChunkStore> {
    inner: S,
    /// Derived chunk key. Never the root key itself.
    key: [u8; 32],
    skip_compression: bool,
}

impl<S: ChunkStore> EncryptingStore<S> {
    /// Wraps `inner` with encryption and compression enabled.
    ///
    /// Use for text, scientific, and generic MIME classes where zstd reduces
    /// storage significantly. The chunk key is derived from `root_key` using
    /// [`PURPOSE_LABEL`].
    pub fn new(inner: S, root_key: &[u8; 32]) -> Self {
        Self {
            inner,
            key: blake3::derive_key(PURPOSE_LABEL, root_key),
            skip_compression: false,
        }
    }

    /// Wraps `inner` with encryption and a configurable compression setting.
    ///
    /// Pass `skip_compression = true` for already-compressed content classes
    /// (JPEG, PNG, video, gzip, zip) where zstd produces no gain. Use
    /// [`MimeClass::params`](crate::MimeClass::params) to look up the right
    /// value for a given MIME class.
    pub fn new_with(inner: S, root_key: &[u8; 32], skip_compression: bool) -> Self {
        Self {
            inner,
            key: blake3::derive_key(PURPOSE_LABEL, root_key),
            skip_compression,
        }
    }
}

impl<S: ChunkStore> ChunkStore for EncryptingStore<S> {
    type Error = EncryptStoreError<S::Error>;

    fn write_chunk(&self, hash: &ChunkHash, data: &[u8]) -> Result<(), Self::Error> {
        let (flag, payload) =
            compress_payload(data, self.skip_compression).map_err(EncryptStoreError::Compress)?;

        let mut flagged = Vec::with_capacity(1 + payload.len());
        flagged.push(flag);
        flagged.extend_from_slice(&payload);

        let nonce_bytes = fresh_nonce().map_err(EncryptStoreError::Nonce)?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let cipher = make_cipher(&self.key);
        let aead_payload = Payload {
            msg: &flagged,
            aad: hash.as_bytes().as_slice(),
        };
        let ciphertext = cipher
            .encrypt(nonce, aead_payload)
            .map_err(|_| EncryptStoreError::Encrypt)?;

        let mut stored = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        stored.extend_from_slice(&nonce_bytes);
        stored.extend_from_slice(&ciphertext);

        self.inner
            .write_chunk(hash, &stored)
            .map_err(EncryptStoreError::Inner)
    }

    fn read_chunk(&self, hash: &ChunkHash) -> Result<Vec<u8>, Self::Error> {
        let stored = self
            .inner
            .read_chunk(hash)
            .map_err(EncryptStoreError::Inner)?;

        // Minimum: 24-byte nonce + 1 flag byte + 16-byte Poly1305 tag.
        if stored.len() < NONCE_LEN + 17 {
            return Err(EncryptStoreError::BadFormat);
        }

        let nonce = XNonce::from_slice(&stored[..NONCE_LEN]);
        let ciphertext = &stored[NONCE_LEN..];
        let cipher = make_cipher(&self.key);
        let aead_payload = Payload {
            msg: ciphertext,
            aad: hash.as_bytes().as_slice(),
        };
        let flagged = cipher
            .decrypt(nonce, aead_payload)
            .map_err(|_| EncryptStoreError::Decrypt)?;

        let (&flag, payload) = flagged.split_first().ok_or(EncryptStoreError::BadFormat)?;

        match flag {
            FLAG_COMPRESSED => zstd::decode_all(payload).map_err(EncryptStoreError::Decompress),
            FLAG_RAW => Ok(payload.to_vec()),
            _ => Err(EncryptStoreError::BadFormat),
        }
    }

    fn has_chunk(&self, hash: &ChunkHash) -> Result<bool, Self::Error> {
        self.inner.has_chunk(hash).map_err(EncryptStoreError::Inner)
    }
}

/// Compresses `data` at zstd level 3 if `skip` is false. Returns the flag byte
/// and the (possibly compressed) payload. If compression produces a larger
/// result the raw bytes are returned with `FLAG_RAW`.
fn compress_payload(data: &[u8], skip: bool) -> Result<(u8, Vec<u8>), std::io::Error> {
    if skip {
        return Ok((FLAG_RAW, data.to_vec()));
    }
    let compressed = zstd::encode_all(data, 3)?;
    if compressed.len() < data.len() {
        Ok((FLAG_COMPRESSED, compressed))
    } else {
        Ok((FLAG_RAW, data.to_vec()))
    }
}

fn fresh_nonce() -> Result<[u8; NONCE_LEN], getrandom::Error> {
    let mut bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

fn make_cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key).expect("key is always 32 bytes")
}
