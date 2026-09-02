//! File processing: streaming identity and chunking in one pass.

use std::io::Read;

use fastcdc::v2020::StreamCDC;
use thiserror::Error;

use crate::identity::{ChunkHash, FileId};
use crate::manifest::{ChunkMeta, Manifest};
use crate::params::MimeClass;
use crate::store::ChunkStore;

/// Error returned by [`process_file_from_reader`] and [`process_file`].
#[derive(Debug, Error)]
pub enum ProcessError<E: std::error::Error + Send + Sync + 'static> {
    /// Reading from the input source failed.
    #[error("read failed: {0}")]
    Read(#[from] std::io::Error),
    /// A chunk store operation failed.
    #[error(transparent)]
    Store(E),
}

/// Processes a file from a [`Read`] source in one pass: computes the content
/// identity, splits into chunks per `mime` class parameters, and writes each
/// chunk to `store`.
///
/// The identity is the plain BLAKE3 hash of the raw bytes, independent of how
/// the file is chunked. The manifest records the (hash, length) pair for each
/// chunk in order.
///
/// Files at or under the class's maximum chunk size are stored as one chunk.
/// Larger files use `StreamCDC` for text and scientific classes and fixed-size
/// slab reads for already-compressed media. Bytes are read once and never
/// required all in memory at the same time for large files.
pub fn process_file_from_reader<R: Read, S: ChunkStore>(
    mut reader: R,
    mime: MimeClass,
    store: &S,
) -> Result<Manifest, ProcessError<S::Error>> {
    let params = mime.params();
    let max = usize::try_from(params.max).expect("max chunk size fits in usize");

    let mut file_hasher = blake3::Hasher::new();
    let mut chunk_metas = Vec::new();

    // Read the first max+1 bytes to detect the file size tier. If the source
    // is exhausted before max+1 bytes are accumulated, everything fits in one chunk.
    let mut buf = read_prefix(&mut reader, max + 1)?;

    if buf.len() <= max {
        write_chunk(&buf, &mut file_hasher, &mut chunk_metas, store)
            .map_err(ProcessError::Store)?;
    } else {
        // buf holds exactly max+1 bytes. Split off the look-ahead byte.
        let tail = buf.split_off(max); // buf keeps the first max bytes, tail holds byte max

        if params.avg == 0 {
            // Fixed-size slabs: emit the first slab, then stream the rest.
            write_chunk(&buf, &mut file_hasher, &mut chunk_metas, store)
                .map_err(ProcessError::Store)?;
            let rest = std::io::Cursor::new(tail).chain(reader);
            stream_slabs(rest, max, &mut file_hasher, &mut chunk_metas, store)?;
        } else {
            // CDC chunking: chain all buffered bytes with the remaining source.
            let all = std::io::Cursor::new(buf)
                .chain(std::io::Cursor::new(tail))
                .chain(reader);
            stream_cdc_chunks(
                all,
                params.min,
                params.avg,
                params.max,
                &mut file_hasher,
                &mut chunk_metas,
                store,
            )?;
        }
    }

    let file_id = FileId::from_bytes(*file_hasher.finalize().as_bytes());
    Ok(Manifest::new(file_id, chunk_metas))
}

/// Processes a file slice in one pass: computes the content identity, splits
/// into chunks per `mime` class parameters, and writes each chunk to `store`.
///
/// This is a thin wrapper over [`process_file_from_reader`], since `&[u8]` implements
/// [`Read`] with no allocation.
///
/// The identity is the plain BLAKE3 hash of the raw bytes, independent of how
/// the file is chunked. The manifest records the (hash, length) pair for each
/// chunk in order.
///
/// Files at or under the class's maximum chunk size are stored as one chunk,
/// skipping the `StreamCDC` algorithm entirely. Larger files use content-defined
/// chunking for text and scientific classes and fixed-size slabs for
/// already-compressed media.
pub fn process_file<S: ChunkStore>(
    data: &[u8],
    mime: MimeClass,
    store: &S,
) -> Result<Manifest, ProcessError<S::Error>> {
    process_file_from_reader(data, mime, store)
}

/// Reassembles the original file bytes from `manifest` by reading chunks from
/// `store` in order and concatenating them.
pub fn reassemble<S: ChunkStore>(manifest: &Manifest, store: &S) -> Result<Vec<u8>, S::Error> {
    let capacity: usize = manifest
        .chunks()
        .iter()
        .filter_map(|c| usize::try_from(c.len).ok())
        .sum();
    let mut result = Vec::with_capacity(capacity);
    for meta in manifest.chunks() {
        result.extend_from_slice(&store.read_chunk(&meta.hash)?);
    }
    Ok(result)
}

/// Reads up to `limit` bytes from `reader`, stopping at EOF.
fn read_prefix<R: Read>(reader: &mut R, limit: usize) -> Result<Vec<u8>, std::io::Error> {
    const BATCH: usize = 8192;
    let mut buf = Vec::new();
    let mut tmp = [0u8; BATCH];
    while buf.len() < limit {
        let want = (limit - buf.len()).min(BATCH);
        match reader.read(&mut tmp[..want]) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

/// Hashes, stores, and records one chunk.
fn write_chunk<S: ChunkStore>(
    data: &[u8],
    file_hasher: &mut blake3::Hasher,
    metas: &mut Vec<ChunkMeta>,
    store: &S,
) -> Result<(), S::Error> {
    file_hasher.update(data);
    let chunk_hash = ChunkHash::from_bytes(*blake3::hash(data).as_bytes());
    store.write_chunk(&chunk_hash, data)?;
    metas.push(ChunkMeta {
        hash: chunk_hash,
        len: u64::try_from(data.len()).expect("length fits in u64"),
    });
    Ok(())
}

/// Streams fixed-size slabs of `slab_size` bytes from `reader` until exhausted.
fn stream_slabs<R: Read, S: ChunkStore>(
    mut reader: R,
    slab_size: usize,
    file_hasher: &mut blake3::Hasher,
    metas: &mut Vec<ChunkMeta>,
    store: &S,
) -> Result<(), ProcessError<S::Error>> {
    loop {
        let slab = read_prefix(&mut reader, slab_size)?;
        if slab.is_empty() {
            break;
        }
        write_chunk(&slab, file_hasher, metas, store).map_err(ProcessError::Store)?;
    }
    Ok(())
}

/// Streams CDC chunks from `reader` using `StreamCDC` with the given parameters.
fn stream_cdc_chunks<R: Read, S: ChunkStore>(
    reader: R,
    min: u32,
    avg: u32,
    max: u32,
    file_hasher: &mut blake3::Hasher,
    metas: &mut Vec<ChunkMeta>,
    store: &S,
) -> Result<(), ProcessError<S::Error>> {
    let chunker = StreamCDC::new(reader, min, avg, max);
    for result in chunker {
        let chunk = result.map_err(|e| ProcessError::Read(e.into()))?;
        file_hasher.update(&chunk.data);
        let chunk_hash = ChunkHash::from_bytes(*blake3::hash(&chunk.data).as_bytes());
        store
            .write_chunk(&chunk_hash, &chunk.data)
            .map_err(ProcessError::Store)?;
        metas.push(ChunkMeta {
            hash: chunk_hash,
            len: u64::try_from(chunk.length).expect("chunk length fits in u64"),
        });
    }
    Ok(())
}
