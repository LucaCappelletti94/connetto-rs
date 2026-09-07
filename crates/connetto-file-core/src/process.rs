//! File processing: streaming identity and chunking in one pass.

use std::io::Read;

use fastcdc::v2020::StreamCDC;
use thiserror::Error;

use crate::identity::{ChunkHash, FileId};
use crate::manifest::{ChunkMeta, Manifest};
use crate::maybe_send::MaybeSend;
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
/// `R: MaybeSend` is required so callers on multi-threaded native runtimes can
/// hold this future across `spawn` boundaries. On wasm the bound is vacuous.
pub async fn process_file_from_reader<R, S>(
    mut reader: R,
    mime: MimeClass,
    store: &S,
) -> Result<Manifest, ProcessError<S::Error>>
where
    R: Read + MaybeSend,
    S: ChunkStore,
{
    let params = mime.params();
    let max = usize::try_from(params.max).expect("max chunk size fits in usize");
    let mut file_hasher = blake3::Hasher::new();
    let mut chunk_metas = Vec::new();
    let mut buf = read_prefix(&mut reader, max + 1)?;

    if buf.len() <= max {
        store_chunk(&buf, &mut file_hasher, &mut chunk_metas, store)
            .await
            .map_err(ProcessError::Store)?;
    } else {
        let tail = buf.split_off(max);
        if params.avg == 0 {
            store_chunk(&buf, &mut file_hasher, &mut chunk_metas, store)
                .await
                .map_err(ProcessError::Store)?;
            let rest = std::io::Cursor::new(tail).chain(reader);
            stream_slabs(rest, max, &mut file_hasher, &mut chunk_metas, store).await?;
        } else {
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
            )
            .await?;
        }
    }

    let file_id = FileId::from_bytes(*file_hasher.finalize().as_bytes());
    Ok(Manifest::new(file_id, chunk_metas))
}

/// Processes a file slice in one pass.
///
/// Thin wrapper over [`process_file_from_reader`]: `&[u8]` implements [`Read`]
/// with no allocation.
pub async fn process_file<S: ChunkStore>(
    data: &[u8],
    mime: MimeClass,
    store: &S,
) -> Result<Manifest, ProcessError<S::Error>> {
    process_file_from_reader(data, mime, store).await
}

/// Reassembles the original file bytes from `manifest` by reading chunks from
/// `store` in order.
pub async fn reassemble<S: ChunkStore>(
    manifest: &Manifest,
    store: &S,
) -> Result<Vec<u8>, S::Error> {
    let capacity: usize = manifest
        .chunks()
        .iter()
        .filter_map(|c| usize::try_from(c.len).ok())
        .sum();
    let mut result = Vec::with_capacity(capacity);
    for meta in manifest.chunks() {
        result.extend_from_slice(&store.read_chunk(&meta.hash).await?);
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Reads up to `limit` bytes from `reader`, stopping at EOF.
fn read_prefix<R: Read>(reader: &mut R, limit: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = Vec::with_capacity(limit);
    let mut tmp = [0u8; 8192];
    while buf.len() < limit {
        let remaining = limit - buf.len();
        let to_read = remaining.min(tmp.len());
        let n = reader.read(&mut tmp[..to_read])?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(buf)
}

/// Hashes `data`, writes it to `store`, and records the chunk metadata.
async fn store_chunk<S: ChunkStore>(
    data: &[u8],
    file_hasher: &mut blake3::Hasher,
    metas: &mut Vec<ChunkMeta>,
    store: &S,
) -> Result<(), S::Error> {
    file_hasher.update(data);
    let chunk_hash = ChunkHash::from_bytes(*blake3::hash(data).as_bytes());
    store.write_chunk(&chunk_hash, data).await?;
    metas.push(ChunkMeta {
        hash: chunk_hash,
        len: u64::try_from(data.len()).expect("length fits in u64"),
    });
    Ok(())
}

/// Streams fixed-size slabs from `reader` until exhausted.
async fn stream_slabs<R, S>(
    mut reader: R,
    slab_size: usize,
    file_hasher: &mut blake3::Hasher,
    metas: &mut Vec<ChunkMeta>,
    store: &S,
) -> Result<(), ProcessError<S::Error>>
where
    R: Read + MaybeSend,
    S: ChunkStore,
{
    loop {
        let slab = read_prefix(&mut reader, slab_size)?;
        if slab.is_empty() {
            break;
        }
        store_chunk(&slab, file_hasher, metas, store)
            .await
            .map_err(ProcessError::Store)?;
    }
    Ok(())
}

/// Streams CDC chunks from `reader` and writes each to `store`.
async fn stream_cdc_chunks<R, S>(
    reader: R,
    min: u32,
    avg: u32,
    max: u32,
    file_hasher: &mut blake3::Hasher,
    metas: &mut Vec<ChunkMeta>,
    store: &S,
) -> Result<(), ProcessError<S::Error>>
where
    R: Read + MaybeSend,
    S: ChunkStore,
{
    let chunker = StreamCDC::new(reader, min, avg, max);
    for result in chunker {
        let chunk = result.map_err(|e| ProcessError::Read(e.into()))?;
        file_hasher.update(&chunk.data);
        let chunk_hash = ChunkHash::from_bytes(*blake3::hash(&chunk.data).as_bytes());
        store
            .write_chunk(&chunk_hash, &chunk.data)
            .await
            .map_err(ProcessError::Store)?;
        metas.push(ChunkMeta {
            hash: chunk_hash,
            len: u64::try_from(chunk.length).expect("chunk length fits in u64"),
        });
    }
    Ok(())
}
