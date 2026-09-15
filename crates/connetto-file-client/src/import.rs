//! Import pipeline: plan, chunk storage and replica application.

use std::io::{Read, Seek};

use connetto_client::{ClientError, ConnettoConnection, ImportChoices, ImportOutcome, ImportPlan};
use connetto_core::traits::Transport;
use connetto_file_core::{ChunkHash, ChunkStore, EncryptingStore, Manifest, MaybeSend};

use crate::archive::{CHUNK_PREFIX, validate_import};
use crate::db;
use crate::error::ContentError;

/// A checked device archive ready to restore with its content.
///
/// The source stays open inside `replica` so chunks are read one at a time
/// during `write_import_chunks` rather than held all at once.
#[must_use = "pass this plan and import choices to apply_local_data_import"]
#[derive(Debug)]
pub struct ContentImportPlan<R> {
    pub(crate) replica: ImportPlan<R>,
    pub(crate) manifests: Vec<Manifest>,
    pub(crate) chunks: Vec<ChunkHash>,
}

impl<R> ContentImportPlan<R> {
    /// The replica plan, including collisions the application must present.
    pub fn replica_plan(&self) -> &ImportPlan<R> {
        &self.replica
    }

    /// How many unsent content files the archive restores.
    #[must_use]
    pub fn content_files(&self) -> usize {
        self.manifests.len()
    }
}

pub(crate) fn prepare_content_import<T: Transport, R: Read + Seek>(
    connection: &mut ConnettoConnection<T>,
    source: R,
) -> Result<ContentImportPlan<R>, ContentError> {
    let mut replica = connection.import_local_data(source)?;
    let (manifests, chunks) = validate_import(&mut replica)?;
    Ok(ContentImportPlan {
        replica,
        manifests,
        chunks,
    })
}

/// Reads each distinct chunk from the archive and writes it to the store,
/// one chunk at a time with one reused buffer.
pub(crate) async fn write_import_chunks<B, R>(
    store: &B,
    root_key: &[u8; 32],
    plan: &mut ContentImportPlan<R>,
) -> Result<(), ContentError>
where
    B: ChunkStore + Clone + Sync + MaybeSend + 'static,
    R: Read + Seek,
{
    let enc_store = EncryptingStore::new(store.clone(), root_key);
    // Destructure so the replica and chunk-list borrows are disjoint.
    let ContentImportPlan {
        ref mut replica,
        ref chunks,
        ..
    } = *plan;
    let mut buf = Vec::new();
    for hash in chunks {
        let chunk_path = format!("{CHUNK_PREFIX}{hash}");
        replica.read_attachment(&chunk_path, &mut buf)?;
        enc_store
            .write_chunk(hash, &buf)
            .await
            .map_err(|error| ContentError::Store(error.to_string()))?;
    }
    Ok(())
}

pub(crate) fn apply_content_import<T: Transport, R>(
    connection: &mut ConnettoConnection<T>,
    plan: &ContentImportPlan<R>,
    choices: &ImportChoices,
) -> Result<ImportOutcome, ContentError> {
    connection
        .apply_import_with_bookkeeping(&plan.replica, choices, |database| {
            for manifest in &plan.manifests {
                db::put_manifest(database, manifest)?;
                db::enqueue(database, manifest.file_id())?;
            }
            Ok::<(), ClientError>(())
        })
        .map_err(Into::into)
}
