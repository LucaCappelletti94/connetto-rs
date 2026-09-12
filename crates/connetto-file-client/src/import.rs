//! Import pipeline: plan, chunk storage and replica application.

use connetto_client::{ClientError, ConnettoConnection, ImportChoices, ImportOutcome, ImportPlan};
use connetto_core::traits::Transport;
use connetto_file_core::{ChunkHash, ChunkStore, EncryptingStore, Manifest, MaybeSend};

use crate::db;
use crate::error::ContentError;

/// A checked device archive ready to restore with its content.
#[must_use = "pass this plan and import choices to apply_local_data_import"]
#[derive(Debug)]
pub struct ContentImportPlan {
    replica: ImportPlan,
    manifests: Vec<Manifest>,
    chunks: Vec<(ChunkHash, Vec<u8>)>,
}

impl ContentImportPlan {
    /// The replica plan, including collisions the application must present.
    pub fn replica_plan(&self) -> &ImportPlan {
        &self.replica
    }

    /// How many unsent content files the archive restores.
    #[must_use]
    pub fn content_files(&self) -> usize {
        self.manifests.len()
    }
}

pub(crate) fn prepare_content_import<T: Transport>(
    connection: &mut ConnettoConnection<T>,
    bytes: &[u8],
) -> Result<ContentImportPlan, ContentError> {
    let replica = connection.import_local_data(bytes)?;
    let content = crate::archive::decode(replica.attachments())?;
    Ok(ContentImportPlan {
        replica,
        manifests: content.manifests,
        chunks: content.chunks,
    })
}

pub(crate) async fn write_import_chunks<B>(
    store: &B,
    root_key: &[u8; 32],
    plan: &ContentImportPlan,
) -> Result<(), ContentError>
where
    B: ChunkStore + Clone + Sync + MaybeSend + 'static,
{
    let store = EncryptingStore::new(store.clone(), root_key);
    for (hash, bytes) in &plan.chunks {
        store
            .write_chunk(hash, bytes)
            .await
            .map_err(|error| ContentError::Store(error.to_string()))?;
    }
    Ok(())
}

pub(crate) fn apply_content_import<T: Transport>(
    connection: &mut ConnettoConnection<T>,
    plan: &ContentImportPlan,
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
