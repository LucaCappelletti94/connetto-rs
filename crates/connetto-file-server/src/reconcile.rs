//! The boot pass that brings the chunk store and a restored database back into step (R70).

use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, SystemTime};

use connetto_file_core::{ChunkHash, FileId};
use diesel_async::{AsyncConnection, AsyncConnectionCore, AsyncPgConnection, RunQueryDsl};
use thiserror::Error;

use crate::caller::{CallerSettings, attributions_of_key};
use crate::{functions, router::DbPool, schema::ConnettoFileSchema, store::AnyStore};

/// What one boot pass changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StoreReconciled {
    /// Stored chunks no registry row named, deleted from the store.
    pub orphans_removed: usize,
    /// Files this pass marked lost.
    pub lost: Vec<FileId>,
}

/// Error returned by [`reconcile_store`].
#[derive(Debug, Error)]
pub enum ReconcileError {
    /// Database error outside any one file's marking.
    #[error("database: {0}")]
    Db(#[from] diesel::result::Error),
    /// Connection pool error.
    #[error("pool: {0}")]
    Pool(String),
    /// The chunk store could not be listed, probed or written.
    #[error("store: {0}")]
    Store(#[from] crate::store::StoreError),
    /// The grace window reaches back before the clock's epoch.
    #[error("grace period out of range")]
    GracePeriodOutOfRange,
    /// Marking one file lost rolled back, most likely because the setter refused `lost`.
    #[error("marking file {file_id} lost: {source}")]
    Setter {
        /// The file whose marking rolled back.
        file_id: FileId,
        /// What the database answered.
        source: diesel::result::Error,
    },
}

impl<E: std::error::Error + 'static> From<bb8::RunError<E>> for ReconcileError {
    fn from(e: bb8::RunError<E>) -> Self {
        Self::Pool(e.to_string())
    }
}

/// Deletes stored chunks no registry row names once past `grace`, and marks lost every file whose chunks are gone.
///
/// # Errors
///
/// [`ReconcileError::Setter`] naming the file whose marking failed,
/// [`ReconcileError::Store`] when the store cannot be listed or probed or an
/// orphan cannot be deleted, and [`ReconcileError::Db`] or
/// [`ReconcileError::Pool`] for the database.
pub async fn reconcile_store<S: ConnettoFileSchema>(
    pool: &DbPool,
    store: &AnyStore,
    settings: &CallerSettings,
    grace: Duration,
) -> Result<StoreReconciled, ReconcileError> {
    let cutoff = SystemTime::now()
        .checked_sub(grace)
        .ok_or(ReconcileError::GracePeriodOutOfRange)?;
    // A PUT writes only under an existing registry row, so every chunk in a listing taken first has its row in the later read.
    // A declaration landing after that read on another replica is caught by the claim each deletion takes first.
    let listed = store.list().await?;
    let mut conn = pool.get().await?;
    let registry: Vec<(Vec<u8>, String)> = S::registry_rows_stmt().load(&mut conn).await?;

    let held: HashSet<[u8; 32]> = listed.iter().map(|c| *c.hash.as_bytes()).collect();
    let known: HashSet<&[u8]> = registry.iter().map(|(hash, _)| hash.as_slice()).collect();

    let mut outcome = StoreReconciled::default();
    for chunk in &listed {
        if chunk.modified > cutoff || known.contains(chunk.hash.as_bytes().as_slice()) {
            continue;
        }
        let hash = chunk.hash.as_bytes().to_vec();
        // A `deleting` row makes a concurrent intent or PUT refuse, as during the sweep.
        if conn
            .execute_returning_count(S::claim_orphan_stmt(hash.clone()))
            .await?
            == 0
        {
            continue;
        }
        // A failed deletion leaves the claim for the sweep to finish.
        store.delete(&chunk.hash).await?;
        conn.execute_returning_count(S::delete_registry_row_stmt(hash))
            .await?;
        outcome.orphans_removed += 1;
    }

    let mut missing: Vec<Vec<u8>> = Vec::new();
    for (hash, state) in registry {
        let Ok(bytes) = <[u8; 32]>::try_from(hash.as_slice()) else {
            continue;
        };
        // Probed again because another replica may have finished a PUT since the listing.
        if state == "stored"
            && !held.contains(&bytes)
            && !store.exists(&ChunkHash::from_bytes(bytes)).await?
        {
            missing.push(hash);
        }
    }
    if missing.is_empty() {
        return Ok(outcome);
    }

    let rows: Vec<(Vec<u8>, String, i64)> = S::stored_rows_naming_stmt(missing.clone())
        .load(&mut conn)
        .await?;
    let mut files: BTreeMap<Vec<u8>, BTreeMap<String, i64>> = BTreeMap::new();
    for (file_id, key, len) in rows {
        *files.entry(file_id).or_default().entry(key).or_default() += len;
    }
    for (file_id, manifests) in files {
        let Ok(bytes) = <[u8; 32]>::try_from(file_id.as_slice()) else {
            continue;
        };
        let id = FileId::from_bytes(bytes);
        let marked = mark_lost::<S>(&mut conn, settings, &file_id, &manifests, &missing)
            .await
            .map_err(|source| ReconcileError::Setter {
                file_id: id,
                source,
            })?;
        if marked {
            outcome.lost.push(id);
        }
    }

    // Last, so a pass stopped part way finds the same chunks again at the next boot.
    conn.execute_returning_count(S::unstore_chunks_stmt(missing.clone()))
        .await?;
    conn.execute_returning_count(S::mark_registry_pending_stmt(missing))
        .await?;
    Ok(outcome)
}

/// One file's manifests turn lost and the setter hears `lost`, all or nothing, returning whether any manifest turned.
///
/// A manifest another replica's pass already marked is skipped, so its tally and the setter see one transition.
async fn mark_lost<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    settings: &CallerSettings,
    file_id: &[u8],
    manifests: &BTreeMap<String, i64>,
    missing: &[Vec<u8>],
) -> Result<bool, diesel::result::Error> {
    conn.transaction::<bool, diesel::result::Error, _>(async move |c| {
        let mut marked = false;
        for (key, missing_bytes) in manifests {
            if c.execute_returning_count(S::mark_manifest_lost_stmt(
                file_id.to_vec(),
                key.clone(),
                *missing_bytes,
            ))
            .await?
                == 0
            {
                continue;
            }
            marked = true;
            c.execute_returning_count(S::unstore_manifest_chunks_stmt(
                file_id.to_vec(),
                key.clone(),
                missing.to_vec(),
            ))
            .await?;
            for attribution in attributions_of_key(settings, key) {
                diesel::select(functions::connetto_set_content_state(
                    file_id,
                    "lost",
                    attribution,
                ))
                .get_result::<Option<Vec<u8>>>(c)
                .await?;
            }
        }
        Ok(marked)
    })
    .await
}
