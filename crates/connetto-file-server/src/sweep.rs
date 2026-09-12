//! Mark-sweep garbage collector.
//!
//! Database collection locks the current registry set, removes stale manifests,
//! then marks the locked rows that remain unreferenced. Intent and PUT hold the
//! same row locks while creating references or writing bytes.

use std::time::Duration;

use chrono::{TimeDelta, Utc};
use thiserror::Error;

use crate::{db, router::DbPool, schema::ConnettoFileSchema, store::AnyStore};
use connetto_file_core::ChunkHash;

/// Error returned by [`sweep`].
#[derive(Debug, Error)]
pub enum SweepError {
    /// Database error during sweep.
    #[error("database: {0}")]
    Db(#[from] diesel::result::Error),
    /// Connection pool error.
    #[error("pool: {0}")]
    Pool(String),
    /// Chunk store deletion error.
    #[error("store: {0}")]
    Store(#[from] crate::store::StoreError),
    /// Grace period Duration exceeds chrono's representable range.
    #[error("grace period out of range")]
    GracePeriodOutOfRange,
}

impl<E: std::error::Error + 'static> From<bb8::RunError<E>> for SweepError {
    fn from(e: bb8::RunError<E>) -> Self {
        Self::Pool(e.to_string())
    }
}

/// Runs one sweep cycle and returns the number of artifacts removed.
///
/// # Errors
///
/// Returns `SweepError::GracePeriodOutOfRange` if `grace` cannot be converted to a `chrono::TimeDelta`.
/// Returns `SweepError::Pool` if a database connection cannot be acquired from the pool.
/// Returns `SweepError::Db` on any database query failure.
/// Returns `SweepError::Store` if the chunk store fails to delete a chunk.
pub async fn sweep<S: ConnettoFileSchema>(
    pool: &DbPool,
    store: &AnyStore,
    grace: Duration,
) -> Result<usize, SweepError> {
    let delta = TimeDelta::from_std(grace).map_err(|_| SweepError::GracePeriodOutOfRange)?;
    let mut conn = pool.get().await?;
    let cutoff = Utc::now() - delta;

    let removed_manifests = db::prepare_sweep::<S>(&mut conn, cutoff).await?;
    let deleting = db::list_deleting_hashes::<S>(&mut conn).await?;
    drop(conn);

    // Pass 3: delete from store then remove registry row.
    let removed_chunks = delete_store_then_records::<S>(pool, store, deleting).await?;
    Ok(removed_manifests + removed_chunks)
}

/// For each hash: delete from the object store first, then remove the registry
/// row.  Store failures are preserved so the next sweep can retry.
async fn delete_store_then_records<S: ConnettoFileSchema>(
    pool: &DbPool,
    store: &AnyStore,
    raw_hashes: Vec<Vec<u8>>,
) -> Result<usize, SweepError> {
    let mut count = 0;
    let mut first_store_error: Option<SweepError> = None;
    for raw in raw_hashes {
        let arr: [u8; 32] = match raw.try_into() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let hash = ChunkHash::from_bytes(arr);
        match store.delete(&hash).await {
            Ok(()) => {
                let mut conn = pool.get().await?;
                db::delete_registry_row::<S>(&mut conn, &hash).await?;
                count += 1;
            }
            Err(e) => {
                if first_store_error.is_none() {
                    first_store_error = Some(SweepError::Store(e));
                }
            }
        }
    }
    if let Some(e) = first_store_error {
        return Err(e);
    }
    Ok(count)
}
