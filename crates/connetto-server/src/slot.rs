//! Watching the replication slot the change stream reads from.
//!
//! A slot retains write-ahead log on the primary until its consumer confirms
//! it, without limit unless the deployment caps it, so a connetto server that
//! is gone or stuck makes the primary keep its journal until the disk fills and
//! writes stop for every application on it, not only for sync. Once the
//! deployment does cap it, the slot is invalidated instead, which trades the
//! outage for a hole in the change stream.
//!
//! Neither is connetto's to prevent, and both are connetto's to make visible.
//! This reads what Postgres already knows about the slot and writes it to the
//! structured log on a cadence. Deciding when a number is alarming belongs to
//! the deployment's log aggregator, as everywhere else, so the line goes out at
//! one level on a fixed interval rather than escalating on a threshold connetto
//! picked: an aggregator can graph a complete series and cannot graph one that
//! changes shape when it matters.

use core::time::Duration;

use diesel::sql_types::{BigInt, Bool, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::bb8::Pool;

/// A failure while reading the slot's state.
#[derive(Debug, thiserror::Error)]
pub enum SlotError {
    /// The connection pool could not hand out a connection.
    #[error("slot pool error: {0}")]
    Pool(String),
    /// The catalog read failed.
    #[error(transparent)]
    Query(#[from] diesel::result::Error),
}

/// What Postgres knows about one replication slot right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotLag {
    /// Write-ahead log the slot is holding on the primary: the current write
    /// position less the slot's restart position, in bytes. `None` when the
    /// slot has no restart position, which is what an invalidated slot looks
    /// like.
    pub retained_bytes: Option<i64>,
    /// Bytes that may still be written before this slot is invalidated.
    /// `None` when the deployment has set no cap, which is the default and the
    /// case where the disk fills instead.
    pub safe_bytes: Option<i64>,
    /// Postgres's own verdict on the reservation: `reserved`, `extended`,
    /// `unreserved`, or `lost`. The last means the slot is already invalidated
    /// and the changes it was holding are gone.
    pub wal_status: Option<String>,
    /// Whether a consumer is attached. A slot that is retaining log with
    /// nobody reading it is the shape that fills a disk.
    pub active: bool,
}

#[derive(QueryableByName)]
struct LagRow {
    #[diesel(sql_type = Nullable<BigInt>)]
    retained_bytes: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    safe_bytes: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    wal_status: Option<String>,
    #[diesel(sql_type = Bool)]
    active: bool,
}

/// Read one slot's state, or `None` when this database has no such slot.
///
/// Scoped to the current database for the same reason the startup check is:
/// `pg_replication_slots` lists the whole cluster and a logical slot name is
/// unique cluster-wide, so a bare name match can read a neighbour's slot.
///
/// # Errors
///
/// [`SlotError::Pool`] when no connection was available, [`SlotError::Query`]
/// when the catalog read failed.
pub async fn read_lag(
    pool: &Pool<AsyncPgConnection>,
    slot: &str,
) -> Result<Option<SlotLag>, SlotError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|err| SlotError::Pool(err.to_string()))?;
    // `pg_wal_lsn_diff` is numeric, and a WAL distance fits a bigint with room
    // to spare, so the cast keeps this off `bigdecimal`.
    let rows: Vec<LagRow> = sql_query(
        "SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)::bigint AS retained_bytes, \
         safe_wal_size AS safe_bytes, \
         wal_status, \
         active \
         FROM pg_replication_slots \
         WHERE slot_name = $1 AND database = current_database()",
    )
    .bind::<Text, _>(slot)
    .load(&mut *conn)
    .await?;
    Ok(rows.into_iter().next().map(|row| SlotLag {
        retained_bytes: row.retained_bytes,
        safe_bytes: row.safe_bytes,
        wal_status: row.wal_status,
        active: row.active,
    }))
}

/// The position a stream opened on this slot would resume from, or `None` when
/// this database has no such slot or the slot has no confirmed position.
///
/// This is the number the gap check compares against what the log holds, so it
/// is `confirmed_flush_lsn` rather than `restart_lsn`: the first is where
/// delivery continues, the second is only how far back Postgres must keep log
/// to reconstruct a transaction already in flight.
///
/// Returned in the same integer space as the log's own positions, which is the
/// raw byte offset a `pg_lsn` denotes, so `pg_wal_lsn_diff` against the origin
/// is the conversion rather than a reinterpretation.
///
/// # Errors
///
/// [`SlotError::Pool`] when no connection was available, [`SlotError::Query`]
/// when the catalog read failed.
pub async fn resume_position(
    pool: &Pool<AsyncPgConnection>,
    slot: &str,
) -> Result<Option<u64>, SlotError> {
    #[derive(QueryableByName)]
    struct ResumeRow {
        #[diesel(sql_type = Nullable<BigInt>)]
        resume_lsn: Option<i64>,
    }
    let mut conn = pool
        .get()
        .await
        .map_err(|err| SlotError::Pool(err.to_string()))?;
    let rows: Vec<ResumeRow> = sql_query(
        "SELECT pg_wal_lsn_diff(confirmed_flush_lsn, '0/0'::pg_lsn)::bigint AS resume_lsn \
         FROM pg_replication_slots \
         WHERE slot_name = $1 AND database = current_database()",
    )
    .bind::<Text, _>(slot)
    .load(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .next()
        .and_then(|row| row.resume_lsn)
        .and_then(|lsn| u64::try_from(lsn).ok()))
}

/// Write the slot's state to the structured log every `every`, for ever.
///
/// Never returns and never fails the process: a read that fails is a warning
/// and the next tick tries again, because a monitor that dies on a blip stops
/// monitoring exactly when the thing it watches is unwell.
///
/// A slot that has vanished draws its own warning rather than silence. Startup
/// refuses a missing slot, so one disappearing later is somebody dropping it
/// under a running server, which the operator wants to hear about.
///
/// `safe_bytes` is absent from the line rather than null when the deployment
/// has set no cap, because `tracing` drops a `None` field. Its absence is the
/// report: with no cap there is no headroom to run out of, and the failure
/// mode is the primary's disk instead of an invalidated slot.
pub async fn log_lag_forever(pool: Pool<AsyncPgConnection>, slot: String, every: Duration) {
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match read_lag(&pool, &slot).await {
            Ok(Some(lag)) => tracing::info!(
                slot = %slot,
                retained_bytes = lag.retained_bytes,
                safe_bytes = lag.safe_bytes,
                wal_status = lag.wal_status,
                active = lag.active,
                "replication slot"
            ),
            Ok(None) => tracing::warn!(slot = %slot, "replication slot is gone"),
            Err(err) => tracing::warn!(slot = %slot, error = %err, "reading the replication slot"),
        }
    }
}
