//! R87 storage quotas and the deployment ceilings.
//!
//! Three meters, per chapter 18:
//!
//! - a per-identity storage quota, summed live over the uploader's committed
//!   manifests at commit time, where every declarer pays the full size of
//!   their own declaration even when the bytes dedup,
//! - a deployment-wide storage ceiling over the distinct chunks the committed
//!   manifests reference, and
//! - a deployment-wide bandwidth ceiling over the bytes actually served and
//!   accepted inside a trailing window, ledgered in the shared day table so
//!   every replica of the file server counts into the same numbers.
//!
//! The two deployment numbers are cached per replica and refreshed on a
//! cadence, so a commit or a read checks a number in memory; the overshoot is
//! bounded by the cadence times the deployment's throughput, which is what
//! the setting's documentation states rather than what this code hides.
//!
//! The raw SQL here interpolates table names only from the schema trait's
//! compile-time constants, never from request data, and every value is a
//! bind parameter.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, NaiveDate, Utc};
use diesel::QueryableByName;
use diesel::sql_types::{BigInt, Date, Integer, Nullable};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use futures_util::stream::BoxStream;
use tokio::sync::RwLock;

use crate::router::DbPool;
use crate::schema::ConnettoFileSchema;

/// The configured ceilings. A zero ceiling or quota means unlimited, which is
/// the default. An unconfigured deployment never consults a ceiling and takes
/// neither the uploader lock nor either SUM; it does carry the shared costs
/// of the feature, the per-transfer ledger row decided 2026-09-13 and the
/// preflight that requires the shipped DDL.
#[derive(Debug, Clone)]
pub struct QuotaSettings {
    /// Bytes one uploader may hold across their committed manifests.
    pub identity_quota: u64,
    /// Deployment-wide stored bytes across distinct committed chunks.
    pub storage_ceiling: u64,
    /// Deployment-wide served plus accepted bytes inside the window.
    pub bandwidth_ceiling: u64,
    /// Trailing window length in UTC day rows, default thirty.
    pub window_days: i32,
    /// Fraction of each ceiling at which one structured warning fires per
    /// crossing, re-armed when the sum drops back below it.
    pub warn_fraction: f64,
    /// Cadence at which each replica refreshes its cached deployment numbers.
    /// The storage refusal's `Retry-After` is six times this interval.
    pub refresh: Duration,
}

impl Default for QuotaSettings {
    fn default() -> Self {
        Self {
            identity_quota: 0,
            storage_ceiling: 0,
            bandwidth_ceiling: 0,
            window_days: 30,
            warn_fraction: 0.8,
            refresh: Duration::from_secs(10),
        }
    }
}

impl QuotaSettings {
    /// Whether any deployment meter needs the refresh task at all.
    #[must_use]
    pub fn deployment_metered(&self) -> bool {
        self.storage_ceiling > 0 || self.bandwidth_ceiling > 0
    }
}

/// The cached deployment totals plus the saturation bookkeeping for the
/// once-per-crossing warnings. Zero is a harmless value before the first
/// refresh: an unconfigured deployment never reads it, and a configured one
/// refreshes before its router serves.
#[derive(Debug, Default, Clone)]
pub struct CeilingTotals {
    /// Distinct chunk bytes referenced by committed manifests.
    pub stored_bytes: u64,
    /// Served plus accepted bytes inside the trailing window.
    pub window_bytes: u64,
    /// The oldest counted ledger day inside the window, raw. The window
    /// exit is this day plus `window_days`; answers that need it add the
    /// window themselves. `None` while the ledger is empty inside it.
    pub oldest_day: Option<NaiveDate>,
    /// This ceiling's once-per-crossing saturation state for storage.
    pub storage_crossing: Crossing,
    /// This ceiling's once-per-crossing saturation state for bandwidth.
    pub bandwidth_crossing: Crossing,
}

/// One ceiling's saturation bookkeeping: silent below the warning fraction,
/// warned between the fraction and the ceiling, saturated at or above the
/// ceiling. Any state falls back to `Below`, re-arming the pair, only when
/// the total drops below the fraction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Crossing {
    /// Nothing has fired.
    #[default]
    Below,
    /// The warning has fired and stayed silent since.
    Warned,
    /// The saturation error has fired. Survives a drop back into the
    /// warning band so the error does not re-fire while the ceiling keeps
    /// being hit.
    Saturated,
}

/// The handle handlers read and the refresh task writes.
pub type CeilingCache = Arc<RwLock<CeilingTotals>>;

#[derive(QueryableByName)]
struct StoredSum {
    #[diesel(sql_type = BigInt)]
    total: i64,
}

#[derive(QueryableByName)]
struct WindowRow {
    #[diesel(sql_type = BigInt)]
    total: i64,
    #[diesel(sql_type = Nullable<Date>)]
    oldest: Option<NaiveDate>,
}

/// Sums the distinct chunk bytes the committed manifests reference.
///
/// Content-addressing makes one hash carry one length, so the distinct pair
/// `(chunk_hash, chunk_len)` is exactly the set of stored chunks.
pub(crate) async fn stored_chunk_bytes<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
) -> Result<u64, diesel::result::Error> {
    let sql = format!(
        "SELECT COALESCE(SUM(d.chunk_len), 0)::bigint AS total FROM \
         (SELECT DISTINCT mc.chunk_hash, mc.chunk_len FROM {chunks} mc \
          JOIN {manifests} m ON mc.file_id = m.file_id AND mc.uploaded_by = m.uploaded_by \
          WHERE m.committed) d",
        chunks = S::MANIFEST_CHUNKS_SQL,
        manifests = S::MANIFESTS_SQL,
    );
    let row: StoredSum = diesel::sql_query(&sql).get_result(conn).await?;
    Ok(u64::try_from(row.total).unwrap_or(u64::MAX))
}

/// Sums served plus accepted bytes over the day rows inside the trailing
/// window and reports the oldest counted day.
pub(crate) async fn window_bytes<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    window_days: i32,
) -> Result<(u64, Option<NaiveDate>), diesel::result::Error> {
    let sql = format!(
        "SELECT COALESCE(SUM(served_bytes + accepted_bytes), 0)::bigint AS total, \
         MIN(day) AS oldest FROM {traffic} \
         WHERE day > ((CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date - $1::int)",
        traffic = S::TRAFFIC_SQL,
    );
    let row: WindowRow = diesel::sql_query(&sql)
        .bind::<Integer, _>(window_days)
        .get_result(conn)
        .await?;
    Ok((u64::try_from(row.total).unwrap_or(u64::MAX), row.oldest))
}

/// Adds served and accepted bytes to today's ledger row.
///
/// "Today" is the UTC day regardless of the server's timezone, the day the
/// plan fixes for the window and what [`bandwidth_retry_after_secs`] assumes
/// when it names the midnight the oldest day leaves the window at.
///
/// Runs inside the transaction that moved the bytes where one exists, so an
/// accounting row never claims a transfer a rollback undid. A read that
/// streams counts the bytes it wrote when its body completes or is dropped,
/// which is why this takes the pool and spawns rather than a connection.
pub(crate) async fn ledger_add<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    served: u64,
    accepted: u64,
) -> Result<(), diesel::result::Error> {
    let served_i64 = i64::try_from(served).unwrap_or(i64::MAX);
    let accepted_i64 = i64::try_from(accepted).unwrap_or(i64::MAX);
    let sql = format!(
        "INSERT INTO {traffic} (day, served_bytes, accepted_bytes) \
         VALUES ((CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date, $1, $2) \
         ON CONFLICT (day) DO UPDATE SET \
           served_bytes = {traffic}.served_bytes + EXCLUDED.served_bytes, \
           accepted_bytes = {traffic}.accepted_bytes + EXCLUDED.accepted_bytes",
        traffic = S::TRAFFIC_SQL,
    );
    diesel::sql_query(&sql)
        .bind::<BigInt, _>(served_i64)
        .bind::<BigInt, _>(accepted_i64)
        .execute(conn)
        .await?;
    Ok(())
}

/// Spawns the ledger write for bytes already transferred, where no caller
/// transaction covers it. A failed ledger write is logged and lost: the
/// accounting is an operator number, not a reason to fail a completed
/// response.
pub(crate) fn spawn_ledger_add<S: ConnettoFileSchema>(pool: &DbPool, served: u64, accepted: u64) {
    if served == 0 && accepted == 0 {
        return;
    }
    let pool = pool.clone();
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let mut conn = match pool.get().await {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::warn!(error = %err, "traffic ledger write found no connection");
                    return;
                }
            };
            if let Err(err) = ledger_add::<S>(&mut conn, served, accepted).await {
                tracing::warn!(error = %err, "traffic ledger write failed");
            }
        });
    } else {
        tracing::warn!("traffic ledger write outside a runtime, bytes uncounted");
    }
}

/// Wraps a served body so the bytes it carried are ledgered once when the
/// body is dropped, whether it ran to completion or the client hung up half
/// way. The count is what was polled into the body, which a client abort can
/// overstate by what the transport had buffered but not flushed. This is why
/// bandwidth is "bytes served" rather than the `Content-Length` of a
/// refusal-or-abort.
pub(crate) struct CountedServing<S: ConnettoFileSchema, E> {
    inner: BoxStream<'static, Result<Bytes, E>>,
    pool: DbPool,
    served: u64,
    marker: PhantomData<fn() -> S>,
}

impl<S: ConnettoFileSchema, E> Stream for CountedServing<S, E> {
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let polled = Pin::new(&mut self.inner).poll_next(cx);
        if let Poll::Ready(Some(Ok(bytes))) = &polled {
            self.served = self.served.saturating_add(bytes.len() as u64);
        }
        polled
    }
}

impl<S: ConnettoFileSchema, E> Drop for CountedServing<S, E> {
    fn drop(&mut self) {
        spawn_ledger_add::<S>(&self.pool, self.served, 0);
    }
}

/// Wraps a served body stream with [`CountedServing`].
pub(crate) fn counted_serving<S: ConnettoFileSchema, E>(
    pool: DbPool,
    body: BoxStream<'static, Result<Bytes, E>>,
) -> CountedServing<S, E> {
    CountedServing {
        inner: body,
        pool,
        served: 0,
        marker: PhantomData,
    }
}

/// Serializes one uploader's quota checks across concurrent commits.
///
/// The manifest `FOR UPDATE` lock only serializes commits of the same file,
/// so two uploads of different files by one uploader would each SUM without
/// seeing the other's pending flip and both pass under the quota.  This
/// transaction-scoped advisory lock makes the second committer wait for the
/// first to commit, so its SUM sees the committed bytes.  Lock order is
/// uniform (manifest row, then advisory) and each transaction takes at most
/// one advisory lock, so no cycle forms with the sweep, which never takes
/// one.  `hashtextextended` collisions only serialize unrelated uploaders
/// for the length of one commit.
pub(crate) async fn serialize_uploader(
    conn: &mut AsyncPgConnection,
    uploader: &str,
) -> Result<(), diesel::result::Error> {
    diesel::sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<diesel::sql_types::Text, _>(uploader)
        .execute(conn)
        .await?;
    Ok(())
}

/// Sums the total declared bytes of `uploader`'s committed manifests.
pub(crate) async fn uploader_committed_bytes<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    uploader: &str,
) -> Result<u64, diesel::result::Error> {
    let sql = format!(
        "SELECT COALESCE(SUM(total_len), 0)::bigint AS total FROM {manifests} \
         WHERE uploaded_by = $1 AND committed",
        manifests = S::MANIFESTS_SQL,
    );
    let row: StoredSum = diesel::sql_query(&sql)
        .bind::<diesel::sql_types::Text, _>(uploader)
        .get_result(conn)
        .await?;
    Ok(u64::try_from(row.total).unwrap_or(u64::MAX))
}

/// The UTC instant the day `oldest` rolls out of a `window_days`-day
/// trailing window. The window predicate is `day >` the UTC date minus
/// days, and ledger rows are UTC days, so the oldest counted day leaves
/// the window when the UTC date reaches `oldest + days`, at the midnight
/// opening that date.
fn window_exit_instant(oldest: NaiveDate, window_days: i32) -> Option<DateTime<Utc>> {
    oldest
        .checked_add_signed(chrono::TimeDelta::days(i64::from(window_days)))?
        .and_hms_opt(0, 0, 0)
        .map(|d| d.and_utc())
}

/// Seconds a bandwidth refusal should ask the caller to wait: the moment the
/// oldest counted day rolls out of the window. Never less than one.
#[must_use]
pub fn bandwidth_retry_after_secs(
    oldest: Option<NaiveDate>,
    window_days: i32,
    now: DateTime<Utc>,
) -> u64 {
    let Some(target) = oldest.and_then(|day| window_exit_instant(day, window_days)) else {
        return 1;
    };
    (target - now).to_std().map_or(1, |d| d.as_secs().max(1))
}

/// Refreshes the cached deployment totals and applies the once-per-crossing
/// saturation logging for both ceilings. Each meter is read, published and
/// logged independently: a broken ledger cannot freeze the storage total,
/// nor a broken chunk sum freeze the window.
///
/// # Errors
///
/// Names each meter that could not be read. The boot seed treats this as
/// fatal, a deployment that asked for enforcement must not serve without
/// having read it once; the periodic loop only logs, because a blip must
/// not take a serving replica down and the last published totals stay in
/// force meanwhile.
pub(crate) async fn refresh_once<S: ConnettoFileSchema>(
    pool: &DbPool,
    settings: &QuotaSettings,
    cache: &CeilingCache,
) -> Result<(), String> {
    let mut conn = match pool.get().await {
        Ok(conn) => conn,
        Err(err) => return Err(format!("ceiling refresh found no connection: {err}")),
    };
    let mut failures: Vec<&str> = Vec::new();
    match stored_chunk_bytes::<S>(&mut conn).await {
        Ok(stored) => {
            let mut totals = cache.write().await;
            totals.stored_bytes = stored;
            cross(
                settings.storage_ceiling,
                settings.warn_fraction,
                stored,
                "storage",
                &mut totals.storage_crossing,
            );
        }
        Err(err) => {
            tracing::warn!(error = %err, "ceiling refresh could not sum stored bytes");
            failures.push("stored bytes");
        }
    }
    match window_bytes::<S>(&mut conn, settings.window_days).await {
        Ok((window, oldest_day)) => {
            let mut totals = cache.write().await;
            totals.window_bytes = window;
            totals.oldest_day = oldest_day;
            cross(
                settings.bandwidth_ceiling,
                settings.warn_fraction,
                window,
                "bandwidth",
                &mut totals.bandwidth_crossing,
            );
        }
        Err(err) => {
            tracing::warn!(error = %err, "ceiling refresh could not sum the window");
            failures.push("bandwidth window");
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "ceiling refresh failed for: {}",
            failures.join(", ")
        ))
    }
}

/// One ceiling's crossing bookkeeping: a warning the first time the total
/// reaches the fraction, an error the first time it reaches the ceiling, both
/// re-armed when it drops back below the fraction.
fn cross(ceiling: u64, fraction: f64, total: u64, name: &'static str, state: &mut Crossing) {
    if ceiling == 0 {
        return;
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "an operator threshold; the 52-bit mantissa misses by tens of bytes at petabyte scale"
    )]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "ceiling times a fraction clamped to [0,1] never exceeds the ceiling itself"
    )]
    #[expect(
        clippy::cast_sign_loss,
        reason = "the fraction is clamped to [0,1] where it is parsed, so the product is non-negative"
    )]
    let warn_at = ((ceiling as f64) * fraction) as u64;
    if total >= ceiling {
        if *state != Crossing::Saturated {
            tracing::error!(ceiling, total, "deployment {} ceiling saturated", name);
        }
        *state = Crossing::Saturated;
    } else if total >= warn_at {
        if matches!(*state, Crossing::Below) {
            tracing::warn!(
                ceiling,
                total,
                "deployment {} ceiling passed the warning fraction",
                name
            );
            *state = Crossing::Warned;
        }
    } else {
        *state = Crossing::Below;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).expect("valid date")
    }

    #[test]
    fn bandwidth_retry_after_counts_to_window_exit_midnight() {
        // Oldest counted day 2026-08-21 with a 30-day window leaves the
        // window at the midnight that opens 2026-09-20.
        let now = date(2026, 9, 19)
            .and_hms_opt(12, 0, 0)
            .expect("valid")
            .and_utc();
        let secs = bandwidth_retry_after_secs(Some(date(2026, 8, 21)), 30, now);
        assert_eq!(secs, 12 * 3600);
    }

    #[test]
    fn bandwidth_retry_after_is_never_zero_and_survives_no_rows() {
        let now = date(2026, 9, 19)
            .and_hms_opt(12, 0, 0)
            .expect("valid")
            .and_utc();
        assert_eq!(bandwidth_retry_after_secs(None, 30, now), 1);
        let past = date(2026, 9, 25)
            .and_hms_opt(0, 0, 0)
            .expect("valid")
            .and_utc();
        assert_eq!(
            bandwidth_retry_after_secs(Some(date(2026, 8, 21)), 30, past),
            1
        );
    }

    #[test]
    fn warning_fires_once_per_crossing_and_rearms() {
        let mut state = Crossing::default();
        // Below the fraction: silent.
        cross(1000, 0.8, 700, "storage", &mut state);
        assert_eq!(state, Crossing::Below);
        // Crossing the fraction: warned once, further refreshes silent.
        cross(1000, 0.8, 850, "storage", &mut state);
        assert_eq!(state, Crossing::Warned);
        cross(1000, 0.8, 900, "storage", &mut state);
        assert_eq!(state, Crossing::Warned);
        // Saturation errors once and stays armed through the warning band.
        cross(1000, 0.8, 1000, "storage", &mut state);
        assert_eq!(state, Crossing::Saturated);
        cross(1000, 0.8, 900, "storage", &mut state);
        assert_eq!(state, Crossing::Saturated);
        // A drop below the fraction re-arms.
        cross(1000, 0.8, 100, "storage", &mut state);
        assert_eq!(state, Crossing::Below);
        // Zero ceiling is silent forever.
        cross(0, 0.8, u64::MAX, "storage", &mut state);
        assert_eq!(state, Crossing::Below);
    }
}
