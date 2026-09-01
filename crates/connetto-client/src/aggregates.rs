//! The client resting table for server-computed results (R83).
//!
//! Every aggregate value the server pushes rests in `_connetto_aggregates` so
//! an offline restart reads the last synced value instead of nothing. Rows are
//! keyed by query identity, not by the run-local wire subscription id: those
//! ids (`wire-N`) are minted fresh every run, so a row filed under one could
//! never be found again after a restart. The key reuses `_connetto_query` for
//! the normalized query text and carries the binds verbatim in one canonical
//! blob (see [`crate::subscriptions::encode_binds`]), so identity is exact by
//! construction with no hashing.
//!
//! Written only under capture suspension, like the rest of `_connetto_*`, so
//! it never rides a mutation upload. See
//! `docs/architecture/13-aggregates.md`.

use connetto_core::messages::BindValue;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use crate::ClientError;
use crate::subscriptions::{encode_binds, query_text};

/// DDL for the resting table. `query_id` references the shared query-text row,
/// so the normalized text stays readable through a join and the key is a small
/// surrogate rather than the full statement. A scalar rests as the single row
/// whose `group_key` is the empty blob.
pub(crate) const AGGREGATE_DDL: &str = "CREATE TABLE IF NOT EXISTS _connetto_aggregates \
    (query_id INTEGER NOT NULL REFERENCES _connetto_query(id), \
    binds BLOB NOT NULL, group_key BLOB NOT NULL, group_values_json TEXT, \
    result_json TEXT NOT NULL, \
    updated_at INTEGER NOT NULL, PRIMARY KEY (query_id, binds, group_key))";

diesel::table! {
    /// One rested server-computed value, keyed by query identity and group.
    #[sql_name = "_connetto_aggregates"]
    aggregate (query_id, binds, group_key) {
        /// The `_connetto_query` row whose text produced this value.
        query_id -> Integer,
        /// The subscription's binds in the canonical resting encoding.
        binds -> Binary,
        /// The wire's opaque group key, or the empty blob for a scalar.
        group_key -> Binary,
        /// The decoded group values the wire carried beside the key, as a
        /// JSON array in `GROUP BY` order. `NULL` for the scalar row and for
        /// the positional rows of a whole answer (R84).
        group_values_json -> Nullable<Text>,
        /// The JSON the server pushed, decoded by the handle into its type.
        result_json -> Text,
        /// When this row was last written, in seconds since the epoch on the
        /// local clock: the as-of time a handle reports.
        updated_at -> BigInt,
    }
}

/// The empty group key of a scalar statistic's single row.
const SCALAR_KEY: &[u8] = &[];

// A rested value must outlive the subscription that produced it (aggregates
// carry zero grace, so the subscription record is gone the moment the last
// handle drops). The write path is keyed by the `query_id` the caller resolved
// from that subscription, and the orphan sweep in
// `crate::subscriptions::forget` spares a query row a rested value still
// references, so the row survives the subscription.

/// The query-text row id for `query`, or `None` when the text was never
/// recorded, so a reader against an absent statistic is a no-op.
fn query_id_of(conn: &mut SqliteConnection, query: &str) -> QueryResult<Option<i32>> {
    query_text::table
        .filter(query_text::sql.eq(query))
        .select(query_text::id)
        .first(conn)
        .optional()
}

/// One server aggregate frame as the resting table consumes it, borrowed
/// from the wire message.
pub(crate) struct AggregateFrame<'a> {
    /// The addressed group's opaque key, `None` for a scalar or whole answer.
    pub group_key: Option<&'a [u8]>,
    /// The decoded group values beside the key, present exactly when it is.
    pub group_values_json: Option<&'a str>,
    /// The body, or `None` for a removal.
    pub result_json: Option<&'a str>,
    /// Whether the body replaces the whole result.
    pub is_full_result: bool,
}

/// Apply one server aggregate frame to the resting table, under the query
/// identity `query_id` and `binds` the caller resolved from the frame's
/// subscription.
///
/// The frame's shape decides the write: a removal (`result_json` absent)
/// deletes the addressed row, a keyed delta upserts that group, a scalar
/// upserts the single empty-key row, and a whole-result push whose body is a
/// JSON array replaces every row of the statistic keyed by position (the
/// re-executed row set, R30 decision 6). A scalar and a whole answer both
/// arrive with `is_full_result` set and no group key, and are told apart by
/// whether the body is a JSON array: a scalar aggregate never renders as one.
pub(crate) fn apply_frame(
    conn: &mut SqliteConnection,
    query_id: i32,
    binds: &[BindValue],
    frame: &AggregateFrame<'_>,
    now: i64,
) -> Result<(), ClientError> {
    let binds_blob = encode_binds(binds);
    match frame.result_json {
        None => remove(
            conn,
            query_id,
            &binds_blob,
            frame.group_key.unwrap_or(SCALAR_KEY),
        ),
        Some(json) => match frame.group_key {
            Some(key) => upsert(
                conn,
                query_id,
                &binds_blob,
                key,
                frame.group_values_json,
                json,
                now,
            ),
            None if frame.is_full_result && is_json_array(json) => {
                replace_whole(conn, query_id, &binds_blob, json, now)
            }
            None => upsert(conn, query_id, &binds_blob, SCALAR_KEY, None, json, now),
        },
    }
}

/// Whether `json` is a JSON array, the shape a re-executed whole-result push
/// carries and a scalar value never does.
fn is_json_array(json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(json).is_ok_and(|value| value.is_array())
}

/// Upsert one group's (or the scalar's) value.
fn upsert(
    conn: &mut SqliteConnection,
    query_id: i32,
    binds_blob: &[u8],
    group_key: &[u8],
    group_values_json: Option<&str>,
    result_json: &str,
    now: i64,
) -> Result<(), ClientError> {
    diesel::insert_into(aggregate::table)
        .values((
            aggregate::query_id.eq(query_id),
            aggregate::binds.eq(binds_blob),
            aggregate::group_key.eq(group_key),
            aggregate::group_values_json.eq(group_values_json),
            aggregate::result_json.eq(result_json),
            aggregate::updated_at.eq(now),
        ))
        .on_conflict((aggregate::query_id, aggregate::binds, aggregate::group_key))
        .do_update()
        .set((
            aggregate::group_values_json.eq(group_values_json),
            aggregate::result_json.eq(result_json),
            aggregate::updated_at.eq(now),
        ))
        .execute(conn)?;
    Ok(())
}

/// Delete one addressed row.
fn remove(
    conn: &mut SqliteConnection,
    query_id: i32,
    binds_blob: &[u8],
    group_key: &[u8],
) -> Result<(), ClientError> {
    diesel::delete(
        aggregate::table
            .filter(aggregate::query_id.eq(query_id))
            .filter(aggregate::binds.eq(binds_blob))
            .filter(aggregate::group_key.eq(group_key)),
    )
    .execute(conn)?;
    Ok(())
}

/// Replace every row of the statistic with the elements of a whole-result
/// JSON array, keyed by position. This is the resting form of a re-executed
/// row set (a demoted grouped fold or a join re-read): the array is the whole
/// answer, so the old rows go and each element becomes one positional row.
fn replace_whole(
    conn: &mut SqliteConnection,
    query_id: i32,
    binds_blob: &[u8],
    json: &str,
    now: i64,
) -> Result<(), ClientError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|err| ClientError::Session(err.to_string()))?;
    let rows = match value {
        serde_json::Value::Array(rows) => rows,
        // apply_frame only routes an array here, so this is unreachable, but a
        // non-array body rests as the scalar it must be rather than panicking.
        other => {
            return upsert(
                conn,
                query_id,
                binds_blob,
                SCALAR_KEY,
                None,
                &other.to_string(),
                now,
            );
        }
    };
    conn.transaction::<_, ClientError, _>(|conn| {
        diesel::delete(
            aggregate::table
                .filter(aggregate::query_id.eq(query_id))
                .filter(aggregate::binds.eq(binds_blob)),
        )
        .execute(conn)?;
        for (position, element) in rows.iter().enumerate() {
            let key = u64::try_from(position)
                .unwrap_or(u64::MAX)
                .to_be_bytes()
                .to_vec();
            diesel::insert_into(aggregate::table)
                .values((
                    aggregate::query_id.eq(query_id),
                    aggregate::binds.eq(binds_blob),
                    aggregate::group_key.eq(&key),
                    aggregate::result_json.eq(element.to_string()),
                    aggregate::updated_at.eq(now),
                ))
                .execute(conn)?;
        }
        Ok(())
    })
}

/// The rested scalar value and its as-of time for `query` under `binds`, or
/// `None` when no scalar row rests. This is the single empty-key row the
/// scalar watch bootstraps from on an offline restart, the relay answers a
/// tab's aggregate watch from while its worker is offline, and the pump reads
/// to push a live value to its typed handles.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica cannot be read.
pub(crate) fn lookup_scalar(
    conn: &mut SqliteConnection,
    query: &str,
    binds: &[BindValue],
) -> Result<Option<(String, i64)>, ClientError> {
    let Some(query_id) = query_id_of(conn, query)? else {
        return Ok(None);
    };
    let binds_blob = encode_binds(binds);
    Ok(aggregate::table
        .filter(aggregate::query_id.eq(query_id))
        .filter(aggregate::binds.eq(&binds_blob))
        .filter(aggregate::group_key.eq(SCALAR_KEY))
        .select((aggregate::result_json, aggregate::updated_at))
        .first(conn)
        .optional()?)
}

/// One rested group row of a statistic: the decoded group values the wire
/// carried beside its key (`None` for the positional rows a whole answer
/// rests as), the value body, and its as-of time. The opaque stored key stays
/// in the table as identity and ordering; a handle keys on decoded values,
/// so it never travels up.
pub(crate) struct RestedGroup {
    /// The decoded group values as a JSON array, `None` for positional rows.
    pub group_values_json: Option<String>,
    /// The JSON body: a bare value for a keyed delta row, a whole object for
    /// a positional row.
    pub result_json: String,
    /// When the row was last written, seconds since the epoch, local clock.
    pub updated_at: i64,
}

/// Every rested group row of the statistic for `query` under `binds`, the
/// scalar row excluded, ordered by stored key so positional rows come back in
/// answer order. A keyed or row-shaped handle bootstraps from this on an
/// offline restart and a late join, whichever resting shape it finds (a keyed
/// delta set or a whole answer's positional rows), so a server-side demotion
/// stays invisible across a restart (R84).
///
/// # Errors
///
/// [`ClientError::Session`] when the replica cannot be read.
pub(crate) fn lookup_groups(
    conn: &mut SqliteConnection,
    query: &str,
    binds: &[BindValue],
) -> Result<Vec<RestedGroup>, ClientError> {
    let Some(query_id) = query_id_of(conn, query)? else {
        return Ok(Vec::new());
    };
    let binds_blob = encode_binds(binds);
    let rows: Vec<(Option<String>, String, i64)> = aggregate::table
        .filter(aggregate::query_id.eq(query_id))
        .filter(aggregate::binds.eq(&binds_blob))
        .filter(aggregate::group_key.ne(SCALAR_KEY))
        .order(aggregate::group_key)
        .select((
            aggregate::group_values_json,
            aggregate::result_json,
            aggregate::updated_at,
        ))
        .load(conn)?;
    Ok(rows
        .into_iter()
        .map(|(group_values_json, result_json, updated_at)| RestedGroup {
            group_values_json,
            result_json,
            updated_at,
        })
        .collect())
}

/// Evict rested statistics down to `cap`, oldest updated first, never one that
/// is currently watched.
///
/// A statistic is one query plus binds, however many group rows it holds, and
/// its age is that of its most recent row. `protected` names the (query id,
/// canonical binds) of every subscription still on record, the ones a handle
/// still watches, so eviction spares them: a live handle must keep reading its
/// value through a restart-crossing table that never drops it. When every
/// statistic over the cap is watched the table stays over the cap rather than
/// evicting a value in use.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica cannot be read or written.
pub(crate) fn enforce_cap(
    conn: &mut SqliteConnection,
    cap: usize,
    protected: &[(i32, Vec<u8>)],
) -> Result<(), ClientError> {
    let mut stats: Vec<(i32, Vec<u8>, Option<i64>)> = aggregate::table
        .group_by((aggregate::query_id, aggregate::binds))
        .select((
            aggregate::query_id,
            aggregate::binds,
            diesel::dsl::max(aggregate::updated_at),
        ))
        .load(conn)?;
    if stats.len() <= cap {
        return Ok(());
    }
    let protected: std::collections::HashSet<&(i32, Vec<u8>)> = protected.iter().collect();
    // Oldest most-recent update first, so the statistic used longest ago goes
    // before a fresher one.
    stats.sort_by_key(|(_, _, recent)| recent.unwrap_or(i64::MIN));
    let mut over = stats.len() - cap;
    for (query_id, binds_blob, _) in stats {
        if over == 0 {
            break;
        }
        if protected.contains(&(query_id, binds_blob.clone())) {
            continue;
        }
        diesel::delete(
            aggregate::table
                .filter(aggregate::query_id.eq(query_id))
                .filter(aggregate::binds.eq(&binds_blob)),
        )
        .execute(conn)?;
        over -= 1;
    }
    Ok(())
}
