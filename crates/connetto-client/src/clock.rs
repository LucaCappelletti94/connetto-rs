//! The one clock this crate reads.
//!
//! The client library deliberately never calls a clock of its own: `chrono` is
//! a dev dependency and the one `SystemTime::now` is in a test, which is what
//! keeps it compiling for wasm, where `SystemTime::now` panics. The replica is
//! open on both targets and carries a clock, so anything measuring elapsed time
//! measures it through the same connection it stores state in.

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use crate::ClientError;

/// Seconds since the epoch, read from SQLite rather than from the host.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica cannot be read.
pub(crate) fn now_secs(db: &mut SqliteConnection) -> Result<i64, ClientError> {
    // A scalar SELECT over a SQLite built-in with no table to name, so there is
    // no `table!` for the DSL to go through.
    #[derive(diesel::QueryableByName)]
    struct Now {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        secs: i64,
    }
    let row: Now =
        diesel::sql_query("SELECT CAST(strftime('%s','now') AS INTEGER) AS secs").get_result(db)?;
    Ok(row.secs)
}
