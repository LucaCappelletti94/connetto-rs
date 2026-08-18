//! The SQLite hardening applied to every replica connection connetto opens.
//!
//! One module holds the values, so a knob and the reason it carries that value
//! stay together. The table of values and what the pass does not promise are in
//! `docs/architecture/13-client-connection.md`.
//!
//! A hardened connection can attach nothing at rest. Every connetto-owned
//! attach goes through [`attach_in_window`], which opens exactly what that site
//! needs, attaches, and seals the connection again.

use diesel::RunQueryDsl;
use diesel::result::QueryResult;
use diesel::sqlite::{SqliteConnection, SqliteLimit};

/// What an attach window allows while it is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachPermits {
    /// The attached database may be written, and a missing file is refused.
    Write,
    /// The attached database may be written, and a missing file is created.
    CreateAndWrite,
}

/// Harden a freshly opened replica connection.
///
/// Runs once per open, after the cipher unlock (the header is ciphertext until
/// then) and after the journal mode. Both the native and the browser path reach
/// it through the same open, so the two agree on every value by construction.
///
/// Only four of SQLite's recommended limits are set. The rest of that table is
/// written for a process running nothing but untrusted SQL, and this connection
/// also runs the application's own diesel queries: measured against the full
/// set, a four-row batch insert, an eleven-key lookup, a twelve-term filter
/// chain and a 1.5 MB value are all refused. The four kept here are the ones no
/// application shape reached.
///
/// # Errors
///
/// The first setting SQLite refuses. The attach configuration needs core 3.49
/// or later, and defensive mode 3.26.
pub fn harden_replica_connection(conn: &mut SqliteConnection) -> QueryResult<()> {
    conn.set_defensive(true)?;
    conn.set_trusted_schema(false)?;
    // Eight arguments covers every function an application registers here (the
    // caller function takes none), so a wider one is a schema surprise.
    conn.set_limit(
        SqliteLimit::FunctionArg,
        SqliteLimit::SAFE_FUNCTION_ARG_LIMIT,
    );
    // Trigger recursion is controlled by whatever schema is attached, and
    // connetto's own translation nests one deep.
    conn.set_limit(
        SqliteLimit::TriggerDepth,
        SqliteLimit::SAFE_TRIGGER_DEPTH_LIMIT,
    );
    // Bounds one statement's compiled program, which is what a giant expression
    // inside an attached database's view would otherwise buy cheaply. Measured
    // to accept a five-thousand-bind key list and a three-way join with a
    // subquery, a group by and an order by.
    conn.set_limit(SqliteLimit::VdbeOp, SqliteLimit::SAFE_VDBE_OP_LIMIT);
    // SQLite's default too, set rather than inherited so the value is pinned.
    conn.set_limit(
        SqliteLimit::WorkerThreads,
        SqliteLimit::SAFE_WORKER_THREADS_LIMIT,
    );
    seal_attaches(conn)
}

/// Attach `path` as `schema` through the smallest window that admits it.
///
/// The window raises the attached-database ceiling by one, enables what
/// `permits` names, attaches, and seals the connection again, so the state
/// after this call refuses every further attach. Sealing happens even when the
/// attach fails.
///
/// # Errors
///
/// The attach's own error, or a failure to seal afterwards.
pub fn attach_in_window(
    conn: &mut SqliteConnection,
    path: &str,
    schema: &str,
    permits: AttachPermits,
) -> QueryResult<()> {
    let attached = open_window(conn, permits).and_then(|()| conn.attach_database(path, schema));
    let sealed = seal_attaches(conn);
    attached.and(sealed)
}

/// Open the window: enable what `permits` names and make room for one attach.
fn open_window(conn: &mut SqliteConnection, permits: AttachPermits) -> QueryResult<()> {
    if permits == AttachPermits::CreateAndWrite {
        conn.set_attach_create_enabled(true)?;
    }
    conn.set_attach_write_enabled(true)?;
    let room = attached_count(conn)?.saturating_add(1);
    conn.set_limit(SqliteLimit::Attached, room);
    Ok(())
}

/// Seal the connection: no attach may create or write, and the ceiling equals
/// what is already attached, so no further attach fits at all.
///
/// The two enables are attach-time settings, so sealing leaves the databases
/// already attached readable and writable. That is what keeps the local tier
/// usable at rest.
fn seal_attaches(conn: &mut SqliteConnection) -> QueryResult<()> {
    conn.set_attach_create_enabled(false)?;
    conn.set_attach_write_enabled(false)?;
    let live = attached_count(conn)?;
    conn.set_limit(SqliteLimit::Attached, live);
    Ok(())
}

/// How many databases besides `main` and `temp` the connection holds.
///
/// Read back from SQLite rather than tracked in Rust, so the ceiling cannot
/// drift from what is actually attached, and so a caller holding only the
/// connection (the browser relay) needs no bookkeeping of its own.
fn attached_count(conn: &mut SqliteConnection) -> QueryResult<i32> {
    #[derive(diesel::QueryableByName)]
    struct Entry {
        /// One schema name from `PRAGMA database_list`.
        #[diesel(sql_type = diesel::sql_types::Text)]
        name: String,
    }
    let entries: Vec<Entry> = diesel::sql_query("PRAGMA database_list").load(conn)?;
    let attached = entries
        .iter()
        .filter(|entry| entry.name != "main" && entry.name != "temp")
        .count();
    // SQLite refuses to attach beyond 125 databases, so the count fits and the
    // saturating arm is unreachable.
    debug_assert!(
        attached <= 125,
        "more attached databases than SQLite permits"
    );
    Ok(i32::try_from(attached).unwrap_or(i32::MAX))
}
