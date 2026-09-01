//! End-to-end characterization of the RLS name-mapping sync contract.
//!
//! pg2sqlite's RLS translation stores rows in a suffixed backing table and
//! serves the logical name through a policy view with INSTEAD OF triggers.
//! The wire speaks logical Postgres names, so changeset bytes must be
//! renamed at the sync boundaries. Applying logical-named bytes to the
//! replica is silent data loss: `sqlite3changeset_apply` resolves the view
//! through `PRAGMA table_xinfo`, synthesizes an implicit rowid key since a
//! view declares no PK (`sqlite3session.c:1116,1129-1139`), the shape
//! checks pass, and every row then fails as a per-row `Constraint`
//! conflict, which the client's `server_wins` policy maps to Omit. Apply
//! reports success and delivers nothing. These tests pin that hazard and
//! prove the fix with the landed upstream pieces:
//! `Pg2Sqlite::translation_manifest` exports the logical to physical map
//! and `ParsedDiffSet::rename_tables` rewrites the bytes, both directions.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use diesel::connection::SimpleConnection;
use diesel::sqlite::SqliteFunctionBehavior;
use diesel::{Connection, RunQueryDsl, SqliteConnection};
use diesel_sqlite_session::{ConflictAction, ConflictType, SqliteSessionExt};
use pg2sqlite::prelude::{Pg2Sqlite, Pg2SqliteOptions, SessionVariableMapping};
use sqlite_diff_rs::ParsedDiffSet;

/// The Postgres source document: one policy-bearing table. The SELECT
/// policy drives the view filter, the INSERT policy drives the WITH CHECK
/// enforcement in the INSTEAD OF trigger.
const PG_DDL: &str = "
CREATE TABLE orders (
    id BIGINT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    quantity BIGINT NOT NULL
);

ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

CREATE POLICY orders_select ON orders
    FOR SELECT
    USING (owner_id = current_setting('app.user_id'));

CREATE POLICY orders_insert ON orders
    FOR INSERT
    WITH CHECK (owner_id = current_setting('app.user_id'));
";

/// The same table without policies: what the server materializer holds,
/// plain logical names, no views.
const PG_DDL_PLAIN: &str = "
CREATE TABLE orders (
    id BIGINT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    quantity BIGINT NOT NULL
);
";

diesel::define_sql_function! {
    /// Replica-side emulation of Postgres `current_setting('app.user_id')`,
    /// registered per connection and referenced by the generated policy
    /// view and triggers.
    fn current_app_user() -> diesel::sql_types::Text;
}

fn options() -> Pg2SqliteOptions {
    Pg2SqliteOptions::default()
        .with_session_variable(SessionVariableMapping::current_setting(
            "app.user_id",
            "current_app_user",
        ))
        .with_rls_audit_table_name("rls_audit".to_string())
        // The download boundary: the apply below holds this function true
        // while it lands server-authoritative rows, exactly as connetto's
        // own apply does through its suspension guard.
        .with_write_exemption_function(connetto_client::WRITE_EXEMPTION_FUNCTION)
}

/// Translate `ddl` and execute every emitted statement on a fresh in-memory
/// connection with `current_app_user()` registered to return `user` and the
/// write exemption registered over the returned flag, false at rest.
fn build_db(ddl: &str, user: &'static str) -> (SqliteConnection, Arc<AtomicBool>) {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    current_app_user_utils::register_nondeterministic_impl(&mut conn, move || user.to_string())
        .expect("register current_app_user");
    let exempt = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&exempt);
    conn.register_noarg_sql_function::<diesel::sql_types::Bool, _, _>(
        connetto_client::WRITE_EXEMPTION_FUNCTION,
        SqliteFunctionBehavior::INNOCUOUS,
        move || flag.load(Ordering::Relaxed),
    )
    .expect("register the write exemption");
    let statements = Pg2Sqlite::default()
        .sql(ddl)
        .expect("parse postgres ddl")
        .translate_to_sql(&options())
        .expect("translate to sqlite");
    for statement in &statements {
        conn.batch_execute(statement)
            .unwrap_or_else(|e| panic!("ddl failed: {e}\n{statement}"));
    }
    (conn, exempt)
}

/// The logical to physical map for the policy-bearing document.
fn orders_mapping() -> (String, String) {
    let manifest = Pg2Sqlite::default()
        .sql(PG_DDL)
        .expect("parse postgres ddl")
        .translation_manifest(&options())
        .expect("manifest");
    let entry = manifest
        .iter()
        .find(|e| e.logical == "orders")
        .expect("orders entry");
    assert_eq!(entry.wrapper, pg2sqlite::prelude::WrapperKind::RlsView);
    assert_ne!(
        entry.logical, entry.physical,
        "RLS backing table must be renamed"
    );
    (entry.logical.clone(), entry.physical.clone())
}

fn abort_on_conflict(_conflict: ConflictType) -> ConflictAction {
    ConflictAction::Abort
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    n: i64,
}

#[derive(diesel::QueryableByName)]
struct QtyRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    quantity: i64,
}

fn count(conn: &mut SqliteConnection, table: &str) -> i64 {
    diesel::sql_query(format!("SELECT COUNT(*) AS n FROM \"{table}\""))
        .get_result::<CountRow>(conn)
        .expect("count")
        .n
}

/// Capture a changeset on a plain (server-shaped) database holding one row
/// per user, section named with the logical `orders`.
fn server_changeset(server: &mut SqliteConnection) -> Vec<u8> {
    let mut session = server.create_session().expect("session");
    session.attach_all().expect("attach");
    diesel::sql_query("INSERT INTO orders (id, owner_id, quantity) VALUES (1, 'alice', 5)")
        .execute(server)
        .expect("insert alice");
    diesel::sql_query("INSERT INTO orders (id, owner_id, quantity) VALUES (2, 'bob', 7)")
        .execute(server)
        .expect("insert bob");
    session.changeset().expect("changeset")
}

/// The hazard this contract exists for: a logical-named changeset applied
/// to an RLS-translated replica reports success and delivers nothing.
/// Every row surfaces as a `Constraint` conflict against the view, and the
/// client's real conflict policy (`server_wins`) maps `Constraint` to
/// Omit, so the mapping below mirrors it.
#[test]
fn logical_changeset_without_rename_is_silently_dropped() {
    let (logical, physical) = orders_mapping();
    let (mut server, _) = build_db(PG_DDL_PLAIN, "alice");
    let changeset = server_changeset(&mut server);

    let conflicts = std::cell::Cell::new(0u32);
    let (mut replica, _) = build_db(PG_DDL, "alice");
    replica
        .apply_changeset(&changeset, |conflict: ConflictType| {
            conflicts.set(conflicts.get() + 1);
            match conflict {
                ConflictType::Data | ConflictType::Conflict => ConflictAction::Replace,
                _ => ConflictAction::Omit,
            }
        })
        .expect("apply reports success");

    assert_eq!(
        conflicts.get(),
        2,
        "every row misfires as a per-row conflict"
    );
    assert_eq!(
        count(&mut replica, &physical),
        0,
        "no row may land in the backing table"
    );
    assert_eq!(count(&mut replica, &logical), 0, "the view stays empty too");
}

/// The download boundary: rename logical to physical via the manifest,
/// apply into the backing table (bypassing the policy triggers, server data
/// is authoritative), and read through the view, which still filters.
#[test]
fn renamed_changeset_lands_in_backing_table_and_view_filters() {
    let (logical, physical) = orders_mapping();
    let (mut server, _) = build_db(PG_DDL_PLAIN, "alice");
    let changeset = server_changeset(&mut server);

    let mut parsed = ParsedDiffSet::parse(&changeset).expect("parse changeset");
    let renamed = parsed.rename_tables(|name| (name == logical).then(|| physical.clone()));
    assert_eq!(renamed, 1, "exactly the orders section is renamed");
    let rewritten: Vec<u8> = parsed.into();

    let (mut replica, exempt) = build_db(PG_DDL, "alice");
    // The download boundary holds the exemption, as connetto's own apply does.
    exempt.store(true, Ordering::Relaxed);
    replica
        .apply_changeset(&rewritten, abort_on_conflict)
        .expect("apply renamed changeset");
    exempt.store(false, Ordering::Relaxed);

    assert_eq!(
        count(&mut replica, &physical),
        2,
        "both rows land physically, policy bypassed"
    );
    assert_eq!(
        count(&mut replica, &logical),
        1,
        "the view shows only alice's row"
    );
    let qty: QtyRow = diesel::sql_query(format!("SELECT quantity FROM \"{logical}\""))
        .get_result(&mut replica)
        .expect("read through view");
    assert_eq!(qty.quantity, 5);
}

/// The upload boundary: a local write goes through the view's INSTEAD OF
/// trigger into the backing table, capture records the physical name, and
/// the rename back to logical makes the bytes apply on a plain server
/// schema.
#[test]
fn captured_local_write_renames_back_to_logical() {
    let (logical, physical) = orders_mapping();

    let (mut replica, _) = build_db(PG_DDL, "alice");
    let mut capture = replica.create_session().expect("capture session");
    capture.attach_all().expect("attach");
    diesel::sql_query(format!(
        "INSERT INTO \"{logical}\" (id, owner_id, quantity) VALUES (3, 'alice', 9)"
    ))
    .execute(&mut replica)
    .expect("write through the view");
    let upload = capture.changeset().expect("captured changeset");

    let mut parsed = ParsedDiffSet::parse(&upload).expect("parse captured changeset");
    let captured: Vec<&str> = parsed
        .table_schemas()
        .iter()
        .map(|s| s.name().as_str())
        .collect();
    assert_eq!(
        captured,
        vec![physical.as_str()],
        "capture records the backing table"
    );

    let renamed = parsed.rename_tables(|name| (name == physical).then(|| logical.clone()));
    assert_eq!(renamed, 1);
    let rewritten: Vec<u8> = parsed.into();

    let (mut server, _) = build_db(PG_DDL_PLAIN, "alice");
    server
        .apply_changeset(&rewritten, abort_on_conflict)
        .expect("apply upload");
    assert_eq!(
        count(&mut server, &logical),
        1,
        "the uploaded row lands under the logical name"
    );
}
