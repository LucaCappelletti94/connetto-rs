//! Proves that pg2sqlite at e02e7b9 correctly forwards column defaults through
//! the INSTEAD OF INSERT trigger it emits for a policy-bearing table.
//!
//! The defect (documented in docs/upstream-pg2sqlite-instead-of-insert-drops-defaults.md):
//! the old trigger forwarded every column as `VALUES (NEW.id, ...)` so a column
//! the caller omitted arrived as NULL and the backing table's DEFAULT never
//! fired. For a UUID primary key this caused `NOT NULL constraint failed:
//! orders_rls.id` on any client-authored insert that omitted the key.
//!
//! The fix: the trigger now emits `COALESCE(NEW.id, uuidv4())` so an omitted
//! key picks up the translated DEFAULT expression. This test verifies that
//! shape by translating the exact schema the wasm-smoke demo uses, applying it
//! to an in-memory SQLite, inserting through the policy view without naming the
//! id column, and asserting the backing table holds one row with a 16-byte id.

use diesel::connection::SimpleConnection;
use diesel::{Connection, ExpressionMethods, QueryDsl, RunQueryDsl, SqliteConnection};
use pg2sqlite::prelude::{Pg2Sqlite, Pg2SqliteOptions, SessionVariableMapping, UuidRepresentation};
use pg2sqlite::traits::TranslationOptions;

/// The exact schema the wasm-smoke demo uses: schema.sql plus policies.sql.
const PG_DDL: &str = "
CREATE TABLE orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id TEXT NOT NULL,
    quantity BIGINT NOT NULL CHECK (quantity >= 0)
);
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_p ON orders
    USING (owner_id = current_setting('app.user_id', true));
";

diesel::define_sql_function! {
    /// Replica-side emulation of `current_setting('app.user_id')`.
    fn current_app_user() -> diesel::sql_types::Text;
}

diesel::define_sql_function! {
    /// UUID v4 key minter, registered by the application on each connection.
    fn uuidv4() -> diesel::sql_types::Binary;
}

diesel::table! {
    /// The policy view the application writes through.
    orders (id) {
        /// Primary key, omitted by the client to trigger the DEFAULT.
        id -> Binary,
        /// Row owner, compared against `current_app_user()` by the policy.
        owner_id -> Text,
        /// Item count.
        quantity -> BigInt,
    }
}

diesel::table! {
    /// The backing table the trigger writes into.
    orders_rls (id) {
        /// The stored UUID, minted from the DEFAULT when the insert omits it.
        id -> Binary,
        /// Row owner.
        owner_id -> Text,
        /// Item count.
        quantity -> BigInt,
    }
}

fn options() -> Pg2SqliteOptions {
    Pg2SqliteOptions::default()
        .with_uuid_representation(UuidRepresentation::Blob)
        .with_uuid_function_name("uuidv4")
        .with_session_variable(SessionVariableMapping::current_setting(
            "app.user_id",
            "current_app_user",
        ))
        .with_rls_audit_table_name("rls_audit".to_string())
}

fn translate_ddl() -> String {
    let statements = Pg2Sqlite::default()
        .sql(PG_DDL)
        .expect("parse the Postgres schema")
        .translate_to_sql(&options())
        .expect("translate to SQLite DDL");
    let mut ddl = statements.join(";\n");
    ddl.push(';');
    ddl
}

#[test]
fn omitting_uuid_primary_key_lands_a_row_with_a_minted_id() {
    let ddl = translate_ddl();

    // The trigger must use COALESCE so the default fires when id is omitted.
    assert!(
        ddl.contains("COALESCE(NEW.id"),
        "expected COALESCE(NEW.id in the emitted trigger, got:\n{ddl}"
    );

    let mut conn = SqliteConnection::establish(":memory:").expect("open in-memory SQLite");

    // Register the functions the trigger body calls.
    current_app_user_utils::register_nondeterministic_impl(&mut conn, || "alice".to_owned())
        .expect("register current_app_user");
    uuidv4_utils::register_nondeterministic_impl(&mut conn, || vec![0x42u8; 16])
        .expect("register uuidv4");

    conn.batch_execute(&ddl)
        .expect("SQLite accepts the translated DDL");

    // Insert through the policy view without naming id.
    // Before the fix this raised: NOT NULL constraint failed: orders_rls.id
    diesel::insert_into(orders::table)
        .values((orders::owner_id.eq("alice"), orders::quantity.eq(3_i64)))
        .execute(&mut conn)
        .expect("insert through the policy view must succeed");

    // Confirm one row landed in the backing table with a non-null 16-byte id.
    let ids: Vec<Vec<u8>> = orders_rls::table
        .select(orders_rls::id)
        .load::<Vec<u8>>(&mut conn)
        .expect("read the backing table");

    assert_eq!(ids.len(), 1, "exactly one row must be in the backing table");
    assert_eq!(
        ids[0].len(),
        16,
        "the minted id must be 16 bytes (UUID Blob), got {:?}",
        ids[0]
    );
}
