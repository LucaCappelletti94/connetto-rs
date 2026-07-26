//! The custom SQL-function registration mechanism, exercised natively.
//!
//! connetto opens every replica connection itself, so it owns the point where
//! a schema's key-generating function must be registered. [`SqlFunctions`] is
//! that seam: [`ConnettoConnection::connect`] runs `SqlFunctions::install` on
//! the fresh connection before any DDL or insert. This test drives `install`
//! the same way, then proves a column `DEFAULT` that calls the registered
//! function fires per row (the nondeterministic registrar, so SQLite never
//! folds the DEFAULT to a constant).

use connetto_client::SqlFunctions;
use core::sync::atomic::{AtomicI64, Ordering};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use std::sync::Arc;

// A stand-in for an app's key generator: a monotonic counter, so each row's
// DEFAULT yields a distinct, exactly assertable value.
#[diesel::declare_sql_function]
extern "SQL" {
    /// A monotonic counter, standing in for an app's key generator.
    fn next_seq() -> diesel::sql_types::BigInt;
}

diesel::table! {
    minted (id) {
        id -> diesel::sql_types::BigInt,
        label -> diesel::sql_types::Text,
    }
}

#[test]
fn installer_registers_a_function_that_fires_a_column_default() {
    let counter = Arc::new(AtomicI64::new(0));

    // The installer connetto stores in ClientConfig: it registers a
    // nondeterministic function on whatever connection connetto opens.
    let installer_counter = Arc::clone(&counter);
    let functions = SqlFunctions::new().with(Arc::new(move |conn: &mut SqliteConnection| {
        let counter = Arc::clone(&installer_counter);
        next_seq_utils::register_nondeterministic_impl(conn, move || {
            counter.fetch_add(1, Ordering::Relaxed) + 1
        })
    }));
    assert_eq!(functions.len(), 1, "one installer registered");

    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    functions
        .install(&mut conn)
        .expect("install the app functions");

    conn.batch_execute(
        "CREATE TABLE minted (id BIGINT PRIMARY KEY DEFAULT (next_seq()) NOT NULL, label TEXT)",
    )
    .expect("create table with a function-backed default");

    // Insert twice omitting the key: the DEFAULT mints it each time.
    diesel::insert_into(minted::table)
        .values(minted::label.eq("first"))
        .execute(&mut conn)
        .expect("insert omitting id");
    diesel::insert_into(minted::table)
        .values(minted::label.eq("second"))
        .execute(&mut conn)
        .expect("insert omitting id");

    let ids: Vec<i64> = minted::table
        .order(minted::label)
        .select(minted::id)
        .load(&mut conn)
        .expect("read minted ids");

    assert_eq!(
        ids,
        vec![1, 2],
        "the DEFAULT fired once per row through the registered nondeterministic function"
    );
}

#[test]
fn default_functions_is_empty() {
    let functions = SqlFunctions::default();
    assert!(functions.is_empty(), "connetto ships no built-in functions");
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    functions
        .install(&mut conn)
        .expect("installing an empty set is a no-op");
}
