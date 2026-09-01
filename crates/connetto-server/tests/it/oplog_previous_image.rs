//! The reconnect log keeps the row as it was, across the round trip it makes
//! (R6).
//!
//! Catchup re-answers the two-check question from the log rather than from the
//! change stream, so a caller who lost access while disconnected is only taken
//! back to a correct set if the stored event still carries the previous row
//! image. `PgOplog` stores the whole event as JSON and reads it back the same
//! way, and nothing tested that the old image survived that.
//!
//! Native rather than Docker-gated on purpose: what is at risk is the encoding,
//! not the database. A gated test would prove the same thing more slowly and
//! would not run in the ordinary suite.

use std::sync::Arc;

use pg_walstream::{ChangeEvent, ColumnValue, Lsn, ReplicaIdentity, RowData};
use sqlparser::dialect::PostgreSqlDialect;
use subql::ParserDB;
use subql::backend::Value;
use subql::visibility::{EventRow, RowView};

const SCHEMA: &str = "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT NOT NULL);";

fn row_data(columns: &[(&str, &str)]) -> RowData {
    let mut row = RowData::with_capacity(columns.len());
    for (name, value) in columns {
        row.push(Arc::from(*name), ColumnValue::text(value));
    }
    row
}

/// An update's previous row image survives being stored and read back.
///
/// The assertion is on the non-key column, because that is the one the policy
/// reads and the one `REPLICA IDENTITY DEFAULT` would have left out. Asserting
/// the key alone would pass under exactly the configuration this phase refuses.
#[test]
fn the_reconnect_log_round_trips_the_row_as_it_was() {
    let catalog = ParserDB::parse::<PostgreSqlDialect>(SCHEMA).expect("catalog");
    let event = ChangeEvent::update(
        "public",
        "notes",
        0,
        Some(row_data(&[("id", "1"), ("owner", "alice")])),
        row_data(&[("id", "1"), ("owner", "bob")]),
        ReplicaIdentity::Full,
        vec![Arc::from("id")],
        Lsn::new(1),
    );

    let stored = serde_json::to_vec(&event).expect("the log stores the event");
    let read_back: ChangeEvent = serde_json::from_slice(&stored).expect("the log reads it back");

    let previous = EventRow::previous(&read_back, &catalog).expect("the old image is still there");
    assert_eq!(
        previous.value_at(1).expect("the owner column decodes"),
        Value::String("alice".into()),
        "catchup answers about the version the caller could see, so the stored \
         event has to carry the values the policy reads, not just the key"
    );
    let current = EventRow::current(&read_back, &catalog).expect("the new image is still there");
    assert_eq!(
        current.value_at(1).expect("the owner column decodes"),
        Value::String("bob".into()),
        "and the new version too, or the row would be withdrawn from everybody"
    );
}
