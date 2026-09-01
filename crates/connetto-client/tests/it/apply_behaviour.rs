//! What SQLite's own apply does, measured rather than assumed (R56 step 7).
//!
//! The import design leans on two behaviours that were stated from
//! documentation and memory during the design discussion. Both are pinned here,
//! because each decides something: whether a table absent from the target has
//! to be refused before applying, and whether a failed apply can leave a
//! partial import behind.

use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::{Connection, SqliteConnection};
use diesel_sqlite_session::{ConflictAction, SqliteSessionExt};
use sqlite_diff_rs::{ChangeSet, DiffOps, Insert, PatchSet, SimpleTable, Value};

/// A patchset inserting one row of `table`, built by hand so the target need
/// not have the table at all.
fn one_insert(table: &str) -> Vec<u8> {
    let schema = SimpleTable::new(table, &["id", "body"], &[0]);
    PatchSet::<SimpleTable, String, Vec<u8>>::new()
        .insert(
            Insert::from(schema)
                .set(0, Value::Integer(1))
                .expect("key")
                .set(1, Value::Text("row".to_owned()))
                .expect("body"),
        )
        .build()
}

/// A changeset inserting two rows of `table`, the second colliding with a row
/// the target already holds.
fn two_inserts(table: &str) -> Vec<u8> {
    let schema = SimpleTable::new(table, &["id", "body"], &[0]);
    ChangeSet::<SimpleTable, String, Vec<u8>>::new()
        .insert(
            Insert::from(schema.clone())
                .set(0, Value::Integer(1))
                .expect("key")
                .set(1, Value::Text("first".to_owned()))
                .expect("body"),
        )
        .insert(
            Insert::from(schema)
                .set(0, Value::Integer(2))
                .expect("key")
                .set(1, Value::Text("second".to_owned()))
                .expect("body"),
        )
        .build()
}

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    rows: i64,
}

fn rows(db: &mut SqliteConnection) -> i64 {
    diesel::sql_query("SELECT count(*) AS rows FROM present")
        .load::<Count>(db)
        .expect("count")
        .first()
        .map_or(0, |count| count.rows)
}

/// A record naming a table the target does not have applies as a success and
/// writes nothing.
///
/// So an import cannot learn about a missing table from the apply: it has to
/// check the table set itself first, which is what `R56` decision 6 says and
/// what the refusal in `import_local_data` does. This is the same silent-loss
/// shape `R26` and `R40` were both bitten by.
#[test]
fn an_absent_table_is_skipped_in_silence() {
    let mut db = SqliteConnection::establish(":memory:").expect("open");
    db.batch_execute("CREATE TABLE present (id INTEGER PRIMARY KEY, body TEXT)")
        .expect("schema");

    let applied = db.apply_patchset(&one_insert("absent"), |_| ConflictAction::Abort);

    assert!(
        applied.is_ok(),
        "an absent table reports nothing, so it cannot be detected here: {applied:?}"
    );
    assert_eq!(rows(&mut db), 0, "and nothing was written");
}

/// A failed apply leaves nothing behind: SQLite rolls its own apply back.
///
/// Measured because the design assumed it. It holds for one apply, which is
/// why an import still wraps its whole sequence of applies in one transaction:
/// per-apply atomicity is not per-import atomicity.
#[test]
fn a_failed_apply_leaves_nothing_behind() {
    let mut db = SqliteConnection::establish(":memory:").expect("open");
    db.batch_execute(
        "CREATE TABLE present (id INTEGER PRIMARY KEY, body TEXT);
         INSERT INTO present (id, body) VALUES (2, 'already here');",
    )
    .expect("schema");

    let applied = db.apply_changeset(&two_inserts("present"), |_| ConflictAction::Abort);

    assert!(applied.is_err(), "the collision aborts the apply");
    assert_eq!(
        rows(&mut db),
        1,
        "the row before the collision went with it, so one apply is atomic"
    );
}

/// And inside a transaction, which is the shape the import uses, it is the
/// same: the rollback is the outer one and nothing survives it.
#[test]
fn a_failed_apply_inside_a_transaction_leaves_nothing_either() {
    let mut db = SqliteConnection::establish(":memory:").expect("open");
    db.batch_execute(
        "CREATE TABLE present (id INTEGER PRIMARY KEY, body TEXT);
         INSERT INTO present (id, body) VALUES (2, 'already here');",
    )
    .expect("schema");

    let outcome: Result<(), diesel::result::Error> = db.transaction(|db| {
        db.apply_changeset(&two_inserts("present"), |_| ConflictAction::Abort)
            .map_err(|_| diesel::result::Error::RollbackTransaction)
    });

    assert!(outcome.is_err(), "the apply still fails");
    assert_eq!(
        rows(&mut db),
        1,
        "and the rollback took the partial write with it"
    );
}
