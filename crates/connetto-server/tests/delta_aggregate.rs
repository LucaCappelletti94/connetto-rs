//! Materializer-level coverage for the delta aggregate path.
//!
//! Tests registration classification (delta aggregate versus row) and the
//! in-process fold, calling the public [`Materializer`] API directly without
//! the session, routing, or transport layers, so a regression in the register
//! split or the dispatch fold surfaces here before the full end-to-end loop.

use connetto_server::{Materializer, Registration};
use subql::backend::ScalarKind;
use subql::{AggAccumulator, AggSpec, CdcSource, PgSqliteEmuSource};

const PG_DDL: &str = "CREATE TABLE orders (id INT PRIMARY KEY, quantity INT);";

#[test]
fn register_classifies_delta_aggregate_and_row() {
    let mut mat = Materializer::new(PG_DDL).expect("build materializer");

    let Registration::DeltaAggregate(cap) = mat
        .register(1, "SELECT COUNT(*) FROM orders")
        .expect("register count")
    else {
        panic!("COUNT(*) should register as a delta aggregate");
    };
    assert_eq!(cap.consumer_id, 1);
    assert_eq!(cap.spec, AggSpec::CountStar);
    assert_eq!(cap.bootstrap.kinds, vec![ScalarKind::Int]);
    assert!(
        cap.bootstrap.sql.contains("COUNT(*)"),
        "bootstrap SQL should carry the aggregate, got {:?}",
        cap.bootstrap.sql,
    );

    let row = mat
        .register(2, "SELECT * FROM orders WHERE quantity > 0")
        .expect("register row");
    assert!(
        matches!(row, Registration::Row(_)),
        "SELECT * should register as a row subscription",
    );
}

#[tokio::test]
async fn dispatch_folds_installed_delta_aggregate() {
    let mut mat = Materializer::new(PG_DDL).expect("build materializer");
    let Registration::DeltaAggregate(cap) = mat
        .register(1, "SELECT COUNT(*) FROM orders")
        .expect("register")
    else {
        panic!("expected a delta aggregate");
    };

    // Seed the accumulator empty (COUNT = 0), as the session would after a
    // zero-row bootstrap, then install it under the consumer id.
    let acc = AggAccumulator::from_spec(&cap.spec);
    mat.install_aggregate(cap.consumer_id, cap.spec, acc);

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");

    // Two inserts then a delete: the fold tracks 0 -> 1 -> 2 -> 1, one folded
    // value per dispatched event, keyed to the installed consumer.
    for (sql, want) in [
        ("INSERT INTO orders (id, quantity) VALUES (1, 10)", "1"),
        ("INSERT INTO orders (id, quantity) VALUES (2, 20)", "2"),
        ("DELETE FROM orders WHERE id = 1", "1"),
    ] {
        source.execute_sql(sql).expect("execute dml");
        let mut last = None;
        while let Some(event) = source.next_event().await.expect("poll source") {
            let dispatched = mat.dispatch(&event).expect("dispatch");
            for change in dispatched.delta_aggregates {
                assert_eq!(change.consumer_id, 1);
                last = Some(change.result_json);
            }
        }
        assert_eq!(last.as_deref(), Some(want), "fold mismatch after `{sql}`");
    }
}

#[tokio::test]
async fn dispatch_without_installed_aggregate_yields_no_delta() {
    // Registering a delta aggregate but never installing its accumulator must
    // not fold: the dispatch skips the aggregate path entirely (the common
    // no-aggregate workload) and produces no delta change.
    let mut mat = Materializer::new(PG_DDL).expect("build materializer");
    mat.register(1, "SELECT COUNT(*) FROM orders")
        .expect("register");

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, quantity) VALUES (1, 10)")
        .expect("execute dml");
    while let Some(event) = source.next_event().await.expect("poll source") {
        let dispatched = mat.dispatch(&event).expect("dispatch");
        assert!(
            dispatched.delta_aggregates.is_empty(),
            "no accumulator installed, so no delta should be produced",
        );
    }
}
