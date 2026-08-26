//! Materializer-level coverage for the fold aggregate path.
//!
//! Tests registration classification (fold aggregate versus row) and the
//! in-process fold, calling the public [`Materializer`] API directly without
//! the session, routing, or transport layers, so a regression in the register
//! split or the dispatch fold surfaces here before the full end-to-end loop.

use connetto_server::{Materializer, Registration, SeedPlan};
use subql::backend::{ScalarKind, Value as PgValue};
use subql::{CdcSource, PgSqliteEmuSource};

const PG_DDL: &str = "CREATE TABLE orders (id INT PRIMARY KEY, quantity INT);";

#[test]
fn register_classifies_fold_aggregate_and_row() {
    let mut mat = Materializer::new(PG_DDL).expect("build materializer");

    let Registration::Computed(cap) = mat
        .register(1, "SELECT COUNT(*) FROM orders")
        .expect("register count")
    else {
        panic!("COUNT(*) should register as a computed subscription");
    };
    assert_eq!(cap.consumer_id, 1);
    let SeedPlan::Fold { bootstrap } = &cap.seed else {
        panic!("ungrouped COUNT(*) should seed as a fold");
    };
    assert_eq!(bootstrap.group_columns, 0, "COUNT(*) is ungrouped");
    assert_eq!(bootstrap.kinds, vec![ScalarKind::Int]);
    assert!(
        bootstrap.sql.contains("COUNT(*)"),
        "bootstrap SQL should carry the aggregate, got {:?}",
        bootstrap.sql,
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
async fn install_fold_seed_delivers_initial_computed_value() {
    // The seed's initial value arrives in FoldSeeded.changes, not through
    // dispatch: nothing has changed yet, so there is nothing to dispatch.
    // Later changes flow through dispatch, which
    // dispatch_folds_an_installed_ungrouped_count pins.
    let mut mat = Materializer::new(PG_DDL).expect("build materializer");
    let Registration::Computed(cap) = mat
        .register(1, "SELECT COUNT(*) FROM orders")
        .expect("register")
    else {
        panic!("expected a computed subscription");
    };
    let SeedPlan::Fold { .. } = &cap.seed else {
        panic!("expected a fold seed plan");
    };

    // Seed with COUNT = 0: the initial change carries "0" as JSON.
    let seeded = mat
        .install_fold_seed(cap.subscription_id, vec![vec![PgValue::Int(0)]], None)
        .expect("seed fold");
    assert!(
        !seeded.needs_snapshot,
        "COUNT(*) fold should not demote to snapshot"
    );
    let initial_values: Vec<Option<String>> = seeded
        .changes
        .iter()
        .map(|c| c.result_json.clone())
        .collect();
    assert_eq!(
        initial_values,
        vec![Some("0".to_owned())],
        "seed delivers the initial COUNT as a computed change"
    );

    // Seeding with a non-zero count delivers the actual count.
    let Registration::Computed(cap2) = mat
        .register(2, "SELECT COUNT(*) FROM orders")
        .expect("register second")
    else {
        panic!("expected a computed subscription");
    };
    let seeded2 = mat
        .install_fold_seed(cap2.subscription_id, vec![vec![PgValue::Int(42)]], None)
        .expect("seed second fold");
    assert_eq!(
        seeded2
            .changes
            .iter()
            .map(|c| c.result_json.clone())
            .collect::<Vec<_>>(),
        vec![Some("42".to_owned())],
        "seed with 42 delivers 42 as JSON"
    );
}

#[tokio::test]
async fn dispatch_without_installed_fold_yields_no_computed() {
    // Registering a fold but never installing its seed must produce no
    // computed output: the engine holds buffered changes until the session
    // calls install_fold_seed.
    let mut mat = Materializer::new(PG_DDL).expect("build materializer");
    mat.register(1, "SELECT COUNT(*) FROM orders")
        .expect("register");

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, quantity) VALUES (1, 10)")
        .expect("execute dml");
    while let Some(event) = source.next_event().await.expect("poll source") {
        let dispatched = mat.dispatch(&event).await.expect("dispatch");
        assert!(
            dispatched.computed.is_empty(),
            "no fold seed installed, so no computed change should be produced",
        );
    }
}

/// The U11 acceptance, pinned here so the channel can never silently close
/// again: an installed ungrouped fold updates through dispatch itself.
#[tokio::test]
async fn dispatch_folds_an_installed_ungrouped_count() {
    let mut mat = Materializer::new(PG_DDL).expect("build materializer");
    let Registration::Computed(cap) = mat
        .register(1, "SELECT COUNT(*) FROM orders")
        .expect("register")
    else {
        panic!("expected a computed subscription");
    };
    mat.install_fold_seed(cap.subscription_id, vec![vec![PgValue::Int(0)]], None)
        .expect("seed fold");

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, quantity) VALUES (1, 10)")
        .expect("execute dml");
    let mut folded = Vec::new();
    while let Some(event) = source.next_event().await.expect("poll source") {
        folded.extend(mat.dispatch(&event).await.expect("dispatch").computed);
    }
    assert_eq!(folded.len(), 1, "one insert moves the count exactly once");
    assert_eq!(folded[0].subscription_id, cap.subscription_id);
    assert_eq!(folded[0].group_key, None, "ungrouped: no key");
    assert_eq!(folded[0].result_json.as_deref(), Some("1"));
}

/// R82's grouped loopback assertion: a grouped fold seeds one value per
/// group, an insert moves exactly its own group's value with the key on the
/// change, the sibling group stays silent, and a group whose last source row
/// goes is removed (`result_json: None`).
#[tokio::test]
async fn dispatch_folds_a_grouped_count_per_group() {
    const GROUPED_DDL: &str =
        "CREATE TABLE orders (id INT PRIMARY KEY, quantity INT, status TEXT);";
    let mut mat = Materializer::new(GROUPED_DDL).expect("build materializer");
    let Registration::Computed(cap) = mat
        .register(1, "SELECT status, COUNT(*) FROM orders GROUP BY status")
        .expect("register grouped")
    else {
        panic!("expected a computed subscription");
    };
    let SeedPlan::Fold { bootstrap } = &cap.seed else {
        panic!("a grouped accumulable registers as a fold");
    };
    assert_eq!(bootstrap.group_columns, 1, "one group column");

    // Two groups as the table stands: one 'a' row (id 1), one 'b' row (id 2).
    let seeded = mat
        .install_fold_seed(
            cap.subscription_id,
            vec![
                vec![
                    PgValue::String("a".to_owned()),
                    PgValue::Int(1),
                    PgValue::Int(1),
                ],
                vec![
                    PgValue::String("b".to_owned()),
                    PgValue::Int(1),
                    PgValue::Int(1),
                ],
            ],
            None,
        )
        .expect("seed grouped fold");
    assert!(
        !seeded.needs_snapshot,
        "two groups sit far under the budget"
    );
    assert_eq!(seeded.changes.len(), 2, "one initial value per group");
    let key_a = seeded.changes[0]
        .group_key
        .clone()
        .expect("grouped changes carry keys");
    assert!(
        seeded.changes.iter().all(|c| c.group_key.is_some()
            && c.result_json.as_deref() == Some("1")
            && !c.is_full_result),
        "each group seeds its own value as a keyed upsert",
    );

    // One source holds the baseline the seed already counts (the 'a' and 'b'
    // rows). Their events are drained without dispatching: the canned seed
    // and the emu share no clock, so the test does by hand what read_at does
    // against a real source, keeping already-counted rows out of the fold.
    let mut source = PgSqliteEmuSource::open_in_memory(GROUPED_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, quantity, status) VALUES (1, 10, 'a'), (2, 20, 'b')")
        .expect("baseline rows");
    while let Some(_baseline) = source.next_event().await.expect("poll source") {}

    source
        .execute_sql("INSERT INTO orders (id, quantity, status) VALUES (3, 30, 'a')")
        .expect("insert into a");
    let mut moved = Vec::new();
    while let Some(event) = source.next_event().await.expect("poll source") {
        moved.extend(mat.dispatch(&event).await.expect("dispatch").computed);
    }
    assert_eq!(moved.len(), 1, "only the touched group moves");
    assert_eq!(
        moved[0].group_key.as_deref(),
        Some(key_a.as_slice()),
        "the change addresses group a by the same key its seed used",
    );
    assert_eq!(moved[0].result_json.as_deref(), Some("2"));
    assert!(
        !moved[0].is_full_result,
        "a grouped fold delta is an upsert"
    );

    source
        .execute_sql("DELETE FROM orders WHERE status = 'b'")
        .expect("delete b");
    let mut removed = Vec::new();
    while let Some(event) = source.next_event().await.expect("poll source") {
        removed.extend(mat.dispatch(&event).await.expect("dispatch").computed);
    }
    assert_eq!(removed.len(), 1, "the emptied group produces one removal");
    assert!(
        removed[0].group_key.as_deref() != Some(key_a.as_slice()) && removed[0].group_key.is_some(),
        "the removal addresses group b",
    );
    assert_eq!(
        removed[0].result_json, None,
        "a group with no source rows left is removed, not zeroed",
    );
}

/// R82's demotion assertion: a seed whose groups already exceed the budget
/// demotes at install, answering by whole re-read from then on, with the
/// transition logged and counted rather than told to the client.
#[tokio::test]
async fn a_seed_past_the_group_budget_demotes_to_a_whole_read() {
    const GROUPED_DDL: &str =
        "CREATE TABLE orders (id INT PRIMARY KEY, quantity INT, status TEXT);";
    let mut mat = Materializer::new(GROUPED_DDL).expect("build materializer");
    let Registration::Computed(cap) = mat
        .register(1, "SELECT status, COUNT(*) FROM orders GROUP BY status")
        .expect("register grouped")
    else {
        panic!("expected a computed subscription");
    };
    // One row per group, one past subql's default budget of 1024.
    let rows: Vec<Vec<PgValue<subql::backend::Postgres>>> = (0..=1024)
        .map(|group| {
            vec![
                PgValue::String(format!("g{group}")),
                PgValue::Int(1),
                PgValue::Int(1),
            ]
        })
        .collect();
    let seeded = mat
        .install_fold_seed(cap.subscription_id, rows, None)
        .expect("an over-budget seed demotes rather than failing");
    assert!(
        seeded.needs_snapshot,
        "the demotion leaves the first answer to the follow-up whole read",
    );
    assert!(
        seeded.changes.is_empty(),
        "no per-group values are delivered for a demoted seed",
    );
}
