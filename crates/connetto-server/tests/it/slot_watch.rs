//! R32 step 2: the replication slot is observable, and the numbers are real.
//!
//! A slot retains write-ahead log on the primary until its consumer confirms
//! it, without limit unless the deployment caps it, so a stuck or departed
//! server fills the disk and stops writes for every application on it. connetto
//! cannot prevent that and can say it is happening, which is worth nothing if
//! the reading is wrong.
//!
//! So this asserts the reading against a real slot rather than asserting that a
//! log line was emitted: that the reservation is seen, that the retained figure
//! moves the way write-ahead log actually moves, that a slot which is not there
//! reads as absent rather than as zero, and that a slot belonging to another
//! database is not mistaken for this one.

use connetto_server::slot;
use connetto_test_harness::Fixture;

/// Its own slot name, so this never contends with the shared fixture slot the
/// end-to-end suites create and drop.
const SLOT: &str = "connetto_slot_watch";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_slot_reads_back_what_postgres_knows() {
    let fixture = Fixture::acquire().await;
    let admin = fixture.admin();
    fixture
        .setup(&[&format!(
            "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots \
             WHERE slot_name = '{SLOT}'"
        )])
        .await;

    assert_eq!(
        slot::read_lag(admin, SLOT).await.expect("read absent slot"),
        None,
        "a slot that is not there reads as absent, not as a slot holding nothing",
    );

    fixture
        .setup(&[&format!(
            "SELECT pg_create_logical_replication_slot('{SLOT}', 'pgoutput')"
        )])
        .await;
    let fresh = slot::read_lag(admin, SLOT)
        .await
        .expect("read the fresh slot")
        .expect("the slot exists");
    assert_eq!(
        fresh.wal_status.as_deref(),
        Some("reserved"),
        "a slot nobody has strained is reserved",
    );
    assert!(
        !fresh.active,
        "nothing is streaming from it, and a slot retaining log with no reader \
         is the shape that fills a disk",
    );
    let held = fresh
        .retained_bytes
        .expect("a reserved slot has a position");
    assert!(held >= 0, "the primary cannot be behind the slot: {held}");
    assert_eq!(
        fresh.safe_bytes, None,
        "max_slot_wal_keep_size is -1 by default, so there is no headroom to \
         report and the failure mode is the disk rather than invalidation",
    );

    // Force the write-ahead log forward. The slot is not consuming, so every
    // byte written is a byte it is now holding: the figure has to grow, and a
    // reading that were constant or backwards would pass every assertion above.
    fixture
        .setup(&[
            "CREATE TABLE IF NOT EXISTS slot_watch_churn (id BIGINT PRIMARY KEY, body TEXT)",
            "INSERT INTO slot_watch_churn \
             SELECT g, repeat('x', 2000) FROM generate_series(1, 2000) AS g \
             ON CONFLICT (id) DO UPDATE SET body = excluded.body",
            "SELECT pg_switch_wal()",
        ])
        .await;
    let later = slot::read_lag(admin, SLOT)
        .await
        .expect("read the slot again")
        .expect("the slot exists");
    let grown = later.retained_bytes.expect("still has a position");
    assert!(
        grown > held,
        "the slot is not consuming, so writing must have grown what it holds: \
         {held} then {grown}",
    );

    fixture
        .setup(&[
            &format!("SELECT pg_drop_replication_slot('{SLOT}')"),
            "DROP TABLE IF EXISTS slot_watch_churn",
        ])
        .await;
    assert_eq!(
        slot::read_lag(admin, SLOT).await.expect("read after drop"),
        None,
        "a dropped slot reads as absent, which is what the watch warns about",
    );
}

/// A slot of the same name in a neighbouring database is not this one.
///
/// `pg_replication_slots` lists the whole cluster and a logical slot name is
/// unique cluster-wide rather than per database, so a bare name match reads a
/// neighbour's slot and calls it ours. That is not hypothetical: it is how the
/// startup check first passed on a database that had no slot at all, found by
/// running it against a cluster where another database happened to have one.
///
/// The scratch database is created and dropped here rather than assumed,
/// because the property is only observable when two databases hold the name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_neighbouring_databases_slot_is_not_this_one() {
    let fixture = Fixture::acquire().await;
    let neighbour_db = "connetto_slot_watch_neighbour";
    // FORCE because a lingering connection would otherwise block the drop, and
    // a leftover database blocks the next run's create.
    fixture
        .setup(&[&format!(
            "DROP DATABASE IF EXISTS {neighbour_db} WITH (FORCE)"
        )])
        .await;
    fixture
        .setup(&[&format!("CREATE DATABASE {neighbour_db}")])
        .await;

    let neighbour_url = fixture
        .admin_url()
        .rsplit_once('/')
        .map(|(head, _)| format!("{head}/{neighbour_db}"))
        .expect("the admin url names a database");
    {
        let neighbour = connetto_test_harness::pool_for(&neighbour_url).await;
        connetto_test_harness::exec(
            &neighbour,
            &format!("SELECT pg_create_logical_replication_slot('{SLOT}', 'pgoutput')"),
        )
        .await;

        assert_eq!(
            slot::read_lag(fixture.admin(), SLOT)
                .await
                .expect("read from this database"),
            None,
            "the slot exists in the cluster and belongs to another database, so \
             from here it is absent and unusable",
        );

        connetto_test_harness::exec(
            &neighbour,
            &format!("SELECT pg_drop_replication_slot('{SLOT}')"),
        )
        .await;
    }

    fixture
        .setup(&[&format!(
            "DROP DATABASE IF EXISTS {neighbour_db} WITH (FORCE)"
        )])
        .await;
}
