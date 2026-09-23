//! R70 decision 8: the recorded cluster against the one the database reports.

use connetto_server::epoch::{EPOCH_DDL, Epoch, compare, record};
use connetto_test_harness::{Fixture, exec};

#[tokio::test]
async fn a_changed_cluster_stays_changed_until_it_is_recorded() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin();
    exec(pool, "DROP TABLE IF EXISTS connetto_epoch").await;
    exec(pool, EPOCH_DDL).await;

    assert_eq!(compare(pool, 7).await.expect("compare"), Epoch::First);
    assert_eq!(
        compare(pool, 7).await.expect("compare"),
        Epoch::First,
        "comparing writes nothing"
    );
    record(pool, 7).await.expect("record");
    assert_eq!(compare(pool, 7).await.expect("compare"), Epoch::Same);

    let restored = Epoch::Changed { recorded: 7 };
    assert_eq!(compare(pool, 9).await.expect("compare"), restored);
    assert_eq!(
        compare(pool, 9).await.expect("compare"),
        restored,
        "a revocation that failed before the record meets the change again"
    );
    record(pool, 9).await.expect("record");
    assert_eq!(compare(pool, 9).await.expect("compare"), Epoch::Same);

    record(pool, u64::MAX).await.expect("record");
    assert_eq!(
        compare(pool, u64::MAX).await.expect("compare"),
        Epoch::Same,
        "an identifier past the signed range round-trips"
    );
}
