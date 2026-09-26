//! A transaction that commits after a newer one reaches every subscriber, in commit order.
//!
//! The older transaction writes first and stays open while a newer one
//! commits, then commits itself. Its rows arrive second, and before subql
//! ordered positions by commit they carried a lower position than the newer
//! row, so the cursor advance refused them, the change feed restarted on them
//! for ever, and no subscriber ever received them.
//!
//! The same run proves the other half of commit ordering: the slot is released
//! to the end of each acknowledged commit, which is exactly the end the ingest
//! recorded first, so the check a reconnect makes reads it as no gap.
//!
//! Needs Docker: the fixture starts its own Postgres and its own `OpenFGA`.

use std::collections::BTreeSet;
use std::time::Duration;

use connetto_server::counters;
use connetto_server::{Position, slot};
use connetto_test_harness::fanout::visibility_fixture;
use connetto_test_harness::{Client, Fixture, SLOT};
use diesel_async::SimpleAsyncConnection;
use sqlite_diff_rs::{ParsedDiffSet, PatchsetOp, Value as WireValue};

/// Everything the owner may see.
const QUERY: &str = "SELECT * FROM items WHERE id > 0";

/// How long a row that should arrive is given.
const DELIVERY: Duration = Duration::from_secs(30);

/// The ids a live patch inserts.
fn inserted_ids(patchset_zstd: &[u8]) -> Vec<i64> {
    let bytes = zstd::decode_all(patchset_zstd).expect("decompress");
    let Ok(ParsedDiffSet::Patchset(set)) = ParsedDiffSet::parse(&bytes) else {
        return Vec::new();
    };
    set.iter()
        .filter_map(|op| match op {
            PatchsetOp::Insert { values, .. } => match values.first() {
                Some(WireValue::Integer(id)) => Some(*id),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// Read live patches until `expected` ids have all arrived, returning the ids in arrival order and each patch's position.
async fn receive(client: &mut Client, expected: &BTreeSet<i64>) -> Vec<(i64, Position)> {
    let mut arrived = Vec::new();
    while !expected
        .iter()
        .all(|id| arrived.iter().any(|(seen, _)| seen == id))
    {
        let patch = client
            .try_live(DELIVERY)
            .await
            .unwrap_or_else(|| panic!("only {arrived:?} of {expected:?} arrived"));
        let position = Position::from_cursor_bytes(patch.cursor.as_bytes()).expect("a live cursor");
        arrived.extend(
            inserted_ids(&patch.patchset_zstd)
                .into_iter()
                .map(|id| (id, position)),
        );
    }
    arrived
}

/// One open transaction writing `older_rows` rows while an autocommit insert commits, then committing.
async fn an_older_transaction_committing_last_reaches_every_subscriber(older_rows: i64) {
    let fixture = Fixture::acquire().await;
    let server = visibility_fixture(&fixture).await;
    let rewinds = counters::snapshot();

    let mut subscribers = Vec::new();
    for device in ["a", "b"] {
        let mut client = server.connect();
        client
            .handshake_with(
                &format!("interleaved-{device}"),
                &format!("user:alice#{device}"),
            )
            .await;
        client.subscribe("items", QUERY).await;
        client.expect_snapshot("items").await;
        subscribers.push(client);
    }

    let mut older = fixture.admin().get().await.expect("a second connection");
    older.batch_execute("BEGIN").await.expect("begin");
    for offset in 0..older_rows {
        older
            .batch_execute(&format!(
                "INSERT INTO items (id, owner, label) VALUES ({}, 'alice', 'older')",
                100 + offset
            ))
            .await
            .expect("the older transaction's write");
    }
    fixture
        .exec("INSERT INTO items (id, owner, label) VALUES (1, 'alice', 'newer')")
        .await;
    older
        .batch_execute("COMMIT")
        .await
        .expect("commit the older");

    let older_ids: Vec<i64> = (0..older_rows).map(|offset| 100 + offset).collect();
    let expected: BTreeSet<i64> = older_ids.iter().copied().chain([1]).collect();
    let mut latest_commit_lsn = 0;
    for subscriber in &mut subscribers {
        let arrived = receive(subscriber, &expected).await;
        latest_commit_lsn = arrived
            .iter()
            .map(|(_, position)| position.at.commit_lsn().0)
            .fold(latest_commit_lsn, u64::max);
        let arrival: Vec<i64> = arrived.iter().map(|(id, _)| *id).collect();
        assert_eq!(
            arrival,
            [1].into_iter()
                .chain(older_ids.iter().copied())
                .collect::<Vec<_>>(),
            "rows arrive in the order their transactions committed"
        );
        assert!(
            arrived.windows(2).all(|pair| pair[0].1.at < pair[1].1.at),
            "positions strictly increase in delivery order: {arrived:?}"
        );
    }
    // The newest commit's rows reached every subscriber, so acknowledging it releases the slot to where that commit ends.
    let deadline = tokio::time::Instant::now() + DELIVERY;
    loop {
        let resumed = slot::resume_position(fixture.admin(), SLOT)
            .await
            .expect("read the slot")
            .expect("the slot has a confirmed position");
        let check = server
            .manager()
            .check_before_stream(fixture.admin_url(), fixture.admin(), SLOT)
            .await
            .expect("check the stream");
        assert_eq!(
            check.gap, None,
            "a slot released to acknowledged commits is never read as a gap, at {resumed}"
        );
        if resumed > latest_commit_lsn {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the slot was never released past the acknowledged commits"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        counters::snapshot().since(&rewinds).cursor_rewinds,
        0,
        "no cursor advance was refused"
    );
    assert_eq!(
        server.ingest_restarts(),
        0,
        "the change feed never restarted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_row_committed_after_a_newer_transaction_reaches_every_subscriber() {
    an_older_transaction_committing_last_reaches_every_subscriber(1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_rows_committed_after_a_newer_transaction_reach_every_subscriber() {
    an_older_transaction_committing_last_reaches_every_subscriber(2).await;
}
