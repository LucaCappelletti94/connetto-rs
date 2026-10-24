//! Replay departures and visibility withdrawals.

use core::convert::Infallible;

use sqlite_diff_rs::{ParsedDiffSet, PatchsetOp, Value as WireValue};
use subql::backend::Value as PgValue;

use super::*;

/// Refuses rows with `quantity >= 50` to `strict`.
struct QuantityCeiling;

impl VisibilityPolicy for QuantityCeiling {
    type Watcher = Arc<Principal>;
    type Error = Infallible;
    type Backend = Postgres;

    fn may_see<R>(
        &self,
        row: &R,
        watchers: &[Self::Watcher],
        verdicts: &mut [Verdict],
    ) -> impl Future<Output = Result<(), Infallible>>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        let PgValue::Int(quantity) = row.value_at(2).expect("quantity column") else {
            panic!("quantity must be an integer");
        };
        for (watcher, verdict) in watchers.iter().zip(verdicts.iter_mut()) {
            let user = watcher.identity().map(|identity| identity.user_id.as_str());
            let granted = matches!(user, Some("leader" | "strict" | "open"));
            let denied = user == Some("strict") && quantity >= 50;
            *verdict = if granted && !denied {
                Verdict::Allow
            } else {
                Verdict::Deny
            };
        }
        std::future::ready(Ok(()))
    }

    fn may_write<R>(
        &self,
        _write: RowWrite<'_, R>,
        _watcher: &Self::Watcher,
    ) -> impl Future<Output = Result<Verdict, Infallible>>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        std::future::ready(Ok(Verdict::Deny))
    }
}

fn single_delete_of(frame: &[u8], id: i64, marked: bool) {
    let raw = zstd::decode_all(frame).expect("the frame decompresses");
    let ParsedDiffSet::Patchset(set) = ParsedDiffSet::parse(&raw).expect("the frame parses") else {
        panic!("the frame is a patchset");
    };
    let mut ops = set.iter();
    let Some(PatchsetOp::Delete {
        table,
        pk,
        indirect,
    }) = ops.next()
    else {
        panic!("the frame is a single delete of the row");
    };
    assert!(ops.next().is_none(), "the notice has exactly one operation");
    assert_eq!(indirect, marked);
    assert_eq!(table.name(), "orders");
    assert_eq!(pk.to_vec(), [WireValue::Integer(id)]);
}

async fn update_frame(
    client: &mut WaveClient,
    id: i64,
    insert: &PgChangeEvent,
    update: &PgChangeEvent,
    applier: &Materializer,
    replica: &mut SqliteConnection,
) -> Vec<u8> {
    let BulkMessage::LivePatch(first) = next_bulk(&mut client.transport).await else {
        panic!("expected the row insert");
    };
    assert_eq!(first.sub_id, "orders");
    assert_eq!(first.cursor, cursor_of(insert));
    applier
        .apply_diffset(&first.patchset_zstd, replica)
        .expect("apply the row insert");
    assert_eq!(orders(replica), vec![order(id, 10.0, 30, "row")]);

    let BulkMessage::LivePatch(second) = next_bulk(&mut client.transport).await else {
        panic!("expected the row update frame");
    };
    assert_eq!(second.sub_id, "orders");
    assert_eq!(second.cursor, cursor_of(update));
    second.patchset_zstd
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_replay_departure_is_one_marked_notice_for_every_window_left() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let (manager, script, mut events, mut source) = scripted_for(
            &fixture,
            SessionConfig::default(),
            &["leader", "left", "also", "keeper"],
        )
        .await;
        events.extend(
            drive(
                &mut source,
                &manager,
                "INSERT INTO orders (id, price, quantity, status) VALUES (5, 10.0, 30, 'row')",
            )
            .await,
        );
        events.extend(
            drive(
                &mut source,
                &manager,
                "UPDATE orders SET quantity = 60 WHERE id = 5",
            )
            .await,
        );
        let (insert5, update5) = (&events[3], &events[4]);

        let applier = Materializer::builder(PG_DDL)
            .build()
            .expect("build the applier");
        let resume = cursor_of(&events[2]);

        arm(&script, &[], true, None);
        let (arrived, release) = hold_page(&script);
        let mut leader = wave_client(&manager, &script, "leader", cursor_of(&events[3])).await;
        leader.subscribe(QUERY).await;
        page_arrived(&arrived).await;
        let mut left = wave_client(&manager, &script, "left", resume.clone()).await;
        left.subscribe("SELECT * FROM orders WHERE quantity < 50")
            .await;
        let mut also = wave_client(&manager, &script, "also", resume.clone()).await;
        also.subscribe("SELECT * FROM orders WHERE quantity <= 40")
            .await;
        let mut keeper = wave_client(&manager, &script, "keeper", resume).await;
        keeper
            .subscribe("SELECT * FROM orders WHERE price > 0")
            .await;
        release.notify_one();
        expect_patches(&mut leader.transport, &events[4..]).await;

        let mut replica_left = client_replica();
        let notice_left =
            update_frame(&mut left, 5, insert5, update5, &applier, &mut replica_left).await;
        single_delete_of(&notice_left, 5, true);
        applier
            .apply_diffset(&notice_left, &mut replica_left)
            .expect("apply the departure");
        assert!(
            orders(&mut replica_left).is_empty(),
            "left no longer holds the row"
        );

        let mut replica_also = client_replica();
        let notice_also =
            update_frame(&mut also, 5, insert5, update5, &applier, &mut replica_also).await;
        single_delete_of(&notice_also, 5, true);
        applier
            .apply_diffset(&notice_also, &mut replica_also)
            .expect("apply the departure");
        assert!(
            orders(&mut replica_also).is_empty(),
            "also no longer holds the row"
        );

        let mut replica_keeper = client_replica();
        let plain = update_frame(
            &mut keeper,
            5,
            insert5,
            update5,
            &applier,
            &mut replica_keeper,
        )
        .await;
        applier
            .apply_diffset(&plain, &mut replica_keeper)
            .expect("apply the update");
        assert_eq!(orders(&mut replica_keeper), vec![order(5, 10.0, 60, "row")]);

        expect_catchup_end(&mut left.transport, "orders").await;
        expect_idle(&mut left.transport).await;
        expect_catchup_end(&mut also.transport, "orders").await;
        expect_idle(&mut also.transport).await;
        expect_catchup_end(&mut keeper.transport, "orders").await;
        expect_idle(&mut keeper.transport).await;
        left.close().await;
        also.close().await;
        keeper.close().await;
        leader.close().await;
    })
    .await
    .expect("the departure replay finished before the deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_update_crossing_the_policy_ceiling_withdraws_unmarked() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let (manager, script, mut events, mut source) =
            scripted_with_auth(&fixture, SessionConfig::default(), QuantityCeiling, PG_DDL).await;
        events.extend(
            drive(
                &mut source,
                &manager,
                "INSERT INTO orders (id, price, quantity, status) VALUES (6, 10.0, 30, 'row')",
            )
            .await,
        );
        events.extend(
            drive(
                &mut source,
                &manager,
                "UPDATE orders SET quantity = 60 WHERE id = 6",
            )
            .await,
        );
        let (insert6, update6) = (&events[3], &events[4]);

        let applier = Materializer::builder(PG_DDL)
            .build()
            .expect("build the applier");
        let resume = cursor_of(&events[2]);

        arm(&script, &[], true, None);
        let (arrived, release) = hold_page(&script);
        let mut leader = wave_client(&manager, &script, "leader", cursor_of(&events[3])).await;
        leader.subscribe(QUERY).await;
        page_arrived(&arrived).await;
        let mut strict = wave_client(&manager, &script, "strict", resume.clone()).await;
        strict
            .subscribe("SELECT * FROM orders WHERE price > 0")
            .await;
        let mut open = wave_client(&manager, &script, "open", resume).await;
        open.subscribe("SELECT * FROM orders WHERE price > 0").await;
        release.notify_one();
        expect_patches(&mut leader.transport, &events[4..]).await;

        let mut replica_strict = client_replica();
        let withdrawal = update_frame(
            &mut strict,
            6,
            insert6,
            update6,
            &applier,
            &mut replica_strict,
        )
        .await;
        single_delete_of(&withdrawal, 6, false);
        applier
            .apply_diffset(&withdrawal, &mut replica_strict)
            .expect("apply the withdrawal");
        assert!(
            orders(&mut replica_strict).is_empty(),
            "strict no longer holds the row"
        );

        let mut replica_open = client_replica();
        let plain = update_frame(&mut open, 6, insert6, update6, &applier, &mut replica_open).await;
        applier
            .apply_diffset(&plain, &mut replica_open)
            .expect("apply the update");
        assert_eq!(orders(&mut replica_open), vec![order(6, 10.0, 60, "row")]);

        expect_catchup_end(&mut strict.transport, "orders").await;
        expect_idle(&mut strict.transport).await;
        expect_catchup_end(&mut open.transport, "orders").await;
        expect_idle(&mut open.transport).await;
        strict.close().await;
        open.close().await;
        leader.close().await;
    })
    .await
    .expect("the withdrawal replay finished before the deadline");
}
