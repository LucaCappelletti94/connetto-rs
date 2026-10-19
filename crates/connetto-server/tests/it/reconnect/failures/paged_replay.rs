use super::*;

async fn expect_complete_replay(
    client: &mut LoopbackTransport,
    events: &[PgChangeEvent],
    held: impl Fn(&PgChangeEvent) -> bool,
    expected: &[Order],
) {
    let applier = Materializer::builder(PG_DDL)
        .build()
        .expect("build applier");
    let mut replica = client_replica();
    for event in events.iter().filter(|event| held(event)) {
        let patch = applier.encode_patch(event).expect("encode snapshot row");
        applier
            .apply_diffset(&patch, &mut replica)
            .expect("seed snapshot row");
    }
    for event in events.iter().filter(|event| !held(event)) {
        let BulkMessage::LivePatch(patch) = next_bulk(client).await else {
            panic!("expected a replayed order");
        };
        assert_eq!(patch.sub_id, "orders");
        assert_eq!(patch.cursor, cursor_of(event));
        applier
            .apply_diffset(&patch.patchset_zstd, &mut replica)
            .expect("apply replayed order");
    }
    assert_eq!(orders(&mut replica), expected);
    expect_idle(client).await;
}

/// A replay crossing the 1,000-record page boundary keeps each member's exact ordered records, fenced or plain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_page_walk_delivers_each_member_its_exact_records() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let (manager, script, mut events, mut source) = scripted_for(
            &fixture,
            SessionConfig::default().with_initial_credits(2_000),
            &["leader", "early", "late", "plain"],
        )
        .await;
        for id in 4..=1_053 {
            events.extend(
                drive(
                    &mut source,
                    &manager,
                    &format!("INSERT INTO orders VALUES ({id}, 1.0, {id}, 'page')"),
                )
                .await,
            );
        }
        let fence = ReadFence::parse(
            &format!(
                "{}:{}:{}",
                events[0].position().xid().0,
                events[2].position().xid().0 + 1,
                events[1].position().xid().0
            ),
            PgLsn(events[2].position().commit_lsn().0 + 1),
        )
        .expect("fence");
        let late_fence = ReadFence::parse(
            &format!(
                "{}:{}:{},{}",
                events[0].position().xid().0,
                events[151].position().xid().0 + 1,
                events[1].position().xid().0,
                events[100].position().xid().0
            ),
            PgLsn(events[151].position().commit_lsn().0 + 1),
        )
        .expect("late fence");
        let early_from =
            PgCommitPosition::before_commit(PgLsn(events[1].position().commit_lsn().0 + 1));
        let late_from =
            PgCommitPosition::before_commit(PgLsn(events[150].position().commit_lsn().0 + 1));
        arm(&script, &[], true, None);
        let (arrived, release) = hold_page(&script);
        let mut leader = wave_client(&manager, &script, "leader", cursor_of(&events[1051])).await;
        leader.subscribe(QUERY).await;
        page_arrived(&arrived).await;
        let mut early = wave_client(
            &manager,
            &script,
            "early",
            fenced_cursor(early_from, Some(&fence)),
        )
        .await;
        early.subscribe(QUERY).await;
        let mut late = wave_client(
            &manager,
            &script,
            "late",
            fenced_cursor(late_from, Some(&late_fence)),
        )
        .await;
        late.subscribe(QUERY).await;
        let mut plain = wave_client(&manager, &script, "plain", cursor_of(&events[500])).await;
        plain.subscribe(QUERY).await;
        release.notify_one();
        expect_patches(&mut leader.transport, &events[1052..]).await;
        let expected: Vec<_> = (1..=1_053)
            .map(|id| order(id, 1.0, id, if id <= 3 { "row" } else { "page" }))
            .collect();
        expect_complete_replay(
            &mut early.transport,
            &events,
            |event| fence.seen(event.position()) == subql::Seen::Held,
            &expected,
        )
        .await;
        expect_complete_replay(
            &mut late.transport,
            &events,
            |event| late_fence.seen(event.position()) == subql::Seen::Held,
            &expected,
        )
        .await;
        expect_complete_replay(
            &mut plain.transport,
            &events,
            |event| event.position() <= events[500].position(),
            &expected,
        )
        .await;
        early.close().await;
        late.close().await;
        plain.close().await;
        leader.close().await;
    })
    .await
    .expect("the multi-page walk finished before the deadline");
}

/// Retention advancing between a walk's pages resyncs the member whose start fell behind it, while a later cursor in the same wave still catches up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retention_advancing_between_pages_resyncs_only_the_falling_member() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let (manager, script, mut events, mut source) = scripted_for(
            &fixture,
            SessionConfig::default().with_initial_credits(2_000),
            &["leader", "early", "late"],
        )
        .await;
        for id in 4..=1_050 {
            events.extend(
                drive(
                    &mut source,
                    &manager,
                    &format!("INSERT INTO orders VALUES ({id}, 1.0, {id}, 'page')"),
                )
                .await,
            );
        }
        // Prune past the next page's start after the first page's retention check.
        let through = events[1000].checkpoint().expect("a checkpoint");
        let (leader_arrived, leader_release) = hold_page(&script);
        let (first_arrived, first_release) = hold_page(&script);
        let (second_arrived, second_release) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        script.lock().expect("script").holds.push_back((
            Arc::clone(&second_arrived),
            Arc::clone(&second_release),
            Some(through),
        ));
        arm(&script, &[], true, None);
        let mut leader = wave_client(&manager, &script, "leader", cursor_of(&events[1048])).await;
        leader.subscribe(QUERY).await;
        page_arrived(&leader_arrived).await;
        let mut early = wave_client(&manager, &script, "early", cursor_of(&events[0])).await;
        early.subscribe(QUERY).await;
        let mut late = wave_client(&manager, &script, "late", cursor_of(&events[1039])).await;
        late.subscribe(QUERY).await;
        leader_release.notify_one();
        expect_patches(&mut leader.transport, &events[1049..]).await;
        page_arrived(&first_arrived).await;
        first_release.notify_one();
        page_arrived(&second_arrived).await;
        second_release.notify_one();
        expect_patches_before_truncate(&mut early.transport, &events[1..=1000]).await;
        let ControlMessage::FullResyncRequired(resync) = next_control(&mut early.transport).await
        else {
            panic!("expected the resync once retention passed the walked page");
        };
        assert_eq!(resync.reason, FullResyncReason::CursorOutsideRetention);
        assert_eq!(resync.sub_id, "orders");
        let ControlMessage::SnapshotBegin(begin) = next_control(&mut early.transport).await else {
            panic!("the resync re-snapshots before any rows");
        };
        assert_eq!(begin.sub_id, "orders");
        let BulkMessage::SnapshotPatch(patch) = next_bulk(&mut early.transport).await else {
            panic!("the resync snapshot carries the rows");
        };
        assert_eq!(patch.sub_id, "orders");
        let ControlMessage::SnapshotEnd(end) = next_control(&mut early.transport).await else {
            panic!("the resync snapshot ends");
        };
        assert_eq!(end.sub_id, "orders");
        expect_idle(&mut early.transport).await;
        expect_patches(&mut late.transport, &events[1040..=1049]).await;
        early.close().await;
        late.close().await;
        leader.close().await;
    })
    .await
    .expect("the mid-walk retention finished before the deadline");
}
