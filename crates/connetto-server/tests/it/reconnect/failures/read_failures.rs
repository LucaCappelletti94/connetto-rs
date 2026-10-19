use super::*;

async fn ended_with_the_refused_read(name: &str, task: SessionTask) {
    let result = tokio::time::timeout(WAIT, task)
        .await
        .expect("the failed walk releases the session before its deadline")
        .expect("the session task did not panic");
    assert!(
        matches!(result, Err(SessionError::Oplog(_))),
        "{name} must end with an oplog error, got {result:?}"
    );
}

async fn sent_nothing_then_closed(name: &str, transport: &mut LoopbackTransport) {
    let closed = tokio::time::timeout(WAIT, transport.recv()).await;
    assert!(
        matches!(closed, Ok(Ok(None))),
        "{name} saw a frame after its session ended"
    );
}

async fn shared_read_failure(read: &'static str) {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let (manager, script, events, _source) = scripted_for(
            &fixture,
            SessionConfig::default(),
            &["leader", "member-a", "member-b", "fresh"],
        )
        .await;
        arm(&script, &[], true, None);
        let (arrived, release) = hold_page(&script);
        let mut leader = wave_client(&manager, &script, "leader", cursor_of(&events[0])).await;
        leader.subscribe(QUERY).await;
        page_arrived(&arrived).await;
        let mut member_a = wave_client(&manager, &script, "member-a", cursor_of(&events[0])).await;
        member_a.subscribe(QUERY).await;
        let mut member_b = wave_client(&manager, &script, "member-b", cursor_of(&events[0])).await;
        member_b.subscribe(QUERY).await;
        let (next_arrived, next_release) = hold_page(&script);
        release.notify_one();
        expect_patches(&mut leader.transport, &events[1..]).await;
        // The shared walk's page read is holding and every admission read is done, so only it can take the refusal.
        page_arrived(&next_arrived).await;
        arm(&script, &[read], false, None);
        next_release.notify_one();

        ended_with_the_refused_read("member-a", member_a.task).await;
        ended_with_the_refused_read("member-b", member_b.task).await;
        sent_nothing_then_closed("member-a", &mut member_a.transport).await;
        sent_nothing_then_closed("member-b", &mut member_b.transport).await;

        let mut fresh = wave_client(&manager, &script, "fresh", cursor_of(&events[0])).await;
        fresh.subscribe(QUERY).await;
        expect_patches(&mut fresh.transport, &events[1..]).await;
        leader.close().await;
        fresh.close().await;
    })
    .await
    .expect("shared read failure fanout completes before its deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_wave_page_read_failure_fans_out_then_the_next_wave_recovers() {
    shared_read_failure("entries_since").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_wave_min_position_read_failure_fans_out_then_the_next_wave_recovers() {
    shared_read_failure("min_position").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_wave_fenced_missed_read_failure_fans_out_then_the_next_wave_recovers() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let (manager, script, events, _source) = scripted_for(
            &fixture,
            SessionConfig::default(),
            &["leader", "member-a", "member-b", "fresh"],
        )
        .await;
        arm(&script, &[], true, None);
        let (arrived, release) = hold_page(&script);
        let mut leader = wave_client(&manager, &script, "leader", cursor_of(&events[0])).await;
        leader.subscribe(QUERY).await;
        page_arrived(&arrived).await;
        let fence = ReadFence::parse("11:12:", events[2].position().commit_lsn()).expect("fence");
        let resume = fenced_cursor(events[0].position(), Some(&fence));
        let mut member_a = wave_client(&manager, &script, "member-a", resume.clone()).await;
        member_a.subscribe(QUERY).await;
        let mut member_b = wave_client(&manager, &script, "member-b", resume).await;
        member_b.subscribe(QUERY).await;
        arm(&script, &["entries_of"], false, None);
        release.notify_one();
        expect_patches(&mut leader.transport, &events[1..]).await;

        ended_with_the_refused_read("member-a", member_a.task).await;
        ended_with_the_refused_read("member-b", member_b.task).await;
        sent_nothing_then_closed("member-a", &mut member_a.transport).await;
        sent_nothing_then_closed("member-b", &mut member_b.transport).await;

        let mut fresh = wave_client(&manager, &script, "fresh", cursor_of(&events[0])).await;
        fresh.subscribe(QUERY).await;
        expect_patches(&mut fresh.transport, &events[1..]).await;
        leader.close().await;
        fresh.close().await;
    })
    .await
    .expect("the fence read failure fanned out before the deadline");
}
