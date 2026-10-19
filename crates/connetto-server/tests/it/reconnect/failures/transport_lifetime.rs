//! Connection lifetime and ordered input during shared catch-up.

use connetto_core::WebSocketTransport;
use connetto_core::messages::{FatalErrorReason, Ping};

use super::*;

/// Require EOF without a trailing frame.
async fn expect_silent_close<T: Transport>(transport: &mut T) {
    let frame = tokio::time::timeout(WAIT, transport.recv())
        .await
        .expect("the session ended before the deadline")
        .expect("the transport stayed readable until the close");
    assert!(frame.is_none(), "the ending session sent a trailing frame");
}

/// Connect one native peer through an ephemeral TCP listener.
async fn native_client(
    manager: &Arc<ScriptedManager<SelectiveOutage>>,
    name: &str,
    resume: Cursor,
) -> (WebSocketTransport<tokio::net::TcpStream>, SessionTask) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind the ephemeral listener");
    let address = listener.local_addr().expect("listener address");
    let server = Arc::clone(manager);
    let task = tokio::spawn(async move {
        let (stream, _) = tokio::time::timeout(WAIT, listener.accept())
            .await
            .expect("the proof peer connected before the deadline")
            .expect("accept the stream");
        let transport = WebSocketTransport::accept(stream)
            .await
            .expect("the websocket upgrade completed");
        server.serve(transport).await
    });
    let stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect the proof peer");
    let mut client = WebSocketTransport::connect(&format!("ws://{address}/"), stream)
        .await
        .expect("the websocket handshake completed");
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, name)
                .with_grant(connetto_core::messages::Grant::new(format!("user:{name}")))
                .with_cursor(resume),
        ))
        .await
        .expect("send the native handshake");
    assert!(matches!(
        next_control(&mut client).await,
        ControlMessage::Challenge(_)
    ));
    assert!(matches!(
        next_control(&mut client).await,
        ControlMessage::HandshakeAck(_)
    ));
    (client, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_close_during_an_auth_retry_releases_the_queued_resume() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let state = Arc::new(Mutex::new(AuthState::default()));
        let auth = SelectiveOutage {
            roster: RosterAuth::granting("gone").and("healthy"),
            state: Arc::clone(&state),
        };
        let (manager, script, events, _source) =
            scripted_with_auth(&fixture, SessionConfig::default(), auth, PG_DDL).await;
        arm(&script, &[], true, None);
        state.lock().expect("auth state").down = true;
        let mut gone = wave_client(&manager, &script, "gone", cursor_of(&events[0])).await;
        gone.subscribe("SELECT * FROM orders WHERE quantity = 2")
            .await;
        assert!(matches!(
            next_control(&mut gone.transport).await,
            ControlMessage::DeliveryPaused { .. }
        ));
        let mut healthy = wave_client(&manager, &script, "healthy", cursor_of(&events[0])).await;
        healthy
            .subscribe("SELECT * FROM orders WHERE quantity = 3")
            .await;
        gone.transport
            .close()
            .await
            .expect("the peer closes cleanly");
        let ended = tokio::time::timeout(WAIT, gone.task)
            .await
            .expect("the closed session ended before the deadline")
            .expect("the session task did not panic");
        assert!(
            matches!(ended, Ok(())),
            "a peer close ends the session cleanly"
        );
        let refused_before = state.lock().expect("auth state").refused.len();
        tokio::time::timeout(WAIT, async {
            expect_patches(&mut healthy.transport, &events[2..]).await;
        })
        .await
        .expect("the queued resume is released by the peer close");
        let retried_departed = state
            .lock()
            .expect("auth state")
            .refused
            .iter()
            .skip(refused_before)
            .any(|watchers| watchers.iter().any(|user| user == "gone"));
        assert!(
            !retried_departed,
            "a visibility question still names the closed peer"
        );
        healthy.close().await;
    })
    .await
    .expect("the peer close released the queued resume before the deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_close_during_an_auth_retry_releases_the_queued_resume() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let state = Arc::new(Mutex::new(AuthState::default()));
        let auth = SelectiveOutage {
            roster: RosterAuth::granting("gone").and("healthy"),
            state: Arc::clone(&state),
        };
        let (manager, script, events, _source) =
            scripted_with_auth(&fixture, SessionConfig::default(), auth, PG_DDL).await;
        arm(&script, &[], true, None);
        state.lock().expect("auth state").down = true;
        let (mut gone, gone_task) = native_client(&manager, "gone", cursor_of(&events[0])).await;
        gone.send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "orders".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM orders WHERE quantity = 2"),
        }))
        .await
        .expect("subscribe the gone peer");
        assert!(matches!(
            next_control(&mut gone).await,
            ControlMessage::DeliveryPaused { .. }
        ));
        let (mut healthy, healthy_task) =
            native_client(&manager, "healthy", cursor_of(&events[0])).await;
        healthy
            .send_control(ControlMessage::Subscribe(Subscribe {
                sub_id: "orders".to_owned(),
                spec: SubscriptionSpec::new("SELECT * FROM orders WHERE quantity = 3"),
            }))
            .await
            .expect("subscribe the healthy peer");
        gone.close()
            .await
            .expect("the peer sends a websocket close");
        drop(gone);
        let ended = tokio::time::timeout(WAIT, gone_task)
            .await
            .expect("the closed session ended before the deadline")
            .expect("the session task did not panic");
        assert!(
            matches!(ended, Ok(())),
            "a websocket close ends the session cleanly"
        );
        let refused_before = state.lock().expect("auth state").refused.len();
        let replayed = tokio::time::timeout(WAIT, next_bulk(&mut healthy)).await;
        let BulkMessage::LivePatch(patch) = replayed.expect("the queued resume is released") else {
            panic!("the healthy peer receives its catch-up patch");
        };
        assert_eq!(patch.sub_id, "orders");
        assert_eq!(patch.cursor, cursor_of(&events[2]));
        let retried_departed = state
            .lock()
            .expect("auth state")
            .refused
            .iter()
            .skip(refused_before)
            .any(|watchers| watchers.iter().any(|user| user == "gone"));
        assert!(
            !retried_departed,
            "a visibility question still names the closed peer"
        );
        healthy
            .close()
            .await
            .expect("the healthy peer closes cleanly");
        let ended = tokio::time::timeout(WAIT, healthy_task)
            .await
            .expect("the healthy session ended before the deadline")
            .expect("the healthy task did not panic");
        assert!(
            matches!(ended, Ok(())),
            "the healthy session closed cleanly"
        );
    })
    .await
    .expect("the websocket close released the queued resume before the deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_server_close_during_a_paused_catchup_releases_the_worker() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let state = Arc::new(Mutex::new(AuthState::default()));
        let auth = SelectiveOutage {
            roster: RosterAuth::granting("gone").and("healthy").and("fresh"),
            state: Arc::clone(&state),
        };
        let (manager, script, events, _source) =
            scripted_with_auth(&fixture, SessionConfig::default(), auth, PG_DDL).await;
        arm(&script, &[], true, None);
        state.lock().expect("auth state").down = true;
        let mut gone = wave_client(&manager, &script, "gone", cursor_of(&events[0])).await;
        gone.subscribe("SELECT * FROM orders WHERE quantity = 2")
            .await;
        assert!(matches!(
            next_control(&mut gone.transport).await,
            ControlMessage::DeliveryPaused { .. }
        ));
        let mut healthy = wave_client(&manager, &script, "healthy", cursor_of(&events[0])).await;
        healthy
            .subscribe("SELECT * FROM orders WHERE quantity = 3")
            .await;
        assert_eq!(
            manager.close_person("gone").await,
            1,
            "the close names the paused session"
        );
        let ended = tokio::time::timeout(WAIT, gone.task)
            .await
            .expect("the closed session ended before the deadline")
            .expect("the session task did not panic");
        assert!(
            matches!(ended, Ok(())),
            "a silent close ends the session cleanly"
        );
        expect_silent_close(&mut gone.transport).await;
        tokio::time::timeout(WAIT, async {
            expect_patches(&mut healthy.transport, &events[2..]).await;
        })
        .await
        .expect("the unrelated resume is released by the silent close");
        let mut fresh = wave_client(&manager, &script, "fresh", cursor_of(&events[0])).await;
        fresh.subscribe(QUERY).await;
        tokio::time::timeout(WAIT, async {
            expect_patches(&mut fresh.transport, &events[1..]).await;
        })
        .await
        .expect("a fresh resume walks the log after the silent close");
        healthy.close().await;
        fresh.close().await;
    })
    .await
    .expect("the silent close released the worker before the deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fatal_server_close_during_a_paused_catchup_delivers_its_fatal() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let state = Arc::new(Mutex::new(AuthState::default()));
        let auth = SelectiveOutage {
            roster: RosterAuth::granting("gone").and("healthy"),
            state: Arc::clone(&state),
        };
        let (manager, script, events, _source) =
            scripted_with_auth(&fixture, SessionConfig::default(), auth, PG_DDL).await;
        arm(&script, &[], true, None);
        state.lock().expect("auth state").down = true;
        let mut gone = wave_client(&manager, &script, "gone", cursor_of(&events[0])).await;
        gone.subscribe("SELECT * FROM orders WHERE quantity = 2")
            .await;
        assert!(matches!(
            next_control(&mut gone.transport).await,
            ControlMessage::DeliveryPaused { .. }
        ));
        assert!(
            manager
                .close_session(
                    connetto_core::SessionId::from_token_hash("user:gone"),
                    FatalErrorReason::SessionRevoked,
                )
                .await,
            "the revocation finds the paused session"
        );
        let ControlMessage::FatalError(fatal) = next_control(&mut gone.transport).await else {
            panic!("the revocation delivers its fatal frame");
        };
        assert_eq!(fatal.reason, FatalErrorReason::SessionRevoked);
        expect_silent_close(&mut gone.transport).await;
        let ended = tokio::time::timeout(WAIT, gone.task)
            .await
            .expect("the closed session ended before the deadline")
            .expect("the session task did not panic");
        assert!(
            matches!(ended, Ok(())),
            "the fatal ends the session cleanly"
        );
        let mut healthy = wave_client(&manager, &script, "healthy", cursor_of(&events[0])).await;
        healthy
            .subscribe("SELECT * FROM orders WHERE quantity = 3")
            .await;
        tokio::time::timeout(WAIT, async {
            expect_patches(&mut healthy.transport, &events[2..]).await;
        })
        .await
        .expect("a fresh resume walks the log after the fatal close");
        healthy.close().await;
    })
    .await
    .expect("the fatal close delivered its frame before the deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frames_arriving_during_catchup_are_served_in_order_behind_the_replay() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let (manager, script, events, mut source) =
            scripted_for(&fixture, SessionConfig::default(), &["held"]).await;
        arm(&script, &[], true, None);
        let (arrived, release) = hold_page(&script);
        let mut held = wave_client(&manager, &script, "held", cursor_of(&events[0])).await;
        held.subscribe(QUERY).await;
        page_arrived(&arrived).await;
        held.transport
            .send_control(ControlMessage::Ping(Ping { nonce: 11 }))
            .await
            .expect("send the first ping");
        held.transport
            .send_control(ControlMessage::Subscribe(Subscribe {
                sub_id: "solo".to_owned(),
                spec: SubscriptionSpec::new("SELECT * FROM orders WHERE status = 'late'"),
            }))
            .await
            .expect("send the second subscription");
        held.transport
            .send_control(ControlMessage::Ping(Ping { nonce: 12 }))
            .await
            .expect("send the second ping");
        expect_idle(&mut held.transport).await;
        release.notify_one();
        for event in &events[1..] {
            let BulkMessage::LivePatch(patch) = next_bulk(&mut held.transport).await else {
                panic!("the catch-up precedes held requests");
            };
            assert_eq!(patch.sub_id, "orders");
            assert_eq!(patch.cursor, cursor_of(event));
        }
        let ControlMessage::Pong(pong) = next_control(&mut held.transport).await else {
            panic!("the first ping is answered after the replay");
        };
        assert_eq!(pong.nonce, 11);
        let ControlMessage::Pong(pong) = next_control(&mut held.transport).await else {
            panic!("the second ping is answered after the first");
        };
        assert_eq!(pong.nonce, 12);
        let late = drive(
            &mut source,
            &manager,
            "INSERT INTO orders VALUES (5, 5.0, -1, 'late')",
        )
        .await;
        let BulkMessage::LivePatch(patch) = next_bulk(&mut held.transport).await else {
            panic!("the second subscription received its first row");
        };
        assert_eq!(patch.sub_id, "solo");
        assert_eq!(patch.cursor, cursor_of(&late[0]));
        expect_idle(&mut held.transport).await;
        held.close().await;
    })
    .await
    .expect("the held frames were served in order before the deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn held_input_overflow_closes_only_the_offending_session() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let budget = 256;
        let (manager, script, events, _source) = scripted_for(
            &fixture,
            SessionConfig::default().with_catchup_input_budget(budget),
            &["overflow", "healthy"],
        )
        .await;
        arm(&script, &[], true, None);
        let (arrived, release) = hold_page(&script);
        let mut overflow = wave_client(&manager, &script, "overflow", cursor_of(&events[0])).await;
        overflow.subscribe(QUERY).await;
        page_arrived(&arrived).await;
        let mut healthy = wave_client(&manager, &script, "healthy", cursor_of(&events[0])).await;
        healthy
            .subscribe("SELECT * FROM orders WHERE quantity = 3")
            .await;
        let oversized = format!(
            "SELECT * FROM orders WHERE quantity > {}",
            "x".repeat(budget * 8)
        );
        overflow
            .transport
            .send_control(ControlMessage::Subscribe(Subscribe {
                sub_id: "junk".to_owned(),
                spec: SubscriptionSpec::new(oversized),
            }))
            .await
            .expect("send the oversized frame");
        let ended = tokio::time::timeout(WAIT, overflow.task)
            .await
            .expect("the offending session ended before the deadline")
            .expect("the session task did not panic");
        assert!(
            matches!(ended, Err(SessionError::Protocol(_))),
            "the overflow ends the offending session with a protocol error"
        );
        expect_silent_close(&mut overflow.transport).await;
        release.notify_one();
        tokio::time::timeout(WAIT, async {
            expect_patches(&mut healthy.transport, &events[2..]).await;
        })
        .await
        .expect("the healthy queued resume continues past the overflow");
        healthy.close().await;
    })
    .await
    .expect("the overflow closed the offending session before the deadline");
}
