//! A refused upstream subscription must reach the tabs that read its tables.
//! The worker's boot pump has already seen the server's refusal before the
//! hub exists, so the hub seeds it, and a tab that later subscribes to one of
//! the upstream's tables draws the one fixed phrase a direct server would
//! send, before any snapshot frame.
//!
//! No server, Postgres or identity provider is needed. Run this suite with:
//! `wasm-pack test --headless --chrome examples/wasm-smoke --test refused_upstream`

#![cfg(target_arch = "wasm32")]

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientBuilder, ClientEvent};
use connetto_core::messages::{
    ControlMessage, Handshake, HandshakeAck, NonFatalError, SUBSCRIPTION_REFUSED, Subscribe,
    SubscriptionSpec, WriterGrant,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackError, LoopbackTransport, PROTOCOL_VERSION, loopback};
use connetto_wasm_smoke::RelayHub;
use connetto_wasm_smoke::build::Once;
use connetto_wasm_smoke::build::raw_schema;
use connetto_web::relay::HubReconnect;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DDL: &str = "CREATE TABLE photos (id BLOB PRIMARY KEY DEFAULT (uuidv4()) CHECK (length(id) = 16) NOT NULL, content_state TEXT) STRICT;";
const QUERY: &str = "SELECT * FROM photos";
/// The worker's upstream subscription id: it must match the hub's reconnect
/// spec so the refusal maps to the tab subscriptions reading those tables.
const UPSTREAM_SUB: &str = "db-photos-upstream";

/// The fake upstream: it refuses the first subscription with the one fixed
/// phrase, then stays open so the hub never redials against a spent factory.
async fn refusing_upstream(mut server: LoopbackTransport) {
    let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await else {
        return;
    };
    server
        .send_control(ControlMessage::HandshakeAck(HandshakeAck {
            connection_id: "refusal-upstream".to_owned(),
            session_token: "refusal".to_owned(),
            resume_token: String::new(),
            current_cursor: Cursor::new(Vec::new()),
            schema_version: None,
            initial_credits: 64,
            writer: Some(WriterGrant {
                number: 1,
                frontier: 0,
            }),
        }))
        .await
        .expect("handshake ack");
    let sub_id = loop {
        match server.recv().await {
            Ok(Some(IncomingFrame::Control(ControlMessage::Subscribe(sub)))) => break sub.sub_id,
            Ok(Some(_)) => {}
            _ => return,
        }
    };
    server
        .send_control(ControlMessage::NonFatalError(NonFatalError {
            related_to: Some(sub_id),
            detail: SUBSCRIPTION_REFUSED.to_owned(),
        }))
        .await
        .expect("refusal");
    while let Ok(Some(_)) = server.recv().await {}
}

/// The boot-time refusal the worker's pump saw before the hub exists still
/// refuses a tab that later subscribes to the upstream's table: the tab hears
/// the one fixed phrase correlated to its own sub id, no snapshot frames.
#[wasm_bindgen_test]
async fn a_boot_time_upstream_refusal_reaches_a_later_tab() {
    let (worker_up, fake_up) = loopback();
    spawn_local(async move {
        refusing_upstream(fake_up).await;
    });

    let mut worker = ClientBuilder::new(raw_schema(DDL), Once::new(worker_up))
        .with_client_id("refused-upstream-worker")
        .connect_driven()
        .await
        .expect("worker connect");
    worker
        .subscribe(UPSTREAM_SUB, QUERY)
        .await
        .expect("worker subscribe");
    // The boot pump's end: the worker has answered the upstream, and the
    // refusal among those answers is what the hub will seed from.
    loop {
        match worker.pump_one().await.expect("worker pump") {
            ClientEvent::NonFatal {
                related_to: Some(id),
                ..
            } if id == UPSTREAM_SUB => break,
            ClientEvent::Closed => panic!("the upstream closed before the refusal"),
            _ => {}
        }
    }

    // The hub carries the upstream spec so it can map the refusal to the tab
    // subscriptions reading those tables. The factory and sleeper are never
    // invoked: the fake upstream never drops.
    let reconnect = HubReconnect {
        factory: || core::future::pending::<Result<LoopbackTransport, LoopbackError>>(),
        sleeper: |_duration: core::time::Duration| async {},
        policy: ReconnectPolicy::default(),
        upstream: vec![(UPSTREAM_SUB.to_owned(), SubscriptionSpec::new(QUERY))],
    };
    let (hub, pump, _notices) =
        RelayHub::with_reconnect(worker, ":memory:", reconnect).expect("relay hub");
    spawn_local(async move {
        let _ = pump.await;
    });

    let (mut tab, relay_end) = loopback();
    hub.attach(relay_end);
    tab.send_control(ControlMessage::Handshake(Handshake::new(
        PROTOCOL_VERSION,
        "refusal-tab",
    )))
    .await
    .expect("tab handshake");
    // The ack arrives with the state frames that follow it, and the tab then
    // sends the subscription the photos pane would.
    loop {
        match tab.recv().await.expect("tab recv").expect("tab frame") {
            IncomingFrame::Control(ControlMessage::HandshakeAck(_)) => break,
            IncomingFrame::Control(_) => {}
            other => panic!("expected a control frame, got {other:?}"),
        }
    }
    tab.send_control(ControlMessage::Subscribe(Subscribe {
        sub_id: "tab-photos".to_owned(),
        spec: SubscriptionSpec::new(QUERY),
    }))
    .await
    .expect("tab subscribe");

    // The answer to the subscribe is the refusal itself. Snapshot frames and
    // state frames that precede it are skipped, and a hub that answers
    // nothing at all hangs until the test's own deadline.
    let answer = loop {
        match tab.recv().await.expect("tab recv").expect("tab frame") {
            IncomingFrame::Control(ControlMessage::NonFatalError(err)) => break err,
            IncomingFrame::Control(ControlMessage::FatalError(fatal)) => {
                panic!("the hub closed the tab: {fatal:?}")
            }
            IncomingFrame::Control(_) => {}
            other => panic!("expected a control frame, got {other:?}"),
        }
    };
    assert_eq!(
        answer.related_to.as_deref(),
        Some("tab-photos"),
        "the refusal correlates to the tab's own subscription"
    );
    assert_eq!(
        answer.detail, SUBSCRIPTION_REFUSED,
        "the phrase is the wire's own, whatever refused"
    );
}
