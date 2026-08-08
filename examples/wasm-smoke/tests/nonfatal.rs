//! Phase 4 relay parity: non-fatal error propagation through the hub.
//!
//! The direct server attaches a `NonFatalError` to one failed request and keeps
//! the session alive: a subscription it cannot serve is rejected without tearing
//! the connection down, and every sibling subscription keeps flowing. A relay
//! tab must behave the same. A bad tab subscription has to arrive as
//! `ClientEvent::NonFatal` scoped to that sub id, not as a silent tab teardown,
//! and the worker's own `NonFatal` for an aggregate or row upstream must map
//! back to the owning tab subscriptions.
//!
//! Each test drives the worker's upstream with a fake server over a loopback,
//! so no real server or Postgres is needed.
//!
//! **Needs the auth stack.** See `authenticated_boot.rs` for the auth stack
//! commands. No server or Postgres is needed for these tests.
//! Run this suite with:
//! `wasm-pack test --headless --chrome examples/wasm-smoke --test nonfatal`

#![cfg(target_arch = "wasm32")]

mod common;

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection, Grant, Replica};
use connetto_core::messages::{
    ControlMessage, HandshakeAck, NonFatalError, SUBSCRIPTION_REFUSED, SubscriptionSpec,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackError, LoopbackTransport, loopback};
use connetto_wasm_smoke::RelayHub;
use connetto_web::relay::HubReconnect;
use futures_channel::oneshot;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY NOT NULL, quantity INTEGER) STRICT;";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
const AGG_QUERY: &str = "SELECT COUNT(*) FROM orders WHERE quantity > 0";
/// A query the hub cannot parse, so it cannot serve the subscription.
const BAD_QUERY: &str = "@@@ this is not a valid query @@@";
/// The worker's row upstream subscription id, matching the hub reconnect spec.
const UPSTREAM_SUB: &str = "db-upstream";

/// Send the handshake ack the worker's `connect` waits for.
async fn ack_handshake(server: &mut LoopbackTransport, session: &str) -> bool {
    let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await else {
        return false;
    };
    server
        .send_control(ControlMessage::HandshakeAck(HandshakeAck {
            connection_id: session.to_owned(),
            session_token: "nonfatal".to_owned(),
            resume_token: String::new(),
            current_cursor: Cursor::new(Vec::new()),
            schema_version: None,
            initial_credits: 64,
            last_applied_seq: None,
        }))
        .await
        .expect("handshake ack");
    true
}

/// A fake upstream that only completes the handshake and then drains, never
/// itself producing an error. The worker replica stays empty.
async fn quiet_upstream(mut server: LoopbackTransport) {
    if !ack_handshake(&mut server, "nonfatal-quiet").await {
        return;
    }
    while let Ok(Some(_)) = server.recv().await {}
}

/// A fake upstream that answers every `Subscribe` with a `NonFatalError`
/// correlated to that sub id, modelling a rejected or unservable upstream sub.
async fn reject_every_subscribe(mut server: LoopbackTransport) {
    if !ack_handshake(&mut server, "nonfatal-reject").await {
        return;
    }
    loop {
        match server.recv().await {
            Ok(Some(IncomingFrame::Control(ControlMessage::Subscribe(sub)))) => {
                server
                    .send_control(ControlMessage::NonFatalError(NonFatalError {
                        related_to: Some(sub.sub_id),
                        detail: SUBSCRIPTION_REFUSED.to_owned(),
                    }))
                    .await
                    .expect("nonfatal reply");
            }
            Ok(Some(_)) => {}
            _ => return,
        }
    }
}

/// A fake upstream that completes the handshake and, once triggered, reports a
/// `NonFatalError` on the hub's row upstream subscription.
async fn nonfatal_row_upstream(mut server: LoopbackTransport, trigger: oneshot::Receiver<()>) {
    if !ack_handshake(&mut server, "nonfatal-row").await {
        return;
    }
    if trigger.await.is_err() {
        return;
    }
    server
        .send_control(ControlMessage::NonFatalError(NonFatalError {
            related_to: Some(UPSTREAM_SUB.to_owned()),
            detail: SUBSCRIPTION_REFUSED.to_owned(),
        }))
        .await
        .expect("nonfatal reply");
    while let Ok(Some(_)) = server.recv().await {}
}

/// Pump `conn` until an event matches `pred`, applying every frame between.
async fn pump_until<T>(conn: &mut ConnettoConnection<T>, pred: impl Fn(&ClientEvent) -> bool)
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    loop {
        let event = conn.pump_one().await.expect("pump");
        if matches!(event, ClientEvent::Closed) {
            panic!("connection closed before the expected event");
        }
        if pred(&event) {
            return;
        }
    }
}

async fn tab_config() -> ClientConfig {
    ClientConfig {
        client_id: rosetta_uuid::Uuid::new_v4().to_string(),
        login: Some(Grant::new(common::mint_token().await)),
        capabilities: Vec::new(),
        schema_version: None,
        sql_functions: connetto_wasm_smoke::uuidv4_functions(),
    }
}

#[wasm_bindgen_test]
async fn bad_tab_subscription_yields_scoped_nonfatal() {
    let (worker_up, fake_up) = loopback();
    spawn_local(quiet_upstream(fake_up));

    let worker_cfg = tab_config().await;
    let worker =
        ConnettoConnection::connect(worker_up, &Replica::in_memory(), DDL, &worker_cfg, None)
            .await
            .expect("worker connect");
    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("relay hub");
    spawn_local(async move {
        let _ = pump.await;
    });

    let (tab_end, relay_end) = loopback();
    hub.attach(relay_end);
    let tab_cfg = tab_config().await;
    let mut tab = ConnettoConnection::connect(tab_end, &Replica::in_memory(), DDL, &tab_cfg, None)
        .await
        .expect("tab connect");

    // A well-formed subscription is served from the (empty) replica.
    tab.subscribe("tab-good", QUERY)
        .await
        .expect("good subscribe");
    pump_until(&mut tab, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;

    // A subscription the hub cannot serve must come back as a scoped NonFatal,
    // never a tab teardown.
    tab.subscribe("tab-bad", BAD_QUERY)
        .await
        .expect("bad subscribe send");
    let (related, detail) = loop {
        match tab.pump_one().await.expect("tab pump") {
            ClientEvent::NonFatal { related_to, detail } => break (related_to, detail),
            ClientEvent::Closed => panic!("a bad subscription tore the whole tab down"),
            _ => {}
        }
    };
    assert_eq!(
        related.as_deref(),
        Some("tab-bad"),
        "the non-fatal error is scoped to the rejected subscription",
    );
    assert_eq!(
        detail, SUBSCRIPTION_REFUSED,
        "the hub's own refusal carries the fixed text and not the cause",
    );

    // The session and its sibling subscription are still alive: a ping
    // round-trips through the hub.
    tab.ping(99).await.expect("ping");
    pump_until(
        &mut tab,
        |event| matches!(event, ClientEvent::Pong { nonce } if *nonce == 99),
    )
    .await;
}

#[wasm_bindgen_test]
async fn aggregate_upstream_nonfatal_reaches_the_tab() {
    let (worker_up, fake_up) = loopback();
    spawn_local(reject_every_subscribe(fake_up));

    let worker_cfg = tab_config().await;
    let worker =
        ConnettoConnection::connect(worker_up, &Replica::in_memory(), DDL, &worker_cfg, None)
            .await
            .expect("worker connect");
    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("relay hub");
    spawn_local(async move {
        let _ = pump.await;
    });

    let (tab_end, relay_end) = loopback();
    hub.attach(relay_end);
    let tab_cfg = tab_config().await;
    let mut tab = ConnettoConnection::connect(tab_end, &Replica::in_memory(), DDL, &tab_cfg, None)
        .await
        .expect("tab connect");

    // The tab's aggregate registers a private upstream sub the fake server
    // rejects. The worker's NonFatal for it must map back to this tab's sub id.
    tab.subscribe("tab-agg", AGG_QUERY)
        .await
        .expect("aggregate subscribe");
    let related = loop {
        match tab.pump_one().await.expect("tab pump") {
            ClientEvent::NonFatal { related_to, .. } => break related_to,
            ClientEvent::Closed => panic!("tab closed instead of surfacing the aggregate NonFatal"),
            _ => {}
        }
    };
    assert_eq!(
        related.as_deref(),
        Some("tab-agg"),
        "the upstream aggregate NonFatal maps back to the owning tab's sub id",
    );
}

#[wasm_bindgen_test]
async fn row_upstream_nonfatal_fans_out_to_reading_tabs() {
    let (worker_up, fake_up) = loopback();
    let (trigger_tx, trigger_rx) = oneshot::channel();
    spawn_local(nonfatal_row_upstream(fake_up, trigger_rx));

    let worker_cfg = tab_config().await;
    let worker =
        ConnettoConnection::connect(worker_up, &Replica::in_memory(), DDL, &worker_cfg, None)
            .await
            .expect("worker connect");

    // The hub carries the upstream spec, so it can map an upstream NonFatal on
    // that row sub to the tab subscriptions reading its tables.
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

    let (tab_end, relay_end) = loopback();
    hub.attach(relay_end);
    let tab_cfg = tab_config().await;
    let mut tab = ConnettoConnection::connect(tab_end, &Replica::in_memory(), DDL, &tab_cfg, None)
        .await
        .expect("tab connect");
    tab.subscribe("tab-orders", QUERY)
        .await
        .expect("tab subscribe");
    pump_until(&mut tab, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;

    // The upstream reports a NonFatal on the row sub now that a tab reads it.
    trigger_tx.send(()).expect("trigger nonfatal");

    let related = loop {
        match tab.pump_one().await.expect("tab pump") {
            ClientEvent::NonFatal { related_to, .. } => break related_to,
            ClientEvent::Closed => panic!("tab closed instead of surfacing the row NonFatal"),
            _ => {}
        }
    };
    assert_eq!(
        related.as_deref(),
        Some("tab-orders"),
        "the upstream row NonFatal fans out to every tab subscription reading its tables",
    );
}
