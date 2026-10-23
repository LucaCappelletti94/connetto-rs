//! The relay hub runs the worker's keepalive. An upstream that stops answering
//! after the handshake is dropped once the probe and answer bounds elapse, the
//! tabs are told the worker is offline, and the hub redials and tells them it
//! is connected again.
//!
//! No server, Postgres or identity provider is needed. Run this suite with:
//! `wasm-pack test --headless --chrome examples/wasm-smoke --test hub_keepalive`

#![cfg(target_arch = "wasm32")]

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientBuilder, SyncTuning};
use connetto_core::messages::{
    ControlMessage, Handshake, HandshakeAck, Pong, SyncStatus, WriterGrant,
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

const DDL: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT) STRICT;";

/// A fake upstream that acks the handshake, then answers probes only when
/// `answers` is set, counting the probes it draws.
async fn upstream(mut server: LoopbackTransport, answers: bool, pings: Rc<Cell<u32>>) {
    let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await else {
        return;
    };
    server
        .send_control(ControlMessage::HandshakeAck(HandshakeAck {
            connection_id: "keepalive-upstream".to_owned(),
            session_token: "keepalive".to_owned(),
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
    while let Ok(Some(frame)) = server.recv().await {
        if let IncomingFrame::Control(ControlMessage::Ping(ping)) = frame {
            pings.set(pings.get() + 1);
            if answers {
                server
                    .send_control(ControlMessage::Pong(Pong { nonce: ping.nonce }))
                    .await
                    .expect("pong");
            }
        }
    }
}

/// The next sync status the tab is told. A hub that never tells one hangs
/// until the runner's own deadline.
async fn next_status(tab: &mut LoopbackTransport) -> SyncStatus {
    loop {
        match tab.recv().await.expect("tab recv").expect("tab frame") {
            IncomingFrame::Control(ControlMessage::SyncStatus(status)) => return status,
            IncomingFrame::Control(ControlMessage::FatalError(fatal)) => {
                panic!("the hub closed the tab: {fatal:?}")
            }
            _ => {}
        }
    }
}

/// A silent upstream is dropped after the probe and answer bounds, the tab
/// hears offline, and the hub redials an answering upstream and the tab hears
/// connected again.
#[wasm_bindgen_test]
async fn a_silent_upstream_is_dropped_and_the_hub_redials() {
    let silent_pings = Rc::new(Cell::new(0));
    let (worker_up, fake_up) = loopback();
    spawn_local(upstream(fake_up, false, Rc::clone(&silent_pings)));

    let worker = ClientBuilder::new(raw_schema(DDL), Once::new(worker_up))
        .with_client_id("hub-keepalive-worker")
        .with_tuning(
            SyncTuning::default()
                .with_probe_after(Duration::from_millis(150))
                .with_answer_within(Duration::from_millis(200)),
        )
        .connect_driven()
        .await
        .expect("worker connect");

    let dials = Rc::new(Cell::new(0_u32));
    let reconnect = HubReconnect {
        factory: {
            let dials = Rc::clone(&dials);
            move || {
                dials.set(dials.get() + 1);
                let (server, client) = loopback();
                spawn_local(upstream(server, true, Rc::new(Cell::new(0))));
                async move { Ok::<LoopbackTransport, LoopbackError>(client) }
            }
        },
        sleeper: |_duration: Duration| async {},
        policy: ReconnectPolicy::default(),
        upstream: Vec::new(),
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
        "keepalive-tab",
    )))
    .await
    .expect("tab handshake");

    assert_eq!(next_status(&mut tab).await, SyncStatus::Connected);
    assert_eq!(
        next_status(&mut tab).await,
        SyncStatus::Offline,
        "the silent upstream is noticed"
    );
    assert!(
        silent_pings.get() >= 1,
        "the probe went out into the silence before the drop"
    );
    assert_eq!(
        next_status(&mut tab).await,
        SyncStatus::Connected,
        "the hub reconnects"
    );
    assert!(dials.get() >= 1, "the hub dialed a fresh upstream");
}
