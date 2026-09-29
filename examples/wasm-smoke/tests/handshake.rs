//! Phase 6 relay parity: handshake ack and schema-version alignment.
//!
//! The direct server sends a real `schema_version` in its `HandshakeAck`
//! (`SessionConfig`). A relay tab must receive the same version, not a "relay"
//! placeholder, so a tab cannot distinguish a relay ack from a server ack in
//! any field it reads, and so Phase 7's schema-staleness detection works
//! identically behind the relay. The worker learns the upstream version at its
//! own handshake, and the hub propagates it to every tab.
//!
//! The worker's upstream is a fake server over a loopback that answers the
//! handshake with the worker's own bundle version, so no real server, Postgres
//! or identity provider is needed. Run this suite with:
//! `wasm-pack test --headless --chrome examples/wasm-smoke --test handshake`

#![cfg(target_arch = "wasm32")]

use connetto_client::ClientBuilder;
use connetto_core::messages::{ControlMessage, Handshake, HandshakeAck};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackTransport, PROTOCOL_VERSION, SchemaVersion, loopback};
use connetto_wasm_smoke::RelayHub;
use connetto_wasm_smoke::build::{Once, raw_schema};
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY NOT NULL, quantity INTEGER) STRICT;";

/// A fake upstream that answers the worker handshake with `version`, then
/// drains.
async fn schema_upstream(mut server: LoopbackTransport, version: SchemaVersion) {
    let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await else {
        return;
    };
    server
        .send_control(ControlMessage::HandshakeAck(HandshakeAck {
            connection_id: "upstream-session".to_owned(),
            session_token: "upstream".to_owned(),
            resume_token: String::new(),
            current_cursor: Cursor::new(Vec::new()),
            schema_version: Some(version),
            initial_credits: 64,
            last_applied_seq: None,
        }))
        .await
        .expect("handshake ack");
    while let Ok(Some(_)) = server.recv().await {}
}

#[wasm_bindgen_test]
async fn tab_handshake_ack_carries_the_upstream_schema_version() {
    let upstream_version = raw_schema(DDL).version();

    let (worker_up, fake_up) = loopback();
    spawn_local(schema_upstream(fake_up, upstream_version.clone()));

    let worker = ClientBuilder::new(raw_schema(DDL), Once::new(worker_up))
        .connect_driven()
        .await
        .expect("worker connect");
    assert_eq!(
        worker.schema_version(),
        Some(&upstream_version),
        "the worker records the upstream server's schema version at handshake",
    );

    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("relay hub");
    spawn_local(async move {
        let _ = pump.await;
    });

    // A raw frame-level tab: hand-send the handshake and read the ack directly.
    let (mut tab, relay_end) = loopback();
    hub.attach(relay_end);
    tab.send_control(ControlMessage::Handshake(Handshake::new(
        PROTOCOL_VERSION,
        rosetta_uuid::Uuid::new_v4().to_string(),
    )))
    .await
    .expect("tab handshake");
    let ack = match tab.recv().await.expect("tab recv").expect("tab frame") {
        IncomingFrame::Control(ControlMessage::HandshakeAck(ack)) => ack,
        other => panic!("expected a handshake ack, got {other:?}"),
    };

    assert_eq!(
        ack.schema_version,
        Some(upstream_version),
        "the relay ack carries the upstream server's schema version, not a placeholder",
    );
    assert!(
        ack.schema_version.is_some(),
        "the relay forwards the upstream version, never an empty placeholder",
    );
}
