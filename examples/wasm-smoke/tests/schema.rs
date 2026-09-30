//! Phase 7 relay parity: schema-version staleness detection through the hub.
//!
//! Phase 6 makes the relay forward the upstream server's real `schema_version`
//! to every tab. Phase 7 makes a client with a stale baked schema fail at the
//! handshake instead of subscribing. Together they mean a tab behind the relay
//! detects staleness exactly as a direct client would: the hub carries the real
//! version, and the tab's own `connect` compares it against its baked version.
//!
//! The worker's upstream is a fake server over a loopback that advertises the
//! current bundle's version, so no real server, Postgres or identity provider
//! is needed. Run this suite with:
//! `wasm-pack test --headless --chrome examples/wasm-smoke --test schema`

#![cfg(target_arch = "wasm32")]

use connetto_client::{ClientBuilder, ClientError};
use connetto_core::messages::{ControlMessage, HandshakeAck};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackTransport, SchemaVersion, loopback};
use connetto_wasm_smoke::RelayHub;
use connetto_wasm_smoke::build::{Once, raw_schema};
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The schema the server and the worker run now.
const DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY NOT NULL, quantity INTEGER, extra TEXT) STRICT;";
/// The schema an older build of the tab was compiled against.
const OLD_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY NOT NULL, quantity INTEGER) STRICT;";

/// A fake upstream that completes the worker handshake advertising
/// `server_version`, then drains.
async fn schema_upstream(mut server: LoopbackTransport, server_version: SchemaVersion) {
    let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await else {
        return;
    };
    server
        .send_control(ControlMessage::HandshakeAck(HandshakeAck {
            connection_id: "upstream-session".to_owned(),
            session_token: "upstream".to_owned(),
            resume_token: String::new(),
            current_cursor: Cursor::new(Vec::new()),
            schema_version: Some(server_version),
            initial_credits: 64,
            last_applied_seq: None,
        }))
        .await
        .expect("handshake ack");
    while let Ok(Some(_)) = server.recv().await {}
}

/// Stand up a hub whose worker learned the current bundle's version from its
/// upstream.
async fn hub_on_current_schema() -> RelayHub {
    let (worker_up, fake_up) = loopback();
    spawn_local(schema_upstream(fake_up, raw_schema(DDL).version()));
    let worker = ClientBuilder::new(raw_schema(DDL), Once::new(worker_up))
        .connect_driven()
        .await
        .expect("worker connect");
    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("relay hub");
    spawn_local(async move {
        let _ = pump.await;
    });
    hub
}

#[wasm_bindgen_test]
async fn stale_tab_is_rejected_through_the_relay() {
    let hub = hub_on_current_schema().await;

    // A tab built for an older schema must be told to reload, not subscribe.
    let (tab_end, relay_end) = loopback();
    hub.attach(relay_end);
    let result = ClientBuilder::new(raw_schema(OLD_DDL), Once::new(tab_end))
        .connect_driven()
        .await;
    match result {
        Err(ClientError::SchemaOutdated { server, .. }) => {
            assert_eq!(
                server,
                raw_schema(DDL).version(),
                "the tab sees the upstream server's version through the relay",
            );
        }
        Err(other) => panic!("expected SchemaOutdated, got {other:?}"),
        Ok(_) => panic!("a stale tab connected through the relay instead of being told to reload"),
    }
}

#[wasm_bindgen_test]
async fn matching_tab_connects_through_the_relay() {
    let hub = hub_on_current_schema().await;

    let (tab_end, relay_end) = loopback();
    hub.attach(relay_end);
    let conn = ClientBuilder::new(raw_schema(DDL), Once::new(tab_end))
        .connect_driven()
        .await;
    assert!(
        conn.is_ok(),
        "a tab whose baked version matches the server connects normally: {:?}",
        conn.err()
    );
}
