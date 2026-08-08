//! Phase 7 relay parity: schema-version staleness detection through the hub.
//!
//! Phase 6 makes the relay forward the upstream server's real `schema_version`
//! to every tab. Phase 7 makes a client with a stale baked schema fail at the
//! handshake instead of subscribing. Together they mean a tab behind the relay
//! detects staleness exactly as a direct client would: the hub carries the real
//! version, and the tab's own `connect` compares it against its baked version.
//!
//! The worker's upstream is a fake server over a loopback that advertises a
//! distinctive schema version, so no real server or Postgres is needed.
//!
//! **Needs the auth stack.** See `authenticated_boot.rs` for the auth stack
//! commands. No server or Postgres is needed for this test.
//! Run this suite with:
//! `wasm-pack test --headless --chrome examples/wasm-smoke --test schema`

#![cfg(target_arch = "wasm32")]

mod common;

use connetto_client::{ClientConfig, ClientError, ConnettoConnection, Grant, Replica};
use connetto_core::messages::{ControlMessage, HandshakeAck};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackTransport, SchemaVersion, loopback};
use connetto_wasm_smoke::RelayHub;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY NOT NULL, quantity INTEGER) STRICT;";

fn unique_base() -> i64 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let millis = js_sys::Date::now() as i64;
    95_000_000_000 + millis
}

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

/// Stand up a hub whose worker learned `server_version` from its upstream, and
/// return a handle plus the tab attach closure.
async fn hub_with_server_version(base: i64, server_version: SchemaVersion) -> RelayHub {
    let (worker_up, fake_up) = loopback();
    spawn_local(schema_upstream(fake_up, server_version.clone()));
    let worker_config = ClientConfig {
        client_id: format!("schema-worker-{base}"),
        login: Some(Grant::new(common::mint_token().await)),
        capabilities: Vec::new(),
        // The worker presents the same version the upstream advertises, so it
        // connects and then forwards that version to tabs.
        schema_version: Some(server_version),
        sql_functions: connetto_wasm_smoke::uuidv4_functions(),
    };
    let worker =
        ConnettoConnection::connect(worker_up, &Replica::in_memory(), DDL, &worker_config, None)
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
    let base = unique_base();
    let server_version = SchemaVersion::from_source("CREATE TABLE orders (id INT, extra INT);");
    let hub = hub_with_server_version(base, server_version).await;

    // A tab built for an older schema must be told to reload, not subscribe.
    let (tab_end, relay_end) = loopback();
    hub.attach(relay_end);
    let stale = ClientConfig {
        client_id: rosetta_uuid::Uuid::new_v4().to_string(),
        login: Some(Grant::new(common::mint_token().await)),
        capabilities: Vec::new(),
        schema_version: Some(SchemaVersion::from_source("CREATE TABLE orders (id INT);")),
        sql_functions: connetto_wasm_smoke::uuidv4_functions(),
    };
    let result =
        ConnettoConnection::connect(tab_end, &Replica::in_memory(), DDL, &stale, None).await;
    match result {
        Err(ClientError::SchemaOutdated { server, .. }) => {
            assert_eq!(
                server,
                SchemaVersion::from_source("CREATE TABLE orders (id INT, extra INT);"),
                "the tab sees the upstream server's version through the relay",
            );
        }
        Err(other) => panic!("expected SchemaOutdated, got {other:?}"),
        Ok(_) => panic!("a stale tab connected through the relay instead of being told to reload"),
    }
}

#[wasm_bindgen_test]
async fn matching_tab_connects_through_the_relay() {
    let base = unique_base();
    let version = SchemaVersion::from_source("CREATE TABLE orders (id INT, quantity INT);");
    let hub = hub_with_server_version(base, version.clone()).await;

    let (tab_end, relay_end) = loopback();
    hub.attach(relay_end);
    let fresh = ClientConfig {
        client_id: rosetta_uuid::Uuid::new_v4().to_string(),
        login: Some(Grant::new(common::mint_token().await)),
        capabilities: Vec::new(),
        schema_version: Some(version),
        sql_functions: connetto_wasm_smoke::uuidv4_functions(),
    };
    let conn = ConnettoConnection::connect(tab_end, &Replica::in_memory(), DDL, &fresh, None).await;
    assert!(
        conn.is_ok(),
        "a tab whose baked version matches the server connects normally: {:?}",
        conn.err()
    );
}
