//! What a tab learns when the relay hub refuses it, and which client ids the
//! hub takes. Runs in a dedicated worker for the wasm SQLite build.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use core::time::Duration;

use connetto_client::{ClientConfig, ConnettoConnection, Replica};
use connetto_core::PROTOCOL_VERSION;
use connetto_core::messages::{ControlMessage, FatalErrorReason, Handshake};
use connetto_core::test_support::FakeTransport;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_web::{MessageTransport, RelayHub};
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::MessagePort;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

/// A hub over a silent upstream, and the tab end of a real message channel
/// attached to it.
async fn hub_with_tab() -> (RelayHub, MessageTransport<MessagePort>) {
    let worker = ConnettoConnection::connect(
        FakeTransport::accepting_but_silent(),
        &Replica::in_memory(),
        DDL,
        &ClientConfig::new("tab-refusal-worker"),
        None,
    )
    .await
    .expect("worker connect");
    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("hub meta");
    spawn_local(async move {
        pump.await.expect("hub pump");
    });
    let channel = web_sys::MessageChannel::new().expect("message channel");
    hub.attach(MessageTransport::<MessagePort>::new(channel.port1()));
    (hub, MessageTransport::<MessagePort>::new(channel.port2()))
}

/// A refused tab hears why before its channel closes, so the page can say what
/// went wrong instead of reporting a connection that merely vanished.
#[wasm_bindgen_test]
async fn a_refused_tab_is_told_why() {
    let (_hub, mut tab) = hub_with_tab().await;
    for _ in 0..2 {
        tab.send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "a-tab",
        )))
        .await
        .expect("post handshake");
    }
    let refusal = loop {
        let frame = tokio::select! {
            frame = tab.recv() => frame.expect("transport"),
            () = connetto_web::workers::sleep(Duration::from_secs(5)) => {
                panic!("the hub neither refused the tab nor closed it")
            }
        };
        match frame {
            Some(IncomingFrame::Control(ControlMessage::FatalError(fatal))) => break fatal.reason,
            Some(_) => {}
            None => panic!("the hub closed the tab without saying why"),
        }
    };
    assert_eq!(
        refusal,
        FatalErrorReason::ProtocolViolation {
            detail: "second handshake".to_owned(),
        }
    );
}

/// The server treats a client id as a label, so the hub does too: a tab that
/// names itself with a timestamp connects like one that names itself with a
/// UUID.
#[wasm_bindgen_test]
async fn a_tab_with_any_client_id_connects() {
    for client_id in ["tab-1790236972826", "6f1c9d2e-8a4b-4c5d-9e6f-0a1b2c3d4e5f"] {
        let (_hub, tab) = hub_with_tab().await;
        let connected = ConnettoConnection::connect(
            tab,
            &Replica::in_memory(),
            DDL,
            &ClientConfig::new(client_id),
            None,
        )
        .await;
        assert!(
            connected.is_ok(),
            "{client_id} was refused: {:?}",
            connected.err()
        );
    }
}
