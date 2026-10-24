//! What a tab learns when the relay hub refuses it, and which client ids the
//! hub takes. Runs in a dedicated worker for the wasm SQLite build.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use core::time::Duration;

use connetto_client::{ClientBuilder, FirstThen, SyncSchema};
use connetto_core::messages::{ControlMessage, FatalErrorReason, Handshake};
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Major, PROTOCOL_VERSION};
use connetto_web::{MessageTransport, RelayHub};
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::MessagePort;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The major line the test schema source declares.
const SOURCE: &str = "-- connetto:major 1";

/// The major [`SOURCE`] declares, which a tab built from it presents.
fn major() -> Major {
    Major::declared_in(SOURCE).expect("the source declares major 1")
}

const DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

/// The client schema over [`DDL`].
fn schema() -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            SOURCE,
            "",
            DDL,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            None::<&str>,
        )
        .expect("the source declares major 1"),
    )
}

/// A dialer handing out `transport` once and nothing after.
fn once<T: Transport + 'static>(
    transport: T,
) -> FirstThen<impl FnMut() -> core::future::Ready<Result<T, &'static str>>> {
    FirstThen::new(transport, || core::future::ready(Err("spent")))
}

/// A hub over a silent upstream, and the tab end of a real message channel
/// attached to it.
async fn hub_with_tab() -> (RelayHub, MessageTransport<MessagePort>) {
    let worker = ClientBuilder::new(schema(), once(FakeTransport::accepting_but_silent()))
        .with_client_id("tab-refusal-worker")
        .connect_driven()
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
        tab.send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "a-tab").with_major(major()),
        ))
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

/// A tab built at another major than its worker is refused naming both, since
/// it would read and write a schema the replica does not hold (R31).
#[wasm_bindgen_test]
async fn a_tab_at_another_major_is_refused_naming_both() {
    let (_hub, mut tab) = hub_with_tab().await;
    let other = Major::new(2).expect("two is a major");
    tab.send_control(ControlMessage::Handshake(
        Handshake::new(PROTOCOL_VERSION, "a-tab").with_major(other),
    ))
    .await
    .expect("post handshake");
    let frame = tokio::select! {
        frame = tab.recv() => frame.expect("transport"),
        () = connetto_web::workers::sleep(Duration::from_secs(5)) => {
            panic!("the hub neither refused the tab nor closed it")
        }
    };
    let Some(IncomingFrame::Control(ControlMessage::FatalError(fatal))) = frame else {
        panic!("the hub's first answer is the refusal, got {frame:?}");
    };
    assert_eq!(
        fatal.reason,
        FatalErrorReason::MajorMismatch {
            server: major(),
            client: Some(other),
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
        let connected = ClientBuilder::new(schema(), once(tab))
            .with_client_id(client_id)
            .connect_driven()
            .await;
        assert!(
            connected.is_ok(),
            "{client_id} was refused: {:?}",
            connected.err()
        );
    }
}
