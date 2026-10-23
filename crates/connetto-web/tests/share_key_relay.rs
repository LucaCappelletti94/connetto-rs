//! A tab's share-key change goes through the hub to the worker that holds the
//! keys, and every tab of the relay answers its views with the result (R95
//! decision 17). Runs in a dedicated worker for the wasm SQLite build.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use core::time::Duration;

use base64::Engine as _;
use connetto_client::{
    ClientBuilder, ConnettoClient, FirstThen, Grant, HeldCredential, SyncSchema,
};
use connetto_core::auth::CapabilitySubject;
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use connetto_core::traits::Transport;
use connetto_web::{MessageTransport, RelayHub};
use diesel::prelude::*;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::MessagePort;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

fn schema() -> SyncSchema {
    SyncSchema::new(SchemaBundle::new(
        "",
        "",
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT NOT NULL); \
         CREATE VIEW visible AS SELECT * FROM notes \
         WHERE owner = current_app_user() \
            OR instr(',' || current_app_subjects() || ',', ',' || owner || ',') > 0;",
        Vec::<(String, String)>::new(),
        vec!["visible".to_owned()],
        None::<&str>,
    ))
}

/// A dialer handing out `transport` once and nothing after.
fn once<T: Transport + 'static>(
    transport: T,
) -> FirstThen<impl FnMut() -> core::future::Ready<Result<T, &'static str>>> {
    FirstThen::new(transport, || core::future::ready(Err("spent")))
}

/// A grant whose `exp` claim is `exp` seconds, the shape the client reads.
fn grant(exp: Option<f64>) -> Grant {
    let payload = match exp {
        Some(exp) => format!("{{\"exp\":{exp:.0}}}"),
        None => "{}".to_owned(),
    };
    Grant::new(format!(
        "h.{}.s",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
    ))
}

#[derive(QueryableByName)]
struct Subjects {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    subjects: Option<String>,
}

/// A hub over a silent upstream, its worker signed in and holding no key.
async fn hub() -> RelayHub {
    let credential = HeldCredential::new(Grant::new("user:token"), "token")
        .expect("a string identity serializes");
    let worker = ClientBuilder::new(schema(), once(FakeTransport::accepting_but_silent()))
        .signed_in(credential)
        .connect_driven()
        .await
        .expect("the worker connects");
    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("hub meta");
    spawn_local(async move {
        let _ = pump.await;
    });
    hub
}

/// A tab attached to `hub` through a real message channel, its pump running.
async fn tab(hub: &RelayHub, client_id: &str) -> ConnettoClient<MessageTransport<MessagePort>> {
    let channel = web_sys::MessageChannel::new().expect("message channel");
    hub.attach(MessageTransport::<MessagePort>::new(channel.port1()));
    let conn = ClientBuilder::new(
        schema().relay_mirror(),
        once(MessageTransport::<MessagePort>::new(channel.port2())),
    )
    .with_client_id(client_id)
    .connect_driven()
    .await
    .expect("the hub acknowledges the tab");
    let (client, pump) = ConnettoClient::with_pump(conn);
    spawn_local(pump);
    client
}

async fn subjects(tab: &ConnettoClient<MessageTransport<MessagePort>>) -> Option<String> {
    tab.with_conn(|conn| {
        diesel::sql_query("SELECT current_app_subjects() AS subjects")
            .get_result::<Subjects>(conn.conn())
            .expect("the mirror answers its subjects function")
            .subjects
    })
    .await
    .expect("the tab is open")
}

/// Wait until `tab` answers `expected`, failing after `bound`.
async fn await_subjects(
    tab: &ConnettoClient<MessageTransport<MessagePort>>,
    expected: Option<&str>,
    bound: Duration,
) {
    let deadline = js_sys::Date::now() + bound.as_secs_f64() * 1000.0;
    loop {
        let held = subjects(tab).await;
        if held.as_deref() == expected {
            return;
        }
        assert!(
            js_sys::Date::now() < deadline,
            "the tab answers {held:?}, expected {expected:?}"
        );
        connetto_web::workers::sleep(Duration::from_millis(20)).await;
    }
}

/// A key one tab adds or removes is answered by every tab of the relay, and the
/// tab that asked already answers it when its call returns.
#[wasm_bindgen_test]
async fn a_tab_change_reaches_every_tab_of_the_relay() {
    let hub = hub().await;
    let first = tab(&hub, "tab-first").await;
    let second = tab(&hub, "tab-second").await;
    assert_eq!(subjects(&first).await, None);

    first
        .add_share_key(
            &grant(None),
            &CapabilitySubject::<String>::new("shared".to_owned()),
        )
        .await
        .expect("the worker holds the key");
    assert_eq!(subjects(&first).await.as_deref(), Some("shared"));
    await_subjects(&second, Some("shared"), Duration::from_secs(5)).await;

    second
        .remove_share_key(&CapabilitySubject::<String>::new("shared".to_owned()))
        .await
        .expect("the worker drops the key");
    assert_eq!(subjects(&second).await, None);
    await_subjects(&first, None, Duration::from_secs(5)).await;
}

/// A key reaching its expiry leaves every tab of the relay without any call.
#[wasm_bindgen_test]
async fn an_expired_key_leaves_every_tab_of_the_relay() {
    let hub = hub().await;
    let first = tab(&hub, "tab-expiring-first").await;
    let second = tab(&hub, "tab-expiring-second").await;
    let expires = js_sys::Date::now() / 1000.0 + 3.0;

    first
        .add_share_key(
            &grant(Some(expires)),
            &CapabilitySubject::<String>::new("brief".to_owned()),
        )
        .await
        .expect("the worker holds the key");
    await_subjects(&second, Some("brief"), Duration::from_secs(2)).await;

    await_subjects(&first, None, Duration::from_secs(10)).await;
    await_subjects(&second, None, Duration::from_secs(5)).await;
}
