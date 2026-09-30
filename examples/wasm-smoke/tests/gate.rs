//! The away-and-return gate in the browser, without a WebAuthn authenticator.
//!
//! Each test spawns the production DB worker with the gate installed on a
//! gate client, and plays the spawning tab that answers the worker's unlock
//! requests over the worker's private port with the protocol's shaped key
//! message, which re-derives the key-encryption key enrolment derived. The
//! tabs connect to the worker's relay hub the way real tabs do, and the
//! visibility protocol is driven directly on the visibility channel, because
//! the test context is a worker with no page events to observe.

#![cfg(target_arch = "wasm32")]

mod common;

use connetto_wasm_smoke::build::Once;
use connetto_wasm_smoke::workers::demo_schema;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use connetto_client::{ClientBuilder, ClientError, ConnettoClient};
use connetto_wasm_smoke::workers::{announce_tab, await_db_worker_ready, sleep};
use connetto_wasm_smoke::{MessageTransport, locks};
use connetto_web::auth::IdbKeyStore;
use connetto_web::visibility::VISIBILITY_CHANNEL;
use indexed_db_futures::database::Database as IdbDatabase;
use indexed_db_futures::prelude::*;
use wasm_bindgen::JsCast as _;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{BroadcastChannel, MessageEvent, Worker};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const KEY_STORE_DB: &str = "connetto-key-store";
const STORE_KEK: &str = "kek";
const STORE_WRAPPED: &str = "wrapped";
const STORE_CREDENTIALS: &str = "credentials";
const DEFAULT_AUTH_DB: &str = "connetto-auth.sqlite";
const GATE_AUTH_DB: &str = "connetto-gate-auth.sqlite";

/// The seed the enrolled credential derives from, so the test can re-import
/// the same HKDF key the ceremony asks for.
const SEED: u8 = 0xd1;

/// Progress marker so a harness timeout shows how far each test reached.
fn stage(message: &str) {
    web_sys::console::log_1(&message.into());
}

/// Set `key` to the string `val` on a plain JS object, silently discarding
/// any error from `Reflect::set` (the set cannot fail on a plain object).
fn set_str(obj: &js_sys::Object, key: &str, val: &str) {
    let _ = js_sys::Reflect::set(
        obj,
        &wasm_bindgen::JsValue::from_str(key),
        &wasm_bindgen::JsValue::from_str(val),
    );
}

/// Build `{kind: "key", credentialId, key}` echoing the requested credential.
fn key_msg(credential_id: &str, key: web_sys::CryptoKey) -> wasm_bindgen::JsValue {
    let obj = js_sys::Object::new();
    set_str(&obj, "kind", "key");
    set_str(&obj, "credentialId", credential_id);
    let _ = js_sys::Reflect::set(
        &obj,
        &wasm_bindgen::JsValue::from_str("key"),
        &wasm_bindgen::JsValue::from(key),
    );
    obj.into()
}

/// The first credential id an unlock request asks for, base64url-encoded.
fn first_credential(data: &wasm_bindgen::JsValue) -> String {
    js_sys::Reflect::get(data, &wasm_bindgen::JsValue::from_str("credentials"))
        .ok()
        .and_then(|v| v.dyn_into::<js_sys::Array>().ok())
        .and_then(|a| a.get(0).as_string())
        .unwrap_or_default()
}

/// Spawn a dedicated worker that boots with the unlock protocol and installs
/// the gate on a gate client after boot, with `grace_ms` as the away grace
/// (`0` re-checks on every return).
///
/// The worker calls `db_worker_gate_boot()` instead of the stock
/// `db_worker_boot()`. The bootstrap is a blob module so no extra script file
/// is needed, mirroring the `WorkerBootstrap::Generated` pattern.
fn spawn_gate_worker(glue_url: &str, grace_ms: u32) -> Worker {
    spawn_gate_worker_calling(glue_url, &format!("db_worker_gate_boot({grace_ms})"))
}

/// Spawn a gate worker whose bootstrap awaits `call` on the glue module.
fn spawn_gate_worker_calling(glue_url: &str, call: &str) -> Worker {
    let wasm_url = glue_url
        .strip_suffix(".js")
        .map_or_else(|| format!("{glue_url}_bg.wasm"), |b| format!("{b}_bg.wasm"));
    // This blob carries no boot identity, so its failures reach the debug channel only.
    let source = format!(
        "try {{\
         \n  const mod = await import(\"{g}\");\
         \n  await mod.default({{ module_or_path: \"{w}\" }});\
         \n  await mod.{call};\
         \n}} catch (err) {{\
         \n  new BroadcastChannel(\"connetto-debug\").postMessage(\"db worker FAILED: \" + err);\
         \n  throw err;\
         \n}}\n",
        g = glue_url,
        w = wasm_url,
    );
    let parts = js_sys::Array::of1(&wasm_bindgen::JsValue::from_str(&source));
    let blob_opts = web_sys::BlobPropertyBag::new();
    blob_opts.set_type("text/javascript");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&parts, &blob_opts)
        .expect("bootstrap blob");
    let url = web_sys::Url::create_object_url_with_blob(&blob).expect("bootstrap url");
    let worker_opts = web_sys::WorkerOptions::new();
    worker_opts.set_type(web_sys::WorkerType::Module);
    worker_opts.set_name("connetto-db-gate");
    let worker = web_sys::Worker::new_with_options(&url, &worker_opts).expect("spawn gate worker");
    let _ = web_sys::Url::revoke_object_url(&url);
    worker
}

/// Install the one-time `onmessage` handler on `worker` that answers its
/// unlock requests.
///
/// The first unlock is the boot ceremony and is answered at once with the
/// enrolled key. Every later unlock is a gate prompt, which is stored in
/// `prompts` for the test to hold or answer.
fn install_prompt_handler(worker: &Worker, prompts: Rc<RefCell<Option<wasm_bindgen::JsValue>>>) {
    let w = worker.clone();
    let prompts = Rc::clone(&prompts);
    let seen = Rc::new(RefCell::new(0u32));
    let on_message = wasm_bindgen::closure::Closure::<dyn FnMut(MessageEvent)>::new(
        move |event: MessageEvent| {
            let data = event.data();
            if data.is_undefined() || data.is_null() {
                return;
            }
            let kind = js_sys::Reflect::get(&data, &wasm_bindgen::JsValue::from_str("kind"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_default();
            if kind != "unlock" {
                return;
            }
            let mut n = seen.borrow_mut();
            *n += 1;
            let credential = first_credential(&data);
            if *n == 1 {
                // The boot ceremony is answered at once with the enrolled key.
                let w = w.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let key = hkdf_key_from_bytes(&[SEED; 32]).await;
                    let _ = w.post_message(&key_msg(&credential, key));
                });
            } else {
                // A gate prompt goes to the test.
                *prompts.borrow_mut() = Some(data);
            }
        },
    );
    worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();
}

/// Import raw bytes as a non-extractable HKDF key.
async fn hkdf_key_from_bytes(seed: &[u8]) -> web_sys::CryptoKey {
    let scope: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let subtle = scope.crypto().expect("crypto").subtle();
    let raw: js_sys::Object = js_sys::Uint8Array::from(seed).unchecked_into();
    let usages = js_sys::Array::new();
    usages.push(&wasm_bindgen::JsValue::from_str("deriveBits"));
    let promise = subtle
        .import_key_with_str("raw", &raw, "HKDF", false, usages.as_ref())
        .expect("importKey promise");
    JsFuture::from(promise)
        .await
        .expect("importKey await")
        .unchecked_into::<web_sys::CryptoKey>()
}

async fn reset_key_store() {
    drop(IdbKeyStore::open().await.expect("open the key store"));
    let db = IdbDatabase::open(KEY_STORE_DB)
        .await
        .expect("reopen the key store");
    let tx = db
        .transaction([STORE_CREDENTIALS, STORE_KEK, STORE_WRAPPED])
        .with_mode(indexed_db_futures::transaction::TransactionMode::Readwrite)
        .build()
        .expect("reset tx");
    for store_name in [STORE_CREDENTIALS, STORE_KEK, STORE_WRAPPED] {
        tx.object_store(store_name)
            .expect("reset store")
            .clear()
            .expect("clear")
            .await
            .expect("clear await");
    }
    tx.commit().await.expect("reset commit");
}

async fn reset_profile() {
    reset_key_store().await;
    let storage = connetto_web::storage::ReplicaStorage::install().await;
    for db in [DEFAULT_AUTH_DB, GATE_AUTH_DB] {
        storage.delete_db(db).expect("clear auth database");
    }
}

/// Enrol one credential in the key store from `seed`, the way the boot
/// ceremony would on a first launch.
async fn plant_enrolled_credential(seed: u8, credential: u8) {
    reset_profile().await;
    let key_store = IdbKeyStore::open().await.expect("open key store");
    let hkdf = hkdf_key_from_bytes(&[seed; 32]).await;
    key_store
        .adopt_derived(hkdf, &[credential; 16])
        .await
        .expect("adopt credential");
}

/// The served URL of this test's wasm-bindgen glue module, recovered from the
/// wasm fetch the harness already performed.
fn glue_url() -> String {
    let found = js_sys::eval(
        r#"performance.getEntriesByType("resource").map((e) => e.name).find((n) => n.endsWith("_bg.wasm"))"#,
    )
    .expect("query resource entries")
    .as_string()
    .expect("a loaded wasm resource entry");
    let base = found.strip_suffix("_bg.wasm").expect("wasm suffix");
    format!("{base}.js")
}

/// Wait until a gate prompt has been handed to the test.
async fn await_prompt(prompts: &Rc<RefCell<Option<wasm_bindgen::JsValue>>>) {
    for _ in 0..2_000 {
        if prompts.borrow().is_some() {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("no unlock prompt within 20s");
}

/// Answer a held gate prompt with the enrolled key.
async fn answer_prompt(worker: &Worker, prompt: wasm_bindgen::JsValue) {
    let credential = first_credential(&prompt);
    let key = hkdf_key_from_bytes(&[SEED; 32]).await;
    worker
        .post_message(&key_msg(&credential, key))
        .expect("post the key answer");
}

/// Post one visibility report for `tab` on the visibility channel.
fn post_visibility(tab: &str, visible: bool) {
    let channel = BroadcastChannel::new(VISIBILITY_CHANNEL).expect("open the visibility channel");
    let message = format!("vis:{tab}:{}", if visible { "v" } else { "h" });
    channel
        .post_message(&wasm_bindgen::JsValue::from_str(&message))
        .expect("post the visibility report");
}

/// Connect a tab to the worker's hub and apply the relayed gate state to its
/// client.
async fn connect_gate_tab(client_id: &str) -> ConnettoClient<MessageTransport<BroadcastChannel>> {
    let wire = format!("connetto-gate-wire-{client_id}");
    announce_tab(&wire).await.expect("announce the tab");
    let transport = MessageTransport::<BroadcastChannel>::new(&wire).expect("wire channel");
    let (running, pump) = ClientBuilder::new(demo_schema(), Once::new(transport))
        .with_client_id(client_id.to_owned())
        .connect_with_pump()
        .await
        .expect("tab connect through the wire channel");
    let client = running.client().clone();
    // The tab applies the relayed gate state before the pump handles the
    // handshake's gate frame, so the first state cannot be missed.
    wasm_bindgen_futures::spawn_local(pump);
    client
}

/// Wait until `client` refuses application access with the locked error.
async fn await_locked<T>(client: &ConnettoClient<T>)
where
    T: connetto_core::traits::Transport + connetto_core::traits::MaybeSend + 'static,
    T::Error: core::fmt::Display,
{
    for _ in 0..2_000 {
        match client.with_conn(|_| 0_i64).await {
            Err(ClientError::Locked) => return,
            _ => sleep(Duration::from_millis(10)).await,
        }
    }
    panic!("the tab never locked within 20s");
}

/// Wait until `client` allows application access, bounded so a lost
/// unlock is diagnosed rather than hung on.
async fn await_open<T>(client: &ConnettoClient<T>)
where
    T: connetto_core::traits::Transport + connetto_core::traits::MaybeSend + 'static,
    T::Error: core::fmt::Display,
{
    for _ in 0..2_000 {
        match client.with_conn(|_| 0_i64).await {
            Ok(_) => return,
            Err(_) => sleep(Duration::from_millis(10)).await,
        }
    }
    panic!("the tab never opened within 20s");
}

/// Assert that `client` allows application access right now.
async fn assert_open<T>(client: &ConnettoClient<T>)
where
    T: connetto_core::traits::Transport + connetto_core::traits::MaybeSend + 'static,
    T::Error: core::fmt::Display,
{
    client
        .with_conn(|_| 0_i64)
        .await
        .expect("the tab must be open");
}

async fn spawn_worker_with_prompt_handler(
    grace_ms: u32,
) -> (Worker, Rc<RefCell<Option<wasm_bindgen::JsValue>>>) {
    let prompts: Rc<RefCell<Option<wasm_bindgen::JsValue>>> = Rc::new(RefCell::new(None));
    let worker = spawn_gate_worker(&glue_url(), grace_ms);
    install_prompt_handler(&worker, Rc::clone(&prompts));
    (worker, prompts)
}

// Test cases are self-contained. `wasm-bindgen-test` does not promise source
// order, and the key store is browser-profile state.

/// A durable boot that says nothing about the gate is gated. With a
/// credential enrolled it runs the unlock ceremony and becomes ready, where a
/// boot with the gate turned off refuses an enrolled credential outright.
#[wasm_bindgen_test]
async fn a_durable_boot_with_no_gate_setting_is_gated() {
    stage("gate test: default");
    plant_enrolled_credential(SEED, 0x05).await;
    common::play_the_tab();
    let prompts: Rc<RefCell<Option<wasm_bindgen::JsValue>>> = Rc::new(RefCell::new(None));
    let worker = spawn_gate_worker_calling(&glue_url(), "db_worker_default_gate_boot()");
    install_prompt_handler(&worker, Rc::clone(&prompts));
    await_db_worker_ready(&[])
        .await
        .expect("the default boot unlocks through the ceremony and is ready");
    worker.terminate();
    stage("gate test: done");
}

#[wasm_bindgen_test]
async fn a_locked_gate_refuses_the_tabs_that_attach_while_it_is_locked() {
    stage("gate test: locked attach");
    plant_enrolled_credential(SEED, 0x01).await;
    stage("gate test: credential enrolled");
    common::play_the_tab();
    let (worker, prompts) = spawn_worker_with_prompt_handler(0).await;

    stage("gate test: waiting for worker ready");
    await_db_worker_ready(&[]).await.expect("db worker ready");

    // Hold the gate's launch prompt unanswered, so the gate stays locked.
    stage("gate test: holding the launch prompt");
    await_prompt(&prompts).await;

    let tab_a = connect_gate_tab("gate-tab-a").await;
    let tab_b = connect_gate_tab("gate-tab-b").await;

    // A tab that attaches while the gate is locked starts refusing.
    stage("gate test: waiting for the tabs to lock");
    await_locked(&tab_a).await;
    await_locked(&tab_b).await;
    assert!(
        matches!(tab_a.with_conn(|_| 0_i64).await, Err(ClientError::Locked)),
        "a tab that attached while the gate was locked must refuse access"
    );

    worker.terminate();
    stage("gate test: done");
}

#[wasm_bindgen_test]
async fn tab_visibility_aggregates_the_gate_lock_on_every_return() {
    stage("gate test: aggregation");
    plant_enrolled_credential(SEED, 0x02).await;
    common::play_the_tab();
    let (worker, prompts) = spawn_worker_with_prompt_handler(0).await;

    await_db_worker_ready(&[]).await.expect("db worker ready");
    stage("gate test: answering the launch prompt");
    await_prompt(&prompts).await;
    let launch = prompts.borrow_mut().take().expect("the launch prompt");
    answer_prompt(&worker, launch).await;

    let tab_a = connect_gate_tab("gate-tab-agga").await;
    let tab_b = connect_gate_tab("gate-tab-aggb").await;
    assert_open(&tab_a).await;
    assert_open(&tab_b).await;

    // Both tabs visible, then each hidden, and the application is away only when
    // the last visible tab goes hidden.
    post_visibility("gate-tab-agga", true);
    post_visibility("gate-tab-aggb", true);
    sleep(Duration::from_millis(50)).await;
    assert_open(&tab_a).await;
    post_visibility("gate-tab-agga", false);
    sleep(Duration::from_millis(50)).await;
    assert_open(&tab_a).await;
    assert_open(&tab_b).await;
    post_visibility("gate-tab-aggb", false);
    sleep(Duration::from_millis(50)).await;
    // Away, but a zero-grace re-check has not happened yet, so the gate is open.
    assert_open(&tab_a).await;
    assert_open(&tab_b).await;

    // One tab returns and the away time exceeds the zero grace, so the gate
    // re-checks and every tab locks until the re-check is answered.
    stage("gate test: the return re-checks");
    post_visibility("gate-tab-aggb", true);
    await_locked(&tab_a).await;
    await_locked(&tab_b).await;
    assert!(
        matches!(tab_a.with_conn(|_| 0_i64).await, Err(ClientError::Locked)),
        "a return past the zero grace must lock the gate"
    );

    worker.terminate();
    stage("gate test: done");
}

#[wasm_bindgen_test]
async fn a_closing_tab_counts_as_hidden_for_the_gate() {
    stage("gate test: closing tab counts as hidden");
    plant_enrolled_credential(SEED, 0x03).await;
    common::play_the_tab();
    let (worker, prompts) = spawn_worker_with_prompt_handler(0).await;

    await_db_worker_ready(&[]).await.expect("db worker ready");
    await_prompt(&prompts).await;
    let launch = prompts.borrow_mut().take().expect("the launch prompt");
    answer_prompt(&worker, launch).await;

    let tab_a = connect_gate_tab("gate-tab-clsa").await;
    let tab_b = connect_gate_tab("gate-tab-clsb").await;
    assert_open(&tab_a).await;

    // Tab A holds its liveness lock, so the worker watches it.
    let lock_a = locks::hold_lock(&locks::tab_lock_name("gate-tab-clsa")).await;
    post_visibility("gate-tab-clsa", true);
    post_visibility("gate-tab-clsb", true);
    sleep(Duration::from_millis(50)).await;
    assert_open(&tab_a).await;

    // Tab A closes without a report, and its liveness lock freeing is the report.
    stage("gate test: tab A closes");
    drop(lock_a);
    sleep(Duration::from_millis(100)).await;
    post_visibility("gate-tab-clsb", false);
    sleep(Duration::from_millis(100)).await;
    assert_open(&tab_a).await;
    assert_open(&tab_b).await;

    // Tab B returns and the away time exceeds the zero grace, so the gate
    // re-checks and locks.
    stage("gate test: the return re-checks");
    post_visibility("gate-tab-clsb", true);
    await_locked(&tab_a).await;
    await_locked(&tab_b).await;

    worker.terminate();
    stage("gate test: done");
}

#[wasm_bindgen_test]
async fn an_approval_unlocks_every_tab() {
    stage("gate test: approval unlocks every tab");
    plant_enrolled_credential(SEED, 0x04).await;
    common::play_the_tab();
    let (worker, prompts) = spawn_worker_with_prompt_handler(0).await;

    await_db_worker_ready(&[]).await.expect("db worker ready");
    await_prompt(&prompts).await;
    let launch = prompts.borrow_mut().take().expect("the launch prompt");
    answer_prompt(&worker, launch).await;

    let tab_a = connect_gate_tab("gate-tab-unla").await;
    let tab_b = connect_gate_tab("gate-tab-unlb").await;
    assert_open(&tab_a).await;
    assert_open(&tab_b).await;

    // Both tabs hide and tab B returns, and the re-check locks, held open.
    post_visibility("gate-tab-unla", true);
    post_visibility("gate-tab-unlb", true);
    sleep(Duration::from_millis(50)).await;
    assert_open(&tab_a).await;
    post_visibility("gate-tab-unla", false);
    post_visibility("gate-tab-unlb", false);
    sleep(Duration::from_millis(100)).await;
    assert_open(&tab_a).await;
    stage("gate test: the return locks");
    post_visibility("gate-tab-unlb", true);
    await_locked(&tab_a).await;
    await_locked(&tab_b).await;

    // A tab that attaches while the re-check is pending starts locked.
    let tab_c = connect_gate_tab("gate-tab-unlc").await;
    await_locked(&tab_c).await;

    // The approval unlocks every tab, attached and locking alike.
    stage("gate test: answering the re-check");
    let held = prompts
        .borrow_mut()
        .take()
        .expect("the held re-check prompt");
    answer_prompt(&worker, held).await;
    for tab in [&tab_a, &tab_b, &tab_c] {
        await_open(tab).await;
    }

    worker.terminate();
    stage("gate test: done");
}
