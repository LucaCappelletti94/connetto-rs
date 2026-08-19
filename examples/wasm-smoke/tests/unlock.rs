//! Tab-worker unlock protocol, without a WebAuthn authenticator.
//!
//! Three properties the protocol guarantees are provable with a stand-in tab
//! that posts the protocol's shaped objects directly rather than running a
//! ceremony, plus a fourth that acts as a regression guard for existing
//! consumers. Each test controls a spawned DB worker via `worker.onmessage`
//! and `worker.post_message`, so no simulated authenticator is needed.
//!
//! **Needs the stack up.** See `authenticated_boot.rs` for the commands.
//! Run this suite with:
//! `wasm-pack test --headless --chrome examples/wasm-smoke --test unlock`
//!
//! Test ordering matters: tests 1 and 2 require an empty credentials store,
//! test 3 populates it, and test 4 relies on that state. wasm-bindgen runs
//! tests in source order within one binary.

#![cfg(target_arch = "wasm32")]

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use connetto_core::{Custody, NoGate};
use connetto_wasm_smoke::workers::{await_db_worker_ready, request_custody};
use connetto_web::auth::{IdbKeyStore, LOCKED_MESSAGE};
use wasm_bindgen::JsCast as _;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::MessageEvent;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

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

/// Build `{kind: "declined"}`.
fn declined_msg() -> wasm_bindgen::JsValue {
    let obj = js_sys::Object::new();
    set_str(&obj, "kind", "declined");
    obj.into()
}

/// Build `{kind: "unsupported"}`.
fn unsupported_msg() -> wasm_bindgen::JsValue {
    let obj = js_sys::Object::new();
    set_str(&obj, "kind", "unsupported");
    obj.into()
}

/// Spawn a dedicated worker that boots with the unlock protocol enabled.
///
/// The worker calls `db_worker_unlock_boot()` instead of the stock
/// `db_worker_boot()`. The bootstrap is a blob module so no extra script file
/// is needed, mirroring the `WorkerBootstrap::Generated` pattern in
/// `connetto_web::workers`.
fn spawn_unlock_worker(glue_url: &str) -> web_sys::Worker {
    let wasm_url = glue_url
        .strip_suffix(".js")
        .map_or_else(|| format!("{glue_url}_bg.wasm"), |b| format!("{b}_bg.wasm"));
    // The blob broadcasts failures to connetto-debug before rethrowing, matching
    // the pattern db-worker.js uses, so test listeners can detect boot errors.
    let source = format!(
        "try {{\
         \n  const mod = await import(\"{g}\");\
         \n  await mod.default({{ module_or_path: \"{w}\" }});\
         \n  await mod.db_worker_unlock_boot();\
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
    worker_opts.set_name("connetto-db-unlock");
    let worker =
        web_sys::Worker::new_with_options(&url, &worker_opts).expect("spawn unlock worker");
    let _ = web_sys::Url::revoke_object_url(&url);
    worker
}

/// Install a one-time handler on `channel` that resolves the returned future
/// when a message whose body contains `needle` arrives.
fn wait_debug_for(needle: &'static str) -> futures_channel::oneshot::Receiver<String> {
    let (tx, rx) = futures_channel::oneshot::channel::<String>();
    let tx = Rc::new(RefCell::new(Some(tx)));
    let channel = web_sys::BroadcastChannel::new("connetto-debug").expect("debug channel");
    let on_message = wasm_bindgen::closure::Closure::<dyn FnMut(MessageEvent)>::new(
        move |event: MessageEvent| {
            if let Some(msg) = event.data().as_string()
                && msg.contains(needle)
                && let Some(s) = tx.borrow_mut().take()
            {
                let _ = s.send(msg);
            }
        },
    );
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    // Both the channel and the closure outlive the call.
    on_message.forget();
    std::mem::forget(channel);
    rx
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

// ─────────────────────────────────────────── tests ──────────────────────────

/// Tests 1 and 2 require no enrolled credentials in IDB. Test 3 plants them.
/// Test 4 uses what test 3 left. Source order is execution order.

#[wasm_bindgen_test]
async fn an_unsupported_enrolment_response_boots_with_ungated_custody_readable_from_the_tab() {
    stage("test 1: unsupported enrolment");
    // Relay worker breadcrumbs from the debug channel.
    let _debug_relay = {
        let ch = web_sys::BroadcastChannel::new("connetto-debug").expect("debug channel");
        let on_msg =
            wasm_bindgen::closure::Closure::<dyn FnMut(MessageEvent)>::new(|e: MessageEvent| {
                web_sys::console::log_1(&e.data());
            });
        ch.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
        on_msg.forget();
        ch
    };

    // The test plays the tab for login requests and for the enrol request.
    let logins = common::play_the_tab();
    let worker = spawn_unlock_worker(&glue_url());

    // Stand-in tab handler: respond "unsupported" to the enrol request.
    {
        let w = worker.clone();
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
                if kind == "enrol" {
                    w.post_message(&unsupported_msg()).unwrap_or(());
                }
            },
        );
        worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        on_message.forget();
    }

    stage("test 1: waiting for worker ready");
    await_db_worker_ready().await;

    assert!(
        logins.get() >= 1,
        "the worker must have asked the tab to log in"
    );

    stage("test 1: reading custody from the worker");
    let custody = request_custody().await;
    assert_eq!(
        custody,
        Custody::Unverified(NoGate::Unsupported),
        "unsupported response leaves custody as unverified with no gate"
    );

    drop(worker);
    stage("test 1: done");
}

#[wasm_bindgen_test]
async fn custody_without_the_unlock_flag_reads_as_offerable() {
    stage("test 2: custody offerable regression guard");
    common::play_the_tab();

    // Spawn a worker with unlock=false (the default from spawn_db_worker).
    let worker =
        connetto_wasm_smoke::workers::spawn_db_worker(&glue_url()).expect("spawn default worker");

    stage("test 2: waiting for worker ready");
    await_db_worker_ready().await;

    stage("test 2: reading custody from the worker");
    let custody = request_custody().await;
    assert_eq!(
        custody,
        Custody::Unverified(NoGate::Offerable),
        "a consumer that does not enable unlock always sees offerable custody"
    );

    drop(worker);
    stage("test 2: done");
}

#[wasm_bindgen_test]
async fn a_declined_unlock_refuses_the_boot_and_destroys_nothing() {
    stage("test 3: declined unlock");

    // Plant an enrolled credential in IDB. After this call the credentials store
    // is non-empty, so the spawned worker will send an unlock request.
    let key_store = IdbKeyStore::open().await.expect("open key store");
    let hkdf = hkdf_key_from_bytes(&[0xbbu8; 32]).await;
    key_store
        .adopt_derived(hkdf, &[0x01u8; 16])
        .await
        .expect("adopt credential");
    stage("test 3: credential enrolled in IDB");

    // Capture the OPFS pool state before the (failing) boot.
    let storage = connetto_web::storage::ReplicaStorage::install().await;
    let pool_before = storage.list();

    // Arm the failure detector before spawning the worker.
    let failure_rx = wait_debug_for("FAILED");

    let worker = spawn_unlock_worker(&glue_url());

    // Stand-in tab handler: respond "declined" to the unlock request.
    {
        let w = worker.clone();
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
                if kind == "unlock" {
                    w.post_message(&declined_msg()).unwrap_or(());
                }
            },
        );
        worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        on_message.forget();
    }

    stage("test 3: waiting for boot failure");
    let failure_msg = failure_rx.await.expect("must receive the failure message");
    assert!(
        failure_msg.contains(LOCKED_MESSAGE),
        "boot must fail with the locked message, got: {failure_msg}"
    );

    // The boot destroyed nothing: the OPFS pool is unchanged.
    let pool_after = storage.list();
    assert_eq!(
        pool_before, pool_after,
        "a declined boot must not alter the OPFS pool"
    );

    drop(worker);
    stage("test 3: done");
}

#[wasm_bindgen_test]
async fn unlock_disabled_with_an_enrolled_credential_refuses_the_boot() {
    stage("test 4: unlock=false with enrolled credential");
    // Credentials are present from test 3. The default spawn_db_worker uses
    // unlock=false, so the boot must refuse rather than silently fall back.

    let failure_rx = wait_debug_for("FAILED");
    let _worker =
        connetto_wasm_smoke::workers::spawn_db_worker(&glue_url()).expect("spawn default worker");

    stage("test 4: waiting for boot failure");
    let failure_msg = failure_rx.await.expect("must receive the failure message");
    assert!(
        failure_msg.contains(LOCKED_MESSAGE),
        "boot with unlock=false and enrolled credential must fail, got: {failure_msg}"
    );

    stage("test 4: done");
}
