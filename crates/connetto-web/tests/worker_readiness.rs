//! Browser acceptance for page-side DB worker readiness failures.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_web::workers::{HELLO_CHANNEL, await_db_worker_ready};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::BroadcastChannel;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// A worker boot failure on the hello channel ends the page-side wait.
#[wasm_bindgen_test]
async fn readiness_wait_reports_worker_boot_failure() {
    let channel = BroadcastChannel::new(HELLO_CHANNEL).expect("hello channel");
    let sender = channel.clone();
    spawn_local(async move {
        connetto_web::workers::sleep(core::time::Duration::from_millis(50)).await;
        let _ = sender.post_message(&JsValue::from_str("failed:stale schema"));
    });

    let err = await_db_worker_ready()
        .await
        .expect_err("the worker failure is reported");
    let detail = err.as_string().expect("the failure is a string");
    assert!(
        detail.contains("stale schema"),
        "the named worker failure is returned"
    );
    channel.close();
}
