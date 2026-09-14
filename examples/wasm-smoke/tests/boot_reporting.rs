//! A failing boot names the boot it belongs to, whichever bootstrap spawned it.
//!
//! The shipped script bootstrap (`db-worker.js`) fails before the Rust side runs when the
//! glue it is handed cannot be imported, so the page can only learn why if the script tags
//! its own failure with the boot identity it was spawned with.
//!

#![cfg(target_arch = "wasm32")]

use connetto_wasm_smoke::workers::await_db_worker_ready;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// A glue URL that resolves beside this suite's assets and has nothing behind it.
fn missing_glue_url() -> String {
    let found = js_sys::eval(
        r#"performance.getEntriesByType("resource").map((e) => e.name).find((n) => n.endsWith("_bg.wasm"))"#,
    )
    .expect("query resource entries")
    .as_string()
    .expect("a loaded wasm resource entry");
    let base = found.strip_suffix("_bg.wasm").expect("wasm suffix");
    format!("{base}-absent.js")
}

#[wasm_bindgen_test]
async fn a_script_bootstrap_reports_an_import_failure_to_the_waiting_page() {
    let (worker, boot) = connetto_wasm_smoke::workers::spawn_db_worker(&missing_glue_url())
        .expect("spawning the worker itself must succeed");

    let reported = await_db_worker_ready(&[boot])
        .await
        .expect_err("a worker that cannot import its glue must not report readiness")
        .as_string()
        .unwrap_or_default();

    assert!(
        reported.contains("boot failed"),
        "the failure must be attributed, not waited out as a timeout: {reported}"
    );
    worker.terminate();
}
