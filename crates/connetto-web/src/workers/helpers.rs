use js_sys::Promise;
use sha2::{Digest, Sha256};
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

/// Derive the browser content store namespace from `seed` and `replica_db_name`.
pub(super) fn content_store_namespace(seed: &str, replica_db_name: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(seed.as_bytes());
    digest.update([0]);
    digest.update(replica_db_name.as_bytes());
    format!("{:x}", digest.finalize())
}

/// Resolve after `ms` milliseconds, in a window or a worker context.
pub(super) async fn sleep_ms(ms: i32) {
    let promise = Promise::new(&mut |resolve, _reject| {
        let global = js_sys::global();
        let set_timeout = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
            .ok()
            .and_then(|f| f.dyn_into::<js_sys::Function>().ok());
        if let Some(set_timeout) = set_timeout {
            let _ = set_timeout.call2(&global, &resolve, &JsValue::from_f64(f64::from(ms)));
        }
    });
    let _ = JsFuture::from(promise).await;
}
