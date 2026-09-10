//! Browser content URL ownership contracts.

use connetto_web::ObjectUrl;
use js_sys::Uint8Array;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{DedicatedWorkerGlobalScope, Response};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
async fn a_blob_url_survives_clones_and_is_revoked_with_the_last_owner() {
    let first = ObjectUrl::new(b"local photo", "image/jpeg").expect("create object URL");
    let url = first.as_str().to_owned();
    let last = first.clone();
    drop(first);

    assert_eq!(
        fetch(&url).await.expect("clone keeps URL alive"),
        b"local photo"
    );
    drop(last);
    assert!(fetch(&url).await.is_err(), "the last drop revokes the URL");
}

async fn fetch(url: &str) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
    let scope: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    let response = JsFuture::from(scope.fetch_with_str(url))
        .await?
        .dyn_into::<Response>()?;
    let buffer = JsFuture::from(response.array_buffer()?).await?;
    Ok(Uint8Array::new(&buffer).to_vec())
}
