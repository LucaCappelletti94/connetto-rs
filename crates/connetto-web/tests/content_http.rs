//! Browser content HTTP request contracts.

use std::cell::RefCell;
use std::rc::Rc;

use connetto_file_client::{BrowserHttp, ContentHttp};
use js_sys::{Promise, Reflect, Uint8Array};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, future_to_promise};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{Request, RequestRedirect, Response};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[derive(Debug, PartialEq, Eq)]
struct SeenRequest {
    method: String,
    url: String,
    content_type: Option<String>,
    range: Option<String>,
    body: Vec<u8>,
}

#[wasm_bindgen_test]
async fn fetch_transport_builds_every_content_request_shape() {
    let (seen, fetch) = install_recording_fetch();
    exercise_http().await;
    drop(fetch);
    assert_eq!(*seen.borrow(), expected_requests());
}

#[wasm_bindgen_test]
async fn fetch_transport_rejects_cleartext_non_loopback_tickets() {
    let Err(error) = BrowserHttp::new()
        .get("http://content.invalid/file", None)
        .await
    else {
        panic!("cleartext ticket must be refused");
    };
    assert!(error.to_string().contains("must use HTTPS"));
}

#[wasm_bindgen_test]
async fn fetch_transport_aborts_at_its_deadline() {
    let fetch = install_hanging_fetch();
    let Err(error) = BrowserHttp::new()
        .with_timeout(std::time::Duration::from_millis(1))
        .get("https://content.invalid/file", None)
        .await
    else {
        panic!("request must reach its deadline");
    };
    drop(fetch);
    assert!(error.to_string().contains("aborted"));
}

struct FetchReplacement {
    global: js_sys::Object,
    key: JsValue,
    previous: JsValue,
    _closure: Closure<dyn FnMut(JsValue) -> Promise>,
}

impl Drop for FetchReplacement {
    fn drop(&mut self) {
        let _ = Reflect::set(&self.global, &self.key, &self.previous);
    }
}

fn install_recording_fetch() -> (Rc<RefCell<Vec<SeenRequest>>>, FetchReplacement) {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let captured = Rc::clone(&seen);
    let closure = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |value: JsValue| {
        let request = value
            .dyn_into::<Request>()
            .expect("fetch receives a request");
        assert_eq!(request.redirect(), RequestRedirect::Error);
        let captured = Rc::clone(&captured);
        future_to_promise(async move {
            let buffer = JsFuture::from(request.array_buffer()?).await?;
            captured.borrow_mut().push(SeenRequest {
                method: request.method(),
                url: request.url(),
                content_type: request.headers().get("content-type")?,
                range: request.headers().get("range")?,
                body: Uint8Array::new(&buffer).to_vec(),
            });
            Ok(Response::new_with_opt_str(Some("browser reply"))?.into())
        })
    });
    let global = js_sys::global();
    let key = JsValue::from_str("fetch");
    let previous = Reflect::get(&global, &key).expect("read fetch");
    Reflect::set(&global, &key, closure.as_ref()).expect("replace fetch");
    (
        Rc::clone(&seen),
        FetchReplacement {
            global,
            key,
            previous,
            _closure: closure,
        },
    )
}

fn install_hanging_fetch() -> FetchReplacement {
    let closure = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |value: JsValue| {
        let request = value
            .dyn_into::<Request>()
            .expect("fetch receives a request");
        Promise::new(&mut move |_resolve, reject| {
            let reject = reject.clone();
            let abort = Closure::<dyn FnMut()>::once(move || {
                let _ = reject.call1(&JsValue::UNDEFINED, &JsValue::from_str("aborted"));
            });
            Reflect::set(
                request.signal().as_ref(),
                &JsValue::from_str("onabort"),
                abort.as_ref(),
            )
            .expect("observe abort");
            abort.forget();
        })
    });
    let global = js_sys::global();
    let key = JsValue::from_str("fetch");
    let previous = Reflect::get(&global, &key).expect("read fetch");
    Reflect::set(&global, &key, closure.as_ref()).expect("replace fetch");
    FetchReplacement {
        global,
        key,
        previous,
        _closure: closure,
    }
}

async fn exercise_http() {
    let http = BrowserHttp::new();
    let replies = [
        http.post(
            "https://content.invalid/tickets",
            Some(br#"{"size":12}"#.to_vec()),
        )
        .await,
        http.post("https://content.invalid/commit", None).await,
        http.put("https://content.invalid/chunk", b"ciphertext".to_vec())
            .await,
        http.get("https://content.invalid/file", None).await,
        http.get("https://content.invalid/file", Some((11, 29)))
            .await,
        http.get("http://127.0.0.1/file", None).await,
    ];
    for reply in replies {
        let reply = reply.expect("fetch request succeeds");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, b"browser reply");
    }
}

fn expected_requests() -> Vec<SeenRequest> {
    vec![
        SeenRequest {
            method: "POST".to_owned(),
            url: "https://content.invalid/tickets".to_owned(),
            content_type: Some("application/json".to_owned()),
            range: None,
            body: br#"{"size":12}"#.to_vec(),
        },
        SeenRequest {
            method: "POST".to_owned(),
            url: "https://content.invalid/commit".to_owned(),
            content_type: None,
            range: None,
            body: Vec::new(),
        },
        SeenRequest {
            method: "PUT".to_owned(),
            url: "https://content.invalid/chunk".to_owned(),
            content_type: Some("application/octet-stream".to_owned()),
            range: None,
            body: b"ciphertext".to_vec(),
        },
        SeenRequest {
            method: "GET".to_owned(),
            url: "https://content.invalid/file".to_owned(),
            content_type: None,
            range: None,
            body: Vec::new(),
        },
        SeenRequest {
            method: "GET".to_owned(),
            url: "https://content.invalid/file".to_owned(),
            content_type: None,
            range: Some("bytes=11-29".to_owned()),
            body: Vec::new(),
        },
        SeenRequest {
            method: "GET".to_owned(),
            url: "http://127.0.0.1/file".to_owned(),
            content_type: None,
            range: None,
            body: Vec::new(),
        },
    ]
}
