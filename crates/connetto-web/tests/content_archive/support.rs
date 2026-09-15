use std::cell::{Cell, RefCell};
use std::rc::Rc;

use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, future_to_promise};
use web_sys::{DedicatedWorkerGlobalScope, Request, Response};

/// A global replaced for the duration of one test, restored on drop.
pub(super) struct Replaced {
    global: Object,
    key: JsValue,
    previous: JsValue,
    #[expect(
        dead_code,
        reason = "the replacement calls these closures from JavaScript, so they outlive it here"
    )]
    kept: Kept,
}

/// The callbacks a replacement calls, alive as long as the replacement is.
#[expect(
    dead_code,
    reason = "the replacement calls these closures from JavaScript, so they outlive it here"
)]
enum Kept {
    /// The `fetch` answering the intent and the commit.
    Fetch(Closure<dyn FnMut(JsValue) -> Promise>),
    /// The upload's body recorder and its start signal.
    Upload(Closure<dyn FnMut(JsValue)>, Closure<dyn FnMut()>),
}

/// The two transports a content transfer uses, `fetch` for the intent and the
/// commit and `XMLHttpRequest` for the chunk `PUT` whose send is observed.
pub(super) struct ContentStubs {
    _fetch: Replaced,
    _upload: Replaced,
}

/// The same pair, with the chunk `PUT` held until the test releases it.
pub(super) struct BlockedUpload {
    _stubs: ContentStubs,
    pub(super) started: Rc<Cell<bool>>,
    release: Function,
}

impl BlockedUpload {
    pub(super) fn release(&self) {
        self.release
            .call0(&JsValue::UNDEFINED)
            .expect("release upload");
    }
}

pub(super) fn install_content_transport(uploaded: &Rc<RefCell<Vec<Vec<u8>>>>) -> ContentStubs {
    ContentStubs {
        _fetch: replace_content_fetch(),
        _upload: replace_content_upload(uploaded, None),
    }
}

pub(super) fn install_blocked_content_transport(
    uploaded: &Rc<RefCell<Vec<Vec<u8>>>>,
) -> BlockedUpload {
    let resolver = Rc::new(RefCell::new(None));
    let release = Rc::clone(&resolver);
    let gate = Promise::new(&mut move |resolve, _reject| {
        release.borrow_mut().replace(resolve);
    });
    let release = resolver.borrow_mut().take().expect("upload gate resolver");
    let started = Rc::new(Cell::new(false));
    let stubs = ContentStubs {
        _fetch: replace_content_fetch(),
        _upload: replace_content_upload(uploaded, Some((Rc::clone(&started), gate))),
    };
    BlockedUpload {
        _stubs: stubs,
        started,
        release,
    }
}

/// Answers the chunk `PUT` the way the file server does, recording its body,
/// reporting upload progress so the transport's idle bound keeps resetting,
/// and waiting on `gate` before answering when the test holds one.
fn replace_content_upload(
    uploaded: &Rc<RefCell<Vec<Vec<u8>>>>,
    gate: Option<(Rc<Cell<bool>>, Promise)>,
) -> Replaced {
    let captured = Rc::clone(uploaded);
    let record = Closure::<dyn FnMut(JsValue)>::new(move |body: JsValue| {
        let bytes = body
            .dyn_into::<Uint8Array>()
            .expect("the upload body is a byte array");
        captured.borrow_mut().push(bytes.to_vec());
    });
    let (started_flag, held) = match gate {
        Some((started, gate)) => (Some(started), gate.into()),
        None => (None, JsValue::NULL),
    };
    let started = Closure::<dyn FnMut()>::new(move || {
        if let Some(flag) = started_flag.as_ref() {
            flag.set(true);
        }
    });
    let factory = js_sys::eval(UPLOAD_STUB).expect("evaluate the upload replacement");
    let replacement = factory
        .dyn_into::<Function>()
        .expect("the upload replacement is a factory")
        .call3(
            &JsValue::UNDEFINED,
            record.as_ref(),
            started.as_ref(),
            &held,
        )
        .expect("build the upload replacement");
    replace_global(
        "XMLHttpRequest",
        &replacement,
        Kept::Upload(record, started),
    )
}

/// An `XMLHttpRequest` that answers `204` once its body has gone out, and
/// whose progress events are what a bounded upload observes.
const UPLOAD_STUB: &str = "(record, started, gate) => class ScriptedUpload {
    constructor() {
        this.upload = {};
        this.status = 0;
        this.responseURL = '';
        this.response = null;
    }
    open(method, url) {
        this.method = method;
        this.url = url;
    }
    setRequestHeader() {}
    abort() {
        this.aborted = true;
        if (this.onabort) { this.onabort(); }
    }
    send(body) {
        if (this.upload.onprogress) { this.upload.onprogress(); }
        const answer = () => {
            if (this.aborted) { return; }
            record(body);
            this.status = 204;
            this.responseURL = this.url;
            this.response = new ArrayBuffer(0);
            if (this.onload) { this.onload(); }
        };
        if (gate) {
            started();
            gate.then(answer);
        } else {
            answer();
        }
    }
};";

/// Replaces one global, answering the value to restore it with on drop.
fn replace_global(name: &str, replacement: &JsValue, kept: Kept) -> Replaced {
    let global = js_sys::global();
    let key = JsValue::from_str(name);
    let previous = Reflect::get(&global, &key).expect("read the global");
    Reflect::set(&global, &key, replacement).expect("replace the global");
    Replaced {
        global,
        key,
        previous,
        kept,
    }
}

/// Answers the intent with every declared hash and the commit with `200`.
fn replace_content_fetch() -> Replaced {
    let closure = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |value: JsValue| {
        let request = value.dyn_into::<Request>().expect("fetch receives Request");
        future_to_promise(async move {
            let body = JsFuture::from(request.array_buffer()?).await?;
            let body = Uint8Array::new(&body).to_vec();
            if request.url().contains("/intent?") {
                let intent: serde_json::Value =
                    serde_json::from_slice(&body).expect("decode upload intent");
                let needed: Vec<&str> = intent["chunks"]
                    .as_array()
                    .expect("intent chunks")
                    .iter()
                    .map(|chunk| chunk["hash"].as_str().expect("chunk hash"))
                    .collect();
                response(
                    Some(&serde_json::json!({ "needed": needed }).to_string()),
                    200,
                )
            } else {
                response(None, 200)
            }
        })
    });
    let replacement: JsValue = closure.as_ref().clone();
    replace_global("fetch", &replacement, Kept::Fetch(closure))
}

impl Drop for Replaced {
    fn drop(&mut self) {
        let _ = Reflect::set(&self.global, &self.key, &self.previous);
    }
}

fn response(body: Option<&str>, status: u16) -> Result<JsValue, JsValue> {
    let global = js_sys::global();
    let constructor =
        Reflect::get(&global, &JsValue::from_str("Response"))?.dyn_into::<Function>()?;
    let init = Object::new();
    Reflect::set(
        &init,
        &JsValue::from_str("status"),
        &JsValue::from_f64(f64::from(status)),
    )?;
    let arguments = Array::new();
    arguments.push(&body.map_or(JsValue::NULL, JsValue::from_str));
    arguments.push(&init);
    Reflect::construct(&constructor, &arguments)
}

pub(super) async fn fetch_bytes(url: &str) -> Result<Vec<u8>, JsValue> {
    let scope = js_sys::global().dyn_into::<DedicatedWorkerGlobalScope>()?;
    let response = JsFuture::from(scope.fetch_with_str(url))
        .await?
        .dyn_into::<Response>()?;
    let buffer = JsFuture::from(response.array_buffer()?).await?;
    Ok(Uint8Array::new(&buffer).to_vec())
}

pub(super) async fn timeout_ms(ms: i32) {
    let promise = Promise::new(&mut |resolve, _reject| {
        let global = js_sys::global();
        let set_timeout = Reflect::get(&global, &JsValue::from_str("setTimeout"))
            .expect("read setTimeout")
            .dyn_into::<Function>()
            .expect("setTimeout function");
        set_timeout
            .call2(&global, &resolve, &JsValue::from_f64(f64::from(ms)))
            .expect("schedule timeout");
    });
    JsFuture::from(promise).await.expect("timeout");
}

/// Polls per task turn rather than per microtask, because the worker's stored
/// bytes and its timers only advance on the macrotask queue.
const POLL_MS: i32 = 10;
/// Three seconds of turns, enough for a loaded CI machine.
const POLLS: usize = 300;

/// Wait for `ready`, yielding a task turn between attempts.
pub(super) async fn until(mut ready: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..POLLS {
        if ready().await {
            return true;
        }
        timeout_ms(POLL_MS).await;
    }
    ready().await
}
