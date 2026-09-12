use std::cell::{Cell, RefCell};
use std::rc::Rc;

use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, future_to_promise};
use web_sys::{DedicatedWorkerGlobalScope, Request, Response};

pub(super) struct FetchReplacement {
    global: Object,
    key: JsValue,
    previous: JsValue,
    _closure: Closure<dyn FnMut(JsValue) -> Promise>,
}

pub(super) struct BlockedFetch {
    _fetch: FetchReplacement,
    pub(super) started: Rc<Cell<bool>>,
    release: Function,
}

impl BlockedFetch {
    pub(super) fn release(&self) {
        self.release
            .call0(&JsValue::UNDEFINED)
            .expect("release upload");
    }
}

pub(super) fn install_content_fetch(uploaded: &Rc<RefCell<Vec<Vec<u8>>>>) -> FetchReplacement {
    replace_content_fetch(uploaded, None)
}

pub(super) fn install_blocked_content_fetch(uploaded: &Rc<RefCell<Vec<Vec<u8>>>>) -> BlockedFetch {
    let resolver = Rc::new(RefCell::new(None));
    let release = Rc::clone(&resolver);
    let gate = Promise::new(&mut move |resolve, _reject| {
        release.borrow_mut().replace(resolve);
    });
    let release = resolver.borrow_mut().take().expect("upload gate resolver");
    let started = Rc::new(Cell::new(false));
    let fetch = replace_content_fetch(uploaded, Some((Rc::clone(&started), gate)));
    BlockedFetch {
        _fetch: fetch,
        started,
        release,
    }
}

fn replace_content_fetch(
    uploaded: &Rc<RefCell<Vec<Vec<u8>>>>,
    gate: Option<(Rc<Cell<bool>>, Promise)>,
) -> FetchReplacement {
    let captured = Rc::clone(uploaded);
    let closure = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |value: JsValue| {
        let request = value.dyn_into::<Request>().expect("fetch receives Request");
        let captured = Rc::clone(&captured);
        let gate = gate.clone();
        future_to_promise(async move {
            let body = JsFuture::from(request.array_buffer()?).await?;
            let body = Uint8Array::new(&body).to_vec();
            if request.method() == "PUT" {
                if let Some((started, gate)) = gate {
                    started.set(true);
                    JsFuture::from(gate).await?;
                }
                captured.borrow_mut().push(body);
                response(None, 204)
            } else if request.url().contains("/intent?") {
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

impl Drop for FetchReplacement {
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
