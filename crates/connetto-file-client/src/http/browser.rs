//! The browser content transport, bounded by silence rather than by time.

use core::time::Duration;
use std::cell::Cell;
use std::rc::Rc;

use js_sys::{ArrayBuffer, Promise, Reflect, Uint8Array};
use thiserror::Error;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    AbortController, AbortSignal, DedicatedWorkerGlobalScope, DomException, Headers,
    ReadableStreamDefaultReader, Request, RequestInit, RequestRedirect, Response, ResponseType,
    XmlHttpRequest, XmlHttpRequestResponseType,
};

use super::{ContentHttp, DEFAULT_IDLE_BOUND, HttpFailure, HttpReply};

/// What one browser request failed with before any reply could be read.
type Failed = HttpFailure<BrowserHttpError>;

/// A browser content request failure before a reply could be read.
#[derive(Debug, Error)]
pub enum BrowserHttpError {
    /// The browser refused an operation the transport needs.
    #[error("browser HTTP {operation}: {message}")]
    Refused {
        /// The operation that failed.
        operation: &'static str,
        /// The browser exception text.
        message: String,
    },
    /// Nothing moved in either direction for the idle bound.
    #[error("no byte moved in either direction for {bound_ms} ms")]
    Idle {
        /// The bound that elapsed in silence.
        bound_ms: i32,
    },
}

/// Content transport through the current worker's `fetch` and
/// `XMLHttpRequest`, bounded by silence rather than by elapsed time.
///
/// A transfer is aborted when no byte has moved in either direction for the
/// idle bound, thirty seconds by default, and a moving transfer is never
/// aborted however long it runs.
///
/// `GET` and `POST` go through `fetch` and read the reply as a stream, so the
/// bound is reset by the status line and by every received chunk. A `fetch`
/// request body send is unobservable, which is why the chunk `PUT` goes
/// through `XMLHttpRequest`, the one portable source of upload progress a
/// worker has. The intent body is a manifest of about a hundred bytes per
/// chunk and the commit carries no body, so for those the silence before the
/// status line covers the send and the server's work as one window.
///
/// `fetch` asks for the `manual` redirect mode, whose opaque reply is
/// distinguishable, where the `error` mode rejects with the same failure a
/// dropped connection raises. `XMLHttpRequest` follows every redirect with no
/// way to refuse, so the address its reply landed on is compared with the
/// address that was asked for, and any difference is refused.
#[derive(Clone, Copy, Debug)]
pub struct BrowserHttp {
    idle_bound_ms: i32,
}

impl Default for BrowserHttp {
    fn default() -> Self {
        Self::new()
    }
}

impl BrowserHttp {
    /// Creates a browser content transport under the default thirty second
    /// idle bound.
    #[must_use]
    pub fn new() -> Self {
        Self {
            idle_bound_ms: bound_ms(DEFAULT_IDLE_BOUND),
        }
    }

    /// Sets how long a transfer may stay silent before it is aborted.
    ///
    /// The bound covers every phase of a request, including the wait for the
    /// status line while the server verifies a chunk or runs a commit, so a
    /// deployment with a slow commit raises this rather than gaining a second
    /// number.
    #[must_use]
    pub fn with_idle_bound(mut self, idle_bound: Duration) -> Self {
        self.idle_bound_ms = bound_ms(idle_bound);
        self
    }

    /// Runs one `fetch` request and reads its reply as it arrives.
    async fn fetch(
        &self,
        method: &'static str,
        url: &str,
        body: Option<(Vec<u8>, &'static str)>,
        range: Option<(u64, u64)>,
    ) -> Result<HttpReply, Failed> {
        let scope = worker_scope()?;
        let controller =
            AbortController::new().map_err(|value| refused("create abort controller", &value))?;
        let request = build_request(method, url, body, range, &controller.signal())?;
        let watch = IdleWatch::new(&scope, self.idle_bound_ms, move || controller.abort())?;
        let reply = async {
            let response = JsFuture::from(scope.fetch_with_request(&request))
                .await
                .map_err(|value| refused("fetch", &value))?
                .dyn_into::<Response>()
                .map_err(|value| refused("decode response", &value))?;
            watch.reset();
            if response.type_() == ResponseType::Opaqueredirect {
                return Err(HttpFailure::Redirected { origin: None });
            }
            let status = response.status();
            let body = read_stream(&response, &watch).await?;
            Ok(HttpReply { status, body })
        }
        .await;
        watch.name_silence(reply)
    }
}

impl ContentHttp for BrowserHttp {
    type Error = BrowserHttpError;

    async fn post(
        &self,
        url: &str,
        json: Option<Vec<u8>>,
    ) -> Result<HttpReply, HttpFailure<Self::Error>> {
        self.fetch(
            "POST",
            url,
            json.map(|body| (body, "application/json")),
            None,
        )
        .await
    }

    async fn put(&self, url: &str, body: Vec<u8>) -> Result<HttpReply, HttpFailure<Self::Error>> {
        send_with_progress(url, body, self.idle_bound_ms).await
    }

    async fn get(
        &self,
        url: &str,
        range: Option<(u64, u64)>,
    ) -> Result<HttpReply, HttpFailure<Self::Error>> {
        self.fetch("GET", url, None, range).await
    }
}

/// Sends one body through `XMLHttpRequest`, which is the one portable source
/// of upload progress a worker has, and refuses a reply that landed on another
/// address than the one asked for.
async fn send_with_progress(
    url: &str,
    body: Vec<u8>,
    idle_bound_ms: i32,
) -> Result<HttpReply, Failed> {
    let scope = worker_scope()?;
    let request = XmlHttpRequest::new().map_err(|value| refused("create upload", &value))?;
    request
        .open_with_async("PUT", url, true)
        .map_err(|value| refused("open upload", &value))?;
    request.set_response_type(XmlHttpRequestResponseType::Arraybuffer);
    request
        .set_request_header("content-type", "application/octet-stream")
        .map_err(|value| refused("set content type", &value))?;
    let aborting = request.clone();
    let watch = IdleWatch::new(&scope, idle_bound_ms, move || {
        let _ = aborting.abort();
    })?;
    let reply = async {
        let settled = observe(&request, &watch)?;
        request
            .send_with_opt_u8_array(Some(&body))
            .map_err(|value| refused("send upload", &value))?;
        JsFuture::from(settled.promise.clone())
            .await
            .map_err(|value| refused("upload", &value))?;
        watch.reset();
        let landed = request.response_url();
        if landed_elsewhere(url, &landed) {
            return Err(HttpFailure::Redirected {
                origin: origin_of(&landed),
            });
        }
        let status = request
            .status()
            .map_err(|value| refused("read upload status", &value))?;
        let answer = request
            .response()
            .map_err(|value| refused("read upload reply", &value))?;
        Ok(HttpReply {
            status,
            body: buffer_bytes(&answer),
        })
    }
    .await;
    watch.name_silence(reply)
}

/// The handlers one `XMLHttpRequest` needs, alive until the request settles.
struct Observed {
    promise: Promise,
    _progress: Closure<dyn FnMut()>,
    _done: Closure<dyn FnMut()>,
    _failed: Closure<dyn FnMut()>,
}

/// Resolves when the request settles, resetting the bound as bytes move in
/// either direction.
fn observe(request: &XmlHttpRequest, watch: &IdleWatch) -> Result<Observed, Failed> {
    let upload = request
        .upload()
        .map_err(|value| refused("observe upload progress", &value))?;
    let moved = watch.resetter();
    let progress = Closure::<dyn FnMut()>::new(move || moved());
    upload.set_onprogress(Some(progress.as_ref().unchecked_ref()));
    request.set_onprogress(Some(progress.as_ref().unchecked_ref()));
    let mut handlers = None;
    let promise = Promise::new(&mut |resolve, reject| {
        let done = Closure::<dyn FnMut()>::new(move || {
            let _ = resolve.call0(&JsValue::UNDEFINED);
        });
        request.set_onload(Some(done.as_ref().unchecked_ref()));
        let failed = Closure::<dyn FnMut()>::new(move || {
            let _ = reject.call1(&JsValue::UNDEFINED, &JsValue::from_str("upload failed"));
        });
        request.set_onerror(Some(failed.as_ref().unchecked_ref()));
        request.set_onabort(Some(failed.as_ref().unchecked_ref()));
        handlers = Some((done, failed));
    });
    let (done, failed) = handlers.ok_or_else(|| {
        refused(
            "observe upload",
            &JsValue::from_str("the promise ran no executor"),
        )
    })?;
    Ok(Observed {
        promise,
        _progress: progress,
        _done: done,
        _failed: failed,
    })
}

/// Reads a reply body chunk by chunk, resetting the bound per chunk.
async fn read_stream(response: &Response, watch: &IdleWatch) -> Result<Vec<u8>, Failed> {
    let Some(stream) = response.body() else {
        return Ok(Vec::new());
    };
    let reader = stream
        .get_reader()
        .dyn_into::<ReadableStreamDefaultReader>()
        .map_err(|value| refused("read reply stream", &value))?;
    let mut body = Vec::new();
    loop {
        let chunk = JsFuture::from(reader.read())
            .await
            .map_err(|value| refused("read reply chunk", &value))?;
        watch.reset();
        if Reflect::get(&chunk, &JsValue::from_str("done"))
            .map_err(|value| refused("read reply chunk", &value))?
            .is_truthy()
        {
            return Ok(body);
        }
        let bytes = Reflect::get(&chunk, &JsValue::from_str("value"))
            .map_err(|value| refused("read reply chunk", &value))?
            .dyn_into::<Uint8Array>()
            .map_err(|value| refused("decode reply chunk", &value))?;
        body.extend_from_slice(&bytes.to_vec());
    }
}

/// Builds one `fetch` request in the `manual` redirect mode.
fn build_request(
    method: &str,
    url: &str,
    body: Option<(Vec<u8>, &'static str)>,
    range: Option<(u64, u64)>,
    signal: &AbortSignal,
) -> Result<Request, Failed> {
    let init = RequestInit::new();
    init.set_signal(Some(signal));
    init.set_redirect(RequestRedirect::Manual);
    init.set_method(method);
    let headers = Headers::new().map_err(|value| refused("create headers", &value))?;
    if let Some((bytes, content_type)) = body {
        headers
            .set("content-type", content_type)
            .map_err(|value| refused("set content type", &value))?;
        init.set_body_opt_u8_array(Some(&Uint8Array::from(bytes.as_slice())));
    }
    if let Some((first, last)) = range {
        headers
            .set("range", &format!("bytes={first}-{last}"))
            .map_err(|value| refused("set byte range", &value))?;
    }
    init.set_headers_headers(&headers);
    Request::new_with_str_and_init(url, &init).map_err(|value| refused("create request", &value))
}

/// The timer one request is aborted by, re-armed by every byte that moves.
struct IdleTimer {
    scope: DedicatedWorkerGlobalScope,
    bound_ms: i32,
    handle: Cell<Option<i32>>,
    abort: Closure<dyn FnMut()>,
}

impl IdleTimer {
    /// Starts the bound again from now.
    ///
    /// The fresh timer is armed before the previous one is cleared, so a
    /// browser that refuses the call leaves the request watched by the timer
    /// it already had rather than unwatched.
    fn reset(&self) {
        let armed = self
            .scope
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                self.abort.as_ref().unchecked_ref(),
                self.bound_ms,
            )
            .ok();
        let previous = self.handle.replace(armed);
        if let Some(handle) = previous {
            self.scope.clear_timeout_with_handle(handle);
        }
    }

    /// Stops watching, which is what a settled request needs.
    fn clear(&self) {
        if let Some(handle) = self.handle.take() {
            self.scope.clear_timeout_with_handle(handle);
        }
    }
}

/// One request's silence watchdog.
struct IdleWatch {
    timer: Rc<IdleTimer>,
    fired: Rc<Cell<bool>>,
}

impl IdleWatch {
    /// Starts watching, aborting the request when the bound elapses in silence.
    fn new(
        scope: &DedicatedWorkerGlobalScope,
        bound_ms: i32,
        abort: impl Fn() + 'static,
    ) -> Result<Self, Failed> {
        let fired = Rc::new(Cell::new(false));
        let raised = Rc::clone(&fired);
        let timer = Rc::new(IdleTimer {
            scope: scope.clone(),
            bound_ms,
            handle: Cell::new(None),
            abort: Closure::<dyn FnMut()>::new(move || {
                raised.set(true);
                abort();
            }),
        });
        let watch = Self { timer, fired };
        watch.timer.reset();
        if watch.timer.handle.get().is_none() {
            return Err(refused(
                "set idle bound",
                &JsValue::from_str("the worker refused a timer"),
            ));
        }
        Ok(watch)
    }

    /// Records that a byte moved, so the bound starts again from here.
    fn reset(&self) {
        self.timer.reset();
    }

    /// A reset this request's own event handlers can call.
    fn resetter(&self) -> impl Fn() + 'static {
        let timer = Rc::clone(&self.timer);
        move || timer.reset()
    }

    /// Names the silence when this watch is what ended the request.
    fn name_silence(self, reply: Result<HttpReply, Failed>) -> Result<HttpReply, Failed> {
        match reply {
            Err(HttpFailure::Transport(_)) if self.fired.get() => {
                Err(HttpFailure::Transport(BrowserHttpError::Idle {
                    bound_ms: self.timer.bound_ms,
                }))
            }
            other => other,
        }
    }
}

impl Drop for IdleWatch {
    fn drop(&mut self) {
        self.timer.clear();
    }
}

/// The current worker scope, which is where content transfers run.
fn worker_scope() -> Result<DedicatedWorkerGlobalScope, Failed> {
    js_sys::global()
        .dyn_into()
        .map_err(|value: js_sys::Object| refused("acquire worker scope", &value.into()))
}

/// Whether a reply landed on an address other than the one asked for.
fn landed_elsewhere(asked: &str, landed: &str) -> bool {
    match (url::Url::parse(asked), url::Url::parse(landed)) {
        (Ok(asked), Ok(landed)) => asked != landed,
        // An address the parser refuses is not the address that was asked for,
        // and an empty one is a reply that never reached a server.
        (Ok(_), Err(_)) => !landed.is_empty(),
        _ => false,
    }
}

/// The origin of a landed address, which is all a refusal records, because a
/// landed address can carry the ticket in its query.
fn origin_of(landed: &str) -> Option<String> {
    url::Url::parse(landed)
        .ok()
        .map(|url| url.origin().ascii_serialization())
}

/// The bytes of an `arraybuffer` reply, empty when the answer carried none.
fn buffer_bytes(answer: &JsValue) -> Vec<u8> {
    answer
        .dyn_ref::<ArrayBuffer>()
        .map(|buffer| Uint8Array::new(buffer).to_vec())
        .unwrap_or_default()
}

/// The bound as the millisecond count a browser timer takes.
fn bound_ms(bound: Duration) -> i32 {
    i32::try_from(bound.as_millis()).unwrap_or(i32::MAX)
}

/// The transport's own failure, named by the operation that raised it.
fn refused(operation: &'static str, value: &JsValue) -> Failed {
    let message = value
        .dyn_ref::<DomException>()
        .map(|exception| format!("{}: {}", exception.name(), exception.message()))
        .or_else(|| value.as_string())
        .unwrap_or_else(|| format!("{value:?}"));
    HttpFailure::Transport(BrowserHttpError::Refused { operation, message })
}
