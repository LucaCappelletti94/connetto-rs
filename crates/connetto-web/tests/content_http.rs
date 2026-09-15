//! Browser content HTTP request contracts and the idle bound they run under.
//!
//! Every bound here is injected small, a few hundred milliseconds in place of
//! the shipped thirty seconds, because the runner allows about twenty seconds
//! per test and drives the whole suite concurrently in one page.
//!
//! `fetch` and `XMLHttpRequest` are both replaced on the worker global, so a
//! test decides exactly when a byte moves and when nothing does.

use core::cell::RefCell;
use core::time::Duration;
use std::rc::Rc;

use connetto_file_client::{BrowserHttp, ContentHttp, HttpFailure};
use js_sys::{Function, Promise, Reflect, Uint8Array};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, future_to_promise};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{Request, RequestRedirect, Response};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The bound every test here injects.
const BOUND: Duration = Duration::from_millis(200);

/// A transport under the test bound.
fn transport() -> BrowserHttp {
    BrowserHttp::new().with_idle_bound(BOUND)
}

#[derive(Debug, PartialEq, Eq)]
struct SeenRequest {
    method: String,
    url: String,
    content_type: Option<String>,
    range: Option<String>,
    body: Vec<u8>,
}

/// Every `fetch` shape the protocol uses reaches the network as itself.
#[wasm_bindgen_test]
async fn fetch_transport_builds_every_content_request_shape() {
    let (seen, fetch) = install_recording_fetch();
    exercise_fetch_shapes().await;
    drop(fetch);
    assert_eq!(*seen.borrow(), expected_requests());
}

/// A reply that stops arriving aborts after the bound, and names the silence.
#[wasm_bindgen_test]
async fn a_stalled_reply_aborts_after_the_bound() {
    let fetch = install_stalling_fetch();

    let failure = transport()
        .get("https://content.invalid/files/ab?t=TOKEN", None)
        .await
        .map(|reply| reply.status)
        .expect_err("a stalled reply aborts");

    drop(fetch);
    assert!(
        failure.to_string().contains("no byte moved"),
        "the failure names the silence, got {failure}"
    );
}

/// A reply that keeps arriving in chunks is never aborted, however long it
/// takes in total.
#[wasm_bindgen_test]
async fn a_trickling_reply_is_never_aborted() {
    let chunks = 8;
    let fetch = install_trickling_fetch(chunks, BOUND / 4);

    let reply = transport()
        .get("https://content.invalid/files/ab?t=TOKEN", None)
        .await
        .expect("a moving reply is never aborted");

    drop(fetch);
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.body.len(),
        chunks,
        "every chunk the reply trickled is collected"
    );
}

/// An opaque reply is what the `manual` redirect mode answers with, and it is
/// the refusal, not a transport failure that would be retried.
#[wasm_bindgen_test]
async fn an_opaque_redirect_is_refused() {
    let fetch = install_opaque_redirect_fetch();

    let failure = transport()
        .get("https://content.invalid/files/ab?t=TOKEN", None)
        .await
        .map(|reply| reply.status)
        .expect_err("an opaque reply is a refusal");

    drop(fetch);
    assert!(
        matches!(failure, HttpFailure::Redirected { origin: None }),
        "a refused hop names no origin because nothing landed, got {failure}"
    );
}

/// A chunk `PUT` goes out through `XMLHttpRequest`, whose upload progress is
/// what keeps the bound from elapsing while a large body is still going out.
#[wasm_bindgen_test]
async fn a_chunk_upload_reports_progress_and_is_never_aborted() {
    let xhr = install_scripted_xhr(
        r#"{ status: 204, responseURL: "https://content.invalid/chunks/ab?t=TOKEN",
             uploadTicks: 6, tickMs: 50, response: new ArrayBuffer(0) }"#,
    );

    let reply = transport()
        .put(
            "https://content.invalid/chunks/ab?t=TOKEN",
            vec![7_u8; 4096],
        )
        .await
        .expect("an upload reporting progress is never aborted");

    drop(xhr);
    assert_eq!(reply.status, 204, "the server answered the chunk");
}

/// An upload that stops reporting progress aborts after the bound.
#[wasm_bindgen_test]
async fn a_stalled_chunk_upload_aborts_after_the_bound() {
    let xhr = install_scripted_xhr(
        r#"{ status: 204, responseURL: "https://content.invalid/chunks/ab?t=TOKEN",
             uploadTicks: 1, tickMs: 10, stall: true, response: new ArrayBuffer(0) }"#,
    );

    let failure = transport()
        .put(
            "https://content.invalid/chunks/ab?t=TOKEN",
            vec![7_u8; 4096],
        )
        .await
        .map(|reply| reply.status)
        .expect_err("a stalled upload aborts");

    drop(xhr);
    assert!(
        failure.to_string().contains("no byte moved"),
        "the failure names the silence, got {failure}"
    );
}

/// `XMLHttpRequest` follows every redirect with no way to refuse, so a reply
/// that landed on another address is refused by the address it landed on.
#[wasm_bindgen_test]
async fn an_upload_that_landed_elsewhere_is_refused() {
    let xhr = install_scripted_xhr(
        r#"{ status: 200, responseURL: "https://elsewhere.invalid/chunks/ab?t=TOKEN",
             uploadTicks: 2, tickMs: 10, response: new ArrayBuffer(0) }"#,
    );

    let failure = transport()
        .put(
            "https://content.invalid/chunks/ab?t=TOKEN",
            vec![7_u8; 1024],
        )
        .await
        .map(|reply| reply.status)
        .expect_err("a reply from another address is refused");

    drop(xhr);
    match failure {
        HttpFailure::Redirected { origin } => assert_eq!(
            origin.as_deref(),
            Some("https://elsewhere.invalid"),
            "the refusal names the origin the reply landed on"
        ),
        other @ HttpFailure::Transport(_) => {
            panic!("a followed hop must be refused, got {other}")
        }
    }
}

/// A global replaced for the duration of one test, restored on drop.
struct Replaced {
    global: js_sys::Object,
    key: JsValue,
    previous: JsValue,
    _closure: Option<Closure<dyn FnMut(JsValue) -> Promise>>,
}

impl Drop for Replaced {
    fn drop(&mut self) {
        let _ = Reflect::set(&self.global, &self.key, &self.previous);
    }
}

/// Installs `closure` as the worker's `fetch`.
fn install_fetch(closure: Closure<dyn FnMut(JsValue) -> Promise>) -> Replaced {
    let global = js_sys::global();
    let key = JsValue::from_str("fetch");
    let previous = Reflect::get(&global, &key).expect("read fetch");
    Reflect::set(&global, &key, closure.as_ref()).expect("replace fetch");
    Replaced {
        global,
        key,
        previous,
        _closure: Some(closure),
    }
}

fn install_recording_fetch() -> (Rc<RefCell<Vec<SeenRequest>>>, Replaced) {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let captured = Rc::clone(&seen);
    let closure = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |value: JsValue| {
        let request = value
            .dyn_into::<Request>()
            .expect("fetch receives a request");
        assert_eq!(
            request.redirect(),
            RequestRedirect::Manual,
            "a hop must arrive as an opaque reply rather than as a rejection"
        );
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
    (Rc::clone(&seen), install_fetch(closure))
}

/// A `fetch` that answers nothing at all, so only the bound ends the request.
fn install_stalling_fetch() -> Replaced {
    install_fetch(Closure::<dyn FnMut(JsValue) -> Promise>::new(
        move |value: JsValue| {
            let request = value
                .dyn_into::<Request>()
                .expect("fetch receives a request");
            reject_on_abort(&request)
        },
    ))
}

/// A `fetch` whose reply body arrives in `chunks` one byte pieces, `gap` apart.
fn install_trickling_fetch(chunks: usize, gap: Duration) -> Replaced {
    let gap_ms = i32::try_from(gap.as_millis()).unwrap_or(i32::MAX);
    let source = format!(
        "(request) => {{
            let sent = 0;
            const stream = new ReadableStream({{
                pull(controller) {{
                    return new Promise((resolve) => setTimeout(() => {{
                        if (sent === {chunks}) {{
                            controller.close();
                        }} else {{
                            controller.enqueue(new Uint8Array([sent & 0xff]));
                            sent += 1;
                        }}
                        resolve();
                    }}, {gap_ms}));
                }},
            }});
            return Promise.resolve(new Response(stream, {{ status: 200 }}));
        }}"
    );
    install_evaluated_fetch(&source)
}

/// A `fetch` that answers the opaque reply the `manual` mode gives a hop.
///
/// An opaque reply cannot be constructed, so its observable shape is what the
/// transport reads, the reply type, with the target hidden.
fn install_opaque_redirect_fetch() -> Replaced {
    install_evaluated_fetch(
        "(() => {
            const reply = new Response(null, { status: 200 });
            Object.defineProperty(reply, 'type', { value: 'opaqueredirect' });
            return () => Promise.resolve(reply);
        })()",
    )
}

/// Installs a `fetch` written in script, for the shapes `web_sys` cannot
/// build from Rust.
fn install_evaluated_fetch(source: &str) -> Replaced {
    let replacement = js_sys::eval(source).expect("evaluate the fetch replacement");
    let global = js_sys::global();
    let key = JsValue::from_str("fetch");
    let previous = Reflect::get(&global, &key).expect("read fetch");
    Reflect::set(&global, &key, &replacement).expect("replace fetch");
    Replaced {
        global,
        key,
        previous,
        _closure: None,
    }
}

/// Installs an `XMLHttpRequest` that follows `script`, an object naming the
/// status, the address the reply landed on, how many upload progress events
/// to report and how far apart, and whether to then go silent.
fn install_scripted_xhr(script: &str) -> Replaced {
    let source = format!(
        "(() => {{
            const script = {script};
            return class ScriptedRequest {{
                constructor() {{
                    this.upload = {{}};
                    this.status = 0;
                    this.responseURL = '';
                    this.response = null;
                }}
                open(method, url) {{
                    this.method = method;
                    this.url = url;
                }}
                setRequestHeader() {{}}
                abort() {{
                    this.aborted = true;
                    if (this.onabort) {{ this.onabort(); }}
                }}
                send() {{
                    let tick = 0;
                    const step = () => {{
                        if (this.aborted) {{ return; }}
                        if (tick < script.uploadTicks) {{
                            tick += 1;
                            if (this.upload.onprogress) {{ this.upload.onprogress(); }}
                            setTimeout(step, script.tickMs);
                            return;
                        }}
                        if (script.stall) {{ return; }}
                        this.status = script.status;
                        this.responseURL = script.responseURL;
                        this.response = script.response;
                        if (this.onload) {{ this.onload(); }}
                    }};
                    setTimeout(step, script.tickMs);
                }}
            }};
        }})()"
    );
    let replacement = js_sys::eval(&source).expect("evaluate the request replacement");
    let global = js_sys::global();
    let key = JsValue::from_str("XMLHttpRequest");
    let previous = Reflect::get(&global, &key).expect("read XMLHttpRequest");
    Reflect::set(&global, &key, &replacement).expect("replace XMLHttpRequest");
    Replaced {
        global,
        key,
        previous,
        _closure: None,
    }
}

/// A promise that settles only when the request is aborted, which is what a
/// stalled `fetch` looks like to the transport.
fn reject_on_abort(request: &Request) -> Promise {
    let signal = request.signal();
    Promise::new(&mut move |_resolve, reject| {
        let abort = Closure::<dyn FnMut()>::once(move || {
            let _ = reject.call1(&JsValue::UNDEFINED, &JsValue::from_str("aborted"));
        });
        let handler: &Function = abort.as_ref().unchecked_ref();
        Reflect::set(signal.as_ref(), &JsValue::from_str("onabort"), handler)
            .expect("observe the abort");
        abort.forget();
    })
}

async fn exercise_fetch_shapes() {
    let http = BrowserHttp::new();
    let replies = [
        http.post(
            "https://content.invalid/files/ab/intent?t=TOKEN",
            Some(br#"{"total_len":12}"#.to_vec()),
        )
        .await,
        http.post("https://content.invalid/files/ab/commit?t=TOKEN", None)
            .await,
        http.get("https://content.invalid/files/ab?t=TOKEN", None)
            .await,
        http.get("https://content.invalid/files/ab?t=TOKEN", Some((11, 29)))
            .await,
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
            url: "https://content.invalid/files/ab/intent?t=TOKEN".to_owned(),
            content_type: Some("application/json".to_owned()),
            range: None,
            body: br#"{"total_len":12}"#.to_vec(),
        },
        SeenRequest {
            method: "POST".to_owned(),
            url: "https://content.invalid/files/ab/commit?t=TOKEN".to_owned(),
            content_type: None,
            range: None,
            body: Vec::new(),
        },
        SeenRequest {
            method: "GET".to_owned(),
            url: "https://content.invalid/files/ab?t=TOKEN".to_owned(),
            content_type: None,
            range: None,
            body: Vec::new(),
        },
        SeenRequest {
            method: "GET".to_owned(),
            url: "https://content.invalid/files/ab?t=TOKEN".to_owned(),
            content_type: None,
            range: Some("bytes=11-29".to_owned()),
            body: Vec::new(),
        },
    ]
}
