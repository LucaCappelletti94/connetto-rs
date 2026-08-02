//! R12 part A browser acceptance: an event emitted through the facade reaches
//! the developer console at the console's own severity.
//!
//! A browser has no stdout, so the console is the destination, and nothing a
//! compile can check says an event actually got there. The console methods are
//! replaced for the duration of the test and the captured arguments are read
//! back, so this asserts the console specifically rather than only that the
//! formatter ran.

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::Closure;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// Replace one console method with a recorder and return the captured
/// arguments once `body` has run. The original is put back either way.
fn capture(method: &str, body: impl FnOnce()) -> Vec<String> {
    let console = js_sys::Reflect::get(&js_sys::global(), &"console".into())
        .expect("the global console")
        .unchecked_into::<js_sys::Object>();
    let key = wasm_bindgen::JsValue::from_str(method);
    let original = js_sys::Reflect::get(&console, &key).expect("the console method");

    let seen = js_sys::Array::new();
    let recorder = {
        let seen = seen.clone();
        Closure::<dyn FnMut(wasm_bindgen::JsValue)>::new(move |line: wasm_bindgen::JsValue| {
            seen.push(&line);
        })
    };
    js_sys::Reflect::set(&console, &key, recorder.as_ref()).expect("install the recorder");
    body();
    js_sys::Reflect::set(&console, &key, &original).expect("restore the console method");

    seen.iter()
        .map(|line| line.as_string().unwrap_or_default())
        .collect()
}

#[wasm_bindgen_test]
fn an_event_reaches_the_console_at_its_own_severity() {
    connetto_web::logging::init_console();

    let warned = capture("warn", || {
        tracing::warn!(tab = 7_u64, "relay hub closed a tab");
    });
    assert_eq!(warned.len(), 1, "one console line per event: {warned:?}");
    let line = &warned[0];
    assert!(
        line.contains("relay hub closed a tab"),
        "the message did not reach the console: {line}"
    );
    assert!(
        line.contains("tab=7"),
        "the event's named values did not reach the console: {line}"
    );
    assert!(
        line.contains("WARN"),
        "the level did not reach the console: {line}"
    );

    // Severity routing: the console's own filter and stack capture key off the
    // method, so an error must not arrive as a warning.
    let errored = capture("error", || {
        tracing::error!("relay hub ended");
    });
    assert_eq!(errored.len(), 1, "one console line per event: {errored:?}");
    assert!(
        errored[0].contains("relay hub ended"),
        "the error did not reach console.error: {}",
        errored[0]
    );
}

#[wasm_bindgen_test]
fn an_event_inside_a_span_carries_it_to_the_console() {
    connetto_web::logging::init_console();

    let logged = capture("info", || {
        let worker = tracing::info_span!("db_worker", replica = "orders.sqlite");
        worker.in_scope(|| tracing::info!("replica open"));
    });
    assert_eq!(logged.len(), 1, "one console line per event: {logged:?}");
    assert!(
        logged[0].contains("db_worker") && logged[0].contains("orders.sqlite"),
        "the enclosing context did not reach the console: {}",
        logged[0]
    );
}
