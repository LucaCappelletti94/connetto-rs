use std::cell::Cell;
use std::rc::Rc;

use connetto_client::{ExportScope, ImportOutcome};
use connetto_file_client::BrowserStore;
use connetto_file_core::{ChunkHash, ChunkStore};
use js_sys::{Date, Reflect};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{BroadcastChannel, DedicatedWorkerGlobalScope, File, MessageEvent};

use super::archive_channel::{
    decode_export_request, decode_import_request, export_generation_reply, export_reply_ok,
    import_generation_reply, import_reply_failed, import_reply_ok, is_import_generation_request,
};
use super::helpers::content_store_namespace;
use super::{
    DB_ALIVE_LOCK, EXPORT_CHANNEL, HELLO_CHANNEL, IMPORT_CHANNEL, IntakeError, announce_tab,
    await_db_worker_ready, request_custody, request_export, request_import,
};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
async fn one_seed_keeps_two_account_replicas_in_separate_content_namespaces() {
    let worker: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    let alice = content_store_namespace("shared-seed", "replica-alice");
    let bob = content_store_namespace("shared-seed", "replica-bob");
    let hash = ChunkHash::from_bytes([0x41; 32]);
    BrowserStore::remove(&worker, &alice)
        .await
        .expect("clear alice store");
    BrowserStore::remove(&worker, &bob)
        .await
        .expect("clear bob store");

    let alice_store = BrowserStore::install(&worker, &alice)
        .await
        .expect("open alice store");
    alice_store
        .write_chunk(&hash, b"alice content")
        .await
        .expect("stage alice content");
    let bob_store = BrowserStore::install(&worker, &bob)
        .await
        .expect("open bob store");

    assert_ne!(alice, bob);
    assert!(!bob_store.has_chunk(&hash).await.expect("probe bob store"));
    BrowserStore::remove(&worker, &alice)
        .await
        .expect("remove alice store");
    BrowserStore::remove(&worker, &bob)
        .await
        .expect("remove bob store");
}

#[wasm_bindgen_test]
async fn export_without_a_worker_follows_the_liveness_lock() {
    let started = Date::now();
    let error = request_export(ExportScope::Unsynced)
        .await
        .expect_err("no worker can answer");

    assert!(matches!(error, crate::relay::ExportRefused::Gone(_)));
    assert!(
        Date::now() - started < 1_000.0,
        "worker absence must not wait for an archive-size deadline"
    );
}

#[wasm_bindgen_test]
async fn an_export_wait_refuses_a_replacement_worker_generation() {
    let alive = crate::locks::hold_lock(DB_ALIVE_LOCK).await;
    let channel = BroadcastChannel::new(EXPORT_CHANNEL).expect("open export responder");
    let replaced = Rc::new(Cell::new(false));
    let on_message = {
        let channel = channel.clone();
        let replaced = Rc::clone(&replaced);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let kind = Reflect::get(&event.data(), &JsValue::from_str("kind"))
                .ok()
                .and_then(|value| value.as_string());
            match kind.as_deref() {
                Some("export?") => replaced.set(true),
                Some("generation?") => {
                    let generation = if replaced.get() {
                        "replacement-worker"
                    } else {
                        "original-worker"
                    };
                    let reply = export_generation_reply(generation).expect("generation reply");
                    channel.post_message(&reply).expect("answer generation");
                }
                _ => {}
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let started = Date::now();

    let error = request_export(ExportScope::Unsynced)
        .await
        .expect_err("replacement worker must not satisfy the old wait");

    assert!(
        replaced.get(),
        "the export request reached the original worker"
    );
    assert!(matches!(error, crate::relay::ExportRefused::Gone(_)));
    assert!(
        Date::now() - started < 1_000.0,
        "generation replacement must end the old wait promptly"
    );
    channel.set_onmessage(None);
    channel.close();
    drop(on_message);
    alive.release();
}

/// Two callers on one channel: each reply carries the request it answers, so
/// neither caller can be handed the other's archive.
#[wasm_bindgen_test]
async fn two_concurrent_exports_each_receive_their_own_archive() {
    let alive = crate::locks::hold_lock(DB_ALIVE_LOCK).await;
    let channel = BroadcastChannel::new(EXPORT_CHANNEL).expect("open export responder");
    let on_message = {
        let channel = channel.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let data = event.data();
            if Reflect::get(&data, &JsValue::from_str("kind"))
                .ok()
                .and_then(|value| value.as_string())
                .as_deref()
                == Some("generation?")
            {
                let reply = export_generation_reply("one-worker").expect("generation reply");
                channel.post_message(&reply).expect("answer generation");
                return;
            }
            let Some((tag, scope)) = decode_export_request(&data) else {
                return;
            };
            // The archive names the scope it was asked for, which is what makes
            // a crossed reply visible.
            let archive = match scope {
                ExportScope::Everything => b"everything".to_vec(),
                ExportScope::Unsynced => b"unsynced".to_vec(),
            };
            let reply = export_reply_ok(&tag, &archive).expect("export reply");
            channel.post_message(&reply).expect("answer export");
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

    let (everything, unsynced) = futures_util::future::join(
        request_export(ExportScope::Everything),
        request_export(ExportScope::Unsynced),
    )
    .await;

    assert_eq!(everything.expect("whole archive"), b"everything");
    assert_eq!(unsynced.expect("unsynced archive"), b"unsynced");
    channel.set_onmessage(None);
    channel.close();
    drop(on_message);
    alive.release();
}

/// Two callers on one channel: each reply is correlated by both generation
/// and request id, so neither caller receives the other's outcome.
///
/// Caller A sends a file whose first byte is `A` (success, 3 `rows_restored`).
/// Caller B sends a file whose first byte is `B` (failure). A swap would
/// cause A to receive a failure and B to receive a success: the per-caller
/// assertions catch it. Before per-request tag correlation, both callers
/// accepted the first broadcast reply and both returned `Ok`.
#[wasm_bindgen_test]
async fn two_concurrent_imports_each_receive_their_own_outcome() {
    let alive = crate::locks::hold_lock(DB_ALIVE_LOCK).await;
    let channel = BroadcastChannel::new(IMPORT_CHANNEL).expect("open import responder");
    let on_message = {
        let channel = channel.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let data = event.data();
            if is_import_generation_request(&data) {
                let reply = import_generation_reply("gen-1").expect("build gen reply");
                channel.post_message(&reply).expect("post gen reply");
                return;
            }
            let Some((tag, file)) = decode_import_request(&data) else {
                return;
            };
            let channel = channel.clone();
            spawn_local(async move {
                let buffer = JsFuture::from(file.array_buffer())
                    .await
                    .expect("read file buffer");
                let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
                let reply = if bytes.first() == Some(&b'A') {
                    import_reply_ok(
                        &tag,
                        &ImportOutcome {
                            rows_restored: 3,
                            rows_kept: 0,
                            writes_restored: 0,
                        },
                        0,
                    )
                } else {
                    import_reply_failed(&tag, "file B rejected intentionally")
                };
                channel
                    .post_message(&reply.expect("build import reply"))
                    .expect("post reply");
            });
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

    let make_file = |content: &str| {
        let arr = js_sys::Array::new();
        arr.push(&JsValue::from_str(content));
        File::new_with_str_sequence(&arr, "test.zip").expect("create file")
    };

    let (result_a, result_b) = futures_util::future::join(
        request_import(make_file("A-file content")),
        request_import(make_file("B-file content")),
    )
    .await;

    assert!(
        matches!(
            result_a,
            Ok((
                ImportOutcome {
                    rows_restored: 3,
                    ..
                },
                0
            ))
        ),
        "caller A expected success, got {result_a:?}"
    );
    assert!(
        matches!(result_b, Err(crate::relay::ImportRefused::Failed(_))),
        "caller B expected failure, got {result_b:?}"
    );
    channel.set_onmessage(None);
    channel.close();
    drop(on_message);
    alive.release();
}

/// An import wait ends with `Gone` when the answering worker is replaced by a
/// new generation rather than polling until the alive lock drops.
///
/// The assertion that would have failed before the fix:
/// `matches!(result, Err(ImportRefused::Gone(_)))` — the caller polled
/// indefinitely because the import channel does not replay the request to the
/// replacement worker and there was no generation check to break the loop.
#[wasm_bindgen_test]
async fn import_wait_ends_when_worker_generation_is_replaced() {
    let alive = crate::locks::hold_lock(DB_ALIVE_LOCK).await;
    let channel = BroadcastChannel::new(IMPORT_CHANNEL).expect("open import responder");
    // Phase 0: first gen request -> "gen-1"; phase 1+: -> "gen-2"
    let gen_phase: Rc<Cell<u32>> = Rc::new(Cell::new(0));
    let on_message = {
        let channel = channel.clone();
        let gen_phase = Rc::clone(&gen_phase);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if !is_import_generation_request(&event.data()) {
                return;
            }
            let phase = gen_phase.get();
            gen_phase.set(phase + 1);
            let generation_name = if phase == 0 { "gen-1" } else { "gen-2" };
            let reply = import_generation_reply(generation_name).expect("build gen reply");
            channel.post_message(&reply).expect("post gen reply");
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

    let content = js_sys::Array::new();
    content.push(&JsValue::from_str("x"));
    let file = File::new_with_str_sequence(&content, "test.zip").expect("create test file");
    let result = request_import(file).await;

    assert!(
        matches!(result, Err(crate::relay::ImportRefused::Gone(_))),
        "expected Gone when generation replaced, got {result:?}"
    );
    channel.set_onmessage(None);
    channel.close();
    drop(on_message);
    alive.release();
}

/// A boot-failure message on the hello channel causes `await_db_worker_ready` to return
/// the typed `BootFailed` variant, not an opaque `JsValue`.
///
/// The assertion that would have failed before the fix: callers had to call
/// `err.as_string()` (a `JsValue` method) to inspect the failure; now `matches!`
/// on the enum variant suffices.
#[wasm_bindgen_test]
async fn await_db_worker_ready_reports_boot_failure_as_typed_error() {
    let channel = BroadcastChannel::new(HELLO_CHANNEL).expect("hello channel");
    let sender = channel.clone();
    spawn_local(async move {
        crate::workers::sleep(core::time::Duration::from_millis(20)).await;
        let _ = sender.post_message(&JsValue::from_str("failed:schema-mismatch"));
    });
    let error = await_db_worker_ready()
        .await
        .expect_err("boot failure is reported");
    assert!(
        matches!(&error, IntakeError::BootFailed { detail } if detail.contains("schema-mismatch")),
        "expected BootFailed with the worker detail, got {error:?}"
    );
    channel.close();
}

/// A mock worker that acknowledges the wire causes `announce_tab` to return `Ok(())`.
///
/// The typed `Result<(), IntakeError>` return makes this success case matchable; before
/// the fix the return was `Result<(), JsValue>`, so the caller had to treat errors as
/// opaque strings.
#[wasm_bindgen_test]
async fn announce_tab_returns_ok_when_worker_acknowledges() {
    let channel = BroadcastChannel::new(HELLO_CHANNEL).expect("hello channel");
    let wire = "mock-wire-ack-test";
    let replier = channel.clone();
    let on_message = {
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if event.data().as_string().as_deref() == Some(&format!("tab:{wire}")) {
                let _ = replier.post_message(&JsValue::from_str(&format!("attached:{wire}")));
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    announce_tab(wire)
        .await
        .expect("mock worker acknowledged the tab wire");
    channel.set_onmessage(None);
    channel.close();
    drop(on_message);
}

/// Without a running worker, `request_custody` returns the typed timeout variant.
///
/// The assertion that would have failed before the fix:
/// `matches!(error, IntakeError::Timeout { .. })` — previously the function returned
/// `Result<_, JsValue>`.
#[wasm_bindgen_test]
async fn request_custody_without_worker_returns_timeout() {
    let error = request_custody().await.expect_err("no worker is running");
    assert!(
        matches!(
            error,
            IntakeError::Timeout {
                deadline_ms: 15_000
            }
        ),
        "expected Timeout {{deadline_ms: 15_000}}, got {error:?}"
    );
}

/// A relative glue URL resolves against the current location rather than failing to parse.
#[wasm_bindgen_test]
fn boot_spawn_db_worker_relative_glue_url_resolves_against_current_location() {
    let result =
        super::boot::spawn_db_worker("./db-worker.js", &super::boot::WorkerBootstrap::Generated);
    assert!(
        !matches!(result, Err(super::boot::BootError::BootstrapUrl(_))),
        "a relative glue URL must resolve against the current location"
    );
}

/// The generated bootstrap module imports the glue by absolute URL, because a blob module
/// resolves a relative specifier against `blob:`.
#[wasm_bindgen_test]
fn boot_generated_bootstrap_imports_the_glue_by_absolute_url() {
    let source = super::boot::generated_bootstrap_source("./db-worker.js")
        .expect("a relative glue URL must produce a bootstrap source");
    assert!(
        !source.contains("\"./db-worker.js\""),
        "the import specifier must not stay relative: {source}"
    );
    assert!(
        source.contains("await import(\"http"),
        "the import specifier must be absolute: {source}"
    );
}
