use std::cell::Cell;
use std::rc::Rc;

use connetto_client::{ExportScope, ImportOutcome};
use connetto_file_client::BrowserStore;
use connetto_file_core::{ChunkHash, ChunkStore};
use js_sys::{Date, Reflect};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{BroadcastChannel, DedicatedWorkerGlobalScope, File, MessageEvent};

use super::archive_channel::{
    decode_export_request, decode_import_request, export_generation_reply, export_reply_ok,
    import_reply_failed, import_reply_ok,
};
use super::helpers::content_store_namespace;
use super::{DB_ALIVE_LOCK, EXPORT_CHANNEL, IMPORT_CHANNEL, request_export, request_import};

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

/// Two callers on one channel: each reply carries the request it answers, so
/// neither caller can be handed the other's outcome.
///
/// Without tag correlation the assertion `successes == [true, false] || ...`
/// fails because both callers accept the first reply broadcast, giving `[true, true]`.
#[wasm_bindgen_test]
async fn two_concurrent_imports_each_receive_their_own_outcome() {
    let alive = crate::locks::hold_lock(DB_ALIVE_LOCK).await;
    let channel = BroadcastChannel::new(IMPORT_CHANNEL).expect("open import responder");
    let counter = Rc::new(Cell::new(0u32));
    let on_message = {
        let channel = channel.clone();
        let counter = Rc::clone(&counter);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some((tag, _file)) = decode_import_request(&event.data()) else {
                return;
            };
            let n = counter.get();
            counter.set(n + 1);
            let reply = if n == 0 {
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
                import_reply_failed(&tag, "second import intentionally failed")
            };
            channel
                .post_message(&reply.expect("build import reply"))
                .expect("post reply");
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

    let make_file = || {
        let content = js_sys::Array::new();
        content.push(&JsValue::from_str("x"));
        File::new_with_str_sequence(&content, "test.zip").expect("create test file")
    };

    let (first, second) =
        futures_util::future::join(request_import(make_file()), request_import(make_file())).await;

    // Exactly one caller must succeed and one must fail; without per-request tag
    // correlation both handlers fire on the first reply and both return Ok.
    let successes = [first.is_ok(), second.is_ok()];
    assert!(
        successes == [true, false] || successes == [false, true],
        "exactly one import must succeed and one must fail; got first={first:?} second={second:?}"
    );
    channel.set_onmessage(None);
    channel.close();
    drop(on_message);
    alive.release();
}
