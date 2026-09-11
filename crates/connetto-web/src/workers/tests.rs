use std::cell::Cell;
use std::rc::Rc;

use connetto_client::ExportScope;
use connetto_file_client::BrowserStore;
use connetto_file_core::{ChunkHash, ChunkStore};
use js_sys::{Date, Reflect};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{BroadcastChannel, DedicatedWorkerGlobalScope, MessageEvent};

use super::{
    DB_ALIVE_LOCK, EXPORT_CHANNEL, content_store_namespace, export_generation_reply, request_export,
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
