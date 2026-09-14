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
    BootIdentity, DB_ALIVE_LOCK, EXPORT_CHANNEL, HELLO_CHANNEL, IMPORT_CHANNEL, IntakeError,
    announce_tab, request_export, request_import,
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

/// A failure whose identity the caller does not know is ignored, so the wait expires instead.
#[wasm_bindgen_test]
async fn await_db_worker_ready_ignores_a_failure_with_foreign_identity() {
    let hello = "connetto-hello-foreign-failure";
    let channel = BroadcastChannel::new(hello).expect("hello channel");
    let sender = channel.clone();
    spawn_local(async move {
        crate::workers::sleep(core::time::Duration::from_millis(20)).await;
        let _ = sender.post_message(&JsValue::from_str("failed:foreign00000000:some-error"));
    });
    let error = crate::workers::intake::await_db_worker_ready_bounded(hello, &[], 300.0)
        .await
        .expect_err("deadline must expire");
    assert!(
        matches!(&error, IntakeError::Timeout { .. }),
        "expected Timeout, not a foreign failure: {error:?}"
    );
    channel.close();
}

/// A failure whose identity matches the one this caller was given is reported with its detail.
///
/// The assertion that would have failed before the fix: callers had to call
/// `err.as_string()` (a `JsValue` method) to inspect the failure; now `matches!`
/// on the enum variant suffices.
#[wasm_bindgen_test]
async fn await_db_worker_ready_reports_failure_for_own_identity() {
    let identity = BootIdentity::mint();
    let id_str = identity.to_string();
    let hello = "connetto-hello-own-failure";
    let channel = BroadcastChannel::new(hello).expect("hello channel");
    let sender = channel.clone();
    spawn_local(async move {
        crate::workers::sleep(core::time::Duration::from_millis(20)).await;
        let _ = sender.post_message(&JsValue::from_str(&format!(
            "failed:{id_str}:schema-mismatch"
        )));
    });
    let error = crate::workers::intake::await_db_worker_ready_bounded(hello, &[identity], 2_000.0)
        .await
        .expect_err("own-identity failure is reported");
    assert!(
        matches!(&error, IntakeError::BootFailed { detail } if detail.contains("schema-mismatch")),
        "expected BootFailed with the worker detail, got {error:?}"
    );
    channel.close();
}

/// An identity announced via `booting:` while waiting is learned and later matched against a
/// failure, so a follower tab fails fast for the boot that was announced.
#[wasm_bindgen_test]
async fn await_db_worker_ready_reports_failure_for_announced_identity() {
    let identity = BootIdentity::mint();
    let id_str = identity.to_string();
    let hello = "connetto-hello-announced-failure";
    let channel = BroadcastChannel::new(hello).expect("hello channel");
    let sender = channel.clone();
    spawn_local(async move {
        crate::workers::sleep(core::time::Duration::from_millis(20)).await;
        let _ = sender.post_message(&JsValue::from_str(&format!("booting:{id_str}")));
        crate::workers::sleep(core::time::Duration::from_millis(20)).await;
        let _ = sender.post_message(&JsValue::from_str(&format!(
            "failed:{id_str}:network-error"
        )));
    });
    let error = crate::workers::intake::await_db_worker_ready_bounded(hello, &[], 2_000.0)
        .await
        .expect_err("announced failure is reported");
    assert!(
        matches!(&error, IntakeError::BootFailed { detail } if detail.contains("network-error")),
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
    let error = crate::workers::intake::request_custody_bounded(300.0)
        .await
        .expect_err("no worker is running");
    let IntakeError::Timeout { deadline_ms } = error else {
        panic!("expected Timeout, got {error:?}")
    };
    assert!(
        (deadline_ms - 300.0).abs() < f64::EPSILON,
        "expected the deadline it was given, got {deadline_ms}"
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

/// A wait scoped to one boot ignores the failure of a boot spawned after it, because a caller
/// that named an identity asked about that one.
#[wasm_bindgen_test]
async fn a_wait_scoped_to_one_boot_ignores_a_later_spawn() {
    let older = super::boot::BootIdentity::mint();
    let newer = super::boot::BootIdentity::mint();
    let hello = "connetto-hello-scoped-wait";
    let announcer = crate::workers::intake::announce_boot_on(hello, &newer)
        .expect("the hello channel must open");
    spawn_local({
        let newer = newer.to_string();
        async move {
            crate::workers::sleep(core::time::Duration::from_millis(50)).await;
            if let Ok(sender) = BroadcastChannel::new(hello) {
                let _ =
                    sender.post_message(&JsValue::from_str(&format!("failed:{newer}:later-spawn")));
            }
        }
    });

    let error = crate::workers::intake::await_db_worker_ready_bounded(hello, &[older], 500.0)
        .await
        .expect_err("no worker reports readiness here");
    assert!(
        matches!(&error, IntakeError::Timeout { .. }),
        "the newer boot {newer}'s failure must not resolve this wait, got {error:?}"
    );
    drop(announcer);
}

/// A waiter that named nothing, in a context whose own boot is in flight, still refuses another
/// boot announced beside it.
#[wasm_bindgen_test]
async fn an_implicit_wait_refuses_another_boot_while_its_own_is_in_flight() {
    let mine = super::boot::BootIdentity::mint();
    crate::workers::intake::announce_current_boot(&mine);
    let other = super::boot::BootIdentity::mint().to_string();

    spawn_local(async move {
        crate::workers::sleep(core::time::Duration::from_millis(50)).await;
        if let Ok(sender) = BroadcastChannel::new(crate::workers::HELLO_CHANNEL) {
            let _ = sender.post_message(&JsValue::from_str(&format!("booting:{other}")));
            crate::workers::sleep(core::time::Duration::from_millis(50)).await;
            let _ = sender.post_message(&JsValue::from_str(&format!(
                "failed:{other}:someone-elses-boot"
            )));
        }
    });

    let error = crate::workers::intake::await_db_worker_ready_bounded(HELLO_CHANNEL, &[], 600.0)
        .await
        .expect_err("no worker reports readiness here");
    assert!(
        matches!(&error, IntakeError::Timeout { .. }),
        "another boot's failure must not resolve a wait for this context's boot, got {error:?}"
    );
}

/// A failure arriving in the same turn as readiness does not undo it, because a worker that
/// answered the wait booted.
#[wasm_bindgen_test]
async fn a_failure_after_readiness_does_not_undo_it() {
    let identity = BootIdentity::mint();
    let id_str = identity.to_string();
    // Readiness carries no identity, so it is spoken on a channel of this test's own rather
    // than on the one every other waiter in this context is listening to.
    let hello = "connetto-hello-terminal-readiness";
    spawn_local(async move {
        crate::workers::sleep(core::time::Duration::from_millis(20)).await;
        if let Ok(sender) = BroadcastChannel::new(hello) {
            let _ = sender.post_message(&JsValue::from_str("ready"));
            let _ = sender.post_message(&JsValue::from_str(&format!("failed:{id_str}:late-throw")));
        }
    });

    crate::workers::intake::await_db_worker_ready_bounded(hello, &[identity], 2_000.0)
        .await
        .expect("readiness stands even when the worker throws right after it");
}

/// A waiter never announces a boot, because a waiter can hold an identity whose boot has been
/// replaced and an announcement from it would silence the announcer of the boot that replaced it.
#[wasm_bindgen_test]
async fn a_waiter_does_not_announce_the_boot_it_holds() {
    let held = super::boot::BootIdentity::mint();
    let announcement = format!("booting:{held}");
    let heard = Rc::new(Cell::new(false));
    let hello = "connetto-hello-waiter-silence";
    let listener = BroadcastChannel::new(hello).expect("hello channel");
    let on_message = {
        let heard = Rc::clone(&heard);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if event.data().as_string().as_deref() == Some(announcement.as_str()) {
                heard.set(true);
            }
        })
    };
    listener.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

    spawn_local(async move {
        let _ = crate::workers::intake::await_db_worker_ready_bounded(hello, &[held], 600.0).await;
    });
    crate::workers::sleep(core::time::Duration::from_millis(100)).await;
    let _ = listener.post_message(&JsValue::from_str("ask"));
    crate::workers::sleep(core::time::Duration::from_millis(300)).await;

    assert!(
        !heard.get(),
        "a waiter must not answer an ask with the boot it holds"
    );
    listener.set_onmessage(None);
    listener.close();
    drop(on_message);
}

/// A worker that throws after it reported ready has not failed its boot, so a later wait is not
/// told that it did.
#[wasm_bindgen_test]
async fn an_error_after_ready_is_not_replayed_as_a_boot_failure() {
    let identity = super::boot::BootIdentity::mint();
    let hello = "connetto-hello-spent-announcer";
    let announcer = crate::workers::intake::announce_boot_on(hello, &identity)
        .expect("the hello channel must open");
    if let Ok(sender) = BroadcastChannel::new(hello) {
        let _ = sender.post_message(&JsValue::from_str(&format!("ready:{identity}")));
        let _ = sender.post_message(&JsValue::from_str(&format!("failed:{identity}:late-crash")));
    }
    crate::workers::sleep(core::time::Duration::from_millis(100)).await;

    let error = crate::workers::intake::await_db_worker_ready_bounded(hello, &[], 400.0)
        .await
        .expect_err("no worker answers this wait");
    assert!(
        matches!(&error, IntakeError::Timeout { .. }),
        "a completed boot must not be replayed as failed, got {error:?}"
    );
    drop(announcer);
}

/// A readiness that names another boot does not spend this one, because readiness carries no
/// identity for the waiters and an outgoing worker can answer after its replacement is announced.
#[wasm_bindgen_test]
async fn an_unscoped_readiness_does_not_spend_a_pending_boot() {
    let replacement = super::boot::BootIdentity::mint();
    let hello = "connetto-hello-outgoing-readiness";
    let announcer = crate::workers::intake::announce_boot_on(hello, &replacement)
        .expect("the hello channel must open");
    if let Ok(sender) = BroadcastChannel::new(hello) {
        // What the worker being replaced left on the channel.
        let _ = sender.post_message(&JsValue::from_str("ready"));
    }
    crate::workers::sleep(core::time::Duration::from_millis(50)).await;
    if let Ok(sender) = BroadcastChannel::new(hello) {
        let _ = sender.post_message(&JsValue::from_str(&format!(
            "failed:{replacement}:no-replacement"
        )));
    }
    crate::workers::sleep(core::time::Duration::from_millis(50)).await;

    let error = crate::workers::intake::await_db_worker_ready_bounded(hello, &[], 1_000.0)
        .await
        .expect_err("the replacement's failure must still be tellable");
    assert!(
        matches!(&error, IntakeError::BootFailed { detail } if detail.contains("no-replacement")),
        "expected the replacement's failure, got {error:?}"
    );
    drop(announcer);
}

/// A boot that failed before anyone started waiting still explains itself, because a reconnect
/// can begin after both the announcement and the failure have been broadcast.
#[wasm_bindgen_test]
async fn a_failure_broadcast_before_the_wait_is_replayed_to_it() {
    let identity = super::boot::BootIdentity::mint();
    let hello = "connetto-hello-replayed-failure";
    let announcer = crate::workers::intake::announce_boot_on(hello, &identity)
        .expect("the hello channel must open");
    if let Ok(sender) = BroadcastChannel::new(hello) {
        let _ = sender.post_message(&JsValue::from_str(&format!(
            "failed:{identity}:already-gone"
        )));
    }
    crate::workers::sleep(core::time::Duration::from_millis(100)).await;

    let error = crate::workers::intake::await_db_worker_ready_bounded(hello, &[], 2_000.0)
        .await
        .expect_err("a wait that starts after the failure must still learn of it");
    assert!(
        matches!(&error, IntakeError::BootFailed { detail } if detail.contains("already-gone")),
        "expected the failure to be replayed, got {error:?}"
    );
    drop(announcer);
}

/// A boot stays obtainable while it is in flight, so a waiter that joined after the announcement
/// gets it from the announcer rather than from another waiter.
#[wasm_bindgen_test]
async fn an_announcer_answers_a_waiter_that_joined_late() {
    let identity = super::boot::BootIdentity::mint();
    let id_str = identity.to_string();
    let hello = "connetto-hello-late-joiner";
    let announcer = crate::workers::intake::announce_boot_on(hello, &identity)
        .expect("the hello channel must open");

    spawn_local(async move {
        crate::workers::sleep(core::time::Duration::from_millis(300)).await;
        if let Ok(sender) = BroadcastChannel::new(hello) {
            let _ =
                sender.post_message(&JsValue::from_str(&format!("failed:{id_str}:late-joiner")));
        }
    });

    let error = crate::workers::intake::await_db_worker_ready_bounded(hello, &[], 3_000.0)
        .await
        .expect_err("the late joiner must act on the announced boot's failure");
    assert!(
        matches!(&error, IntakeError::BootFailed { detail } if detail.contains("late-joiner")),
        "expected the announcer to make the boot attributable, got {error:?}"
    );
    drop(announcer);
}

/// A waiter that knows the boot it is waiting for does not adopt another boot announced beside
/// it, because two boots can overlap while one worker replaces another.
#[wasm_bindgen_test]
async fn a_waiter_with_its_own_boot_ignores_another_announced_boot() {
    let mine = super::boot::BootIdentity::mint();
    let other = super::boot::BootIdentity::mint().to_string();
    let hello = "connetto-hello-own-boot-only";

    spawn_local(async move {
        crate::workers::sleep(core::time::Duration::from_millis(50)).await;
        if let Ok(sender) = BroadcastChannel::new(hello) {
            let _ = sender.post_message(&JsValue::from_str(&format!("booting:{other}")));
            crate::workers::sleep(core::time::Duration::from_millis(50)).await;
            let _ = sender.post_message(&JsValue::from_str(&format!(
                "failed:{other}:someone-elses-boot"
            )));
        }
    });

    let error = crate::workers::intake::await_db_worker_ready_bounded(hello, &[mine], 400.0)
        .await
        .expect_err("no worker reports readiness here");
    assert!(
        matches!(&error, IntakeError::Timeout { .. }),
        "another boot's failure must not be adopted, got {error:?}"
    );
}

/// A module that cannot be fetched fails before any Rust runs, and the spawning context
/// reports it, so a reconnect attempt handed no identity still learns why.
#[wasm_bindgen_test]
async fn a_worker_error_is_reported_by_the_context_that_spawned_it() {
    // An empty module loads, so the worker exists and carries the spawn's error listener
    // without the page also taking an uncaught module failure.
    let parts = js_sys::Array::of1(&JsValue::from_str("// nothing to boot\n"));
    let options = web_sys::BlobPropertyBag::new();
    options.set_type("text/javascript");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&parts, &options)
        .expect("the empty module blob");
    let module_url = web_sys::Url::create_object_url_with_blob(&blob).expect("the module URL");
    let (worker, _identity) =
        super::boot::spawn_db_worker(&module_url, &super::boot::WorkerBootstrap::Glue)
            .expect("spawning the worker must succeed");

    spawn_local({
        let worker = worker.clone();
        async move {
            crate::workers::sleep(core::time::Duration::from_millis(50)).await;
            let event = web_sys::ErrorEvent::new("error").expect("the error event");
            let _ = worker.dispatch_event(&event);
        }
    });

    let error = crate::workers::intake::await_db_worker_ready_bounded(HELLO_CHANNEL, &[], 2_000.0)
        .await
        .expect_err("a worker that raised an error must not report readiness");
    assert!(
        matches!(&error, IntakeError::BootFailed { .. }),
        "expected the failure to be attributed, got {error:?}"
    );
    worker.terminate();
    let _ = web_sys::Url::revoke_object_url(&module_url);
}

/// A boot parameter already on the worker URL is replaced, not duplicated, because the worker
/// reads the first value of the name.
#[wasm_bindgen_test]
fn boot_tagged_url_replaces_an_existing_boot_parameter() {
    let identity = super::boot::BootIdentity::mint();
    let tagged = super::boot::boot_tagged_url("./db-worker.js?boot=stale&keep=yes", &identity)
        .expect("a relative worker URL must be taggable");
    let url = web_sys::Url::new(&tagged).expect("the tagged URL must parse");
    let params = url.search_params();
    assert_eq!(
        params.get_all("boot").length(),
        1,
        "the boot parameter must appear once: {tagged}"
    );
    assert!(
        identity.matches_str(&params.get("boot").unwrap_or_default()),
        "the boot parameter must name this boot: {tagged}"
    );
    assert_eq!(
        params.get("keep").as_deref(),
        Some("yes"),
        "an unrelated parameter must survive: {tagged}"
    );
}

/// The generated bootstrap leaves its boot identity in a global, because a blob worker's own
/// location carries no query for it to read.
#[wasm_bindgen_test]
fn boot_generated_bootstrap_carries_its_identity() {
    let identity = super::boot::BootIdentity::mint();
    let source = super::boot::generated_bootstrap_source("./db-worker.js", &identity)
        .expect("a relative glue URL must produce a bootstrap source");
    assert!(
        source.contains(&format!("self.connettoBoot = \"{identity}\"")),
        "the source must carry the identity: {source}"
    );
}

/// The generated bootstrap module imports the glue by absolute URL, because a blob module
/// resolves a relative specifier against `blob:`.
#[wasm_bindgen_test]
fn boot_generated_bootstrap_imports_the_glue_by_absolute_url() {
    let identity = super::boot::BootIdentity::mint();
    let source = super::boot::generated_bootstrap_source("./db-worker.js", &identity)
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

/// The generated bootstrap source embeds the boot identity in the failure message, so a waiter
/// that holds the identity can match the failure rather than waiting out the deadline.
#[wasm_bindgen_test]
fn boot_generated_bootstrap_source_carries_the_boot_identity() {
    let identity = super::boot::BootIdentity::mint();
    let id_str = identity.to_string();
    let source = super::boot::generated_bootstrap_source("./db-worker.js", &identity)
        .expect("a relative glue URL must produce a bootstrap source");
    assert!(
        source.contains(&format!("\"failed:{id_str}:\" + err")),
        "the failure message must carry the boot identity: {source}"
    );
}
