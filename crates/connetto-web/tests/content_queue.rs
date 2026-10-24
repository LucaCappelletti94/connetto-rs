//! The tab's queue reads and actions over the real content lane. A refused
//! upload is listed with its detail and retried once the server accepts it,
//! and a retired file is listed and forgotten, all through a tab rather than
//! the hub directly.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use connetto_file_client::BrowserStore;
use connetto_file_core::{ChunkHash, ChunkInventory, ChunkStore};
use connetto_web::workers::DB_ALIVE_LOCK;
use connetto_web::{TabContent, TabResolved, locks};
use js_sys::Uint8Array;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::MessagePort;

#[expect(
    dead_code,
    reason = "the fixture is shared with the archive suite, whose tests use helpers this one does not call"
)]
#[path = "content_archive/support.rs"]
mod support;

#[expect(
    dead_code,
    reason = "the fixture is shared with the relay suite, whose tests use ticket answers this one does not"
)]
#[path = "content_relay/fixture.rs"]
mod fixture;

use fixture::{
    Tickets, blob_of, captured_insert, declared_id, relay_tab, send_mutation, stage, uploads_of,
};
use support::{
    Replaced, install_fetch, intent_answer, replace_content_upload, response, response_with,
    timeout_ms, until,
};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const TEST_LOCK: &str = "connetto-content-queue-test";

/// Distinct bytes per test: a relay a finished test left running keeps driving
/// its own outbox against whatever `fetch` the current test installed.
const REFUSED_PHOTO: &[u8] = b"a photograph the file server turns away on storage quota";
const LOST_PHOTO: &[u8] = b"a photograph whose stored bytes the test lets go";
const PINNED_PHOTO: &[u8] = b"a photograph a pin keeps after its stored bytes are lost";
const TIDY_KEPT: &[u8] = b"a photograph a pin keeps when storage is tidied";
const TIDY_FREED: &[u8] = b"a photograph no pin keeps, so tidying frees it";
const TIDY_SACRIFICE: &[u8] = b"a photograph the sweep frees so the test sees it settle";

/// A `fetch` answering the upload intent like the file server does and the
/// commit with the status the test holds in a cell.
fn status_fetch(status: &Rc<Cell<u16>>) -> Replaced {
    let status = Rc::clone(status);
    install_fetch(move |request, body| {
        let status = status.get();
        async move {
            if request.url().contains("/intent?") {
                intent_answer(&body)
            } else {
                response(None, status)
            }
        }
    })
}

/// The same `fetch` with every commit accepted, letting the named chunk go on
/// each intent answer, before the upload reads it.
fn losing_fetch(store: BrowserStore, chunk: &'static [u8]) -> Replaced {
    install_fetch(move |request, body| {
        let store = store.clone();
        async move {
            if request.url().contains("/intent?") {
                let _ = store.delete_chunk(&ChunkHash::from_data(chunk)).await;
                intent_answer(&body)
            } else {
                response(None, 200)
            }
        }
    })
}

/// A `fetch` answering the upload intent like the file server does and every
/// other request, the commit and every granted read URL, with the served
/// bytes.
fn serving_fetch(served: &'static [u8]) -> Replaced {
    install_fetch(move |_request, body| async move {
        if body.is_empty() {
            response_with(Some(Uint8Array::from(served).into()), 200)
        } else {
            intent_answer(&body)
        }
    })
}

/// A `fetch` answering the upload intent like the file server does and
/// every commit with `200`, counting the commits so a test can wait for the
/// outbox to drain.
fn commit_fetch(commits: &Rc<Cell<u32>>) -> Replaced {
    let commits = Rc::clone(commits);
    install_fetch(move |_request, body| {
        let commits = Rc::clone(&commits);
        async move {
            if body.is_empty() {
                commits.set(commits.get() + 1);
                response(None, 200)
            } else {
                intent_answer(&body)
            }
        }
    })
}

/// The file server turns the commit away on quota, the tab lists the refusal
/// with its detail, and once the refusal is cleared and the server accepts,
/// the next walk uploads the very bytes it refused.
#[wasm_bindgen_test]
async fn a_refused_upload_is_listed_then_retried() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let status = Rc::new(Cell::new(507u16));
    let _fetch = status_fetch(&status);
    let _upload = replace_content_upload(&uploaded, None);
    let (_hub, mutations, mut tab, _answers, _store) =
        relay_tab("r69d-refused", [21; 32], Tickets::Grants).await;
    let content = TabContent::<MessagePort>::new(&mut tab);
    let file_id = declared_id(REFUSED_PHOTO);
    stage(&tab, file_id, &blob_of(REFUSED_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(1, file_id.as_bytes())).await;
    assert!(
        until(async || mutations.get() == 1).await,
        "the row commits"
    );
    assert!(
        until(async || {
            content.refused_content().await.is_ok_and(|refused| {
                refused
                    .iter()
                    .any(|(id, detail)| *id == file_id && detail.contains("507"))
            })
        })
        .await,
        "the walk must record the quota refusal for the tab to list"
    );
    let refused = content
        .refused_content()
        .await
        .expect("list the refused uploads");
    assert_eq!(
        refused.iter().filter(|(id, _)| *id == file_id).count(),
        1,
        "the refusal lists the file once, got {refused:?}"
    );
    status.set(200);
    content
        .retry_refused(file_id)
        .await
        .expect("retry the refused upload");
    assert!(
        until(async || uploads_of(&uploaded, REFUSED_PHOTO) == 2).await,
        "the cleared entry must be walked again and its bytes uploaded"
    );
    assert!(
        until(async || {
            content
                .refused_content()
                .await
                .is_ok_and(|refused| refused.is_empty())
        })
        .await,
        "a retried upload leaves no refusal listed"
    );
    serial.release();
}

/// The attempt's own intent answer lets the staged bytes go before its chunk read.
#[wasm_bindgen_test]
async fn a_retired_file_is_listed_then_forgotten() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let _upload = replace_content_upload(&uploaded, None);
    let (_hub, mutations, mut tab, _answers, store) =
        relay_tab("r69d-retired", [22; 32], Tickets::Grants).await;
    let _fetch = losing_fetch(store.clone(), LOST_PHOTO);
    let content = TabContent::<MessagePort>::new(&mut tab);
    let file_id = declared_id(LOST_PHOTO);
    stage(&tab, file_id, &blob_of(LOST_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(1, file_id.as_bytes())).await;
    assert!(
        until(async || mutations.get() == 1).await,
        "the row commits"
    );
    assert!(
        until(async || {
            content
                .retired_content()
                .await
                .is_ok_and(|retired| retired == vec![file_id])
        })
        .await,
        "the outbox attempt must retire the unreadable file for the tab to list"
    );
    content
        .forget_retired_content(&[file_id])
        .await
        .expect("forget the lost bytes");
    assert!(
        until(async || {
            content
                .retired_content()
                .await
                .is_ok_and(|retired| retired.is_empty())
        })
        .await,
        "a forgotten loss leaves nothing retired"
    );
    serial.release();
}

/// The stored bytes of a pinned file are lost after the upload, and
/// `fetch_pinned` restores them from the server: the tab lists the file it
/// restored and the bytes then resolve locally from the fetched chunks.
#[wasm_bindgen_test]
async fn a_pinned_file_with_lost_bytes_is_fetched() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let _upload = replace_content_upload(&uploaded, None);
    let _fetch = serving_fetch(PINNED_PHOTO);
    let (_hub, _mutations, mut tab, _answers, store) =
        relay_tab("r69d-fetched", [23; 32], Tickets::Grants).await;
    let content = TabContent::<MessagePort>::new(&mut tab);
    let file_id = declared_id(PINNED_PHOTO);
    stage(&tab, file_id, &blob_of(PINNED_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(1, file_id.as_bytes())).await;
    assert!(
        until(async || uploads_of(&uploaded, PINNED_PHOTO) == 1).await,
        "the walk must upload the staged file"
    );
    content
        .pin_content("photos-pin", "SELECT content_id FROM photos", "content_id")
        .await
        .expect("pin the photo");
    let chunk = ChunkHash::from_data(PINNED_PHOTO);
    // The store may still be settling the chunk the upload just read, so the
    // drop retries until the store accepts it.
    assert!(
        until(async || store.delete_chunk(&chunk).await.is_ok()).await,
        "the stored chunk must go"
    );
    let arrived = tokio::select! {
        arrived = content.fetch_pinned() => arrived.expect("fetch the pinned file"),
        () = timeout_ms(2_000) => panic!("fetch_pinned never answered"),
    };
    assert_eq!(
        arrived,
        vec![file_id],
        "the fetch answers the file it restored"
    );
    let resolved = tokio::select! {
        resolved = content.resolve(file_id) => resolved,
        () = timeout_ms(2_000) => panic!("the resolve never answered"),
    };
    assert!(
        matches!(resolved, TabResolved::Local { .. }),
        "the fetched bytes resolve locally, got {resolved:?}"
    );
    assert!(
        store
            .stored_hashes()
            .await
            .expect("list the store")
            .contains(&chunk),
        "the fetch restored the chunk to the store"
    );
    serial.release();
}

/// Three uploaded files, two pinned at first: the hub's retention sweep frees the
/// unpinned one while the pins hold, which is how the test observes the sweep settling;
/// then the freed photo's pin goes and `tidy` releases that file's records and chunks
/// while the pinned file's bytes stay, and the freed file still resolves from the server.
#[wasm_bindgen_test]
async fn tidy_frees_unpinned_bytes_and_keeps_pinned() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let _upload = replace_content_upload(&uploaded, None);
    let commits = Rc::new(Cell::new(0u32));
    let _fetch = commit_fetch(&commits);
    let (_hub, _mutations, mut tab, _answers, store) =
        relay_tab("r69d-tidy", [24; 32], Tickets::Grants).await;
    let content = TabContent::<MessagePort>::new(&mut tab);
    let kept_id = declared_id(TIDY_KEPT);
    let freed_id = declared_id(TIDY_FREED);
    let sacrifice_id = declared_id(TIDY_SACRIFICE);
    // The hub's retention sweep releases any sent file no pin covers, so the pins hold
    // from the start and the test releases one only after the sweep has settled.
    content
        .pin_content(
            "kept-pin",
            "SELECT content_id FROM photos WHERE id = 1",
            "content_id",
        )
        .await
        .expect("pin the kept photo");
    content
        .pin_content(
            "freed-pin",
            "SELECT content_id FROM photos WHERE id = 2",
            "content_id",
        )
        .await
        .expect("pin the freed photo");
    stage(&tab, kept_id, &blob_of(TIDY_KEPT));
    send_mutation(&mut tab, 1, &captured_insert(1, kept_id.as_bytes())).await;
    stage(&tab, freed_id, &blob_of(TIDY_FREED));
    send_mutation(&mut tab, 2, &captured_insert(2, freed_id.as_bytes())).await;
    stage(&tab, sacrifice_id, &blob_of(TIDY_SACRIFICE));
    send_mutation(&mut tab, 3, &captured_insert(3, sacrifice_id.as_bytes())).await;
    assert!(
        until(async || {
            uploads_of(&uploaded, TIDY_KEPT) == 1
                && uploads_of(&uploaded, TIDY_FREED) == 1
                && uploads_of(&uploaded, TIDY_SACRIFICE) == 1
        })
        .await,
        "the walk must upload all three files"
    );
    assert!(
        until(async || commits.get() == 3).await,
        "the walk must commit all three uploads before retention can release them"
    );
    let sacrifice_chunk = ChunkHash::from_data(TIDY_SACRIFICE);
    assert!(
        until(async || {
            store
                .stored_hashes()
                .await
                .is_ok_and(|hashes| !hashes.contains(&sacrifice_chunk))
        })
        .await,
        "the sweep must release the unpinned file, settling the retention pass"
    );
    content
        .unpin_content("freed-pin")
        .await
        .expect("release the freed photo");
    let freed = tokio::select! {
        freed = content.tidy() => freed.expect("tidy the local store"),
        () = timeout_ms(2_000) => panic!("tidy never answered"),
    };
    assert_eq!(freed, 1, "tidy answers the one record it released");
    let held = store.stored_hashes().await.expect("list the store");
    assert!(
        held.contains(&ChunkHash::from_data(TIDY_KEPT)),
        "the pinned file's bytes stay"
    );
    assert!(
        !held.contains(&ChunkHash::from_data(TIDY_FREED)),
        "the unpinned file's bytes are freed"
    );
    let resolved = content.resolve(freed_id).await;
    assert!(
        matches!(resolved, TabResolved::Remote { .. }),
        "the freed file still resolves from the server, got {resolved:?}"
    );
    serial.release();
}
