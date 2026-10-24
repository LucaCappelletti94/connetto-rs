//! The tab-to-worker content lane over a real message channel: staged files
//! commit with the mutation that names them, mismatches are refused, and
//! resolution answers from the worker's store, the server ticket, or nowhere.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use connetto_core::messages::{
    ContentTicketGrant, ControlMessage, MutationReject, MutationRejectReason,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_file_core::FileId;
use connetto_web::content_wire::{ContentFrame, WireResolve};
use connetto_web::relay::RelayHub;
use connetto_web::workers::DB_ALIVE_LOCK;
use connetto_web::{InternalInbound, MessageTransport, locks};
use futures_channel::mpsc;
use futures_util::StreamExt;
use js_sys::Uint8Array;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::MessagePort;

#[expect(
    dead_code,
    reason = "the fixture is shared with the archive suite, whose tests use helpers this one does not call"
)]
#[path = "content_archive/support.rs"]
mod support;

#[path = "content_relay/fixture.rs"]
mod fixture;

use fixture::{
    Tickets, blob_of, captured_insert, declared_id, relay_tab, send_mutation, stage, uploads_of,
};
use support::{install_content_transport, timeout_ms, until};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const TEST_LOCK: &str = "connetto-content-relay-test";

/// Distinct bytes per test: a relay a finished test left running keeps driving
/// its own outbox against whatever `fetch` the current test installed.
const COMMIT_PHOTO: &[u8] = b"a photograph whose row and bytes commit as one hub mutation";
const REFUSE_PHOTO: &[u8] = b"a photograph whose declared identity is a lie";
const UNPAIRED_PHOTO: &[u8] = b"a staged photograph no mutation ever names";
const LOCAL_PHOTO: &[u8] = b"a photograph resolved back over the lane before upload";
const REMOTE_PHOTO: &[u8] = b"a photograph resolved to its server address after upload";
const HELD_PHOTO: &[u8] = b"a photograph committed while another file's ticket is held";

/// The same relay with a scripted grant or refusal for every ticket.
async fn relay_with_tab(
    store_name: &str,
    key: [u8; 32],
    grants: bool,
) -> (RelayHub, Rc<Cell<u32>>, MessageTransport<MessagePort>) {
    let (hub, mutations, tab, _answers, _store) = relay_tab(
        store_name,
        key,
        if grants {
            Tickets::Grants
        } else {
            Tickets::Refused
        },
    )
    .await;
    (hub, mutations, tab)
}

fn resolve(tab: &MessageTransport<MessagePort>, request_id: u64, file_id: FileId) {
    let frame = ContentFrame::Resolve {
        request_id,
        file_id: *file_id.as_bytes(),
    };
    tab.post_internal(&frame.to_json(), None)
        .expect("post resolve");
}

async fn recv_control(
    tab: &mut MessageTransport<MessagePort>,
    patience: i32,
) -> Option<ControlMessage> {
    tokio::select! {
        frame = tab.recv() => match frame.expect("transport") {
            Some(IncomingFrame::Control(message)) => Some(message),
            Some(IncomingFrame::Bulk(bulk)) => panic!("unexpected bulk toward the tab: {bulk:?}"),
            None => panic!("the hub closed the tab"),
        },
        () = timeout_ms(patience) => None,
    }
}

async fn next_reply(
    inbox: &mut mpsc::UnboundedReceiver<InternalInbound>,
) -> (u64, WireResolve, Option<web_sys::Blob>) {
    let inbound = tokio::select! {
        inbound = inbox.next() => inbound.expect("the lane stays open"),
        () = timeout_ms(3_000) => panic!("the hub never answered the resolve"),
    };
    match ContentFrame::from_json(&inbound.json).expect("decodable reply") {
        ContentFrame::ResolveReply { request_id, answer } => (request_id, answer, inbound.blob),
        frame => panic!("the lane answered a resolve with {frame:?}"),
    }
}

fn blob_bytes(blob: &web_sys::Blob) -> Vec<u8> {
    let reader = web_sys::FileReaderSync::new().expect("FileReaderSync in worker");
    let buffer = reader.read_as_array_buffer(blob).expect("read blob");
    Uint8Array::new(&buffer).to_vec()
}

/// A staged file plus a row naming its id: the hub commits the manifest with
/// the mutation, forwards it once, and the driver uploads the bytes.
#[wasm_bindgen_test]
async fn a_staged_file_and_its_row_reach_the_hub_as_one_mutation() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let stubs = install_content_transport(&uploaded);
    let (_hub, mutations, mut tab) = relay_with_tab("r69c-staged-commit", [11; 32], true).await;
    let file_id = declared_id(COMMIT_PHOTO);
    stage(&tab, file_id, &blob_of(COMMIT_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(1, file_id.as_bytes())).await;
    assert!(
        until(async || uploads_of(&uploaded, COMMIT_PHOTO) == 1).await,
        "the staged file must upload"
    );
    assert_eq!(mutations.get(), 1, "the mutation reaches the server");
    for _ in 0..4 {
        let Some(message) = recv_control(&mut tab, 250).await else {
            break;
        };
        assert!(
            !matches!(message, ControlMessage::MutationReject(_)),
            "the staged mutation must be accepted, got {message:?}"
        );
    }
    drop(stubs);
    serial.release();
}

#[wasm_bindgen_test]
async fn a_declaration_that_is_not_the_blob_is_refused_and_uploads_nothing() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let stubs = install_content_transport(&uploaded);
    let (_hub, mutations, mut tab) = relay_with_tab("r69c-staged-mismatch", [12; 32], true).await;
    // The lane declares an identity the bytes do not hash to, and the row
    // names that same lie, so pairing succeeds and the recomputed hash fails.
    let lie = FileId::from_bytes([9; 32]);
    stage(&tab, lie, &blob_of(REFUSE_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(1, lie.as_bytes())).await;
    let mut reject = None;
    for _ in 0..8 {
        match recv_control(&mut tab, 1_000).await {
            Some(ControlMessage::MutationReject(rejection)) => {
                reject = Some(rejection);
                break;
            }
            Some(_) => {}
            None => break,
        }
    }
    let detail = match reject {
        Some(MutationReject {
            reason: MutationRejectReason::Other { detail },
            ..
        }) => detail,
        other => panic!("the lying declaration must be refused, got {other:?}"),
    };
    assert!(
        detail.contains("hash to"),
        "the refusal names the hash, got {detail}"
    );
    assert_eq!(
        mutations.get(),
        0,
        "a refused mutation never reaches the server"
    );
    timeout_ms(300).await;
    assert!(
        uploaded.borrow().is_empty(),
        "a refused commit uploads nothing"
    );
    drop(stubs);
    serial.release();
}

#[wasm_bindgen_test]
async fn content_that_no_mutation_names_uploads_nothing() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let stubs = install_content_transport(&uploaded);
    // Tickets are refused, so even a wrongly paired stage cannot upload, and
    // the age-out probe below cannot be answered from a server ticket.
    let (_hub, mutations, mut tab) = relay_with_tab("r69c-staged-unpaired", [13; 32], false).await;
    stage(&tab, declared_id(UNPAIRED_PHOTO), &blob_of(UNPAIRED_PHOTO));
    // The row names a three-byte value, not a file identity, so nothing
    // pairs and the mutation goes out as an ordinary one.
    send_mutation(&mut tab, 1, &captured_insert(1, &[0xAA, 0xBB, 0xCC])).await;
    assert!(
        until(async || mutations.get() == 1).await,
        "the unnamed mutation is an ordinary one and must still forward"
    );
    for _ in 0..4 {
        let Some(message) = recv_control(&mut tab, 250).await else {
            break;
        };
        assert!(
            !matches!(message, ControlMessage::MutationReject(_)),
            "an unpaired stage is no reason to refuse the mutation, got {message:?}"
        );
    }
    timeout_ms(300).await;
    assert!(
        uploaded.borrow().is_empty() && mutations.get() == 1,
        "the mutation forwards as an ordinary one and uploads nothing"
    );
    // The stage must have aged out of the hub's books too: an ordinary
    // mutation must not have left it resolvable as local content.
    let mut inbox = tab.take_internal_inbox().expect("the lane is the tab's");
    resolve(&tab, 6, declared_id(UNPAIRED_PHOTO));
    let (request_id, answer, blob) = next_reply(&mut inbox).await;
    assert_eq!(request_id, 6, "the reply answers the age-out probe");
    assert!(
        matches!(answer, WireResolve::Unavailable),
        "an unpaired stage must leave nothing resolvable, got {answer:?}"
    );
    assert!(blob.is_none(), "an Unavailable answer carries no bytes");
    drop(stubs);
    serial.release();
}

#[wasm_bindgen_test]
async fn an_unsent_staged_file_resolves_to_its_own_bytes() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    // Tickets are refused, so the upload can never complete and the file
    // stays unsent, which is exactly the state a local answer comes from.
    let (_hub, mutations, mut tab) = relay_with_tab("r69c-resolve-local", [14; 32], false).await;
    let mut inbox = tab.take_internal_inbox().expect("the lane is the tab's");
    let file_id = declared_id(LOCAL_PHOTO);
    stage(&tab, file_id, &blob_of(LOCAL_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(1, file_id.as_bytes())).await;
    assert!(
        until(async || mutations.get() == 1).await,
        "the row commits"
    );
    resolve(&tab, 7, file_id);
    let (request_id, answer, blob) = next_reply(&mut inbox).await;
    assert_eq!(request_id, 7, "the reply carries the request's own id");
    assert!(
        matches!(answer, WireResolve::Local),
        "an unsent file answers Local, got {answer:?}"
    );
    let bytes = blob_bytes(&blob.expect("a Local answer carries the bytes"));
    assert_eq!(
        bytes, LOCAL_PHOTO,
        "the lane carries the exact staged bytes"
    );
    serial.release();
}

#[wasm_bindgen_test]
async fn an_uploaded_file_resolves_to_a_server_address() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let stubs = install_content_transport(&uploaded);
    let (_hub, _mutations, mut tab) = relay_with_tab("r69c-resolve-remote", [15; 32], true).await;
    let mut inbox = tab.take_internal_inbox().expect("the lane is the tab's");
    let file_id = declared_id(REMOTE_PHOTO);
    stage(&tab, file_id, &blob_of(REMOTE_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(1, file_id.as_bytes())).await;
    assert!(
        until(async || uploads_of(&uploaded, REMOTE_PHOTO) == 1).await,
        "the file must finish uploading before the resolve"
    );
    // The recorded upload is the request's send, not the dequeuing write
    // that follows the server's answer, so the file can still read as
    // unsent for a moment here. Retry until it reads sent.
    let mut remote = None;
    for attempt in 0..30 {
        resolve(&tab, 8 + attempt, file_id);
        let (reply_id, answer, blob) = next_reply(&mut inbox).await;
        assert_eq!(reply_id, 8 + attempt, "the reply answers its own request");
        match answer {
            WireResolve::Remote { url } => {
                assert!(blob.is_none(), "a Remote answer carries no bytes");
                remote = Some(url);
                break;
            }
            WireResolve::Local => timeout_ms(100).await,
            WireResolve::Unavailable => {
                panic!("an uploaded granted file must answer Remote, not Unavailable");
            }
        }
    }
    let url = remote.expect("the uploaded file answers Remote within the retries");
    assert!(
        url.contains(&file_id.to_string()),
        "the ticket names the file, got {url}"
    );
    drop(stubs);
    serial.release();
}

#[wasm_bindgen_test]
async fn a_file_the_hub_never_saw_answers_unavailable() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let (_hub, _mutations, mut tab) = relay_with_tab("r69c-resolve-unknown", [16; 32], false).await;
    let mut inbox = tab.take_internal_inbox().expect("the lane is the tab's");
    resolve(&tab, 9, FileId::from_bytes([5; 32]));
    let (request_id, answer, blob) = next_reply(&mut inbox).await;
    assert_eq!(request_id, 9);
    assert!(
        matches!(answer, WireResolve::Unavailable),
        "no manifest and a refused ticket answer Unavailable, got {answer:?}"
    );
    assert!(blob.is_none());
    serial.release();
}

/// Proves the hub's event loop is not parked on a ticket wait: a resolve
/// whose ticket never arrives stays unanswered, while mutations commit and
/// other resolves answer, and the grant released at last reaches only the
/// resolve that asked for it.
#[wasm_bindgen_test]
async fn the_hub_answers_around_a_ticket_that_never_arrives() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let held: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let (_hub, mutations, mut tab, answers, _store) = relay_tab(
        "r69c-resolve-held",
        [17; 32],
        Tickets::Held(Rc::clone(&held)),
    )
    .await;
    let mut inbox = tab.take_internal_inbox().expect("the lane is the tab's");

    let stuck = FileId::from_bytes([42u8; 32]);
    resolve(&tab, 11, stuck);
    assert!(
        until(async || !held.borrow().is_empty()).await,
        "the ticket request goes out and waits"
    );
    timeout_ms(200).await;
    assert!(
        matches!(
            inbox.try_recv(),
            Err(futures_channel::mpsc::TryRecvError::Empty)
        ),
        "a held ticket must leave the resolve unanswered"
    );

    stage(&tab, declared_id(HELD_PHOTO), &blob_of(HELD_PHOTO));
    let file_id = declared_id(HELD_PHOTO);
    send_mutation(&mut tab, 1, &captured_insert(1, file_id.as_bytes())).await;
    assert!(
        until(async || mutations.get() == 1).await,
        "a mutation commits while another resolve waits on its ticket"
    );
    resolve(&tab, 12, file_id);
    let (reply_id, answer, _blob) = next_reply(&mut inbox).await;
    assert_eq!(
        reply_id, 12,
        "the second resolve answers while the first waits"
    );
    assert!(
        matches!(answer, WireResolve::Local),
        "an unsent staged file answers Local beside a waiting resolve, got {answer:?}"
    );

    let request_id = held.borrow_mut().remove(0);
    answers
        .unbounded_send(IncomingFrame::Control(ControlMessage::ContentTicketGrant(
            ContentTicketGrant {
                request_id,
                url: format!("https://content.invalid/files/{stuck}?t=r69c-held"),
            },
        )))
        .expect("queue the released grant");
    let (reply_id, answer, blob) = next_reply(&mut inbox).await;
    assert_eq!(
        reply_id, 11,
        "the grant answers the resolve that waited on it"
    );
    match answer {
        WireResolve::Remote { url } => assert!(
            url.contains(&stuck.to_string()),
            "the released grant carries its URL, got {url}"
        ),
        other => panic!("a granted ticket answers Remote, got {other:?}"),
    }
    assert!(blob.is_none());
    serial.release();
}
