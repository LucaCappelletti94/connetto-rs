//! The content-aware hub both tab suites drive: a fake upstream, the hub over
//! it, and a handshaken tab on the other end of a real message channel, plus
//! the frames a tab posts.

use core::convert::Infallible;
use core::future::{Future, ready};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientBuilder, FirstThen, Grant, HeldCredential, SyncSchema};
use connetto_core::Cursor;
use connetto_core::PROTOCOL_VERSION;
use connetto_core::messages::{
    BulkMessage, CONTENT_TICKET_REFUSED, ContentTicketGrant, ControlMessage, Handshake,
    HandshakeAck, MutationHeader, MutationPatch, NonFatalError, WriterGrant,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_file_client::{BrowserHttp, BrowserStore, ContentArchive};
use connetto_file_core::{FileId, FileIdHasher, MimeClass};
use connetto_web::MessageTransport;
use connetto_web::content_wire::{ContentFrame, mime_code};
use connetto_web::relay::{HubReconnect, RelayHub};
use diesel::Connection;
use diesel::connection::SimpleConnection;
use futures_channel::mpsc;
use futures_util::StreamExt;
use js_sys::{Array, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use web_sys::{DedicatedWorkerGlobalScope, MessagePort};

use super::support::timeout_ms;

const DDL: &str = "CREATE TABLE photos (id INTEGER PRIMARY KEY, content_id BLOB NOT NULL)";
/// The scripted tab's client id, from which the hub derives its watermark key.
const TAB_CLIENT_ID: &str = "6f1c9d2e-8a4b-4c5d-9e6f-0a1b2c3d4e5f";

/// How the fake upstream answers content tickets.
#[derive(Clone)]
pub(super) enum Tickets {
    /// Every request is granted.
    Grants,
    /// Every request is refused with the wire's fixed phrase.
    Refused,
    /// Every request goes unanswered and lands on the shared list, for a
    /// test that releases one later.
    Held(Rc<RefCell<Vec<String>>>),
}

struct Upstream {
    incoming: mpsc::UnboundedReceiver<IncomingFrame>,
    answers: mpsc::UnboundedSender<IncomingFrame>,
    mutations: Rc<Cell<u32>>,
    tickets: Tickets,
}

impl Upstream {
    /// A live upstream answering the handshake, counting forwarded mutations,
    /// and answering every content ticket per `tickets`.
    fn live(mutations: Rc<Cell<u32>>, tickets: Tickets) -> Self {
        let (answers, incoming) = mpsc::unbounded();
        answers
            .unbounded_send(IncomingFrame::Control(ControlMessage::HandshakeAck(
                HandshakeAck {
                    connection_id: "content-lane".to_owned(),
                    session_token: "content-lane".to_owned(),
                    resume_token: "content-lane".to_owned(),
                    current_cursor: Cursor::new(Vec::new()),
                    schema_version: None,
                    initial_credits: 64,
                    writer: Some(WriterGrant {
                        number: 1,
                        frontier: 0,
                    }),
                },
            )))
            .expect("queue handshake");
        Self {
            incoming,
            answers,
            mutations,
            tickets,
        }
    }
}

impl Transport for Upstream {
    type Error = Infallible;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        if let ControlMessage::ContentTicketRequest(request) = message {
            let reply = match &self.tickets {
                Tickets::Grants => Some(ControlMessage::ContentTicketGrant(ContentTicketGrant {
                    request_id: request.request_id.clone(),
                    url: format!(
                        "https://content.invalid/files/{}/intent?t=lane",
                        FileId::from_bytes(request.file_id)
                    ),
                })),
                Tickets::Refused => Some(ControlMessage::NonFatalError(NonFatalError {
                    related_to: Some(request.request_id.clone()),
                    detail: CONTENT_TICKET_REFUSED.to_owned(),
                })),
                Tickets::Held(held) => {
                    held.borrow_mut().push(request.request_id);
                    None
                }
            };
            if let Some(reply) = reply {
                self.answers
                    .unbounded_send(IncomingFrame::Control(reply))
                    .expect("queue ticket");
            }
        }
        ready(Ok(()))
    }

    fn send_bulk(&mut self, message: BulkMessage) -> impl Future<Output = Result<(), Self::Error>> {
        if matches!(message, BulkMessage::MutationPatch(_)) {
            self.mutations.set(self.mutations.get() + 1);
        }
        ready(Ok(()))
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error> {
        Ok(self.incoming.next().await)
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }
}

/// The client schema over [`DDL`].
fn schema() -> SyncSchema {
    SyncSchema::new(SchemaBundle::new(
        "",
        "",
        DDL,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        None::<&str>,
    ))
}

/// A dialer handing out `transport` once and nothing after.
fn once<T: Transport + 'static>(
    transport: T,
) -> FirstThen<impl FnMut() -> core::future::Ready<Result<T, &'static str>>> {
    FirstThen::new(transport, || core::future::ready(Err("spent")))
}

/// A content-aware hub on a live fake upstream plus the tab transport on
/// the other end of a real message channel, already handshaken.
///
/// Also hands back the mutation counter, a sender onto the upstream's
/// inbound queue for tests that inject an answer the fake never scripts, and
/// the store the hub's archive writes into, so a test can let stored bytes go.
pub(super) async fn relay_tab(
    store_name: &str,
    key: [u8; 32],
    tickets: Tickets,
) -> (
    RelayHub,
    Rc<Cell<u32>>,
    MessageTransport<MessagePort>,
    mpsc::UnboundedSender<IncomingFrame>,
    BrowserStore,
) {
    let mutations = Rc::new(Cell::new(0u32));
    let upstream = Upstream::live(Rc::clone(&mutations), tickets.clone());
    let answers = upstream.answers.clone();
    let worker = ClientBuilder::new(schema(), once(upstream))
        .signed_in(
            HeldCredential::new(Grant::new("user:content-lane"), "content-lane")
                .expect("a string identity serializes"),
        )
        .connect_driven()
        .await
        .expect("connect relay replica");
    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .expect("dedicated worker");
    let store = BrowserStore::install(&scope, store_name)
        .await
        .expect("install store");
    let content = ContentArchive::new(store.clone(), key);
    let (hub, pump, _notices) = RelayHub::with_reconnect_and_content(
        worker,
        ":memory:",
        HubReconnect {
            factory: {
                let mutations = Rc::clone(&mutations);
                let tickets = tickets.clone();
                move || {
                    ready(Ok::<_, Infallible>(Upstream::live(
                        Rc::clone(&mutations),
                        tickets.clone(),
                    )))
                }
            },
            // A refused ticket or a deferred attempt retries on this timer.
            // An instant sleeper turns that backoff into a busy loop that
            // starves the worker, so the fixture sleeps for real, capped to
            // keep tests bounded.
            sleeper: |delay: core::time::Duration| async move {
                let ms = delay.as_millis().clamp(1, 500);
                timeout_ms(i32::try_from(ms).expect("capped above")).await;
            },
            policy: ReconnectPolicy::new(),
            upstream: Vec::new(),
        },
        content,
        BrowserHttp::new(),
    )
    .expect("content relay");
    spawn_local(async move {
        pump.await.expect("relay pump");
    });
    let channel = web_sys::MessageChannel::new().expect("message channel");
    hub.attach_with_content(MessageTransport::<MessagePort>::new(channel.port1()));
    let mut tab = MessageTransport::<MessagePort>::new(channel.port2());
    tab.send_control(ControlMessage::Handshake(Handshake::new(
        PROTOCOL_VERSION,
        TAB_CLIENT_ID,
    )))
    .await
    .expect("post handshake");
    let ack = tokio::select! {
        frame = tab.recv() => frame.expect("transport").expect("open"),
        () = timeout_ms(2_000) => panic!("the hub never answered the handshake"),
    };
    assert!(
        matches!(ack, IncomingFrame::Control(ControlMessage::HandshakeAck(_))),
        "the hub's first answer is the ack, got {ack:?}"
    );
    (hub, mutations, tab, answers, store)
}

pub(super) fn blob_of(bytes: &[u8]) -> web_sys::Blob {
    let arr = Uint8Array::from(bytes);
    web_sys::Blob::new_with_u8_array_sequence(&Array::of1(&arr)).expect("blob from bytes")
}

pub(super) fn declared_id(bytes: &[u8]) -> FileId {
    let mut hasher = FileIdHasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

pub(super) fn stage(tab: &MessageTransport<MessagePort>, file_id: FileId, blob: &web_sys::Blob) {
    let frame = ContentFrame::Stage {
        file_id: *file_id.as_bytes(),
        mime: mime_code(MimeClass::Jpeg),
    };
    tab.post_internal(&frame.to_json(), Some(blob))
        .expect("post stage");
}

/// The changeset of one `photos` insert declaring `content_id` in row `row`,
/// captured from a throwaway replica the way a tab's own capture would
/// produce it.
pub(super) fn captured_insert(row: u32, content_id: &[u8]) -> Vec<u8> {
    use diesel_sqlite_session::SqliteSessionExt;
    let mut hex = String::new();
    for byte in content_id {
        std::fmt::write(&mut hex, format_args!("{byte:02x}")).expect("string append");
    }
    let mut conn = diesel::SqliteConnection::establish(":memory:").expect("open");
    conn.batch_execute(DDL).expect("schema");
    let mut session = conn.create_session().expect("session");
    session.attach_all().expect("attach");
    conn.batch_execute(&format!("INSERT INTO photos VALUES ({row}, x'{hex}')"))
        .expect("insert");
    session.changeset().expect("changeset")
}

pub(super) async fn send_mutation(
    tab: &mut MessageTransport<MessagePort>,
    seq: u64,
    changeset: &[u8],
) {
    tab.send_control(ControlMessage::MutationHeader(MutationHeader {
        client_seq: seq,
        op_count: 1,
        provenance: None,
    }))
    .await
    .expect("post header");
    tab.send_bulk(BulkMessage::MutationPatch(MutationPatch {
        client_seq: seq,
        patchset_zstd: zstd::encode_all(changeset, 3).expect("compress"),
    }))
    .await
    .expect("post patchset");
}

pub(super) fn uploads_of(uploaded: &RefCell<Vec<Vec<u8>>>, photo: &[u8]) -> usize {
    uploaded
        .borrow()
        .iter()
        .filter(|body| body.as_slice() == photo)
        .count()
}
