//! A tab receives the upstream refusal reason and rolls back its optimistic row.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use core::future::{Future, ready};

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use connetto_client::{
    ClientBuilder, ClientEvent, ConnettoConnection, FirstThen, KeyValue, SyncSchema,
};
use connetto_core::Cursor;
use connetto_core::messages::{
    BulkMessage, ControlMessage, HandshakeAck, MutationReject, MutationRejectReason, WriterGrant,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_web::{MessageTransport, RelayHub};
use diesel::prelude::*;
use futures_channel::mpsc;
use futures_util::StreamExt;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::MessagePort;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

diesel::table! {
    /// The optimistic write target.
    items (id) {
        /// The row's key.
        id -> diesel::sql_types::BigInt,
        /// The row's label.
        label -> diesel::sql_types::Text,
    }
}

const DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

/// The schema source the bundle declares, which names its major.
const SOURCE: &str = "-- connetto:major 1";

/// The client schema over [`DDL`].
fn schema() -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            SOURCE,
            "",
            DDL,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            None::<&str>,
        )
        .expect("the source declares major 1"),
    )
}

/// A dialer handing out `transport` once and nothing after.
fn once<T: Transport + 'static>(
    transport: T,
) -> FirstThen<impl FnMut() -> core::future::Ready<Result<T, &'static str>>> {
    FirstThen::new(transport, || core::future::ready(Err("spent")))
}

/// Refuses each mutation under its upstream sequence.
struct Upstream {
    incoming: mpsc::UnboundedReceiver<IncomingFrame>,
    answers: mpsc::UnboundedSender<IncomingFrame>,
    script: Rc<RefCell<VecDeque<MutationRejectReason>>>,
}

impl Upstream {
    fn new(script: Vec<MutationRejectReason>) -> Self {
        let (answers, incoming) = mpsc::unbounded();
        answers
            .unbounded_send(IncomingFrame::Control(ControlMessage::HandshakeAck(
                HandshakeAck {
                    connection_id: "r57c".to_owned(),
                    session_token: "r57c".to_owned(),
                    resume_token: "r57c".to_owned(),
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
            script: Rc::new(RefCell::new(script.into())),
        }
    }
}

impl Transport for Upstream {
    type Error = core::convert::Infallible;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        if let ControlMessage::MutationHeader(header) = message
            && let Some(reason) = self.script.borrow_mut().pop_front()
        {
            self.answers
                .unbounded_send(IncomingFrame::Control(ControlMessage::MutationReject(
                    MutationReject {
                        client_seq: header.client_seq,
                        reason,
                    },
                )))
                .expect("queue refusal");
        }
        ready(Ok(()))
    }

    fn send_bulk(
        &mut self,
        _message: BulkMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error> {
        loop {
            if let Some(frame) = self.incoming.next().await {
                return Ok(Some(frame));
            }
            // A drained queue means the scripted answers are spent, not that
            // the upstream went away.
            core::future::pending::<()>().await;
        }
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }
}

/// Pump the tab until its client settles a rejected mutation.
async fn pump_rejection(
    tab: &mut ConnettoConnection<MessageTransport<MessagePort>>,
) -> ClientEvent {
    let deadline = connetto_web::workers::sleep(Duration::from_secs(5));
    tokio::pin!(deadline);
    loop {
        let event = tokio::select! {
            event = tab.pump_one() => event.expect("tab pump"),
            () = &mut deadline => panic!("the tab received no rejection within five seconds"),
        };
        assert_ne!(event, ClientEvent::Closed, "the tab closed early");
        if matches!(event, ClientEvent::MutationRejected { .. }) {
            return event;
        }
    }
}

#[wasm_bindgen_test]
async fn an_upstream_refusal_reaches_the_tab_with_its_reason() {
    let upstream = Upstream::new(vec![
        MutationRejectReason::Unauthorized,
        MutationRejectReason::SchemaMismatch,
        MutationRejectReason::Constraint {
            detail: "unique constraint failed".to_owned(),
        },
    ]);
    let worker = ClientBuilder::new(schema(), once(upstream))
        .with_client_id("reject-reason-worker")
        .connect_driven()
        .await
        .expect("worker connect");
    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("hub meta");
    spawn_local(async move {
        pump.await.expect("hub pump");
    });
    let channel = web_sys::MessageChannel::new().expect("message channel");
    hub.attach(MessageTransport::<MessagePort>::new(channel.port1()));
    let mut tab = ClientBuilder::new(
        schema(),
        once(MessageTransport::<MessagePort>::new(channel.port2())),
    )
    .with_client_id("reject-reason-tab")
    .connect_driven()
    .await
    .expect("tab connect");

    let cases = [
        (1_i64, MutationRejectReason::Unauthorized),
        (2_i64, MutationRejectReason::SchemaMismatch),
        (
            3_i64,
            MutationRejectReason::Constraint {
                detail: "unique constraint failed".to_owned(),
            },
        ),
    ];
    for (id, reason) in cases {
        diesel::insert_into(items::table)
            .values((items::id.eq(id), items::label.eq("held")))
            .execute(tab.conn())
            .expect("tab insert");
        let tab_seq = tab.push().await.expect("push").expect("mutation sent");
        let event = pump_rejection(&mut tab).await;
        assert!(
            matches!(&event, ClientEvent::MutationRejected { client_seq, reason: r, rows }
                if *client_seq == tab_seq
                    && *r == reason
                    && rows.iter().any(|row| row.table == "items"
                        && row.key == vec![KeyValue::Int(id)])),
            "the tab must be told why the upstream refused: {event:?}"
        );
        let held: i64 = items::table
            .filter(items::id.eq(id))
            .count()
            .get_result(tab.conn())
            .expect("count after refusal");
        assert_eq!(held, 0, "the refused write rolled back in the tab");
    }
}
