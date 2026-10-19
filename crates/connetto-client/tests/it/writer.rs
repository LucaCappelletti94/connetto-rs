//! R75, the client's writer state table, the number-writer half.
//!
//! One behaviour test per reachable row of the table that a number writer can
//! hold: a handshake acknowledged with no writer yet keeps the issued number
//! and re-keys the queue; a handshake with a number writer reconciles the
//! queue against the reported frontier without retiring anything locally; a
//! write whose answer was lost is rolled back when its resend is refused; the
//! number's sequence and chain head outlive an emptied queue and a restart.

use std::collections::VecDeque;
use std::future::{Future, ready};
use std::sync::Arc;

use connetto_client::{
    ClientBuilder, ClientError, ClientEvent, ConnettoConnection, DataDir, UnsyncedWrite,
};
use connetto_core::Cursor;
use connetto_core::messages::{
    BulkMessage, ControlMessage, FatalError, FatalErrorReason, HandshakeAck, MutationApplied,
    MutationReject, MutationRejectReason, WriterGrant, WriterRef, WriterRequest,
};
use connetto_core::traits::{IncomingFrame, Transport};
use diesel::prelude::*;
use parking_lot::Mutex;
use tempfile::tempdir;

const DDL: &str = "CREATE TABLE t (id INTEGER PRIMARY KEY)";

diesel::table! {
    /// The suite's one synced table.
    t (id) {
        /// Row identifier.
        id -> Integer,
    }
}

diesel::table! {
    /// The client's private writer-state table, read by the assertions.
    _connetto_writers (id) {
        id -> Text,
        next_seq -> BigInt,
        head -> Binary,
    }
}

/// How the fake answers the mutation headers it is handed.
#[derive(Clone, Copy, Default)]
enum Answer {
    #[default]
    Applied,
    Reject,
    Silent,
}

/// The grant shape a lying handshake answers with.
#[derive(Clone, Copy)]
enum Lie {
    /// No writer at all.
    Ungranted,
    /// A named grant, whatever it says.
    Grant(WriterGrant),
}

/// What the connection has been sent, plus the frames it is due to hand back.
#[derive(Default)]
struct Log {
    handshakes: Vec<WriterRequest>,
    mutations: Vec<u64>,
    outbox: VecDeque<IncomingFrame>,
}

/// A transport that plays a fresh server: it grants a writer number at the
/// handshake, records what it is sent, and answers mutations from its own
/// record.
#[derive(Clone)]
struct Wire {
    log: Arc<Mutex<Log>>,
    writer_number: u64,
    writer_frontier: u64,
    answer: Answer,
    lie: Option<Lie>,
    closing: Option<FatalErrorReason>,
}

impl Default for Wire {
    fn default() -> Self {
        Self {
            log: Arc::new(Mutex::new(Log::default())),
            writer_number: 1,
            writer_frontier: 0,
            answer: Answer::default(),
            lie: None,
            closing: None,
        }
    }
}

impl Wire {
    /// The number and frontier this fake grants.
    fn grant(mut self, number: u64, frontier: u64) -> Self {
        self.writer_number = number;
        self.writer_frontier = frontier;
        self
    }

    /// Answer every mutation header with a final refusal.
    fn rejecting(mut self) -> Self {
        self.answer = Answer::Reject;
        self
    }

    /// Answer nothing at all.
    fn silent(mut self) -> Self {
        self.answer = Answer::Silent;
        self
    }

    /// Answer every handshake with `lie` instead of the honest one.
    fn lie(mut self, lie: Option<WriterGrant>) -> Self {
        self.lie = Some(match lie {
            Some(grant) => Lie::Grant(grant),
            None => Lie::Ungranted,
        });
        self
    }

    /// Close the session deliberately with `reason` right after the handshake.
    fn closing_with(mut self, reason: FatalErrorReason) -> Self {
        self.closing = Some(reason);
        self
    }
}

impl Transport for Wire {
    type Error = std::convert::Infallible;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        match message {
            ControlMessage::Handshake(handshake) => {
                let writer = match self.lie {
                    Some(Lie::Ungranted) => None,
                    Some(Lie::Grant(grant)) => Some(grant),
                    None => match handshake.writer {
                        WriterRequest::Device => None,
                        WriterRequest::Issue | WriterRequest::Number(_) => Some(WriterGrant {
                            number: self.writer_number,
                            frontier: self.writer_frontier,
                        }),
                    },
                };
                let mut log = self.log.lock();
                log.handshakes.push(handshake.writer);
                log.outbox
                    .push_back(IncomingFrame::Control(ControlMessage::HandshakeAck(
                        HandshakeAck {
                            connection_id: "wire".to_owned(),
                            session_token: "wire".to_owned(),
                            resume_token: "run:wire".to_owned(),
                            current_cursor: Cursor::new(Vec::new()),
                            schema_version: None,
                            initial_credits: 64,
                            writer,
                        },
                    )));
                if let Some(reason) = self.closing.take() {
                    log.outbox
                        .push_back(IncomingFrame::Control(ControlMessage::FatalError(
                            FatalError::new(reason),
                        )));
                }
            }
            ControlMessage::MutationHeader(header) => {
                // The silent arm still records what went up, so a test can
                // prove the resend happened.
                self.log.lock().mutations.push(header.client_seq);
                if matches!(self.answer, Answer::Silent) {
                    return ready(Ok(()));
                }
                let frame = match self.answer {
                    Answer::Applied => {
                        IncomingFrame::Control(ControlMessage::MutationApplied(MutationApplied {
                            client_seq: header.client_seq,
                        }))
                    }
                    Answer::Reject => {
                        IncomingFrame::Control(ControlMessage::MutationReject(MutationReject {
                            client_seq: header.client_seq,
                            reason: MutationRejectReason::Unauthorized,
                        }))
                    }
                    Answer::Silent => unreachable!("the silent arm answered above"),
                };
                self.log.lock().outbox.push_back(frame);
            }
            _ => {}
        }
        ready(Ok(()))
    }

    fn send_bulk(
        &mut self,
        _message: BulkMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }

    fn recv(&mut self) -> impl Future<Output = Result<Option<IncomingFrame>, Self::Error>> {
        ready(Ok(self.log.lock().outbox.pop_front()))
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }
}

/// A replica in its own directory, opened offline under the suite's identity.
async fn open(dir: &tempfile::TempDir) -> ConnettoConnection<Wire> {
    let credential = super::support::held("tester");
    let store = super::support::key_store(&credential).await;
    ClientBuilder::new(
        super::support::bundle(DDL),
        super::support::NeverDial::<Wire>::default(),
    )
    .signed_in(credential)
    .durable(DataDir::new(dir.path().to_path_buf()), store)
    .open_driven()
    .await
    .expect("open with no server")
}

fn writers(conn: &mut ConnettoConnection<Wire>) -> Vec<String> {
    _connetto_writers::table
        .select(_connetto_writers::id)
        .order(_connetto_writers::id)
        .load::<String>(conn.conn())
        .expect("read the writer states")
}

/// Pump until the wire is gone, keeping the events the run announced.
async fn drain(conn: &mut ConnettoConnection<Wire>) -> Vec<ClientEvent> {
    let mut seen = Vec::new();
    loop {
        match conn.pump_one().await.expect("pump") {
            ClientEvent::Closed => break,
            event => seen.push(event),
        }
    }
    seen
}

fn write(conn: &mut ConnettoConnection<Wire>, id: i32) {
    diesel::insert_into(t::table)
        .values(t::id.eq(id))
        .execute(conn.conn())
        .expect("local write");
}

/// The table's "no writer yet" row: the issued number keeps the queue that
/// waited under the unissued one, and the next write takes the next sequence
/// of the same number.
#[tokio::test]
async fn a_handshake_ack_keeps_the_issued_number_and_rekeys_the_queue() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;

    write(&mut conn, 1);
    assert_eq!(conn.push().await.expect("queue"), Some(1));
    assert_eq!(
        conn.unsynced(),
        vec![UnsyncedWrite {
            writer: WriterRef::Number(0),
            seq: 1
        }],
        "the offline write waits under the unissued number"
    );

    let wire = Wire::default();
    conn.attach(wire.clone()).await.expect("attach");
    drain(&mut conn).await;

    {
        let log = wire.log.lock();
        assert_eq!(
            log.handshakes,
            vec![WriterRequest::Issue],
            "nothing settled yet, so a fresh number is asked"
        );
        assert_eq!(
            log.mutations,
            vec![1],
            "the queued write went up on the first connection"
        );
    }
    assert!(
        conn.unsynced().is_empty(),
        "the applied answer retired the entry"
    );
    assert_eq!(
        writers(&mut conn),
        vec!["number:1".to_owned()],
        "the queue re-keyed to the issued number"
    );

    write(&mut conn, 2);
    assert_eq!(
        conn.push().await.expect("queue"),
        Some(2),
        "the next write takes the next sequence of the same number"
    );
}

/// The table's "number writer" handshake row: the queue reconciles against
/// the reported frontier, nothing at or below it retires locally, and the
/// next sequence starts past it.
#[tokio::test]
async fn a_handshake_ack_reconciles_the_number_against_the_frontier() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;
    for id in [1, 2, 3] {
        write(&mut conn, id);
        assert_eq!(
            conn.push().await.expect("queue"),
            Some(u64::try_from(id).expect("the test id is positive"))
        );
    }

    // A first connection that never answers, so the queue still waits.
    conn.attach(Wire::default().silent()).await.expect("attach");
    drain(&mut conn).await;

    // A second connection that reports a frontier ahead of the queue, the
    // way a run presenting the number with its settled sequences would.
    let wire = Wire::default().silent().grant(1, 5);
    conn.attach(wire.clone()).await.expect("attach");
    {
        let log = wire.log.lock();
        assert_eq!(
            log.handshakes,
            vec![WriterRequest::Number(1)],
            "the unsent tail outlives the connection, so the number is presented"
        );
    }
    drain(&mut conn).await;
    {
        let log = wire.log.lock();
        assert_eq!(
            log.mutations,
            vec![1, 2, 3],
            "the queue resends in order, since the server re-answers from its record"
        );
    }
    assert_eq!(
        conn.unsynced(),
        (1..=3)
            .map(|seq| UnsyncedWrite {
                writer: WriterRef::Number(1),
                seq
            })
            .collect::<Vec<_>>(),
        "nothing at or below the frontier retired locally"
    );

    write(&mut conn, 4);
    assert_eq!(
        conn.push().await.expect("queue"),
        Some(6),
        "the next sequence starts past the frontier"
    );
}

/// A write whose answer was lost is resent, and a final refusal for it rolls
/// back the optimistic row and retires the entry.
#[tokio::test]
async fn a_write_never_answered_is_rolled_back_when_the_resend_is_refused() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;

    conn.attach(Wire::default().silent()).await.expect("attach");
    write(&mut conn, 1);
    assert_eq!(conn.push().await.expect("queue"), Some(1));
    drain(&mut conn).await;
    assert_eq!(
        t::table.count().load::<i64>(conn.conn()).expect("count"),
        vec![1],
        "the optimistic row stands until a final answer"
    );

    // The server arrives with a final refusal for the resent write.
    conn.attach(Wire::default().rejecting())
        .await
        .expect("attach");
    let seen = drain(&mut conn).await;
    assert!(
        seen.iter()
            .any(|event| matches!(event, ClientEvent::MutationRejected { client_seq: 1, .. })),
        "the refusal surfaced"
    );
    assert_eq!(
        t::table.count().load::<i64>(conn.conn()).expect("count"),
        vec![0],
        "the optimistic row rolled back"
    );
    assert!(
        conn.unsynced().is_empty(),
        "the entry retired with its final answer"
    );
}

/// The number's sequence and chain head outlive an emptied queue and a
/// restart, so a fresh run continues where the queue stood.
#[tokio::test]
async fn sequences_survive_an_emptied_queue_and_a_restart() {
    let dir = tempdir().expect("temp dir");
    {
        let mut conn = open(&dir).await;
        for id in [1, 2] {
            write(&mut conn, id);
            assert_eq!(
                conn.push().await.expect("queue"),
                Some(u64::try_from(id).expect("the test id is positive"))
            );
        }
        conn.attach(Wire::default()).await.expect("attach");
        drain(&mut conn).await;
        assert!(
            conn.unsynced().is_empty(),
            "both writes settled, the queue emptied"
        );
    }

    // A second run on the same replica continues the number's sequence.
    let mut conn = open(&dir).await;
    write(&mut conn, 3);
    assert_eq!(
        conn.push().await.expect("queue"),
        Some(3),
        "the sequence survived the empty queue and the restart"
    );
    assert_eq!(
        conn.unsynced(),
        vec![UnsyncedWrite {
            writer: WriterRef::Number(1),
            seq: 3
        }]
    );
}

diesel::table! {
    /// The client's private pending table, seeded by the boot-skip test.
    _connetto_pending (writer, seq) {
        /// The writer the entry stands under.
        writer -> Text,
        /// The entry's sequence.
        seq -> BigInt,
        /// The captured changeset.
        changeset -> Binary,
        /// The entry's chain hash.
        entry_hash -> Binary,
    }
}

/// A handshake acknowledged with no writer at all refuses the issue: the
/// client asked the server to issue its number and the server declined.
#[tokio::test]
async fn a_handshake_ack_with_no_grant_refuses_the_issue() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;
    let err = conn
        .attach(Wire::default().lie(None))
        .await
        .expect_err("the lying ack refuses");
    let ClientError::Protocol(detail) = err else {
        panic!("the lying ack refuses with a protocol error, got {err:?}");
    };
    assert_eq!(detail, "the server issued no writer to an issue");
}

/// A fresh issue answering with the unissued number is refused: number zero
/// belongs to the queue's waiting room, not to a grant.
#[tokio::test]
async fn a_handshake_ack_issuing_the_unissued_number_is_refused() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;
    let err = conn
        .attach(Wire::default().lie(Some(WriterGrant {
            number: 0,
            frontier: 0,
        })))
        .await
        .expect_err("the lying ack refuses");
    let ClientError::Protocol(detail) = err else {
        panic!("the lying ack refuses with a protocol error, got {err:?}");
    };
    assert_eq!(detail, "the server issued the unissued number");
}

/// A fresh number that arrives with a frontier is refused: nothing settled
/// under a number the client never presented.
#[tokio::test]
async fn a_fresh_number_arriving_with_a_frontier_is_refused() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;
    let err = conn
        .attach(Wire::default().lie(Some(WriterGrant {
            number: 1,
            frontier: 5,
        })))
        .await
        .expect_err("the lying ack refuses");
    let ClientError::Protocol(detail) = err else {
        panic!("the lying ack refuses with a protocol error, got {err:?}");
    };
    assert_eq!(detail, "a fresh number arrived with a frontier");
}

/// A number confirmation the server did not grant is refused, as is one that
/// names a different number than the handshake presented.
#[tokio::test]
async fn number_confirmations_the_server_never_granted_are_refused() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;
    conn.attach(Wire::default()).await.expect("attach");
    let err = conn
        .attach(Wire::default().lie(None))
        .await
        .expect_err("the lying ack refuses");
    let ClientError::Protocol(detail) = err else {
        panic!("the lying ack refuses with a protocol error, got {err:?}");
    };
    assert_eq!(detail, "the server answered a number without a grant");

    conn.attach(Wire::default()).await.expect("attach");
    let err = conn
        .attach(Wire::default().lie(Some(WriterGrant {
            number: 2,
            frontier: 0,
        })))
        .await
        .expect_err("the lying ack refuses");
    let ClientError::Protocol(detail) = err else {
        panic!("the lying ack refuses with a protocol error, got {err:?}");
    };
    assert_eq!(
        detail,
        "the server confirmed another number than the handshake named"
    );
}

/// A writer the server declares unknown carries its unacked tail to the
/// unissued number, so the next run re-issues and resends rather than losing
/// the writes.
#[tokio::test]
async fn a_writer_unknown_fatal_carries_the_tail_to_the_unissued_number() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;

    let wire = Wire::default()
        .silent()
        .closing_with(FatalErrorReason::WriterUnknown);
    conn.attach(wire.clone()).await.expect("attach");
    write(&mut conn, 1);
    assert_eq!(conn.push().await.expect("queue"), Some(1));
    write(&mut conn, 2);
    assert_eq!(conn.push().await.expect("queue"), Some(2));
    let seen = drain(&mut conn).await;
    assert!(
        seen.iter().any(|event| matches!(
            event,
            ClientEvent::ServerClosed {
                reason: FatalErrorReason::WriterUnknown
            }
        )),
        "the fatal surfaced, saw {seen:?}"
    );
    assert_eq!(
        writers(&mut conn),
        vec!["number:0".to_owned()],
        "the tail re-keyed under the unissued number"
    );
    assert_eq!(
        conn.unsynced(),
        vec![
            UnsyncedWrite {
                writer: WriterRef::Number(0),
                seq: 1
            },
            UnsyncedWrite {
                writer: WriterRef::Number(0),
                seq: 2
            },
        ],
        "both writes survive the carry"
    );

    // The fresh run asks for a new number and resends the carried tail.
    let wire = Wire::default();
    conn.attach(wire.clone()).await.expect("re-attach");
    drain(&mut conn).await;
    {
        let log = wire.log.lock();
        assert_eq!(
            log.handshakes,
            vec![WriterRequest::Issue],
            "the carried tail presents no number, so a fresh one is asked"
        );
        assert_eq!(
            log.mutations,
            vec![1, 2],
            "the carried tail resends in order"
        );
    }
    assert!(
        conn.unsynced().is_empty(),
        "the applied answers retired the carried entries"
    );
    assert_eq!(
        writers(&mut conn),
        vec!["number:1".to_owned()],
        "the tail stands under the issued number"
    );
}

/// Pending records a torn write or corruption left undecodable are skipped at
/// boot rather than poisoning the queue, and the decodable record loads.
#[tokio::test]
async fn corrupt_pending_rows_are_skipped_at_boot() {
    let dir = tempdir().expect("temp dir");
    {
        let mut conn = open(&dir).await;
        conn.attach(Wire::default().silent()).await.expect("attach");
        write(&mut conn, 1);
        assert_eq!(conn.push().await.expect("queue"), Some(1));
        drain(&mut conn).await;

        // Seed the pending table the way a torn write would leave it: the
        // good record beside three the boot cannot decode.
        diesel::insert_into(_connetto_pending::table)
            .values((
                _connetto_pending::writer.eq("junk"),
                _connetto_pending::seq.eq(1_i64),
                _connetto_pending::changeset.eq(b"one"),
                _connetto_pending::entry_hash.eq([0u8; 32]),
            ))
            .execute(conn.conn())
            .expect("undecodable writer row");
        diesel::insert_into(_connetto_pending::table)
            .values((
                _connetto_pending::writer.eq("number:5"),
                _connetto_pending::seq.eq(-3_i64),
                _connetto_pending::changeset.eq(b"two"),
                _connetto_pending::entry_hash.eq([0u8; 32]),
            ))
            .execute(conn.conn())
            .expect("negative sequence row");
        diesel::insert_into(_connetto_pending::table)
            .values((
                _connetto_pending::writer.eq("number:9"),
                _connetto_pending::seq.eq(7_i64),
                _connetto_pending::changeset.eq(b"three"),
                _connetto_pending::entry_hash.eq([0u8; 31]),
            ))
            .execute(conn.conn())
            .expect("short hash row");
    }

    // The boot loads the good entry and skips the corrupt rows.
    let conn = open(&dir).await;
    assert_eq!(
        conn.unsynced(),
        vec![UnsyncedWrite {
            writer: WriterRef::Number(1),
            seq: 1
        }],
        "the corrupt rows skipped, the good one loaded"
    );
}
