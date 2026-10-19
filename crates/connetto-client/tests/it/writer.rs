//! R75, the client's writer state table, the number-writer half.
//!
//! One behaviour test per reachable row of the table that a number writer can
//! hold: a handshake acknowledged with no writer yet keeps the issued number
//! and re-keys the queue; a handshake with a number writer reconciles the
//! queue against the reported frontier without retiring anything locally; a
//! `WriterRetired` fatal re-queues the tail with provenance under a fresh
//! number. The device-writer rows need an enrolled key, which the native
//! suites steer through the enrolment task.

use std::collections::VecDeque;
use std::future::{Future, ready};
use std::sync::Arc;

use connetto_client::{
    ClientBuilder, ClientError, ClientEvent, ConnettoConnection, DataDir, SyncSchema, UnsyncedWrite,
};
use connetto_core::Cursor;
use connetto_core::chain::{GENESIS, entry_hash};
use connetto_core::messages::{
    BulkMessage, ControlMessage, FatalError, FatalErrorReason, HandshakeAck, MutationApplied,
    MutationReject, MutationRejectReason, WriterAnswer, WriterGrant, WriterOutcome, WriterRef,
    WriterRequest,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::traits::{IncomingFrame, Transport};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use parking_lot::Mutex;
use sqlite_diff_rs::ParsedDiffSet;
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

diesel::table! {
    /// The client's private pending-queue table, read by the assertions.
    _connetto_pending (writer, seq) {
        writer -> Text,
        seq -> BigInt,
        changeset -> Binary,
        entry_hash -> Binary,
        prov_writer -> Nullable<Text>,
        prov_seq -> Nullable<BigInt>,
    }
}

/// One row of the durable pending queue, the bookkeeping columns the
/// assertions read.
#[derive(diesel::Queryable, Debug, PartialEq, Eq)]
struct PendingRow {
    writer: String,
    seq: i64,
    prov_writer: Option<String>,
    prov_seq: Option<i64>,
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
    bulks: Vec<Vec<u8>>,
    retires: Vec<connetto_core::messages::RetireWriter>,
    outbox: VecDeque<IncomingFrame>,
}

/// A transport that plays a fresh server: it grants a writer number at the
/// handshake, records what it is sent, and answers mutations, binds and
/// retirements from its own record.
#[derive(Clone)]
struct Wire {
    log: Arc<Mutex<Log>>,
    writer_number: u64,
    writer_frontier: u64,
    answer: Answer,
    lie: Option<Lie>,
    closing: Option<FatalErrorReason>,
    refuse: Option<FatalErrorReason>,
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
            refuse: None,
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

    /// Close the connection right after the handshake with `reason`.
    fn closing(mut self, reason: FatalErrorReason) -> Self {
        self.closing = Some(reason);
        self
    }

    /// Refuse the handshake itself with `reason`, before any ack.
    fn refusing_with(mut self, reason: FatalErrorReason) -> Self {
        self.refuse = Some(reason);
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
                if let Some(reason) = self.refuse.take() {
                    log.outbox
                        .push_back(IncomingFrame::Control(ControlMessage::FatalError(
                            FatalError::new(reason),
                        )));
                } else {
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
            ControlMessage::RetireWriter(retire) => {
                let mut log = self.log.lock();
                log.retires.push(retire.clone());
                log.outbox
                    .push_back(IncomingFrame::Control(ControlMessage::WriterAnswer(
                        WriterAnswer {
                            request_id: retire.request_id,
                            outcome: WriterOutcome::Retired,
                        },
                    )));
            }
            _ => {}
        }
        ready(Ok(()))
    }

    fn send_bulk(&mut self, message: BulkMessage) -> impl Future<Output = Result<(), Self::Error>> {
        if let BulkMessage::MutationPatch(patch) = message {
            self.log.lock().bulks.push(patch.patchset_zstd);
        }
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

fn pending(conn: &mut ConnettoConnection<Wire>) -> Vec<PendingRow> {
    _connetto_pending::table
        .select((
            _connetto_pending::writer,
            _connetto_pending::seq,
            _connetto_pending::prov_writer,
            _connetto_pending::prov_seq,
        ))
        .order(_connetto_pending::seq)
        .load(conn.conn())
        .expect("read the queue")
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

    // A second connection that reports a frontier ahead of the queue, as a
    // courier settling this number's writes would.
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

/// The table's `WriterRetired` row for a number writer: the tail re-queues
/// with provenance under a fresh number, and the key is left alone.
#[tokio::test]
async fn a_writer_retired_fatal_requeues_the_tail_with_provenance() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;

    conn.attach(Wire::default().silent()).await.expect("attach");
    write(&mut conn, 1);
    assert_eq!(conn.push().await.expect("queue"), Some(1));
    drain(&mut conn).await;

    // The server retires the writer and closes the connection over it.
    conn.attach(
        Wire::default()
            .silent()
            .closing(FatalErrorReason::WriterRetired),
    )
    .await
    .expect("attach");
    let seen = drain(&mut conn).await;
    assert!(
        seen.iter().any(|event| matches!(
            event,
            ClientEvent::ServerClosed {
                reason: FatalErrorReason::WriterRetired
            }
        )),
        "the fatal surfaced as a server close"
    );

    // A fresh connection asks a fresh number, and the tail goes up again under
    // it, provenance intact.
    let wire = Wire::default().silent().grant(2, 0);
    conn.attach(wire.clone()).await.expect("attach");
    {
        let log = wire.log.lock();
        assert_eq!(
            log.handshakes,
            vec![WriterRequest::Issue],
            "the retired number is no longer presented"
        );
    }
    drain(&mut conn).await;
    {
        let log = wire.log.lock();
        assert_eq!(log.mutations, vec![1], "the tail went up again");
    }
    assert_eq!(
        pending(&mut conn),
        vec![PendingRow {
            writer: "number:2".to_owned(),
            seq: 1,
            prov_writer: Some("number:1".to_owned()),
            prov_seq: Some(1),
        }],
        "the entry carries the writer and sequence it was first written under"
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
        .closing(FatalErrorReason::WriterUnknown);
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

/// A failure inside the append's pending-row write leaves the durable queue
/// exactly where it stood, so the retry takes the same sequence and a
/// restart reloads the unbroken queue.
#[tokio::test]
async fn a_failed_append_keeps_the_queue_unchanged_and_retries_the_same_sequence() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;
    conn.attach(Wire::default().silent()).await.expect("attach");
    write(&mut conn, 1);
    assert_eq!(conn.push().await.expect("queue"), Some(1));
    drain(&mut conn).await;

    // A failure injected into the pending-row write.
    conn.conn()
        .batch_execute(
            "CREATE TRIGGER fail_pending BEFORE INSERT ON _connetto_pending \
             BEGIN SELECT RAISE(FAIL, 'review injected write failure'); END;",
        )
        .expect("arm the trigger");
    write(&mut conn, 2);
    assert!(
        conn.push().await.is_err(),
        "the append fails on the injected write failure"
    );
    conn.conn()
        .batch_execute("DROP TRIGGER fail_pending")
        .expect("disarm the trigger");

    // Nothing durable moved: the next sequence still stands and no entry was left behind.
    let next_seq: i64 = _connetto_writers::table
        .select(_connetto_writers::next_seq)
        .first(conn.conn())
        .expect("read the queue state");
    assert_eq!(
        next_seq, 2,
        "the failed append left the next sequence where it stood"
    );
    assert_eq!(
        _connetto_pending::table
            .count()
            .get_result::<i64>(conn.conn())
            .expect("count the queue"),
        1,
        "the failed append left the standing entry and nothing else"
    );

    // The retry takes the same sequence the failed append did.
    assert_eq!(
        conn.push().await.expect("the retry queues"),
        Some(2),
        "the retry re-takes the failed sequence"
    );
    assert_eq!(
        conn.unsynced(),
        vec![
            UnsyncedWrite {
                writer: WriterRef::Number(1),
                seq: 1
            },
            UnsyncedWrite {
                writer: WriterRef::Number(1),
                seq: 2
            },
        ],
        "the retry sits under the standing entry"
    );
    drop(conn);

    // A restart reloads the unbroken queue and resends it in order.
    let mut conn = open(&dir).await;
    assert_eq!(
        conn.unsynced(),
        vec![
            UnsyncedWrite {
                writer: WriterRef::Number(1),
                seq: 1
            },
            UnsyncedWrite {
                writer: WriterRef::Number(1),
                seq: 2
            },
        ],
        "the restart reloads both entries"
    );
    let wire = Wire::default();
    conn.attach(wire.clone()).await.expect("attach");
    drain(&mut conn).await;
    {
        let log = wire.log.lock();
        assert_eq!(
            log.mutations,
            vec![1, 2],
            "the restart resends the entries in order"
        );
    }
    assert!(
        conn.unsynced().is_empty(),
        "the applied answers retired both entries"
    );
}

/// A failure midway through a multi-entry carry keeps the complete source and
/// leaves no partial target behind, so a restart resends the whole tail.
#[tokio::test]
async fn a_failed_carry_retains_the_complete_source_and_the_restart_resends_it() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;
    conn.attach(Wire::default().silent()).await.expect("attach");
    write(&mut conn, 1);
    assert_eq!(conn.push().await.expect("queue"), Some(1));
    write(&mut conn, 2);
    assert_eq!(conn.push().await.expect("queue"), Some(2));
    drain(&mut conn).await;

    // The reconnect's fatal carries the tail to the unissued number, and the
    // carry's second insert fails.
    conn.conn()
        .batch_execute(
            "CREATE TRIGGER fail_carry BEFORE INSERT ON _connetto_pending \
             WHEN NEW.writer = 'number:0' AND NEW.seq = 2 \
             BEGIN SELECT RAISE(FAIL, 'review carry failure'); END;",
        )
        .expect("arm the trigger");
    conn.attach(
        Wire::default()
            .silent()
            .closing_with(FatalErrorReason::WriterUnknown),
    )
    .await
    .expect("attach");
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
    conn.conn()
        .batch_execute("DROP TRIGGER fail_carry")
        .expect("disarm the trigger");

    // The failed carry left the complete source standing.
    let pending: Vec<(String, i64)> = _connetto_pending::table
        .select((_connetto_pending::writer, _connetto_pending::seq))
        .order(_connetto_pending::seq)
        .load(conn.conn())
        .expect("read the queue");
    assert_eq!(
        pending,
        vec![("number:1".to_owned(), 1), ("number:1".to_owned(), 2)],
        "the failed carry retained both entries under the dead number"
    );
    let ids: Vec<String> = _connetto_writers::table
        .select(_connetto_writers::id)
        .order(_connetto_writers::id)
        .load(conn.conn())
        .expect("read the queue states");
    assert_eq!(
        ids,
        vec!["number:1".to_owned()],
        "the failed carry left no partial target behind"
    );
    drop(conn);

    // The restart loads the source and resends the whole tail.
    let mut conn = open(&dir).await;
    assert_eq!(
        conn.unsynced(),
        vec![
            UnsyncedWrite {
                writer: WriterRef::Number(1),
                seq: 1
            },
            UnsyncedWrite {
                writer: WriterRef::Number(1),
                seq: 2
            },
        ],
        "the restart reloads the complete source"
    );
    let wire = Wire::default();
    conn.attach(wire.clone()).await.expect("attach");
    drain(&mut conn).await;
    {
        let log = wire.log.lock();
        assert_eq!(
            log.mutations,
            vec![1, 2],
            "the restart resends the whole tail"
        );
    }
    assert!(conn.unsynced().is_empty(), "the answers retired the tail");
}

/// A handshake the server refuses as `WriterUnknown` before the ack carries
/// the presented number's tail to the unissued number, so the next run
/// re-issues instead of re-presenting a number the server does not hold.
#[tokio::test]
async fn a_handshake_refusal_carries_the_unknown_numbers_tail() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;
    conn.attach(Wire::default().silent()).await.expect("attach");
    write(&mut conn, 1);
    assert_eq!(conn.push().await.expect("queue"), Some(1));
    write(&mut conn, 2);
    assert_eq!(conn.push().await.expect("queue"), Some(2));
    drain(&mut conn).await;

    // The reconnect presents the number and the server refuses the handshake
    // itself, before any ack.
    let error = conn
        .attach(Wire::default().refusing_with(FatalErrorReason::WriterUnknown))
        .await
        .expect_err("the refused handshake fails the attach");
    assert!(
        matches!(
            error,
            ClientError::Refused {
                reason: FatalErrorReason::WriterUnknown
            }
        ),
        "the refusal surfaces, saw {error:?}"
    );
    assert_eq!(
        writers(&mut conn),
        vec!["number:0".to_owned()],
        "the unknown number's tail re-keyed under the unissued number"
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

    // The next run asks for a fresh number and resends the carried tail.
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
}

/// The split table's local replica writes the physical table under the view,
/// so the queue entry hashes the logical bytes the wire uploads and keeps the
/// physical bytes for the rollback.
const SPLIT_DDL: &str = "CREATE TABLE physical_t (id INTEGER PRIMARY KEY); \
    CREATE VIEW t AS SELECT * FROM physical_t; \
    CREATE TRIGGER t_insert INSTEAD OF INSERT ON t \
    BEGIN INSERT INTO physical_t (id) VALUES (NEW.id); END;";

/// The split schema's bundle: the view `t` over its physical table.
fn split_bundle() -> SyncSchema {
    SyncSchema::new(SchemaBundle::new(
        "",
        "",
        SPLIT_DDL,
        vec![("t".to_owned(), "physical_t".to_owned())],
        vec!["t".to_owned()],
        None::<&str>,
    ))
}

/// A replica in its own directory, opened offline under the split schema.
async fn split_open(dir: &tempfile::TempDir) -> ConnettoConnection<Wire> {
    let credential = super::support::held("tester");
    let store = super::support::key_store(&credential).await;
    ClientBuilder::new(split_bundle(), super::support::NeverDial::<Wire>::default())
        .signed_in(credential)
        .durable(DataDir::new(dir.path().to_path_buf()), store)
        .open_driven()
        .await
        .expect("open with no server")
}

#[tokio::test]
async fn a_split_table_entry_hashes_the_logical_bytes() {
    let dir = tempdir().expect("temp dir");
    let mut conn = split_open(&dir).await;
    conn.attach(Wire::default().silent()).await.expect("attach");
    write(&mut conn, 1);
    assert_eq!(conn.push().await.expect("queue"), Some(1));
    drain(&mut conn).await;

    // The durable record keeps the physical bytes it was captured under...
    let (changeset, stored): (Vec<u8>, Vec<u8>) = _connetto_pending::table
        .select((_connetto_pending::changeset, _connetto_pending::entry_hash))
        .first(conn.conn())
        .expect("read the record");
    let mut parsed = ParsedDiffSet::parse(&changeset).expect("parse the changeset");
    assert_eq!(
        parsed.rename_tables(|name| (name == "physical_t").then(|| "t".to_owned())),
        1,
        "the record was captured under the physical name"
    );
    let logical: Vec<u8> = parsed.into();

    // ...and the hash and the queue head stand the logical upload bytes.
    assert_eq!(
        stored,
        entry_hash(&GENESIS, 1, &logical).to_vec(),
        "the stored hash stands the logical upload bytes"
    );
    let head: Vec<u8> = _connetto_writers::table
        .select(_connetto_writers::head)
        .first(conn.conn())
        .expect("read the queue head");
    assert_eq!(head, stored, "the queue head stands the logical hash");

    // The replay uploads the logical bytes.
    let wire = Wire::default();
    conn.attach(wire.clone()).await.expect("re-attach");
    drain(&mut conn).await;
    let payload = zstd::decode_all(
        wire.log
            .lock()
            .bulks
            .first()
            .expect("the replay uploaded a bulk frame")
            .as_slice(),
    )
    .expect("decompress the upload");
    let mut uploaded = ParsedDiffSet::parse(&payload).expect("parse the upload");
    assert_eq!(
        uploaded.rename_tables(|name| (name == "physical_t").then(|| "t".to_owned())),
        0,
        "the upload speaks the logical name"
    );
}

#[tokio::test]
async fn a_failed_number_grant_preserves_the_unissued_queue_for_retry() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;
    write(&mut conn, 1);
    assert_eq!(conn.push().await.expect("offline write"), Some(1));
    let before = conn.unsynced();
    conn.conn()
        .batch_execute(
            "CREATE TRIGGER fail_grant BEFORE UPDATE ON _connetto_writers \
         WHEN NEW.id = 'number:1' \
         BEGIN SELECT RAISE(FAIL, 'grant failure'); END;",
        )
        .expect("arm grant failure");
    assert!(conn.attach(Wire::default()).await.is_err());
    assert_eq!(
        conn.unsynced(),
        before,
        "a failed grant preserves the in-memory queue"
    );
    assert_eq!(writers(&mut conn), ["number:0"]);
    let durable: Vec<String> = _connetto_pending::table
        .select(_connetto_pending::writer)
        .load(conn.conn())
        .expect("durable writer");
    assert_eq!(durable, ["number:0"]);
    conn.conn()
        .batch_execute("DROP TRIGGER fail_grant")
        .expect("disarm failure");
    drop(conn);
    let mut conn = open(&dir).await;
    assert_eq!(
        conn.unsynced(),
        before,
        "the unissued tail survives restart"
    );
    let wire = Wire::default();
    conn.attach(wire.clone()).await.expect("retry grant");
    drain(&mut conn).await;
    assert_eq!(wire.log.lock().mutations, [1]);
    assert_eq!(conn.unsynced(), Vec::<UnsyncedWrite>::new());
}
