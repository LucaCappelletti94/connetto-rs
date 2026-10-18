//! R75, the client's writer state table, the number-writer half.
//!
//! One behaviour test per reachable row of the table that a number writer can
//! hold: a handshake acknowledged with no writer yet keeps the issued number
//! and re-keys the queue; a handshake with a number writer reconciles the
//! queue against the reported frontier without retiring anything locally; a
//! `WriterRetired` fatal re-queues the tail with provenance under a fresh
//! number; an archive import re-queues the archived writes with provenance
//! and retires the archived writer once. The device-writer rows need an
//! enrolled key, which the native suites steer through the enrolment task.

use std::collections::VecDeque;
use std::future::{Future, ready};
use std::sync::Arc;

use connetto_client::{
    ClientBuilder, ClientError, ClientEvent, ConnettoConnection, DataDir, ExportScope,
    ImportChoices, MemoryRefreshStore, SyncSchema, UnsyncedWrite,
};
use connetto_core::chain::{GENESIS, entry_hash};
use connetto_core::messages::{
    BulkMessage, ControlMessage, FatalError, FatalErrorReason, HandshakeAck, MutationApplied,
    MutationReject, MutationRejectReason, WriterAnswer, WriterGrant, WriterOutcome, WriterRef,
    WriterRequest,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, Major};
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
        position -> BigInt,
        prov_writer -> Nullable<Text>,
        prov_seq -> Nullable<BigInt>,
    }
}

diesel::table! {
    /// The client's private retirement-owed table, seeded by an assertion.
    _connetto_retire (writer) {
        /// The writer to retire, the replica's spelling of the wire name.
        writer -> Text,
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
    retire_answer: Option<String>,
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
            retire_answer: None,
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

    /// Answer a retirement under a request id the connection did not send.
    fn retire_answer_with(mut self, request_id: impl Into<String>) -> Self {
        self.retire_answer = Some(request_id.into());
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
                let request_id = self.retire_answer.clone().unwrap_or(retire.request_id);
                log.outbox
                    .push_back(IncomingFrame::Control(ControlMessage::WriterAnswer(
                        WriterAnswer {
                            request_id,
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
    .durable(
        DataDir::new(dir.path().to_path_buf()),
        store,
        MemoryRefreshStore::default(),
    )
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

/// Pump until the connection fails, past any notices the attach pushed first.
async fn pump_to_error(conn: &mut ConnettoConnection<Wire>) -> ClientError {
    for _ in 0..16 {
        match conn.pump_one().await {
            Ok(_) => {}
            Err(err) => return err,
        }
    }
    panic!("no protocol failure surfaced");
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
            seq: 1,
            major: Major::new(1),
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
                seq,
                major: Major::new(1),
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

/// The table's archive row: the archived writer's writes re-queue with
/// provenance under the importer's fresh writer, and the archived writer is
/// retired once, the answered retirement not re-sent.
#[tokio::test]
async fn an_archive_import_requeues_with_provenance_and_retires_the_archived_writer() {
    let source_dir = tempdir().expect("temp dir");
    let mut source = open(&source_dir).await;
    conn_attach_silent(&mut source).await;
    write(&mut source, 1);
    assert_eq!(source.push().await.expect("queue"), Some(1));
    let archive = source
        .export_local_data(ExportScope::Everything, Vec::new())
        .expect("export");

    let fresh_dir = tempdir().expect("temp dir");
    let mut fresh = open(&fresh_dir).await;
    let plan = fresh
        .import_local_data(std::io::Cursor::new(archive))
        .expect("plan");
    assert_eq!(plan.queued_writes(), 1, "the unsynced write travelled");
    let outcome = fresh
        .apply_import(&plan, &ImportChoices::keeping_the_file())
        .expect("apply");
    assert_eq!(outcome.writes_restored, 1);
    assert_eq!(
        pending(&mut fresh),
        vec![PendingRow {
            writer: "number:0".to_owned(),
            seq: 1,
            prov_writer: Some("number:1".to_owned()),
            prov_seq: Some(1),
        }],
        "the restored write sits under the importer's fresh writer, provenance intact"
    );

    let wire = Wire::default().grant(2, 0);
    fresh.attach(wire.clone()).await.expect("attach");
    {
        let log = wire.log.lock();
        assert_eq!(log.handshakes, vec![WriterRequest::Issue]);
    }
    drain(&mut fresh).await;
    {
        let log = wire.log.lock();
        assert_eq!(
            log.retires.len(),
            1,
            "one retirement owed per distinct archived writer"
        );
        assert_eq!(log.retires[0].writer, WriterRef::Number(1));
        assert_eq!(log.mutations, vec![1], "the restored write went up");
    }
    assert!(
        fresh.unsynced().is_empty(),
        "the applied answer retired the entry"
    );

    // The answer cleared the obligation, so a second connection owes nothing.
    let second = Wire::default().grant(2, 0);
    fresh.attach(second.clone()).await.expect("attach");
    drain(&mut fresh).await;
    assert!(
        second.log.lock().retires.is_empty(),
        "the answered retirement is not re-sent"
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
            seq: 3,
            major: Major::new(1),
        }]
    );
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
                seq: 1,
                major: Major::new(1),
            },
            UnsyncedWrite {
                writer: WriterRef::Number(0),
                seq: 2,
                major: Major::new(1),
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
                _connetto_pending::position.eq(1_i64),
            ))
            .execute(conn.conn())
            .expect("undecodable writer row");
        diesel::insert_into(_connetto_pending::table)
            .values((
                _connetto_pending::writer.eq("number:5"),
                _connetto_pending::seq.eq(-3_i64),
                _connetto_pending::changeset.eq(b"two"),
                _connetto_pending::entry_hash.eq([0u8; 32]),
                _connetto_pending::position.eq(2_i64),
            ))
            .execute(conn.conn())
            .expect("negative sequence row");
        diesel::insert_into(_connetto_pending::table)
            .values((
                _connetto_pending::writer.eq("number:9"),
                _connetto_pending::seq.eq(7_i64),
                _connetto_pending::changeset.eq(b"three"),
                _connetto_pending::entry_hash.eq([0u8; 31]),
                _connetto_pending::position.eq(3_i64),
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
            seq: 1,
            major: Major::new(1),
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
                seq: 1,
                major: Major::new(1),
            },
            UnsyncedWrite {
                writer: WriterRef::Number(1),
                seq: 2,
                major: Major::new(1),
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
                seq: 1,
                major: Major::new(1),
            },
            UnsyncedWrite {
                writer: WriterRef::Number(1),
                seq: 2,
                major: Major::new(1),
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
            .closing(FatalErrorReason::WriterUnknown),
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
                seq: 1,
                major: Major::new(1),
            },
            UnsyncedWrite {
                writer: WriterRef::Number(1),
                seq: 2,
                major: Major::new(1),
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

/// A refused numbered handshake preserves its tail for a fresh writer.
#[tokio::test]
async fn a_handshake_refusal_carries_the_unknown_or_retired_numbers_tail() {
    for reason in [
        FatalErrorReason::WriterUnknown,
        FatalErrorReason::WriterRetired,
    ] {
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
            .attach(Wire::default().refusing_with(reason.clone()))
            .await
            .expect_err("the refused handshake fails the attach");
        assert!(
            matches!(&error, ClientError::Refused { reason: actual } if actual == &reason),
            "the refusal surfaces, saw {error:?}"
        );
        assert_eq!(
            writers(&mut conn),
            vec!["number:0".to_owned()],
            "the refused number's tail travels under the unissued number"
        );
        assert_eq!(
            conn.unsynced(),
            vec![
                UnsyncedWrite {
                    writer: WriterRef::Number(0),
                    seq: 1,
                    major: Major::new(1),
                },
                UnsyncedWrite {
                    writer: WriterRef::Number(0),
                    seq: 2,
                    major: Major::new(1),
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
}

/// The split table's local replica writes the physical table under the view,
/// so the queue entry hashes the logical bytes the wire uploads and keeps the
/// physical bytes for the rollback.
const SPLIT_DDL: &str = "CREATE TABLE physical_t (id INTEGER PRIMARY KEY); \
    CREATE VIEW t AS SELECT * FROM physical_t; \
    CREATE TRIGGER t_insert INSTEAD OF INSERT ON t \
    BEGIN INSERT INTO physical_t (id) VALUES (NEW.id); END;";

/// The schema source the split bundle declares, which names its major.
const SOURCE: &str = "-- connetto:major 1";

/// The split schema's bundle: the view `t` over its physical table.
fn split_bundle() -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            SOURCE,
            "",
            SPLIT_DDL,
            vec![("t".to_owned(), "physical_t".to_owned())],
            vec!["t".to_owned()],
            None::<&str>,
        )
        .expect("the source declares major 1"),
    )
}

/// A replica in its own directory, opened offline under the split schema.
async fn split_open(dir: &tempfile::TempDir) -> ConnettoConnection<Wire> {
    let credential = super::support::held("tester");
    let store = super::support::key_store(&credential).await;
    ClientBuilder::new(split_bundle(), super::support::NeverDial::<Wire>::default())
        .signed_in(credential)
        .durable(
            DataDir::new(dir.path().to_path_buf()),
            store,
            MemoryRefreshStore::default(),
        )
        .open_driven()
        .await
        .expect("open with no server")
}

/// The suite's schema at `major`, one table and no policies.
fn bundle_at(major: u32) -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            format!("-- connetto:major {major}"),
            "",
            DDL,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            None::<&str>,
        )
        .expect("the source declares its major"),
    )
}

/// A replica in its own directory, opened offline under `schema`.
async fn open_with(dir: &tempfile::TempDir, schema: SyncSchema) -> ConnettoConnection<Wire> {
    let credential = super::support::held("tester");
    let store = super::support::key_store(&credential).await;
    ClientBuilder::new(schema, super::support::NeverDial::<Wire>::default())
        .signed_in(credential)
        .durable(
            DataDir::new(dir.path().to_path_buf()),
            store,
            MemoryRefreshStore::default(),
        )
        .open_driven()
        .await
        .expect("open with no server")
}

/// R31 on R75: a write an older major captured leaves only through that
/// major's drain, so the newer major's wire sends nothing queued after it,
/// whether queued before the connection or while it stands.
#[tokio::test]
async fn an_older_majors_entry_holds_the_newer_majors_writes_off_the_wire() {
    let dir = tempdir().expect("temp dir");
    {
        let mut conn = open_with(&dir, bundle_at(1)).await;
        write(&mut conn, 1);
        conn.push().await.expect("queue");
    }
    let mut conn = open_with(&dir, bundle_at(2)).await;
    write(&mut conn, 2);
    conn.push().await.expect("queue");

    let wire = Wire::default();
    conn.attach(wire.clone()).await.expect("attach");
    write(&mut conn, 3);
    conn.push().await.expect("queue");
    drain(&mut conn).await;

    assert!(
        wire.log.lock().mutations.is_empty(),
        "nothing passes the older major's entry on the newer major's wire"
    );
    assert_eq!(
        conn.unsynced()
            .iter()
            .map(|write| (write.seq, write.major))
            .collect::<Vec<_>>(),
        vec![(1, Major::new(1)), (2, Major::new(2)), (3, Major::new(2))],
        "every write stays queued in one chain, each under its own major"
    );
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

/// A `WriterAnswer` with no bind or retirement in flight is a protocol
/// failure, the connection never settling a task it never sent.
#[tokio::test]
async fn a_writer_answer_with_nothing_in_flight_is_a_protocol_failure() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;
    let wire = Wire::default();
    conn.attach(wire.clone()).await.expect("attach");

    // The handshake settled and nothing is owed, so the connection holds no
    // writer task. The server must not answer one.
    wire.log
        .lock()
        .outbox
        .push_back(IncomingFrame::Control(ControlMessage::WriterAnswer(
            WriterAnswer {
                request_id: "spurious".to_owned(),
                outcome: WriterOutcome::Retired,
            },
        )));
    let err = pump_to_error(&mut conn).await;
    let ClientError::Protocol(detail) = err else {
        panic!("the spurious answer must fail the protocol, got {err:?}");
    };
    assert_eq!(
        detail, "a writer answer arrived with nothing in flight",
        "the connection names the violation it refused"
    );
}

/// A `WriterAnswer` naming a request the connection never sent is a protocol
/// failure, and the retirement it owes stays owed for the next answer.
#[tokio::test]
async fn a_writer_answer_naming_a_foreign_request_is_a_protocol_failure() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;

    // A retirement owed before the connection stands goes up at the attach.
    diesel::insert_into(_connetto_retire::table)
        .values(_connetto_retire::writer.eq("number:1"))
        .on_conflict_do_nothing()
        .execute(conn.conn())
        .expect("remember the retirement");
    let wire = Wire::default().retire_answer_with("foreign");
    conn.attach(wire.clone()).await.expect("attach");

    let err = pump_to_error(&mut conn).await;
    let ClientError::Protocol(detail) = err else {
        panic!("the foreign answer must fail the protocol, got {err:?}");
    };
    assert_eq!(
        detail, "the writer answer names a foreign request",
        "the connection names the violation it refused"
    );
    {
        let log = wire.log.lock();
        assert_eq!(log.retires.len(), 1, "the retirement went up once");
    }
}

#[cfg(feature = "device-identity")]
diesel::table! {
    _connetto_device_certificate (id) {
        /// The single row's identifier.
        id -> Integer,
        certificate -> Binary,
        issuer -> Binary,
        lifetime_secs -> Nullable<BigInt>,
    }
}

/// Issue a profile-valid device certificate for a fresh key, returning the
/// leaf and issuer DER beside the key id a writer queue names.
#[cfg(feature = "device-identity")]
fn mint_device_certificate(account: &str) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    use connetto_core::device_cert::{
        AttestationLevel, CertificateRequest, CertificateSerial, DeploymentId, DeviceCertificate,
        DeviceIssuer, RootCa,
    };
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData as _};
    use std::time::{Duration, SystemTime};

    let now = SystemTime::now();
    let root = RootCa::create(
        DeploymentId::from_uuid(uuid::Uuid::new_v4()),
        now,
        Duration::from_hours(8760),
    )
    .expect("root");
    let issuer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let issuer_cert = root
        .sign_issuer(
            &issuer_key.subject_public_key_info(),
            now,
            Duration::from_hours(2160),
            CertificateSerial::new([1; 16]).expect("serial"),
        )
        .expect("issuer");
    let issuer =
        DeviceIssuer::new(issuer_cert.clone(), issuer_key, root.certificate()).expect("issuer");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("device key");
    let csr = CertificateRequest::build(&key, &[7; 32]).expect("request builds");
    let request = CertificateRequest::parse(&csr).expect("request parses");
    let leaf = issuer
        .issue(
            &request,
            account,
            now,
            Duration::from_hours(720),
            CertificateSerial::new([2; 16]).expect("serial"),
            AttestationLevel::Unproven,
        )
        .expect("issued");
    let key_id = *DeviceCertificate::parse(&leaf)
        .expect("profile")
        .identity()
        .key()
        .as_bytes();
    (leaf, issuer_cert, key_id)
}

/// Stand a device certificate the enrolment task would have stored.
#[cfg(feature = "device-identity")]
fn store_certificate(conn: &mut ConnettoConnection<Wire>, leaf: &[u8], issuer: &[u8]) {
    diesel::replace_into(_connetto_device_certificate::table)
        .values((
            _connetto_device_certificate::id.eq(1),
            _connetto_device_certificate::certificate.eq(leaf),
            _connetto_device_certificate::issuer.eq(issuer),
            _connetto_device_certificate::lifetime_secs.eq(Some(30 * 24 * 3600_i64)),
        ))
        .execute(conn.conn())
        .expect("the certificate stores");
}

#[cfg(feature = "device-identity")]
fn unsynced_write(writer: WriterRef, seq: u64) -> UnsyncedWrite {
    UnsyncedWrite {
        writer,
        seq,
        major: Major::new(1),
    }
}

/// The retired-key window: a revoked device keeps its certificate until the
/// enrolment task clears it, and a write captured inside that window must
/// not resurrect the retired key's queue. The write stands under the live
/// number, survives a restart, and settles when the connection is healthy,
/// while the fresh key takes the writes after it.
#[cfg(feature = "device-identity")]
#[tokio::test]
async fn a_write_in_the_retired_key_window_queues_under_the_number_and_stays_deliverable() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;

    // The number writer takes the first write, then the enrolment stands a
    // certificate and the device takes the next one.
    conn.attach(Wire::default().silent()).await.expect("attach");
    write(&mut conn, 1);
    assert_eq!(conn.push().await.expect("queue"), Some(1));
    let (leaf_a, issuer_a, key_a) = mint_device_certificate("tester");
    store_certificate(&mut conn, &leaf_a, &issuer_a);
    write(&mut conn, 2);
    assert_eq!(conn.push().await.expect("queue"), Some(1));
    assert_eq!(
        conn.unsynced(),
        [
            unsynced_write(WriterRef::Device(key_a), 1),
            unsynced_write(WriterRef::Number(1), 1),
        ],
        "the enrolled device takes the newer write, the number keeps the older"
    );

    // The server revokes the device. Its tail travels to the number, but the
    // certificate stays held until the enrolment task clears it.
    let wire = Wire::default()
        .silent()
        .closing(FatalErrorReason::DeviceRevoked);
    conn.attach(wire).await.expect("revocation");
    drain(&mut conn).await;

    // The window: a write captured before the cleanup runs.
    write(&mut conn, 3);
    assert_eq!(conn.push().await.expect("queue"), Some(3));
    assert_eq!(
        conn.unsynced(),
        [
            unsynced_write(WriterRef::Number(1), 1),
            unsynced_write(WriterRef::Number(1), 2),
            unsynced_write(WriterRef::Number(1), 3),
        ],
        "the window write stands under the live number, not the retired key"
    );

    // The fresh key arrives and takes the next write, the retired key never
    // re-selected.
    let (leaf_b, issuer_b, key_b) = mint_device_certificate("tester");
    store_certificate(&mut conn, &leaf_b, &issuer_b);
    write(&mut conn, 4);
    assert_eq!(conn.push().await.expect("queue"), Some(1));
    assert_eq!(
        conn.unsynced(),
        [
            unsynced_write(WriterRef::Device(key_b), 1),
            unsynced_write(WriterRef::Number(1), 1),
            unsynced_write(WriterRef::Number(1), 2),
            unsynced_write(WriterRef::Number(1), 3),
        ],
        "the fresh key takes the new write, the number keeps the window write"
    );

    // A restart keeps the window write deliverable under the number, and the
    // fresh key's queue whole.
    drop(conn);
    let mut conn = open(&dir).await;
    write(&mut conn, 5);
    assert_eq!(conn.push().await.expect("queue"), Some(2));
    assert_eq!(
        conn.unsynced(),
        [
            unsynced_write(WriterRef::Device(key_b), 1),
            unsynced_write(WriterRef::Device(key_b), 2),
            unsynced_write(WriterRef::Number(1), 1),
            unsynced_write(WriterRef::Number(1), 2),
            unsynced_write(WriterRef::Number(1), 3),
        ],
        "the restart keeps the window write under the number"
    );

    // The healthy connection settles the number's tail, the window write in
    // it, and the fresh key's queue stays whole for its bind.
    let wire = Wire::default().grant(1, 0);
    conn.attach(wire.clone()).await.expect("attach");
    drain(&mut conn).await;
    {
        let log = wire.log.lock();
        assert_eq!(
            log.mutations,
            vec![1, 2, 3],
            "the number's tail, the window write included, went up in order"
        );
    }
    assert_eq!(
        conn.unsynced(),
        [
            unsynced_write(WriterRef::Device(key_b), 1),
            unsynced_write(WriterRef::Device(key_b), 2),
        ],
        "the window write settled, the fresh key's queue stands whole"
    );
}

#[cfg(feature = "device-identity")]
#[tokio::test]
async fn a_failed_retirement_preserves_the_device_tail_for_retry() {
    let dir = tempdir().expect("temp dir");
    let mut conn = open(&dir).await;
    conn.attach(Wire::default().silent()).await.expect("attach");
    write(&mut conn, 1);
    conn.push().await.expect("number write");
    let (leaf, issuer, _) = mint_device_certificate("tester");
    store_certificate(&mut conn, &leaf, &issuer);
    write(&mut conn, 2);
    conn.push().await.expect("device write");
    let before = conn.unsynced();
    conn.conn()
        .batch_execute(
            "CREATE TRIGGER fail_retirement BEFORE INSERT ON _connetto_retired_keys \
         BEGIN SELECT RAISE(FAIL, 'retirement failure'); END;",
        )
        .expect("arm retirement failure");
    conn.attach(
        Wire::default()
            .silent()
            .closing(FatalErrorReason::DeviceRevoked),
    )
    .await
    .expect("attach revoked device");
    let _error = pump_to_error(&mut conn).await;
    assert_eq!(
        conn.unsynced(),
        before,
        "a failed marker cannot publish a carry"
    );
    conn.conn()
        .batch_execute("DROP TRIGGER fail_retirement")
        .expect("disarm failure");
    drop(conn);
    let mut conn = open(&dir).await;
    assert_eq!(conn.unsynced(), before, "the source survives restart");
    conn.attach(
        Wire::default()
            .silent()
            .closing(FatalErrorReason::DeviceRevoked),
    )
    .await
    .expect("retry retirement");
    drain(&mut conn).await;
    drop(conn);
    let mut conn = open(&dir).await;
    write(&mut conn, 3);
    assert_eq!(conn.push().await.expect("write after retirement"), Some(3));
    let wire = Wire::default();
    conn.attach(wire.clone())
        .await
        .expect("deliver carried writes");
    drain(&mut conn).await;
    assert_eq!(wire.log.lock().mutations, [1, 2, 3]);
    assert_eq!(conn.unsynced(), Vec::<UnsyncedWrite>::new());
}

#[cfg(feature = "device-identity")]
fn split_pending_writers(source: &mut ConnettoConnection<Wire>) {
    let first_hash: Vec<u8> = _connetto_pending::table
        .filter(_connetto_pending::seq.eq(1_i64))
        .select(_connetto_pending::entry_hash)
        .first(source.conn())
        .expect("number head");
    let second: Vec<u8> = _connetto_pending::table
        .filter(_connetto_pending::seq.eq(2_i64))
        .select(_connetto_pending::changeset)
        .first(source.conn())
        .expect("later delete");
    let device = format!("device:{}", "01".repeat(32));
    let device_head = entry_hash(&GENESIS, 1, &second);
    diesel::update(_connetto_pending::table.filter(_connetto_pending::seq.eq(2_i64)))
        .set((
            _connetto_pending::writer.eq(&device),
            _connetto_pending::seq.eq(1_i64),
            _connetto_pending::entry_hash.eq(device_head),
        ))
        .execute(source.conn())
        .expect("device tail");
    diesel::update(_connetto_writers::table)
        .set((
            _connetto_writers::next_seq.eq(2_i64),
            _connetto_writers::head.eq(first_hash),
        ))
        .execute(source.conn())
        .expect("number frontier");
    diesel::insert_into(_connetto_writers::table)
        .values((
            _connetto_writers::id.eq(device),
            _connetto_writers::next_seq.eq(2_i64),
            _connetto_writers::head.eq(device_head),
        ))
        .execute(source.conn())
        .expect("device frontier");
}

#[cfg(feature = "device-identity")]
#[tokio::test]
async fn resync_and_archive_preserve_a_number_insert_followed_by_a_device_delete() {
    use connetto_client::{ExportScope, ImportChoices};
    use connetto_core::messages::{
        FullResyncReason, FullResyncRequired, SnapshotBegin, SnapshotEnd, SubscriptionPriority,
    };

    let dir = tempdir().expect("source directory");
    let mut source = open(&dir).await;
    source
        .attach(Wire::default().silent())
        .await
        .expect("attach");
    write(&mut source, 1);
    source.push().await.expect("number insert");
    diesel::delete(t::table.filter(t::id.eq(1)))
        .execute(source.conn())
        .expect("device delete");
    source.push().await.expect("queue device delete");
    split_pending_writers(&mut source);
    drop(source);
    let mut source = open(&dir).await;
    let source_wire = Wire::default().silent();
    source.attach(source_wire.clone()).await.expect("reattach");
    source
        .subscribe("ordered", "SELECT id FROM t")
        .await
        .expect("subscribe");
    source_wire.log.lock().outbox.extend([
        IncomingFrame::Control(ControlMessage::FullResyncRequired(FullResyncRequired {
            sub_id: "ordered".to_owned(),
            reason: FullResyncReason::CursorOutsideRetention,
        })),
        IncomingFrame::Control(ControlMessage::SnapshotBegin(SnapshotBegin {
            sub_id: "ordered".to_owned(),
            priority: SubscriptionPriority::default(),
        })),
        IncomingFrame::Control(ControlMessage::SnapshotEnd(SnapshotEnd {
            sub_id: "ordered".to_owned(),
            cursor: Cursor::new(Vec::new()),
        })),
    ]);
    drain(&mut source).await;
    let rows: Vec<i32> = t::table
        .select(t::id)
        .load(source.conn())
        .expect("resynced rows");
    assert_eq!(
        rows,
        Vec::<i32>::new(),
        "resync must reapply the delete after its insert"
    );
    let archive = source
        .export_local_data(ExportScope::Everything, Vec::new())
        .expect("export");
    let fresh = tempdir().expect("destination directory");
    let mut restored = open(&fresh).await;
    let plan = restored
        .import_local_data(std::io::Cursor::new(archive))
        .expect("read archive");
    restored
        .apply_import(&plan, &ImportChoices::keeping_the_file())
        .expect("restore");
    let rows: Vec<i32> = t::table
        .select(t::id)
        .load(restored.conn())
        .expect("restored rows");
    assert_eq!(
        rows,
        Vec::<i32>::new(),
        "the later delete must follow its insert"
    );
    let wire = Wire::default();
    restored
        .attach(wire.clone())
        .await
        .expect("deliver restored writes");
    drain(&mut restored).await;
    assert_eq!(wire.log.lock().mutations, [1, 2]);
    assert_eq!(restored.unsynced(), Vec::<UnsyncedWrite>::new());
}

async fn conn_attach_silent(conn: &mut ConnettoConnection<Wire>) {
    conn.attach(Wire::default().silent()).await.expect("attach");
    drain(conn).await;
}
